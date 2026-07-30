package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/identity/biz"
	"github.com/owndock/owndock/internal/shared/security"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoRepository struct {
	organizations *mongo.Collection
	users         *mongo.Collection
	sessions      *mongo.Collection
	loginAttempts *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		organizations: database.Collection("organizations"),
		users:         database.Collection("users"),
		sessions:      database.Collection("sessions"),
		loginAttempts: database.Collection("login_attempts"),
	}
}

func (r *MongoRepository) HasUsers(ctx context.Context) (bool, error) {
	count, err := r.users.CountDocuments(ctx, bson.D{}, nil)
	if err != nil {
		return false, fmt.Errorf("count users: %w", err)
	}
	return count > 0, nil
}

func (r *MongoRepository) CreateBootstrap(
	ctx context.Context,
	organization biz.Organization,
	user biz.User,
	session biz.Session,
) error {
	if _, err := r.organizations.InsertOne(ctx, organizationDocument{
		ID: organization.ID, SingletonKey: "default", Name: organization.Name, CreatedAt: organization.CreatedAt,
	}); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return biz.ErrAlreadyBootstrapped
		}
		return fmt.Errorf("insert organization: %w", err)
	}
	if _, err := r.users.InsertOne(ctx, userDocumentFromDomain(user)); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return biz.ErrAlreadyBootstrapped
		}
		return fmt.Errorf("insert owner: %w", err)
	}
	if err := r.createSession(ctx, session); err != nil {
		return err
	}
	return nil
}

func (r *MongoRepository) FindUserByEmail(ctx context.Context, normalizedEmail string) (biz.User, error) {
	var document userDocument
	err := r.users.FindOne(ctx, bson.D{{Key: "email_normalized", Value: normalizedEmail}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.User{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.User{}, fmt.Errorf("find user by email: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) CreateSession(
	ctx context.Context,
	session biz.Session,
	now time.Time,
	maximumActive int,
) error {
	if maximumActive < 1 {
		return fmt.Errorf("active session limit is invalid")
	}
	// Serialize session creation per user inside the caller's transaction.
	// Without this write, two concurrent logins could both observe room below
	// the cap and commit more than maximumActive sessions (write skew).
	lock, err := r.users.UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: session.UserID}},
		bson.D{{Key: "$inc", Value: bson.D{
			{Key: "session_revision", Value: 1},
		}}},
	)
	if err != nil {
		return fmt.Errorf("lock user session set: %w", err)
	}
	if lock.MatchedCount != 1 {
		return biz.ErrNotFound
	}
	if err := r.createSession(ctx, session); err != nil {
		return err
	}
	cursor, err := r.sessions.Find(
		ctx,
		bson.D{
			{Key: "user_id", Value: session.UserID},
			{Key: "expires_at", Value: bson.D{
				{Key: "$gt", Value: now.UTC()},
			}},
		},
		options.Find().
			SetProjection(bson.D{{Key: "_id", Value: 1}}).
			SetSort(bson.D{
				{Key: "created_at", Value: -1},
				{Key: "_id", Value: -1},
			}).
			SetSkip(int64(maximumActive)),
	)
	if err != nil {
		return fmt.Errorf("find excess sessions: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var excess []struct {
		ID string `bson:"_id"`
	}
	if err := cursor.All(ctx, &excess); err != nil {
		return fmt.Errorf("decode excess sessions: %w", err)
	}
	if len(excess) == 0 {
		return nil
	}
	ids := make(bson.A, len(excess))
	for index, item := range excess {
		ids[index] = item.ID
	}
	if _, err := r.sessions.DeleteMany(ctx, bson.D{
		{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}},
		{Key: "user_id", Value: session.UserID},
	}); err != nil {
		return fmt.Errorf("remove excess sessions: %w", err)
	}
	return nil
}

func (r *MongoRepository) createSession(ctx context.Context, session biz.Session) error {
	_, err := r.sessions.InsertOne(ctx, sessionDocument{
		ID: session.ID, UserID: session.UserID, TokenHash: session.TokenHash,
		CreatedAt: session.CreatedAt, ExpiresAt: session.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (r *MongoRepository) FindSession(ctx context.Context, tokenHash string, now time.Time) (biz.Session, biz.User, error) {
	var session sessionDocument
	err := r.sessions.FindOne(ctx, bson.D{
		{Key: "token_hash", Value: tokenHash},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
	}).Decode(&session)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Session{}, biz.User{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Session{}, biz.User{}, fmt.Errorf("find session: %w", err)
	}
	var user userDocument
	err = r.users.FindOne(ctx, bson.D{{Key: "_id", Value: session.UserID}}).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Session{}, biz.User{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Session{}, biz.User{}, fmt.Errorf("find session user: %w", err)
	}
	return session.domain(), user.domain(), nil
}

func (r *MongoRepository) ListSessions(
	ctx context.Context,
	userID string,
	now time.Time,
) ([]biz.Session, error) {
	cursor, err := r.sessions.Find(
		ctx,
		bson.D{
			{Key: "user_id", Value: userID},
			{Key: "expires_at", Value: bson.D{
				{Key: "$gt", Value: now.UTC()},
			}},
		},
		options.Find().SetSort(bson.D{
			{Key: "created_at", Value: -1},
			{Key: "_id", Value: -1},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("find user sessions: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []sessionDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode user sessions: %w", err)
	}
	result := make([]biz.Session, len(documents))
	for index, document := range documents {
		result[index] = document.domain()
	}
	return result, nil
}

func (r *MongoRepository) DeleteSession(ctx context.Context, sessionID, userID string) error {
	result, err := r.sessions.DeleteOne(ctx, bson.D{{Key: "_id", Value: sessionID}, {Key: "user_id", Value: userID}})
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	if result.DeletedCount == 0 {
		return biz.ErrNotFound
	}
	return nil
}

type organizationDocument struct {
	ID           string    `bson:"_id"`
	SingletonKey string    `bson:"singleton_key"`
	Name         string    `bson:"name"`
	CreatedAt    time.Time `bson:"created_at"`
}

type userDocument struct {
	ID              string        `bson:"_id"`
	OrganizationID  string        `bson:"organization_id"`
	Email           string        `bson:"email"`
	EmailNormalized string        `bson:"email_normalized"`
	PasswordHash    string        `bson:"password_hash"`
	Role            security.Role `bson:"role"`
	CreatedAt       time.Time     `bson:"created_at"`
}

func userDocumentFromDomain(user biz.User) userDocument {
	return userDocument{
		ID: user.ID, OrganizationID: user.OrganizationID,
		Email: user.Email, EmailNormalized: user.EmailNormalized,
		PasswordHash: user.PasswordHash, Role: user.Role, CreatedAt: user.CreatedAt,
	}
}

func (d userDocument) domain() biz.User {
	return biz.User{
		ID: d.ID, OrganizationID: d.OrganizationID,
		Email: d.Email, EmailNormalized: d.EmailNormalized,
		PasswordHash: d.PasswordHash, Role: d.Role, CreatedAt: d.CreatedAt,
	}
}

type sessionDocument struct {
	ID        string    `bson:"_id"`
	UserID    string    `bson:"user_id"`
	TokenHash string    `bson:"token_hash"`
	CreatedAt time.Time `bson:"created_at"`
	ExpiresAt time.Time `bson:"expires_at"`
}

func (d sessionDocument) domain() biz.Session {
	return biz.Session{
		ID: d.ID, UserID: d.UserID, TokenHash: d.TokenHash,
		CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt,
	}
}
