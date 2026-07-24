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
)

type MongoRepository struct {
	organizations *mongo.Collection
	users         *mongo.Collection
	sessions      *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		organizations: database.Collection("organizations"),
		users:         database.Collection("users"),
		sessions:      database.Collection("sessions"),
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

func (r *MongoRepository) CreateSession(ctx context.Context, session biz.Session) error {
	return r.createSession(ctx, session)
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
