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
	invitations   *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		organizations: database.Collection("organizations"),
		users:         database.Collection("users"),
		sessions:      database.Collection("sessions"),
		loginAttempts: database.Collection("login_attempts"),
		invitations:   database.Collection("user_invitations"),
	}
}

func (r *MongoRepository) ListUsers(ctx context.Context, organizationID string) ([]biz.User, error) {
	cursor, err := r.users.Find(ctx, bson.D{{Key: "organization_id", Value: organizationID}},
		options.Find().SetProjection(bson.D{{Key: "password_hash", Value: 0}}).
			SetSort(bson.D{{Key: "email_normalized", Value: 1}, {Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find organization users: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []userDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode organization users: %w", err)
	}
	items := make([]biz.User, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
		items[index].PasswordHash = ""
	}
	return items, nil
}

func (r *MongoRepository) CreateInvitation(ctx context.Context, item biz.Invitation) (biz.Invitation, error) {
	if _, err := r.invitations.InsertOne(ctx, invitationDocumentFromDomain(item)); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return biz.Invitation{}, biz.ErrInvalidInvitation
		}
		return biz.Invitation{}, fmt.Errorf("insert user invitation: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) ListInvitations(ctx context.Context, organizationID string) ([]biz.Invitation, error) {
	cursor, err := r.invitations.Find(ctx, bson.D{{Key: "organization_id", Value: organizationID}},
		options.Find().SetProjection(bson.D{{Key: "token_hash", Value: 0}}).
			SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}))
	if err != nil {
		return nil, fmt.Errorf("find user invitations: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []invitationDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode user invitations: %w", err)
	}
	items := make([]biz.Invitation, len(documents))
	for index, document := range documents {
		items[index] = document.domain().Safe()
	}
	return items, nil
}

func (r *MongoRepository) GetInvitation(ctx context.Context, organizationID, invitationID string) (biz.Invitation, error) {
	var document invitationDocument
	err := r.invitations.FindOne(ctx, bson.D{{Key: "_id", Value: invitationID},
		{Key: "organization_id", Value: organizationID}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Invitation{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Invitation{}, fmt.Errorf("find user invitation: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) FindInvitationByTokenHash(ctx context.Context, tokenHash string,
	now time.Time) (biz.Invitation, error) {
	var document invitationDocument
	err := r.invitations.FindOne(ctx, bson.D{
		{Key: "token_hash", Value: tokenHash}, {Key: "status", Value: biz.InvitationStatusActive},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
	}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.Invitation{}, biz.ErrInvalidInvitation
	}
	if err != nil {
		return biz.Invitation{}, fmt.Errorf("find invitation token: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) AcceptInvitation(ctx context.Context, accepted biz.Invitation,
	expectedVersion uint64, user biz.User, session biz.Session) error {
	result, err := r.invitations.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: accepted.ID}, {Key: "organization_id", Value: accepted.OrganizationID},
		{Key: "status", Value: biz.InvitationStatusActive}, {Key: "version", Value: expectedVersion},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: accepted.AcceptedAt}}},
	}, invitationDocumentFromDomain(accepted))
	if err != nil {
		return fmt.Errorf("accept user invitation: %w", err)
	}
	if result.MatchedCount != 1 {
		return biz.ErrInvalidInvitation
	}
	if _, err := r.users.InsertOne(ctx, userDocumentFromDomain(user)); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return biz.ErrUserAlreadyExists
		}
		return fmt.Errorf("insert invited user: %w", err)
	}
	return r.createSession(ctx, session)
}

func (r *MongoRepository) RevokeInvitation(ctx context.Context, revoked biz.Invitation,
	expectedVersion uint64) (biz.Invitation, error) {
	result, err := r.invitations.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: revoked.ID}, {Key: "organization_id", Value: revoked.OrganizationID},
		{Key: "status", Value: biz.InvitationStatusActive}, {Key: "version", Value: expectedVersion},
	}, invitationDocumentFromDomain(revoked))
	if err != nil {
		return biz.Invitation{}, fmt.Errorf("revoke user invitation: %w", err)
	}
	if result.MatchedCount != 1 {
		return biz.Invitation{}, biz.ErrInvalidInvitation
	}
	return revoked, nil
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

func (r *MongoRepository) GetOrganizationUser(
	ctx context.Context, organizationID, userID string,
) (biz.User, error) {
	var document userDocument
	err := r.users.FindOne(ctx, bson.D{
		{Key: "_id", Value: userID}, {Key: "organization_id", Value: organizationID},
	}, options.FindOne().SetProjection(bson.D{{Key: "password_hash", Value: 0}})).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.User{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.User{}, fmt.Errorf("find organization user: %w", err)
	}
	item := document.domain()
	item.PasswordHash = ""
	return item, nil
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

func (r *MongoRepository) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	result, err := r.sessions.DeleteMany(ctx, bson.D{{Key: "user_id", Value: userID}})
	if err != nil {
		return 0, fmt.Errorf("delete user sessions: %w", err)
	}
	return result.DeletedCount, nil
}

var _ biz.AdministrativeSessionRepository = (*MongoRepository)(nil)

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

type invitationDocument struct {
	ID              string               `bson:"_id"`
	OrganizationID  string               `bson:"organization_id"`
	Email           string               `bson:"email"`
	EmailNormalized string               `bson:"email_normalized"`
	TokenHash       string               `bson:"token_hash,omitempty"`
	Status          biz.InvitationStatus `bson:"status"`
	Version         uint64               `bson:"version"`
	InvitedBy       string               `bson:"invited_by"`
	CreatedAt       time.Time            `bson:"created_at"`
	ExpiresAt       time.Time            `bson:"expires_at"`
	AcceptedBy      string               `bson:"accepted_by,omitempty"`
	AcceptedAt      time.Time            `bson:"accepted_at,omitempty"`
	RevokedBy       string               `bson:"revoked_by,omitempty"`
	RevokedAt       time.Time            `bson:"revoked_at,omitempty"`
}

func invitationDocumentFromDomain(item biz.Invitation) invitationDocument {
	return invitationDocument{
		ID: item.ID, OrganizationID: item.OrganizationID, Email: item.Email,
		EmailNormalized: item.EmailNormalized, TokenHash: item.TokenHash,
		Status: item.Status, Version: item.Version, InvitedBy: item.InvitedBy,
		CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt,
		AcceptedBy: item.AcceptedBy, AcceptedAt: item.AcceptedAt,
		RevokedBy: item.RevokedBy, RevokedAt: item.RevokedAt,
	}
}

func (d invitationDocument) domain() biz.Invitation {
	return biz.Invitation{
		ID: d.ID, OrganizationID: d.OrganizationID, Email: d.Email,
		EmailNormalized: d.EmailNormalized, TokenHash: d.TokenHash,
		Status: d.Status, Version: d.Version, InvitedBy: d.InvitedBy,
		CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt,
		AcceptedBy: d.AcceptedBy, AcceptedAt: d.AcceptedAt,
		RevokedBy: d.RevokedBy, RevokedAt: d.RevokedAt,
	}
}

func (d sessionDocument) domain() biz.Session {
	return biz.Session{
		ID: d.ID, UserID: d.UserID, TokenHash: d.TokenHash,
		CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt,
	}
}
