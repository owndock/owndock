package data

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoRepository struct {
	policies *mongo.Collection
	sessions *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		policies: database.Collection("terminal_access_policies"),
		sessions: database.Collection("terminal_sessions"),
	}
}

func (r *MongoRepository) GetProjectPolicy(ctx context.Context, organizationID, projectID string) (biz.AccessPolicy, error) {
	return r.getPolicy(ctx, bson.D{
		{Key: "scope", Value: biz.PolicyScopeProject},
		{Key: "organization_id", Value: organizationID},
		{Key: "project_id", Value: projectID},
	})
}

func (r *MongoRepository) GetOrganizationPolicy(ctx context.Context, organizationID string) (biz.AccessPolicy, error) {
	return r.getPolicy(ctx, bson.D{
		{Key: "scope", Value: biz.PolicyScopeOrganization},
		{Key: "organization_id", Value: organizationID},
	})
}

func (r *MongoRepository) getPolicy(ctx context.Context, filter bson.D) (biz.AccessPolicy, error) {
	var document policyDocument
	if err := r.policies.FindOne(ctx, filter).Decode(&document); err == mongo.ErrNoDocuments {
		return biz.AccessPolicy{}, biz.ErrPolicyNotFound
	} else if err != nil {
		return biz.AccessPolicy{}, fmt.Errorf("find terminal access policy: %w", err)
	}
	policy := document.domain()
	if err := policy.Validate(); err != nil {
		return biz.AccessPolicy{}, fmt.Errorf("decode terminal access policy: %w", err)
	}
	return policy, nil
}

func (r *MongoRepository) SavePolicy(ctx context.Context, policy biz.AccessPolicy, expectedVersion uint64) (biz.AccessPolicy, error) {
	if err := policy.Validate(); err != nil {
		return biz.AccessPolicy{}, err
	}
	if expectedVersion == 0 {
		if _, err := r.policies.InsertOne(ctx, policyDocumentFromDomain(policy)); mongo.IsDuplicateKeyError(err) {
			return biz.AccessPolicy{}, biz.ErrPolicyConflict
		} else if err != nil {
			return biz.AccessPolicy{}, fmt.Errorf("insert terminal access policy: %w", err)
		}
		return policy, nil
	}
	result, err := r.policies.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: policy.ID},
		{Key: "organization_id", Value: policy.OrganizationID},
		{Key: "version", Value: expectedVersion},
	}, policyDocumentFromDomain(policy))
	if err != nil {
		return biz.AccessPolicy{}, fmt.Errorf("replace terminal access policy: %w", err)
	}
	if result.MatchedCount != 1 {
		return biz.AccessPolicy{}, biz.ErrPolicyConflict
	}
	return policy, nil
}

func (r *MongoRepository) GetSession(ctx context.Context, organizationID, sessionID string) (biz.TerminalSession, error) {
	var document sessionDocument
	if err := r.sessions.FindOne(ctx, bson.D{
		{Key: "_id", Value: sessionID}, {Key: "organization_id", Value: organizationID},
	}).Decode(&document); err == mongo.ErrNoDocuments {
		return biz.TerminalSession{}, biz.ErrSessionNotFound
	} else if err != nil {
		return biz.TerminalSession{}, fmt.Errorf("find terminal session: %w", err)
	}
	session := document.domain()
	if err := validateStoredSession(session); err != nil {
		return biz.TerminalSession{}, fmt.Errorf("decode terminal session: %w", err)
	}
	return session, nil
}

func (r *MongoRepository) GetSessionForConnect(
	ctx context.Context,
	sessionID string,
) (biz.TerminalSession, error) {
	var document sessionDocument
	if err := r.sessions.FindOne(ctx, bson.D{
		{Key: "_id", Value: sessionID},
		{Key: "status", Value: biz.StatusPending},
		{Key: "active", Value: true},
	}).Decode(&document); err == mongo.ErrNoDocuments {
		return biz.TerminalSession{}, biz.ErrSessionNotFound
	} else if err != nil {
		return biz.TerminalSession{}, fmt.Errorf("find terminal session for connect: %w", err)
	}
	session := document.domain()
	if err := validateStoredSession(session); err != nil {
		return biz.TerminalSession{}, fmt.Errorf("decode terminal session for connect: %w", err)
	}
	return session, nil
}

func (r *MongoRepository) CreateSession(ctx context.Context, session biz.TerminalSession) (biz.TerminalSession, error) {
	if err := session.Validate(); err != nil || session.UserConcurrencySlot < 1 || session.TargetConcurrencySlot < 1 {
		return biz.TerminalSession{}, biz.ErrInvalidSession
	}
	if _, err := r.sessions.InsertOne(ctx, sessionDocumentFromDomain(session)); mongo.IsDuplicateKeyError(err) {
		if duplicateSessionSlot(err) {
			return biz.TerminalSession{}, biz.ErrSessionSlotConflict
		}
		return biz.TerminalSession{}, biz.ErrSessionConflict
	} else if err != nil {
		return biz.TerminalSession{}, fmt.Errorf("insert terminal session: %w", err)
	}
	return session, nil
}

func (r *MongoRepository) SaveSession(ctx context.Context, session biz.TerminalSession, expectedVersion uint64) (biz.TerminalSession, error) {
	if err := validateStoredSession(session); err != nil {
		return biz.TerminalSession{}, err
	}
	result, err := r.sessions.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: session.ID},
		{Key: "organization_id", Value: session.OrganizationID},
		{Key: "version", Value: expectedVersion},
	}, sessionDocumentFromDomain(session))
	if mongo.IsDuplicateKeyError(err) {
		if duplicateSessionSlot(err) {
			return biz.TerminalSession{}, biz.ErrSessionSlotConflict
		}
		return biz.TerminalSession{}, biz.ErrSessionConflict
	}
	if err != nil {
		return biz.TerminalSession{}, fmt.Errorf("replace terminal session: %w", err)
	}
	if result.MatchedCount != 1 {
		return biz.TerminalSession{}, biz.ErrSessionConflict
	}
	return session, nil
}

func (r *MongoRepository) ConsumeTicket(
	ctx context.Context,
	organizationID, sessionID, ticketHash string,
	now time.Time,
) (biz.TerminalSession, error) {
	var document sessionDocument
	err := r.sessions.FindOneAndUpdate(
		ctx,
		bson.D{
			{Key: "_id", Value: sessionID},
			{Key: "organization_id", Value: organizationID},
			{Key: "status", Value: biz.StatusPending},
			{Key: "active", Value: true},
			{Key: "ticket_hash", Value: ticketHash},
			{Key: "ticket_expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
			{Key: "maximum_deadline", Value: bson.D{{Key: "$gt", Value: now}}},
		},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "status", Value: biz.StatusOpen},
				{Key: "connected_at", Value: now},
				{Key: "last_activity_at", Value: now},
				{Key: "ticket_consumed_at", Value: now},
			}},
			{Key: "$unset", Value: bson.D{{Key: "ticket_hash", Value: ""}}},
			{Key: "$inc", Value: bson.D{{Key: "version", Value: 1}}},
		},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.TerminalSession{}, biz.ErrInvalidTicket
	}
	if err != nil {
		return biz.TerminalSession{}, fmt.Errorf("consume terminal ticket: %w", err)
	}
	session := document.domain()
	if err := validateStoredSession(session); err != nil {
		return biz.TerminalSession{}, fmt.Errorf("decode connected terminal session: %w", err)
	}
	return session, nil
}

func duplicateSessionSlot(err error) bool {
	message := err.Error()
	return strings.Contains(message, "uniq_active_terminal_user_slot") ||
		strings.Contains(message, "uniq_active_terminal_target_slot")
}

func validateStoredSession(session biz.TerminalSession) error {
	if session.TicketHash == "" {
		placeholder := session
		placeholder.TicketHash = "0000000000000000000000000000000000000000000000000000000000000000"
		return placeholder.Validate()
	}
	return session.Validate()
}

type policyDocument struct {
	ID                   string          `bson:"_id"`
	Scope                biz.PolicyScope `bson:"scope"`
	OrganizationID       string          `bson:"organization_id"`
	ProjectID            string          `bson:"project_id,omitempty"`
	Enabled              bool            `bson:"enabled"`
	AllowedRoles         []security.Role `bson:"allowed_roles"`
	EnvironmentStages    []string        `bson:"environment_stages,omitempty"`
	RuntimeTargetIDs     []string        `bson:"runtime_target_ids,omitempty"`
	ManagedHostIDs       []string        `bson:"managed_host_ids,omitempty"`
	IdleTimeoutNanos     int64           `bson:"idle_timeout_nanos"`
	MaximumDurationNanos int64           `bson:"maximum_duration_nanos"`
	MaximumPerUser       int             `bson:"maximum_per_user"`
	MaximumPerTarget     int             `bson:"maximum_per_target"`
	RevocationGraceNanos int64           `bson:"revocation_grace_nanos"`
	Version              uint64          `bson:"version"`
	CreatedBy            string          `bson:"created_by"`
	CreatedAt            time.Time       `bson:"created_at"`
	UpdatedBy            string          `bson:"updated_by"`
	UpdatedAt            time.Time       `bson:"updated_at"`
}

func policyDocumentFromDomain(policy biz.AccessPolicy) policyDocument {
	return policyDocument{
		ID: policy.ID, Scope: policy.Scope, OrganizationID: policy.OrganizationID,
		ProjectID: policy.ProjectID, Enabled: policy.Enabled, AllowedRoles: policy.AllowedRoles,
		EnvironmentStages: policy.EnvironmentStages, RuntimeTargetIDs: policy.RuntimeTargetIDs,
		ManagedHostIDs: policy.ManagedHostIDs, IdleTimeoutNanos: int64(policy.IdleTimeout),
		MaximumDurationNanos: int64(policy.MaximumDuration), MaximumPerUser: policy.MaximumPerUser,
		MaximumPerTarget: policy.MaximumPerTarget, RevocationGraceNanos: int64(policy.RevocationGracePeriod),
		Version: policy.Version, CreatedBy: policy.CreatedBy, CreatedAt: policy.CreatedAt,
		UpdatedBy: policy.UpdatedBy, UpdatedAt: policy.UpdatedAt,
	}
}

func (document policyDocument) domain() biz.AccessPolicy {
	return biz.AccessPolicy{
		ID: document.ID, Scope: document.Scope, OrganizationID: document.OrganizationID,
		ProjectID: document.ProjectID, Enabled: document.Enabled, AllowedRoles: document.AllowedRoles,
		EnvironmentStages: document.EnvironmentStages, RuntimeTargetIDs: document.RuntimeTargetIDs,
		ManagedHostIDs: document.ManagedHostIDs, IdleTimeout: time.Duration(document.IdleTimeoutNanos),
		MaximumDuration: time.Duration(document.MaximumDurationNanos), MaximumPerUser: document.MaximumPerUser,
		MaximumPerTarget: document.MaximumPerTarget, RevocationGracePeriod: time.Duration(document.RevocationGraceNanos),
		Version: document.Version, CreatedBy: document.CreatedBy, CreatedAt: document.CreatedAt,
		UpdatedBy: document.UpdatedBy, UpdatedAt: document.UpdatedAt,
	}
}

type sessionDocument struct {
	ID                      string             `bson:"_id"`
	OrganizationID          string             `bson:"organization_id"`
	ProjectID               string             `bson:"project_id,omitempty"`
	Kind                    biz.Kind           `bson:"kind"`
	ActorID                 string             `bson:"actor_id"`
	AuthenticationSessionID string             `bson:"authentication_session_id"`
	ManagedHostID           string             `bson:"managed_host_id"`
	RuntimeTargetID         string             `bson:"runtime_target_id,omitempty"`
	DeploymentID            string             `bson:"deployment_id,omitempty"`
	RunningInstanceID       string             `bson:"running_instance_id,omitempty"`
	InstanceGeneration      uint64             `bson:"instance_generation,omitempty"`
	TargetScope             string             `bson:"target_scope"`
	Status                  biz.SessionStatus  `bson:"status"`
	ConnectionMode          runtimeaccess.Mode `bson:"connection_mode"`
	CreatedAt               time.Time          `bson:"created_at"`
	ConnectedAt             time.Time          `bson:"connected_at,omitempty"`
	LastActivityAt          time.Time          `bson:"last_activity_at"`
	EndedAt                 time.Time          `bson:"ended_at,omitempty"`
	IdleDeadline            time.Time          `bson:"idle_deadline"`
	MaximumDeadline         time.Time          `bson:"maximum_deadline"`
	TicketHash              string             `bson:"ticket_hash,omitempty"`
	TicketExpiresAt         time.Time          `bson:"ticket_expires_at"`
	TicketConsumedAt        time.Time          `bson:"ticket_consumed_at,omitempty"`
	ClientIP                string             `bson:"client_ip"`
	UserAgent               string             `bson:"user_agent"`
	RequestID               string             `bson:"request_id"`
	CloseReason             biz.CloseReason    `bson:"close_reason,omitempty"`
	SafeErrorCode           string             `bson:"safe_error_code,omitempty"`
	UserConcurrencySlot     int                `bson:"user_concurrency_slot"`
	TargetConcurrencySlot   int                `bson:"target_concurrency_slot"`
	Active                  bool               `bson:"active"`
	Version                 uint64             `bson:"version"`
}

func sessionDocumentFromDomain(session biz.TerminalSession) sessionDocument {
	return sessionDocument{
		ID: session.ID, OrganizationID: session.OrganizationID, ProjectID: session.ProjectID,
		Kind: session.Kind, ActorID: session.ActorID, ManagedHostID: session.ManagedHostID,
		AuthenticationSessionID: session.AuthenticationSessionID,
		RuntimeTargetID:         session.RuntimeTargetID, DeploymentID: session.DeploymentID,
		RunningInstanceID: session.RunningInstanceID, InstanceGeneration: session.InstanceGeneration,
		TargetScope: session.TargetScope(), Status: session.Status, ConnectionMode: session.ConnectionMode,
		CreatedAt: session.CreatedAt, ConnectedAt: session.ConnectedAt, LastActivityAt: session.LastActivityAt,
		EndedAt: session.EndedAt, IdleDeadline: session.IdleDeadline, MaximumDeadline: session.MaximumDeadline,
		TicketHash: session.TicketHash, TicketExpiresAt: session.TicketExpiresAt,
		TicketConsumedAt: session.TicketConsumedAt, ClientIP: session.ClientIP,
		UserAgent: session.UserAgent, RequestID: session.RequestID, CloseReason: session.CloseReason,
		SafeErrorCode: session.SafeErrorCode, UserConcurrencySlot: session.UserConcurrencySlot,
		TargetConcurrencySlot: session.TargetConcurrencySlot, Active: session.Active, Version: session.Version,
	}
}

func (document sessionDocument) domain() biz.TerminalSession {
	return biz.TerminalSession{
		ID: document.ID, OrganizationID: document.OrganizationID, ProjectID: document.ProjectID,
		Kind: document.Kind, ActorID: document.ActorID, ManagedHostID: document.ManagedHostID,
		AuthenticationSessionID: document.AuthenticationSessionID,
		RuntimeTargetID:         document.RuntimeTargetID, DeploymentID: document.DeploymentID,
		RunningInstanceID: document.RunningInstanceID, InstanceGeneration: document.InstanceGeneration,
		Status: document.Status, ConnectionMode: document.ConnectionMode, CreatedAt: document.CreatedAt,
		ConnectedAt: document.ConnectedAt, LastActivityAt: document.LastActivityAt, EndedAt: document.EndedAt,
		IdleDeadline: document.IdleDeadline, MaximumDeadline: document.MaximumDeadline,
		TicketHash: document.TicketHash, TicketExpiresAt: document.TicketExpiresAt,
		TicketConsumedAt: document.TicketConsumedAt, ClientIP: document.ClientIP,
		UserAgent: document.UserAgent, RequestID: document.RequestID, CloseReason: document.CloseReason,
		SafeErrorCode: document.SafeErrorCode, UserConcurrencySlot: document.UserConcurrencySlot,
		TargetConcurrencySlot: document.TargetConcurrencySlot, Active: document.Active, Version: document.Version,
	}
}

var _ biz.PolicyRepository = (*MongoRepository)(nil)
var _ biz.SessionRepository = (*MongoRepository)(nil)
