package data

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoRepository struct {
	hosts       *mongo.Collection
	enrollments *mongo.Collection
	identities  *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		hosts:       database.Collection("managed_hosts"),
		enrollments: database.Collection("agent_enrollments"),
		identities:  database.Collection("agent_identities"),
	}
}

func (r *MongoRepository) List(
	ctx context.Context,
	organizationID string,
) ([]biz.ManagedHost, error) {
	cursor, err := r.hosts.Find(
		ctx,
		bson.D{{Key: "organization_id", Value: organizationID}},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}, {Key: "_id", Value: 1}}),
	)
	if err != nil {
		return nil, fmt.Errorf("find managed hosts: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var documents []hostDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode managed hosts: %w", err)
	}
	items := make([]biz.ManagedHost, len(documents))
	for index, document := range documents {
		items[index] = document.domain()
	}
	return items, nil
}

func (r *MongoRepository) Get(
	ctx context.Context,
	organizationID, hostID string,
) (biz.ManagedHost, error) {
	var document hostDocument
	err := r.hosts.FindOne(ctx, bson.D{
		{Key: "_id", Value: hostID},
		{Key: "organization_id", Value: organizationID},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.ManagedHost{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.ManagedHost{}, fmt.Errorf("find managed host: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) Create(
	ctx context.Context,
	item biz.ManagedHost,
) (biz.ManagedHost, error) {
	_, err := r.hosts.InsertOne(ctx, hostDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		return biz.ManagedHost{}, biz.ErrDuplicateName
	}
	if err != nil {
		return biz.ManagedHost{}, fmt.Errorf("insert managed host: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) Disable(
	ctx context.Context,
	organizationID, hostID string,
	now time.Time,
) (biz.ManagedHost, error) {
	var document hostDocument
	err := r.hosts.FindOneAndUpdate(
		ctx,
		bson.D{
			{Key: "_id", Value: hostID},
			{Key: "organization_id", Value: organizationID},
		},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "status", Value: biz.StatusDisabled},
				{Key: "updated_at", Value: now},
			}},
			{Key: "$unset", Value: bson.D{
				{Key: "agent_boot_id", Value: ""},
				{Key: "agent_session_id", Value: ""},
			}},
		},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.ManagedHost{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.ManagedHost{}, fmt.Errorf("disable managed host: %w", err)
	}
	if document.AgentIdentityID != "" {
		if _, err := r.identities.UpdateOne(
			ctx,
			bson.D{
				{Key: "_id", Value: document.AgentIdentityID},
				{Key: "organization_id", Value: organizationID},
				{Key: "managed_host_id", Value: hostID},
				{Key: "revoked_at", Value: bson.D{{Key: "$exists", Value: false}}},
			},
			bson.D{{Key: "$set", Value: bson.D{{Key: "revoked_at", Value: now}}}},
		); err != nil {
			return biz.ManagedHost{}, fmt.Errorf("revoke managed host agent identity: %w", err)
		}
	}
	if _, err := r.enrollments.UpdateMany(
		ctx,
		bson.D{
			{Key: "managed_host_id", Value: hostID},
			{Key: "consumed_at", Value: bson.D{{Key: "$exists", Value: false}}},
			{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
		},
		bson.D{{Key: "$set", Value: bson.D{{Key: "expires_at", Value: now}}}},
	); err != nil {
		return biz.ManagedHost{}, fmt.Errorf("expire managed host enrollments: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) ConnectionMode(
	ctx context.Context,
	organizationID, hostID string,
) (runtimeaccess.Mode, bool, error) {
	var document struct {
		ConnectionMode runtimeaccess.Mode `bson:"connection_mode"`
	}
	err := r.hosts.FindOne(ctx, bson.D{
		{Key: "_id", Value: hostID},
		{Key: "organization_id", Value: organizationID},
		{Key: "status", Value: bson.D{{Key: "$ne", Value: biz.StatusDisabled}}},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("find managed host connection mode: %w", err)
	}
	return document.ConnectionMode, true, nil
}

func (r *MongoRepository) CreateEnrollment(
	ctx context.Context,
	item biz.Enrollment,
) error {
	if _, err := r.enrollments.UpdateMany(
		ctx,
		bson.D{
			{Key: "managed_host_id", Value: item.ManagedHostID},
			{Key: "consumed_at", Value: bson.D{{Key: "$exists", Value: false}}},
			{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: item.CreatedAt}}},
		},
		bson.D{{Key: "$set", Value: bson.D{{Key: "expires_at", Value: item.CreatedAt}}}},
	); err != nil {
		return fmt.Errorf("expire previous agent enrollments: %w", err)
	}
	_, err := r.enrollments.InsertOne(ctx, enrollmentDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		return biz.ErrInvalidEnrollment
	}
	if err != nil {
		return fmt.Errorf("insert agent enrollment: %w", err)
	}
	return nil
}

func (r *MongoRepository) FindAvailableEnrollment(
	ctx context.Context,
	tokenHash string,
	now time.Time,
) (biz.Enrollment, error) {
	var document enrollmentDocument
	err := r.enrollments.FindOne(ctx, bson.D{
		{Key: "token_hash", Value: tokenHash},
		{Key: "consumed_at", Value: bson.D{{Key: "$exists", Value: false}}},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.Enrollment{}, biz.ErrInvalidEnrollment
	}
	if err != nil {
		return biz.Enrollment{}, fmt.Errorf("find agent enrollment: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) ActivateAgent(
	ctx context.Context,
	enrollmentID, tokenHash string,
	now time.Time,
	identity biz.AgentIdentity,
) error {
	result := r.enrollments.FindOneAndUpdate(
		ctx,
		bson.D{
			{Key: "_id", Value: enrollmentID},
			{Key: "token_hash", Value: tokenHash},
			{Key: "organization_id", Value: identity.OrganizationID},
			{Key: "managed_host_id", Value: identity.ManagedHostID},
			{Key: "consumed_at", Value: bson.D{{Key: "$exists", Value: false}}},
			{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
		},
		bson.D{{Key: "$set", Value: bson.D{{Key: "consumed_at", Value: now}}}},
	)
	if err := result.Err(); err == mongo.ErrNoDocuments {
		return biz.ErrInvalidEnrollment
	} else if err != nil {
		return fmt.Errorf("consume agent enrollment: %w", err)
	}
	if _, err := r.identities.InsertOne(
		ctx, identityDocumentFromDomain(identity),
	); mongo.IsDuplicateKeyError(err) {
		return biz.ErrInvalidEnrollment
	} else if err != nil {
		return fmt.Errorf("insert agent identity: %w", err)
	}
	update := r.hosts.FindOneAndUpdate(
		ctx,
		bson.D{
			{Key: "_id", Value: identity.ManagedHostID},
			{Key: "organization_id", Value: identity.OrganizationID},
			{Key: "connection_mode", Value: runtimeaccess.ModeAgent},
			{Key: "status", Value: bson.D{{Key: "$ne", Value: biz.StatusDisabled}}},
			{Key: "agent_identity_id", Value: bson.D{{Key: "$exists", Value: false}}},
		},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "agent_identity_id", Value: identity.ID},
			{Key: "agent_instance_id", Value: identity.InstanceID},
			{Key: "agent_certificate_expires_at", Value: identity.CertificateExpires},
			{Key: "status", Value: biz.StatusOffline},
			{Key: "agent_version", Value: identity.AgentVersion},
			{Key: "protocol_version", Value: identity.ProtocolVersion},
			{Key: "capabilities", Value: identity.Capabilities},
			{Key: "updated_at", Value: now},
		}}},
	)
	if err := update.Err(); err == mongo.ErrNoDocuments {
		return biz.ErrInvalidEnrollment
	} else if err != nil {
		return fmt.Errorf("activate managed host agent identity: %w", err)
	}
	return nil
}

func (r *MongoRepository) AuthenticateAgent(
	ctx context.Context,
	certificate biz.AgentCertificateIdentity,
	now time.Time,
) (biz.AgentIdentity, error) {
	var document identityDocument
	err := r.identities.FindOne(ctx, bson.D{
		{Key: "_id", Value: certificate.IdentityID},
		{Key: "organization_id", Value: certificate.OrganizationID},
		{Key: "managed_host_id", Value: certificate.ManagedHostID},
		{Key: "instance_id", Value: certificate.InstanceID},
		{Key: "certificate_serial", Value: certificate.CertificateSerial},
		{Key: "certificate_sha256", Value: certificate.CertificateSHA256},
		{Key: "certificate_expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
		{Key: "revoked_at", Value: bson.D{{Key: "$exists", Value: false}}},
	}).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.AgentIdentity{}, biz.ErrInvalidAgentIdentity
	}
	if err != nil {
		return biz.AgentIdentity{}, fmt.Errorf("authenticate agent identity: %w", err)
	}
	return document.domain(), nil
}

func (r *MongoRepository) ConnectAgent(
	ctx context.Context,
	session biz.AgentSession,
	now time.Time,
) error {
	result := r.hosts.FindOneAndUpdate(
		ctx,
		bson.D{
			{Key: "_id", Value: session.ManagedHostID},
			{Key: "organization_id", Value: session.OrganizationID},
			{Key: "connection_mode", Value: runtimeaccess.ModeAgent},
			{Key: "agent_identity_id", Value: session.IdentityID},
			{Key: "agent_instance_id", Value: session.InstanceID},
			{Key: "status", Value: bson.D{{Key: "$ne", Value: biz.StatusDisabled}}},
		},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "status", Value: biz.StatusOnline},
			{Key: "agent_boot_id", Value: session.BootID},
			{Key: "agent_session_id", Value: session.ID},
			{Key: "agent_version", Value: session.AgentVersion},
			{Key: "protocol_version", Value: session.ProtocolVersion},
			{Key: "capabilities", Value: session.Capabilities},
			{Key: "last_seen_at", Value: now},
			{Key: "updated_at", Value: now},
		}}},
	)
	if err := result.Err(); err == mongo.ErrNoDocuments {
		return biz.ErrInvalidAgentIdentity
	} else if err != nil {
		return fmt.Errorf("connect managed host agent: %w", err)
	}
	return nil
}

func (r *MongoRepository) HeartbeatAgent(
	ctx context.Context,
	session biz.AgentSession,
	now time.Time,
) error {
	result, err := r.hosts.UpdateOne(
		ctx,
		bson.D{
			{Key: "_id", Value: session.ManagedHostID},
			{Key: "organization_id", Value: session.OrganizationID},
			{Key: "agent_identity_id", Value: session.IdentityID},
			{Key: "agent_instance_id", Value: session.InstanceID},
			{Key: "agent_session_id", Value: session.ID},
			{Key: "status", Value: biz.StatusOnline},
		},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "last_seen_at", Value: now},
			{Key: "updated_at", Value: now},
		}}},
	)
	if err != nil {
		return fmt.Errorf("heartbeat managed host agent: %w", err)
	}
	if result.MatchedCount == 0 {
		return biz.ErrInvalidAgentIdentity
	}
	return nil
}

func (r *MongoRepository) DisconnectAgent(
	ctx context.Context,
	session biz.AgentSession,
	now time.Time,
) (bool, error) {
	result, err := r.hosts.UpdateOne(
		ctx,
		bson.D{
			{Key: "_id", Value: session.ManagedHostID},
			{Key: "organization_id", Value: session.OrganizationID},
			{Key: "agent_identity_id", Value: session.IdentityID},
			{Key: "agent_instance_id", Value: session.InstanceID},
			{Key: "agent_session_id", Value: session.ID},
			{Key: "status", Value: biz.StatusOnline},
		},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "status", Value: biz.StatusOffline},
				{Key: "updated_at", Value: now},
			}},
			{Key: "$unset", Value: bson.D{
				{Key: "agent_boot_id", Value: ""},
				{Key: "agent_session_id", Value: ""},
			}},
		},
	)
	if err != nil {
		return false, fmt.Errorf("disconnect managed host agent: %w", err)
	}
	return result.ModifiedCount == 1, nil
}

type hostDocument struct {
	ID                        string             `bson:"_id"`
	OrganizationID            string             `bson:"organization_id"`
	Name                      string             `bson:"name"`
	NameNormalized            string             `bson:"name_normalized"`
	Status                    biz.Status         `bson:"status"`
	ConnectionMode            runtimeaccess.Mode `bson:"connection_mode"`
	AgentIdentityID           string             `bson:"agent_identity_id,omitempty"`
	AgentInstanceID           string             `bson:"agent_instance_id,omitempty"`
	AgentCertificateExpiresAt time.Time          `bson:"agent_certificate_expires_at,omitempty"`
	AgentBootID               string             `bson:"agent_boot_id,omitempty"`
	AgentSessionID            string             `bson:"agent_session_id,omitempty"`
	DirectSSHRef              string             `bson:"direct_ssh_ref,omitempty"`
	LastSeenAt                time.Time          `bson:"last_seen_at,omitempty"`
	AgentVersion              string             `bson:"agent_version,omitempty"`
	ProtocolVersion           string             `bson:"protocol_version,omitempty"`
	Capabilities              []string           `bson:"capabilities"`
	CreatedBy                 string             `bson:"created_by"`
	CreatedAt                 time.Time          `bson:"created_at"`
	UpdatedAt                 time.Time          `bson:"updated_at"`
}

type enrollmentDocument struct {
	ID             string    `bson:"_id"`
	OrganizationID string    `bson:"organization_id"`
	ManagedHostID  string    `bson:"managed_host_id"`
	TokenHash      string    `bson:"token_hash"`
	ExpiresAt      time.Time `bson:"expires_at"`
	ConsumedAt     time.Time `bson:"consumed_at,omitempty"`
	CreatedBy      string    `bson:"created_by"`
	CreatedAt      time.Time `bson:"created_at"`
}

func enrollmentDocumentFromDomain(item biz.Enrollment) enrollmentDocument {
	return enrollmentDocument{
		ID: item.ID, OrganizationID: item.OrganizationID,
		ManagedHostID: item.ManagedHostID, TokenHash: item.TokenHash,
		ExpiresAt: item.ExpiresAt, ConsumedAt: item.ConsumedAt,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt,
	}
}

func (d enrollmentDocument) domain() biz.Enrollment {
	return biz.Enrollment{
		ID: d.ID, OrganizationID: d.OrganizationID,
		ManagedHostID: d.ManagedHostID, TokenHash: d.TokenHash,
		ExpiresAt: d.ExpiresAt, ConsumedAt: d.ConsumedAt,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt,
	}
}

type identityDocument struct {
	ID                 string    `bson:"_id"`
	OrganizationID     string    `bson:"organization_id"`
	ManagedHostID      string    `bson:"managed_host_id"`
	InstanceID         string    `bson:"instance_id"`
	CertificateSerial  string    `bson:"certificate_serial"`
	CertificateSHA256  string    `bson:"certificate_sha256"`
	CertificateExpires time.Time `bson:"certificate_expires_at"`
	AgentVersion       string    `bson:"agent_version"`
	ProtocolVersion    string    `bson:"protocol_version"`
	Capabilities       []string  `bson:"capabilities"`
	IssuedAt           time.Time `bson:"issued_at"`
	RevokedAt          time.Time `bson:"revoked_at,omitempty"`
}

func identityDocumentFromDomain(item biz.AgentIdentity) identityDocument {
	return identityDocument{
		ID: item.ID, OrganizationID: item.OrganizationID,
		ManagedHostID: item.ManagedHostID, InstanceID: item.InstanceID,
		CertificateSerial:  item.CertificateSerial,
		CertificateSHA256:  item.CertificateSHA256,
		CertificateExpires: item.CertificateExpires,
		AgentVersion:       item.AgentVersion, ProtocolVersion: item.ProtocolVersion,
		Capabilities: item.Capabilities, IssuedAt: item.IssuedAt,
		RevokedAt: item.RevokedAt,
	}
}

func (d identityDocument) domain() biz.AgentIdentity {
	capabilities := append([]string(nil), d.Capabilities...)
	if capabilities == nil {
		capabilities = []string{}
	}
	return biz.AgentIdentity{
		ID: d.ID, OrganizationID: d.OrganizationID,
		ManagedHostID: d.ManagedHostID, InstanceID: d.InstanceID,
		CertificateSerial:  d.CertificateSerial,
		CertificateSHA256:  d.CertificateSHA256,
		CertificateExpires: d.CertificateExpires,
		AgentVersion:       d.AgentVersion, ProtocolVersion: d.ProtocolVersion,
		Capabilities: capabilities, IssuedAt: d.IssuedAt,
		RevokedAt: d.RevokedAt,
	}
}

func hostDocumentFromDomain(item biz.ManagedHost) hostDocument {
	return hostDocument{
		ID: item.ID, OrganizationID: item.OrganizationID,
		Name: item.Name, NameNormalized: strings.ToLower(item.Name),
		Status: item.Status, ConnectionMode: item.ConnectionMode,
		AgentIdentityID: item.AgentIdentityID, AgentInstanceID: item.AgentInstanceID,
		AgentCertificateExpiresAt: item.AgentCertificateExpiresAt,
		AgentBootID:               item.AgentBootID, AgentSessionID: item.AgentSessionID,
		DirectSSHRef: item.DirectSSHRef,
		LastSeenAt:   item.LastSeenAt, AgentVersion: item.AgentVersion,
		ProtocolVersion: item.ProtocolVersion, Capabilities: item.Capabilities,
		CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func (d hostDocument) domain() biz.ManagedHost {
	capabilities := make([]string, len(d.Capabilities))
	copy(capabilities, d.Capabilities)
	return biz.ManagedHost{
		ID: d.ID, OrganizationID: d.OrganizationID, Name: d.Name,
		Status: d.Status, ConnectionMode: d.ConnectionMode,
		AgentIdentityID: d.AgentIdentityID, AgentInstanceID: d.AgentInstanceID,
		AgentCertificateExpiresAt: d.AgentCertificateExpiresAt,
		AgentBootID:               d.AgentBootID, AgentSessionID: d.AgentSessionID,
		DirectSSHRef: d.DirectSSHRef,
		LastSeenAt:   d.LastSeenAt, AgentVersion: d.AgentVersion,
		ProtocolVersion: d.ProtocolVersion, Capabilities: capabilities,
		CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}
