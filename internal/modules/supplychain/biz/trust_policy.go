package biz

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

var (
	ErrInvalidSignatureTrustPolicy  = errors.New("signature trust policy is invalid")
	ErrSignatureTrustPolicyConflict = errors.New("signature trust policy version conflicts")
)

type SignatureTrustPolicy struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	Name                 string
	Mode                 SignatureTrustMode
	PublicKeyPEM         string
	PublicKeyFingerprint string
	TrustedRootID        string
	TrustedRootHash      string
	CertificateIdentity  string
	OIDCIssuer           string
	Enabled              bool
	Version              uint64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type SignatureTrustPolicyInput struct {
	ID                  string
	OrganizationID      string
	ProjectID           string
	Name                string
	Mode                SignatureTrustMode
	PublicKeyPEM        string
	TrustedRootID       string
	TrustedRootHash     string
	CertificateIdentity string
	OIDCIssuer          string
	Enabled             bool
	Version             uint64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func NewSignatureTrustPolicy(input SignatureTrustPolicyInput) (SignatureTrustPolicy, error) {
	item := SignatureTrustPolicy{
		ID: strings.TrimSpace(input.ID), OrganizationID: strings.TrimSpace(input.OrganizationID),
		ProjectID: strings.TrimSpace(input.ProjectID), Name: strings.TrimSpace(input.Name), Mode: input.Mode,
		TrustedRootID: strings.TrimSpace(input.TrustedRootID), TrustedRootHash: strings.TrimSpace(input.TrustedRootHash),
		CertificateIdentity: strings.TrimSpace(input.CertificateIdentity), OIDCIssuer: strings.TrimSpace(input.OIDCIssuer),
		Enabled: input.Enabled, Version: input.Version,
		CreatedAt: input.CreatedAt.UTC(), UpdatedAt: input.UpdatedAt.UTC(),
	}
	switch item.Mode {
	case SignatureTrustPublicKey:
		canonical, fingerprint, err := NormalizeSignaturePublicKey([]byte(input.PublicKeyPEM))
		if err != nil || item.TrustedRootID != "" || item.TrustedRootHash != "" ||
			item.CertificateIdentity != "" || item.OIDCIssuer != "" {
			return SignatureTrustPolicy{}, ErrInvalidSignatureTrustPolicy
		}
		item.PublicKeyPEM, item.PublicKeyFingerprint = string(canonical), fingerprint
	case SignatureTrustKeyless:
		issuer, err := url.Parse(item.OIDCIssuer)
		if input.PublicKeyPEM != "" || !validID(item.TrustedRootID) || !validDigest(item.TrustedRootHash) ||
			!validText(item.CertificateIdentity, 1024) || err != nil || issuer.Scheme != "https" ||
			issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" ||
			issuer.String() != item.OIDCIssuer {
			return SignatureTrustPolicy{}, ErrInvalidSignatureTrustPolicy
		}
	default:
		return SignatureTrustPolicy{}, ErrInvalidSignatureTrustPolicy
	}
	if !validID(item.ID) || !validID(item.OrganizationID) || !validID(item.ProjectID) ||
		!validText(item.Name, 100) || item.Version == 0 || item.CreatedAt.IsZero() ||
		item.UpdatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) {
		return SignatureTrustPolicy{}, ErrInvalidSignatureTrustPolicy
	}
	return item, nil
}

type SignatureTrustSnapshot struct {
	PolicyID             string
	PolicyVersion        uint64
	Mode                 SignatureTrustMode
	PublicKeyPEM         string
	PublicKeyFingerprint string
	TrustedRootID        string
	TrustedRootHash      string
	CertificateIdentity  string
	OIDCIssuer           string
}

func (s SignatureTrustSnapshot) Empty() bool {
	return s == (SignatureTrustSnapshot{})
}

func (p SignatureTrustPolicy) Snapshot() (SignatureTrustSnapshot, error) {
	normalized, err := NewSignatureTrustPolicy(signatureTrustPolicyInputFromDomain(p))
	if err != nil || !normalized.Enabled {
		return SignatureTrustSnapshot{}, ErrInvalidSignatureTrustPolicy
	}
	return SignatureTrustSnapshot{
		PolicyID: normalized.ID, PolicyVersion: normalized.Version, Mode: normalized.Mode,
		PublicKeyPEM: normalized.PublicKeyPEM, PublicKeyFingerprint: normalized.PublicKeyFingerprint,
		TrustedRootID: normalized.TrustedRootID, TrustedRootHash: normalized.TrustedRootHash,
		CertificateIdentity: normalized.CertificateIdentity, OIDCIssuer: normalized.OIDCIssuer,
	}, nil
}

func (s SignatureTrustSnapshot) Validate() error {
	if !validID(s.PolicyID) || s.PolicyVersion == 0 {
		return ErrInvalidSignatureTrustPolicy
	}
	policy := SignatureTrustPolicyInput{
		ID: s.PolicyID, OrganizationID: "snapshot-organization", ProjectID: "snapshot-project",
		Name: "snapshot", Mode: s.Mode, PublicKeyPEM: s.PublicKeyPEM,
		TrustedRootID: s.TrustedRootID, TrustedRootHash: s.TrustedRootHash,
		CertificateIdentity: s.CertificateIdentity, OIDCIssuer: s.OIDCIssuer,
		Enabled: true, Version: s.PolicyVersion, CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0),
	}
	item, err := NewSignatureTrustPolicy(policy)
	if err != nil || item.PublicKeyFingerprint != s.PublicKeyFingerprint {
		return ErrInvalidSignatureTrustPolicy
	}
	return nil
}

type SignatureTrustPolicyRepository interface {
	CreateSignatureTrustPolicy(context.Context, SignatureTrustPolicy) (SignatureTrustPolicy, error)
	ListSignatureTrustPolicies(context.Context, string) ([]SignatureTrustPolicy, error)
	GetSignatureTrustPolicy(context.Context, string, string) (SignatureTrustPolicy, error)
	SaveSignatureTrustPolicy(context.Context, SignatureTrustPolicy, uint64) (SignatureTrustPolicy, error)
}

type SignatureTrustPolicyUseCase struct {
	projects    ProjectLookup
	policies    SignatureTrustPolicyRepository
	newID       func() (string, error)
	now         func() time.Time
	transaction transaction.Manager
	auditor     sharedaudit.Recorder
}

func (u *SignatureTrustPolicyUseCase) WithAudit(manager transaction.Manager,
	auditor sharedaudit.Recorder) *SignatureTrustPolicyUseCase {
	u.transaction, u.auditor = manager, auditor
	return u
}

func NewSignatureTrustPolicyUseCase(projects ProjectLookup, policies SignatureTrustPolicyRepository,
	newID func() (string, error), now func() time.Time) (*SignatureTrustPolicyUseCase, error) {
	if projects == nil || policies == nil || newID == nil || now == nil {
		return nil, ErrUnavailable
	}
	return &SignatureTrustPolicyUseCase{projects: projects, policies: policies, newID: newID, now: now}, nil
}

func (u *SignatureTrustPolicyUseCase) Create(ctx context.Context, principal security.Principal,
	projectID string, input SignatureTrustPolicyInput) (SignatureTrustPolicy, error) {
	if err := principal.Require(security.PermissionSignatureTrustPolicyWrite); err != nil {
		return SignatureTrustPolicy{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SignatureTrustPolicy{}, err
	}
	id, err := u.newID()
	if err != nil {
		return SignatureTrustPolicy{}, err
	}
	now := u.now().UTC()
	input.ID, input.OrganizationID, input.ProjectID = id, principal.OrganizationID, strings.TrimSpace(projectID)
	input.Version, input.CreatedAt, input.UpdatedAt = 1, now, now
	item, err := NewSignatureTrustPolicy(input)
	if err != nil {
		return SignatureTrustPolicy{}, err
	}
	if u.transaction == nil || u.auditor == nil {
		return u.policies.CreateSignatureTrustPolicy(ctx, item)
	}
	var created SignatureTrustPolicy
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var createErr error
		created, createErr = u.policies.CreateSignatureTrustPolicy(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		auditID, auditErr := u.newID()
		if auditErr != nil {
			return auditErr
		}
		return u.auditor.Record(transactionContext, sharedaudit.Event{ID: auditID,
			OrganizationID: principal.OrganizationID, ProjectID: item.ProjectID, ActorID: principal.UserID,
			Action: "signature_trust_policy.create", ResourceType: "signature_trust_policy",
			ResourceID: item.ID, CreatedAt: now})
	})
	return created, err
}

func (u *SignatureTrustPolicyUseCase) List(ctx context.Context, principal security.Principal,
	projectID string) ([]SignatureTrustPolicy, error) {
	if err := principal.Require(security.PermissionSignatureTrustPolicyRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.policies.ListSignatureTrustPolicies(ctx, strings.TrimSpace(projectID))
}

func (u *SignatureTrustPolicyUseCase) Get(ctx context.Context, principal security.Principal,
	projectID, policyID string) (SignatureTrustPolicy, error) {
	if err := principal.Require(security.PermissionSignatureTrustPolicyRead); err != nil {
		return SignatureTrustPolicy{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SignatureTrustPolicy{}, err
	}
	if !validID(strings.TrimSpace(policyID)) {
		return SignatureTrustPolicy{}, ErrInvalidSignatureTrustPolicy
	}
	return u.policies.GetSignatureTrustPolicy(ctx, strings.TrimSpace(projectID), strings.TrimSpace(policyID))
}

func (u *SignatureTrustPolicyUseCase) Update(ctx context.Context, principal security.Principal,
	projectID, policyID string, expectedVersion uint64,
	input SignatureTrustPolicyInput) (SignatureTrustPolicy, error) {
	if err := principal.Require(security.PermissionSignatureTrustPolicyWrite); err != nil {
		return SignatureTrustPolicy{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SignatureTrustPolicy{}, err
	}
	current, err := u.policies.GetSignatureTrustPolicy(ctx, strings.TrimSpace(projectID), strings.TrimSpace(policyID))
	if err != nil {
		return SignatureTrustPolicy{}, err
	}
	if expectedVersion == 0 || current.Version != expectedVersion {
		return SignatureTrustPolicy{}, ErrSignatureTrustPolicyConflict
	}
	input.ID, input.OrganizationID, input.ProjectID = current.ID, current.OrganizationID, current.ProjectID
	input.Version, input.CreatedAt, input.UpdatedAt = current.Version+1, current.CreatedAt, u.now().UTC()
	updated, err := NewSignatureTrustPolicy(input)
	if err != nil {
		return SignatureTrustPolicy{}, err
	}
	if u.transaction == nil || u.auditor == nil {
		return u.policies.SaveSignatureTrustPolicy(ctx, updated, expectedVersion)
	}
	var saved SignatureTrustPolicy
	err = u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var saveErr error
		saved, saveErr = u.policies.SaveSignatureTrustPolicy(transactionContext, updated, expectedVersion)
		if saveErr != nil {
			return saveErr
		}
		auditID, auditErr := u.newID()
		if auditErr != nil {
			return auditErr
		}
		return u.auditor.Record(transactionContext, sharedaudit.Event{ID: auditID,
			OrganizationID: principal.OrganizationID, ProjectID: updated.ProjectID, ActorID: principal.UserID,
			Action: "signature_trust_policy.update", ResourceType: "signature_trust_policy",
			ResourceID: updated.ID, CreatedAt: updated.UpdatedAt})
	})
	return saved, err
}

func (u *SignatureTrustPolicyUseCase) requireProject(ctx context.Context, principal security.Principal,
	projectID string) error {
	projectID = strings.TrimSpace(projectID)
	if !validID(projectID) {
		return ErrInvalidSignatureTrustPolicy
	}
	exists, err := u.projects.ProjectExists(ctx, principal.OrganizationID, projectID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func signatureTrustPolicyInputFromDomain(item SignatureTrustPolicy) SignatureTrustPolicyInput {
	return SignatureTrustPolicyInput{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		Name: item.Name, Mode: item.Mode, PublicKeyPEM: item.PublicKeyPEM,
		TrustedRootID: item.TrustedRootID, TrustedRootHash: item.TrustedRootHash,
		CertificateIdentity: item.CertificateIdentity, OIDCIssuer: item.OIDCIssuer,
		Enabled: item.Enabled, Version: item.Version, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}
