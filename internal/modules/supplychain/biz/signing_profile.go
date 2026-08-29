package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

var (
	ErrInvalidSigningProfile  = errors.New("signature signing profile is invalid")
	ErrSigningProfileConflict = errors.New("signature signing profile version conflicts")
)

type SignatureJobOperation string

const (
	SignatureOperationVerify        SignatureJobOperation = "verify"
	SignatureOperationSignAndVerify SignatureJobOperation = "sign_and_verify"
)

func (o SignatureJobOperation) Valid() bool {
	return o == SignatureOperationVerify || o == SignatureOperationSignAndVerify
}

func SignatureSigningIdempotencyKey(artifactID string, profile SignatureSigningSnapshot,
	policy SignatureTrustSnapshot) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(artifactID) + "\x00sign-and-verify\x00" +
		profile.ProfileID + "\x00" + strconv.FormatUint(profile.ProfileVersion, 10) + "\x00" +
		policy.PolicyID + "\x00" + strconv.FormatUint(policy.PolicyVersion, 10) + "\x003.0.6"))
	return "signature-" + hex.EncodeToString(digest[:])
}

type SignatureSigningProfile struct {
	ID                      string
	OrganizationID          string
	ProjectID               string
	Name                    string
	Provider                SigningKeyProvider
	KeyReference            string
	KeyReferenceFingerprint string
	TrustPolicyID           string
	Enabled                 bool
	Version                 uint64
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type SignatureSigningProfileInput struct {
	ID             string
	OrganizationID string
	ProjectID      string
	Name           string
	KeyReference   string
	TrustPolicyID  string
	Enabled        bool
	Version        uint64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func NewSignatureSigningProfile(input SignatureSigningProfileInput) (SignatureSigningProfile, error) {
	provider, err := ParseSigningKeyReference(input.KeyReference)
	item := SignatureSigningProfile{ID: strings.TrimSpace(input.ID),
		OrganizationID: strings.TrimSpace(input.OrganizationID), ProjectID: strings.TrimSpace(input.ProjectID),
		Name: strings.TrimSpace(input.Name), Provider: provider, KeyReference: strings.TrimSpace(input.KeyReference),
		KeyReferenceFingerprint: SigningKeyReferenceFingerprint(input.KeyReference),
		TrustPolicyID:           strings.TrimSpace(input.TrustPolicyID), Enabled: input.Enabled, Version: input.Version,
		CreatedAt: input.CreatedAt.UTC(), UpdatedAt: input.UpdatedAt.UTC()}
	if err != nil || !validID(item.ID) || !validID(item.OrganizationID) || !validID(item.ProjectID) ||
		!validText(item.Name, 100) || !validID(item.TrustPolicyID) || item.Version == 0 ||
		item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) {
		return SignatureSigningProfile{}, ErrInvalidSigningProfile
	}
	return item, nil
}

type SignatureSigningSnapshot struct {
	ProfileID               string
	ProfileVersion          uint64
	Provider                SigningKeyProvider
	KeyReference            string
	KeyReferenceFingerprint string
	TrustPolicyID           string
}

func (s SignatureSigningSnapshot) Empty() bool { return s == (SignatureSigningSnapshot{}) }

func (s SignatureSigningSnapshot) Validate() error {
	provider, err := ParseSigningKeyReference(s.KeyReference)
	if err != nil || !validID(s.ProfileID) || s.ProfileVersion == 0 || provider != s.Provider ||
		SigningKeyReferenceFingerprint(s.KeyReference) != s.KeyReferenceFingerprint || !validID(s.TrustPolicyID) {
		return ErrInvalidSigningProfile
	}
	return nil
}

func (p SignatureSigningProfile) Snapshot() (SignatureSigningSnapshot, error) {
	item, err := NewSignatureSigningProfile(signingProfileInputFromDomain(p))
	if err != nil || !item.Enabled {
		return SignatureSigningSnapshot{}, ErrInvalidSigningProfile
	}
	return SignatureSigningSnapshot{ProfileID: item.ID, ProfileVersion: item.Version,
		Provider: item.Provider, KeyReference: item.KeyReference,
		KeyReferenceFingerprint: item.KeyReferenceFingerprint, TrustPolicyID: item.TrustPolicyID}, nil
}

type SignatureSigningProfileRepository interface {
	CreateSignatureSigningProfile(context.Context, SignatureSigningProfile) (SignatureSigningProfile, error)
	ListSignatureSigningProfiles(context.Context, string) ([]SignatureSigningProfile, error)
	GetSignatureSigningProfile(context.Context, string, string) (SignatureSigningProfile, error)
	SaveSignatureSigningProfile(context.Context, SignatureSigningProfile, uint64) (SignatureSigningProfile, error)
}

type SignatureSigningProfileUseCase struct {
	projects      ProjectLookup
	trustPolicies SignatureTrustPolicyRepository
	profiles      SignatureSigningProfileRepository
	newID         func() (string, error)
	now           func() time.Time
	transaction   transaction.Manager
	auditor       sharedaudit.Recorder
}

func NewSignatureSigningProfileUseCase(projects ProjectLookup, trustPolicies SignatureTrustPolicyRepository,
	profiles SignatureSigningProfileRepository, newID func() (string, error), now func() time.Time,
) (*SignatureSigningProfileUseCase, error) {
	if projects == nil || trustPolicies == nil || profiles == nil || newID == nil || now == nil {
		return nil, ErrUnavailable
	}
	return &SignatureSigningProfileUseCase{projects: projects, trustPolicies: trustPolicies,
		profiles: profiles, newID: newID, now: now}, nil
}

func (u *SignatureSigningProfileUseCase) WithAudit(manager transaction.Manager,
	auditor sharedaudit.Recorder) *SignatureSigningProfileUseCase {
	u.transaction, u.auditor = manager, auditor
	return u
}

func (u *SignatureSigningProfileUseCase) Create(ctx context.Context, principal security.Principal,
	projectID string, input SignatureSigningProfileInput) (SignatureSigningProfile, error) {
	if err := principal.Require(security.PermissionSignatureTrustPolicyWrite); err != nil {
		return SignatureSigningProfile{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SignatureSigningProfile{}, err
	}
	if err := u.requireCompatibleTrustPolicy(ctx, projectID, input.TrustPolicyID, input.Enabled); err != nil {
		return SignatureSigningProfile{}, err
	}
	id, err := u.newID()
	if err != nil {
		return SignatureSigningProfile{}, err
	}
	now := u.now().UTC()
	input.ID, input.OrganizationID, input.ProjectID = id, principal.OrganizationID, strings.TrimSpace(projectID)
	input.Version, input.CreatedAt, input.UpdatedAt = 1, now, now
	item, err := NewSignatureSigningProfile(input)
	if err != nil {
		return SignatureSigningProfile{}, err
	}
	var created SignatureSigningProfile
	operation := func(operationContext context.Context) error {
		var createErr error
		created, createErr = u.profiles.CreateSignatureSigningProfile(operationContext, item)
		if createErr != nil || u.auditor == nil {
			return createErr
		}
		auditID, auditErr := u.newID()
		if auditErr != nil {
			return auditErr
		}
		return u.auditor.Record(operationContext, sharedaudit.Event{ID: auditID,
			OrganizationID: principal.OrganizationID, ProjectID: item.ProjectID, ActorID: principal.UserID,
			Action: "signature_signing_profile.create", ResourceType: "signature_signing_profile",
			ResourceID: item.ID, CreatedAt: now})
	}
	if u.transaction != nil {
		err = u.transaction.WithinTransaction(ctx, operation)
	} else {
		err = operation(ctx)
	}
	return created, err
}

func (u *SignatureSigningProfileUseCase) List(ctx context.Context, principal security.Principal,
	projectID string) ([]SignatureSigningProfile, error) {
	if err := principal.Require(security.PermissionSignatureTrustPolicyRead); err != nil {
		return nil, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.profiles.ListSignatureSigningProfiles(ctx, strings.TrimSpace(projectID))
}

func (u *SignatureSigningProfileUseCase) Get(ctx context.Context, principal security.Principal,
	projectID, profileID string) (SignatureSigningProfile, error) {
	if err := principal.Require(security.PermissionSignatureTrustPolicyRead); err != nil {
		return SignatureSigningProfile{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SignatureSigningProfile{}, err
	}
	if !validID(strings.TrimSpace(profileID)) {
		return SignatureSigningProfile{}, ErrInvalidSigningProfile
	}
	return u.profiles.GetSignatureSigningProfile(ctx, strings.TrimSpace(projectID), strings.TrimSpace(profileID))
}

func (u *SignatureSigningProfileUseCase) Update(ctx context.Context, principal security.Principal,
	projectID, profileID string, expectedVersion uint64,
	input SignatureSigningProfileInput) (SignatureSigningProfile, error) {
	if err := principal.Require(security.PermissionSignatureTrustPolicyWrite); err != nil {
		return SignatureSigningProfile{}, err
	}
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return SignatureSigningProfile{}, err
	}
	current, err := u.profiles.GetSignatureSigningProfile(ctx, strings.TrimSpace(projectID), strings.TrimSpace(profileID))
	if err != nil {
		return SignatureSigningProfile{}, err
	}
	if expectedVersion == 0 || current.Version != expectedVersion {
		return SignatureSigningProfile{}, ErrSigningProfileConflict
	}
	if err := u.requireCompatibleTrustPolicy(ctx, projectID, input.TrustPolicyID, input.Enabled); err != nil {
		return SignatureSigningProfile{}, err
	}
	input.ID, input.OrganizationID, input.ProjectID = current.ID, current.OrganizationID, current.ProjectID
	input.Version, input.CreatedAt, input.UpdatedAt = current.Version+1, current.CreatedAt, u.now().UTC()
	updated, err := NewSignatureSigningProfile(input)
	if err != nil {
		return SignatureSigningProfile{}, err
	}
	var saved SignatureSigningProfile
	operation := func(operationContext context.Context) error {
		var saveErr error
		saved, saveErr = u.profiles.SaveSignatureSigningProfile(operationContext, updated, expectedVersion)
		if saveErr != nil || u.auditor == nil {
			return saveErr
		}
		auditID, auditErr := u.newID()
		if auditErr != nil {
			return auditErr
		}
		return u.auditor.Record(operationContext, sharedaudit.Event{ID: auditID,
			OrganizationID: principal.OrganizationID, ProjectID: updated.ProjectID, ActorID: principal.UserID,
			Action: "signature_signing_profile.update", ResourceType: "signature_signing_profile",
			ResourceID: updated.ID, CreatedAt: updated.UpdatedAt})
	}
	if u.transaction != nil {
		err = u.transaction.WithinTransaction(ctx, operation)
	} else {
		err = operation(ctx)
	}
	return saved, err
}

func (u *SignatureSigningProfileUseCase) requireProject(ctx context.Context,
	principal security.Principal, projectID string) error {
	projectID = strings.TrimSpace(projectID)
	if !validID(projectID) {
		return ErrInvalidSigningProfile
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

func (u *SignatureSigningProfileUseCase) requireCompatibleTrustPolicy(ctx context.Context,
	projectID, policyID string, signingEnabled bool) error {
	policy, err := u.trustPolicies.GetSignatureTrustPolicy(ctx, strings.TrimSpace(projectID), strings.TrimSpace(policyID))
	if err != nil {
		return err
	}
	if policy.Mode != SignatureTrustPublicKey || signingEnabled && !policy.Enabled {
		return ErrInvalidSigningProfile
	}
	return nil
}

func signingProfileInputFromDomain(item SignatureSigningProfile) SignatureSigningProfileInput {
	return SignatureSigningProfileInput{ID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, Name: item.Name, KeyReference: item.KeyReference,
		TrustPolicyID: item.TrustPolicyID, Enabled: item.Enabled, Version: item.Version,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}
