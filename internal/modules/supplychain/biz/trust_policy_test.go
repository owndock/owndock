package biz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
)

func TestSignatureTrustPolicyNormalizesPublicKeyAndSnapshotsVersion(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	item, err := NewSignatureTrustPolicy(SignatureTrustPolicyInput{
		ID: "trust-1", OrganizationID: "organization-1", ProjectID: "project-1",
		Name: "Release key", Mode: SignatureTrustPublicKey,
		PublicKeyPEM: string(signaturePublicKeyFixture(t)), Enabled: true,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil || item.PublicKeyFingerprint == "" {
		t.Fatalf("NewSignatureTrustPolicy() = %+v, %v", item, err)
	}
	snapshot, err := item.Snapshot()
	if err != nil || snapshot.PolicyID != item.ID || snapshot.PolicyVersion != 1 ||
		snapshot.PublicKeyFingerprint != item.PublicKeyFingerprint || snapshot.Validate() != nil {
		t.Fatalf("Snapshot() = %+v, %v", snapshot, err)
	}
}

func TestSignatureTrustPolicyRequiresPinnedOfflineRootForKeyless(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	valid := SignatureTrustPolicyInput{
		ID: "trust-1", OrganizationID: "organization-1", ProjectID: "project-1",
		Name: "Release workflow", Mode: SignatureTrustKeyless,
		TrustedRootID:       "public-good-2026-08",
		TrustedRootHash:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CertificateIdentity: "https://github.com/owndock/owndock/.github/workflows/release.yml@refs/tags/v1.0.0",
		OIDCIssuer:          "https://token.actions.githubusercontent.com", Enabled: true,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := NewSignatureTrustPolicy(valid); err != nil {
		t.Fatalf("valid keyless policy rejected: %v", err)
	}
	for name, mutate := range map[string]func(*SignatureTrustPolicyInput){
		"missing root hash": func(input *SignatureTrustPolicyInput) { input.TrustedRootHash = "" },
		"mutable issuer":    func(input *SignatureTrustPolicyInput) { input.OIDCIssuer += "?tenant=1" },
		"public key mixed in": func(input *SignatureTrustPolicyInput) {
			input.PublicKeyPEM = string(signaturePublicKeyFixture(t))
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)
			if _, err := NewSignatureTrustPolicy(input); !errors.Is(err, ErrInvalidSignatureTrustPolicy) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

type signaturePolicyRepositoryStub struct {
	items map[string]SignatureTrustPolicy
}

func (s *signaturePolicyRepositoryStub) CreateSignatureTrustPolicy(_ context.Context,
	item SignatureTrustPolicy) (SignatureTrustPolicy, error) {
	if s.items == nil {
		s.items = make(map[string]SignatureTrustPolicy)
	}
	s.items[item.ID] = item
	return item, nil
}

func (s *signaturePolicyRepositoryStub) ListSignatureTrustPolicies(_ context.Context,
	projectID string) ([]SignatureTrustPolicy, error) {
	result := []SignatureTrustPolicy{}
	for _, item := range s.items {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *signaturePolicyRepositoryStub) GetSignatureTrustPolicy(_ context.Context,
	projectID, policyID string) (SignatureTrustPolicy, error) {
	item, ok := s.items[policyID]
	if !ok || item.ProjectID != projectID {
		return SignatureTrustPolicy{}, ErrNotFound
	}
	return item, nil
}

func (s *signaturePolicyRepositoryStub) SaveSignatureTrustPolicy(_ context.Context,
	item SignatureTrustPolicy, expectedVersion uint64) (SignatureTrustPolicy, error) {
	current, ok := s.items[item.ID]
	if !ok || current.Version != expectedVersion {
		return SignatureTrustPolicy{}, ErrSignatureTrustPolicyConflict
	}
	s.items[item.ID] = item
	return item, nil
}

func TestSignatureTrustPolicyUseCaseEnforcesProjectAndMaintainerWrite(t *testing.T) {
	repository := &signaturePolicyRepositoryStub{}
	clock := time.Unix(100, 0).UTC()
	useCase, err := NewSignatureTrustPolicyUseCase(projectLookupStub{exists: true}, repository,
		func() (string, error) { return "trust-1", nil }, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	input := SignatureTrustPolicyInput{
		Name: "Release key", Mode: SignatureTrustPublicKey,
		PublicKeyPEM: string(signaturePublicKeyFixture(t)), Enabled: true,
	}
	viewer := security.Principal{UserID: "viewer", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleViewer}
	if _, err := useCase.Create(t.Context(), viewer, "project-1", input); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("viewer Create() error = %v", err)
	}
	maintainer := viewer
	maintainer.Role = security.RoleMaintainer
	created, err := useCase.Create(t.Context(), maintainer, "project-1", input)
	if err != nil || created.Version != 1 {
		t.Fatalf("maintainer Create() = %+v, %v", created, err)
	}
	input.Name = "Rotated release key"
	input.PublicKeyPEM = string(signaturePublicKeyFixture(t))
	updated, err := useCase.Update(t.Context(), maintainer, "project-1", created.ID, 1, input)
	if err != nil || updated.Version != 2 || updated.PublicKeyFingerprint == created.PublicKeyFingerprint {
		t.Fatalf("Update() = %+v, %v", updated, err)
	}
	if _, err := useCase.Update(t.Context(), maintainer, "project-1", created.ID, 1, input); !errors.Is(err, ErrSignatureTrustPolicyConflict) {
		t.Fatalf("stale Update() error = %v", err)
	}
}
