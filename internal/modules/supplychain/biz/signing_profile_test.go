package biz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
)

type signingProfileRepositoryStub struct {
	items map[string]SignatureSigningProfile
}

func (s *signingProfileRepositoryStub) CreateSignatureSigningProfile(_ context.Context,
	item SignatureSigningProfile) (SignatureSigningProfile, error) {
	s.items[item.ID] = item
	return item, nil
}
func (s *signingProfileRepositoryStub) ListSignatureSigningProfiles(_ context.Context,
	projectID string) ([]SignatureSigningProfile, error) {
	result := []SignatureSigningProfile{}
	for _, item := range s.items {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}
func (s *signingProfileRepositoryStub) GetSignatureSigningProfile(_ context.Context,
	projectID, profileID string) (SignatureSigningProfile, error) {
	item, ok := s.items[profileID]
	if !ok || item.ProjectID != projectID {
		return SignatureSigningProfile{}, ErrNotFound
	}
	return item, nil
}
func (s *signingProfileRepositoryStub) SaveSignatureSigningProfile(_ context.Context,
	item SignatureSigningProfile, expected uint64) (SignatureSigningProfile, error) {
	current, ok := s.items[item.ID]
	if !ok || current.Version != expected {
		return SignatureSigningProfile{}, ErrSigningProfileConflict
	}
	s.items[item.ID] = item
	return item, nil
}

func TestSigningProfileRequiresExternalKMSAndPublicVerificationPolicy(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	trust, err := NewSignatureTrustPolicy(SignatureTrustPolicyInput{ID: "policy-1",
		OrganizationID: "organization-1", ProjectID: "project-1", Name: "KMS public key",
		Mode: SignatureTrustPublicKey, PublicKeyPEM: string(signaturePublicKeyFixture(t)), Enabled: true,
		Version: 1, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	trustRepository := &signaturePolicyRepositoryStub{items: map[string]SignatureTrustPolicy{trust.ID: trust}}
	profiles := &signingProfileRepositoryStub{items: map[string]SignatureSigningProfile{}}
	useCase, err := NewSignatureSigningProfileUseCase(projectLookupStub{exists: true}, trustRepository,
		profiles, func() (string, error) { return "profile-1", nil }, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	maintainer := security.Principal{UserID: "maintainer-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleMaintainer}
	created, err := useCase.Create(t.Context(), maintainer, "project-1", SignatureSigningProfileInput{
		Name: "Vault signer", KeyReference: "hashivault://release-signing-key",
		TrustPolicyID: trust.ID, Enabled: true})
	if err != nil || created.Provider != SigningKeyVault || created.KeyReferenceFingerprint == "" {
		t.Fatalf("Create() = %+v, %v", created, err)
	}
	for _, reference := range []string{"/etc/keys/private.pem", "env://COSIGN_PRIVATE_KEY", "https://kms/key"} {
		_, err := useCase.Create(t.Context(), maintainer, "project-1", SignatureSigningProfileInput{
			Name: "invalid", KeyReference: reference, TrustPolicyID: trust.ID, Enabled: true})
		if !errors.Is(err, ErrInvalidSigningProfile) {
			t.Fatalf("reference %q error = %v", reference, err)
		}
	}
}
