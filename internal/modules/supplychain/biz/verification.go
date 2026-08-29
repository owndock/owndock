package biz

import (
	"context"
	"net/url"
	"strings"
	"time"
)

// EvidenceVerification is a bounded immutable summary of one cryptographic
// verification. The complete Sigstore bundle remains in the OCI Registry.
type EvidenceVerification struct {
	ID                    string
	OrganizationID        string
	ProjectID             string
	ArtifactID            string
	SubjectDigest         string
	PolicyID              string
	PolicyVersion         uint64
	SigningProfileID      string
	SigningProfileVersion uint64
	SigningKeyProvider    SigningKeyProvider
	SigningKeyFingerprint string
	TrustMode             SignatureTrustMode
	TrustRootHash         string
	SignerIdentity        string
	OIDCIssuer            string
	BundleSetDigest       string
	Verifier              string
	VerifierVersion       string
	VerificationStatus    VerificationStatus
	CreatedAt             time.Time
}

func NewEvidenceVerification(item EvidenceVerification) (EvidenceVerification, error) {
	item.ID, item.OrganizationID = strings.TrimSpace(item.ID), strings.TrimSpace(item.OrganizationID)
	item.ProjectID, item.ArtifactID = strings.TrimSpace(item.ProjectID), strings.TrimSpace(item.ArtifactID)
	item.SubjectDigest, item.PolicyID = strings.TrimSpace(item.SubjectDigest), strings.TrimSpace(item.PolicyID)
	item.TrustRootHash, item.SignerIdentity = strings.TrimSpace(item.TrustRootHash), strings.TrimSpace(item.SignerIdentity)
	item.OIDCIssuer, item.BundleSetDigest = strings.TrimSpace(item.OIDCIssuer), strings.TrimSpace(item.BundleSetDigest)
	item.Verifier, item.VerifierVersion = strings.TrimSpace(item.Verifier), strings.TrimSpace(item.VerifierVersion)
	item.CreatedAt = item.CreatedAt.UTC()
	issuer, issuerErr := url.Parse(item.OIDCIssuer)
	signingEmpty := item.SigningProfileID == "" && item.SigningProfileVersion == 0 &&
		item.SigningKeyProvider == "" && item.SigningKeyFingerprint == ""
	signingComplete := validID(item.SigningProfileID) && item.SigningProfileVersion > 0 &&
		item.SigningKeyProvider.Valid() && validDigest(item.SigningKeyFingerprint)
	identityValid := item.TrustMode == SignatureTrustPublicKey && item.SignerIdentity == "" && item.OIDCIssuer == "" ||
		item.TrustMode == SignatureTrustKeyless && validText(item.SignerIdentity, 1024) &&
			validText(item.OIDCIssuer, 2048) && issuerErr == nil && issuer.Scheme == "https" && issuer.Host != "" &&
			issuer.User == nil && issuer.RawQuery == "" && issuer.Fragment == ""
	if !validID(item.ID) || !validID(item.OrganizationID) || !validID(item.ProjectID) ||
		!validID(item.ArtifactID) || !validDigest(item.SubjectDigest) || !validID(item.PolicyID) ||
		item.PolicyVersion == 0 || !item.TrustMode.Valid() || !validDigest(item.TrustRootHash) ||
		!validDigest(item.BundleSetDigest) || item.Verifier != "cosign" ||
		item.VerifierVersion != "3.0.6" || item.VerificationStatus != VerificationVerified ||
		!identityValid || !(signingEmpty || signingComplete) || item.CreatedAt.IsZero() {
		return EvidenceVerification{}, ErrSignatureVerification
	}
	return item, nil
}

type EvidenceVerificationRepository interface {
	ListEvidenceVerifications(context.Context, string, string) ([]EvidenceVerification, error)
}
