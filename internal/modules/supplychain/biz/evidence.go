package biz

import (
	"context"
	"errors"
	"mime"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/shared/security"
)

var (
	ErrInvalidEvidence         = errors.New("artifact evidence is invalid")
	ErrNotFound                = errors.New("artifact evidence was not found")
	ErrDuplicate               = errors.New("artifact evidence already exists")
	ErrUnavailable             = errors.New("artifact evidence is unavailable")
	ErrReferrersUnsupported    = errors.New("OCI registry referrers are not supported")
	ErrRegistryAuthentication  = errors.New("OCI registry authentication failed")
	ErrInvalidRegistryResponse = errors.New("OCI registry returned an invalid response")
	ErrEvidenceContentTooLarge = errors.New("artifact evidence content exceeds the configured size limit")
	ErrEvidenceIntegrity       = errors.New("artifact evidence content failed integrity verification")
)

var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type EvidenceKind string

const (
	EvidenceKindSBOM                EvidenceKind = "sbom"
	EvidenceKindProvenance          EvidenceKind = "provenance"
	EvidenceKindSignature           EvidenceKind = "signature"
	EvidenceKindVulnerabilityReport EvidenceKind = "vulnerability_report"
)

func (k EvidenceKind) Valid() bool {
	switch k {
	case EvidenceKindSBOM, EvidenceKindProvenance, EvidenceKindSignature,
		EvidenceKindVulnerabilityReport:
		return true
	default:
		return false
	}
}

type VerificationStatus string

const (
	VerificationUnverified VerificationStatus = "unverified"
	VerificationVerified   VerificationStatus = "verified"
	VerificationRejected   VerificationStatus = "rejected"
)

func (s VerificationStatus) Valid() bool {
	return s == VerificationUnverified || s == VerificationVerified || s == VerificationRejected
}

// Evidence is an immutable, bounded index for content stored next to an OCI
// Artifact. Full SBOMs, attestations and reports do not belong in this model.
type Evidence struct {
	ID                 string
	OrganizationID     string
	ProjectID          string
	ArtifactID         string
	SubjectDigest      string
	Kind               EvidenceKind
	MediaType          string
	FormatVersion      string
	PredicateType      string
	Producer           string
	RegistryRepository string
	DescriptorDigest   string
	VerificationStatus VerificationStatus
	CreatedAt          time.Time
}

type EvidenceInput struct {
	ID                 string
	OrganizationID     string
	ProjectID          string
	ArtifactID         string
	SubjectDigest      string
	Kind               EvidenceKind
	MediaType          string
	FormatVersion      string
	PredicateType      string
	Producer           string
	RegistryRepository string
	DescriptorDigest   string
	VerificationStatus VerificationStatus
	CreatedAt          time.Time
}

func NewEvidence(input EvidenceInput) (Evidence, error) {
	item := Evidence{
		ID: strings.TrimSpace(input.ID), OrganizationID: strings.TrimSpace(input.OrganizationID),
		ProjectID: strings.TrimSpace(input.ProjectID), ArtifactID: strings.TrimSpace(input.ArtifactID),
		SubjectDigest: strings.TrimSpace(input.SubjectDigest), Kind: input.Kind,
		MediaType: strings.TrimSpace(input.MediaType), FormatVersion: strings.TrimSpace(input.FormatVersion),
		PredicateType: strings.TrimSpace(input.PredicateType), Producer: strings.TrimSpace(input.Producer),
		RegistryRepository: strings.TrimSpace(input.RegistryRepository),
		DescriptorDigest:   strings.TrimSpace(input.DescriptorDigest),
		VerificationStatus: input.VerificationStatus, CreatedAt: input.CreatedAt.UTC(),
	}
	if !validID(item.ID) || !validID(item.OrganizationID) || !validID(item.ProjectID) ||
		!validID(item.ArtifactID) || !item.Kind.Valid() || !item.VerificationStatus.Valid() ||
		item.CreatedAt.IsZero() || !validDigest(item.SubjectDigest) ||
		!validDigest(item.DescriptorDigest) || !validMediaType(item.MediaType) ||
		!validText(item.FormatVersion, 64) || !validText(item.Producer, 200) ||
		!validPredicateType(item.PredicateType) || !validEvidenceKindMetadata(item) ||
		!validRepository(item.RegistryRepository) {
		return Evidence{}, ErrInvalidEvidence
	}
	return item, nil
}

func validEvidenceKindMetadata(item Evidence) bool {
	switch item.Kind {
	case EvidenceKindSBOM:
		return item.MediaType == CycloneDXJSONMediaType &&
			item.FormatVersion == CycloneDXVersion16 && item.PredicateType == ""
	case EvidenceKindProvenance:
		return item.MediaType == SLSAProvenanceMediaType &&
			item.FormatVersion == SLSAProvenanceFormatVersion &&
			item.PredicateType == SLSAProvenancePredicateV1
	case EvidenceKindVulnerabilityReport:
		return item.MediaType == TrivyReportMediaType &&
			item.FormatVersion == TrivyReportFormatVersion && item.PredicateType == ""
	default:
		return item.PredicateType == ""
	}
}

func validID(value string) bool {
	return identifierPattern.MatchString(value) && strings.TrimSpace(value) == value
}

func validDigest(value string) bool {
	parsed, err := digest.Parse(value)
	return err == nil && parsed.Algorithm() == digest.SHA256 && parsed.Validate() == nil
}

func validMediaType(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == value
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
}

func validPredicateType(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 512 || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.IsAbs() && parsed.Scheme == "https" && parsed.Host != ""
}

func validRepository(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	named, err := reference.ParseNormalizedNamed(value)
	return err == nil && named.Name() == value && reference.IsNameOnly(named)
}

type ArtifactSubject struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	SubjectDigest        string
	RegistryRepository   string
	RegistryCredentialID string
}

type ProjectLookup interface {
	ProjectExists(context.Context, string, string) (bool, error)
}

type ArtifactLookup interface {
	ResolveArtifact(context.Context, string, string, string) (ArtifactSubject, error)
}

type Repository interface {
	ListEvidence(context.Context, string, string) ([]Evidence, error)
	GetEvidence(context.Context, string, string, string) (Evidence, error)
	CreateEvidence(context.Context, Evidence) (Evidence, error)
}

type EvidenceContent struct {
	Content   []byte
	MediaType string
	Digest    string
}

type EvidenceContentReader interface {
	ReadEvidence(context.Context, ArtifactSubject, Evidence) (EvidenceContent, error)
}

type UseCase struct {
	projects                  ProjectLookup
	artifacts                 ArtifactLookup
	repository                Repository
	content                   EvidenceContentReader
	verifications             EvidenceVerificationRepository
	vulnerabilityObservations VulnerabilityObservationRepository
	now                       func() time.Time
}

func (u *UseCase) WithVulnerabilityObservations(repository VulnerabilityObservationRepository,
	now func() time.Time) *UseCase {
	u.vulnerabilityObservations, u.now = repository, now
	return u
}

func (u *UseCase) GetLatestVulnerabilityObservation(ctx context.Context, principal security.Principal,
	projectID, artifactID string) (VulnerabilityObservationState, error) {
	if err := u.authorize(ctx, principal, projectID, artifactID); err != nil {
		return VulnerabilityObservationState{}, err
	}
	if u.vulnerabilityObservations == nil || u.now == nil {
		return VulnerabilityObservationState{}, ErrUnavailable
	}
	item, err := u.vulnerabilityObservations.GetLatestVulnerabilityObservation(
		ctx, strings.TrimSpace(projectID), strings.TrimSpace(artifactID))
	if err != nil {
		return VulnerabilityObservationState{}, err
	}
	return VulnerabilityObservationState{Observation: item, Stale: item.Stale(u.now().UTC())}, nil
}

func (u *UseCase) WithVerificationRepository(repository EvidenceVerificationRepository) *UseCase {
	u.verifications = repository
	return u
}

func (u *UseCase) ListEvidenceVerifications(ctx context.Context, principal security.Principal,
	projectID, artifactID string) ([]EvidenceVerification, error) {
	if err := u.authorize(ctx, principal, projectID, artifactID); err != nil {
		return nil, err
	}
	if u.verifications == nil {
		return nil, ErrUnavailable
	}
	return u.verifications.ListEvidenceVerifications(ctx, strings.TrimSpace(projectID), strings.TrimSpace(artifactID))
}

func (u *UseCase) WithContentReader(reader EvidenceContentReader) *UseCase {
	u.content = reader
	return u
}

func NewUseCase(projects ProjectLookup, artifacts ArtifactLookup, repository Repository) (*UseCase, error) {
	if projects == nil || artifacts == nil || repository == nil {
		return nil, ErrUnavailable
	}
	return &UseCase{projects: projects, artifacts: artifacts, repository: repository}, nil
}

func (u *UseCase) ListEvidence(ctx context.Context, principal security.Principal,
	projectID, artifactID string) ([]Evidence, error) {
	if err := u.authorize(ctx, principal, projectID, artifactID); err != nil {
		return nil, err
	}
	return u.repository.ListEvidence(ctx, projectID, artifactID)
}

func (u *UseCase) GetEvidence(ctx context.Context, principal security.Principal,
	projectID, artifactID, evidenceID string) (Evidence, error) {
	if err := u.authorize(ctx, principal, projectID, artifactID); err != nil {
		return Evidence{}, err
	}
	if !validID(strings.TrimSpace(evidenceID)) {
		return Evidence{}, ErrInvalidEvidence
	}
	return u.repository.GetEvidence(ctx, projectID, artifactID, evidenceID)
}

func (u *UseCase) DownloadEvidence(ctx context.Context, principal security.Principal,
	projectID, artifactID, evidenceID string) (Evidence, EvidenceContent, error) {
	subject, err := u.resolveAuthorizedArtifact(ctx, principal, projectID, artifactID)
	if err != nil {
		return Evidence{}, EvidenceContent{}, err
	}
	if !validID(strings.TrimSpace(evidenceID)) {
		return Evidence{}, EvidenceContent{}, ErrInvalidEvidence
	}
	item, err := u.repository.GetEvidence(ctx, projectID, artifactID, evidenceID)
	if err != nil {
		return Evidence{}, EvidenceContent{}, err
	}
	if item.SubjectDigest != subject.SubjectDigest ||
		item.RegistryRepository != subject.RegistryRepository || u.content == nil {
		return Evidence{}, EvidenceContent{}, ErrUnavailable
	}
	content, err := u.content.ReadEvidence(ctx, subject, item)
	if err != nil {
		return Evidence{}, EvidenceContent{}, err
	}
	return item, content, nil
}

func (u *UseCase) authorize(ctx context.Context, principal security.Principal,
	projectID, artifactID string) error {
	_, err := u.resolveAuthorizedArtifact(ctx, principal, projectID, artifactID)
	return err
}

func (u *UseCase) resolveAuthorizedArtifact(ctx context.Context, principal security.Principal,
	projectID, artifactID string) (ArtifactSubject, error) {
	if err := principal.Require(security.PermissionArtifactEvidenceRead); err != nil {
		return ArtifactSubject{}, err
	}
	projectID, artifactID = strings.TrimSpace(projectID), strings.TrimSpace(artifactID)
	if !validID(projectID) || !validID(artifactID) {
		return ArtifactSubject{}, ErrInvalidEvidence
	}
	exists, err := u.projects.ProjectExists(ctx, principal.OrganizationID, projectID)
	if err != nil {
		return ArtifactSubject{}, err
	}
	if !exists {
		return ArtifactSubject{}, ErrNotFound
	}
	return u.artifacts.ResolveArtifact(ctx, principal.OrganizationID, projectID, artifactID)
}
