package biz

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidEvidenceJob      = errors.New("evidence job is invalid")
	ErrEvidenceJobNotClaimable = errors.New("evidence job is not claimable")
	ErrEvidenceLeaseExpired    = errors.New("evidence job lease is expired")
)

type EvidenceJobStatus string

const (
	EvidenceJobQueued     EvidenceJobStatus = "queued"
	EvidenceJobGenerating EvidenceJobStatus = "generating"
	EvidenceJobPublishing EvidenceJobStatus = "publishing"
	EvidenceJobVerifying  EvidenceJobStatus = "verifying"
	EvidenceJobSucceeded  EvidenceJobStatus = "succeeded"
	EvidenceJobFailed     EvidenceJobStatus = "failed"
)

func (s EvidenceJobStatus) Valid() bool {
	switch s {
	case EvidenceJobQueued, EvidenceJobGenerating, EvidenceJobPublishing, EvidenceJobVerifying,
		EvidenceJobSucceeded, EvidenceJobFailed:
		return true
	default:
		return false
	}
}

type EvidenceJobFailure string

const (
	EvidenceJobFailureImagePull       EvidenceJobFailure = "image_pull"
	EvidenceJobFailureResourceLimit   EvidenceJobFailure = "resource_limit"
	EvidenceJobFailureGeneration      EvidenceJobFailure = "generation_failed"
	EvidenceJobFailureRegistryPublish EvidenceJobFailure = "registry_publish"
	EvidenceJobFailureSignatureTrust  EvidenceJobFailure = "signature_trust"
	EvidenceJobFailureSignatureVerify EvidenceJobFailure = "signature_verification"
	EvidenceJobFailureSignatureSign   EvidenceJobFailure = "signature_signing"
	EvidenceJobFailureUnknown         EvidenceJobFailure = "unknown"
)

func (f EvidenceJobFailure) Valid() bool {
	switch f {
	case EvidenceJobFailureImagePull, EvidenceJobFailureResourceLimit,
		EvidenceJobFailureGeneration, EvidenceJobFailureRegistryPublish,
		EvidenceJobFailureSignatureTrust, EvidenceJobFailureSignatureVerify,
		EvidenceJobFailureSignatureSign,
		EvidenceJobFailureUnknown:
		return true
	default:
		return false
	}
}

type EvidenceLease struct {
	Owner      string
	ExpiresAt  time.Time
	Generation uint64
}

func (l EvidenceLease) Active(now time.Time) bool {
	return validID(strings.TrimSpace(l.Owner)) && l.ExpiresAt.After(now)
}

type EvidenceClaim struct {
	WorkerID  string
	Now       time.Time
	ExpiresAt time.Time
	Kinds     []EvidenceKind
}

func (c EvidenceClaim) Validate() error {
	if !validID(strings.TrimSpace(c.WorkerID)) || c.Now.IsZero() || !c.ExpiresAt.After(c.Now) {
		return ErrInvalidEvidenceJob
	}
	seen := make(map[EvidenceKind]struct{}, len(c.Kinds))
	for _, kind := range c.Kinds {
		if !kind.Valid() {
			return ErrInvalidEvidenceJob
		}
		if _, duplicate := seen[kind]; duplicate {
			return ErrInvalidEvidenceJob
		}
		seen[kind] = struct{}{}
	}
	return nil
}

type EvidenceJob struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	ArtifactID           string
	SubjectDigest        string
	RegistryRepository   string
	RegistryCredentialID string
	Kind                 EvidenceKind
	FormatVersion        string
	Producer             string
	Provenance           ProvenanceRecipe
	Signature            SignatureTrustSnapshot
	SignatureOperation   SignatureJobOperation
	Signing              SignatureSigningSnapshot
	IdempotencyKey       string
	Status               EvidenceJobStatus
	Failure              EvidenceJobFailure
	Version              uint64
	Lease                EvidenceLease
	CreatedAt            time.Time
	UpdatedAt            time.Time
	StartedAt            time.Time
	FinishedAt           time.Time
}

type EvidenceJobInput struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	ArtifactID           string
	SubjectDigest        string
	RegistryRepository   string
	RegistryCredentialID string
	Kind                 EvidenceKind
	FormatVersion        string
	Producer             string
	Provenance           ProvenanceRecipe
	Signature            SignatureTrustSnapshot
	SignatureOperation   SignatureJobOperation
	Signing              SignatureSigningSnapshot
	IdempotencyKey       string
	CreatedAt            time.Time
}

func NewEvidenceJob(input EvidenceJobInput) (EvidenceJob, error) {
	now := input.CreatedAt.UTC()
	item := EvidenceJob{
		ID: strings.TrimSpace(input.ID), OrganizationID: strings.TrimSpace(input.OrganizationID),
		ProjectID: strings.TrimSpace(input.ProjectID), ArtifactID: strings.TrimSpace(input.ArtifactID),
		SubjectDigest:      strings.TrimSpace(input.SubjectDigest),
		RegistryRepository: strings.TrimSpace(input.RegistryRepository), Kind: input.Kind,
		RegistryCredentialID: strings.TrimSpace(input.RegistryCredentialID),
		FormatVersion:        strings.TrimSpace(input.FormatVersion), Producer: strings.TrimSpace(input.Producer),
		Provenance: input.Provenance,
		Signature:  input.Signature, SignatureOperation: input.SignatureOperation, Signing: input.Signing,
		IdempotencyKey: strings.TrimSpace(input.IdempotencyKey),
		Status:         EvidenceJobQueued, Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	if item.IdempotencyKey == "" {
		item.IdempotencyKey = item.ID
	}
	if item.Kind == EvidenceKindSignature && item.SignatureOperation == "" {
		item.SignatureOperation = SignatureOperationVerify
	}
	if err := item.Validate(); err != nil {
		return EvidenceJob{}, err
	}
	return item, nil
}

func (j EvidenceJob) Validate() error {
	leaseEmpty := j.Lease.Owner == "" && j.Lease.ExpiresAt.IsZero() && j.Lease.Generation == 0
	leaseComplete := validID(j.Lease.Owner) && !j.Lease.ExpiresAt.IsZero() && j.Lease.Generation > 0
	provenanceValid := j.Kind == EvidenceKindProvenance && j.FormatVersion == SLSAProvenanceFormatVersion &&
		j.Provenance.Validate() == nil || j.Kind != EvidenceKindProvenance && j.Provenance.Empty()
	signatureValid := j.Kind == EvidenceKindSignature && j.FormatVersion == CosignSignatureFormatV03 &&
		j.Signature.Validate() == nil && j.SignatureOperation.Valid() &&
		(j.SignatureOperation == SignatureOperationVerify && j.Signing.Empty() ||
			j.SignatureOperation == SignatureOperationSignAndVerify && j.Signing.Validate() == nil &&
				j.Signing.TrustPolicyID == j.Signature.PolicyID && j.Signature.Mode == SignatureTrustPublicKey) ||
		j.Kind != EvidenceKindSignature && j.Signature.Empty() && j.SignatureOperation == "" && j.Signing.Empty()
	vulnerabilityValid := j.Kind != EvidenceKindVulnerabilityReport ||
		j.FormatVersion == TrivyReportFormatVersion && j.Producer == "trivy/0.74.0"
	commonValid := validID(j.ID) && validID(j.OrganizationID) && validID(j.ProjectID) &&
		validID(j.ArtifactID) && validDigest(j.SubjectDigest) && validRepository(j.RegistryRepository) &&
		validID(j.RegistryCredentialID) &&
		j.Kind.Valid() && validText(j.FormatVersion, 64) && validText(j.Producer, 200) && provenanceValid && signatureValid &&
		vulnerabilityValid &&
		validID(j.IdempotencyKey) &&
		j.Status.Valid() && j.Version > 0 && !j.CreatedAt.IsZero() && !j.UpdatedAt.IsZero() &&
		!j.UpdatedAt.Before(j.CreatedAt) && (leaseEmpty || leaseComplete)
	if !commonValid {
		return ErrInvalidEvidenceJob
	}
	switch j.Status {
	case EvidenceJobQueued:
		if !j.StartedAt.IsZero() || !j.FinishedAt.IsZero() || j.Failure != "" {
			return ErrInvalidEvidenceJob
		}
	case EvidenceJobGenerating, EvidenceJobPublishing, EvidenceJobVerifying:
		if j.StartedAt.IsZero() || !j.FinishedAt.IsZero() || j.Failure != "" || !leaseComplete {
			return ErrInvalidEvidenceJob
		}
	case EvidenceJobSucceeded:
		if j.StartedAt.IsZero() || j.FinishedAt.IsZero() || j.Failure != "" || !leaseEmpty {
			return ErrInvalidEvidenceJob
		}
	case EvidenceJobFailed:
		if j.StartedAt.IsZero() || j.FinishedAt.IsZero() || !j.Failure.Valid() || !leaseEmpty {
			return ErrInvalidEvidenceJob
		}
	}
	return nil
}

func (j EvidenceJob) Terminal() bool {
	return j.Status == EvidenceJobSucceeded || j.Status == EvidenceJobFailed
}

func (j *EvidenceJob) Acquire(claim EvidenceClaim) error {
	if err := claim.Validate(); err != nil {
		return err
	}
	if j.Terminal() || j.Lease.Active(claim.Now) {
		return ErrEvidenceJobNotClaimable
	}
	j.Lease = EvidenceLease{
		Owner: strings.TrimSpace(claim.WorkerID), ExpiresAt: claim.ExpiresAt.UTC(),
		Generation: j.Lease.Generation + 1,
	}
	j.UpdatedAt = claim.Now.UTC()
	return nil
}

func (j *EvidenceJob) Renew(owner string, generation uint64, now, expiresAt time.Time) error {
	if j.Lease.Owner != strings.TrimSpace(owner) || j.Lease.Generation != generation ||
		!j.Lease.Active(now) || !expiresAt.After(now) {
		return ErrEvidenceLeaseExpired
	}
	j.Lease.ExpiresAt, j.UpdatedAt = expiresAt.UTC(), now.UTC()
	return nil
}

func (j *EvidenceJob) Transition(next EvidenceJobStatus, now time.Time) error {
	valid := (j.Status == EvidenceJobQueued && (next == EvidenceJobGenerating || next == EvidenceJobVerifying)) ||
		(j.Status == EvidenceJobGenerating && (next == EvidenceJobPublishing || next == EvidenceJobFailed)) ||
		(j.Status == EvidenceJobPublishing && (next == EvidenceJobSucceeded || next == EvidenceJobFailed)) ||
		(j.Status == EvidenceJobVerifying && (next == EvidenceJobSucceeded || next == EvidenceJobFailed))
	if !valid || now.IsZero() {
		return ErrInvalidEvidenceJob
	}
	j.Status, j.UpdatedAt = next, now.UTC()
	if (next == EvidenceJobGenerating || next == EvidenceJobVerifying) && j.StartedAt.IsZero() {
		j.StartedAt = now.UTC()
	}
	if next != EvidenceJobFailed {
		j.Failure = ""
	}
	if j.Terminal() {
		j.FinishedAt, j.Lease = now.UTC(), EvidenceLease{}
	}
	return nil
}

func (j *EvidenceJob) Fail(failure EvidenceJobFailure, now time.Time) error {
	if !failure.Valid() {
		return ErrInvalidEvidenceJob
	}
	if err := j.Transition(EvidenceJobFailed, now); err != nil {
		return err
	}
	j.Failure = failure
	return nil
}

// EvidenceQueueRepository is internal to the isolated Evidence Worker. Public
// HTTP handlers must never claim jobs or publish worker results directly.
type EvidenceQueueRepository interface {
	CreateEvidenceJob(context.Context, EvidenceJob) (EvidenceJob, error)
	ClaimNextEvidenceJob(context.Context, EvidenceClaim) (EvidenceJob, bool, error)
	RenewEvidenceJobLease(context.Context, string, string, uint64, uint64, time.Time, time.Time) (EvidenceJob, error)
	SaveClaimedEvidenceJob(context.Context, EvidenceJob, uint64, string, uint64, time.Time) (EvidenceJob, error)
	ValidateEvidenceFence(context.Context, string, string, uint64, time.Time) error
	PublishClaimedEvidence(context.Context, EvidenceJob, Evidence, uint64, string, uint64, time.Time) (EvidenceJob, Evidence, error)
	PublishClaimedSignatureVerification(context.Context, EvidenceJob, EvidenceVerification, uint64, string, uint64, time.Time) (EvidenceJob, EvidenceVerification, error)
}
