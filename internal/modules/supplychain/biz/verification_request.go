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

const CosignVerifierProducerV306 = "cosign/3.0.6"

var ErrInvalidSignatureVerificationRequest = errors.New("signature verification request is invalid")

func SignatureVerificationIdempotencyKey(artifactID, policyID string, policyVersion uint64,
	requestKey string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(artifactID) + "\x00signature\x00" +
		strings.TrimSpace(policyID) + "\x00" + strconv.FormatUint(policyVersion, 10) + "\x003.0.6\x00" +
		strings.TrimSpace(requestKey)))
	return "signature-" + hex.EncodeToString(digest[:])
}

type SignatureVerificationSchedule struct {
	JobID         string
	PolicyID      string
	PolicyVersion uint64
	Scheduled     bool
}

type evidenceJobCreator interface {
	CreateEvidenceJob(context.Context, EvidenceJob) (EvidenceJob, error)
}

type SignatureVerificationUseCase struct {
	artifacts   ArtifactLookup
	policies    SignatureTrustPolicyRepository
	jobs        evidenceJobCreator
	newID       func() (string, error)
	now         func() time.Time
	transaction transaction.Manager
	auditor     sharedaudit.Recorder
}

func NewSignatureVerificationUseCase(artifacts ArtifactLookup, policies SignatureTrustPolicyRepository,
	jobs evidenceJobCreator, newID func() (string, error), now func() time.Time,
) (*SignatureVerificationUseCase, error) {
	if artifacts == nil || policies == nil || jobs == nil || newID == nil || now == nil {
		return nil, ErrUnavailable
	}
	return &SignatureVerificationUseCase{
		artifacts: artifacts, policies: policies, jobs: jobs, newID: newID, now: now,
	}, nil
}

func (u *SignatureVerificationUseCase) WithAudit(manager transaction.Manager,
	auditor sharedaudit.Recorder) *SignatureVerificationUseCase {
	u.transaction, u.auditor = manager, auditor
	return u
}

func (u *SignatureVerificationUseCase) Schedule(ctx context.Context, principal security.Principal,
	projectID, artifactID, policyID, requestKey string) (SignatureVerificationSchedule, error) {
	if err := principal.Require(security.PermissionSignatureVerificationWrite); err != nil {
		return SignatureVerificationSchedule{}, err
	}
	projectID, artifactID = strings.TrimSpace(projectID), strings.TrimSpace(artifactID)
	policyID, requestKey = strings.TrimSpace(policyID), strings.TrimSpace(requestKey)
	if !validID(projectID) || !validID(artifactID) || !validID(policyID) || !validID(requestKey) {
		return SignatureVerificationSchedule{}, ErrInvalidSignatureVerificationRequest
	}
	artifact, err := u.artifacts.ResolveArtifact(ctx, principal.OrganizationID, projectID, artifactID)
	if err != nil {
		return SignatureVerificationSchedule{}, err
	}
	policy, err := u.policies.GetSignatureTrustPolicy(ctx, projectID, policyID)
	if err != nil {
		return SignatureVerificationSchedule{}, err
	}
	snapshot, err := policy.Snapshot()
	if err != nil {
		return SignatureVerificationSchedule{}, err
	}
	idempotencyKey := SignatureVerificationIdempotencyKey(artifact.ID, policy.ID, policy.Version, requestKey)
	job, err := NewEvidenceJob(EvidenceJobInput{
		ID: idempotencyKey, OrganizationID: artifact.OrganizationID, ProjectID: artifact.ProjectID,
		ArtifactID: artifact.ID, SubjectDigest: artifact.SubjectDigest,
		RegistryRepository: artifact.RegistryRepository, RegistryCredentialID: artifact.RegistryCredentialID,
		Kind: EvidenceKindSignature, FormatVersion: CosignSignatureFormatV03,
		Producer: CosignVerifierProducerV306, Signature: snapshot,
		IdempotencyKey: idempotencyKey,
		CreatedAt:      u.now().UTC(),
	})
	if err != nil {
		return SignatureVerificationSchedule{}, err
	}
	result := SignatureVerificationSchedule{
		JobID: job.ID, PolicyID: policy.ID, PolicyVersion: policy.Version, Scheduled: true,
	}
	operation := func(operationContext context.Context) error {
		_, createErr := u.jobs.CreateEvidenceJob(operationContext, job)
		if errors.Is(createErr, ErrDuplicate) {
			result.Scheduled = false
			return nil
		}
		if createErr != nil {
			return createErr
		}
		if u.auditor == nil {
			return nil
		}
		auditID, auditErr := u.newID()
		if auditErr != nil {
			return auditErr
		}
		return u.auditor.Record(operationContext, sharedaudit.Event{
			ID: auditID, OrganizationID: principal.OrganizationID, ProjectID: projectID,
			ActorID: principal.UserID, Action: "signature_verification.schedule",
			ResourceType: "artifact", ResourceID: artifact.ID, CreatedAt: job.CreatedAt,
		})
	}
	if u.transaction != nil {
		err = u.transaction.WithinTransaction(ctx, operation)
	} else {
		err = operation(ctx)
	}
	return result, err
}
