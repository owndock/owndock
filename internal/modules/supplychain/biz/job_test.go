package biz

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func evidenceJobFixture(t *testing.T) EvidenceJob {
	t.Helper()
	item, err := NewEvidenceJob(EvidenceJobInput{
		ID: "evidence-job-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", Kind: EvidenceKindSBOM,
		RegistryCredentialID: "registry-1",
		FormatVersion:        "1.6", Producer: "owndock-evidence-worker/1.0.0",
		CreatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatalf("NewEvidenceJob() error = %v", err)
	}
	return item
}

func TestEvidenceJobLeaseStateMachineAndFence(t *testing.T) {
	item := evidenceJobFixture(t)
	claim := EvidenceClaim{WorkerID: "worker-1", Now: time.Unix(110, 0), ExpiresAt: time.Unix(140, 0)}
	if err := item.Acquire(claim); err != nil || item.Lease.Generation != 1 {
		t.Fatalf("Acquire() = %+v, %v", item.Lease, err)
	}
	if err := item.Acquire(claim); !errors.Is(err, ErrEvidenceJobNotClaimable) {
		t.Fatalf("second Acquire() error = %v", err)
	}
	if err := item.Renew("worker-2", 1, time.Unix(120, 0), time.Unix(150, 0)); !errors.Is(err, ErrEvidenceLeaseExpired) {
		t.Fatalf("wrong owner Renew() error = %v", err)
	}
	if err := item.Renew("worker-1", 1, time.Unix(120, 0), time.Unix(160, 0)); err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if err := item.Transition(EvidenceJobGenerating, time.Unix(121, 0)); err != nil {
		t.Fatalf("generating Transition() error = %v", err)
	}
	if err := item.Transition(EvidenceJobPublishing, time.Unix(122, 0)); err != nil {
		t.Fatalf("publishing Transition() error = %v", err)
	}
	if err := item.Transition(EvidenceJobSucceeded, time.Unix(123, 0)); err != nil {
		t.Fatalf("succeeded Transition() error = %v", err)
	}
	if !item.Terminal() || item.Lease.Owner != "" || item.FinishedAt.IsZero() {
		t.Fatalf("terminal EvidenceJob = %+v", item)
	}
	if err := item.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestEvidenceJobExpiredLeaseCanBeReclaimedWithNewGeneration(t *testing.T) {
	item := evidenceJobFixture(t)
	if err := item.Acquire(EvidenceClaim{
		WorkerID: "worker-1", Now: time.Unix(110, 0), ExpiresAt: time.Unix(120, 0),
	}); err != nil {
		t.Fatal(err)
	}
	if err := item.Transition(EvidenceJobGenerating, time.Unix(111, 0)); err != nil {
		t.Fatal(err)
	}
	if err := item.Acquire(EvidenceClaim{
		WorkerID: "worker-2", Now: time.Unix(121, 0), ExpiresAt: time.Unix(151, 0),
	}); err != nil || item.Lease.Generation != 2 || item.Lease.Owner != "worker-2" {
		t.Fatalf("reclaim = %+v, %v", item.Lease, err)
	}
}

func TestEvidenceJobRejectsInvalidInputAndTransitions(t *testing.T) {
	item := evidenceJobFixture(t)
	item.SubjectDigest = "moving-tag"
	if err := item.Validate(); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("invalid digest Validate() error = %v", err)
	}
	item = evidenceJobFixture(t)
	if err := item.Transition(EvidenceJobPublishing, time.Unix(110, 0)); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("invalid transition error = %v", err)
	}
	if err := item.Acquire(EvidenceClaim{WorkerID: "bad worker", Now: time.Unix(110, 0), ExpiresAt: time.Unix(120, 0)}); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("invalid claim error = %v", err)
	}
}

func TestEvidenceJobFailureIsStableAndTerminal(t *testing.T) {
	item := evidenceJobFixture(t)
	_ = item.Acquire(EvidenceClaim{WorkerID: "worker-1", Now: time.Unix(110, 0), ExpiresAt: time.Unix(140, 0)})
	_ = item.Transition(EvidenceJobGenerating, time.Unix(111, 0))
	if err := item.Fail(EvidenceJobFailureResourceLimit, time.Unix(112, 0)); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}
	if item.Status != EvidenceJobFailed || item.Failure != EvidenceJobFailureResourceLimit || !item.Terminal() {
		t.Fatalf("failed EvidenceJob = %+v", item)
	}
}

func TestEvidenceJobValidationFailsClosedForPersistedStates(t *testing.T) {
	if EvidenceJobStatus("invented").Valid() {
		t.Fatal("invented EvidenceJobStatus is valid")
	}
	if EvidenceJobFailure("invented").Valid() {
		t.Fatal("invented EvidenceJobFailure is valid")
	}
	if _, err := NewEvidenceJob(EvidenceJobInput{}); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("empty NewEvidenceJob() error = %v", err)
	}

	queued := evidenceJobFixture(t)
	queued.StartedAt = time.Unix(101, 0)
	if err := queued.Validate(); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("started queued job error = %v", err)
	}

	generating := evidenceJobFixture(t)
	generating.Status = EvidenceJobGenerating
	if err := generating.Validate(); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("unleased generating job error = %v", err)
	}

	succeeded := evidenceJobFixture(t)
	succeeded.Status = EvidenceJobSucceeded
	if err := succeeded.Validate(); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("unfinished succeeded job error = %v", err)
	}

	failed := evidenceJobFixture(t)
	failed.Status = EvidenceJobFailed
	if err := failed.Validate(); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("uncategorized failed job error = %v", err)
	}
}

func TestEvidenceJobRejectsInvalidFailureAndTerminalAcquire(t *testing.T) {
	item := evidenceJobFixture(t)
	if err := item.Fail("invented", time.Unix(110, 0)); !errors.Is(err, ErrInvalidEvidenceJob) {
		t.Fatalf("invalid Fail() error = %v", err)
	}
	_ = item.Acquire(EvidenceClaim{
		WorkerID: "worker-1", Now: time.Unix(110, 0), ExpiresAt: time.Unix(140, 0),
	})
	_ = item.Transition(EvidenceJobGenerating, time.Unix(111, 0))
	_ = item.Transition(EvidenceJobPublishing, time.Unix(112, 0))
	_ = item.Transition(EvidenceJobSucceeded, time.Unix(113, 0))
	if err := item.Acquire(EvidenceClaim{
		WorkerID: "worker-2", Now: time.Unix(150, 0), ExpiresAt: time.Unix(180, 0),
	}); !errors.Is(err, ErrEvidenceJobNotClaimable) {
		t.Fatalf("terminal Acquire() error = %v", err)
	}
}
