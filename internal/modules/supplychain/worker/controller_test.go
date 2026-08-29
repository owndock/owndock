package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type queueProbe struct {
	item                  biz.EvidenceJob
	publishedEvidence     biz.Evidence
	publishedVerification biz.EvidenceVerification
	publishedObservation  biz.VulnerabilityObservation
	wantWorker            string
	wantGeneration        uint64
	fenceErr              error
}

func (q *queueProbe) PublishClaimedVulnerabilityObservation(_ context.Context, item biz.EvidenceJob,
	evidence biz.Evidence, observation biz.VulnerabilityObservation, version uint64, worker string,
	generation uint64, _ time.Time) (biz.EvidenceJob, biz.Evidence, biz.VulnerabilityObservation, error) {
	if worker != q.wantWorker || generation != q.wantGeneration || version != q.item.Version {
		return biz.EvidenceJob{}, biz.Evidence{}, biz.VulnerabilityObservation{}, biz.ErrEvidenceLeaseExpired
	}
	item.Version++
	q.item, q.publishedEvidence, q.publishedObservation = item, evidence, observation
	return item, evidence, observation, nil
}

func (q *queueProbe) CreateEvidenceJob(context.Context, biz.EvidenceJob) (biz.EvidenceJob, error) {
	panic("not used")
}

func (q *queueProbe) ClaimNextEvidenceJob(_ context.Context, claim biz.EvidenceClaim) (biz.EvidenceJob, bool, error) {
	if err := q.item.Acquire(claim); err != nil {
		return biz.EvidenceJob{}, false, err
	}
	q.item.Version++
	return q.item, true, nil
}

func (q *queueProbe) RenewEvidenceJobLease(_ context.Context, _ string, worker string,
	generation, version uint64, now, expiresAt time.Time) (biz.EvidenceJob, error) {
	if worker != q.wantWorker || generation != q.wantGeneration || version != q.item.Version {
		return biz.EvidenceJob{}, biz.ErrEvidenceLeaseExpired
	}
	if err := q.item.Renew(worker, generation, now, expiresAt); err != nil {
		return biz.EvidenceJob{}, err
	}
	q.item.Version++
	return q.item, nil
}

func (q *queueProbe) SaveClaimedEvidenceJob(_ context.Context, item biz.EvidenceJob,
	version uint64, worker string, generation uint64, _ time.Time) (biz.EvidenceJob, error) {
	if worker != q.wantWorker || generation != q.wantGeneration || version != q.item.Version {
		return biz.EvidenceJob{}, biz.ErrEvidenceLeaseExpired
	}
	item.Version++
	q.item = item
	return item, nil
}

func (q *queueProbe) ValidateEvidenceFence(_ context.Context, _ string, worker string,
	generation uint64, _ time.Time) error {
	if worker != q.wantWorker || generation != q.wantGeneration {
		return biz.ErrEvidenceLeaseExpired
	}
	return q.fenceErr
}

func (q *queueProbe) PublishClaimedEvidence(_ context.Context, item biz.EvidenceJob,
	evidence biz.Evidence, version uint64, worker string, generation uint64,
	_ time.Time) (biz.EvidenceJob, biz.Evidence, error) {
	if worker != q.wantWorker || generation != q.wantGeneration || version != q.item.Version {
		return biz.EvidenceJob{}, biz.Evidence{}, biz.ErrEvidenceLeaseExpired
	}
	item.Version++
	q.item, q.publishedEvidence = item, evidence
	return item, evidence, nil
}

func (q *queueProbe) PublishClaimedSignatureVerification(_ context.Context, item biz.EvidenceJob,
	verification biz.EvidenceVerification, version uint64, worker string, generation uint64,
	_ time.Time) (biz.EvidenceJob, biz.EvidenceVerification, error) {
	if worker != q.wantWorker || generation != q.wantGeneration || version != q.item.Version {
		return biz.EvidenceJob{}, biz.EvidenceVerification{}, biz.ErrEvidenceLeaseExpired
	}
	item.Version++
	q.item, q.publishedVerification = item, verification
	return item, verification, nil
}

func workerJobFixture(t *testing.T) biz.EvidenceJob {
	t.Helper()
	item, err := biz.NewEvidenceJob(biz.EvidenceJobInput{
		ID: "job-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", Kind: biz.EvidenceKindSBOM,
		RegistryCredentialID: "registry-1",
		FormatVersion:        "1.6", Producer: "evidence-worker/1.0.0", CreatedAt: time.Unix(100, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func workerEvidenceFixture(t *testing.T, item biz.EvidenceJob) biz.Evidence {
	t.Helper()
	evidence, err := biz.NewEvidence(biz.EvidenceInput{
		ID: "evidence-1", OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest, Kind: item.Kind,
		MediaType: "application/vnd.cyclonedx+json", FormatVersion: item.FormatVersion,
		Producer: item.Producer, RegistryRepository: item.RegistryRepository,
		DescriptorDigest:   "sha256:" + strings.Repeat("b", 64),
		VerificationStatus: biz.VerificationUnverified, CreatedAt: time.Unix(105, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func TestControllerRunsRecoverableEvidenceProtocol(t *testing.T) {
	now := time.Unix(101, 0)
	queue := &queueProbe{item: workerJobFixture(t), wantWorker: "worker-1", wantGeneration: 1}
	controller, err := NewController(queue, func() time.Time { return now }, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	item, found, err := controller.Claim(t.Context(), " worker-1 ")
	if err != nil || !found || item.Lease.Generation != 1 {
		t.Fatalf("Claim() = %+v/%v/%v", item, found, err)
	}
	now = now.Add(time.Second)
	item, err = controller.Heartbeat(t.Context(), item, "worker-1")
	if err != nil || !item.Lease.ExpiresAt.Equal(now.Add(30*time.Second)) {
		t.Fatalf("Heartbeat() = %+v/%v", item, err)
	}
	now = now.Add(time.Second)
	item, err = controller.Advance(t.Context(), item, "worker-1", biz.EvidenceJobGenerating)
	if err != nil || item.Status != biz.EvidenceJobGenerating {
		t.Fatalf("Advance(generating) = %+v/%v", item, err)
	}
	now = now.Add(time.Second)
	item, err = controller.Advance(t.Context(), item, "worker-1", biz.EvidenceJobPublishing)
	if err != nil || item.Status != biz.EvidenceJobPublishing {
		t.Fatalf("Advance(publishing) = %+v/%v", item, err)
	}
	if err := controller.ValidateFence(t.Context(), item, "worker-1"); err != nil {
		t.Fatalf("ValidateFence() error = %v", err)
	}
	now = now.Add(time.Second)
	evidence := workerEvidenceFixture(t, item)
	item, published, err := controller.Publish(t.Context(), item, evidence, "worker-1")
	if err != nil || item.Status != biz.EvidenceJobSucceeded || published.ID != evidence.ID ||
		queue.publishedEvidence.ID != evidence.ID {
		t.Fatalf("Publish() = %+v/%+v/%v", item, published, err)
	}
}

func TestControllerFailsClosedAndValidatesDependencies(t *testing.T) {
	clock := func() time.Time { return time.Unix(101, 0) }
	if _, err := NewController(nil, clock, time.Second); !errors.Is(err, ErrMissingQueue) {
		t.Fatalf("missing queue error = %v", err)
	}
	queue := &queueProbe{item: workerJobFixture(t), wantWorker: "worker-1", wantGeneration: 1}
	if _, err := NewController(queue, nil, time.Second); !errors.Is(err, ErrMissingClock) {
		t.Fatalf("missing clock error = %v", err)
	}
	if _, err := NewController(queue, clock, 0); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("invalid lease error = %v", err)
	}
	controller, _ := NewController(queue, clock, time.Minute)
	item, _, _ := controller.Claim(t.Context(), "worker-1")
	item, _ = controller.Advance(t.Context(), item, "worker-1", biz.EvidenceJobGenerating)
	failed, err := controller.Fail(t.Context(), item, "worker-1", biz.EvidenceJobFailureGeneration)
	if err != nil || failed.Status != biz.EvidenceJobFailed || failed.Failure != biz.EvidenceJobFailureGeneration {
		t.Fatalf("Fail() = %+v/%v", failed, err)
	}
}

func TestControllerRejectsInvalidWorkerTransitions(t *testing.T) {
	clock := func() time.Time { return time.Unix(101, 0) }
	queue := &queueProbe{item: workerJobFixture(t), wantWorker: "worker-1", wantGeneration: 1}
	controller, _ := NewController(queue, clock, time.Minute)
	item, _, _ := controller.Claim(t.Context(), "worker-1")
	if _, err := controller.Advance(t.Context(), item, "worker-1", biz.EvidenceJobSucceeded); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("invalid Advance() error = %v", err)
	}
	if _, err := controller.Fail(t.Context(), item, "worker-1", "invented"); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("invalid Fail() error = %v", err)
	}
	if _, _, err := controller.Publish(t.Context(), item, workerEvidenceFixture(t, item), "worker-1"); !errors.Is(err, biz.ErrInvalidEvidenceJob) {
		t.Fatalf("invalid Publish() error = %v", err)
	}
}
