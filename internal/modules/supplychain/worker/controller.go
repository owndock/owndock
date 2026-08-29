package worker

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

var (
	ErrMissingQueue = errors.New("evidence queue is required")
	ErrMissingClock = errors.New("evidence worker clock is required")
	ErrInvalidLease = errors.New("evidence worker lease duration must be greater than zero")
)

type Clock func() time.Time

// Controller owns the recoverable protocol used by an isolated Evidence
// Worker. Generator and Registry adapters never update job state directly.
type Controller struct {
	queue         biz.EvidenceQueueRepository
	now           Clock
	leaseDuration time.Duration
	claimKinds    []biz.EvidenceKind
}

func (c *Controller) WithClaimKinds(kinds ...biz.EvidenceKind) *Controller {
	c.claimKinds = append([]biz.EvidenceKind(nil), kinds...)
	return c
}

func NewController(queue biz.EvidenceQueueRepository, now Clock, leaseDuration time.Duration) (*Controller, error) {
	if queue == nil {
		return nil, ErrMissingQueue
	}
	if now == nil {
		return nil, ErrMissingClock
	}
	if leaseDuration <= 0 {
		return nil, ErrInvalidLease
	}
	return &Controller{queue: queue, now: now, leaseDuration: leaseDuration}, nil
}

func (c *Controller) Claim(ctx context.Context, workerID string) (biz.EvidenceJob, bool, error) {
	now := c.now().UTC()
	return c.queue.ClaimNextEvidenceJob(ctx, biz.EvidenceClaim{
		WorkerID: strings.TrimSpace(workerID), Now: now, ExpiresAt: now.Add(c.leaseDuration),
		Kinds: append([]biz.EvidenceKind(nil), c.claimKinds...),
	})
}

func (c *Controller) Heartbeat(ctx context.Context, item biz.EvidenceJob, workerID string) (biz.EvidenceJob, error) {
	now := c.now().UTC()
	return c.queue.RenewEvidenceJobLease(ctx, item.ID, strings.TrimSpace(workerID),
		item.Lease.Generation, item.Version, now, now.Add(c.leaseDuration))
}

func (c *Controller) Advance(ctx context.Context, item biz.EvidenceJob, workerID string,
	next biz.EvidenceJobStatus) (biz.EvidenceJob, error) {
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	if err := item.Transition(next, now); err != nil {
		return biz.EvidenceJob{}, err
	}
	return c.queue.SaveClaimedEvidenceJob(ctx, item, expectedVersion,
		strings.TrimSpace(workerID), generation, now)
}

func (c *Controller) Fail(ctx context.Context, item biz.EvidenceJob, workerID string,
	failure biz.EvidenceJobFailure) (biz.EvidenceJob, error) {
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	if err := item.Fail(failure, now); err != nil {
		return biz.EvidenceJob{}, err
	}
	return c.queue.SaveClaimedEvidenceJob(ctx, item, expectedVersion,
		strings.TrimSpace(workerID), generation, now)
}

func (c *Controller) ValidateFence(ctx context.Context, item biz.EvidenceJob, workerID string) error {
	return c.queue.ValidateEvidenceFence(ctx, item.ID, strings.TrimSpace(workerID),
		item.Lease.Generation, c.now().UTC())
}

func (c *Controller) Publish(ctx context.Context, item biz.EvidenceJob, evidence biz.Evidence,
	workerID string) (biz.EvidenceJob, biz.Evidence, error) {
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	if err := item.Transition(biz.EvidenceJobSucceeded, now); err != nil {
		return biz.EvidenceJob{}, biz.Evidence{}, err
	}
	return c.queue.PublishClaimedEvidence(ctx, item, evidence, expectedVersion,
		strings.TrimSpace(workerID), generation, now)
}

func (c *Controller) PublishSignatureVerification(ctx context.Context, item biz.EvidenceJob,
	verification biz.EvidenceVerification, workerID string,
) (biz.EvidenceJob, biz.EvidenceVerification, error) {
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	if err := item.Transition(biz.EvidenceJobSucceeded, now); err != nil {
		return biz.EvidenceJob{}, biz.EvidenceVerification{}, err
	}
	return c.queue.PublishClaimedSignatureVerification(ctx, item, verification, expectedVersion,
		strings.TrimSpace(workerID), generation, now)
}

func (c *Controller) PublishVulnerabilityObservation(ctx context.Context, item biz.EvidenceJob,
	evidence biz.Evidence, observation biz.VulnerabilityObservation, workerID string,
) (biz.EvidenceJob, biz.Evidence, biz.VulnerabilityObservation, error) {
	repository, ok := c.queue.(biz.VulnerabilityObservationPublisherRepository)
	if !ok {
		return biz.EvidenceJob{}, biz.Evidence{}, biz.VulnerabilityObservation{}, biz.ErrUnavailable
	}
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	if err := item.Transition(biz.EvidenceJobSucceeded, now); err != nil {
		return biz.EvidenceJob{}, biz.Evidence{}, biz.VulnerabilityObservation{}, err
	}
	return repository.PublishClaimedVulnerabilityObservation(ctx, item, evidence, observation,
		expectedVersion, strings.TrimSpace(workerID), generation, now)
}
