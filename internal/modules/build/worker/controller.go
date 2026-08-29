package worker

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
)

var (
	ErrMissingQueue       = errors.New("build queue is required")
	ErrMissingTransaction = errors.New("build transaction manager is required")
	ErrMissingAudit       = errors.New("build audit recorder is required")
	ErrMissingIDGenerator = errors.New("build id generator is required")
	ErrMissingClock       = errors.New("build clock is required")
	ErrMissingArtifacts   = errors.New("build artifact repository is required")
	ErrInvalidLease       = errors.New("build lease duration must be greater than zero")
)

// Controller owns the recoverable execution protocol shared by future Build
// Worker steps. It never checks out source or invokes BuildKit itself.
type Controller struct {
	queue         biz.BuildQueueRepository
	transaction   transaction.Manager
	audit         sharedaudit.Recorder
	newID         biz.IDGenerator
	now           biz.Clock
	leaseDuration time.Duration
	claimStatuses []biz.BuildStatus
	artifacts     biz.ArtifactRepository
	evidence      ArtifactEvidenceScheduler
}

// ArtifactEvidenceScheduler is a narrow transaction participant. Build owns
// Artifact publication; the supply-chain adapter owns the Evidence Job shape.
type ArtifactEvidenceScheduler interface {
	EnsureArtifactEvidence(context.Context, biz.Artifact) error
}

func (c *Controller) WithArtifacts(repository biz.ArtifactRepository) *Controller {
	c.artifacts = repository
	return c
}

func (c *Controller) WithArtifactEvidence(scheduler ArtifactEvidenceScheduler) *Controller {
	c.evidence = scheduler
	return c
}

func (c *Controller) WithClaimStatuses(statuses ...biz.BuildStatus) *Controller {
	c.claimStatuses = append([]biz.BuildStatus(nil), statuses...)
	return c
}

func NewController(queue biz.BuildQueueRepository, manager transaction.Manager, audit sharedaudit.Recorder,
	newID biz.IDGenerator, now biz.Clock, leaseDuration time.Duration) (*Controller, error) {
	if queue == nil {
		return nil, ErrMissingQueue
	}
	if manager == nil {
		return nil, ErrMissingTransaction
	}
	if audit == nil {
		return nil, ErrMissingAudit
	}
	if newID == nil {
		return nil, ErrMissingIDGenerator
	}
	if now == nil {
		return nil, ErrMissingClock
	}
	if leaseDuration <= 0 {
		return nil, ErrInvalidLease
	}
	return &Controller{queue: queue, transaction: manager, audit: audit, newID: newID, now: now, leaseDuration: leaseDuration}, nil
}

func (c *Controller) Claim(ctx context.Context, workerID string) (biz.Build, bool, error) {
	workerID = strings.TrimSpace(workerID)
	now := c.now().UTC()
	return c.queue.ClaimNextBuild(ctx, biz.BuildClaim{
		WorkerID: workerID, Now: now, ExpiresAt: now.Add(c.leaseDuration),
		Statuses: append([]biz.BuildStatus(nil), c.claimStatuses...),
	})
}

func (c *Controller) Heartbeat(ctx context.Context, item biz.Build, workerID string) (biz.Build, error) {
	now := c.now().UTC()
	return c.queue.RenewBuildLease(ctx, item.ID, strings.TrimSpace(workerID), item.Lease.Generation,
		item.Version, now, now.Add(c.leaseDuration))
}

func (c *Controller) Advance(ctx context.Context, item biz.Build, workerID string, next biz.BuildStatus) (biz.Build, error) {
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	if err := item.Transition(next, now); err != nil {
		return biz.Build{}, err
	}
	return c.save(ctx, item, strings.TrimSpace(workerID), generation, expectedVersion, now, auditAction(next))
}

func (c *Controller) Fail(ctx context.Context, item biz.Build, workerID string, category biz.BuildFailureCategory) (biz.Build, error) {
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	if err := item.Fail(category, now); err != nil {
		return biz.Build{}, err
	}
	return c.save(ctx, item, strings.TrimSpace(workerID), generation, expectedVersion, now, "build.failed")
}

func (c *Controller) RecordPushedImage(ctx context.Context, item biz.Build, workerID, imageDigest string) (biz.Build, error) {
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	if err := item.RecordPushedImage(imageDigest, now); err != nil {
		return biz.Build{}, err
	}
	return c.save(ctx, item, strings.TrimSpace(workerID), generation, expectedVersion, now, "build.image_pushed")
}

func (c *Controller) PublishArtifact(ctx context.Context, item biz.Build, workerID string) (biz.Build, biz.Artifact, error) {
	if c.artifacts == nil {
		return biz.Build{}, biz.Artifact{}, ErrMissingArtifacts
	}
	artifactID, err := c.newID()
	if err != nil {
		return biz.Build{}, biz.Artifact{}, err
	}
	buildAuditID, err := c.newID()
	if err != nil {
		return biz.Build{}, biz.Artifact{}, err
	}
	artifactAuditID, err := c.newID()
	if err != nil {
		return biz.Build{}, biz.Artifact{}, err
	}
	now, expectedVersion, generation := c.now().UTC(), item.Version, item.Lease.Generation
	artifact, err := biz.NewArtifact(artifactID, item, now)
	if err != nil {
		return biz.Build{}, biz.Artifact{}, err
	}
	item.ArtifactID = artifact.ID
	if err := item.Transition(biz.BuildStatusSucceeded, now); err != nil {
		return biz.Build{}, biz.Artifact{}, err
	}
	workerID = strings.TrimSpace(workerID)
	var saved biz.Build
	err = c.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		created, createErr := c.artifacts.CreateArtifact(transactionContext, artifact)
		if createErr != nil {
			return createErr
		}
		artifact = created
		if c.evidence != nil {
			if evidenceErr := c.evidence.EnsureArtifactEvidence(transactionContext, artifact); evidenceErr != nil {
				return evidenceErr
			}
		}
		var saveErr error
		saved, saveErr = c.queue.SaveClaimedBuild(transactionContext, item, expectedVersion, workerID, generation, now)
		if saveErr != nil {
			return saveErr
		}
		if auditErr := c.audit.Record(transactionContext, sharedaudit.Event{
			ID: artifactAuditID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
			ActorID: "system:" + workerID, Action: "artifact.create", ResourceType: "artifact",
			ResourceID: artifact.ID, CreatedAt: now,
		}); auditErr != nil {
			return auditErr
		}
		return c.audit.Record(transactionContext, sharedaudit.Event{
			ID: buildAuditID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
			ActorID: "system:" + workerID, Action: "build.succeeded", ResourceType: "build",
			ResourceID: item.ID, CreatedAt: now,
		})
	})
	return saved, artifact, err
}

func (c *Controller) RecordArtifactRelease(ctx context.Context, item biz.Artifact, workerID, releaseID string) (biz.Artifact, error) {
	if c.artifacts == nil {
		return biz.Artifact{}, ErrMissingArtifacts
	}
	expectedVersion, now := item.Version, c.now().UTC()
	if err := item.MarkReleaseCreated(releaseID, now); err != nil {
		return biz.Artifact{}, err
	}
	auditID, err := c.newID()
	if err != nil {
		return biz.Artifact{}, err
	}
	var saved biz.Artifact
	err = c.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var saveErr error
		saved, saveErr = c.artifacts.SaveArtifactRelease(transactionContext, item, expectedVersion)
		if saveErr != nil {
			return saveErr
		}
		return c.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
			ActorID: "system:" + strings.TrimSpace(workerID), Action: "artifact.release_created",
			ResourceType: "artifact", ResourceID: item.ID, CreatedAt: now,
		})
	})
	return saved, err
}

func (c *Controller) ValidateFence(ctx context.Context, item biz.Build, workerID string) error {
	return c.queue.ValidateBuildFence(ctx, item.ID, strings.TrimSpace(workerID), item.Lease.Generation, c.now().UTC())
}

func (c *Controller) save(ctx context.Context, item biz.Build, workerID string, generation, expectedVersion uint64,
	now time.Time, action string) (biz.Build, error) {
	auditID, err := c.newID()
	if err != nil {
		return biz.Build{}, err
	}
	var saved biz.Build
	err = c.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var saveErr error
		saved, saveErr = c.queue.SaveClaimedBuild(transactionContext, item, expectedVersion, workerID, generation, now)
		if saveErr != nil {
			return saveErr
		}
		return c.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
			ActorID: "system:" + workerID, Action: action, ResourceType: "build", ResourceID: item.ID, CreatedAt: now,
		})
	})
	return saved, err
}

func auditAction(status biz.BuildStatus) string {
	switch status {
	case biz.BuildStatusCheckingOut:
		return "build.checking_out"
	case biz.BuildStatusBuilding:
		return "build.building"
	case biz.BuildStatusPushing:
		return "build.pushing"
	case biz.BuildStatusSucceeded:
		return "build.succeeded"
	case biz.BuildStatusCanceled:
		return "build.canceled"
	default:
		return "build.status_changed"
	}
}
