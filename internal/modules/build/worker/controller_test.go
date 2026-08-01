package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type queueStub struct {
	item      biz.Build
	artifacts []biz.Artifact
}

func (s *queueStub) ClaimNextBuild(_ context.Context, claim biz.BuildClaim) (biz.Build, bool, error) {
	if err := s.item.Acquire(claim); err != nil {
		return biz.Build{}, false, err
	}
	s.item.Version++
	return s.item, true, nil
}
func (s *queueStub) SaveClaimedBuild(_ context.Context, item biz.Build, expected uint64, owner string, generation uint64, now time.Time) (biz.Build, error) {
	if s.item.Version != expected || s.item.Lease.Owner != owner || s.item.Lease.Generation != generation || !s.item.Lease.Active(now) {
		return biz.Build{}, biz.ErrBuildLeaseExpired
	}
	item.Version = expected + 1
	s.item = item
	return item, nil
}
func (s *queueStub) RenewBuildLease(_ context.Context, id, owner string, generation, expected uint64, now, expires time.Time) (biz.Build, error) {
	if s.item.ID != id || s.item.Version != expected {
		return biz.Build{}, biz.ErrBuildLeaseExpired
	}
	if err := s.item.Renew(owner, generation, now, expires); err != nil {
		return biz.Build{}, biz.ErrBuildLeaseExpired
	}
	s.item.Version++
	return s.item, nil
}
func (s *queueStub) ValidateBuildFence(_ context.Context, id, owner string, generation uint64, now time.Time) error {
	if s.item.ID != id || s.item.Lease.Owner != owner || s.item.Lease.Generation != generation || !s.item.Lease.Active(now) {
		return biz.ErrBuildLeaseExpired
	}
	return nil
}

func (s *queueStub) ListArtifacts(_ context.Context, projectID string) ([]biz.Artifact, error) {
	var result []biz.Artifact
	for _, item := range s.artifacts {
		if item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}
func (s *queueStub) GetArtifact(_ context.Context, projectID, artifactID string) (biz.Artifact, error) {
	for _, item := range s.artifacts {
		if item.ProjectID == projectID && item.ID == artifactID {
			return item, nil
		}
	}
	return biz.Artifact{}, biz.ErrNotFound
}
func (s *queueStub) GetArtifactByBuild(_ context.Context, buildID string) (biz.Artifact, error) {
	for _, item := range s.artifacts {
		if item.BuildID == buildID {
			return item, nil
		}
	}
	return biz.Artifact{}, biz.ErrNotFound
}
func (s *queueStub) CreateArtifact(_ context.Context, item biz.Artifact) (biz.Artifact, error) {
	s.artifacts = append(s.artifacts, item)
	return item, nil
}
func (s *queueStub) NextPendingArtifact(_ context.Context) (biz.Artifact, bool, error) {
	for _, item := range s.artifacts {
		if item.ReleaseStatus == biz.ArtifactReleasePending {
			return item, true, nil
		}
	}
	return biz.Artifact{}, false, nil
}
func (s *queueStub) SaveArtifactRelease(_ context.Context, item biz.Artifact, expected uint64) (biz.Artifact, error) {
	for index := range s.artifacts {
		if s.artifacts[index].ID == item.ID && s.artifacts[index].Version == expected {
			item.Version = expected + 1
			s.artifacts[index] = item
			return item, nil
		}
	}
	return biz.Artifact{}, biz.ErrVersionConflict
}

type auditStub struct{ events []sharedaudit.Event }

func (s *auditStub) Record(_ context.Context, event sharedaudit.Event) error {
	s.events = append(s.events, event)
	return nil
}

func TestControllerClaimHeartbeatTransitionAndFence(t *testing.T) {
	now := time.Unix(100, 0)
	queue := &queueStub{item: biz.Build{
		ID: "build-1", OrganizationID: "organization-1", ProjectID: "project-1",
		Status: biz.BuildStatusQueued, Version: 1, CreatedAt: now, UpdatedAt: now,
	}}
	audit := &auditStub{}
	clock := now
	controller, err := NewController(queue, transaction.Passthrough{}, audit,
		func() (string, error) { return "audit-1", nil }, func() time.Time { return clock }, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	item, claimed, err := controller.Claim(context.Background(), "worker-1")
	if err != nil || !claimed || item.Lease.Generation != 1 || item.Version != 2 {
		t.Fatalf("Claim() = %+v/%t/%v", item, claimed, err)
	}
	clock = clock.Add(5 * time.Second)
	item, err = controller.Heartbeat(context.Background(), item, "worker-1")
	if err != nil || item.Version != 3 || !item.Lease.ExpiresAt.Equal(clock.Add(30*time.Second)) {
		t.Fatalf("Heartbeat() = %+v/%v", item, err)
	}
	item, err = controller.Advance(context.Background(), item, "worker-1", biz.BuildStatusCheckingOut)
	if err != nil || item.Status != biz.BuildStatusCheckingOut || len(audit.events) != 1 || audit.events[0].Action != "build.checking_out" {
		t.Fatalf("Advance() = %+v audit=%+v err=%v", item, audit.events, err)
	}
	if err := controller.ValidateFence(context.Background(), item, "worker-1"); err != nil {
		t.Fatalf("ValidateFence() error = %v", err)
	}
	clock = item.Lease.ExpiresAt
	if err := controller.ValidateFence(context.Background(), item, "worker-1"); !errors.Is(err, biz.ErrBuildLeaseExpired) {
		t.Fatalf("expired fence error = %v", err)
	}
}

func TestControllerRejectsStaleGeneration(t *testing.T) {
	now := time.Unix(100, 0)
	queue := &queueStub{item: biz.Build{ID: "build-1", OrganizationID: "organization-1", ProjectID: "project-1", Status: biz.BuildStatusBuilding, Version: 3,
		Lease: biz.BuildLease{Owner: "worker-new", Generation: 2, ExpiresAt: now.Add(time.Minute)}}}
	controller, err := NewController(queue, transaction.Passthrough{}, &auditStub{}, func() (string, error) { return "audit-1", nil }, func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	stale := queue.item
	stale.Lease.Owner, stale.Lease.Generation = "worker-old", 1
	if _, err := controller.Advance(context.Background(), stale, "worker-old", biz.BuildStatusPushing); !errors.Is(err, biz.ErrBuildLeaseExpired) {
		t.Fatalf("stale generation error = %v", err)
	}
}
