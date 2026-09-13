package biz

import (
	"context"
	"errors"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
)

type retirementRepositoryStub struct {
	items           map[string]Build
	artifacts       map[string]Artifact
	listErr         error
	artifactListErr error
	saveErr         error
	getErr          error
	conflictNow     *Build
}

func (s *retirementRepositoryStub) ListPendingReleaseArtifactsForApplication(
	_ context.Context,
	organizationID, projectID, applicationID string,
	limit int64,
) ([]Artifact, error) {
	if s.artifactListErr != nil {
		return nil, s.artifactListErr
	}
	items := make([]Artifact, 0, limit)
	for _, item := range s.artifacts {
		if item.OrganizationID == organizationID && item.ProjectID == projectID &&
			item.ApplicationID == applicationID && item.ReleaseStatus == ArtifactReleasePending {
			items = append(items, item)
			if int64(len(items)) == limit {
				break
			}
		}
	}
	return items, nil
}

func (s *retirementRepositoryStub) GetArtifact(
	_ context.Context, projectID, artifactID string,
) (Artifact, error) {
	item, found := s.artifacts[artifactID]
	if !found || item.ProjectID != projectID {
		return Artifact{}, ErrNotFound
	}
	return item, nil
}

func (s *retirementRepositoryStub) SaveArtifactRelease(
	_ context.Context, item Artifact, expectedVersion uint64,
) (Artifact, error) {
	current, found := s.artifacts[item.ID]
	if !found || current.Version != expectedVersion {
		return Artifact{}, ErrVersionConflict
	}
	item.Version = expectedVersion + 1
	s.artifacts[item.ID] = item
	return item, nil
}

type artifactReleaseResolverStub struct {
	releases map[string]string
	err      error
}

func (s artifactReleaseResolverStub) ResolveArtifactRelease(
	_ context.Context, _, artifactID string,
) (string, bool, error) {
	if s.err != nil {
		return "", false, s.err
	}
	releaseID, found := s.releases[artifactID]
	return releaseID, found, nil
}

func (s *retirementRepositoryStub) ListActiveBuildsForApplication(
	_ context.Context,
	organizationID, projectID, applicationID string,
	limit int64,
) ([]Build, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	items := make([]Build, 0, limit)
	for _, item := range s.items {
		if item.OrganizationID == organizationID && item.ProjectID == projectID &&
			item.ApplicationID == applicationID && !item.Terminal() {
			items = append(items, item)
			if int64(len(items)) == limit {
				break
			}
		}
	}
	return items, nil
}

func (s *retirementRepositoryStub) GetBuild(
	_ context.Context, projectID, buildID string,
) (Build, error) {
	if s.getErr != nil {
		return Build{}, s.getErr
	}
	item, found := s.items[buildID]
	if !found || item.ProjectID != projectID {
		return Build{}, ErrNotFound
	}
	return item, nil
}

func (s *retirementRepositoryStub) SaveBuild(
	_ context.Context, item Build, expectedVersion uint64,
) (Build, error) {
	if s.conflictNow != nil {
		s.items[item.ID] = *s.conflictNow
		return Build{}, ErrVersionConflict
	}
	if s.saveErr != nil {
		return Build{}, s.saveErr
	}
	current, found := s.items[item.ID]
	if !found || current.Version != expectedVersion {
		return Build{}, ErrVersionConflict
	}
	item.Version = expectedVersion + 1
	s.items[item.ID] = item
	return item, nil
}

type retirementAuditProbe struct{ events []sharedaudit.Event }

func (a *retirementAuditProbe) Record(_ context.Context, event sharedaudit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func retirementBuild(id, applicationID string, status BuildStatus) Build {
	return Build{
		ID: id, OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: applicationID, Status: status, Version: 1,
	}
}

func TestProductResourceRetirementCancelsOnlyApplicationBuilds(t *testing.T) {
	repository := &retirementRepositoryStub{items: map[string]Build{
		"queued":    retirementBuild("queued", "application-1", BuildStatusQueued),
		"building":  retirementBuild("building", "application-1", BuildStatusBuilding),
		"canceling": retirementBuild("canceling", "application-1", BuildStatusCanceling),
		"completed": retirementBuild("completed", "application-1", BuildStatusSucceeded),
		"other":     retirementBuild("other", "application-2", BuildStatusQueued),
	}}
	audit := &retirementAuditProbe{}
	retirement, err := NewProductResourceRetirement(
		repository, transaction.Passthrough{}, audit,
		func() (string, error) { return "audit-1", nil },
		func() time.Time { return time.Unix(100, 0) }, 100,
	)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	)
	if err != nil || !pending {
		t.Fatalf("first convergence = %t, %v", pending, err)
	}
	for _, id := range []string{"queued", "building", "canceling"} {
		if repository.items[id].Status != BuildStatusCanceling {
			t.Fatalf("%s status = %s", id, repository.items[id].Status)
		}
	}
	if repository.items["other"].Status != BuildStatusQueued || len(audit.events) != 2 {
		t.Fatalf("unrelated build or audit changed: %+v / %+v", repository.items["other"], audit.events)
	}
	for _, event := range audit.events {
		if event.Action != AuditActionApplicationRetirementCancel ||
			event.ActorID != "owner-1" || event.RequestID != "request-1" {
			t.Fatalf("audit event = %+v", event)
		}
	}

	for id, item := range repository.items {
		if item.ApplicationID == "application-1" && item.Status == BuildStatusCanceling {
			if err := item.Transition(BuildStatusCanceled, time.Unix(101, 0)); err != nil {
				t.Fatal(err)
			}
			repository.items[id] = item
		}
	}
	pending, err = retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	)
	if err != nil || pending {
		t.Fatalf("completed convergence = %t, %v", pending, err)
	}
}

func TestProductResourceRetirementFinalizesPendingArtifactReleases(t *testing.T) {
	repository := &retirementRepositoryStub{
		items: map[string]Build{},
		artifacts: map[string]Artifact{
			"linked": {
				ID: "linked", OrganizationID: "organization-1", ProjectID: "project-1",
				ApplicationID: "application-1", ReleaseStatus: ArtifactReleasePending, Version: 1,
			},
			"skipped": {
				ID: "skipped", OrganizationID: "organization-1", ProjectID: "project-1",
				ApplicationID: "application-1", ReleaseStatus: ArtifactReleasePending, Version: 1,
			},
			"other": {
				ID: "other", OrganizationID: "organization-1", ProjectID: "project-1",
				ApplicationID: "application-2", ReleaseStatus: ArtifactReleasePending, Version: 1,
			},
		},
	}
	audit := &retirementAuditProbe{}
	retirement, err := NewProductResourceRetirement(
		repository, transaction.Passthrough{}, audit,
		func() (string, error) { return "audit-1", nil },
		func() time.Time { return time.Unix(100, 0) }, 100,
	)
	if err != nil {
		t.Fatal(err)
	}
	retirement.WithArtifactReleaseResolver(artifactReleaseResolverStub{
		releases: map[string]string{"linked": "release-1"},
	})
	pending, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	)
	if err != nil || !pending {
		t.Fatalf("Artifact convergence = %t/%v", pending, err)
	}
	if item := repository.artifacts["linked"]; item.ReleaseStatus != ArtifactReleaseCreated ||
		item.ReleaseID != "release-1" || item.ReleasedAt.IsZero() {
		t.Fatalf("linked Artifact = %+v", item)
	}
	if item := repository.artifacts["skipped"]; item.ReleaseStatus != ArtifactReleaseSkipped ||
		item.ReleaseID != "" {
		t.Fatalf("skipped Artifact = %+v", item)
	}
	if repository.artifacts["other"].ReleaseStatus != ArtifactReleasePending || len(audit.events) != 2 {
		t.Fatalf("unrelated Artifact or audits = %+v/%+v", repository.artifacts["other"], audit.events)
	}
	actions := map[string]bool{}
	for _, event := range audit.events {
		actions[event.Action] = true
	}
	if !actions[AuditActionApplicationRetirementReleaseReconciled] ||
		!actions[AuditActionApplicationRetirementReleaseSkipped] {
		t.Fatalf("Artifact retirement audit actions = %+v", actions)
	}
	pending, err = retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	)
	if err != nil || pending {
		t.Fatalf("completed Artifact convergence = %t/%v", pending, err)
	}
}

func TestProductResourceRetirementFailsClosedForUnresolvedArtifactRelease(t *testing.T) {
	pendingArtifact := Artifact{
		ID: "artifact-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", ReleaseStatus: ArtifactReleasePending, Version: 1,
	}
	repository := &retirementRepositoryStub{
		items: map[string]Build{}, artifacts: map[string]Artifact{pendingArtifact.ID: pendingArtifact},
	}
	retirement, err := NewProductResourceRetirement(
		repository, transaction.Passthrough{}, &retirementAuditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now, 100,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, ErrBuildRetirementUnavailable) {
		t.Fatalf("missing resolver error = %v", err)
	}

	resolveFailure := errors.New("resolve Artifact release")
	retirement.WithArtifactReleaseResolver(artifactReleaseResolverStub{err: resolveFailure})
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, resolveFailure) {
		t.Fatalf("resolver failure = %v", err)
	}

	idFailure := errors.New("create Artifact retirement audit id")
	retirement.WithArtifactReleaseResolver(artifactReleaseResolverStub{releases: map[string]string{}})
	retirement.newID = func() (string, error) { return "", idFailure }
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, idFailure) {
		t.Fatalf("Artifact audit id failure = %v", err)
	}

	listFailure := errors.New("list pending Artifact releases")
	repository.artifactListErr = listFailure
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, listFailure) {
		t.Fatalf("Artifact list failure = %v", err)
	}
}

func TestProductResourceRetirementScopeAndDependencies(t *testing.T) {
	if _, err := NewProductResourceRetirement(
		nil, transaction.Passthrough{}, &retirementAuditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now, 100,
	); !errors.Is(err, ErrBuildRetirementUnavailable) {
		t.Fatalf("nil repository error = %v", err)
	}
	repository := &retirementRepositoryStub{items: map[string]Build{}}
	retirement, err := NewProductResourceRetirement(
		repository, transaction.Passthrough{}, &retirementAuditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now, 100,
	)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "", "environment-1",
		"owner-1", "request-1",
	); err != nil || pending {
		t.Fatalf("environment convergence = %t, %v", pending, err)
	}
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "environment-1",
		"owner-1", "request-1",
	); !errors.Is(err, ErrBuildRetirementUnavailable) {
		t.Fatalf("mixed scope error = %v", err)
	}
}

func TestProductResourceRetirementAcceptsConcurrentTerminalBuild(t *testing.T) {
	queued := retirementBuild("build-1", "application-1", BuildStatusQueued)
	completed := queued
	completed.Status = BuildStatusSucceeded
	completed.Version = 2
	repository := &retirementRepositoryStub{
		items: map[string]Build{queued.ID: queued}, conflictNow: &completed,
	}
	retirement, err := NewProductResourceRetirement(
		repository, transaction.Passthrough{}, &retirementAuditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now, 100,
	)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	)
	if err != nil || !pending {
		t.Fatalf("concurrent completion = %t, %v", pending, err)
	}
}

func TestProductResourceRetirementPropagatesFailures(t *testing.T) {
	if _, err := (*ProductResourceRetirement)(nil).ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, ErrBuildRetirementUnavailable) {
		t.Fatalf("nil retirement error = %v", err)
	}

	listFailure := errors.New("list active builds")
	repository := &retirementRepositoryStub{
		items: map[string]Build{}, listErr: listFailure,
	}
	retirement, err := NewProductResourceRetirement(
		repository, transaction.Passthrough{}, &retirementAuditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now, 100,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, listFailure) {
		t.Fatalf("list failure = %v", err)
	}

	queued := retirementBuild("build-1", "application-1", BuildStatusQueued)
	repository.listErr = nil
	repository.items[queued.ID] = queued
	idFailure := errors.New("create audit id")
	retirement.newID = func() (string, error) { return "", idFailure }
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, idFailure) {
		t.Fatalf("id failure = %v", err)
	}

	retirement.newID = func() (string, error) { return "audit-1", nil }
	saveFailure := errors.New("save build")
	repository.saveErr = saveFailure
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, saveFailure) {
		t.Fatalf("save failure = %v", err)
	}

	repository.saveErr = nil
	invalid := queued
	invalid.Status = BuildStatus("unknown")
	repository.items[queued.ID] = invalid
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, ErrInvalidBuildTransition) {
		t.Fatalf("invalid transition = %v", err)
	}
}

func TestProductResourceRetirementPropagatesUnresolvedConflict(t *testing.T) {
	queued := retirementBuild("build-1", "application-1", BuildStatusQueued)
	current := queued
	current.Version = 2
	repository := &retirementRepositoryStub{
		items: map[string]Build{queued.ID: queued}, conflictNow: &current,
	}
	retirement, err := NewProductResourceRetirement(
		repository, transaction.Passthrough{}, &retirementAuditProbe{},
		func() (string, error) { return "audit-1", nil }, time.Now, 100,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("unresolved conflict = %v", err)
	}

	repository.items[queued.ID] = queued
	repository.getErr = ErrNotFound
	if _, err := retirement.ConvergeProductResource(
		t.Context(), "organization-1", "project-1", "application-1", "",
		"owner-1", "request-1",
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("conflict read failure = %v", err)
	}
}
