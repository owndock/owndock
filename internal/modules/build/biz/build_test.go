package biz

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimespec"
)

func TestNewBuildCapturesImmutableConfigurationSnapshot(t *testing.T) {
	configuration, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"services/api/Dockerfile", "services/api", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 900, 1, true, "user-1", time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := NewSourceRevision(
		"source-1", "refs/heads/main", "a975c10d68a2d7461634f13b15c52a2efba72d16",
	)
	if err != nil {
		t.Fatal(err)
	}
	build, err := NewBuild(
		"build-1", "organization-1", "project-1", "application-1",
		configuration, revision, BuildTriggerSourceManual,
		"", "request-1", "user-1", time.Unix(200, 0),
	)
	if err != nil || build.Status != BuildStatusQueued || build.Version != 1 ||
		build.Configuration.ConfigurationVersion != 1 ||
		build.Configuration.DockerfilePath != "services/api/Dockerfile" ||
		build.Revision.CommitSHA != "a975c10d68a2d7461634f13b15c52a2efba72d16" {
		t.Fatalf("NewBuild() = %+v, %v", build, err)
	}
	name := "changed later"
	updated, err := configuration.Apply(
		BuildConfigurationPatch{Name: &name}, "user-2", time.Unix(300, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || build.Configuration.ConfigurationVersion != 1 {
		t.Fatalf("updated/config snapshot = %+v / %+v", updated, build.Configuration)
	}
	configuration.AllowedRefs[0] = "refs/heads/changed"
	if build.Configuration.AllowedRefs[0] != "refs/heads/main" {
		t.Fatalf("Build snapshot shares mutable allowed refs: %+v", build.Configuration.AllowedRefs)
	}
}

func TestSourceRevisionRejectsNonCommitIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		ref  string
		sha  string
	}{
		{name: "branch shorthand", ref: "main", sha: "a975c10d68a2d7461634f13b15c52a2efba72d16"},
		{name: "short SHA", ref: "refs/heads/main", sha: "a975c10d"},
		{name: "non hexadecimal", ref: "refs/heads/main", sha: "z975c10d68a2d7461634f13b15c52a2efba72d16"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSourceRevision("source-1", test.ref, test.sha); !errors.Is(err, ErrInvalidBuild) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestBuildExecutionStateLeaseAndRetry(t *testing.T) {
	configuration, err := NewBuildConfigurationWithDeliverySpec(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"Dockerfile", ".", []string{"refs/heads/main"}, "registry-1",
		"registry.example.com/team/api", BuildPlatformLinuxAMD64, BuildResources{},
		900, 1, true, runtimespec.Spec{},
		[]AutomaticDeploymentRule{{EnvironmentID: "development-1", RuntimeTargetID: "target-1"}},
		"user-1", time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	revision, _ := NewSourceRevision("source-1", "refs/heads/main", "a975c10d68a2d7461634f13b15c52a2efba72d16")
	item, err := NewBuild("build-1", "organization-1", "project-1", "application-1", configuration,
		revision, BuildTriggerSourceManual, "", "request-1", "user-1", time.Unix(200, 0))
	if err != nil {
		t.Fatal(err)
	}
	claim := BuildClaim{WorkerID: "worker-1", Now: time.Unix(210, 0), ExpiresAt: time.Unix(240, 0)}
	if err := item.Acquire(claim); err != nil || item.Lease.Generation != 1 {
		t.Fatalf("Acquire() = %+v, %v", item.Lease, err)
	}
	if err := item.Acquire(claim); !errors.Is(err, ErrBuildNotClaimable) {
		t.Fatalf("active re-claim error = %v", err)
	}
	if err := item.Transition(BuildStatusCheckingOut, time.Unix(211, 0)); err != nil {
		t.Fatal(err)
	}
	if item.StartedAt.IsZero() || item.Terminal() {
		t.Fatalf("checking out build = %+v", item)
	}
	if err := item.Transition(BuildStatusBuilding, time.Unix(212, 0)); err != nil {
		t.Fatal(err)
	}
	if err := item.Fail(BuildFailureBuild, time.Unix(213, 0)); err != nil {
		t.Fatal(err)
	}
	if !item.Terminal() || item.FailureCategory != BuildFailureBuild || item.FinishedAt.IsZero() || item.Lease.Owner != "" {
		t.Fatalf("failed build = %+v", item)
	}
	retry, err := item.Retry("build-2", "retry-1", "user-2", time.Unix(220, 0))
	if err != nil || retry.Status != BuildStatusQueued || retry.TriggerSource != BuildTriggerSourceRetry ||
		retry.SourceBuildID != item.ID || !retry.MatchesRetry(item.ID) || retry.FailureCategory != "" {
		t.Fatalf("Retry() = %+v, %v", retry, err)
	}
	retry.Configuration.AllowedRefs[0] = "refs/heads/changed"
	retry.Configuration.AutomaticDeployments[0].EnvironmentID = "changed"
	if item.Configuration.AllowedRefs[0] != "refs/heads/main" {
		t.Fatal("retry aliases source build snapshot")
	}
	if item.Configuration.AutomaticDeployments[0].EnvironmentID != "development-1" {
		t.Fatal("retry aliases source automatic deployment snapshot")
	}
}

func TestBuildCancelAndTransitionGuards(t *testing.T) {
	item := Build{Status: BuildStatusQueued}
	if err := item.Cancel(time.Unix(100, 0)); err != nil || item.Status != BuildStatusCanceling {
		t.Fatalf("Cancel() = %+v, %v", item, err)
	}
	if err := item.Cancel(time.Unix(101, 0)); err != nil {
		t.Fatalf("idempotent Cancel() error = %v", err)
	}
	if err := item.Transition(BuildStatusCanceled, time.Unix(102, 0)); err != nil || !item.Terminal() {
		t.Fatalf("canceled = %+v, %v", item, err)
	}
	if err := item.Transition(BuildStatusBuilding, time.Unix(103, 0)); !errors.Is(err, ErrInvalidBuildTransition) {
		t.Fatalf("invalid terminal transition error = %v", err)
	}
}

func TestBuildRecordsOnlyCanonicalPushedImageForSnapshotRepository(t *testing.T) {
	item := Build{
		Status:        BuildStatusPushing,
		Configuration: BuildConfigurationSnapshot{ImageRepository: "registry.example.com/team/api"},
	}
	digest := "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64)
	if err := item.RecordPushedImage(digest, time.Unix(100, 0)); err != nil || item.ImageDigest != digest {
		t.Fatalf("RecordPushedImage() = %+v, %v", item, err)
	}
	if err := item.RecordPushedImage(digest, time.Unix(101, 0)); !errors.Is(err, ErrInvalidBuildOutput) {
		t.Fatalf("duplicate output error = %v", err)
	}
	other := Build{
		Status:        BuildStatusPushing,
		Configuration: BuildConfigurationSnapshot{ImageRepository: "registry.example.com/team/api"},
	}
	if err := other.RecordPushedImage("registry.example.com/team/other@sha256:"+strings.Repeat("b", 64), time.Unix(100, 0)); !errors.Is(err, ErrInvalidBuildOutput) {
		t.Fatalf("cross-repository output error = %v", err)
	}
}
