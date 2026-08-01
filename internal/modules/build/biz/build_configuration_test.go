package biz

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimespec"
)

func TestBuildConfigurationNormalizesSafeDefaults(t *testing.T) {
	item, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"", "", []string{"refs/tags/v1.0.0", "refs/heads/main"},
		"registry-1", "registry.example.com/team/api", "",
		BuildResources{}, 0, 0, true, "user-1", time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if item.DockerfilePath != "Dockerfile" || item.ContextPath != "." ||
		item.ImageRepository != "registry.example.com/team/api" ||
		item.TargetPlatform != BuildPlatformLinuxAMD64 ||
		item.Resources.CPUMilli != DefaultBuildCPUMilli ||
		item.TimeoutSeconds != DefaultBuildTimeoutSeconds || item.MaxConcurrency != 1 ||
		item.ReleaseRuntimeSpec.Resources.CPUMilli != runtimespec.DefaultCPUMilli ||
		item.ReleaseRuntimeSpec.Resources.MemoryBytes != runtimespec.DefaultMemoryBytes ||
		!reflect.DeepEqual(item.AllowedRefs, []string{"refs/heads/main", "refs/tags/v1.0.0"}) {
		t.Fatalf("configuration defaults = %+v", item)
	}
}

func TestBuildConfigurationNormalizesAndSnapshotsReleaseRuntimeSpec(t *testing.T) {
	item, err := NewBuildConfigurationWithReleaseSpec(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, true, runtimespec.Spec{
			Ports:           []runtimespec.Port{{Name: "http", ContainerPort: 8080}},
			EnvironmentKeys: []string{"DATABASE_URL"},
		}, "user-1", time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if item.ReleaseRuntimeSpec.Ports[0].Protocol != "tcp" ||
		item.ReleaseRuntimeSpec.Resources.CPUMilli != runtimespec.DefaultCPUMilli {
		t.Fatalf("release runtime spec = %+v", item.ReleaseRuntimeSpec)
	}
	snapshot := item.Snapshot()
	item.ReleaseRuntimeSpec.Ports[0].Name = "changed"
	if snapshot.ReleaseRuntimeSpec.Ports[0].Name != "http" {
		t.Fatalf("snapshot changed with configuration: %+v", snapshot.ReleaseRuntimeSpec)
	}
}

func TestBuildConfigurationNormalizesAutomaticDevelopmentTargets(t *testing.T) {
	item, err := NewBuildConfigurationWithDeliverySpec(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, true, runtimespec.Spec{},
		[]AutomaticDeploymentRule{
			{EnvironmentID: "environment-b", RuntimeTargetID: "target-b"},
			{EnvironmentID: "environment-a", RuntimeTargetID: "target-a"},
		}, "user-1", time.Unix(100, 0),
	)
	if err != nil || len(item.AutomaticDeployments) != 2 ||
		item.AutomaticDeployments[0].EnvironmentID != "environment-a" {
		t.Fatalf("automatic deployment configuration = %+v/%v", item, err)
	}
	snapshot := item.Snapshot()
	item.AutomaticDeployments[0].EnvironmentID = "changed"
	if snapshot.AutomaticDeployments[0].EnvironmentID != "environment-a" {
		t.Fatalf("automatic deployment snapshot changed = %+v", snapshot.AutomaticDeployments)
	}
	_, err = NewBuildConfigurationWithDeliverySpec(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, false, runtimespec.Spec{},
		[]AutomaticDeploymentRule{{EnvironmentID: "environment-a", RuntimeTargetID: "target-a"}},
		"user-1", time.Unix(100, 0),
	)
	if !errors.Is(err, ErrInvalidBuildConfiguration) {
		t.Fatalf("automatic deployment without Release error = %v", err)
	}
}

func TestBuildConfigurationRejectsUnsafeInputs(t *testing.T) {
	base := func() (BuildConfiguration, error) {
		return NewBuildConfiguration(
			"configuration-1", "project-1", "application-1", "API build", "source-1",
			"services/api/Dockerfile", "services/api", []string{"refs/heads/main"},
			"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
			BuildResources{}, 0, 0, false, "user-1", time.Unix(100, 0),
		)
	}
	if _, err := base(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*BuildConfiguration)
	}{
		{name: "dockerfile traversal", mutate: func(c *BuildConfiguration) { c.DockerfilePath = "../Dockerfile" }},
		{name: "dockerfile outside context", mutate: func(c *BuildConfiguration) { c.DockerfilePath = "Dockerfile" }},
		{name: "absolute context", mutate: func(c *BuildConfiguration) { c.ContextPath = "/workspace" }},
		{name: "branch shorthand", mutate: func(c *BuildConfiguration) { c.AllowedRefs = []string{"main"} }},
		{name: "remote wildcard", mutate: func(c *BuildConfiguration) { c.AllowedRefs = []string{"refs/heads/*"} }},
		{name: "duplicate ref", mutate: func(c *BuildConfiguration) { c.AllowedRefs = []string{"refs/heads/main", "refs/heads/main"} }},
		{name: "tagged image", mutate: func(c *BuildConfiguration) { c.ImageRepository = "registry.example.com/team/api:latest" }},
		{name: "excessive CPU", mutate: func(c *BuildConfiguration) { c.Resources.CPUMilli = 16_001 }},
		{name: "excessive timeout", mutate: func(c *BuildConfiguration) { c.TimeoutSeconds = 7_201 }},
		{name: "excessive concurrency", mutate: func(c *BuildConfiguration) { c.MaxConcurrency = 5 }},
		{name: "invalid release port", mutate: func(c *BuildConfiguration) {
			c.ReleaseRuntimeSpec.Ports = []runtimespec.Port{{Name: "HTTP", ContainerPort: 8080}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item, _ := base()
			test.mutate(&item)
			if _, err := normalizeBuildConfiguration(item); !errors.Is(err, ErrInvalidBuildConfiguration) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestBuildConfigurationRejectsPartialResourceDefaults(t *testing.T) {
	_, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{CPUMilli: 1_000}, 0, 0, false, "user-1", time.Unix(100, 0),
	)
	if !errors.Is(err, ErrInvalidBuildConfiguration) {
		t.Fatalf("partial resources error = %v", err)
	}
}

func TestBuildConfigurationPatchCreatesNewVersion(t *testing.T) {
	item, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, false, "user-1", time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	name := "API release build"
	autoRelease := true
	updated, err := item.Apply(BuildConfigurationPatch{
		Name: &name, AutoCreateRelease: &autoRelease,
	}, "user-2", time.Unix(200, 0))
	if err != nil || updated.Version != 2 || updated.Name != name ||
		!updated.AutoCreateRelease || updated.UpdatedBy != "user-2" ||
		item.Version != 1 || item.AutoCreateRelease {
		t.Fatalf("updated/original = %+v / %+v, %v", updated, item, err)
	}
}

func TestBuildConfigurationPatchDoesNotDefaultExplicitPartialValues(t *testing.T) {
	item, err := NewBuildConfiguration(
		"configuration-1", "project-1", "application-1", "API build", "source-1",
		"Dockerfile", ".", []string{"refs/heads/main"},
		"registry-1", "registry.example.com/team/api", BuildPlatformLinuxAMD64,
		BuildResources{}, 0, 0, false, "user-1", time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	partialResources := BuildResources{CPUMilli: 1_000}
	if _, err := item.Apply(BuildConfigurationPatch{Resources: &partialResources}, "user-2", time.Unix(200, 0)); !errors.Is(err, ErrInvalidBuildConfiguration) {
		t.Fatalf("partial resources error = %v", err)
	}
	emptyDockerfile := ""
	if _, err := item.Apply(BuildConfigurationPatch{DockerfilePath: &emptyDockerfile}, "user-2", time.Unix(200, 0)); !errors.Is(err, ErrInvalidBuildConfiguration) {
		t.Fatalf("empty dockerfile error = %v", err)
	}
}
