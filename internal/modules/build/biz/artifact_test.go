package biz

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimespec"
)

func TestArtifactPinsBuildOutputAndReleaseLink(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	build := Build{
		ID: "build-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", BuildConfigurationID: "configuration-1",
		Status: BuildStatusPushing,
		Configuration: BuildConfigurationSnapshot{
			RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
			TargetPlatform: BuildPlatformLinuxAMD64, AutoCreateRelease: true,
			ReleaseRuntimeSpec: runtimespec.Spec{
				Ports: []runtimespec.Port{{Name: "http", ContainerPort: 8080}},
			},
			AutomaticDeployments: []AutomaticDeploymentRule{{
				EnvironmentID: "development-1", RuntimeTargetID: "target-1",
			}},
		},
		ImageDigest: "registry.example.com/team/api@sha256:" + strings.Repeat("a", 64),
	}
	item, err := NewArtifact("artifact-1", build, now)
	if err != nil {
		t.Fatal(err)
	}
	if item.BuildID != build.ID || item.ReleaseStatus != ArtifactReleasePending || item.Version != 1 ||
		len(item.ReleaseRuntimeSpec.Ports) != 1 || item.ReleaseRuntimeSpec.Ports[0].Protocol != "tcp" ||
		item.ReleaseRuntimeSpec.Resources.CPUMilli != runtimespec.DefaultCPUMilli ||
		len(item.AutomaticDeployments) != 1 {
		t.Fatalf("artifact = %+v", item)
	}
	build.Configuration.AutomaticDeployments[0].EnvironmentID = "changed"
	if item.AutomaticDeployments[0].EnvironmentID != "development-1" {
		t.Fatalf("Artifact automatic rules changed = %+v", item.AutomaticDeployments)
	}
	if err := item.MarkReleaseCreated("release-1", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if item.ReleaseStatus != ArtifactReleaseCreated || item.ReleaseID != "release-1" {
		t.Fatalf("released artifact = %+v", item)
	}
	if err := item.MarkReleaseCreated("release-1", now.Add(2*time.Second)); err != nil {
		t.Fatalf("idempotent release link error = %v", err)
	}
	if err := item.MarkReleaseCreated("release-2", now.Add(3*time.Second)); !errors.Is(err, ErrArtifactAlreadyReleased) {
		t.Fatalf("different release error = %v", err)
	}
}

func TestArtifactRejectsMismatchedOrMutableOutput(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	base := Build{
		ID: "build-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", BuildConfigurationID: "configuration-1",
		Status: BuildStatusPushing,
		Configuration: BuildConfigurationSnapshot{
			RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
			TargetPlatform: BuildPlatformLinuxAMD64,
		},
	}
	for _, image := range []string{
		"registry.example.com/team/api:latest",
		"registry.example.com/team/other@sha256:" + strings.Repeat("a", 64),
		"registry.example.com/team/api@sha512:" + strings.Repeat("a", 128),
	} {
		build := base
		build.ImageDigest = image
		if _, err := NewArtifact("artifact-1", build, now); !errors.Is(err, ErrInvalidArtifact) {
			t.Fatalf("NewArtifact(%q) error = %v", image, err)
		}
	}
}
