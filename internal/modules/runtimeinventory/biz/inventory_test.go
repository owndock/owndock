package biz

import (
	"errors"
	"testing"
	"time"
)

func TestObservationAndChunkValidation(t *testing.T) {
	now := time.Unix(100, 0)
	observation, err := NewObservation(
		"observation-1", "organization-1", "host-1", "target-1",
		1, 1, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := NewResource(
		observation, KindContainer, "container-1", "api", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	resource.Managed = true
	resource.ProjectID = "project-1"
	resource.DeploymentID = "deployment-1"
	resource.Container = &ContainerSummary{
		ImageReference: "registry.example.com/team/api@sha256:abc",
		State:          "running",
		Health:         "healthy",
	}
	resource.Labels["net.owndock.deployment_id"] = "deployment-1"
	resource.Ports = []Port{{
		Name: "http", ContainerPort: 8080, HostIP: "127.0.0.1",
		HostPort: 18080, Protocol: "tcp",
	}}
	resource.Mounts = []Mount{{
		Name: "data", Type: "volume", Destination: "/var/lib/api",
	}}
	resource.Networks = []NetworkAttachment{{
		NetworkID: "network-1", Name: "application",
		IPAddress: "172.18.0.2", Gateway: "172.18.0.1",
		MAC: "02:42:ac:12:00:02",
	}}
	chunk, err := NewChunk(observation, 0, []Resource{resource})
	if err != nil {
		t.Fatal(err)
	}
	if err := chunk.Validate(); err != nil {
		t.Fatal(err)
	}

	chunk.Resources[0].Name = "changed-after-digest"
	if err := chunk.Validate(); !errors.Is(err, ErrInvalidChunk) {
		t.Fatalf("modified chunk error = %v", err)
	}
}

func TestResourceRejectsSecretBearingAndRawHostFields(t *testing.T) {
	observation, err := NewObservation(
		"observation-1", "organization-1", "host-1", "target-1",
		1, 1, time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := NewResource(
		observation, KindContainer, "container-1", "api", time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	resource.Container = &ContainerSummary{State: "running"}
	resource.Attributes["Config.Env"] = "DATABASE_PASSWORD=value"
	if err := resource.Validate(); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("environment field error = %v", err)
	}

	delete(resource.Attributes, "Config.Env")
	resource.Labels["registry.authorization"] = "value"
	if err := resource.Validate(); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("authorization label error = %v", err)
	}
}

func TestResourceRequiresKindSpecificSummaryAndManagedScope(t *testing.T) {
	observation, err := NewObservation(
		"observation-1", "organization-1", "host-1", "target-1",
		1, 1, time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := NewResource(
		observation, KindImage, "sha256:image", "team/api:1",
		time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	resource.Container = &ContainerSummary{}
	if err := resource.Validate(); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("wrong summary error = %v", err)
	}

	resource.Container = nil
	resource.Image = &ImageSummary{SizeBytes: 1}
	resource.Managed = true
	if err := resource.Validate(); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("missing managed scope error = %v", err)
	}
}

func TestNewObservationBoundsEmptyAndChunkedInventories(t *testing.T) {
	now := time.Unix(100, 0)
	if _, err := NewObservation(
		"empty", "organization-1", "host-1", "target-1", 0, 0, now,
	); err != nil {
		t.Fatalf("empty observation: %v", err)
	}
	if _, err := NewObservation(
		"invalid", "organization-1", "host-1", "target-1", 0, 1, now,
	); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("unchunked observation error = %v", err)
	}
	if _, err := NewObservation(
		"invalid", "organization-1", "host-1", "target-1",
		1, MaxResourcesPerChunk+1, now,
	); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("oversized chunk declaration error = %v", err)
	}
}
