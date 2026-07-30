package data

import (
	"reflect"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
)

func TestResourceDocumentRoundTripPreservesSafeProjection(t *testing.T) {
	observation, err := biz.NewObservation(
		"observation-1", "organization-1", "host-1", "target-1",
		1, 1, time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	resource, err := biz.NewResource(
		observation, biz.KindContainer, "container-1", "api",
		time.Unix(101, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	resource.Container = &biz.ContainerSummary{
		ImageReference: "registry.example.com/team/api@sha256:abc",
		State:          "running", Health: "healthy",
	}
	resource.Labels["org.opencontainers.image.title"] = "api"
	resource.Attributes["restart_policy"] = "unless-stopped"
	resource.Mounts = []biz.Mount{{
		Name: "data", Type: "volume", Destination: "/data",
	}}
	if err := resource.Validate(); err != nil {
		t.Fatal(err)
	}
	document := resourceDocumentFromDomain(resource)
	roundTrip := document.domain()
	if !reflect.DeepEqual(roundTrip, resource) {
		t.Fatalf("round trip = %#v, want %#v", roundTrip, resource)
	}
	if document.ID != resourceDocumentID(resource) {
		t.Fatalf("document ID = %s", document.ID)
	}
}

func TestResourceDocumentIDScopesRuntimeObjectsByObservationAndKind(t *testing.T) {
	base := biz.Resource{
		ObservationID: "observation-1",
		Kind:          biz.KindContainer,
		RuntimeID:     "same-runtime-id",
	}
	first := resourceDocumentID(base)
	base.ObservationID = "observation-2"
	second := resourceDocumentID(base)
	base.ObservationID = "observation-1"
	base.Kind = biz.KindImage
	third := resourceDocumentID(base)
	if first == second || first == third || second == third {
		t.Fatalf("resource IDs are not independently scoped")
	}
}
