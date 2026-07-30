package data

import (
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

func TestProjectResourcesDoesNotTrustOwnershipLabels(t *testing.T) {
	observation, err := biz.NewObservation(
		"observation-1", "organization-1", "host-1", "target-1",
		1, 1, time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	source := transport.Resource{
		Kind:      transport.KindContainer,
		RuntimeID: "container-1",
		Name:      "api",
		Container: &transport.ContainerSummary{State: "running"},
		Labels: map[string]string{
			"net.owndock.project_id":    "project-1",
			"net.owndock.deployment_id": "deployment-1",
		},
		ObservedAt:    time.Unix(101, 0),
		SchemaVersion: transport.SchemaVersion,
	}
	resources, err := ProjectResources(observation, []transport.Resource{source})
	if err != nil {
		t.Fatal(err)
	}
	resource := resources[0]
	if resource.Managed || resource.ProjectID != "" || resource.DeploymentID != "" {
		t.Fatalf("unverified ownership was trusted: %#v", resource)
	}
	if resource.Labels["net.owndock.deployment_id"] != "deployment-1" {
		t.Fatal("safe candidate label should remain available for later verification")
	}
}
