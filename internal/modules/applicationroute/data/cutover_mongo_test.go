package data

import (
	"testing"
	"time"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestBuildDesiredConfigPreservesOtherRoutesAndReplacesDeploymentScope(t *testing.T) {
	request := applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-new",
		WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 2,
		CutoverSequence: 4, Ports: map[string]uint16{"http": 8080}}
	document := hostConfigDocument{ID: "host-1", Revision: 6,
		Committed: []gatewayRouteDocument{{RouteID: "route-other", Revision: 2,
			DeploymentID: "deployment-other", CutoverSequence: 3, RuntimeTargetID: "target-2",
			Hostname: "other.example.com", BackendAlias: "other", BackendPort: 9090,
			TLSMode: applicationroutebiz.TLSModeAutomatic}}}
	route := cutoverTestRoute(t, "route-new", "app.example.com")
	desired, err := buildDesiredConfig(document, request, []applicationroutebiz.ApplicationRoute{route})
	if err != nil {
		t.Fatal(err)
	}
	alias, _ := agentprotocol.DeploymentBackendAlias(request.DeploymentID)
	if desired.HostRevision != 7 || len(desired.Routes) != 2 ||
		desired.Routes[0].RouteID != "route-new" || desired.Routes[0].BackendAlias != alias ||
		desired.Routes[1].RouteID != "route-other" || len(desired.ProbeRouteIDs) != 1 ||
		desired.ProbeRouteIDs[0] != "route-new" {
		t.Fatalf("desired config = %+v", desired)
	}
}

func TestCutoverDocumentRoundTripRetainsExactRuntimeFence(t *testing.T) {
	request := applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-1",
		WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 7,
		CutoverSequence: 9, Ports: map[string]uint16{"metrics": 9090, "http": 8080}}
	desired := applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 3,
		ProbeRouteIDs: []string{"route-1"}, Routes: []applicationroutebiz.GatewayRoute{{
			RouteID: "route-1", Revision: 2, DeploymentID: "deployment-1", CutoverSequence: 9,
			RuntimeTargetID: "target-1", Hostname: "app.example.com", BackendAlias: "backend",
			BackendPort: 8080, TLSMode: applicationroutebiz.TLSModeAutomatic,
		}}}
	document := cutoverDocumentFromDomain(applicationroutebiz.CutoverTransaction{Request: request, Desired: desired})
	document.State = cutoverStateControlPlaneCommitted
	decoded, err := document.domain("host-1")
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.ControlPlaneCommitted || decoded.Request.FencingToken != 7 ||
		decoded.Request.Ports["metrics"] != 9090 || decoded.Desired.Routes[0].BackendPort != 8080 {
		t.Fatalf("decoded transaction = %+v", decoded)
	}
}

func cutoverTestRoute(t *testing.T, id, hostname string) applicationroutebiz.ApplicationRoute {
	t.Helper()
	input := applicationroutebiz.Input{ID: id, OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1", RuntimeTargetID: "target-1",
		Hostname: hostname, PortName: "http", TLSMode: applicationroutebiz.TLSModeAutomatic,
		Status: applicationroutebiz.StatusPending, Revision: 1, Version: 1,
		CreatedBy: "user-1", UpdatedBy: "user-1", CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)}
	route, err := applicationroutebiz.NewApplicationRoute(input)
	if err != nil {
		t.Fatal(err)
	}
	return route
}
