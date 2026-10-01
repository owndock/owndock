package data

import (
	"testing"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
)

func TestBuildReconciliationDesiredReplacesOnlySelectedRoute(t *testing.T) {
	route := cutoverTestRoute(t, "route-a", "new.example.com")
	host := hostConfigDocument{ID: "host-1", Revision: 8,
		Committed: []gatewayRouteDocument{
			{RouteID: "route-b", Revision: 2, Hostname: "other.example.com"},
			{RouteID: "route-a", Revision: 1, Hostname: "old.example.com"},
		},
	}
	backend := applicationroutebiz.ActiveBackend{
		OrganizationID: route.OrganizationID, ProjectID: route.ProjectID,
		ApplicationID: route.ApplicationID, EnvironmentID: route.EnvironmentID,
		RuntimeTargetID: route.RuntimeTargetID, ManagedHostID: "host-1",
		DeploymentID: "deployment-1", CutoverSequence: 4, Port: 8080,
	}
	desired, err := buildReconciliationDesired(host, route, backend)
	if err != nil || desired.ManagedHostID != "host-1" || desired.HostRevision != 9 ||
		len(desired.Routes) != 2 || desired.Routes[0].RouteID != "route-a" ||
		desired.Routes[0].Hostname != "new.example.com" ||
		desired.Routes[0].DeploymentID != "deployment-1" ||
		desired.Routes[1].RouteID != "route-b" ||
		len(desired.ProbeRouteIDs) != 1 || desired.ProbeRouteIDs[0] != "route-a" {
		t.Fatalf("desired = %+v, err = %v", desired, err)
	}
}

func TestRouteReconciliationDocumentRoundTripPreservesPhase(t *testing.T) {
	backend := applicationroutebiz.ActiveBackend{
		OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1",
		DeploymentID: "deployment-1", CutoverSequence: 4, Port: 8080,
	}
	value := applicationroutebiz.RouteReconciliationTransaction{
		RouteID: "route-1", RouteRevision: 2, OrganizationID: "organization-1",
		Backend: backend, Prepared: true,
		Desired: applicationroutebiz.HostDesiredConfig{
			ManagedHostID: "host-1", HostRevision: 7, ProbeRouteIDs: []string{"route-1"},
		},
	}
	document := routeReconciliationDocumentFromDomain(value)
	document.State = reconciliationStatePrepared
	decoded, err := document.domain("host-1", "organization-1")
	if err != nil || !decoded.Prepared || decoded.RouteID != value.RouteID ||
		decoded.RouteRevision != 2 || decoded.Backend != backend ||
		decoded.Desired.HostRevision != 7 {
		t.Fatalf("decoded = %+v, err = %v", decoded, err)
	}
}
