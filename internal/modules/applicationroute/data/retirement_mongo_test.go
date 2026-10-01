package data

import (
	"testing"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
)

func TestBuildRetirementDesiredRemovesOnlySelectedRoute(t *testing.T) {
	host := hostConfigDocument{ID: "host-1", Revision: 8,
		Committed: []gatewayRouteDocument{
			{RouteID: "route-b", Revision: 2},
			{RouteID: "route-a", Revision: 3},
		},
	}
	desired, found := buildRetirementDesired(host, "route-a")
	if !found || desired.ManagedHostID != "host-1" || desired.HostRevision != 9 ||
		len(desired.Routes) != 1 || desired.Routes[0].RouteID != "route-b" ||
		len(desired.ProbeRouteIDs) != 0 {
		t.Fatalf("desired = %+v, found = %t", desired, found)
	}
	if _, found := buildRetirementDesired(host, "missing"); found {
		t.Fatal("missing route was reported as committed")
	}
}

func TestRouteRetirementDocumentRoundTripPreservesPhase(t *testing.T) {
	value := applicationroutebiz.RouteRetirementTransaction{RouteID: "route-1",
		OrganizationID: "organization-1", Prepared: true,
		Desired: applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1",
			HostRevision: 4, ProbeRouteIDs: []string{}},
	}
	document := routeRetirementDocumentFromDomain(value)
	document.State = retirementStatePrepared
	decoded, err := document.domain("host-1", "organization-1")
	if err != nil || !decoded.Prepared || decoded.GatewayCommitted ||
		decoded.RouteID != value.RouteID || decoded.Desired.HostRevision != 4 {
		t.Fatalf("decoded = %+v, err = %v", decoded, err)
	}
}
