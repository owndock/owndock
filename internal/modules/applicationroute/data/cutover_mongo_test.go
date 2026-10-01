package data

import (
	"testing"
	"time"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

func TestBuildDesiredConfigPreservesOtherRoutesAndReplacesDeploymentScope(t *testing.T) {
	otherAlias, err := agentprotocol.DeploymentBackendAlias("deployment-other")
	if err != nil {
		t.Fatal(err)
	}
	request := applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-new",
		WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 2,
		CutoverSequence: 4, Ports: map[string]uint16{"http": 8080}}
	document := hostConfigDocument{ID: "host-1", Revision: 6,
		Committed: []gatewayRouteDocument{{RouteID: "route-other", Revision: 2,
			DeploymentID: "deployment-other", CutoverSequence: 3, RuntimeTargetID: "target-2",
			Hostname: "other.example.com", BackendAlias: otherAlias, BackendPort: 9090,
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
	alias, err := agentprotocol.DeploymentBackendAlias("deployment-1")
	if err != nil {
		t.Fatal(err)
	}
	request := applicationroutebiz.CutoverRequest{OrganizationID: "organization-1",
		ProjectID: "project-1", ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", ManagedHostID: "host-1", DeploymentID: "deployment-1",
		WorkerID: "worker-1", ContainerName: "container-1", FencingToken: 7,
		CutoverSequence: 9, Ports: map[string]uint16{"metrics": 9090, "http": 8080}}
	desired := applicationroutebiz.HostDesiredConfig{ManagedHostID: "host-1", HostRevision: 3,
		ProbeRouteIDs: []string{"route-1"}, Routes: []applicationroutebiz.GatewayRoute{{
			RouteID: "route-1", Revision: 2, DeploymentID: "deployment-1", CutoverSequence: 9,
			RuntimeTargetID: "target-1", Hostname: "app.example.com", BackendAlias: alias,
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

func TestRouteDocumentRoundTripRetainsStableFailureCode(t *testing.T) {
	route := cutoverTestRoute(t, "route-degraded", "degraded.example.com")
	var err error
	route, err = route.Transition(
		applicationroutebiz.StatusProvisioning, "controller", route.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	route, err = route.Degrade(
		applicationroutebiz.FailureCertificateUnavailable,
		"controller",
		route.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	document := documentFromDomain(route)
	decoded, err := document.domain()
	if err != nil || decoded.FailureCode != applicationroutebiz.FailureCertificateUnavailable {
		t.Fatalf("decoded route = %+v, %v", decoded, err)
	}
}

func TestAbortRouteRestoresOnlyCurrentDesiredObservation(t *testing.T) {
	route := cutoverTestRoute(t, "route-restored", "restored.example.com")
	provisioning, err := route.Transition(
		applicationroutebiz.StatusProvisioning, "controller", route.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	observation := applicationroutebiz.Observation{Revision: provisioning.Revision,
		DeploymentID: "deployment-old", CutoverSequence: 1,
		ConfigDigest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		CertificateStatus: applicationroutebiz.CertificateStatusReady,
		ObservedAt:        provisioning.UpdatedAt}
	ready, err := provisioning.ObserveReady(
		observation, "controller", provisioning.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err = ready.Transition(
		applicationroutebiz.StatusProvisioning, "controller", ready.UpdatedAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	restored, action, err := abortRoute(
		provisioning, applicationroutebiz.FailureBackendUnhealthy,
		provisioning.UpdatedAt.Add(time.Second),
	)
	if err != nil || restored.Status != applicationroutebiz.StatusReady ||
		restored.FailureCode != "" || action != "application_route.ready_restored" {
		t.Fatalf("restored route/action = %+v/%q, %v", restored, action, err)
	}

	provisioning.Revision++
	provisioning.Version++
	degraded, action, err := abortRoute(
		provisioning, applicationroutebiz.FailureBackendUnhealthy,
		provisioning.UpdatedAt.Add(2*time.Second),
	)
	if err != nil || degraded.Status != applicationroutebiz.StatusDegraded ||
		degraded.FailureCode != applicationroutebiz.FailureBackendUnhealthy ||
		action != "application_route.degraded" {
		t.Fatalf("degraded route/action = %+v/%q, %v", degraded, action, err)
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
