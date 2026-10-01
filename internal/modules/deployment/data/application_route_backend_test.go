package data

import (
	"context"
	"errors"
	"testing"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type currentDeploymentStub struct {
	deployment deploymentbiz.Deployment
	err        error
}

func (s currentDeploymentStub) CurrentSucceededForSlot(
	context.Context, string, string, string, string,
) (deploymentbiz.Deployment, error) {
	return s.deployment, s.err
}

type routeExecutionStoreStub struct {
	connection runtimeaccess.Connection
	spec       runtimespec.Spec
	err        error
}

func (s routeExecutionStoreStub) ReleaseExecutionSpec(
	context.Context, string, string, string,
) (string, string, string, string, runtimespec.Spec, error) {
	return "", "", "", "", s.spec, s.err
}

func (s routeExecutionStoreStub) RuntimeTargetExecution(
	context.Context, string, string,
) (runtimeaccess.Connection, error) {
	return s.connection, s.err
}

func backendTestRoute() applicationroutebiz.ApplicationRoute {
	return applicationroutebiz.ApplicationRoute{
		ID: "route-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", PortName: "http",
	}
}

func TestApplicationRouteBackendResolverUsesCurrentSuccessfulDeployment(t *testing.T) {
	connection, _ := runtimeaccess.NewAgent("host-1")
	deployment := deploymentbiz.Deployment{
		ID: "deployment-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1",
		RuntimeTargetID: "target-1", Status: deploymentbiz.StatusSucceeded,
		CutoverSequence: 5,
	}
	resolver, err := NewApplicationRouteBackendResolver(
		currentDeploymentStub{deployment: deployment},
		routeExecutionStoreStub{connection: connection,
			spec: runtimespec.Spec{Ports: []runtimespec.Port{
				{Name: "http", ContainerPort: 8080, Protocol: "tcp"},
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	backend, exists, err := resolver.ResolveActiveBackend(t.Context(), backendTestRoute())
	if err != nil || !exists || backend.ManagedHostID != "host-1" ||
		backend.DeploymentID != "deployment-1" || backend.CutoverSequence != 5 ||
		backend.Port != 8080 {
		t.Fatalf("ResolveActiveBackend() = %+v, %t, %v", backend, exists, err)
	}
}

func TestApplicationRouteBackendResolverDistinguishesPendingAndInvalidPort(t *testing.T) {
	resolver, _ := NewApplicationRouteBackendResolver(
		currentDeploymentStub{err: deploymentbiz.ErrNotFound}, routeExecutionStoreStub{},
	)
	if _, exists, err := resolver.ResolveActiveBackend(t.Context(), backendTestRoute()); err != nil || exists {
		t.Fatalf("missing deployment = %t, %v", exists, err)
	}

	connection, _ := runtimeaccess.NewAgent("host-1")
	resolver, _ = NewApplicationRouteBackendResolver(
		currentDeploymentStub{deployment: deploymentbiz.Deployment{
			ID: "deployment-1", OrganizationID: "organization-1", ProjectID: "project-1",
			ApplicationID: "application-1", EnvironmentID: "environment-1",
			RuntimeTargetID: "target-1", Status: deploymentbiz.StatusSucceeded,
			CutoverSequence: 5,
		}},
		routeExecutionStoreStub{connection: connection},
	)
	if _, _, err := resolver.ResolveActiveBackend(t.Context(), backendTestRoute()); !errors.Is(err, applicationroutebiz.ErrReconciliationConfiguration) {
		t.Fatalf("missing named port error = %v", err)
	}
}
