package data

import (
	"context"
	"errors"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type currentSucceededDeploymentRepository interface {
	CurrentSucceededForSlot(context.Context, string, string, string, string) (deploymentbiz.Deployment, error)
}

type applicationRouteExecutionStore interface {
	ReleaseExecutionSpec(
		context.Context,
		string,
		string,
		string,
	) (string, string, string, string, runtimespec.Spec, error)
	RuntimeTargetExecution(context.Context, string, string) (runtimeaccess.Connection, error)
}

// ApplicationRouteBackendResolver adapts Deployment ownership into the
// narrow, secret-free port consumed by the Route controller.
type ApplicationRouteBackendResolver struct {
	repository currentSucceededDeploymentRepository
	store      applicationRouteExecutionStore
}

func NewApplicationRouteBackendResolver(
	repository currentSucceededDeploymentRepository,
	store applicationRouteExecutionStore,
) (*ApplicationRouteBackendResolver, error) {
	if repository == nil || store == nil {
		return nil, applicationroutebiz.ErrReconciliationUnavailable
	}
	return &ApplicationRouteBackendResolver{repository: repository, store: store}, nil
}

func (r *ApplicationRouteBackendResolver) ResolveActiveBackend(
	ctx context.Context,
	route applicationroutebiz.ApplicationRoute,
) (applicationroutebiz.ActiveBackend, bool, error) {
	deployment, err := r.repository.CurrentSucceededForSlot(
		ctx, route.ProjectID, route.ApplicationID, route.EnvironmentID, route.RuntimeTargetID,
	)
	if errors.Is(err, deploymentbiz.ErrNotFound) {
		return applicationroutebiz.ActiveBackend{}, false, nil
	}
	if err != nil {
		return applicationroutebiz.ActiveBackend{}, false, err
	}
	if deployment.OrganizationID != route.OrganizationID ||
		deployment.CutoverSequence == 0 || deployment.Status != deploymentbiz.StatusSucceeded {
		return applicationroutebiz.ActiveBackend{}, false, applicationroutebiz.ErrReconciliationConflict
	}
	_, _, _, _, runtimeSpec, err := r.store.ReleaseExecutionSpec(
		ctx, deployment.ProjectID, deployment.ApplicationID, deployment.ReleaseID,
	)
	if err != nil {
		return applicationroutebiz.ActiveBackend{}, false, err
	}
	connection, err := r.store.RuntimeTargetExecution(
		ctx, deployment.ProjectID, deployment.RuntimeTargetID,
	)
	if err != nil {
		return applicationroutebiz.ActiveBackend{}, false, err
	}
	if connection.Mode != runtimeaccess.ModeAgent || connection.ManagedHostID == "" {
		return applicationroutebiz.ActiveBackend{}, false, applicationroutebiz.ErrReconciliationConfiguration
	}
	var backendPort uint16
	for _, port := range runtimeSpec.Ports {
		if port.Name == route.PortName && (port.Protocol == "" || port.Protocol == "tcp") {
			backendPort = port.ContainerPort
			break
		}
	}
	if backendPort == 0 {
		return applicationroutebiz.ActiveBackend{}, false, applicationroutebiz.ErrReconciliationConfiguration
	}
	return applicationroutebiz.ActiveBackend{
		OrganizationID: deployment.OrganizationID, ProjectID: deployment.ProjectID,
		ApplicationID: deployment.ApplicationID, EnvironmentID: deployment.EnvironmentID,
		RuntimeTargetID: deployment.RuntimeTargetID,
		ManagedHostID:   connection.ManagedHostID,
		DeploymentID:    deployment.ID, CutoverSequence: deployment.CutoverSequence,
		Port: backendPort,
	}, true, nil
}

var _ applicationroutebiz.ActiveBackendResolver = (*ApplicationRouteBackendResolver)(nil)
