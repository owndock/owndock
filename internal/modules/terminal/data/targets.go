package data

import (
	"context"
	"errors"
	"strconv"

	controlbiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
)

type controlStore interface {
	ProjectExists(context.Context, string, string) (bool, error)
	GetRuntimeTarget(context.Context, string, string) (controlbiz.RuntimeTarget, error)
	EnvironmentStage(context.Context, string, string) (string, error)
	ResolveProjectRole(context.Context, string, string, string) (security.Role, error)
}

type deploymentStore interface {
	Get(context.Context, string, string) (deploymentbiz.Deployment, error)
	CurrentSucceededForSlot(context.Context, string, string, string, string) (deploymentbiz.Deployment, error)
}

type managedHostStore interface {
	Get(context.Context, string, string) (managedhostbiz.ManagedHost, error)
}

type TargetResolver struct {
	control     controlStore
	deployments deploymentStore
	hosts       managedHostStore
}

func NewTargetResolver(control controlStore, deployments deploymentStore, hosts managedHostStore) *TargetResolver {
	return &TargetResolver{control: control, deployments: deployments, hosts: hosts}
}

func (r *TargetResolver) ProjectExists(ctx context.Context, organizationID, projectID string) (bool, error) {
	return r.control.ProjectExists(ctx, organizationID, projectID)
}

func (r *TargetResolver) ResolveContainer(
	ctx context.Context, organizationID, projectID, deploymentID string,
) (terminalbiz.Target, error) {
	deployment, err := r.deployments.Get(ctx, projectID, deploymentID)
	if errors.Is(err, deploymentbiz.ErrNotFound) {
		return terminalbiz.Target{}, terminalbiz.ErrTargetNotFound
	}
	if err != nil {
		return terminalbiz.Target{}, err
	}
	if deployment.OrganizationID != organizationID || deployment.Status != deploymentbiz.StatusSucceeded ||
		deployment.CutoverSequence == 0 {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	current, err := r.deployments.CurrentSucceededForSlot(
		ctx, projectID, deployment.ApplicationID, deployment.EnvironmentID, deployment.RuntimeTargetID,
	)
	if errors.Is(err, deploymentbiz.ErrNotFound) {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	if err != nil {
		return terminalbiz.Target{}, err
	}
	if current.ID != deployment.ID || current.CutoverSequence != deployment.CutoverSequence {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	runtimeTarget, err := r.control.GetRuntimeTarget(ctx, projectID, deployment.RuntimeTargetID)
	if errors.Is(err, controlbiz.ErrNotFound) {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	if err != nil {
		return terminalbiz.Target{}, err
	}
	if runtimeTarget.Status != controlbiz.RuntimeTargetStatusReady || runtimeTarget.ManagedHostID == "" {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	host, err := r.hosts.Get(ctx, organizationID, runtimeTarget.ManagedHostID)
	if errors.Is(err, managedhostbiz.ErrNotFound) {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	if err != nil {
		return terminalbiz.Target{}, err
	}
	if !containerHostAvailable(host) || host.ConnectionMode != runtimeTarget.ConnectionMode {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	stage, err := r.control.EnvironmentStage(ctx, projectID, deployment.EnvironmentID)
	if errors.Is(err, controlbiz.ErrNotFound) {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	if err != nil {
		return terminalbiz.Target{}, err
	}
	return terminalbiz.Target{
		Kind: terminalbiz.KindContainer, OrganizationID: organizationID, ProjectID: projectID,
		ManagedHostID: host.ID, RuntimeTargetID: runtimeTarget.ID, DeploymentID: deployment.ID,
		RunningInstanceID:  deployment.ID + ":" + strconv.FormatUint(deployment.CutoverSequence, 10),
		InstanceGeneration: deployment.CutoverSequence, EnvironmentStage: stage,
		ConnectionMode: runtimeTarget.ConnectionMode,
	}, nil
}

func (r *TargetResolver) ResolveHost(
	ctx context.Context, organizationID, managedHostID string,
) (terminalbiz.Target, error) {
	host, err := r.hosts.Get(ctx, organizationID, managedHostID)
	if errors.Is(err, managedhostbiz.ErrNotFound) {
		return terminalbiz.Target{}, terminalbiz.ErrTargetNotFound
	}
	if err != nil {
		return terminalbiz.Target{}, err
	}
	if !hostTerminalAvailable(host) {
		return terminalbiz.Target{}, terminalbiz.ErrTargetUnavailable
	}
	return terminalbiz.Target{
		Kind: terminalbiz.KindHost, OrganizationID: organizationID,
		ManagedHostID: host.ID, ConnectionMode: host.ConnectionMode,
	}, nil
}

func containerHostAvailable(host managedhostbiz.ManagedHost) bool {
	switch host.ConnectionMode {
	case runtimeaccess.ModeAgent:
		return host.Status == managedhostbiz.StatusOnline && host.AgentIdentityID != "" && host.AgentSessionID != ""
	case runtimeaccess.ModeDirectDocker:
		return host.Status != managedhostbiz.StatusDisabled
	default:
		return false
	}
}

func hostTerminalAvailable(host managedhostbiz.ManagedHost) bool {
	if !containerHostAvailable(host) {
		return false
	}
	if host.ConnectionMode == runtimeaccess.ModeDirectDocker {
		return host.DirectSSHRef != ""
	}
	return true
}

type ProjectRoleResolver struct{ control controlStore }

func NewProjectRoleResolver(control controlStore) *ProjectRoleResolver {
	return &ProjectRoleResolver{control: control}
}

func (r *ProjectRoleResolver) ResolveTerminalProjectRole(
	ctx context.Context, organizationID, projectID, userID string,
) (security.Role, error) {
	role, err := r.control.ResolveProjectRole(ctx, organizationID, projectID, userID)
	if errors.Is(err, controlbiz.ErrNotFound) {
		return "", terminalbiz.ErrTargetNotFound
	}
	return role, err
}

var _ terminalbiz.TargetResolver = (*TargetResolver)(nil)
var _ terminalbiz.ProjectRoleResolver = (*ProjectRoleResolver)(nil)
