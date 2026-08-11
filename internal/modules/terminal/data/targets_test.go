package data

import (
	"context"
	"errors"
	"testing"

	controlbiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	terminalbiz "github.com/owndock/owndock/internal/modules/terminal/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/security"
)

func TestTargetResolverFixesContainerToCurrentSuccessfulCutover(t *testing.T) {
	resolver := NewTargetResolver(targetControlStub{}, deploymentTargetStub{}, targetHostStub{})
	target, err := resolver.ResolveContainer(
		context.Background(), "organization-1", "project-1", "deployment-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if target.DeploymentID != "deployment-1" || target.RunningInstanceID != "deployment-1:7" ||
		target.InstanceGeneration != 7 || target.EnvironmentStage != "production" ||
		target.ManagedHostID != "host-1" || target.ContainerName == "" ||
		target.Connection.Mode != runtimeaccess.ModeDirectDocker {
		t.Fatalf("target = %+v", target)
	}
}

func TestTargetResolverRejectsStaleDeployment(t *testing.T) {
	deployments := deploymentTargetStub{currentID: "deployment-new"}
	resolver := NewTargetResolver(targetControlStub{}, deployments, targetHostStub{})
	_, err := resolver.ResolveContainer(
		context.Background(), "organization-1", "project-1", "deployment-1",
	)
	if !errors.Is(err, terminalbiz.ErrTargetUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

func TestTargetResolverRequiresConfiguredSSHForDirectHostTerminal(t *testing.T) {
	hosts := targetHostStub{}
	resolver := NewTargetResolver(targetControlStub{}, deploymentTargetStub{}, hosts)
	_, err := resolver.ResolveHost(context.Background(), "organization-1", "host-1")
	if !errors.Is(err, terminalbiz.ErrTargetUnavailable) {
		t.Fatalf("host without SSH error = %v", err)
	}
	hosts.directSSHRef = "secret://host-ssh"
	resolver = NewTargetResolver(targetControlStub{}, deploymentTargetStub{}, hosts)
	if _, err := resolver.ResolveHost(context.Background(), "organization-1", "host-1"); err != nil {
		t.Fatalf("host with SSH: %v", err)
	}
}

type targetControlStub struct{}

func (targetControlStub) ProjectExists(context.Context, string, string) (bool, error) {
	return true, nil
}
func (targetControlStub) GetRuntimeTarget(context.Context, string, string) (controlbiz.RuntimeTarget, error) {
	return controlbiz.RuntimeTarget{
		ID: "target-1", ProjectID: "project-1", ManagedHostID: "host-1",
		ConnectionMode: runtimeaccess.ModeDirectDocker, Status: controlbiz.RuntimeTargetStatusReady,
	}, nil
}
func (targetControlStub) RuntimeTargetExecution(context.Context, string, string) (runtimeaccess.Connection, error) {
	return runtimeaccess.NewDirectDocker(
		"host-1", "tcp://docker.example.com:2376", "docker.example.com", "secret://runtime-target",
	)
}
func (targetControlStub) EnvironmentStage(context.Context, string, string) (string, error) {
	return "production", nil
}
func (targetControlStub) ResolveProjectRole(context.Context, string, string, string) (security.Role, error) {
	return security.RoleMaintainer, nil
}

type deploymentTargetStub struct{ currentID string }

func (deploymentTargetStub) Get(context.Context, string, string) (deploymentbiz.Deployment, error) {
	return deploymentbiz.Deployment{
		ID: "deployment-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ApplicationID: "application-1", EnvironmentID: "environment-1", RuntimeTargetID: "target-1",
		Status: deploymentbiz.StatusSucceeded, CutoverSequence: 7,
	}, nil
}
func (s deploymentTargetStub) CurrentSucceededForSlot(context.Context, string, string, string, string) (deploymentbiz.Deployment, error) {
	id := s.currentID
	if id == "" {
		id = "deployment-1"
	}
	return deploymentbiz.Deployment{ID: id, CutoverSequence: 7}, nil
}

type targetHostStub struct{ directSSHRef string }

func (s targetHostStub) Get(context.Context, string, string) (managedhostbiz.ManagedHost, error) {
	return managedhostbiz.ManagedHost{
		ID: "host-1", OrganizationID: "organization-1", Status: managedhostbiz.StatusOffline,
		ConnectionMode: runtimeaccess.ModeDirectDocker, DirectSSHRef: s.directSSHRef,
		DirectSSHAddress: "host.example.com:22", DirectSSHUser: "owndock",
		DirectSSHHostKeySHA256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}, nil
}
