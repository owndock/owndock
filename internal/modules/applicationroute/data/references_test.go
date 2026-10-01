package data

import (
	"context"
	"errors"
	"testing"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

func TestReferenceResolverRequiresOwnedActiveAgentResources(t *testing.T) {
	source := &controlPlaneReferencesStub{projectExists: true, applicationExists: true,
		stage: "production", target: controlplanebiz.RuntimeTarget{ConnectionMode: runtimeaccess.ModeAgent,
			Status: controlplanebiz.RuntimeTargetStatusReady}}
	resolver := NewReferenceResolver(source)
	references, err := resolver.Resolve(context.Background(), "organization-1", "project-1", "app-1", "env-1", "target-1")
	if err != nil || !references.AgentTarget || references.EnvironmentStage != "production" {
		t.Fatalf("Resolve() = %#v, %v", references, err)
	}
	source.target.Status = controlplanebiz.RuntimeTargetStatusRetiring
	if references, err := resolver.Resolve(context.Background(), "organization-1", "project-1", "app-1", "env-1", "target-1"); err != nil || references.AgentTarget {
		t.Fatalf("retiring Resolve() = %#v, %v", references, err)
	}
	source.projectExists = false
	if _, err := resolver.Resolve(context.Background(), "organization-1", "project-1", "app-1", "env-1", "target-1"); !errors.Is(err, applicationroutebiz.ErrReferenceNotFound) {
		t.Fatalf("missing project error = %v", err)
	}
}

type controlPlaneReferencesStub struct {
	projectExists     bool
	applicationExists bool
	stage             string
	target            controlplanebiz.RuntimeTarget
}

func (s *controlPlaneReferencesStub) ProjectExists(context.Context, string, string) (bool, error) {
	return s.projectExists, nil
}
func (s *controlPlaneReferencesStub) ApplicationExists(context.Context, string, string) (bool, error) {
	return s.applicationExists, nil
}
func (s *controlPlaneReferencesStub) EnvironmentStage(context.Context, string, string) (string, error) {
	return s.stage, nil
}
func (s *controlPlaneReferencesStub) GetRuntimeTarget(context.Context, string, string) (controlplanebiz.RuntimeTarget, error) {
	return s.target, nil
}
