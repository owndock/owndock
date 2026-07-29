package data

import (
	"context"
	"testing"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type executionReferenceStoreStub struct{}

func (executionReferenceStoreStub) ReleaseExecution(
	context.Context, string, string, string,
) (string, error) {
	return "registry.example.com/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}

type fullExecutionReferenceStoreStub struct {
	executionReferenceStoreStub
}

func (fullExecutionReferenceStoreStub) ReleaseExecutionSpec(
	context.Context, string, string, string,
) (string, string, string, string, runtimespec.Spec, error) {
	return "registry.example.com/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"registry.example.com", "robot", "secret://registry-password",
		runtimespec.Spec{
			EnvironmentKeys: []string{"DATABASE_URL"},
			Resources: runtimespec.Resources{
				CPUMilli: 500, MemoryBytes: 256 * 1024 * 1024,
			},
		}, nil
}

func (fullExecutionReferenceStoreStub) EnvironmentExecution(
	context.Context, string, string,
) (map[string]string, error) {
	return map[string]string{
		"DATABASE_URL": "secret://database-url",
		"IGNORED":      "value",
	}, nil
}

func (executionReferenceStoreStub) RuntimeTargetExecution(
	context.Context, string, string,
) (runtimeaccess.Connection, error) {
	return runtimeaccess.NewDirectDocker(
		"", "tcp://docker.example.com:2376", "docker.example.com", "secret://production",
	)
}

func TestExecutionResolverBuildsRegistryAndEnvironmentPlan(t *testing.T) {
	resolver := NewExecutionResolver(fullExecutionReferenceStoreStub{})
	plan, err := resolver.ResolveExecution(t.Context(), biz.Deployment{
		ID: "deployment", ProjectID: "project", ApplicationID: "application",
		EnvironmentID: "environment", RuntimeTargetID: "target", ReleaseID: "release",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.RegistryUsername != "robot" ||
		plan.RegistryPasswordRef != "secret://registry-password" ||
		plan.EnvironmentBindings["DATABASE_URL"] != "secret://database-url" ||
		len(plan.EnvironmentBindings) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestExecutionResolverBuildsStableRuntimePlan(t *testing.T) {
	resolver := NewExecutionResolver(executionReferenceStoreStub{})
	deployment := biz.Deployment{
		ID: "deployment", ProjectID: "project", ApplicationID: "application",
		EnvironmentID: "environment", RuntimeTargetID: "target", ReleaseID: "release",
	}
	first, err := resolver.ResolveExecution(t.Context(), deployment)
	if err != nil {
		t.Fatal(err)
	}
	deployment.ID = "retry"
	second, err := resolver.ResolveExecution(t.Context(), deployment)
	if err != nil {
		t.Fatal(err)
	}
	if first.ContainerName == "" || first.ContainerName != second.ContainerName {
		t.Fatalf("container names = %q, %q", first.ContainerName, second.ContainerName)
	}
	if first.DeploymentID != "deployment" || second.DeploymentID != "retry" ||
		first.TargetConnection.DirectDocker == nil ||
		first.TargetConnection.DirectDocker.CredentialRef != "secret://production" {
		t.Fatalf("plans = %+v, %+v", first, second)
	}
}
