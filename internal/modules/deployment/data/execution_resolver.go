package data

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

type ExecutionReferenceStore interface {
	ReleaseExecution(
		context.Context,
		string,
		string,
		string,
	) (imageDigest string, err error)
	RuntimeTargetExecution(
		context.Context,
		string,
		string,
	) (runtimeaccess.Connection, error)
}

type registryExecutionReferenceStore interface {
	ReleaseExecutionRegistry(
		context.Context,
		string,
		string,
		string,
	) (imageDigest, server, username, passwordRef string, err error)
}

type releaseSpecExecutionReferenceStore interface {
	ReleaseExecutionSpec(
		context.Context,
		string,
		string,
		string,
	) (
		imageDigest, server, username, passwordRef string,
		spec runtimespec.Spec,
		err error,
	)
}

type environmentExecutionReferenceStore interface {
	EnvironmentExecution(context.Context, string, string) (map[string]string, error)
}

type ExecutionResolver struct {
	store ExecutionReferenceStore
}

func NewExecutionResolver(store ExecutionReferenceStore) *ExecutionResolver {
	return &ExecutionResolver{store: store}
}

func (r *ExecutionResolver) ResolveExecution(
	ctx context.Context,
	deployment biz.Deployment,
) (biz.ExecutionPlan, error) {
	var image, registryServer, registryUsername, registryPasswordRef string
	var runtimeSpec runtimespec.Spec
	var err error
	if specStore, ok := r.store.(releaseSpecExecutionReferenceStore); ok {
		image, registryServer, registryUsername, registryPasswordRef, runtimeSpec, err =
			specStore.ReleaseExecutionSpec(
				ctx, deployment.ProjectID, deployment.ApplicationID, deployment.ReleaseID,
			)
	} else if registryStore, ok := r.store.(registryExecutionReferenceStore); ok {
		image, registryServer, registryUsername, registryPasswordRef, err =
			registryStore.ReleaseExecutionRegistry(
				ctx, deployment.ProjectID, deployment.ApplicationID, deployment.ReleaseID,
			)
	} else {
		image, err = r.store.ReleaseExecution(
			ctx, deployment.ProjectID, deployment.ApplicationID, deployment.ReleaseID,
		)
	}
	if err != nil {
		return biz.ExecutionPlan{}, fmt.Errorf("resolve release: %w", err)
	}
	var environmentBindings map[string]string
	if len(runtimeSpec.EnvironmentKeys) > 0 {
		environmentStore, ok := r.store.(environmentExecutionReferenceStore)
		if !ok {
			return biz.ExecutionPlan{}, fmt.Errorf("resolve environment: execution lookup is unavailable")
		}
		variables, lookupErr := environmentStore.EnvironmentExecution(
			ctx, deployment.ProjectID, deployment.EnvironmentID,
		)
		if lookupErr != nil {
			return biz.ExecutionPlan{}, fmt.Errorf("resolve environment: %w", lookupErr)
		}
		if _, validationErr := runtimespec.ValidateBindings(runtimeSpec, variables); validationErr != nil {
			return biz.ExecutionPlan{}, fmt.Errorf("resolve environment: %w", validationErr)
		}
		environmentBindings = make(map[string]string, len(runtimeSpec.EnvironmentKeys))
		for _, name := range runtimeSpec.EnvironmentKeys {
			environmentBindings[name] = variables[name]
		}
	}
	targetConnection, err := r.store.RuntimeTargetExecution(
		ctx, deployment.ProjectID, deployment.RuntimeTargetID,
	)
	if err != nil {
		return biz.ExecutionPlan{}, fmt.Errorf("resolve runtime target: %w", err)
	}
	scope := deployment.ProjectID + "\x00" + deployment.ApplicationID + "\x00" +
		deployment.EnvironmentID + "\x00" + deployment.RuntimeTargetID
	sum := sha256.Sum256([]byte(scope))
	return biz.ExecutionPlan{
		DeploymentID: deployment.ID, WorkerID: deployment.Lease.Owner,
		FencingToken: deployment.Lease.Generation, ProjectID: deployment.ProjectID,
		ApplicationID: deployment.ApplicationID, EnvironmentID: deployment.EnvironmentID,
		RuntimeTargetID: deployment.RuntimeTargetID, ImageDigest: image,
		TargetConnection: targetConnection,
		RegistryServer:   registryServer, RegistryUsername: registryUsername,
		RegistryPasswordRef: registryPasswordRef,
		RuntimeSpec:         runtimeSpec, EnvironmentBindings: environmentBindings,
		ContainerName: fmt.Sprintf("owndock-%x", sum[:12]),
	}, nil
}
