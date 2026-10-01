package data

import (
	"context"
	"errors"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	controlplanebiz "github.com/owndock/owndock/internal/modules/controlplane/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type ControlPlaneReferences interface {
	ProjectExists(context.Context, string, string) (bool, error)
	ApplicationExists(context.Context, string, string) (bool, error)
	EnvironmentStage(context.Context, string, string) (string, error)
	GetRuntimeTarget(context.Context, string, string) (controlplanebiz.RuntimeTarget, error)
}

type ReferenceResolver struct {
	source ControlPlaneReferences
}

func NewReferenceResolver(source ControlPlaneReferences) *ReferenceResolver {
	return &ReferenceResolver{source: source}
}

func (r *ReferenceResolver) Resolve(ctx context.Context, organizationID, projectID, applicationID, environmentID, runtimeTargetID string) (applicationroutebiz.References, error) {
	if r == nil || r.source == nil {
		return applicationroutebiz.References{}, applicationroutebiz.ErrUnavailable
	}
	projectExists, err := r.source.ProjectExists(ctx, organizationID, projectID)
	if err != nil {
		return applicationroutebiz.References{}, err
	}
	if !projectExists {
		return applicationroutebiz.References{}, applicationroutebiz.ErrReferenceNotFound
	}
	applicationExists, err := r.source.ApplicationExists(ctx, projectID, applicationID)
	if err != nil {
		return applicationroutebiz.References{}, err
	}
	if !applicationExists {
		return applicationroutebiz.References{}, applicationroutebiz.ErrReferenceNotFound
	}
	stage, err := r.source.EnvironmentStage(ctx, projectID, environmentID)
	if errors.Is(err, controlplanebiz.ErrNotFound) {
		return applicationroutebiz.References{}, applicationroutebiz.ErrReferenceNotFound
	}
	if err != nil {
		return applicationroutebiz.References{}, err
	}
	target, err := r.source.GetRuntimeTarget(ctx, projectID, runtimeTargetID)
	if errors.Is(err, controlplanebiz.ErrNotFound) {
		return applicationroutebiz.References{}, applicationroutebiz.ErrReferenceNotFound
	}
	if err != nil {
		return applicationroutebiz.References{}, err
	}
	return applicationroutebiz.References{EnvironmentStage: stage,
		AgentTarget: target.ConnectionMode == runtimeaccess.ModeAgent &&
			target.Status != controlplanebiz.RuntimeTargetStatusRetiring}, nil
}

var _ applicationroutebiz.ReferenceResolver = (*ReferenceResolver)(nil)
