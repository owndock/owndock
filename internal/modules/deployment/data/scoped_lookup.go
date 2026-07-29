package data

import (
	"context"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

// ScopedReferenceStore is the narrow control-plane surface required to prove
// that every deployment reference belongs to one Project.
type ScopedReferenceStore interface {
	ProjectExists(context.Context, string, string) (bool, error)
	ApplicationExists(context.Context, string, string) (bool, error)
	EnvironmentExists(context.Context, string, string) (bool, error)
	ReleaseExists(context.Context, string, string, string) (bool, error)
	RuntimeTargetExists(context.Context, string, string) (bool, error)
	RuntimeTargetReady(context.Context, string, string) (bool, error)
}

type FormalReferenceLookup struct {
	store ScopedReferenceStore
}

func NewFormalReferenceLookup(store ScopedReferenceStore) *FormalReferenceLookup {
	return &FormalReferenceLookup{store: store}
}

func (l *FormalReferenceLookup) ValidateProject(ctx context.Context, organizationID, projectID string) error {
	exists, err := l.store.ProjectExists(ctx, organizationID, projectID)
	if err != nil {
		return err
	}
	if !exists {
		return biz.ErrNotFound
	}
	return nil
}

func (l *FormalReferenceLookup) Validate(
	ctx context.Context,
	projectID, releaseID, applicationID, environmentID, targetID string,
) error {
	checks := []struct {
		id       string
		notFound error
		exists   func(context.Context, string, string) (bool, error)
	}{
		{applicationID, biz.ErrApplicationNotFound, l.store.ApplicationExists},
		{environmentID, biz.ErrEnvironmentNotFound, l.store.EnvironmentExists},
	}
	for _, check := range checks {
		exists, err := check.exists(ctx, projectID, check.id)
		if err != nil {
			return err
		}
		if !exists {
			return check.notFound
		}
	}
	exists, err := l.store.ReleaseExists(ctx, projectID, applicationID, releaseID)
	if err != nil {
		return err
	}
	if !exists {
		return biz.ErrReleaseNotFound
	}
	exists, err = l.store.RuntimeTargetExists(ctx, projectID, targetID)
	if err != nil {
		return err
	}
	if !exists {
		return biz.ErrRuntimeTargetNotFound
	}
	ready, err := l.store.RuntimeTargetReady(ctx, projectID, targetID)
	if err != nil {
		return err
	}
	if !ready {
		return biz.ErrRuntimeTargetNotReady
	}
	return nil
}
