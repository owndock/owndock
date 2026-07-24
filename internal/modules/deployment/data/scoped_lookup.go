package data

import "context"

// ScopedReferenceStore is the narrow control-plane surface needed by formal
// deployments. It deliberately exposes existence checks only.
type ScopedReferenceStore interface {
	ReleaseExists(context.Context, string, string) (bool, error)
	RuntimeTargetExists(context.Context, string, string) (bool, error)
}

type ReleaseLookup struct {
	store     ScopedReferenceStore
	projectID string
}

func NewReleaseLookup(store ScopedReferenceStore, projectID string) *ReleaseLookup {
	return &ReleaseLookup{store: store, projectID: projectID}
}

func (l *ReleaseLookup) Exists(ctx context.Context, releaseID string) (bool, error) {
	return l.store.ReleaseExists(ctx, l.projectID, releaseID)
}

type RuntimeTargetLookup struct {
	store     ScopedReferenceStore
	projectID string
}

func NewRuntimeTargetLookup(store ScopedReferenceStore, projectID string) *RuntimeTargetLookup {
	return &RuntimeTargetLookup{store: store, projectID: projectID}
}

func (l *RuntimeTargetLookup) Exists(ctx context.Context, targetID string) (bool, error) {
	return l.store.RuntimeTargetExists(ctx, l.projectID, targetID)
}
