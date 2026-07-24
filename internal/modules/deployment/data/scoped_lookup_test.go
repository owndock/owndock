package data

import (
	"context"
	"testing"
)

type lookupProbe struct {
	projectID string
	releaseID string
	targetID  string
}

func (p *lookupProbe) ReleaseExists(_ context.Context, projectID, releaseID string) (bool, error) {
	p.projectID, p.releaseID = projectID, releaseID
	return true, nil
}
func (p *lookupProbe) RuntimeTargetExists(_ context.Context, projectID, targetID string) (bool, error) {
	p.projectID, p.targetID = projectID, targetID
	return true, nil
}

func TestScopedLookupsPropagateProjectScope(t *testing.T) {
	probe := &lookupProbe{}
	releases := NewReleaseLookup(probe, "project-1")
	targets := NewRuntimeTargetLookup(probe, "project-1")
	if ok, err := releases.Exists(context.Background(), "release-1"); err != nil || !ok {
		t.Fatalf("release lookup = %t, %v", ok, err)
	}
	if probe.projectID != "project-1" || probe.releaseID != "release-1" {
		t.Fatalf("release scope = %+v", probe)
	}
	if ok, err := targets.Exists(context.Background(), "target-1"); err != nil || !ok {
		t.Fatalf("target lookup = %t, %v", ok, err)
	}
	if probe.projectID != "project-1" || probe.targetID != "target-1" {
		t.Fatalf("target scope = %+v", probe)
	}
}
