package data

import (
	"context"
	"errors"
	"testing"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

type lookupProbe struct {
	projectIDs []string
	missing    string
	notReady   string
}

func (p *lookupProbe) result(projectID, resource string) (bool, error) {
	p.projectIDs = append(p.projectIDs, projectID)
	return resource != p.missing, nil
}
func (p *lookupProbe) ProjectExists(_ context.Context, organizationID, projectID string) (bool, error) {
	if organizationID != "organization-1" {
		return false, nil
	}
	return p.result(projectID, projectID)
}
func (p *lookupProbe) ApplicationExists(_ context.Context, projectID, id string) (bool, error) {
	return p.result(projectID, id)
}
func (p *lookupProbe) EnvironmentExists(_ context.Context, projectID, id string) (bool, error) {
	return p.result(projectID, id)
}
func (p *lookupProbe) ReleaseExists(_ context.Context, projectID, _ string, id string) (bool, error) {
	return p.result(projectID, id)
}
func (p *lookupProbe) RuntimeTargetExists(_ context.Context, projectID, id string) (bool, error) {
	return p.result(projectID, id)
}
func (p *lookupProbe) RuntimeTargetReady(_ context.Context, projectID, id string) (bool, error) {
	p.projectIDs = append(p.projectIDs, projectID)
	return id != p.notReady, nil
}

func TestFormalReferenceLookupRejectsTargetThatIsNotReady(t *testing.T) {
	lookup := NewFormalReferenceLookup(&lookupProbe{notReady: "target-1"})
	err := lookup.Validate(
		t.Context(), "project-1", "release-1", "app-1", "env-1", "target-1",
	)
	if !errors.Is(err, biz.ErrRuntimeTargetNotReady) {
		t.Fatalf("error = %v", err)
	}
}

func TestFormalReferenceLookupPropagatesProjectScope(t *testing.T) {
	probe := &lookupProbe{}
	lookup := NewFormalReferenceLookup(probe)
	if err := lookup.ValidateProject(t.Context(), "organization-1", "project-1"); err != nil {
		t.Fatal(err)
	}
	if err := lookup.Validate(t.Context(), "project-1", "release-1", "app-1", "env-1", "target-1"); err != nil {
		t.Fatal(err)
	}
	if len(probe.projectIDs) != 6 {
		t.Fatalf("scope checks = %d", len(probe.projectIDs))
	}
	for _, projectID := range probe.projectIDs {
		if projectID != "project-1" {
			t.Fatalf("project scope = %q", projectID)
		}
	}
}
