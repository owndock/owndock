package data

import (
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/controlplane/biz"
)

func TestRuntimeTargetDocumentPreservesDurableRetirementMetadata(t *testing.T) {
	startedAt := time.Unix(100, 0).UTC()
	domain := (runtimeTargetDocument{
		ID: "target-1", ProjectID: "project-1",
		Status: biz.RuntimeTargetStatusRetiring,
		Retirement: &runtimeTargetRetirementDocument{
			OrganizationID: "organization-1", ActorID: "owner-1",
			RequestID: "request-1", StartedAt: startedAt,
		},
	}).domain()
	if domain.Retirement == nil ||
		domain.Retirement.OrganizationID != "organization-1" ||
		domain.Retirement.ActorID != "owner-1" ||
		domain.Retirement.RequestID != "request-1" ||
		!domain.Retirement.StartedAt.Equal(startedAt) {
		t.Fatalf("retirement = %+v", domain.Retirement)
	}
}
