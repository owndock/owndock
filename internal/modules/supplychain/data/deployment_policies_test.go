package data

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func deploymentPolicyDataFixture(t *testing.T) biz.DeploymentPolicy {
	t.Helper()
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	item, err := biz.NewDeploymentPolicy(biz.DeploymentPolicyInput{
		ID: "policy-1", OrganizationID: "organization-1", ProjectID: "project-1",
		Name: "Production baseline", Scope: biz.DeploymentPolicyScopeEnvironment,
		EnvironmentID: "environment-1", Mode: biz.DeploymentPolicyEnforced,
		Requirements: biz.DeploymentPolicyRequirements{
			RequireSBOM: true, RequireProvenance: true,
			AllowedSignaturePolicyIDs:    []string{"trust-1", "trust-2"},
			MaximumVulnerabilitySeverity: biz.VulnerabilitySeverityMedium,
			MaximumScanAge:               12 * time.Hour,
		}, Enabled: true, Version: 1, CreatedBy: "maintainer-1", UpdatedBy: "maintainer-1",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestDeploymentPolicyDocumentRoundTripRejectsCorruption(t *testing.T) {
	item := deploymentPolicyDataFixture(t)
	document := deploymentPolicyDocumentFromDomain(item)
	restored, err := document.domain()
	if err != nil || !reflect.DeepEqual(restored, item) {
		t.Fatalf("round trip = %+v, %v", restored, err)
	}
	document.Requirements.MaximumScanAgeSeconds = 1
	if _, err := document.domain(); !errors.Is(err, biz.ErrInvalidDeploymentPolicy) {
		t.Fatalf("corrupt document error = %v", err)
	}
}
