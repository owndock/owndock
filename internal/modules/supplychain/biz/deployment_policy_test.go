package biz

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

func validDeploymentPolicyInput(now time.Time) DeploymentPolicyInput {
	return DeploymentPolicyInput{
		ID: "policy-1", OrganizationID: "organization-1", ProjectID: "project-1",
		Name: "Production baseline", Scope: DeploymentPolicyScopeProject,
		Mode: DeploymentPolicyEnforced, Requirements: DeploymentPolicyRequirements{
			RequireSBOM: true, AllowedSignaturePolicyIDs: []string{"trust-2", "trust-1", "trust-1"},
			MaximumVulnerabilitySeverity: VulnerabilitySeverityHigh,
			MaximumScanAge:               24 * time.Hour,
		}, Enabled: true, Version: 1, CreatedBy: "maintainer-1", UpdatedBy: "maintainer-1",
		CreatedAt: now, UpdatedAt: now,
	}
}

func TestDeploymentPolicyNormalizesRestrictedRequirements(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	item, err := NewDeploymentPolicy(validDeploymentPolicyInput(now))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"trust-1", "trust-2"}; !reflect.DeepEqual(item.Requirements.AllowedSignaturePolicyIDs, want) {
		t.Fatalf("AllowedSignaturePolicyIDs = %v, want %v", item.Requirements.AllowedSignaturePolicyIDs, want)
	}
	for name, mutate := range map[string]func(*DeploymentPolicyInput){
		"empty requirements": func(input *DeploymentPolicyInput) {
			input.Requirements = DeploymentPolicyRequirements{}
		},
		"partial vulnerability gate": func(input *DeploymentPolicyInput) {
			input.Requirements.MaximumScanAge = 0
		},
		"unknown severity": func(input *DeploymentPolicyInput) {
			input.Requirements.MaximumVulnerabilitySeverity = VulnerabilitySeverityUnknown
		},
		"unbounded scan age": func(input *DeploymentPolicyInput) {
			input.Requirements.MaximumScanAge = MaximumDeploymentPolicyScanAge + time.Second
		},
		"arbitrary signer": func(input *DeploymentPolicyInput) {
			input.Requirements.AllowedSignaturePolicyIDs = []string{"*"}
		},
		"project environment": func(input *DeploymentPolicyInput) {
			input.EnvironmentID = "environment-1"
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := validDeploymentPolicyInput(now)
			mutate(&input)
			if _, err := NewDeploymentPolicy(input); !errors.Is(err, ErrInvalidDeploymentPolicy) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDeploymentPolicyEffectiveModeAppliesSafetyFloor(t *testing.T) {
	item, err := NewDeploymentPolicy(validDeploymentPolicyInput(time.Unix(100, 0).UTC()))
	if err != nil {
		t.Fatal(err)
	}
	item.Mode = DeploymentPolicyAdvisory
	for _, test := range []struct {
		stage string
		want  DeploymentPolicyMode
	}{
		{"development", DeploymentPolicyAdvisory},
		{"staging", DeploymentPolicyAdvisory},
		{"production", DeploymentPolicyEnforced},
	} {
		got, enabled, err := item.EffectiveMode(test.stage)
		if err != nil || !enabled || got != test.want {
			t.Errorf("EffectiveMode(%q) = %q, %t, %v; want %q", test.stage, got, enabled, err, test.want)
		}
	}
	item.Enabled = false
	if mode, enabled, err := item.EffectiveMode("production"); err != nil || enabled || mode != "" {
		t.Fatalf("disabled EffectiveMode() = %q, %t, %v", mode, enabled, err)
	}
}

type deploymentPolicyEnvironmentLookupStub struct {
	stages map[string]string
}

func (s deploymentPolicyEnvironmentLookupStub) EnvironmentStage(_ context.Context,
	projectID, environmentID string) (string, error) {
	stage, ok := s.stages[projectID+"/"+environmentID]
	if !ok {
		return "", ErrNotFound
	}
	return stage, nil
}

type deploymentPolicyRepositoryStub struct {
	items map[string]DeploymentPolicy
}

func (s *deploymentPolicyRepositoryStub) CreateDeploymentPolicy(_ context.Context,
	item DeploymentPolicy) (DeploymentPolicy, error) {
	if s.items == nil {
		s.items = make(map[string]DeploymentPolicy)
	}
	for _, current := range s.items {
		if current.OrganizationID == item.OrganizationID && current.ProjectID == item.ProjectID &&
			current.Scope == item.Scope && current.EnvironmentID == item.EnvironmentID {
			return DeploymentPolicy{}, ErrDuplicate
		}
	}
	s.items[item.ID] = item
	return item, nil
}

func (s *deploymentPolicyRepositoryStub) ListDeploymentPolicies(_ context.Context,
	organizationID, projectID string) ([]DeploymentPolicy, error) {
	result := []DeploymentPolicy{}
	for _, item := range s.items {
		if item.OrganizationID == organizationID && item.ProjectID == projectID {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *deploymentPolicyRepositoryStub) GetDeploymentPolicy(_ context.Context,
	organizationID, projectID, policyID string) (DeploymentPolicy, error) {
	item, ok := s.items[policyID]
	if !ok || item.OrganizationID != organizationID || item.ProjectID != projectID {
		return DeploymentPolicy{}, ErrNotFound
	}
	return item, nil
}

func (s *deploymentPolicyRepositoryStub) SaveDeploymentPolicy(_ context.Context,
	item DeploymentPolicy, expectedVersion uint64) (DeploymentPolicy, error) {
	current, ok := s.items[item.ID]
	if !ok || current.Version != expectedVersion {
		return DeploymentPolicy{}, ErrDeploymentPolicyConflict
	}
	s.items[item.ID] = item
	return item, nil
}

type deploymentPolicyAuditStub struct{ events []sharedaudit.Event }

func (s *deploymentPolicyAuditStub) Record(_ context.Context, event sharedaudit.Event) error {
	s.events = append(s.events, event)
	return nil
}

func TestDeploymentPolicyUseCaseEnforcesScopeRoleVersionAndAudit(t *testing.T) {
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	repository := &deploymentPolicyRepositoryStub{}
	audits := &deploymentPolicyAuditStub{}
	sequence := 0
	useCase, err := NewDeploymentPolicyUseCase(projectLookupStub{exists: true},
		deploymentPolicyEnvironmentLookupStub{stages: map[string]string{
			"project-1/development-1": "development", "project-1/production-1": "production",
		}}, repository, func() (string, error) {
			sequence++
			return fmt.Sprintf("identifier-%d", sequence), nil
		}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	useCase.WithAudit(transaction.Passthrough{}, audits)
	viewer := security.Principal{UserID: "viewer-1", OrganizationID: "organization-1",
		SessionID: "session-1", Role: security.RoleViewer}
	input := validDeploymentPolicyInput(now)
	input.ID, input.OrganizationID, input.ProjectID, input.CreatedBy, input.UpdatedBy = "", "", "", "", ""
	input.Version, input.CreatedAt, input.UpdatedAt = 0, time.Time{}, time.Time{}
	if _, err := useCase.Create(t.Context(), viewer, "project-1", input, "request-viewer"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("viewer Create() error = %v", err)
	}
	maintainer := viewer
	maintainer.UserID, maintainer.Role = "maintainer-1", security.RoleMaintainer
	created, err := useCase.Create(t.Context(), maintainer, "project-1", input, "request-create")
	if err != nil || created.Version != 1 || created.CreatedBy != maintainer.UserID ||
		len(audits.events) != 1 || audits.events[0].Action != "deployment_policy.create" ||
		audits.events[0].RequestID != "request-create" {
		t.Fatalf("Create() = %+v, %v audits=%+v", created, err, audits.events)
	}
	input.Name = "Updated baseline"
	updated, err := useCase.Update(t.Context(), maintainer, "project-1", created.ID, 1, input, "request-update")
	if err != nil || updated.Version != 2 || created.Name == updated.Name ||
		len(audits.events) != 2 || audits.events[1].Action != "deployment_policy.update" {
		t.Fatalf("Update() = %+v, %v audits=%+v", updated, err, audits.events)
	}
	if _, err := useCase.Update(t.Context(), maintainer, "project-1", created.ID, 1, input, "stale"); !errors.Is(err, ErrDeploymentPolicyConflict) {
		t.Fatalf("stale Update() error = %v", err)
	}

	environmentInput := input
	environmentInput.Scope, environmentInput.EnvironmentID = DeploymentPolicyScopeEnvironment, "development-1"
	environmentInput.Mode = DeploymentPolicyEnforced
	if _, err := useCase.Create(t.Context(), maintainer, "project-1", environmentInput, "request-development"); !errors.Is(err, ErrInvalidDeploymentPolicy) {
		t.Fatalf("enforced development policy error = %v", err)
	}
	environmentInput.EnvironmentID, environmentInput.Mode = "production-1", DeploymentPolicyAdvisory
	if _, err := useCase.Create(t.Context(), maintainer, "project-1", environmentInput, "request-production"); !errors.Is(err, ErrInvalidDeploymentPolicy) {
		t.Fatalf("advisory production policy error = %v", err)
	}
}
