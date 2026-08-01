package biz

import (
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
)

func TestDefaultTerminalPoliciesAreRestrictive(t *testing.T) {
	project := DefaultProjectPolicy("organization-1", "project-1")
	if err := project.Validate(); err != nil {
		t.Fatal(err)
	}
	if !project.AllowsContainer(security.RoleMaintainer, "development", "target-1") ||
		project.AllowsContainer(security.RoleDeveloper, "development", "target-1") ||
		project.AllowsContainer(security.RoleMaintainer, "production", "target-1") {
		t.Fatalf("unexpected project default policy: %+v", project)
	}
	organization := DefaultOrganizationPolicy("organization-1")
	if err := organization.Validate(); err != nil {
		t.Fatal(err)
	}
	if !organization.AllowsHost(security.RoleOwner, "host-1") ||
		organization.AllowsHost(security.RoleMaintainer, "host-1") {
		t.Fatalf("unexpected organization default policy: %+v", organization)
	}
}

func TestProjectPolicyExplicitlyEnablesDeveloperAndProduction(t *testing.T) {
	policy, err := NewProjectPolicy(
		"policy-1", "organization-1", "project-1", "owner-1",
		PolicyInput{
			Enabled: true,
			AllowedRoles: []security.Role{
				security.RoleDeveloper, security.RoleOwner, security.RoleMaintainer,
			},
			EnvironmentStages: []string{"production", "development"},
			RuntimeTargetIDs:  []string{"target-2"},
			IdleTimeout:       5 * time.Minute, MaximumDuration: time.Hour,
			MaximumPerUser: 2, MaximumPerTarget: 4,
			RevocationGracePeriod: 15 * time.Second,
		},
		time.Unix(100, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.AllowsContainer(security.RoleDeveloper, "production", "target-2") ||
		policy.AllowsContainer(security.RoleDeveloper, "production", "target-1") {
		t.Fatalf("unexpected scoped policy: %+v", policy)
	}
}

func TestTerminalPolicyValidationRejectsUnsafeInputs(t *testing.T) {
	base := PolicyInput{
		Enabled: true, AllowedRoles: []security.Role{security.RoleOwner},
		EnvironmentStages: []string{"development"},
		IdleTimeout:       5 * time.Minute, MaximumDuration: time.Hour,
		MaximumPerUser: 1, MaximumPerTarget: 2,
		RevocationGracePeriod: 15 * time.Second,
	}
	tests := []struct {
		name   string
		mutate func(*PolicyInput)
	}{
		{name: "viewer", mutate: func(input *PolicyInput) { input.AllowedRoles = append(input.AllowedRoles, security.RoleViewer) }},
		{name: "no owner", mutate: func(input *PolicyInput) { input.AllowedRoles = []security.Role{security.RoleDeveloper} }},
		{name: "unknown stage", mutate: func(input *PolicyInput) { input.EnvironmentStages = []string{"preview"} }},
		{name: "short idle", mutate: func(input *PolicyInput) { input.IdleTimeout = 30 * time.Second }},
		{name: "idle exceeds maximum", mutate: func(input *PolicyInput) { input.MaximumDuration = input.IdleTimeout }},
		{name: "too many user sessions", mutate: func(input *PolicyInput) { input.MaximumPerUser = 11 }},
		{name: "too many target sessions", mutate: func(input *PolicyInput) { input.MaximumPerTarget = 51 }},
		{name: "long revocation", mutate: func(input *PolicyInput) { input.RevocationGracePeriod = 6 * time.Minute }},
		{name: "invalid target ID", mutate: func(input *PolicyInput) { input.RuntimeTargetIDs = []string{"target/one"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.AllowedRoles = append([]security.Role(nil), base.AllowedRoles...)
			input.EnvironmentStages = append([]string(nil), base.EnvironmentStages...)
			test.mutate(&input)
			_, err := NewProjectPolicy(
				"policy-1", "organization-1", "project-1", "owner-1", input, time.Now(),
			)
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
