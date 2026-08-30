package biz

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

const (
	MinimumDeploymentPolicyScanAge = time.Hour
	MaximumDeploymentPolicyScanAge = 30 * 24 * time.Hour
)

var (
	ErrInvalidDeploymentPolicy  = errors.New("deployment policy is invalid")
	ErrDeploymentPolicyConflict = errors.New("deployment policy version or scope conflicts")
)

type DeploymentPolicyScope string

const (
	DeploymentPolicyScopeProject     DeploymentPolicyScope = "project"
	DeploymentPolicyScopeEnvironment DeploymentPolicyScope = "environment"
)

func (s DeploymentPolicyScope) Valid() bool {
	return s == DeploymentPolicyScopeProject || s == DeploymentPolicyScopeEnvironment
}

type DeploymentPolicyMode string

const (
	DeploymentPolicyAdvisory DeploymentPolicyMode = "advisory"
	DeploymentPolicyEnforced DeploymentPolicyMode = "enforced"
)

func (m DeploymentPolicyMode) Valid() bool {
	return m == DeploymentPolicyAdvisory || m == DeploymentPolicyEnforced
}

type DeploymentPolicyRequirements struct {
	RequireSBOM                  bool
	RequireProvenance            bool
	AllowedSignaturePolicyIDs    []string
	MaximumVulnerabilitySeverity VulnerabilitySeverity
	MaximumScanAge               time.Duration
}

func normalizeDeploymentPolicyRequirements(input DeploymentPolicyRequirements) (DeploymentPolicyRequirements, error) {
	result := input
	result.AllowedSignaturePolicyIDs = append([]string{}, input.AllowedSignaturePolicyIDs...)
	for index := range result.AllowedSignaturePolicyIDs {
		result.AllowedSignaturePolicyIDs[index] = strings.TrimSpace(result.AllowedSignaturePolicyIDs[index])
		if !validID(result.AllowedSignaturePolicyIDs[index]) {
			return DeploymentPolicyRequirements{}, ErrInvalidDeploymentPolicy
		}
	}
	slices.Sort(result.AllowedSignaturePolicyIDs)
	result.AllowedSignaturePolicyIDs = slices.Compact(result.AllowedSignaturePolicyIDs)
	if len(result.AllowedSignaturePolicyIDs) > 16 {
		return DeploymentPolicyRequirements{}, ErrInvalidDeploymentPolicy
	}
	vulnerabilityGate := result.MaximumVulnerabilitySeverity != "" || result.MaximumScanAge != 0
	if vulnerabilityGate && (!result.MaximumVulnerabilitySeverity.Valid() ||
		result.MaximumVulnerabilitySeverity == VulnerabilitySeverityUnknown ||
		result.MaximumScanAge < MinimumDeploymentPolicyScanAge ||
		result.MaximumScanAge > MaximumDeploymentPolicyScanAge) {
		return DeploymentPolicyRequirements{}, ErrInvalidDeploymentPolicy
	}
	if !result.RequireSBOM && !result.RequireProvenance &&
		len(result.AllowedSignaturePolicyIDs) == 0 && !vulnerabilityGate {
		return DeploymentPolicyRequirements{}, ErrInvalidDeploymentPolicy
	}
	return result, nil
}

type DeploymentPolicy struct {
	ID             string
	OrganizationID string
	ProjectID      string
	Name           string
	Scope          DeploymentPolicyScope
	EnvironmentID  string
	Mode           DeploymentPolicyMode
	Requirements   DeploymentPolicyRequirements
	Enabled        bool
	Version        uint64
	CreatedBy      string
	UpdatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type DeploymentPolicyInput struct {
	ID             string
	OrganizationID string
	ProjectID      string
	Name           string
	Scope          DeploymentPolicyScope
	EnvironmentID  string
	Mode           DeploymentPolicyMode
	Requirements   DeploymentPolicyRequirements
	Enabled        bool
	Version        uint64
	CreatedBy      string
	UpdatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func NewDeploymentPolicy(input DeploymentPolicyInput) (DeploymentPolicy, error) {
	requirements, err := normalizeDeploymentPolicyRequirements(input.Requirements)
	if err != nil {
		return DeploymentPolicy{}, err
	}
	item := DeploymentPolicy{ID: strings.TrimSpace(input.ID),
		OrganizationID: strings.TrimSpace(input.OrganizationID), ProjectID: strings.TrimSpace(input.ProjectID),
		Name: strings.TrimSpace(input.Name), Scope: input.Scope,
		EnvironmentID: strings.TrimSpace(input.EnvironmentID), Mode: input.Mode,
		Requirements: requirements, Enabled: input.Enabled, Version: input.Version,
		CreatedBy: strings.TrimSpace(input.CreatedBy), UpdatedBy: strings.TrimSpace(input.UpdatedBy),
		CreatedAt: input.CreatedAt.UTC(), UpdatedAt: input.UpdatedAt.UTC()}
	if !validID(item.ID) || !validID(item.OrganizationID) || !validID(item.ProjectID) ||
		!validText(item.Name, 100) || !item.Scope.Valid() || !item.Mode.Valid() ||
		item.Version == 0 || !validID(item.CreatedBy) || !validID(item.UpdatedBy) ||
		item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) {
		return DeploymentPolicy{}, ErrInvalidDeploymentPolicy
	}
	if item.Scope == DeploymentPolicyScopeProject {
		if item.EnvironmentID != "" {
			return DeploymentPolicy{}, ErrInvalidDeploymentPolicy
		}
	} else if !validID(item.EnvironmentID) {
		return DeploymentPolicy{}, ErrInvalidDeploymentPolicy
	}
	return item, nil
}

// EffectiveMode applies the product's non-configurable safety floor. An
// enabled development policy can only warn, while an enabled production
// policy always blocks. Staging follows the stored advisory/enforced choice.
func (p DeploymentPolicy) EffectiveMode(environmentStage string) (DeploymentPolicyMode, bool, error) {
	if !p.Enabled {
		return "", false, nil
	}
	switch strings.TrimSpace(environmentStage) {
	case "development":
		return DeploymentPolicyAdvisory, true, nil
	case "staging":
		return p.Mode, true, nil
	case "production":
		return DeploymentPolicyEnforced, true, nil
	default:
		return "", false, ErrInvalidDeploymentPolicy
	}
}

type DeploymentPolicyRepository interface {
	CreateDeploymentPolicy(context.Context, DeploymentPolicy) (DeploymentPolicy, error)
	ListDeploymentPolicies(context.Context, string, string) ([]DeploymentPolicy, error)
	GetDeploymentPolicy(context.Context, string, string, string) (DeploymentPolicy, error)
	SaveDeploymentPolicy(context.Context, DeploymentPolicy, uint64) (DeploymentPolicy, error)
}

type DeploymentPolicyEnvironmentLookup interface {
	EnvironmentStage(context.Context, string, string) (string, error)
}

type DeploymentPolicyUseCase struct {
	projects     ProjectLookup
	environments DeploymentPolicyEnvironmentLookup
	policies     DeploymentPolicyRepository
	newID        func() (string, error)
	now          func() time.Time
	transaction  transaction.Manager
	auditor      sharedaudit.Recorder
}

func NewDeploymentPolicyUseCase(projects ProjectLookup, environments DeploymentPolicyEnvironmentLookup,
	policies DeploymentPolicyRepository, newID func() (string, error), now func() time.Time,
) (*DeploymentPolicyUseCase, error) {
	if projects == nil || environments == nil || policies == nil || newID == nil || now == nil {
		return nil, ErrUnavailable
	}
	return &DeploymentPolicyUseCase{projects: projects, environments: environments,
		policies: policies, newID: newID, now: now}, nil
}

func (u *DeploymentPolicyUseCase) WithAudit(manager transaction.Manager,
	auditor sharedaudit.Recorder) *DeploymentPolicyUseCase {
	u.transaction, u.auditor = manager, auditor
	return u
}

func (u *DeploymentPolicyUseCase) Create(ctx context.Context, principal security.Principal,
	projectID string, input DeploymentPolicyInput, requestID string) (DeploymentPolicy, error) {
	if err := principal.Require(security.PermissionDeploymentPolicyWrite); err != nil {
		return DeploymentPolicy{}, err
	}
	projectID = strings.TrimSpace(projectID)
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return DeploymentPolicy{}, err
	}
	if err := u.validateScope(ctx, projectID, input.Scope, input.EnvironmentID, input.Mode); err != nil {
		return DeploymentPolicy{}, err
	}
	id, err := u.newID()
	if err != nil {
		return DeploymentPolicy{}, err
	}
	now := u.now().UTC()
	input.ID, input.OrganizationID, input.ProjectID = id, principal.OrganizationID, projectID
	input.Version, input.CreatedBy, input.UpdatedBy = 1, principal.UserID, principal.UserID
	input.CreatedAt, input.UpdatedAt = now, now
	item, err := NewDeploymentPolicy(input)
	if err != nil {
		return DeploymentPolicy{}, err
	}
	return u.create(ctx, principal, item, requestID, now)
}

func (u *DeploymentPolicyUseCase) List(ctx context.Context, principal security.Principal,
	projectID string) ([]DeploymentPolicy, error) {
	if err := principal.Require(security.PermissionDeploymentPolicyRead); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return nil, err
	}
	return u.policies.ListDeploymentPolicies(ctx, principal.OrganizationID, projectID)
}

func (u *DeploymentPolicyUseCase) Get(ctx context.Context, principal security.Principal,
	projectID, policyID string) (DeploymentPolicy, error) {
	if err := principal.Require(security.PermissionDeploymentPolicyRead); err != nil {
		return DeploymentPolicy{}, err
	}
	projectID, policyID = strings.TrimSpace(projectID), strings.TrimSpace(policyID)
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return DeploymentPolicy{}, err
	}
	if !validID(policyID) {
		return DeploymentPolicy{}, ErrInvalidDeploymentPolicy
	}
	return u.policies.GetDeploymentPolicy(ctx, principal.OrganizationID, projectID, policyID)
}

func (u *DeploymentPolicyUseCase) Update(ctx context.Context, principal security.Principal,
	projectID, policyID string, expectedVersion uint64, input DeploymentPolicyInput,
	requestID string) (DeploymentPolicy, error) {
	if err := principal.Require(security.PermissionDeploymentPolicyWrite); err != nil {
		return DeploymentPolicy{}, err
	}
	projectID, policyID = strings.TrimSpace(projectID), strings.TrimSpace(policyID)
	if err := u.requireProject(ctx, principal, projectID); err != nil {
		return DeploymentPolicy{}, err
	}
	current, err := u.policies.GetDeploymentPolicy(ctx, principal.OrganizationID, projectID, policyID)
	if err != nil {
		return DeploymentPolicy{}, err
	}
	if expectedVersion == 0 || current.Version != expectedVersion ||
		input.Scope != current.Scope || strings.TrimSpace(input.EnvironmentID) != current.EnvironmentID {
		return DeploymentPolicy{}, ErrDeploymentPolicyConflict
	}
	if err := u.validateScope(ctx, projectID, input.Scope, input.EnvironmentID, input.Mode); err != nil {
		return DeploymentPolicy{}, err
	}
	input.ID, input.OrganizationID, input.ProjectID = current.ID, current.OrganizationID, current.ProjectID
	input.Version, input.CreatedBy, input.UpdatedBy = current.Version+1, current.CreatedBy, principal.UserID
	input.CreatedAt, input.UpdatedAt = current.CreatedAt, u.now().UTC()
	updated, err := NewDeploymentPolicy(input)
	if err != nil {
		return DeploymentPolicy{}, err
	}
	return u.save(ctx, principal, updated, expectedVersion, requestID)
}

func (u *DeploymentPolicyUseCase) validateScope(ctx context.Context, projectID string,
	scope DeploymentPolicyScope, environmentID string, mode DeploymentPolicyMode) error {
	if scope == DeploymentPolicyScopeProject {
		if strings.TrimSpace(environmentID) != "" {
			return ErrInvalidDeploymentPolicy
		}
		return nil
	}
	if scope != DeploymentPolicyScopeEnvironment || !validID(strings.TrimSpace(environmentID)) {
		return ErrInvalidDeploymentPolicy
	}
	stage, err := u.environments.EnvironmentStage(ctx, projectID, strings.TrimSpace(environmentID))
	if err != nil {
		return err
	}
	switch stage {
	case "development":
		if mode != DeploymentPolicyAdvisory {
			return ErrInvalidDeploymentPolicy
		}
	case "staging":
	case "production":
		if mode != DeploymentPolicyEnforced {
			return ErrInvalidDeploymentPolicy
		}
	default:
		return ErrInvalidDeploymentPolicy
	}
	return nil
}

func (u *DeploymentPolicyUseCase) requireProject(ctx context.Context, principal security.Principal,
	projectID string) error {
	if !validID(projectID) {
		return ErrInvalidDeploymentPolicy
	}
	exists, err := u.projects.ProjectExists(ctx, principal.OrganizationID, projectID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (u *DeploymentPolicyUseCase) create(ctx context.Context, principal security.Principal,
	item DeploymentPolicy, requestID string, now time.Time) (DeploymentPolicy, error) {
	if u.transaction == nil || u.auditor == nil {
		return u.policies.CreateDeploymentPolicy(ctx, item)
	}
	var created DeploymentPolicy
	err := u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var createErr error
		created, createErr = u.policies.CreateDeploymentPolicy(transactionContext, item)
		if createErr != nil {
			return createErr
		}
		return u.recordAudit(transactionContext, principal, item, "deployment_policy.create", requestID, now)
	})
	return created, err
}

func (u *DeploymentPolicyUseCase) save(ctx context.Context, principal security.Principal,
	item DeploymentPolicy, expectedVersion uint64, requestID string) (DeploymentPolicy, error) {
	if u.transaction == nil || u.auditor == nil {
		return u.policies.SaveDeploymentPolicy(ctx, item, expectedVersion)
	}
	var saved DeploymentPolicy
	err := u.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		var saveErr error
		saved, saveErr = u.policies.SaveDeploymentPolicy(transactionContext, item, expectedVersion)
		if saveErr != nil {
			return saveErr
		}
		return u.recordAudit(transactionContext, principal, item, "deployment_policy.update",
			requestID, item.UpdatedAt)
	})
	return saved, err
}

func (u *DeploymentPolicyUseCase) recordAudit(ctx context.Context, principal security.Principal,
	item DeploymentPolicy, action, requestID string, now time.Time) error {
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	return u.auditor.Record(ctx, sharedaudit.Event{ID: auditID,
		OrganizationID: principal.OrganizationID, ProjectID: item.ProjectID, ActorID: principal.UserID,
		Action: action, ResourceType: "deployment_policy", ResourceID: item.ID,
		RequestID: strings.TrimSpace(requestID), CreatedAt: now})
}
