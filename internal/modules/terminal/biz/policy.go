package biz

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/security"
)

const (
	DefaultContainerIdleTimeout       = 10 * time.Minute
	DefaultContainerMaximumDuration   = time.Hour
	DefaultContainerSessionsPerUser   = 2
	DefaultContainerSessionsPerTarget = 5
	DefaultHostIdleTimeout            = 5 * time.Minute
	DefaultHostMaximumDuration        = 30 * time.Minute
	DefaultHostSessionsPerUser        = 1
	DefaultHostSessionsPerTarget      = 2
	DefaultRevocationGrace            = 30 * time.Second
	MaximumPolicyScopeIDs             = 64
)

var (
	ErrInvalidPolicy  = errors.New("terminal access policy is invalid")
	ErrPolicyConflict = errors.New("terminal access policy has changed")
	ErrPolicyNotFound = errors.New("terminal access policy was not found")
)

type PolicyScope string

const (
	PolicyScopeProject      PolicyScope = "project"
	PolicyScopeOrganization PolicyScope = "organization"
)

type AccessPolicy struct {
	ID                    string
	Scope                 PolicyScope
	OrganizationID        string
	ProjectID             string
	Enabled               bool
	AllowedRoles          []security.Role
	EnvironmentStages     []string
	RuntimeTargetIDs      []string
	ManagedHostIDs        []string
	IdleTimeout           time.Duration
	MaximumDuration       time.Duration
	MaximumPerUser        int
	MaximumPerTarget      int
	RevocationGracePeriod time.Duration
	Version               uint64
	CreatedBy             string
	CreatedAt             time.Time
	UpdatedBy             string
	UpdatedAt             time.Time
}

type PolicyInput struct {
	Enabled               bool
	AllowedRoles          []security.Role
	EnvironmentStages     []string
	RuntimeTargetIDs      []string
	ManagedHostIDs        []string
	IdleTimeout           time.Duration
	MaximumDuration       time.Duration
	MaximumPerUser        int
	MaximumPerTarget      int
	RevocationGracePeriod time.Duration
}

func DefaultProjectPolicy(organizationID, projectID string) AccessPolicy {
	return AccessPolicy{
		ID: "project:" + strings.TrimSpace(projectID), Scope: PolicyScopeProject,
		OrganizationID: strings.TrimSpace(organizationID), ProjectID: strings.TrimSpace(projectID),
		Enabled: true, AllowedRoles: []security.Role{security.RoleOwner, security.RoleMaintainer},
		EnvironmentStages: []string{"development", "staging"},
		IdleTimeout:       DefaultContainerIdleTimeout, MaximumDuration: DefaultContainerMaximumDuration,
		MaximumPerUser:        DefaultContainerSessionsPerUser,
		MaximumPerTarget:      DefaultContainerSessionsPerTarget,
		RevocationGracePeriod: DefaultRevocationGrace,
	}
}

func DefaultOrganizationPolicy(organizationID string) AccessPolicy {
	return AccessPolicy{
		ID: "organization:" + strings.TrimSpace(organizationID), Scope: PolicyScopeOrganization,
		OrganizationID: strings.TrimSpace(organizationID), Enabled: true,
		AllowedRoles: []security.Role{security.RoleOwner},
		IdleTimeout:  DefaultHostIdleTimeout, MaximumDuration: DefaultHostMaximumDuration,
		MaximumPerUser:        DefaultHostSessionsPerUser,
		MaximumPerTarget:      DefaultHostSessionsPerTarget,
		RevocationGracePeriod: DefaultRevocationGrace,
	}
}

func NewProjectPolicy(
	id, organizationID, projectID, actorID string,
	input PolicyInput,
	now time.Time,
) (AccessPolicy, error) {
	policy := AccessPolicy{
		ID: strings.TrimSpace(id), Scope: PolicyScopeProject,
		OrganizationID: strings.TrimSpace(organizationID), ProjectID: strings.TrimSpace(projectID),
		Version: 1, CreatedBy: strings.TrimSpace(actorID), CreatedAt: now.UTC(),
		UpdatedBy: strings.TrimSpace(actorID), UpdatedAt: now.UTC(),
	}
	policy.apply(input)
	if err := policy.Validate(); err != nil {
		return AccessPolicy{}, err
	}
	return policy, nil
}

func NewOrganizationPolicy(
	id, organizationID, actorID string,
	input PolicyInput,
	now time.Time,
) (AccessPolicy, error) {
	policy := AccessPolicy{
		ID: strings.TrimSpace(id), Scope: PolicyScopeOrganization,
		OrganizationID: strings.TrimSpace(organizationID),
		Version:        1, CreatedBy: strings.TrimSpace(actorID), CreatedAt: now.UTC(),
		UpdatedBy: strings.TrimSpace(actorID), UpdatedAt: now.UTC(),
	}
	policy.apply(input)
	if err := policy.Validate(); err != nil {
		return AccessPolicy{}, err
	}
	return policy, nil
}

func (p AccessPolicy) Change(input PolicyInput, actorID string, now time.Time) (AccessPolicy, error) {
	if p.Version == 0 {
		return AccessPolicy{}, ErrPolicyConflict
	}
	p.apply(input)
	p.Version++
	p.UpdatedBy, p.UpdatedAt = strings.TrimSpace(actorID), now.UTC()
	if err := p.Validate(); err != nil {
		return AccessPolicy{}, err
	}
	return p, nil
}

func (p *AccessPolicy) apply(input PolicyInput) {
	p.Enabled = input.Enabled
	p.AllowedRoles = canonicalRoles(input.AllowedRoles)
	p.EnvironmentStages = canonicalStrings(input.EnvironmentStages)
	p.RuntimeTargetIDs = canonicalStrings(input.RuntimeTargetIDs)
	p.ManagedHostIDs = canonicalStrings(input.ManagedHostIDs)
	p.IdleTimeout = input.IdleTimeout
	p.MaximumDuration = input.MaximumDuration
	p.MaximumPerUser = input.MaximumPerUser
	p.MaximumPerTarget = input.MaximumPerTarget
	p.RevocationGracePeriod = input.RevocationGracePeriod
}

func (p AccessPolicy) Validate() error {
	if !validIdentifier(p.ID) || !validIdentifier(p.OrganizationID) ||
		p.Scope != PolicyScopeProject && p.Scope != PolicyScopeOrganization ||
		p.Version > 0 && (!validIdentifier(p.CreatedBy) || !validIdentifier(p.UpdatedBy) ||
			p.CreatedAt.IsZero() || p.UpdatedAt.IsZero()) ||
		p.IdleTimeout < time.Minute || p.IdleTimeout > time.Hour ||
		p.MaximumDuration < 5*time.Minute || p.MaximumDuration > 8*time.Hour ||
		p.MaximumDuration <= p.IdleTimeout ||
		p.MaximumPerUser < 1 || p.MaximumPerUser > 10 ||
		p.MaximumPerTarget < 1 || p.MaximumPerTarget > 50 ||
		p.RevocationGracePeriod < 0 || p.RevocationGracePeriod > 5*time.Minute ||
		p.RevocationGracePeriod > p.IdleTimeout ||
		len(p.AllowedRoles) == 0 || len(p.RuntimeTargetIDs) > MaximumPolicyScopeIDs ||
		len(p.ManagedHostIDs) > MaximumPolicyScopeIDs {
		return ErrInvalidPolicy
	}
	roleSet := make(map[security.Role]struct{}, len(p.AllowedRoles))
	for _, role := range p.AllowedRoles {
		if !role.Valid() || role == security.RoleViewer {
			return ErrInvalidPolicy
		}
		roleSet[role] = struct{}{}
	}
	if _, ok := roleSet[security.RoleOwner]; !ok {
		return ErrInvalidPolicy
	}
	for _, id := range append(append([]string{}, p.RuntimeTargetIDs...), p.ManagedHostIDs...) {
		if !validIdentifier(id) {
			return ErrInvalidPolicy
		}
	}
	switch p.Scope {
	case PolicyScopeProject:
		if !validIdentifier(p.ProjectID) || len(p.ManagedHostIDs) != 0 ||
			len(p.EnvironmentStages) == 0 {
			return ErrInvalidPolicy
		}
		for _, role := range p.AllowedRoles {
			if role != security.RoleOwner && role != security.RoleMaintainer &&
				role != security.RoleDeveloper {
				return ErrInvalidPolicy
			}
		}
		for _, stage := range p.EnvironmentStages {
			if stage != "development" && stage != "staging" && stage != "production" {
				return ErrInvalidPolicy
			}
		}
	case PolicyScopeOrganization:
		if p.ProjectID != "" || len(p.EnvironmentStages) != 0 || len(p.RuntimeTargetIDs) != 0 {
			return ErrInvalidPolicy
		}
		for _, role := range p.AllowedRoles {
			if role != security.RoleOwner && role != security.RoleMaintainer {
				return ErrInvalidPolicy
			}
		}
	}
	return nil
}

func (p AccessPolicy) AllowsContainer(role security.Role, stage, runtimeTargetID string) bool {
	return p.Scope == PolicyScopeProject && p.Enabled && containsRole(p.AllowedRoles, role) &&
		containsString(p.EnvironmentStages, stage) && allowedScopeID(p.RuntimeTargetIDs, runtimeTargetID)
}

func (p AccessPolicy) AllowsHost(role security.Role, managedHostID string) bool {
	return p.Scope == PolicyScopeOrganization && p.Enabled && containsRole(p.AllowedRoles, role) &&
		allowedScopeID(p.ManagedHostIDs, managedHostID)
}

func canonicalRoles(values []security.Role) []security.Role {
	seen := make(map[security.Role]struct{}, len(values))
	result := make([]security.Role, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func canonicalStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			result = append(result, value)
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func containsRole(values []security.Role, want security.Role) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func allowedScopeID(values []string, want string) bool {
	return len(values) == 0 || containsString(values, want)
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 160 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("-_.:", character) {
			continue
		}
		return false
	}
	return true
}
