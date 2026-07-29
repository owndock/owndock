package security

import (
	"context"
	"errors"
)

var (
	ErrUnauthenticated = errors.New("authentication is required")
	ErrForbidden       = errors.New("permission is denied")
)

type Role string

const (
	RoleOwner      Role = "owner"
	RoleMaintainer Role = "maintainer"
	RoleDeveloper  Role = "developer"
	RoleViewer     Role = "viewer"
)

func (r Role) Valid() bool {
	switch r {
	case RoleOwner, RoleMaintainer, RoleDeveloper, RoleViewer:
		return true
	default:
		return false
	}
}

type Permission string

const (
	PermissionProjectRead        Permission = "project.read"
	PermissionProjectCreate      Permission = "project.create"
	PermissionApplicationRead    Permission = "application.read"
	PermissionApplicationWrite   Permission = "application.write"
	PermissionReleaseRead        Permission = "release.read"
	PermissionReleaseCreate      Permission = "release.create"
	PermissionManagedHostRead    Permission = "managed_host.read"
	PermissionManagedHostWrite   Permission = "managed_host.write"
	PermissionRuntimeTargetRead  Permission = "runtime_target.read"
	PermissionRuntimeTargetWrite Permission = "runtime_target.write"
	PermissionRegistryRead       Permission = "registry.read"
	PermissionRegistryWrite      Permission = "registry.write"
	PermissionEnvironmentRead    Permission = "environment.read"
	PermissionEnvironmentWrite   Permission = "environment.write"
	PermissionDeploymentRead     Permission = "deployment.read"
	PermissionDeploymentCreate   Permission = "deployment.create"
	PermissionDeploymentCancel   Permission = "deployment.cancel"
	PermissionDeploymentRollback Permission = "deployment.rollback"
	PermissionAuditRead          Permission = "audit.read"
	PermissionOrganizationManage Permission = "organization.manage"
)

type Principal struct {
	UserID         string
	OrganizationID string
	Email          string
	Role           Role
	SessionID      string
}

func (p Principal) Valid() bool {
	return p.UserID != "" && p.OrganizationID != "" && p.SessionID != "" && p.Role.Valid()
}

func (p Principal) Require(permission Permission) error {
	if !p.Valid() {
		return ErrUnauthenticated
	}
	if allowed(p.Role, permission) {
		return nil
	}
	return ErrForbidden
}

func allowed(role Role, permission Permission) bool {
	if role == RoleOwner {
		return true
	}
	switch permission {
	case PermissionProjectRead, PermissionApplicationRead, PermissionReleaseRead, PermissionRuntimeTargetRead, PermissionRegistryRead, PermissionEnvironmentRead, PermissionDeploymentRead:
		return role == RoleMaintainer || role == RoleDeveloper || role == RoleViewer
	case PermissionManagedHostRead:
		return role == RoleMaintainer
	case PermissionApplicationWrite, PermissionReleaseCreate, PermissionDeploymentCreate, PermissionDeploymentCancel:
		return role == RoleMaintainer || role == RoleDeveloper
	case PermissionRuntimeTargetWrite, PermissionRegistryWrite, PermissionEnvironmentWrite, PermissionDeploymentRollback, PermissionAuditRead:
		return role == RoleMaintainer
	case PermissionProjectCreate, PermissionOrganizationManage:
		return false
	default:
		return false
	}
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(Principal)
	return principal, ok && principal.Valid()
}
