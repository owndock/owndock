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
	PermissionProjectRead               Permission = "project.read"
	PermissionProjectCreate             Permission = "project.create"
	PermissionProjectMemberRead         Permission = "project_member.read"
	PermissionProjectMemberManage       Permission = "project_member.manage"
	PermissionApplicationRead           Permission = "application.read"
	PermissionApplicationWrite          Permission = "application.write"
	PermissionReleaseRead               Permission = "release.read"
	PermissionReleaseCreate             Permission = "release.create"
	PermissionManagedHostRead           Permission = "managed_host.read"
	PermissionManagedHostWrite          Permission = "managed_host.write"
	PermissionRuntimeTargetRead         Permission = "runtime_target.read"
	PermissionRuntimeTargetWrite        Permission = "runtime_target.write"
	PermissionRegistryRead              Permission = "registry.read"
	PermissionRegistryWrite             Permission = "registry.write"
	PermissionEnvironmentRead           Permission = "environment.read"
	PermissionEnvironmentWrite          Permission = "environment.write"
	PermissionDeploymentRead            Permission = "deployment.read"
	PermissionDeploymentCreate          Permission = "deployment.create"
	PermissionDeploymentCancel          Permission = "deployment.cancel"
	PermissionDeploymentRollback        Permission = "deployment.rollback"
	PermissionAuditRead                 Permission = "audit.read"
	PermissionRuntimeInventoryRead      Permission = "runtime_inventory.read"
	PermissionHostInventoryRead         Permission = "host_inventory.read"
	PermissionSourceRepositoryRead      Permission = "source_repository.read"
	PermissionSourceRepositoryWrite     Permission = "source_repository.write"
	PermissionBuildConfigurationRead    Permission = "build_configuration.read"
	PermissionBuildConfigurationWrite   Permission = "build_configuration.write"
	PermissionBuildRead                 Permission = "build.read"
	PermissionBuildTrigger              Permission = "build.trigger"
	PermissionBuildTriggerManage        Permission = "build_trigger.manage"
	PermissionAutomaticDeploymentManage Permission = "automatic_deployment.manage"
	PermissionTerminalContainerOpen     Permission = "terminal.container.open"
	PermissionTerminalHostOpen          Permission = "terminal.host.open"
	PermissionTerminalSessionRead       Permission = "terminal.session.read"
	PermissionTerminalSessionTerminate  Permission = "terminal.session.terminate"
	PermissionTerminalPolicyManage      Permission = "terminal.policy.manage"
	PermissionOrganizationManage        Permission = "organization.manage"
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
	case PermissionProjectRead, PermissionProjectMemberRead, PermissionApplicationRead, PermissionReleaseRead,
		PermissionRuntimeTargetRead, PermissionRegistryRead,
		PermissionEnvironmentRead, PermissionDeploymentRead,
		PermissionRuntimeInventoryRead, PermissionSourceRepositoryRead,
		PermissionBuildConfigurationRead, PermissionBuildRead:
		return role == RoleMaintainer || role == RoleDeveloper || role == RoleViewer
	case PermissionManagedHostRead, PermissionHostInventoryRead:
		return role == RoleMaintainer
	case PermissionApplicationWrite, PermissionReleaseCreate, PermissionDeploymentCreate, PermissionDeploymentCancel:
		return role == RoleMaintainer || role == RoleDeveloper
	case PermissionRuntimeTargetWrite, PermissionRegistryWrite, PermissionEnvironmentWrite, PermissionDeploymentRollback, PermissionAuditRead:
		return role == RoleMaintainer
	case PermissionProjectMemberManage:
		return role == RoleMaintainer
	case PermissionSourceRepositoryWrite:
		return role == RoleMaintainer
	case PermissionBuildTriggerManage:
		return role == RoleMaintainer
	case PermissionAutomaticDeploymentManage:
		return role == RoleMaintainer
	case PermissionBuildConfigurationWrite:
		return role == RoleMaintainer || role == RoleDeveloper
	case PermissionBuildTrigger:
		return role == RoleMaintainer || role == RoleDeveloper
	case PermissionTerminalContainerOpen, PermissionTerminalSessionRead,
		PermissionTerminalSessionTerminate:
		return role == RoleMaintainer || role == RoleDeveloper
	case PermissionTerminalHostOpen, PermissionTerminalPolicyManage:
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
