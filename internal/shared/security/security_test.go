package security

import "testing"

func TestRolePermissions(t *testing.T) {
	tests := []struct {
		role       Role
		permission Permission
		allowed    bool
	}{
		{RoleOwner, PermissionOrganizationManage, true},
		{RoleMaintainer, PermissionRuntimeTargetWrite, true},
		{RoleMaintainer, PermissionManagedHostRead, true},
		{RoleMaintainer, PermissionManagedHostWrite, false},
		{RoleDeveloper, PermissionManagedHostRead, false},
		{RoleDeveloper, PermissionReleaseCreate, true},
		{RoleDeveloper, PermissionRuntimeTargetWrite, false},
		{RoleViewer, PermissionProjectRead, true},
		{RoleViewer, PermissionApplicationWrite, false},
		{RoleDeveloper, PermissionDeploymentCreate, true},
		{RoleDeveloper, PermissionDeploymentCancel, true},
		{RoleDeveloper, PermissionDeploymentRollback, false},
		{RoleMaintainer, PermissionDeploymentCancel, true},
		{RoleMaintainer, PermissionDeploymentRollback, true},
		{RoleViewer, PermissionRuntimeInventoryRead, true},
		{RoleDeveloper, PermissionHostInventoryRead, false},
		{RoleMaintainer, PermissionHostInventoryRead, true},
		{RoleViewer, PermissionSourceRepositoryRead, true},
		{RoleDeveloper, PermissionSourceRepositoryWrite, false},
		{RoleMaintainer, PermissionSourceRepositoryWrite, true},
		{RoleViewer, PermissionBuildConfigurationRead, true},
		{RoleDeveloper, PermissionBuildConfigurationWrite, true},
		{RoleMaintainer, PermissionBuildConfigurationWrite, true},
		{RoleViewer, PermissionBuildRead, true},
		{RoleViewer, PermissionBuildTrigger, false},
		{RoleMaintainer, PermissionAutomaticDeploymentManage, true},
		{RoleDeveloper, PermissionAutomaticDeploymentManage, false},
		{RoleDeveloper, PermissionBuildTrigger, true},
		{RoleDeveloper, PermissionBuildTriggerManage, false},
		{RoleMaintainer, PermissionBuildTriggerManage, true},
		{RoleOwner, PermissionTerminalHostOpen, true},
		{RoleMaintainer, PermissionTerminalContainerOpen, true},
		{RoleMaintainer, PermissionTerminalHostOpen, true},
		{RoleDeveloper, PermissionTerminalContainerOpen, true},
		{RoleDeveloper, PermissionTerminalHostOpen, false},
		{RoleDeveloper, PermissionTerminalSessionTerminate, true},
		{RoleViewer, PermissionTerminalSessionRead, false},
		{RoleMaintainer, PermissionTerminalPolicyManage, true},
	}
	for _, test := range tests {
		principal := Principal{
			UserID: "user", OrganizationID: "organization", SessionID: "session", Role: test.role,
		}
		if got := principal.Require(test.permission) == nil; got != test.allowed {
			t.Errorf("role %s permission %s allowed = %t, want %t", test.role, test.permission, got, test.allowed)
		}
	}
}
