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
