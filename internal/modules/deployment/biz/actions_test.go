package biz

import "testing"

func TestDeploymentAuditActionsAreStable(t *testing.T) {
	for name, value := range map[string]string{
		"create": AuditActionCreate, "cancel": AuditActionCancel,
		"retry": AuditActionRetry, "rollback": AuditActionRollback,
		"succeeded": AuditActionSucceeded, "failed": AuditActionFailed,
	} {
		if value == "" || value[:11] != "deployment." {
			t.Errorf("%s action = %q", name, value)
		}
	}
}
