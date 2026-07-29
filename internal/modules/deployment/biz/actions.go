package biz

// Stable audit action names used by the future authenticated Deployment API.
const (
	AuditActionCreate    = "deployment.create"
	AuditActionCancel    = "deployment.cancel"
	AuditActionRetry     = "deployment.retry"
	AuditActionRollback  = "deployment.rollback"
	AuditActionPreparing = "deployment.preparing"
	AuditActionDeploying = "deployment.deploying"
	AuditActionSucceeded = "deployment.succeeded"
	AuditActionFailed    = "deployment.failed"
	AuditActionCanceled  = "deployment.canceled"
)
