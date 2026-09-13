package biz

import (
	"context"
	"errors"
	"sort"
	"strings"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimeidentity"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

var (
	ErrRetirementUnavailable   = errors.New("runtime target retirement is unavailable")
	ErrRetirementPending       = errors.New("runtime target retirement is waiting for deployments")
	ErrRetirementTargetRemoved = errors.New("runtime target was already retired")
)

const AuditActionRetirementCancel = "deployment.cancel_for_runtime_target_retirement"

const AuditActionResourceRetirementCancel = "deployment.cancel_for_resource_retirement"

type RetirementTarget struct {
	ID         string
	ProjectID  string
	Connection runtimeaccess.Connection
}

// RetirementScope identifies the deployment-owned runtime slots that must be
// drained before a product resource can finish retiring.
type RetirementScope struct {
	ProjectID       string
	ApplicationID   string
	EnvironmentID   string
	RuntimeTargetID string
	Connection      runtimeaccess.Connection
}

type RetirementRepository interface {
	List(context.Context, string, string, string) ([]Deployment, error)
	ListForRuntimeTarget(context.Context, string, string) ([]Deployment, error)
	Save(context.Context, Deployment, uint64) (Deployment, error)
}

type RetirementConnectionResolver interface {
	RuntimeTargetCleanupExecution(
		context.Context,
		string,
		string,
	) (runtimeaccess.Connection, error)
}

type RuntimeTargetRetirement struct {
	repository  RetirementRepository
	credentials CredentialResolver
	gateway     RuntimeLifecycleGateway
	transaction transaction.Manager
	audit       sharedaudit.Recorder
	newID       IDGenerator
	now         Clock
	connections RetirementConnectionResolver
}

func (r *RuntimeTargetRetirement) WithConnectionResolver(
	resolver RetirementConnectionResolver,
) *RuntimeTargetRetirement {
	r.connections = resolver
	return r
}

func NewRuntimeTargetRetirement(
	repository RetirementRepository,
	credentials CredentialResolver,
	gateway RuntimeLifecycleGateway,
	manager transaction.Manager,
	audit sharedaudit.Recorder,
	newID IDGenerator,
	now Clock,
) (*RuntimeTargetRetirement, error) {
	if repository == nil || credentials == nil || gateway == nil ||
		manager == nil || audit == nil || newID == nil || now == nil {
		return nil, ErrRetirementUnavailable
	}
	return &RuntimeTargetRetirement{
		repository: repository, credentials: credentials, gateway: gateway,
		transaction: manager, audit: audit, newID: newID, now: now,
	}, nil
}

func (r *RuntimeTargetRetirement) Retire(
	ctx context.Context,
	target RetirementTarget,
	principal security.Principal,
	requestID string,
) error {
	if strings.TrimSpace(target.ID) == "" ||
		strings.TrimSpace(target.ProjectID) == "" ||
		target.Connection.Validate() != nil {
		return ErrRetirementUnavailable
	}
	return r.RetireScope(ctx, RetirementScope{
		ProjectID: target.ProjectID, RuntimeTargetID: target.ID,
		Connection: target.Connection,
	}, principal, requestID)
}

// RetireScope cancels active work and cleans the latest stable runtime for
// each matching Application/Environment/Runtime Target slot. Callers retain
// their durable lifecycle record until this repeatable operation returns nil.
func (r *RuntimeTargetRetirement) RetireScope(
	ctx context.Context,
	scope RetirementScope,
	principal security.Principal,
	requestID string,
) error {
	scope.ProjectID = strings.TrimSpace(scope.ProjectID)
	scope.ApplicationID = strings.TrimSpace(scope.ApplicationID)
	scope.EnvironmentID = strings.TrimSpace(scope.EnvironmentID)
	scope.RuntimeTargetID = strings.TrimSpace(scope.RuntimeTargetID)
	if scope.ProjectID == "" ||
		(scope.ApplicationID == "" && scope.EnvironmentID == "" && scope.RuntimeTargetID == "") {
		return ErrRetirementUnavailable
	}
	var (
		items []Deployment
		err   error
	)
	if scope.RuntimeTargetID != "" {
		items, err = r.repository.ListForRuntimeTarget(ctx, scope.ProjectID, scope.RuntimeTargetID)
		if err == nil && (scope.ApplicationID != "" || scope.EnvironmentID != "") {
			items = filterRetirementDeployments(items, scope)
		}
	} else {
		items, err = r.repository.List(ctx, scope.ProjectID, scope.ApplicationID, scope.EnvironmentID)
	}
	if err != nil {
		return err
	}
	pending := false
	for index := range items {
		item := items[index]
		if item.Terminal() {
			continue
		}
		pending = true
		if item.Status == StatusCanceling {
			continue
		}
		expectedVersion := item.Version
		if err := item.Cancel(r.now().UTC()); err != nil {
			return err
		}
		auditID, err := r.newID()
		if err != nil {
			return err
		}
		now := r.now().UTC()
		err = r.transaction.WithinTransaction(
			ctx,
			func(transactionContext context.Context) error {
				if _, saveErr := r.repository.Save(
					transactionContext, item, expectedVersion,
				); saveErr != nil {
					return saveErr
				}
				return r.audit.Record(transactionContext, sharedaudit.Event{
					ID: auditID, OrganizationID: principal.OrganizationID,
					ProjectID: scope.ProjectID, ActorID: principal.UserID,
					Action:       retirementCancelAction(scope),
					ResourceType: "deployment", ResourceID: item.ID,
					RequestID: requestID, CreatedAt: now,
				})
			},
		)
		if err != nil && !errors.Is(err, ErrConflict) {
			return err
		}
	}
	if pending {
		return ErrRetirementPending
	}

	return r.cleanupScopeSlots(ctx, scope, items)
}

func filterRetirementDeployments(items []Deployment, scope RetirementScope) []Deployment {
	filtered := make([]Deployment, 0, len(items))
	for _, item := range items {
		if scope.ApplicationID != "" && item.ApplicationID != scope.ApplicationID {
			continue
		}
		if scope.EnvironmentID != "" && item.EnvironmentID != scope.EnvironmentID {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func retirementCancelAction(scope RetirementScope) string {
	if scope.RuntimeTargetID != "" && scope.ApplicationID == "" && scope.EnvironmentID == "" {
		return AuditActionRetirementCancel
	}
	return AuditActionResourceRetirementCancel
}

func (r *RuntimeTargetRetirement) cleanupScopeSlots(
	ctx context.Context,
	scope RetirementScope,
	items []Deployment,
) error {
	targets := make(map[string][]Deployment)
	for _, item := range items {
		targets[item.RuntimeTargetID] = append(targets[item.RuntimeTargetID], item)
	}
	targetIDs := make([]string, 0, len(targets))
	for targetID := range targets {
		targetIDs = append(targetIDs, targetID)
	}
	sort.Strings(targetIDs)
	for _, targetID := range targetIDs {
		connection := scope.Connection
		if scope.RuntimeTargetID == "" {
			if r.connections == nil {
				return ErrRetirementUnavailable
			}
			var err error
			connection, err = r.connections.RuntimeTargetCleanupExecution(ctx, scope.ProjectID, targetID)
			if errors.Is(err, ErrRetirementTargetRemoved) {
				continue
			}
			if err != nil {
				return err
			}
		}
		if err := connection.Validate(); err != nil {
			return ErrRetirementUnavailable
		}
		if err := r.cleanupSlots(ctx, RetirementTarget{
			ID: targetID, ProjectID: scope.ProjectID, Connection: connection,
		}, targets[targetID]); err != nil {
			return err
		}
	}
	return nil
}

func (r *RuntimeTargetRetirement) cleanupSlots(
	ctx context.Context,
	target RetirementTarget,
	items []Deployment,
) error {
	var credential RuntimeCredential
	credentialResolved := false
	defer clearRetirementCredential(&credential)
	slots := make(map[string][]Deployment)
	for _, item := range items {
		key := item.ApplicationID + "\x00" + item.EnvironmentID
		slots[key] = append(slots[key], item)
	}
	keys := make([]string, 0, len(slots))
	for key := range slots {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		deployments := slots[key]
		sort.Slice(deployments, func(i, j int) bool {
			return deployments[i].CutoverSequence > deployments[j].CutoverSequence
		})
		var stable *Deployment
		for index := range deployments {
			if deployments[index].Status == StatusSucceeded {
				stable = &deployments[index]
				break
			}
		}
		if stable != nil {
			if target.Connection.Mode == runtimeaccess.ModeDirectDocker &&
				!credentialResolved {
				var err error
				credential, err = r.credentials.ResolveCredential(ctx, target.Connection)
				if err != nil {
					return &ExecutionError{Category: FailureCredential, Cause: err}
				}
				credentialResolved = true
			}
			plan, err := retirementPlan(*stable, target.Connection)
			if err != nil {
				return err
			}
			if err := r.gateway.RemoveRuntime(ctx, plan, credential); err != nil {
				return err
			}
		}
		if target.Connection.Mode != runtimeaccess.ModeAgent {
			continue
		}
		released := false
		for _, item := range deployments {
			plan, err := retirementPlan(item, target.Connection)
			if err != nil {
				return err
			}
			err = r.gateway.ReleaseCutoverWatermark(ctx, plan)
			if errors.Is(err, ErrCutoverConflict) {
				continue
			}
			if err != nil {
				return err
			}
			released = true
			break
		}
		if !released && len(deployments) > 0 {
			return ErrCutoverConflict
		}
	}
	return nil
}

func retirementPlan(
	deployment Deployment,
	connection runtimeaccess.Connection,
) (ExecutionPlan, error) {
	containerName, err := runtimeidentity.ContainerName(
		deployment.ProjectID,
		deployment.ApplicationID,
		deployment.EnvironmentID,
		deployment.RuntimeTargetID,
	)
	if err != nil {
		return ExecutionPlan{}, err
	}
	return ExecutionPlan{
		DeploymentID: deployment.ID, CutoverSequence: deployment.CutoverSequence,
		ProjectID: deployment.ProjectID, ApplicationID: deployment.ApplicationID,
		EnvironmentID:    deployment.EnvironmentID,
		RuntimeTargetID:  deployment.RuntimeTargetID,
		TargetConnection: connection, ContainerName: containerName,
	}, nil
}

func clearRetirementCredential(credential *RuntimeCredential) {
	values := [][]byte{credential.RegistryAuthorization}
	if credential.DirectDocker != nil {
		values = append(values,
			credential.DirectDocker.CACertificate,
			credential.DirectDocker.ClientCertificate,
			credential.DirectDocker.ClientKey,
		)
	}
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}
