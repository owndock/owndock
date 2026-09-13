package biz

import (
	"context"
	"errors"
	"strings"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
)

const AuditActionApplicationRetirementCancel = "build.cancel_for_application_retirement"

var ErrBuildRetirementUnavailable = errors.New("build retirement is unavailable")

type RetirementRepository interface {
	ListActiveBuildsForApplication(
		context.Context,
		string,
		string,
		string,
		int64,
	) ([]Build, error)
	GetBuild(context.Context, string, string) (Build, error)
	SaveBuild(context.Context, Build, uint64) (Build, error)
}

// ProductResourceRetirement cancels active Application Builds in bounded
// batches. Build workers own the final canceling -> canceled transition.
type ProductResourceRetirement struct {
	repository  RetirementRepository
	transaction transaction.Manager
	audit       sharedaudit.Recorder
	newID       IDGenerator
	now         Clock
	batchSize   int64
}

func NewProductResourceRetirement(
	repository RetirementRepository,
	manager transaction.Manager,
	audit sharedaudit.Recorder,
	newID IDGenerator,
	now Clock,
	batchSize int64,
) (*ProductResourceRetirement, error) {
	if repository == nil || manager == nil || audit == nil || newID == nil ||
		now == nil || batchSize < 1 || batchSize > 100 {
		return nil, ErrBuildRetirementUnavailable
	}
	return &ProductResourceRetirement{
		repository: repository, transaction: manager, audit: audit,
		newID: newID, now: now, batchSize: batchSize,
	}, nil
}

// ConvergeProductResource implements the control-plane retirement dependency
// contract without importing the control-plane module. Environment retirement
// does not cancel Builds because Build ownership stops at Application.
func (r *ProductResourceRetirement) ConvergeProductResource(
	ctx context.Context,
	organizationID, projectID, applicationID, environmentID,
	actorID, requestID string,
) (bool, error) {
	if r == nil || r.repository == nil {
		return false, ErrBuildRetirementUnavailable
	}
	if strings.TrimSpace(applicationID) == "" {
		return false, nil
	}
	if strings.TrimSpace(environmentID) != "" ||
		strings.TrimSpace(organizationID) == "" || strings.TrimSpace(projectID) == "" ||
		strings.TrimSpace(actorID) == "" {
		return false, ErrBuildRetirementUnavailable
	}
	items, err := r.repository.ListActiveBuildsForApplication(
		ctx, organizationID, projectID, applicationID, r.batchSize,
	)
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.Terminal() || item.Status == BuildStatusCanceling {
			continue
		}
		if err := r.cancel(ctx, item, actorID, requestID); err != nil {
			return false, err
		}
	}
	return len(items) > 0, nil
}

func (r *ProductResourceRetirement) cancel(
	ctx context.Context,
	item Build,
	actorID, requestID string,
) error {
	expectedVersion := item.Version
	now := r.now().UTC()
	if err := item.Cancel(now); err != nil {
		return err
	}
	auditID, err := r.newID()
	if err != nil {
		return err
	}
	err = r.transaction.WithinTransaction(ctx, func(transactionContext context.Context) error {
		if _, saveErr := r.repository.SaveBuild(
			transactionContext, item, expectedVersion,
		); saveErr != nil {
			return saveErr
		}
		return r.audit.Record(transactionContext, sharedaudit.Event{
			ID: auditID, OrganizationID: item.OrganizationID,
			ProjectID: item.ProjectID, ActorID: actorID,
			Action:       AuditActionApplicationRetirementCancel,
			ResourceType: "build", ResourceID: item.ID,
			RequestID: requestID, CreatedAt: now,
		})
	})
	if !errors.Is(err, ErrVersionConflict) {
		return err
	}
	current, getErr := r.repository.GetBuild(ctx, item.ProjectID, item.ID)
	if getErr == nil && (current.Terminal() || current.Status == BuildStatusCanceling) {
		return nil
	}
	if getErr != nil {
		return getErr
	}
	return err
}
