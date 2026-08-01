package biz

import (
	"context"
	"errors"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
)

const (
	DefaultPageSize = 100
	MaximumPageSize = 200
)

var (
	ErrInvalidViewQuery = errors.New("runtime inventory view query is invalid")
	ErrViewUnavailable  = errors.New("runtime inventory view is unavailable")
)

type ViewQuery struct {
	RuntimeTargetID string
	Kind            Kind
	IncludeAbsent   bool
	Limit           int
	Cursor          string
}

func (q ViewQuery) Validate() error {
	if q.RuntimeTargetID != "" &&
		(!validID(q.RuntimeTargetID) || strings.TrimSpace(q.RuntimeTargetID) != q.RuntimeTargetID) ||
		q.Kind != "" && !q.Kind.Valid() ||
		q.Limit < 1 || q.Limit > MaximumPageSize ||
		len(q.Cursor) > 2048 || strings.TrimSpace(q.Cursor) != q.Cursor {
		return ErrInvalidViewQuery
	}
	return nil
}

type StatePage struct {
	Items      []State
	NextCursor string
}

type ViewRepository interface {
	ListProject(
		context.Context,
		string,
		string,
		ViewQuery,
	) (StatePage, error)
	ListHost(
		context.Context,
		string,
		string,
		ViewQuery,
	) (StatePage, error)
}

type Ownership struct {
	ProjectID    string
	DeploymentID string
}

type OwnershipVerifier interface {
	// VerifyContainers returns verified ownership keyed by runtime ID. Missing
	// entries are deliberately treated as unmanaged.
	VerifyContainers(context.Context, []Resource) (map[string]Ownership, error)
}

type ViewUseCase struct {
	repository ViewRepository
	audit      sharedaudit.Recorder
	newID      func() (string, error)
	now        func() time.Time
}

func NewViewUseCase(
	repository ViewRepository,
	audit sharedaudit.Recorder,
	newID func() (string, error),
	now func() time.Time,
) (*ViewUseCase, error) {
	if repository == nil || audit == nil || newID == nil || now == nil {
		return nil, ErrViewUnavailable
	}
	return &ViewUseCase{
		repository: repository, audit: audit, newID: newID, now: now,
	}, nil
}

func (u *ViewUseCase) ListProject(
	ctx context.Context,
	principal security.Principal,
	projectID string,
	query ViewQuery,
	requestID string,
) (StatePage, error) {
	if err := principal.Require(security.PermissionRuntimeInventoryRead); err != nil {
		return StatePage{}, err
	}
	projectID = strings.TrimSpace(projectID)
	query = normalizeViewQuery(query)
	if !validID(projectID) || query.Validate() != nil {
		return StatePage{}, ErrInvalidViewQuery
	}
	page, err := u.repository.ListProject(
		ctx,
		principal.OrganizationID,
		projectID,
		query,
	)
	if err != nil {
		return StatePage{}, err
	}
	if err := u.record(
		ctx,
		principal,
		projectID,
		"runtime_inventory.project.list",
		"project",
		projectID,
		requestID,
	); err != nil {
		return StatePage{}, err
	}
	return page, nil
}

func (u *ViewUseCase) ListHost(
	ctx context.Context,
	principal security.Principal,
	hostID string,
	query ViewQuery,
	requestID string,
) (StatePage, error) {
	if err := principal.Require(security.PermissionHostInventoryRead); err != nil {
		return StatePage{}, err
	}
	hostID = strings.TrimSpace(hostID)
	query = normalizeViewQuery(query)
	if !validID(hostID) || query.Validate() != nil {
		return StatePage{}, ErrInvalidViewQuery
	}
	page, err := u.repository.ListHost(
		ctx,
		principal.OrganizationID,
		hostID,
		query,
	)
	if err != nil {
		return StatePage{}, err
	}
	if err := u.record(
		ctx,
		principal,
		"",
		"runtime_inventory.host.list",
		"managed_host",
		hostID,
		requestID,
	); err != nil {
		return StatePage{}, err
	}
	return page, nil
}

func normalizeViewQuery(query ViewQuery) ViewQuery {
	if query.Limit == 0 {
		query.Limit = DefaultPageSize
	}
	return query
}

func (u *ViewUseCase) record(
	ctx context.Context,
	principal security.Principal,
	projectID, action, resourceType, resourceID, requestID string,
) error {
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	return u.audit.Record(ctx, sharedaudit.Event{
		ID: auditID, OrganizationID: principal.OrganizationID,
		ProjectID: projectID, ActorID: principal.UserID,
		Action: action, ResourceType: resourceType, ResourceID: resourceID,
		RequestID: requestID, CreatedAt: u.now().UTC(),
	})
}
