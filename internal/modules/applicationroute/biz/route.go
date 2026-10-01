package biz

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/security"
	"github.com/owndock/owndock/internal/shared/transaction"
)

const MaxRoutesPerProject = 128

var (
	ErrInvalidRoute       = errors.New("application route is invalid")
	ErrRouteConflict      = errors.New("application route already exists or has changed")
	ErrNotFound           = errors.New("application route was not found")
	ErrReferenceNotFound  = errors.New("application route reference was not found")
	ErrUnsupportedTarget  = errors.New("application route requires an Agent runtime target")
	ErrRouteLimitExceeded = errors.New("application route limit is exceeded")
	ErrUnavailable        = errors.New("application route service is unavailable")
)

type TLSMode string

const (
	TLSModeAutomatic TLSMode = "automatic"
	TLSModeDisabled  TLSMode = "disabled"
)

func (m TLSMode) Valid() bool { return m == TLSModeAutomatic || m == TLSModeDisabled }

type Status string

const (
	StatusPending      Status = "pending"
	StatusProvisioning Status = "provisioning"
	StatusReady        Status = "ready"
	StatusDegraded     Status = "degraded"
	StatusRetiring     Status = "retiring"
	StatusRetired      Status = "retired"
)

func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusProvisioning, StatusReady, StatusDegraded, StatusRetiring, StatusRetired:
		return true
	default:
		return false
	}
}

type CertificateStatus string

const (
	CertificateStatusPending       CertificateStatus = "pending"
	CertificateStatusReady         CertificateStatus = "ready"
	CertificateStatusFailed        CertificateStatus = "failed"
	CertificateStatusNotApplicable CertificateStatus = "not_applicable"
)

func (s CertificateStatus) Valid() bool {
	switch s {
	case CertificateStatusPending, CertificateStatusReady, CertificateStatusFailed, CertificateStatusNotApplicable:
		return true
	default:
		return false
	}
}

type FailureCode string

const (
	FailureGatewayUnavailable     FailureCode = "gateway_unavailable"
	FailureRuntimeUnavailable     FailureCode = "runtime_unavailable"
	FailurePortConflict           FailureCode = "port_conflict"
	FailureCertificateUnavailable FailureCode = "certificate_unavailable"
	FailureBackendUnhealthy       FailureCode = "backend_unhealthy"
	FailureFenceConflict          FailureCode = "fence_conflict"
	FailureStateFull              FailureCode = "state_full"
	FailureConfiguration          FailureCode = "configuration"
	FailureCanceled               FailureCode = "canceled"
	FailureUnknown                FailureCode = "unknown"
)

func (c FailureCode) Valid() bool {
	switch c {
	case FailureGatewayUnavailable, FailureRuntimeUnavailable, FailurePortConflict,
		FailureCertificateUnavailable, FailureBackendUnhealthy,
		FailureFenceConflict, FailureStateFull, FailureConfiguration,
		FailureCanceled, FailureUnknown:
		return true
	default:
		return false
	}
}

type Observation struct {
	Revision          uint64
	DeploymentID      string
	CutoverSequence   uint64
	ConfigDigest      string
	CertificateStatus CertificateStatus
	ObservedAt        time.Time
}

// Retirement preserves the identity of the accepted delete request so a
// worker can resume gateway cleanup after a process restart without losing
// audit attribution.
type Retirement struct {
	ActorID   string
	RequestID string
	StartedAt time.Time
}

type ApplicationRoute struct {
	ID              string
	OrganizationID  string
	ProjectID       string
	ApplicationID   string
	EnvironmentID   string
	RuntimeTargetID string
	Hostname        string
	PortName        string
	TLSMode         TLSMode
	Status          Status
	Revision        uint64
	Version         uint64
	Observation     *Observation
	Retirement      *Retirement
	FailureCode     FailureCode
	CreatedBy       string
	UpdatedBy       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Input struct {
	ID              string
	OrganizationID  string
	ProjectID       string
	ApplicationID   string
	EnvironmentID   string
	RuntimeTargetID string
	Hostname        string
	PortName        string
	TLSMode         TLSMode
	Status          Status
	Revision        uint64
	Version         uint64
	Observation     *Observation
	Retirement      *Retirement
	FailureCode     FailureCode
	CreatedBy       string
	UpdatedBy       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

var (
	idPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	hostLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	portNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func NewApplicationRoute(input Input) (ApplicationRoute, error) {
	route := ApplicationRoute{
		ID: strings.TrimSpace(input.ID), OrganizationID: strings.TrimSpace(input.OrganizationID),
		ProjectID: strings.TrimSpace(input.ProjectID), ApplicationID: strings.TrimSpace(input.ApplicationID),
		EnvironmentID: strings.TrimSpace(input.EnvironmentID), RuntimeTargetID: strings.TrimSpace(input.RuntimeTargetID),
		Hostname: normalizeHostname(input.Hostname), PortName: strings.TrimSpace(input.PortName),
		TLSMode: input.TLSMode, Status: input.Status, Revision: input.Revision, Version: input.Version,
		Observation: cloneObservation(input.Observation), Retirement: cloneRetirement(input.Retirement),
		FailureCode: input.FailureCode,
		CreatedBy:   strings.TrimSpace(input.CreatedBy), UpdatedBy: strings.TrimSpace(input.UpdatedBy),
		CreatedAt: input.CreatedAt.UTC(), UpdatedAt: input.UpdatedAt.UTC(),
	}
	if !validID(route.ID) || !validID(route.OrganizationID) || !validID(route.ProjectID) ||
		!validID(route.ApplicationID) || !validID(route.EnvironmentID) || !validID(route.RuntimeTargetID) ||
		!validHostname(route.Hostname, route.TLSMode) || !portNamePattern.MatchString(route.PortName) ||
		!route.TLSMode.Valid() || !route.Status.Valid() || route.Revision == 0 ||
		route.Version == 0 || route.Revision > route.Version ||
		!validID(route.CreatedBy) || !validID(route.UpdatedBy) || route.CreatedAt.IsZero() ||
		route.UpdatedAt.IsZero() || route.UpdatedAt.Before(route.CreatedAt) {
		return ApplicationRoute{}, ErrInvalidRoute
	}
	if !validObservation(route) {
		return ApplicationRoute{}, ErrInvalidRoute
	}
	if !validRetirement(route) {
		return ApplicationRoute{}, ErrInvalidRoute
	}
	if route.Status == StatusDegraded && !route.FailureCode.Valid() ||
		route.Status != StatusDegraded && route.FailureCode != "" {
		return ApplicationRoute{}, ErrInvalidRoute
	}
	return route, nil
}

func cloneRetirement(value *Retirement) *Retirement {
	if value == nil {
		return nil
	}
	copy := *value
	copy.ActorID = strings.TrimSpace(copy.ActorID)
	copy.RequestID = strings.TrimSpace(copy.RequestID)
	copy.StartedAt = copy.StartedAt.UTC()
	return &copy
}

func validRetirement(route ApplicationRoute) bool {
	if route.Status != StatusRetiring {
		return route.Retirement == nil
	}
	return route.Retirement != nil && validID(route.Retirement.ActorID) &&
		!route.Retirement.StartedAt.IsZero() &&
		!route.Retirement.StartedAt.Before(route.CreatedAt) &&
		!route.Retirement.StartedAt.After(route.UpdatedAt)
}

func cloneObservation(value *Observation) *Observation {
	if value == nil {
		return nil
	}
	copy := *value
	copy.DeploymentID = strings.TrimSpace(copy.DeploymentID)
	copy.ConfigDigest = strings.TrimSpace(copy.ConfigDigest)
	copy.ObservedAt = copy.ObservedAt.UTC()
	return &copy
}

func validObservation(route ApplicationRoute) bool {
	observation := route.Observation
	if observation == nil {
		return route.Status != StatusReady
	}
	if observation.Revision == 0 || observation.Revision > route.Revision ||
		!validID(observation.DeploymentID) || observation.CutoverSequence == 0 ||
		!digestPattern.MatchString(observation.ConfigDigest) || !observation.CertificateStatus.Valid() ||
		observation.ObservedAt.IsZero() {
		return false
	}
	if route.Status == StatusReady {
		if observation.Revision != route.Revision {
			return false
		}
		return (route.TLSMode == TLSModeAutomatic && observation.CertificateStatus == CertificateStatusReady) ||
			(route.TLSMode == TLSModeDisabled && observation.CertificateStatus == CertificateStatusNotApplicable)
	}
	return true
}

func normalizeHostname(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validHostname(value string, tlsMode TLSMode) bool {
	if value == "" || len(value) > 253 || strings.HasSuffix(value, ".") || strings.Contains(value, ":") ||
		net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	if tlsMode == TLSModeAutomatic && (len(labels) < 2 || value == "localhost" ||
		strings.HasSuffix(value, ".localhost") || strings.HasSuffix(value, ".local") ||
		strings.HasSuffix(value, ".internal") || strings.HasSuffix(value, ".home.arpa")) {
		return false
	}
	return true
}

func validID(value string) bool { return idPattern.MatchString(value) }

// Transition advances only controller-owned lifecycle state. Product API
// callers cannot set Status directly; gateway reconciliation will use this
// method while persisting the current Version as its optimistic-lock fence.
func (r ApplicationRoute) Transition(next Status, actorID string, now time.Time) (ApplicationRoute, error) {
	actorID = strings.TrimSpace(actorID)
	if !validID(actorID) || now.IsZero() || next == StatusRetiring ||
		!validTransition(r.Status, next) {
		return ApplicationRoute{}, ErrRouteConflict
	}
	if next == StatusDegraded {
		return r.Degrade(FailureUnknown, actorID, now)
	}
	r.Status, r.Version, r.UpdatedBy, r.UpdatedAt = next, r.Version+1, actorID, now.UTC()
	r.FailureCode = ""
	return NewApplicationRoute(Input{ID: r.ID, OrganizationID: r.OrganizationID, ProjectID: r.ProjectID,
		ApplicationID: r.ApplicationID, EnvironmentID: r.EnvironmentID, RuntimeTargetID: r.RuntimeTargetID,
		Hostname: r.Hostname, PortName: r.PortName, TLSMode: r.TLSMode, Status: r.Status,
		Revision: r.Revision, Version: r.Version, Observation: r.Observation,
		Retirement: r.Retirement, FailureCode: r.FailureCode,
		CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
}

func (r ApplicationRoute) Degrade(
	failure FailureCode,
	actorID string,
	now time.Time,
) (ApplicationRoute, error) {
	actorID = strings.TrimSpace(actorID)
	if !failure.Valid() || !validID(actorID) || now.IsZero() ||
		!validTransition(r.Status, StatusDegraded) {
		return ApplicationRoute{}, ErrRouteConflict
	}
	r.Status, r.Version, r.UpdatedBy, r.UpdatedAt =
		StatusDegraded, r.Version+1, actorID, now.UTC()
	r.FailureCode = failure
	return NewApplicationRoute(Input{ID: r.ID, OrganizationID: r.OrganizationID, ProjectID: r.ProjectID,
		ApplicationID: r.ApplicationID, EnvironmentID: r.EnvironmentID, RuntimeTargetID: r.RuntimeTargetID,
		Hostname: r.Hostname, PortName: r.PortName, TLSMode: r.TLSMode, Status: r.Status,
		Revision: r.Revision, Version: r.Version, Observation: r.Observation,
		Retirement: r.Retirement, FailureCode: r.FailureCode,
		CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
}

// BeginRetirement closes route admission before any external gateway work is
// attempted. The returned state is durable and safe for worker replay.
func (r ApplicationRoute) BeginRetirement(
	actorID, requestID string,
	now time.Time,
) (ApplicationRoute, error) {
	actorID, requestID = strings.TrimSpace(actorID), strings.TrimSpace(requestID)
	if !validID(actorID) || now.IsZero() || !validTransition(r.Status, StatusRetiring) {
		return ApplicationRoute{}, ErrRouteConflict
	}
	r.Status, r.Version, r.UpdatedBy, r.UpdatedAt =
		StatusRetiring, r.Version+1, actorID, now.UTC()
	r.Retirement = &Retirement{ActorID: actorID, RequestID: requestID, StartedAt: now.UTC()}
	r.FailureCode = ""
	return NewApplicationRoute(inputFromRoute(r))
}

// CompleteRetirement is controller-only and may run only after the committed
// gateway configuration no longer contains the route.
func (r ApplicationRoute) CompleteRetirement(actorID string, now time.Time) (ApplicationRoute, error) {
	actorID = strings.TrimSpace(actorID)
	if !validID(actorID) || now.IsZero() || r.Retirement == nil ||
		!validTransition(r.Status, StatusRetired) {
		return ApplicationRoute{}, ErrRouteConflict
	}
	r.Status, r.Version, r.UpdatedBy, r.UpdatedAt =
		StatusRetired, r.Version+1, actorID, now.UTC()
	r.Retirement, r.FailureCode = nil, ""
	return NewApplicationRoute(inputFromRoute(r))
}

func validTransition(current, next Status) bool {
	switch current {
	case StatusPending:
		return next == StatusProvisioning || next == StatusRetiring
	case StatusProvisioning:
		return next == StatusDegraded || next == StatusRetiring
	case StatusReady:
		return next == StatusPending || next == StatusProvisioning || next == StatusDegraded || next == StatusRetiring
	case StatusDegraded:
		return next == StatusPending || next == StatusProvisioning || next == StatusRetiring
	case StatusRetiring:
		return next == StatusRetired
	default:
		return false
	}
}

// ObserveReady records the exact desired revision and deployment fence proven
// by the Agent's private route probe. A stale observation cannot mark a newer
// desired route ready.
func (r ApplicationRoute) ObserveReady(observation Observation, actorID string, now time.Time) (ApplicationRoute, error) {
	actorID = strings.TrimSpace(actorID)
	if !validID(actorID) || now.IsZero() || r.Status != StatusProvisioning || observation.Revision != r.Revision {
		return ApplicationRoute{}, ErrRouteConflict
	}
	r.Status, r.Version, r.UpdatedBy, r.UpdatedAt = StatusReady, r.Version+1, actorID, now.UTC()
	r.Observation = cloneObservation(&observation)
	r.FailureCode = ""
	return NewApplicationRoute(Input{ID: r.ID, OrganizationID: r.OrganizationID, ProjectID: r.ProjectID,
		ApplicationID: r.ApplicationID, EnvironmentID: r.EnvironmentID, RuntimeTargetID: r.RuntimeTargetID,
		Hostname: r.Hostname, PortName: r.PortName, TLSMode: r.TLSMode, Status: r.Status,
		Revision: r.Revision, Version: r.Version, Observation: r.Observation,
		Retirement: r.Retirement, FailureCode: r.FailureCode,
		CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
}

func inputFromRoute(r ApplicationRoute) Input {
	return Input{ID: r.ID, OrganizationID: r.OrganizationID, ProjectID: r.ProjectID,
		ApplicationID: r.ApplicationID, EnvironmentID: r.EnvironmentID,
		RuntimeTargetID: r.RuntimeTargetID, Hostname: r.Hostname, PortName: r.PortName,
		TLSMode: r.TLSMode, Status: r.Status, Revision: r.Revision, Version: r.Version,
		Observation: r.Observation, Retirement: r.Retirement, FailureCode: r.FailureCode,
		CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

type Repository interface {
	Create(context.Context, ApplicationRoute) (ApplicationRoute, error)
	List(context.Context, string, string) ([]ApplicationRoute, error)
	Get(context.Context, string, string, string) (ApplicationRoute, error)
	Save(context.Context, ApplicationRoute, uint64) (ApplicationRoute, error)
}

type References struct {
	EnvironmentStage string
	AgentTarget      bool
}

type ReferenceResolver interface {
	Resolve(context.Context, string, string, string, string, string) (References, error)
}

type UseCase struct {
	repository               Repository
	references               ReferenceResolver
	newID                    func() (string, error)
	now                      func() time.Time
	transaction              transaction.Manager
	auditor                  sharedaudit.Recorder
	retirementRepository     RetirementRepository
	retirer                  RouteRetirer
	reconciliationRepository ReconciliationRepository
	reconciler               RouteReconciler
}

func NewUseCase(repository Repository, references ReferenceResolver, newID func() (string, error), now func() time.Time) (*UseCase, error) {
	if repository == nil || references == nil || newID == nil || now == nil {
		return nil, ErrUnavailable
	}
	return &UseCase{repository: repository, references: references, newID: newID, now: now}, nil
}

func (u *UseCase) WithAudit(manager transaction.Manager, auditor sharedaudit.Recorder) *UseCase {
	u.transaction, u.auditor = manager, auditor
	return u
}

func (u *UseCase) WithRetirement(
	repository RetirementRepository,
	retirer RouteRetirer,
) *UseCase {
	u.retirementRepository, u.retirer = repository, retirer
	return u
}

func (u *UseCase) WithReconciliation(
	repository ReconciliationRepository,
	reconciler RouteReconciler,
) *UseCase {
	u.reconciliationRepository, u.reconciler = repository, reconciler
	return u
}

func (u *UseCase) Create(ctx context.Context, principal security.Principal, projectID string, input Input, requestID string) (ApplicationRoute, error) {
	if err := principal.Require(security.PermissionApplicationRouteWrite); err != nil {
		return ApplicationRoute{}, err
	}
	projectID = strings.TrimSpace(projectID)
	if !validID(projectID) {
		return ApplicationRoute{}, ErrInvalidRoute
	}
	input.ApplicationID, input.EnvironmentID, input.RuntimeTargetID = strings.TrimSpace(input.ApplicationID), strings.TrimSpace(input.EnvironmentID), strings.TrimSpace(input.RuntimeTargetID)
	if err := u.validateReferences(ctx, principal.OrganizationID, projectID, input); err != nil {
		return ApplicationRoute{}, err
	}
	routeID, err := u.newID()
	if err != nil {
		return ApplicationRoute{}, err
	}
	now := u.now().UTC()
	input.ID, input.OrganizationID, input.ProjectID = routeID, principal.OrganizationID, projectID
	input.Status, input.Revision, input.Version = StatusPending, 1, 1
	input.Observation, input.FailureCode = nil, ""
	input.CreatedBy, input.UpdatedBy, input.CreatedAt, input.UpdatedAt = principal.UserID, principal.UserID, now, now
	item, err := NewApplicationRoute(input)
	if err != nil {
		return ApplicationRoute{}, err
	}
	return u.create(ctx, principal, item, requestID)
}

func (u *UseCase) List(ctx context.Context, principal security.Principal, projectID string) ([]ApplicationRoute, error) {
	if err := principal.Require(security.PermissionApplicationRouteRead); err != nil {
		return nil, err
	}
	projectID = strings.TrimSpace(projectID)
	if !validID(projectID) {
		return nil, ErrInvalidRoute
	}
	return u.repository.List(ctx, principal.OrganizationID, projectID)
}

func (u *UseCase) Get(ctx context.Context, principal security.Principal, projectID, routeID string) (ApplicationRoute, error) {
	if err := principal.Require(security.PermissionApplicationRouteRead); err != nil {
		return ApplicationRoute{}, err
	}
	projectID, routeID = strings.TrimSpace(projectID), strings.TrimSpace(routeID)
	if !validID(projectID) || !validID(routeID) {
		return ApplicationRoute{}, ErrInvalidRoute
	}
	return u.repository.Get(ctx, principal.OrganizationID, projectID, routeID)
}

func (u *UseCase) Update(ctx context.Context, principal security.Principal, projectID, routeID string, expectedVersion uint64, input Input, requestID string) (ApplicationRoute, error) {
	if err := principal.Require(security.PermissionApplicationRouteWrite); err != nil {
		return ApplicationRoute{}, err
	}
	projectID, routeID = strings.TrimSpace(projectID), strings.TrimSpace(routeID)
	if !validID(projectID) || !validID(routeID) || expectedVersion == 0 {
		return ApplicationRoute{}, ErrInvalidRoute
	}
	current, err := u.repository.Get(ctx, principal.OrganizationID, projectID, routeID)
	if err != nil {
		return ApplicationRoute{}, err
	}
	if current.Version != expectedVersion || current.Status == StatusProvisioning ||
		current.Status == StatusRetiring || current.Status == StatusRetired {
		return ApplicationRoute{}, ErrRouteConflict
	}
	if strings.TrimSpace(input.ApplicationID) != current.ApplicationID || strings.TrimSpace(input.EnvironmentID) != current.EnvironmentID || strings.TrimSpace(input.RuntimeTargetID) != current.RuntimeTargetID {
		return ApplicationRoute{}, ErrRouteConflict
	}
	if err := u.validateReferences(ctx, principal.OrganizationID, projectID, input); err != nil {
		return ApplicationRoute{}, err
	}
	input.ID, input.OrganizationID, input.ProjectID = current.ID, current.OrganizationID, current.ProjectID
	input.Status, input.Revision, input.Version = StatusPending, current.Revision+1, current.Version+1
	input.Observation, input.FailureCode = current.Observation, ""
	input.CreatedBy, input.UpdatedBy = current.CreatedBy, principal.UserID
	input.CreatedAt, input.UpdatedAt = current.CreatedAt, u.now().UTC()
	updated, err := NewApplicationRoute(input)
	if err != nil {
		return ApplicationRoute{}, err
	}
	return u.save(ctx, principal, updated, expectedVersion, requestID)
}

func (u *UseCase) validateReferences(ctx context.Context, organizationID, projectID string, input Input) error {
	refs, err := u.references.Resolve(ctx, organizationID, projectID, input.ApplicationID, input.EnvironmentID, input.RuntimeTargetID)
	if err != nil {
		return err
	}
	if !refs.AgentTarget {
		return ErrUnsupportedTarget
	}
	if input.TLSMode == TLSModeDisabled && refs.EnvironmentStage != "development" {
		return ErrInvalidRoute
	}
	return nil
}

func (u *UseCase) create(ctx context.Context, principal security.Principal, item ApplicationRoute, requestID string) (ApplicationRoute, error) {
	if u.transaction == nil || u.auditor == nil {
		return u.repository.Create(ctx, item)
	}
	var created ApplicationRoute
	err := u.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var createErr error
		created, createErr = u.repository.Create(tx, item)
		if createErr != nil {
			return createErr
		}
		return u.recordAudit(tx, principal, item, "application_route.create", requestID, item.CreatedAt)
	})
	return created, err
}

func (u *UseCase) save(ctx context.Context, principal security.Principal, item ApplicationRoute, expectedVersion uint64, requestID string) (ApplicationRoute, error) {
	if u.transaction == nil || u.auditor == nil {
		return u.repository.Save(ctx, item, expectedVersion)
	}
	var saved ApplicationRoute
	err := u.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var saveErr error
		saved, saveErr = u.repository.Save(tx, item, expectedVersion)
		if saveErr != nil {
			return saveErr
		}
		return u.recordAudit(tx, principal, item, "application_route.update", requestID, item.UpdatedAt)
	})
	return saved, err
}

func (u *UseCase) recordAudit(ctx context.Context, principal security.Principal, item ApplicationRoute, action, requestID string, now time.Time) error {
	auditID, err := u.newID()
	if err != nil {
		return err
	}
	return u.auditor.Record(ctx, sharedaudit.Event{ID: auditID, OrganizationID: principal.OrganizationID,
		ProjectID: item.ProjectID, ActorID: principal.UserID, Action: action, ResourceType: "application_route",
		ResourceID: item.ID, RequestID: strings.TrimSpace(requestID), CreatedAt: now})
}
