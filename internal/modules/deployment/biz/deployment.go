package biz

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidApplication    = errors.New("application id is required")
	ErrInvalidProject        = errors.New("project id is required")
	ErrInvalidEnvironment    = errors.New("environment id is required")
	ErrInvalidTransition     = errors.New("invalid deployment status transition")
	ErrInvalidLease          = errors.New("invalid deployment lease")
	ErrNotClaimable          = errors.New("deployment is not claimable")
	ErrNotFound              = errors.New("deployment not found")
	ErrConflict              = errors.New("deployment version conflict")
	ErrDuplicateIdempotency  = errors.New("idempotency key already used")
	ErrLeaseExpired          = errors.New("deployment lease expired")
	ErrApplicationNotFound   = errors.New("application not found")
	ErrEnvironmentNotFound   = errors.New("environment not found")
	ErrReleaseNotFound       = errors.New("release not found")
	ErrRuntimeTargetNotFound = errors.New("runtime target not found")
	ErrRuntimeTargetNotReady = errors.New("runtime target is not ready")
	ErrReferenceLookup       = errors.New("formal deployment reference lookup is required")
	ErrFormalSecurity        = errors.New("formal deployment transaction and audit are required")
	ErrInvalidRelease        = errors.New("release id is required")
	ErrInvalidRuntimeTarget  = errors.New("runtime target id is required")
	ErrInvalidIdempotencyKey = errors.New("idempotency key is required")
	ErrIdempotencyMismatch   = errors.New("idempotency key was used with different deployment references")
	ErrRetryRequiresFailed   = errors.New("only a failed deployment can be retried")
	ErrRollbackRequiresFinal = errors.New("only a completed deployment can be rolled back")
	ErrRollbackSameRelease   = errors.New("rollback release must differ from the source release")
	ErrRollbackNotSucceeded  = errors.New("rollback release has no successful deployment on the selected target")
	ErrInvalidFailure        = errors.New("deployment failure category is invalid")
	ErrStaleExecution        = errors.New("deployment execution lease is stale")
)

type Status string
type Operation string

const (
	StatusQueued    Status = "queued"
	StatusPreparing Status = "preparing"
	StatusDeploying Status = "deploying"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCanceling Status = "canceling"
	StatusCanceled  Status = "canceled"

	OperationDeploy   Operation = "deploy"
	OperationRetry    Operation = "retry"
	OperationRollback Operation = "rollback"
)

type Lease struct {
	Owner      string
	ExpiresAt  time.Time
	Generation uint64
}

func (l Lease) Active(now time.Time) bool {
	return strings.TrimSpace(l.Owner) != "" && l.ExpiresAt.After(now)
}

type Deployment struct {
	ID                 string
	OrganizationID     string
	ProjectID          string
	ReleaseID          string
	ApplicationID      string
	EnvironmentID      string
	RuntimeTargetID    string
	IdempotencyKey     string
	Operation          Operation
	SourceDeploymentID string
	Revision           string
	Status             Status
	FailureCategory    FailureCategory
	CreatedAt          time.Time
	UpdatedAt          time.Time
	Version            uint64
	Lease              Lease
}

// NewFormal creates the immutable product deployment reference. Runtime execution
// may evolve, but these references and the idempotency key never change.
func NewFormal(id, projectID, releaseID, applicationID, environmentID, runtimeTargetID, idempotencyKey string, now time.Time) (Deployment, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return Deployment{}, ErrInvalidProject
	}
	if strings.TrimSpace(releaseID) == "" {
		return Deployment{}, ErrInvalidRelease
	}
	if strings.TrimSpace(runtimeTargetID) == "" {
		return Deployment{}, ErrInvalidRuntimeTarget
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" || len(idempotencyKey) > 128 {
		return Deployment{}, ErrInvalidIdempotencyKey
	}
	item, err := New(applicationID, environmentID, "", id, now)
	if err != nil {
		return Deployment{}, err
	}
	item.ReleaseID = strings.TrimSpace(releaseID)
	item.ProjectID = projectID
	item.RuntimeTargetID = strings.TrimSpace(runtimeTargetID)
	item.IdempotencyKey = idempotencyKey
	item.Operation = OperationDeploy
	return item, nil
}

type Claim struct {
	WorkerID  string
	Now       time.Time
	ExpiresAt time.Time
}

func (c Claim) Validate() error {
	if strings.TrimSpace(c.WorkerID) == "" || c.Now.IsZero() || !c.ExpiresAt.After(c.Now) {
		return ErrInvalidLease
	}
	return nil
}

type Repository interface {
	List(context.Context, string, string, string) ([]Deployment, error)
	Get(context.Context, string, string) (Deployment, error)
	GetByIdempotency(context.Context, string, string) (Deployment, error)
	HasSucceeded(context.Context, string, string, string, string, string) (bool, error)
	Create(context.Context, Deployment) (Deployment, error)
	Save(context.Context, Deployment, uint64) (Deployment, error)
	ClaimNext(context.Context, Claim) (Deployment, bool, error)
	SaveClaimed(context.Context, Deployment, uint64, string, time.Time) (Deployment, error)
	RenewLease(context.Context, string, string, uint64, time.Time, time.Time) (Deployment, error)
}

type ApplicationLookup interface {
	Exists(context.Context, string) (bool, error)
}

type EnvironmentLookup interface {
	Exists(context.Context, string) (bool, error)
}

func New(applicationID, environmentID, revision, id string, now time.Time) (Deployment, error) {
	applicationID = strings.TrimSpace(applicationID)
	environmentID = strings.TrimSpace(environmentID)
	if applicationID == "" {
		return Deployment{}, ErrInvalidApplication
	}
	if environmentID == "" {
		return Deployment{}, ErrInvalidEnvironment
	}
	now = now.UTC()
	return Deployment{
		ID:            strings.TrimSpace(id),
		ApplicationID: applicationID,
		EnvironmentID: environmentID,
		Revision:      strings.TrimSpace(revision),
		Status:        StatusQueued,
		CreatedAt:     now,
		UpdatedAt:     now,
		Version:       1,
	}, nil
}

func (d *Deployment) Transition(next Status, now time.Time) error {
	valid := (d.Status == StatusQueued && (next == StatusPreparing || next == StatusCanceling)) ||
		(d.Status == StatusPreparing && (next == StatusDeploying || next == StatusFailed || next == StatusCanceling)) ||
		(d.Status == StatusDeploying && (next == StatusSucceeded || next == StatusFailed || next == StatusCanceling)) ||
		(d.Status == StatusCanceling && next == StatusCanceled)
	if !valid {
		return ErrInvalidTransition
	}
	d.Status = next
	d.UpdatedAt = now.UTC()
	if next == StatusFailed {
		d.FailureCategory = FailureUnknown
	} else {
		d.FailureCategory = ""
	}
	if d.Terminal() {
		d.Lease = Lease{}
	}
	return nil
}

// Fail stores only a stable, safe category. Raw infrastructure errors are
// deliberately excluded from the domain record and public API.
func (d *Deployment) Fail(category FailureCategory, now time.Time) error {
	if !category.Valid() {
		return ErrInvalidFailure
	}
	if err := d.Transition(StatusFailed, now); err != nil {
		return err
	}
	d.FailureCategory = category
	return nil
}

// Cancel requests cooperative cancellation. Workers must observe canceling and
// only then move the operation to canceled, preserving the audit trail.
func (d *Deployment) Cancel(now time.Time) error {
	if d.Terminal() {
		return ErrInvalidTransition
	}
	return d.Transition(StatusCanceling, now)
}

// Retry creates a new queued operation while preserving the immutable product
// references. The caller must provide a fresh idempotency key.
func (d Deployment) Retry(newID, idempotencyKey string, now time.Time) (Deployment, error) {
	if d.Status != StatusFailed {
		return Deployment{}, ErrRetryRequiresFailed
	}
	item, err := NewFormal(newID, d.ProjectID, d.ReleaseID, d.ApplicationID, d.EnvironmentID, d.RuntimeTargetID, idempotencyKey, now)
	if err != nil {
		return Deployment{}, err
	}
	item.Operation = OperationRetry
	item.OrganizationID = d.OrganizationID
	item.SourceDeploymentID = d.ID
	return item, nil
}

// Rollback creates a new queued operation targeting a previously known release.
func (d Deployment) Rollback(newID, releaseID, idempotencyKey string, now time.Time) (Deployment, error) {
	if !d.Terminal() {
		return Deployment{}, ErrRollbackRequiresFinal
	}
	if strings.TrimSpace(releaseID) == d.ReleaseID {
		return Deployment{}, ErrRollbackSameRelease
	}
	item, err := NewFormal(newID, d.ProjectID, releaseID, d.ApplicationID, d.EnvironmentID, d.RuntimeTargetID, idempotencyKey, now)
	if err != nil {
		return Deployment{}, err
	}
	item.Operation = OperationRollback
	item.OrganizationID = d.OrganizationID
	item.SourceDeploymentID = d.ID
	return item, nil
}

func (d *Deployment) Acquire(claim Claim) error {
	if err := claim.Validate(); err != nil {
		return err
	}
	switch d.Status {
	case StatusQueued:
		if d.Lease.Active(claim.Now) {
			return ErrNotClaimable
		}
		d.UpdatedAt = claim.Now.UTC()
	case StatusPreparing, StatusDeploying:
		if d.Lease.Active(claim.Now) {
			return ErrNotClaimable
		}
		d.UpdatedAt = claim.Now.UTC()
	case StatusCanceling:
		if d.Lease.Active(claim.Now) {
			return ErrNotClaimable
		}
		d.UpdatedAt = claim.Now.UTC()
	default:
		return ErrNotClaimable
	}
	d.Lease = Lease{
		Owner: strings.TrimSpace(claim.WorkerID), ExpiresAt: claim.ExpiresAt.UTC(),
		Generation: d.Lease.Generation + 1,
	}
	return nil
}

func (d *Deployment) Renew(owner string, now, expiresAt time.Time) error {
	if strings.TrimSpace(owner) == "" || d.Lease.Owner != owner || !d.Lease.Active(now) || !expiresAt.After(now) {
		return ErrInvalidLease
	}
	d.Lease.ExpiresAt = expiresAt.UTC()
	return nil
}

func (d Deployment) Terminal() bool {
	return d.Status == StatusSucceeded || d.Status == StatusFailed || d.Status == StatusCanceled
}
