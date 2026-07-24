package biz

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidApplication    = errors.New("application id is required")
	ErrInvalidEnvironment    = errors.New("environment id is required")
	ErrInvalidTransition     = errors.New("invalid deployment status transition")
	ErrInvalidLease          = errors.New("invalid deployment lease")
	ErrNotClaimable          = errors.New("deployment is not claimable")
	ErrNotFound              = errors.New("deployment not found")
	ErrConflict              = errors.New("deployment version conflict")
	ErrLeaseExpired          = errors.New("deployment lease expired")
	ErrApplicationNotFound   = errors.New("application not found")
	ErrEnvironmentNotFound   = errors.New("environment not found")
	ErrInvalidRelease        = errors.New("release id is required")
	ErrInvalidRuntimeTarget  = errors.New("runtime target id is required")
	ErrInvalidIdempotencyKey = errors.New("idempotency key is required")
)

type Status string

const (
	StatusQueued    Status = "queued"
	StatusBuilding  Status = "building"
	StatusDeploying Status = "deploying"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCanceling Status = "canceling"
	StatusCanceled  Status = "canceled"
)

type Lease struct {
	Owner     string
	ExpiresAt time.Time
}

func (l Lease) Active(now time.Time) bool {
	return strings.TrimSpace(l.Owner) != "" && l.ExpiresAt.After(now)
}

type Deployment struct {
	ID              string
	ReleaseID       string
	ApplicationID   string
	EnvironmentID   string
	RuntimeTargetID string
	IdempotencyKey  string
	Revision        string
	Status          Status
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Version         uint64
	Lease           Lease
}

// NewFormal creates the immutable product deployment reference. Runtime execution
// may evolve, but these references and the idempotency key never change.
func NewFormal(id, releaseID, applicationID, environmentID, runtimeTargetID, idempotencyKey string, now time.Time) (Deployment, error) {
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
	item.RuntimeTargetID = strings.TrimSpace(runtimeTargetID)
	item.IdempotencyKey = idempotencyKey
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
	List(context.Context, string, string) ([]Deployment, error)
	Create(context.Context, Deployment) (Deployment, error)
	ClaimNext(context.Context, Claim) (Deployment, bool, error)
	SaveClaimed(context.Context, Deployment, uint64, string, time.Time) (Deployment, error)
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
	valid := (d.Status == StatusQueued && (next == StatusBuilding || next == StatusCanceling)) ||
		(d.Status == StatusBuilding && (next == StatusDeploying || next == StatusFailed || next == StatusCanceling)) ||
		(d.Status == StatusDeploying && (next == StatusSucceeded || next == StatusFailed || next == StatusCanceling)) ||
		(d.Status == StatusCanceling && next == StatusCanceled)
	if !valid {
		return ErrInvalidTransition
	}
	d.Status = next
	d.UpdatedAt = now.UTC()
	if d.Terminal() {
		d.Lease = Lease{}
	}
	return nil
}

func (d *Deployment) Acquire(claim Claim) error {
	if err := claim.Validate(); err != nil {
		return err
	}
	switch d.Status {
	case StatusQueued:
		if err := d.Transition(StatusBuilding, claim.Now); err != nil {
			return err
		}
	case StatusBuilding, StatusDeploying:
		if d.Lease.Active(claim.Now) {
			return ErrNotClaimable
		}
		d.UpdatedAt = claim.Now.UTC()
	default:
		return ErrNotClaimable
	}
	d.Lease = Lease{Owner: strings.TrimSpace(claim.WorkerID), ExpiresAt: claim.ExpiresAt.UTC()}
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
