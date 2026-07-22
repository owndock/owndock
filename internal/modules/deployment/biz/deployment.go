package biz

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidApplication  = errors.New("application id is required")
	ErrInvalidEnvironment  = errors.New("environment id is required")
	ErrInvalidTransition   = errors.New("invalid deployment status transition")
	ErrApplicationNotFound = errors.New("application not found")
	ErrEnvironmentNotFound = errors.New("environment not found")
)

type Status string

const (
	StatusQueued    Status = "queued"
	StatusBuilding  Status = "building"
	StatusDeploying Status = "deploying"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCanceled  Status = "canceled"
)

type Deployment struct {
	ID            string    `json:"id"`
	ApplicationID string    `json:"application_id"`
	EnvironmentID string    `json:"environment_id"`
	Revision      string    `json:"revision"`
	Status        Status    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
}

type Repository interface {
	List(context.Context, string, string) ([]Deployment, error)
	Create(context.Context, Deployment) (Deployment, error)
	Update(context.Context, Deployment) error
}

type ApplicationLookup interface {
	Exists(context.Context, string) (bool, error)
}

type EnvironmentLookup interface {
	Exists(context.Context, string) (bool, error)
}

func New(applicationID, environmentID, revision, id string, now time.Time) (Deployment, error) {
	if strings.TrimSpace(applicationID) == "" {
		return Deployment{}, ErrInvalidApplication
	}
	if strings.TrimSpace(environmentID) == "" {
		return Deployment{}, ErrInvalidEnvironment
	}
	return Deployment{
		ID: id, ApplicationID: applicationID, EnvironmentID: environmentID,
		Revision: strings.TrimSpace(revision), Status: StatusQueued, CreatedAt: now.UTC(),
	}, nil
}

func (d *Deployment) Transition(next Status) error {
	valid := (d.Status == StatusQueued && next == StatusBuilding) ||
		(d.Status == StatusBuilding && (next == StatusDeploying || next == StatusFailed || next == StatusCanceled)) ||
		(d.Status == StatusDeploying && (next == StatusSucceeded || next == StatusFailed))
	if !valid {
		return ErrInvalidTransition
	}
	d.Status = next
	return nil
}
