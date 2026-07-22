package biz

import (
	"context"
	"errors"
	"strings"
	"time"
)

var ErrInvalidName = errors.New("application name is required")
var ErrDuplicateName = errors.New("application name already exists")
var ErrNotFound = errors.New("application not found")
var ErrInvalidStatusTransition = errors.New("invalid application status transition")

type Status string

const (
	StatusPending Status = "pending"
	StatusReady   Status = "ready"
	StatusFailed  Status = "failed"
)

type Application struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type Repository interface {
	List(context.Context) ([]Application, error)
	Create(context.Context, Application) (Application, error)
	Find(context.Context, string) (Application, error)
}

func New(name, id string, now time.Time) (Application, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Application{}, ErrInvalidName
	}
	return Application{ID: id, Name: name, Status: StatusPending, CreatedAt: now.UTC()}, nil
}

func (a *Application) Transition(next Status) error {
	valid := (a.Status == StatusPending && (next == StatusReady || next == StatusFailed)) ||
		(a.Status == StatusFailed && next == StatusPending)
	if !valid {
		return ErrInvalidStatusTransition
	}
	a.Status = next
	return nil
}
