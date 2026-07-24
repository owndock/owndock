package biz

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidName       = errors.New("environment name is required")
	ErrDuplicateName     = errors.New("environment name already exists")
	ErrNotFound          = errors.New("environment not found")
	ErrInvalidTransition = errors.New("invalid environment status transition")
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDraining Status = "draining"
	StatusDeleted  Status = "deleted"
)

type Environment struct {
	ID        string
	Name      string
	Provider  string
	Status    Status
	CreatedAt time.Time
}

type Repository interface {
	List(context.Context) ([]Environment, error)
	Create(context.Context, Environment) (Environment, error)
	Find(context.Context, string) (Environment, error)
}

func New(name, provider, id string, now time.Time) (Environment, error) {
	name = strings.TrimSpace(name)
	provider = strings.TrimSpace(provider)
	if name == "" || provider == "" {
		return Environment{}, ErrInvalidName
	}
	return Environment{ID: id, Name: name, Provider: provider, Status: StatusActive, CreatedAt: now.UTC()}, nil
}

func (e *Environment) Transition(next Status) error {
	valid := (e.Status == StatusActive && next == StatusDraining) ||
		(e.Status == StatusDraining && next == StatusDeleted)
	if !valid {
		return ErrInvalidTransition
	}
	e.Status = next
	return nil
}
