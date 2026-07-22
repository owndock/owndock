package biz

import (
	"context"
	"errors"
	"strings"
	"time"
)

var ErrInvalidName = errors.New("application name is required")

type Application struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Repository interface {
	List(context.Context) ([]Application, error)
	Create(context.Context, Application) (Application, error)
}

func New(name, id string, now time.Time) (Application, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Application{}, ErrInvalidName
	}
	return Application{ID: id, Name: name, CreatedAt: now.UTC()}, nil
}
