package data

import (
	"context"
	"errors"

	applicationbiz "github.com/owndock/owndock/internal/modules/application/biz"
	environmentbiz "github.com/owndock/owndock/internal/modules/environment/biz"
)

type ApplicationLookup struct {
	repo applicationbiz.Repository
}

func NewApplicationLookup(repo applicationbiz.Repository) *ApplicationLookup {
	return &ApplicationLookup{repo: repo}
}

func (l *ApplicationLookup) Exists(ctx context.Context, id string) (bool, error) {
	_, err := l.repo.Find(ctx, id)
	if errors.Is(err, applicationbiz.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

type EnvironmentLookup struct {
	repo environmentbiz.Repository
}

func NewEnvironmentLookup(repo environmentbiz.Repository) *EnvironmentLookup {
	return &EnvironmentLookup{repo: repo}
}

func (l *EnvironmentLookup) Exists(ctx context.Context, id string) (bool, error) {
	_, err := l.repo.Find(ctx, id)
	if errors.Is(err, environmentbiz.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
