package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/deployment/data"
)

type failingExecutor struct{}

func (failingExecutor) Build(context.Context, biz.Deployment) error {
	return errors.New("build failed")
}
func (failingExecutor) Deploy(context.Context, biz.Deployment) error { return nil }

func TestRunOnceCompletesQueuedDeployment(t *testing.T) {
	repo := data.NewMemoryRepository()
	item, err := biz.New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Create(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if err := NewRunner(repo, NoopExecutor{}).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	items, err := repo.List(context.Background(), "", "")
	if err != nil || len(items) != 1 || items[0].Status != biz.StatusSucceeded {
		t.Fatalf("items = %+v, err = %v", items, err)
	}
}

func TestRunOnceMarksBuildFailure(t *testing.T) {
	repo := data.NewMemoryRepository()
	item, _ := biz.New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	_, _ = repo.Create(context.Background(), item)
	if err := NewRunner(repo, failingExecutor{}).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	items, _ := repo.List(context.Background(), "", "")
	if len(items) != 1 || items[0].Status != biz.StatusFailed {
		t.Fatalf("items = %+v", items)
	}
}
