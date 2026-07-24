package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/deployment/data"
)

var errBuildFailed = errors.New("build failed")

type failingExecutor struct{}

func (failingExecutor) Build(context.Context, biz.Deployment) error {
	return errBuildFailed
}
func (failingExecutor) Deploy(context.Context, biz.Deployment) error { return nil }

func newTestRunner(t *testing.T, repo biz.Repository, executor Executor, now time.Time) *Runner {
	t.Helper()
	runner, err := NewRunner(repo, executor, "worker-1", time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestRunOnceCompletesQueuedDeployment(t *testing.T) {
	repo := data.NewMemoryRepository()
	item, err := biz.New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Create(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	if err := newTestRunner(t, repo, NoopExecutor{}, time.Unix(10, 0)).RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	items, err := repo.List(t.Context(), "", "")
	if err != nil || len(items) != 1 || items[0].Status != biz.StatusSucceeded {
		t.Fatalf("items = %+v, err = %v", items, err)
	}
	if items[0].Lease.Owner != "" || items[0].Version != 4 {
		t.Fatalf("completed deployment metadata = %+v", items[0])
	}
}

func TestRunOnceMarksAndReportsBuildFailure(t *testing.T) {
	repo := data.NewMemoryRepository()
	item, _ := biz.New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	_, _ = repo.Create(t.Context(), item)
	err := newTestRunner(t, repo, failingExecutor{}, time.Unix(10, 0)).RunOnce(t.Context())
	if !errors.Is(err, errBuildFailed) {
		t.Fatalf("RunOnce() error = %v", err)
	}
	items, _ := repo.List(t.Context(), "", "")
	if len(items) != 1 || items[0].Status != biz.StatusFailed {
		t.Fatalf("items = %+v", items)
	}
}

func TestNewRunnerValidatesLeaseConfiguration(t *testing.T) {
	if _, err := NewRunner(nil, NoopExecutor{}, "worker-1", time.Minute, time.Now); !errors.Is(err, ErrMissingRepository) {
		t.Fatalf("repository error = %v", err)
	}
	if _, err := NewRunner(data.NewMemoryRepository(), nil, "worker-1", time.Minute, time.Now); !errors.Is(err, ErrMissingExecutor) {
		t.Fatalf("executor error = %v", err)
	}
	if _, err := NewRunner(data.NewMemoryRepository(), NoopExecutor{}, "", time.Minute, time.Now); !errors.Is(err, ErrInvalidWorkerID) {
		t.Fatalf("worker id error = %v", err)
	}
	if _, err := NewRunner(data.NewMemoryRepository(), NoopExecutor{}, "worker-1", 0, time.Now); !errors.Is(err, ErrInvalidLeaseTimeout) {
		t.Fatalf("lease duration error = %v", err)
	}
	if _, err := NewRunner(data.NewMemoryRepository(), NoopExecutor{}, "worker-1", time.Minute, nil); !errors.Is(err, ErrMissingClock) {
		t.Fatalf("clock error = %v", err)
	}
}
