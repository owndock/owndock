package worker

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/deployment/data"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
)

var errBuildFailed = errors.New("prepare failed")

type failingExecutor struct{}

func (failingExecutor) Prepare(context.Context, biz.Deployment) error {
	return errBuildFailed
}
func (failingExecutor) Deploy(context.Context, biz.Deployment) error { return nil }
func (failingExecutor) Cancel(context.Context, biz.Deployment) error { return nil }

type slowBuildExecutor struct{ duration time.Duration }

func (e slowBuildExecutor) Prepare(ctx context.Context, _ biz.Deployment) error {
	select {
	case <-time.After(e.duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (slowBuildExecutor) Deploy(context.Context, biz.Deployment) error { return nil }
func (slowBuildExecutor) Cancel(context.Context, biz.Deployment) error { return nil }

func newTestRunner(t *testing.T, repo biz.Repository, executor biz.Executor, now time.Time) *Runner {
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
	items, err := repo.List(t.Context(), "", "", "")
	if err != nil || len(items) != 1 || items[0].Status != biz.StatusSucceeded {
		t.Fatalf("items = %+v, err = %v", items, err)
	}
	if items[0].Lease.Owner != "" || items[0].Version != 7 {
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
	items, _ := repo.List(t.Context(), "", "", "")
	if len(items) != 1 || items[0].Status != biz.StatusFailed ||
		items[0].FailureCategory != biz.FailureConfiguration {
		t.Fatalf("items = %+v", items)
	}
}

type workerAuditProbe struct {
	events []sharedaudit.Event
}

func (p *workerAuditProbe) Record(_ context.Context, event sharedaudit.Event) error {
	p.events = append(p.events, event)
	return nil
}

func TestRunOnceAuditsEveryWorkerStatusTransition(t *testing.T) {
	repository := data.NewMemoryRepository()
	item, err := biz.New("app", "env", "", "deployment", time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	item.OrganizationID = "organization"
	item.ProjectID = "project"
	if _, err := repository.Create(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	runner := newTestRunner(t, repository, NoopExecutor{}, time.Unix(10, 0))
	audits := &workerAuditProbe{}
	sequence := 0
	runner.WithAudit(transaction.Passthrough{}, audits, func() (string, error) {
		sequence++
		return fmt.Sprintf("audit-%d", sequence), nil
	})
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(audits.events) != 3 {
		t.Fatalf("audit events = %+v", audits.events)
	}
	want := []string{
		biz.AuditActionPreparing,
		biz.AuditActionDeploying,
		biz.AuditActionSucceeded,
	}
	for index := range want {
		event := audits.events[index]
		if event.Action != want[index] || event.OrganizationID != "organization" ||
			event.ProjectID != "project" || event.ActorID != "system:worker-1" {
			t.Errorf("audit event %d = %+v", index, event)
		}
	}
}

func TestRunOnceRenewsLeaseDuringLongStep(t *testing.T) {
	repo := data.NewMemoryRepository()
	item, _ := biz.New("app-1", "env-1", "main@abc", "dep-1", time.Now())
	if _, err := repo.Create(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(
		repo, slowBuildExecutor{duration: 180 * time.Millisecond},
		"worker-1", 60*time.Millisecond, time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	items, err := repo.List(t.Context(), "", "", "")
	if err != nil || len(items) != 1 || items[0].Status != biz.StatusSucceeded {
		t.Fatalf("items = %+v, err = %v", items, err)
	}
	if items[0].Version <= 6 {
		t.Fatalf("version = %d, expected heartbeat renewals", items[0].Version)
	}
}

func TestRunOnceCompletesCancellation(t *testing.T) {
	repo := data.NewMemoryRepository()
	item, _ := biz.New("app-1", "env-1", "main@abc", "dep-1", time.Unix(0, 0))
	item.ProjectID = "project-1"
	item, err := repo.Create(t.Context(), item)
	if err != nil {
		t.Fatal(err)
	}
	if err := item.Cancel(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Save(t.Context(), item, item.Version); err != nil {
		t.Fatal(err)
	}
	if err := newTestRunner(t, repo, NoopExecutor{}, time.Unix(10, 0)).RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	items, err := repo.List(t.Context(), "project-1", "", "")
	if err != nil || len(items) != 1 || items[0].Status != biz.StatusCanceled {
		t.Fatalf("items = %+v, err = %v", items, err)
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
