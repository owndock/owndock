package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type scheduleRepositoryStub struct {
	mu        sync.Mutex
	targets   []biz.Target
	available bool
	lease     biz.ScheduleLease
	finished  bool
	succeeded bool
	nextDueAt time.Time
}

func (r *scheduleRepositoryStub) ListReadyTargets(
	context.Context,
	int,
	time.Time,
) ([]biz.Target, error) {
	return append([]biz.Target{}, r.targets...), nil
}

func (r *scheduleRepositoryStub) TryAcquire(
	_ context.Context,
	target biz.Target,
	owner string,
	_, _ time.Time,
) (biz.ScheduleLease, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.available {
		return biz.ScheduleLease{}, false, nil
	}
	r.available = false
	r.lease = biz.ScheduleLease{
		RuntimeTargetID: target.RuntimeTargetID,
		OwnerID:         owner,
		Token:           1,
	}
	return r.lease, true, nil
}

func (r *scheduleRepositoryStub) Finish(
	_ context.Context,
	lease biz.ScheduleLease,
	_, nextDueAt time.Time,
	succeeded bool,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if lease != r.lease {
		return biz.ErrLeaseLost
	}
	r.finished = true
	r.succeeded = succeeded
	r.nextDueAt = nextDueAt
	return nil
}

type collectorStub struct {
	err error
}

func (c collectorStub) Collect(context.Context, biz.Target) error { return c.err }

func TestRunnerSchedulesSuccessAndRetry(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	target := testTarget(t)
	tests := []struct {
		name       string
		collectErr error
		wantDelay  time.Duration
		succeeded  bool
	}{
		{name: "success", wantDelay: 5 * time.Minute, succeeded: true},
		{name: "failure", collectErr: errors.New("unavailable"), wantDelay: 30 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &scheduleRepositoryStub{
				targets: []biz.Target{target}, available: true,
			}
			runner, err := NewRunner(
				repository,
				collectorStub{err: test.collectErr},
				"worker-1",
				2*time.Minute,
				5*time.Minute,
				30*time.Second,
				256,
				func() time.Time { return now },
			)
			if err != nil {
				t.Fatal(err)
			}
			runErr := runner.RunOnce(t.Context())
			if (runErr != nil) != (test.collectErr != nil) {
				t.Fatalf("RunOnce() error = %v", runErr)
			}
			if !repository.finished || repository.succeeded != test.succeeded ||
				repository.nextDueAt != now.Add(test.wantDelay) {
				t.Fatalf(
					"settlement = finished:%v succeeded:%v next:%v",
					repository.finished,
					repository.succeeded,
					repository.nextDueAt,
				)
			}
		})
	}
}

func TestRunnerDoesNothingWhenEveryTargetIsLeased(t *testing.T) {
	repository := &scheduleRepositoryStub{targets: []biz.Target{testTarget(t)}}
	runner, err := NewRunner(
		repository,
		collectorStub{err: errors.New("must not run")},
		"worker-1",
		time.Minute,
		time.Minute,
		time.Second,
		10,
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if repository.finished {
		t.Fatal("leased target was settled by a worker that did not own it")
	}
}

func testTarget(t *testing.T) biz.Target {
	t.Helper()
	connection, err := runtimeaccess.NewAgent("host-1")
	if err != nil {
		t.Fatal(err)
	}
	return biz.Target{
		OrganizationID:  "organization-1",
		ProjectID:       "project-1",
		ManagedHostID:   "host-1",
		RuntimeTargetID: "target-1",
		Connection:      connection,
	}
}
