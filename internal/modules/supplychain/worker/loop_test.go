package worker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func TestEvidenceLoopPollsAndStops(t *testing.T) {
	queue := &queueProbe{
		item: workerJobFixture(t), wantWorker: "evidence-worker-1", wantGeneration: 1,
	}
	controller, err := NewController(queue, time.Now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(
		controller,
		&sbomGeneratorProbe{document: validSBOMDocument(t)},
		&sbomPublisherProbe{descriptor: biz.PublishedDescriptor{
			Digest:    "sha256:" + strings.Repeat("c", 64),
			MediaType: "application/vnd.oci.image.manifest.v1+json",
		}},
		func() (string, error) { return "evidence-1", nil },
		time.Now, "evidence-worker-1", time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	loop, err := NewLoop(runner, 5*time.Millisecond, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var mutex sync.Mutex
	results := make([]string, 0, 1)
	loop.WithObservability(func(result string, _ time.Duration) {
		mutex.Lock()
		results = append(results, result)
		count := len(results)
		mutex.Unlock()
		if count == 1 {
			cancel()
		}
	})
	if err := loop.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(results) != 1 || results[0] != "success" {
		t.Fatalf("poll results = %v", results)
	}
}

func TestEvidenceLoopValidatesConfigurationAndBoundsResults(t *testing.T) {
	if _, err := NewLoop(nil, time.Second, time.Second, nil); err == nil {
		t.Fatal("nil runner accepted")
	}
	for _, test := range []struct {
		err  error
		want string
	}{
		{err: nil, want: "success"},
		{err: context.DeadlineExceeded, want: "timeout"},
		{err: context.Canceled, want: "canceled"},
		{err: biz.ErrUnavailable, want: "error"},
	} {
		if got := evidenceLoopResult(test.err); got != test.want {
			t.Errorf("evidenceLoopResult(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}
