package data

import (
	"context"
	"testing"
	"time"

	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type snapshotSourceStub struct {
	resources []transport.Resource
	err       error
}

func (s snapshotSourceStub) Collect(
	context.Context,
) ([]transport.Resource, error) {
	return append([]transport.Resource{}, s.resources...), s.err
}

func TestDirectCollectorCommitsOnlyCompleteSafeSnapshot(t *testing.T) {
	now := time.Unix(3000, 0).UTC()
	repository := &inventoryRepositoryStub{}
	collector, err := NewDirectCollector(
		snapshotSourceStub{resources: []transport.Resource{
			inventoryTransportChunk(0, "container-1", now).Resources[0],
			inventoryTransportChunk(0, "container-2", now).Resources[0],
		}},
		repository,
		func() (string, error) { return "observation-direct-1", nil },
		func() time.Time { return now },
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Synchronize(
		t.Context(),
		"organization-1",
		"host-1",
		"target-1",
	); err != nil {
		t.Fatal(err)
	}
	if !repository.completed || len(repository.chunks) != 1 ||
		len(repository.chunks[0].Resources) != 2 {
		t.Fatalf(
			"completed/chunks/resources = %v/%d/%d",
			repository.completed,
			len(repository.chunks),
			len(repository.chunks[0].Resources),
		)
	}
}

func TestDirectCollectorRejectsSkewedObservationTime(t *testing.T) {
	now := time.Unix(3000, 0).UTC()
	collector, err := NewDirectCollector(
		snapshotSourceStub{resources: []transport.Resource{
			inventoryTransportChunk(
				0,
				"container-1",
				now.Add(25*time.Hour),
			).Resources[0],
		}},
		&inventoryRepositoryStub{},
		func() (string, error) { return "observation-direct-1", nil },
		func() time.Time { return now },
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Synchronize(
		t.Context(),
		"organization-1",
		"host-1",
		"target-1",
	); err == nil {
		t.Fatal("collector accepted an observation outside the clock window")
	}
}
