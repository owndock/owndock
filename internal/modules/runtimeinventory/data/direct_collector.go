package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	inventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

var ErrDirectInventoryUnavailable = errors.New(
	"direct runtime inventory is unavailable",
)

type SnapshotSource interface {
	Collect(context.Context) ([]transport.Resource, error)
}

// DirectCollector applies the same safe transport projection and generation
// commit semantics as Agent collection. Runtime credential resolution and
// source construction stay outside this type.
type DirectCollector struct {
	source        SnapshotSource
	repository    inventorybiz.Repository
	newID         func() (string, error)
	now           func() time.Time
	maxChunkBytes int
}

func NewDirectCollector(
	source SnapshotSource,
	repository inventorybiz.Repository,
	newID func() (string, error),
	now func() time.Time,
	maxChunkBytes int,
) (*DirectCollector, error) {
	if source == nil || repository == nil || newID == nil || now == nil ||
		maxChunkBytes < 4*1024 ||
		maxChunkBytes > transport.MaxChunkBytes {
		return nil, ErrDirectInventoryUnavailable
	}
	return &DirectCollector{
		source:        source,
		repository:    repository,
		newID:         newID,
		now:           now,
		maxChunkBytes: maxChunkBytes,
	}, nil
}

func (c *DirectCollector) Synchronize(
	ctx context.Context,
	organizationID, managedHostID, runtimeTargetID string,
) error {
	observationID, err := c.newID()
	if err != nil {
		return fmt.Errorf("%w: generate observation ID", ErrDirectInventoryUnavailable)
	}
	startedAt := c.now().UTC()
	resources, err := c.source.Collect(ctx)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return fmt.Errorf("%w: collection failed", ErrDirectInventoryUnavailable)
	}
	if err := validateObservedTimesAt(resources, c.now().UTC()); err != nil {
		return fmt.Errorf("%w: collector clock outside accepted window", ErrDirectInventoryUnavailable)
	}
	chunks, err := transport.Split(
		resources,
		c.maxChunkBytes,
		transport.MaxResourcesPerChunk,
	)
	if err != nil {
		return fmt.Errorf("%w: invalid snapshot", ErrDirectInventoryUnavailable)
	}
	observation, err := inventorybiz.NewObservation(
		observationID,
		organizationID,
		managedHostID,
		runtimeTargetID,
		len(chunks),
		len(resources),
		startedAt,
	)
	if err != nil {
		return fmt.Errorf("%w: invalid scope", ErrDirectInventoryUnavailable)
	}
	if err := c.repository.Begin(ctx, observation); err != nil {
		return err
	}
	for index, transportChunk := range chunks {
		projected, err := ProjectResources(
			observation,
			transportChunk.Resources,
		)
		if err != nil {
			return err
		}
		chunk, err := inventorybiz.NewChunk(observation, index, projected)
		if err != nil {
			return err
		}
		if err := c.repository.Append(ctx, chunk); err != nil {
			return err
		}
	}
	return c.repository.Complete(
		ctx,
		observation.ID,
		observation.RuntimeTargetID,
		c.now().UTC(),
	)
}

func validateObservedTimesAt(
	resources []transport.Resource,
	now time.Time,
) error {
	minimum := now.Add(-maximumInventoryClockSkew)
	maximum := now.Add(maximumInventoryClockSkew)
	for _, resource := range resources {
		if resource.ObservedAt.Before(minimum) ||
			resource.ObservedAt.After(maximum) {
			return ErrDirectInventoryUnavailable
		}
	}
	return nil
}
