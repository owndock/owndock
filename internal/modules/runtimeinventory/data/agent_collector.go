package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/managedhost/biz"
	inventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

const maximumInventoryClockSkew = 24 * time.Hour

const defaultAgentInventoryRetryDelay = 100 * time.Millisecond

var ErrAgentInventoryUnavailable = errors.New(
	"Agent runtime inventory is unavailable",
)

// AgentCollector pulls one bounded chunk at a time. This keeps the existing
// command stream as the backpressure boundary and never asks either endpoint
// to cache an entire inventory result frame.
type AgentCollector struct {
	dispatcher     biz.AgentCommandDispatcher
	repository     inventorybiz.Repository
	newID          func() (string, error)
	now            func() time.Time
	commandTimeout time.Duration
	maxChunkBytes  int
	retryDelay     time.Duration
	eventHints     inventorybiz.EventHintRepository
}

func (c *AgentCollector) WithEventHints(
	repository inventorybiz.EventHintRepository,
) *AgentCollector {
	c.eventHints = repository
	return c
}

func (c *AgentCollector) Collect(
	ctx context.Context,
	target inventorybiz.Target,
) error {
	if err := target.Validate(); err != nil ||
		target.Connection.Mode != runtimeaccess.ModeAgent {
		return inventorybiz.ErrInvalidTarget
	}
	return c.Synchronize(
		ctx,
		target.OrganizationID,
		target.ManagedHostID,
		target.RuntimeTargetID,
	)
}

func NewAgentCollector(
	dispatcher biz.AgentCommandDispatcher,
	repository inventorybiz.Repository,
	newID func() (string, error),
	now func() time.Time,
	commandTimeout time.Duration,
	maxChunkBytes int,
) (*AgentCollector, error) {
	if dispatcher == nil || repository == nil || newID == nil || now == nil ||
		commandTimeout <= 0 || commandTimeout > time.Minute ||
		maxChunkBytes < 4*1024 ||
		maxChunkBytes > transport.DefaultChunkBytes {
		return nil, ErrAgentInventoryUnavailable
	}
	return &AgentCollector{
		dispatcher:     dispatcher,
		repository:     repository,
		newID:          newID,
		now:            now,
		commandTimeout: commandTimeout,
		maxChunkBytes:  maxChunkBytes,
		retryDelay:     defaultAgentInventoryRetryDelay,
	}, nil
}

var _ inventorybiz.Collector = (*AgentCollector)(nil)

func (c *AgentCollector) Synchronize(
	ctx context.Context,
	organizationID, managedHostID, runtimeTargetID string,
) error {
	observationID, err := c.newID()
	if err != nil {
		return fmt.Errorf("%w: generate observation ID", ErrAgentInventoryUnavailable)
	}
	startedAt := c.now().UTC()
	request := agentprotocol.RuntimeInventoryCommand{
		RuntimeTargetID: runtimeTargetID,
		ObservationID:   observationID,
		MaxChunkBytes:   c.maxChunkBytes,
	}
	result, err := c.dispatch(
		ctx,
		managedHostID,
		agentprotocol.AgentCommandInventoryPrepare,
		request,
	)
	if err != nil {
		return err
	}
	manifest := result.Inventory.Manifest
	snapshotDeadline := startedAt.Add(
		time.Duration(manifest.RetentionSeconds) * time.Second,
	)
	defer c.releaseSnapshot(managedHostID, request)

	observation, err := inventorybiz.NewObservation(
		observationID,
		organizationID,
		managedHostID,
		runtimeTargetID,
		manifest.ExpectedChunks,
		manifest.ExpectedResources,
		startedAt,
	)
	if err != nil {
		return fmt.Errorf("%w: invalid manifest", ErrAgentInventoryUnavailable)
	}
	if err := c.repository.Begin(ctx, observation); err != nil {
		return err
	}
	for index := 0; index < manifest.ExpectedChunks; index++ {
		if !c.now().UTC().Before(snapshotDeadline) {
			return fmt.Errorf(
				"%w: snapshot retention elapsed",
				ErrAgentInventoryUnavailable,
			)
		}
		request.ChunkIndex = index
		result, err := c.dispatch(
			ctx,
			managedHostID,
			agentprotocol.AgentCommandInventoryChunk,
			request,
		)
		if err != nil {
			return err
		}
		if err := c.validateObservedTimes(result.Inventory.Chunk.Resources); err != nil {
			return err
		}
		resources, err := ProjectResources(
			observation,
			result.Inventory.Chunk.Resources,
		)
		if err != nil {
			return err
		}
		chunk, err := inventorybiz.NewChunk(observation, index, resources)
		if err != nil {
			return err
		}
		if err := c.repository.Append(ctx, chunk); err != nil {
			return err
		}
	}
	completedAt := c.now().UTC()
	if err := c.repository.Complete(
		ctx,
		observation.ID,
		observation.RuntimeTargetID,
		completedAt,
	); err != nil {
		return err
	}
	return c.recordSnapshotWindowEvents(
		ctx,
		organizationID,
		runtimeTargetID,
		manifest.Events,
		completedAt,
	)
}

func (c *AgentCollector) recordSnapshotWindowEvents(
	ctx context.Context,
	organizationID, runtimeTargetID string,
	events []transport.Event,
	receivedAt time.Time,
) error {
	if c.eventHints == nil {
		return nil
	}
	for _, event := range events {
		hint, err := inventorybiz.NewEventHint(
			organizationID,
			runtimeTargetID,
			inventorybiz.Kind(event.Kind),
			event.RuntimeID,
			inventorybiz.EventAction(event.Action),
			event.OccurredAt,
			receivedAt,
		)
		if err != nil {
			return fmt.Errorf("%w: invalid event hint", ErrAgentInventoryUnavailable)
		}
		if err := c.eventHints.RecordEventHint(ctx, hint); err != nil {
			return err
		}
	}
	return nil
}

func (c *AgentCollector) dispatch(
	ctx context.Context,
	managedHostID string,
	kind agentprotocol.AgentCommandKind,
	inventory agentprotocol.RuntimeInventoryCommand,
) (agentprotocol.AgentCommandResult, error) {
	deadline := c.now().UTC().Add(c.commandTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok &&
		contextDeadline.Before(deadline) {
		deadline = contextDeadline.UTC()
	}
	dispatchContext, cancel := context.WithTimeout(ctx, c.commandTimeout)
	defer cancel()
	for {
		commandID, err := c.newID()
		if err != nil {
			return agentprotocol.AgentCommandResult{},
				fmt.Errorf("%w: generate command ID", ErrAgentInventoryUnavailable)
		}
		command := biz.AgentCommand{
			ID:        commandID,
			Kind:      kind,
			Deadline:  deadline,
			Inventory: &inventory,
		}
		result, err := c.dispatcher.Dispatch(
			dispatchContext,
			managedHostID,
			command,
		)
		if err != nil {
			if transientInventoryDispatchError(err) &&
				waitForInventoryRetry(dispatchContext, c.retryDelay) {
				continue
			}
			return agentprotocol.AgentCommandResult{},
				c.dispatchError(dispatchContext, err)
		}
		if err := result.Validate(command); err != nil {
			return agentprotocol.AgentCommandResult{},
				fmt.Errorf("%w: invalid result", ErrAgentInventoryUnavailable)
		}
		if result.Status != agentprotocol.AgentCommandSucceeded {
			return agentprotocol.AgentCommandResult{},
				fmt.Errorf(
					"%w: %s",
					ErrAgentInventoryUnavailable,
					result.ErrorCode,
				)
		}
		return result, nil
	}
}

func transientInventoryDispatchError(err error) bool {
	return errors.Is(err, biz.ErrAgentNotConnected) ||
		errors.Is(err, biz.ErrAgentDisconnected) ||
		errors.Is(err, biz.ErrAgentBackpressure)
}

func waitForInventoryRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *AgentCollector) dispatchError(ctx context.Context, err error) error {
	return agentInventoryDispatchError(ctx, err)
}

func (c *AgentCollector) releaseSnapshot(
	managedHostID string,
	request agentprotocol.RuntimeInventoryCommand,
) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		min(c.commandTimeout, 10*time.Second),
	)
	defer cancel()
	request.MaxChunkBytes = 0
	request.ChunkIndex = 0
	_, _ = c.dispatch(
		ctx,
		managedHostID,
		agentprotocol.AgentCommandInventoryRelease,
		request,
	)
}

func (c *AgentCollector) validateObservedTimes(
	resources []transport.Resource,
) error {
	if err := validateObservedTimesAt(resources, c.now().UTC()); err != nil {
		return fmt.Errorf(
			"%w: collector clock outside accepted window",
			ErrAgentInventoryUnavailable,
		)
	}
	return nil
}
