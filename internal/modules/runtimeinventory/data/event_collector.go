package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/adapters/dockerengine"
	"github.com/owndock/owndock/internal/adapters/dockerinventory"
	managedhostbiz "github.com/owndock/owndock/internal/modules/managedhost/biz"
	inventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

var ErrInvalidEventCollector = errors.New(
	"runtime inventory event collector is invalid",
)

type DirectEventCollector struct {
	credentials DirectCredentialResolver
	repository  inventorybiz.EventHintRepository
	wait        time.Duration
	now         func() time.Time
	openEngine  DirectEngineFactory
}

func NewDirectEventCollector(
	credentials DirectCredentialResolver,
	repository inventorybiz.EventHintRepository,
	wait time.Duration,
	now func() time.Time,
) (*DirectEventCollector, error) {
	if credentials == nil || repository == nil || wait <= 0 ||
		wait > 10*time.Second || now == nil {
		return nil, ErrInvalidEventCollector
	}
	return &DirectEventCollector{
		credentials: credentials,
		repository:  repository,
		wait:        wait,
		now:         now,
		openEngine: func(
			connection runtimeaccess.Connection,
			credential dockerengine.TLSCredential,
		) (DirectEngine, error) {
			return dockerengine.NewTLS(connection, credential)
		},
	}, nil
}

func (c *DirectEventCollector) CollectEvents(
	ctx context.Context,
	target inventorybiz.Target,
	cursor time.Time,
) (time.Time, error) {
	if err := target.Validate(); err != nil ||
		target.Connection.Mode != runtimeaccess.ModeDirectDocker {
		return cursor, inventorybiz.ErrInvalidTarget
	}
	credential, err := c.credentials.ResolveDirectCredential(ctx, target.Connection)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return cursor, contextError
		}
		return cursor, ErrDirectCredentialUnavailable
	}
	defer clearDirectCredential(&credential)
	engine, err := c.openEngine(target.Connection, credential)
	if err != nil {
		return cursor, fmt.Errorf(
			"%w: create Docker event client",
			ErrDirectInventoryUnavailable,
		)
	}
	defer func() { _ = engine.Close() }()

	pollContext, cancel := context.WithTimeout(ctx, c.wait)
	batch, readErr := dockerinventory.NewEventReader(engine).ReadSince(
		pollContext,
		cursor,
		transport.MaxEventsPerWindow,
	)
	cancel()
	if contextError := ctx.Err(); contextError != nil {
		return cursor, contextError
	}
	if readErr != nil {
		return cursor, fmt.Errorf(
			"%w: read Docker event stream",
			ErrDirectInventoryUnavailable,
		)
	}
	if err := recordTransportEvents(
		ctx,
		c.repository,
		target.OrganizationID,
		target.RuntimeTargetID,
		batch.Events,
		c.now().UTC(),
	); err != nil {
		return cursor, err
	}
	return batch.CursorAt(cursor), nil
}

type AgentEventCollector struct {
	dispatcher     managedhostbiz.AgentCommandDispatcher
	repository     inventorybiz.EventHintRepository
	newID          func() (string, error)
	now            func() time.Time
	commandTimeout time.Duration
	waitSeconds    int
	retryDelay     time.Duration
}

func NewAgentEventCollector(
	dispatcher managedhostbiz.AgentCommandDispatcher,
	repository inventorybiz.EventHintRepository,
	newID func() (string, error),
	now func() time.Time,
	commandTimeout, wait time.Duration,
) (*AgentEventCollector, error) {
	if dispatcher == nil || repository == nil || newID == nil || now == nil ||
		commandTimeout <= 0 || commandTimeout > time.Minute ||
		wait < time.Second || wait > 10*time.Second || wait%time.Second != 0 ||
		wait >= commandTimeout {
		return nil, ErrInvalidEventCollector
	}
	return &AgentEventCollector{
		dispatcher: dispatcher, repository: repository, newID: newID, now: now,
		commandTimeout: commandTimeout,
		waitSeconds:    int(wait / time.Second),
		retryDelay:     defaultAgentInventoryRetryDelay,
	}, nil
}

func (c *AgentEventCollector) CollectEvents(
	ctx context.Context,
	target inventorybiz.Target,
	cursor time.Time,
) (time.Time, error) {
	if err := target.Validate(); err != nil ||
		target.Connection.Mode != runtimeaccess.ModeAgent {
		return cursor, inventorybiz.ErrInvalidTarget
	}
	result, err := c.dispatch(ctx, target.ManagedHostID, agentprotocol.RuntimeInventoryCommand{
		RuntimeTargetID:  target.RuntimeTargetID,
		EventSince:       cursor.UTC(),
		EventWaitSeconds: c.waitSeconds,
	})
	if err != nil {
		return cursor, err
	}
	batch := result.Inventory.Events
	if err := recordTransportEvents(
		ctx,
		c.repository,
		target.OrganizationID,
		target.RuntimeTargetID,
		batch.Events,
		c.now().UTC(),
	); err != nil {
		return cursor, err
	}
	return batch.CursorAt(cursor), nil
}

func (c *AgentEventCollector) dispatch(
	ctx context.Context,
	managedHostID string,
	inventory agentprotocol.RuntimeInventoryCommand,
) (agentprotocol.AgentCommandResult, error) {
	deadline := c.now().UTC().Add(c.commandTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline.UTC()
	}
	dispatchContext, cancel := context.WithTimeout(ctx, c.commandTimeout)
	defer cancel()
	for {
		commandID, err := c.newID()
		if err != nil {
			return agentprotocol.AgentCommandResult{}, fmt.Errorf(
				"%w: generate event command ID",
				ErrAgentInventoryUnavailable,
			)
		}
		command := managedhostbiz.AgentCommand{
			ID: commandID, Kind: agentprotocol.AgentCommandInventoryEvents,
			Deadline: deadline, Inventory: &inventory,
		}
		result, err := c.dispatcher.Dispatch(dispatchContext, managedHostID, command)
		if err != nil {
			if transientInventoryDispatchError(err) &&
				waitForInventoryRetry(dispatchContext, c.retryDelay) {
				continue
			}
			return agentprotocol.AgentCommandResult{}, agentInventoryDispatchError(
				dispatchContext,
				err,
			)
		}
		if err := result.Validate(command); err != nil {
			return agentprotocol.AgentCommandResult{}, fmt.Errorf(
				"%w: invalid event result",
				ErrAgentInventoryUnavailable,
			)
		}
		if result.Status != agentprotocol.AgentCommandSucceeded {
			return agentprotocol.AgentCommandResult{}, fmt.Errorf(
				"%w: %s",
				ErrAgentInventoryUnavailable,
				result.ErrorCode,
			)
		}
		return result, nil
	}
}

func recordTransportEvents(
	ctx context.Context,
	repository inventorybiz.EventHintRepository,
	organizationID, runtimeTargetID string,
	events []transport.Event,
	receivedAt time.Time,
) error {
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
			return fmt.Errorf("project Docker event: %w", err)
		}
		if err := repository.RecordEventHint(ctx, hint); err != nil {
			return err
		}
	}
	return nil
}

func agentInventoryDispatchError(ctx context.Context, err error) error {
	if contextError := ctx.Err(); contextError != nil {
		return contextError
	}
	switch {
	case errors.Is(err, managedhostbiz.ErrAgentNotConnected),
		errors.Is(err, managedhostbiz.ErrAgentDisconnected),
		errors.Is(err, managedhostbiz.ErrAgentCommandExpired),
		errors.Is(err, managedhostbiz.ErrAgentBackpressure),
		errors.Is(err, managedhostbiz.ErrAgentCapabilityUnavailable),
		errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: Agent unavailable", ErrAgentInventoryUnavailable)
	default:
		return fmt.Errorf("%w: command failed", ErrAgentInventoryUnavailable)
	}
}

var (
	_ inventorybiz.EventCollector = (*DirectEventCollector)(nil)
	_ inventorybiz.EventCollector = (*AgentEventCollector)(nil)
)
