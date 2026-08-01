package dockerinventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	inventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

var ErrInvalidEventWindow = errors.New("Docker runtime inventory event window is invalid")

type EventEngine interface {
	Events(context.Context, client.EventsListOptions) client.EventsResult
}

type EventReader struct {
	engine EventEngine
}

func NewEventReader(engine EventEngine) *EventReader {
	return &EventReader{engine: engine}
}

// ReadWindow reads a finite historical window. Reaching the bound is treated
// as truncation, which is enough to request another full observation without
// retaining an unbounded event stream.
func (r *EventReader) ReadWindow(
	ctx context.Context,
	since, until time.Time,
	maximum int,
) (inventory.EventBatch, error) {
	if r == nil || r.engine == nil || since.IsZero() || until.IsZero() ||
		!until.After(since) || maximum < 1 || maximum > inventory.MaxEventsPerWindow {
		return inventory.EventBatch{}, ErrInvalidEventWindow
	}
	streamContext, cancel := context.WithCancel(ctx)
	defer cancel()
	filters := make(client.Filters).Add(
		"type", "container", "image", "network", "volume",
	)
	result := r.engine.Events(streamContext, client.EventsListOptions{
		Since:   since.UTC().Format(time.RFC3339Nano),
		Until:   until.UTC().Format(time.RFC3339Nano),
		Filters: filters,
	})
	batch := inventory.EventBatch{Events: make([]inventory.Event, 0, maximum)}
	messages := result.Messages
	errorsChannel := result.Err
	for messages != nil || errorsChannel != nil {
		select {
		case <-ctx.Done():
			return inventory.EventBatch{}, ctx.Err()
		case message, open := <-messages:
			if !open {
				messages = nil
				continue
			}
			event, ok := projectDockerEvent(message)
			if !ok {
				continue
			}
			batch.Events = append(batch.Events, event)
			if len(batch.Events) == maximum {
				batch.Truncated = true
				cancel()
				return batch, nil
			}
		case streamErr, open := <-errorsChannel:
			if !open {
				errorsChannel = nil
				continue
			}
			if streamErr != nil && !errors.Is(streamErr, io.EOF) {
				return inventory.EventBatch{}, fmt.Errorf("read Docker events: %w", streamErr)
			}
			errorsChannel = nil
		}
	}
	return batch, nil
}

// ReadSince consumes a live stream until ctx ends. Context cancellation is a
// successful bounded poll, not an Engine failure. Since is a Docker-owned
// timestamp from a previously received event and may be zero for first use.
func (r *EventReader) ReadSince(
	ctx context.Context,
	since time.Time,
	maximum int,
) (inventory.EventBatch, error) {
	if r == nil || r.engine == nil || maximum < 1 ||
		maximum > inventory.MaxEventsPerWindow {
		return inventory.EventBatch{}, ErrInvalidEventWindow
	}
	filters := make(client.Filters).Add(
		"type", "container", "image", "network", "volume",
	)
	options := client.EventsListOptions{Filters: filters}
	if !since.IsZero() {
		options.Since = since.UTC().Format(time.RFC3339Nano)
	}
	result := r.engine.Events(ctx, options)
	batch := inventory.EventBatch{Events: make([]inventory.Event, 0, maximum)}
	messages := result.Messages
	errorsChannel := result.Err
	for messages != nil || errorsChannel != nil {
		select {
		case <-ctx.Done():
			return batch, nil
		case message, open := <-messages:
			if !open {
				messages = nil
				continue
			}
			event, ok := projectDockerEvent(message)
			if !ok {
				continue
			}
			batch.Events = append(batch.Events, event)
			if len(batch.Events) == maximum {
				batch.Truncated = true
				return batch, nil
			}
		case streamErr, open := <-errorsChannel:
			if !open {
				errorsChannel = nil
				continue
			}
			if streamErr != nil {
				if ctx.Err() != nil {
					return batch, nil
				}
				return inventory.EventBatch{}, fmt.Errorf(
					"read Docker events: %w",
					streamErr,
				)
			}
			errorsChannel = nil
		}
	}
	if ctx.Err() != nil {
		return batch, nil
	}
	return inventory.EventBatch{}, fmt.Errorf(
		"read Docker events: live stream closed",
	)
}

func projectDockerEvent(message events.Message) (inventory.Event, bool) {
	if message.TimeNano <= 0 && message.Time <= 0 {
		return inventory.Event{}, false
	}
	kind := projectEventKind(message.Type)
	action := projectEventAction(message.Action)
	occurredAt := time.Unix(message.Time, 0).UTC()
	if message.TimeNano > 0 {
		occurredAt = time.Unix(0, message.TimeNano).UTC()
	}
	event := inventory.Event{
		Kind: kind, RuntimeID: strings.TrimSpace(message.Actor.ID),
		Action: action, OccurredAt: occurredAt,
	}
	return event, event.Validate() == nil
}

func projectEventKind(value events.Type) inventory.Kind {
	switch value {
	case events.ContainerEventType:
		return inventory.KindContainer
	case events.ImageEventType:
		return inventory.KindImage
	case events.NetworkEventType:
		return inventory.KindNetwork
	case events.VolumeEventType:
		return inventory.KindVolume
	default:
		return ""
	}
}

func projectEventAction(value events.Action) inventory.EventAction {
	action := string(value)
	switch {
	case value == events.ActionCreate || value == events.ActionLoad ||
		value == events.ActionPull:
		return inventory.EventActionCreate
	case value == events.ActionStart || value == events.ActionRestart ||
		value == events.ActionUnPause:
		return inventory.EventActionStart
	case value == events.ActionStop || value == events.ActionDie ||
		value == events.ActionKill || value == events.ActionOOM ||
		value == events.ActionPause:
		return inventory.EventActionStop
	case value == events.ActionDestroy || value == events.ActionRemove:
		return inventory.EventActionDestroy
	case value == events.ActionDelete || value == events.ActionPrune ||
		value == events.ActionUnTag:
		return inventory.EventActionDelete
	case value == events.ActionConnect:
		return inventory.EventActionConnect
	case value == events.ActionDisconnect:
		return inventory.EventActionDisconnect
	case value == events.ActionMount:
		return inventory.EventActionMount
	case value == events.ActionUnmount:
		return inventory.EventActionUnmount
	case value == events.ActionUpdate || value == events.ActionRename ||
		value == events.ActionTag || value == events.ActionPush ||
		strings.HasPrefix(action, string(events.ActionHealthStatus)):
		return inventory.EventActionUpdate
	default:
		return ""
	}
}

var _ EventEngine = (*client.Client)(nil)
