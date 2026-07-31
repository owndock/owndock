package dockerinventory

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	inventory "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type eventEngineStub struct {
	options  client.EventsListOptions
	messages []events.Message
	err      error
}

func (s *eventEngineStub) Events(
	_ context.Context,
	options client.EventsListOptions,
) client.EventsResult {
	s.options = options
	messages := make(chan events.Message, len(s.messages))
	errorsChannel := make(chan error, 1)
	for _, message := range s.messages {
		messages <- message
	}
	close(messages)
	if s.err != nil {
		errorsChannel <- s.err
	} else {
		errorsChannel <- io.EOF
	}
	close(errorsChannel)
	return client.EventsResult{Messages: messages, Err: errorsChannel}
}

func TestEventReaderProjectsOnlyBoundedSafeRuntimeEvents(t *testing.T) {
	since := time.Unix(100, 0).UTC()
	until := since.Add(time.Second)
	engine := &eventEngineStub{messages: []events.Message{
		{
			Type: events.ContainerEventType, Action: events.ActionDestroy,
			Actor: events.Actor{ID: "container-1", Attributes: map[string]string{
				"secret": "must-not-cross-adapter",
			}},
			TimeNano: since.Add(100 * time.Millisecond).UnixNano(),
		},
		{
			Type:   events.ContainerEventType,
			Action: events.Action("exec_start: cat /run/secrets/token"),
			Actor:  events.Actor{ID: "container-1"}, Time: since.Unix(),
		},
		{
			Type: events.NetworkEventType, Action: events.ActionConnect,
			Actor: events.Actor{ID: "network-1"}, Time: since.Unix(),
		},
	}}
	batch, err := NewEventReader(engine).ReadWindow(
		context.Background(), since, until, inventory.MaxEventsPerWindow,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 2 || batch.Truncated ||
		batch.Events[0].RuntimeID != "container-1" ||
		batch.Events[0].Action != inventory.EventActionDestroy ||
		batch.Events[1].Kind != inventory.KindNetwork {
		t.Fatalf("event batch = %#v", batch)
	}
	if engine.options.Since != since.Format(time.RFC3339Nano) ||
		engine.options.Until != until.Format(time.RFC3339Nano) ||
		!engine.options.Filters["type"]["container"] ||
		engine.options.Filters["type"]["daemon"] {
		t.Fatalf("event options = %#v", engine.options)
	}
}

func TestEventReaderBoundsAndFailsClosedOnStreamError(t *testing.T) {
	since := time.Unix(100, 0).UTC()
	engine := &eventEngineStub{messages: []events.Message{
		{Type: events.VolumeEventType, Action: events.ActionMount,
			Actor: events.Actor{ID: "volume-1"}, Time: since.Unix()},
		{Type: events.VolumeEventType, Action: events.ActionUnmount,
			Actor: events.Actor{ID: "volume-1"}, Time: since.Unix()},
	}}
	batch, err := NewEventReader(engine).ReadWindow(
		context.Background(), since, since.Add(time.Second), 1,
	)
	if err != nil || len(batch.Events) != 1 || !batch.Truncated {
		t.Fatalf("bounded event batch = %#v, %v", batch, err)
	}
	engine.messages = nil
	engine.err = errors.New("daemon disconnected")
	if _, err := NewEventReader(engine).ReadWindow(
		context.Background(), since, since.Add(time.Second), 1,
	); err == nil {
		t.Fatal("event stream error = nil")
	}
}
