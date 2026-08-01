package data

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"github.com/owndock/owndock/internal/adapters/dockerengine"
	inventorybiz "github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
)

type directCredentialResolverStub struct {
	credential dockerengine.TLSCredential
}

func (r directCredentialResolverStub) ResolveDirectCredential(
	context.Context,
	runtimeaccess.Connection,
) (dockerengine.TLSCredential, error) {
	return r.credential, nil
}

type directInventoryEngineStub struct {
	closed       bool
	events       []events.Message
	eventOptions client.EventsListOptions
}

func (e *directInventoryEngineStub) Events(
	ctx context.Context,
	options client.EventsListOptions,
) client.EventsResult {
	e.eventOptions = options
	messages := make(chan events.Message, len(e.events))
	errorsChannel := make(chan error, 1)
	for _, item := range e.events {
		messages <- item
	}
	close(messages)
	if options.Until == "" {
		go func() {
			<-ctx.Done()
			errorsChannel <- ctx.Err()
			close(errorsChannel)
		}()
	} else {
		errorsChannel <- io.EOF
		close(errorsChannel)
	}
	return client.EventsResult{Messages: messages, Err: errorsChannel}
}

func (*directInventoryEngineStub) ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error) {
	return client.ContainerListResult{}, nil
}

type eventHintRepositoryStub struct {
	hints []inventorybiz.EventHint
	err   error
}

func (r *eventHintRepositoryStub) RecordEventHint(
	_ context.Context,
	hint inventorybiz.EventHint,
) error {
	if r.err != nil {
		return r.err
	}
	r.hints = append(r.hints, hint)
	return nil
}
func (*directInventoryEngineStub) ImageList(context.Context, client.ImageListOptions) (client.ImageListResult, error) {
	return client.ImageListResult{}, nil
}

func TestDirectTargetCollectorSchedulesFullReconcileForSnapshotWindowEvent(
	t *testing.T,
) {
	base := time.Unix(5000, 0).UTC()
	times := []time.Time{base, base, base, base, base.Add(time.Second)}
	now := func() time.Time {
		value := times[0]
		times = times[1:]
		return value
	}
	engine := &directInventoryEngineStub{events: []events.Message{{
		Type: events.ContainerEventType, Action: events.ActionDestroy,
		Actor:    events.Actor{ID: "container-removed-during-snapshot"},
		TimeNano: base.Add(500 * time.Millisecond).UnixNano(),
	}}}
	hints := &eventHintRepositoryStub{}
	collector, err := NewDirectTargetCollector(
		directCredentialResolverStub{credential: dockerengine.TLSCredential{
			CACertificate: []byte("ca"), ClientCertificate: []byte("certificate"),
			ClientKey: []byte("key"),
		}},
		&inventoryRepositoryStub{},
		func() (string, error) { return "observation-direct-event", nil },
		now,
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	collector.WithEventHints(hints)
	collector.openEngine = func(
		runtimeaccess.Connection,
		dockerengine.TLSCredential,
	) (DirectEngine, error) {
		return engine, nil
	}
	connection, err := runtimeaccess.NewDirectDocker(
		"host-1", "tcp://runtime.example:2376", "runtime.example", "secret://runtime-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Collect(t.Context(), inventorybiz.Target{
		OrganizationID: "organization-1", ProjectID: "project-1",
		ManagedHostID: "host-1", RuntimeTargetID: "target-1", Connection: connection,
	}); err != nil {
		t.Fatal(err)
	}
	if len(hints.hints) != 1 ||
		hints.hints[0].RuntimeID != "container-removed-during-snapshot" ||
		hints.hints[0].Action != inventorybiz.EventActionDestroy ||
		engine.eventOptions.Since != base.Format(time.RFC3339Nano) {
		t.Fatalf("event hints/options = %#v / %#v", hints.hints, engine.eventOptions)
	}
}
func (*directInventoryEngineStub) NetworkList(context.Context, client.NetworkListOptions) (client.NetworkListResult, error) {
	return client.NetworkListResult{}, nil
}
func (*directInventoryEngineStub) VolumeList(context.Context, client.VolumeListOptions) (client.VolumeListResult, error) {
	return client.VolumeListResult{}, nil
}
func (e *directInventoryEngineStub) Close() error {
	e.closed = true
	return nil
}

func TestDirectTargetCollectorKeepsCredentialEphemeral(t *testing.T) {
	now := time.Unix(4000, 0).UTC()
	ca := []byte("ca")
	certificate := []byte("certificate")
	key := []byte("private-key")
	engine := &directInventoryEngineStub{}
	repository := &inventoryRepositoryStub{}
	collector, err := NewDirectTargetCollector(
		directCredentialResolverStub{credential: dockerengine.TLSCredential{
			CACertificate: ca, ClientCertificate: certificate, ClientKey: key,
		}},
		repository,
		func() (string, error) { return "observation-direct-target-1", nil },
		func() time.Time { return now },
		transport.DefaultChunkBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	collector.openEngine = func(
		runtimeaccess.Connection,
		dockerengine.TLSCredential,
	) (DirectEngine, error) {
		return engine, nil
	}
	connection, err := runtimeaccess.NewDirectDocker(
		"host-1",
		"tcp://runtime.example:2376",
		"runtime.example",
		"secret://runtime-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	err = collector.Collect(t.Context(), inventorybiz.Target{
		OrganizationID:  "organization-1",
		ProjectID:       "project-1",
		ManagedHostID:   "host-1",
		RuntimeTargetID: "target-1",
		Connection:      connection,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !engine.closed || !repository.completed {
		t.Fatalf("engine closed / observation completed = %v / %v", engine.closed, repository.completed)
	}
	for name, value := range map[string][]byte{
		"CA": ca, "certificate": certificate, "key": key,
	} {
		for _, item := range value {
			if item != 0 {
				t.Fatalf("%s credential was not cleared", name)
			}
		}
	}
}

func TestDirectEventCollectorUsesPersistedCursorAndClearsCredential(t *testing.T) {
	cursor := time.Unix(8000, 0).UTC()
	eventAt := cursor.Add(2 * time.Second)
	ca := []byte("ca")
	certificate := []byte("certificate")
	key := []byte("private-key")
	engine := &directInventoryEngineStub{events: []events.Message{{
		Type:     events.ContainerEventType,
		Action:   events.ActionStart,
		Actor:    events.Actor{ID: "container-live"},
		TimeNano: eventAt.UnixNano(),
	}}}
	hints := &eventHintRepositoryStub{}
	collector, err := NewDirectEventCollector(
		directCredentialResolverStub{credential: dockerengine.TLSCredential{
			CACertificate: ca, ClientCertificate: certificate, ClientKey: key,
		}},
		hints,
		time.Millisecond,
		func() time.Time { return cursor.Add(time.Hour) },
	)
	if err != nil {
		t.Fatal(err)
	}
	collector.openEngine = func(
		runtimeaccess.Connection,
		dockerengine.TLSCredential,
	) (DirectEngine, error) {
		return engine, nil
	}
	connection, err := runtimeaccess.NewDirectDocker(
		"host-1", "tcp://runtime.example:2376", "runtime.example", "secret://runtime-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := collector.CollectEvents(t.Context(), inventorybiz.Target{
		OrganizationID: "organization-1", ProjectID: "project-1",
		ManagedHostID: "host-1", RuntimeTargetID: "target-1", Connection: connection,
	}, cursor)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(eventAt) || len(hints.hints) != 1 ||
		engine.eventOptions.Since != cursor.Format(time.RFC3339Nano) ||
		engine.eventOptions.Until != "" || !engine.closed {
		t.Fatalf(
			"cursor / hints / options / closed = %v / %#v / %#v / %v",
			got, hints.hints, engine.eventOptions, engine.closed,
		)
	}
	for name, value := range map[string][]byte{
		"CA": ca, "certificate": certificate, "key": key,
	} {
		for _, item := range value {
			if item != 0 {
				t.Fatalf("%s credential was not cleared", name)
			}
		}
	}
}
