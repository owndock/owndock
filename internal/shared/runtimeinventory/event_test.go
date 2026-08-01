package runtimeinventory

import (
	"errors"
	"testing"
	"time"
)

func TestEventValidationExcludesArbitraryActionsAndMissingIdentity(t *testing.T) {
	event := Event{
		Kind: KindContainer, RuntimeID: "container-1",
		Action: EventActionDestroy, OccurredAt: time.Unix(100, 0).UTC(),
	}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	event.Action = "exec_start: print-secret"
	if err := event.Validate(); !errors.Is(err, ErrInvalidResource) {
		t.Fatalf("unsafe action error = %v", err)
	}
}

func TestEventBatchCursorUsesOnlyReceivedDockerTimestamps(t *testing.T) {
	previous := time.Unix(100, 0).UTC()
	batch := EventBatch{Events: []Event{
		{Kind: KindContainer, RuntimeID: "container-1", Action: EventActionStart,
			OccurredAt: previous.Add(2 * time.Second)},
		{Kind: KindContainer, RuntimeID: "container-2", Action: EventActionStop,
			OccurredAt: previous.Add(time.Second)},
	}}
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
	if cursor := batch.CursorAt(previous); !cursor.Equal(previous.Add(2 * time.Second)) {
		t.Fatalf("cursor = %v", cursor)
	}
	if cursor := (EventBatch{}).CursorAt(previous); !cursor.Equal(previous) {
		t.Fatalf("empty cursor = %v", cursor)
	}
}
