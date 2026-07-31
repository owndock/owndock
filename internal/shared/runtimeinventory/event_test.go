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
