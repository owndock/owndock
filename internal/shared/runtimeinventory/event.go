package runtimeinventory

import "time"

// Keep the complete Agent manifest comfortably below the default 64 KiB
// control-frame limit even when runtime IDs approach their maximum length.
const MaxEventsPerWindow = 64

type EventAction string

const (
	EventActionCreate     EventAction = "create"
	EventActionUpdate     EventAction = "update"
	EventActionStart      EventAction = "start"
	EventActionStop       EventAction = "stop"
	EventActionDestroy    EventAction = "destroy"
	EventActionConnect    EventAction = "connect"
	EventActionDisconnect EventAction = "disconnect"
	EventActionMount      EventAction = "mount"
	EventActionUnmount    EventAction = "unmount"
	EventActionDelete     EventAction = "delete"
)

func (a EventAction) Valid() bool {
	switch a {
	case EventActionCreate, EventActionUpdate, EventActionStart, EventActionStop,
		EventActionDestroy, EventActionConnect, EventActionDisconnect,
		EventActionMount, EventActionUnmount, EventActionDelete:
		return true
	default:
		return false
	}
}

// Event is the secret-safe subset of one Docker Engine event. Actor
// attributes are deliberately excluded because they may contain arbitrary
// labels, image metadata or command details.
type Event struct {
	Kind       Kind        `json:"kind"`
	RuntimeID  string      `json:"runtime_id"`
	Action     EventAction `json:"action"`
	OccurredAt time.Time   `json:"occurred_at"`
}

func (e Event) Validate() error {
	if !e.Kind.Valid() || !validText(e.RuntimeID, 512) ||
		!e.Action.Valid() || e.OccurredAt.IsZero() {
		return ErrInvalidResource
	}
	return nil
}

type EventBatch struct {
	Events    []Event
	Truncated bool
}
