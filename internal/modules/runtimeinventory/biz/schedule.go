package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

var (
	ErrInvalidTarget = errors.New("runtime inventory target is invalid")
	ErrLeaseLost     = errors.New("runtime inventory schedule lease was lost")
)

// Target is the minimum control-plane projection needed to collect one
// Runtime Target. It contains routing metadata and a credential reference, not
// secret material.
type Target struct {
	OrganizationID  string
	ProjectID       string
	ManagedHostID   string
	RuntimeTargetID string
	Connection      runtimeaccess.Connection
}

func (t Target) Validate() error {
	if !validID(t.OrganizationID) || !validID(t.ProjectID) ||
		!validID(t.ManagedHostID) || !validID(t.RuntimeTargetID) ||
		strings.TrimSpace(t.Connection.ManagedHostID) !=
			strings.TrimSpace(t.ManagedHostID) {
		return ErrInvalidTarget
	}
	if err := t.Connection.Validate(); err != nil {
		return ErrInvalidTarget
	}
	return nil
}

type Collector interface {
	Collect(context.Context, Target) error
}

type ScheduleLease struct {
	RuntimeTargetID string
	OwnerID         string
	Token           uint64
}

type ScheduleRepository interface {
	ListReadyTargets(context.Context, int, time.Time) ([]Target, error)
	TryAcquire(
		context.Context,
		Target,
		string,
		time.Time,
		time.Time,
	) (ScheduleLease, bool, error)
	Finish(
		context.Context,
		ScheduleLease,
		time.Time,
		time.Time,
		bool,
	) error
}

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

// EventHint is a deliberately small, secret-safe Docker Event summary. It is
// only a request for an earlier full reconciliation and is never authoritative
// evidence that a resource exists or has been deleted.
type EventHint struct {
	ID              string
	OrganizationID  string
	RuntimeTargetID string
	Kind            Kind
	RuntimeID       string
	Action          EventAction
	OccurredAt      time.Time
	ReceivedAt      time.Time
}

func NewEventHint(
	organizationID, runtimeTargetID string,
	kind Kind,
	runtimeID string,
	action EventAction,
	occurredAt, receivedAt time.Time,
) (EventHint, error) {
	hint := EventHint{
		OrganizationID:  strings.TrimSpace(organizationID),
		RuntimeTargetID: strings.TrimSpace(runtimeTargetID),
		Kind:            kind, RuntimeID: strings.TrimSpace(runtimeID), Action: action,
		OccurredAt: occurredAt.UTC(), ReceivedAt: receivedAt.UTC(),
	}
	hint.ID = eventHintID(hint)
	if err := hint.Validate(); err != nil {
		return EventHint{}, err
	}
	return hint, nil
}

func (h EventHint) Validate() error {
	if !validID(h.OrganizationID) || !validID(h.RuntimeTargetID) ||
		!h.Kind.Valid() || !validRuntimeID(h.RuntimeID) || !h.Action.Valid() ||
		h.OccurredAt.IsZero() || h.ReceivedAt.IsZero() || h.ID != eventHintID(h) {
		return ErrInvalidResource
	}
	return nil
}

func eventHintID(h EventHint) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"%s\x00%s\x00%s\x00%s\x00%s\x00%d",
		h.OrganizationID,
		h.RuntimeTargetID,
		h.Kind,
		h.RuntimeID,
		h.Action,
		h.OccurredAt.UTC().UnixNano(),
	)))
	return hex.EncodeToString(digest[:])
}

type EventHintRepository interface {
	RecordEventHint(context.Context, EventHint) error
}
