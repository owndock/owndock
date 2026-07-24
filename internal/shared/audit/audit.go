package audit

import (
	"context"
	"time"
)

type Event struct {
	ID             string
	OrganizationID string
	ProjectID      string
	ActorID        string
	Action         string
	ResourceType   string
	ResourceID     string
	RequestID      string
	CreatedAt      time.Time
}

type Recorder interface {
	Record(context.Context, Event) error
}

type Reader interface {
	List(context.Context, string, string, int64) ([]Event, error)
}
