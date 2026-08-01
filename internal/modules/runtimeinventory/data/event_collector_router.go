package data

import (
	"context"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type EventCollectorRouter struct {
	collectors map[runtimeaccess.Mode]biz.EventCollector
}

func NewEventCollectorRouter(
	collectors map[runtimeaccess.Mode]biz.EventCollector,
) *EventCollectorRouter {
	copyOfCollectors := make(map[runtimeaccess.Mode]biz.EventCollector, len(collectors))
	for mode, collector := range collectors {
		if mode.Valid() && collector != nil {
			copyOfCollectors[mode] = collector
		}
	}
	return &EventCollectorRouter{collectors: copyOfCollectors}
}

func (r *EventCollectorRouter) CollectEvents(
	ctx context.Context,
	target biz.Target,
	cursor time.Time,
) (time.Time, error) {
	if err := target.Validate(); err != nil {
		return cursor, err
	}
	collector := r.collectors[target.Connection.Mode]
	if collector == nil {
		return cursor, fmt.Errorf(
			"runtime inventory event collector for mode %q is unavailable",
			target.Connection.Mode,
		)
	}
	return collector.CollectEvents(ctx, target, cursor)
}

var _ biz.EventCollector = (*EventCollectorRouter)(nil)
