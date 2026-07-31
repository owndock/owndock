package data

import (
	"context"
	"fmt"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
)

type CollectorRouter struct {
	collectors map[runtimeaccess.Mode]biz.Collector
}

func NewCollectorRouter(
	collectors map[runtimeaccess.Mode]biz.Collector,
) *CollectorRouter {
	copyOfCollectors := make(map[runtimeaccess.Mode]biz.Collector, len(collectors))
	for mode, collector := range collectors {
		if mode.Valid() && collector != nil {
			copyOfCollectors[mode] = collector
		}
	}
	return &CollectorRouter{collectors: copyOfCollectors}
}

func (r *CollectorRouter) Collect(ctx context.Context, target biz.Target) error {
	if err := target.Validate(); err != nil {
		return err
	}
	collector := r.collectors[target.Connection.Mode]
	if collector == nil {
		return fmt.Errorf(
			"runtime inventory collector for mode %q is unavailable",
			target.Connection.Mode,
		)
	}
	return collector.Collect(ctx, target)
}

var _ biz.Collector = (*CollectorRouter)(nil)
