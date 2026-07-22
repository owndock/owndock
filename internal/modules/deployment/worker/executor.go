package worker

import (
	"context"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
)

// NoopExecutor is the development adapter. It validates orchestration without
// requiring Docker, Kubernetes, credentials, or an external queue.
type NoopExecutor struct{}

func (NoopExecutor) Build(context.Context, biz.Deployment) error  { return nil }
func (NoopExecutor) Deploy(context.Context, biz.Deployment) error { return nil }
