package biz

import (
	"context"
	"time"
)

// BuildQueueRepository is the internal execution boundary used by the
// dedicated Build Worker. Browser and Webhook handlers must not call it.
type BuildQueueRepository interface {
	ClaimNextBuild(context.Context, BuildClaim) (Build, bool, error)
	SaveClaimedBuild(context.Context, Build, uint64, string, uint64, time.Time) (Build, error)
	RenewBuildLease(context.Context, string, string, uint64, uint64, time.Time, time.Time) (Build, error)
	ValidateBuildFence(context.Context, string, string, uint64, time.Time) error
}
