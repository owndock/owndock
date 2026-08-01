package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const buildTriggerGuardMaximumRetries = 32

type buildTriggerRateDocument struct {
	ID              string    `bson:"_id"`
	WindowStartedAt time.Time `bson:"window_started_at"`
	Attempts        int       `bson:"attempts"`
	ExpiresAt       time.Time `bson:"expires_at"`
	Revision        uint64    `bson:"revision"`
}

// ReserveBuildTrigger uses optimistic concurrency so every Server instance
// shares one admission counter through MongoDB.
func (r *MongoRepository) ReserveBuildTrigger(
	ctx context.Context,
	triggerID string,
	now time.Time,
	limit int,
	window time.Duration,
) (bool, time.Time, error) {
	return r.reserveBuildAdmission(ctx, "trigger:"+triggerID, now, limit, window)
}

// ReserveBuildWebhook shares one fixed-window counter across all Server
// instances for a Build Hook. The namespace prevents Hook and Trigger IDs from
// colliding in the common TTL collection.
func (r *MongoRepository) ReserveBuildWebhook(
	ctx context.Context,
	hookID string,
	now time.Time,
	limit int,
	window time.Duration,
) (bool, time.Time, error) {
	return r.reserveBuildAdmission(ctx, "webhook:"+hookID, now, limit, window)
}

func (r *MongoRepository) reserveBuildAdmission(
	ctx context.Context,
	admissionID string,
	now time.Time,
	limit int,
	window time.Duration,
) (bool, time.Time, error) {
	if admissionID == "trigger:" || admissionID == "webhook:" || limit < 1 || window <= 0 {
		return false, time.Time{}, biz.ErrBuildTriggerRateLimited
	}
	now = now.UTC()
	for retry := 0; retry < buildTriggerGuardMaximumRetries; retry++ {
		var current buildTriggerRateDocument
		err := r.triggerRates.FindOne(ctx, bson.D{{Key: "_id", Value: admissionID}}).Decode(&current)
		if errors.Is(err, mongo.ErrNoDocuments) {
			document := buildTriggerRateDocument{
				ID: admissionID, WindowStartedAt: now, Attempts: 1,
				ExpiresAt: now.Add(2 * window), Revision: 1,
			}
			if _, err := r.triggerRates.InsertOne(ctx, document); err == nil {
				return true, time.Time{}, nil
			} else if mongo.IsDuplicateKeyError(err) {
				continue
			} else {
				return false, time.Time{}, fmt.Errorf("create build trigger rate state: %w", err)
			}
		}
		if err != nil {
			return false, time.Time{}, fmt.Errorf("find build trigger rate state: %w", err)
		}
		windowEnd := current.WindowStartedAt.Add(window)
		if !windowEnd.After(now) {
			current.WindowStartedAt, current.Attempts = now, 0
			windowEnd = now.Add(window)
		}
		if current.Attempts >= limit {
			return false, windowEnd, nil
		}
		next := current
		next.Attempts++
		next.Revision++
		next.ExpiresAt = next.WindowStartedAt.Add(2 * window)
		result, err := r.triggerRates.ReplaceOne(ctx, bson.D{
			{Key: "_id", Value: admissionID}, {Key: "revision", Value: current.Revision},
		}, next)
		if err != nil {
			return false, time.Time{}, fmt.Errorf("update build trigger rate state: %w", err)
		}
		if result.MatchedCount == 1 {
			return true, time.Time{}, nil
		}
	}
	return false, now.Add(window), nil
}

var _ biz.BuildTriggerRateGuard = (*MongoRepository)(nil)
var _ biz.WebhookRateGuard = (*MongoRepository)(nil)
