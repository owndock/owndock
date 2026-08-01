package ingress

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const mongoGuardMaximumRetries = 128

type rateDocument struct {
	ID              string    `bson:"_id"`
	WindowStartedAt time.Time `bson:"window_started_at"`
	Requests        int       `bson:"requests"`
	ExpiresAt       time.Time `bson:"expires_at"`
	Revision        uint64    `bson:"revision"`
}

type MongoGuard struct {
	rates *mongo.Collection
}

func NewMongoGuard(database *mongo.Database) *MongoGuard {
	return &MongoGuard{rates: database.Collection("ingress_rate_limits")}
}

func (g *MongoGuard) Reserve(
	ctx context.Context, key string, now time.Time, limit int, window time.Duration,
) (bool, time.Time, error) {
	if g == nil || g.rates == nil || len(key) != 64 || limit < 1 || window <= 0 {
		return false, time.Time{}, ErrInvalidPolicy
	}
	now = now.UTC()
	for retry := 0; retry < mongoGuardMaximumRetries; retry++ {
		var current rateDocument
		err := g.rates.FindOne(ctx, bson.D{{Key: "_id", Value: key}}).Decode(&current)
		if errors.Is(err, mongo.ErrNoDocuments) {
			document := rateDocument{
				ID: key, WindowStartedAt: now, Requests: 1,
				ExpiresAt: now.Add(2 * window), Revision: 1,
			}
			if _, insertErr := g.rates.InsertOne(ctx, document); insertErr == nil {
				return true, time.Time{}, nil
			} else if mongo.IsDuplicateKeyError(insertErr) {
				continue
			} else {
				return false, time.Time{}, fmt.Errorf("create ingress rate state: %w", insertErr)
			}
		}
		if err != nil {
			return false, time.Time{}, fmt.Errorf("find ingress rate state: %w", err)
		}
		windowEnd := current.WindowStartedAt.Add(window)
		if !windowEnd.After(now) {
			current.WindowStartedAt, current.Requests = now, 0
			windowEnd = now.Add(window)
		}
		if current.Requests >= limit {
			return false, windowEnd, nil
		}
		next := current
		next.Requests++
		next.Revision++
		next.ExpiresAt = next.WindowStartedAt.Add(2 * window)
		result, replaceErr := g.rates.ReplaceOne(ctx, bson.D{
			{Key: "_id", Value: key}, {Key: "revision", Value: current.Revision},
		}, next)
		if replaceErr != nil {
			return false, time.Time{}, fmt.Errorf("update ingress rate state: %w", replaceErr)
		}
		if result.MatchedCount == 1 {
			return true, time.Time{}, nil
		}
	}
	// Under extreme contention, fail closed for the rest of a window instead
	// of bypassing a protection that is expected to work across Server nodes.
	return false, now.Add(window), nil
}

var _ Guard = (*MongoGuard)(nil)
