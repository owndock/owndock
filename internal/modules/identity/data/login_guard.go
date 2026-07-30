package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/identity/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const loginGuardMaximumRetries = 32

type loginAttemptDocument struct {
	ID              string    `bson:"_id"`
	WindowStartedAt time.Time `bson:"window_started_at"`
	Attempts        int       `bson:"attempts"`
	BlockedUntil    time.Time `bson:"blocked_until,omitempty"`
	ExpiresAt       time.Time `bson:"expires_at"`
	Revision        uint64    `bson:"revision"`
}

func (r *MongoRepository) ReserveLoginAttempt(
	ctx context.Context,
	key string,
	now time.Time,
	limit int,
	window time.Duration,
) (bool, time.Time, error) {
	if len(key) != 64 || limit < 1 || window <= 0 {
		return false, time.Time{}, biz.ErrLoginRateLimited
	}
	now = now.UTC()
	for retry := 0; retry < loginGuardMaximumRetries; retry++ {
		var current loginAttemptDocument
		err := r.loginAttempts.FindOne(
			ctx,
			bson.D{{Key: "_id", Value: key}},
		).Decode(&current)
		if errors.Is(err, mongo.ErrNoDocuments) {
			document := loginAttemptDocument{
				ID:              key,
				WindowStartedAt: now,
				Attempts:        1,
				ExpiresAt:       now.Add(2 * window),
				Revision:        1,
			}
			if limit == 1 {
				document.BlockedUntil = now.Add(window)
				document.ExpiresAt = document.BlockedUntil.Add(window)
			}
			if _, err := r.loginAttempts.InsertOne(ctx, document); err == nil {
				return true, time.Time{}, nil
			} else if mongo.IsDuplicateKeyError(err) {
				continue
			} else {
				return false, time.Time{},
					fmt.Errorf("create login attempt: %w", err)
			}
		}
		if err != nil {
			return false, time.Time{},
				fmt.Errorf("find login attempt: %w", err)
		}
		if current.BlockedUntil.After(now) {
			return false, current.BlockedUntil, nil
		}

		next := current
		next.Revision++
		if !current.WindowStartedAt.After(now.Add(-window)) {
			next.WindowStartedAt = now
			next.Attempts = 1
			next.BlockedUntil = time.Time{}
		} else {
			next.Attempts++
		}
		next.ExpiresAt = next.WindowStartedAt.Add(2 * window)
		if next.Attempts >= limit {
			next.BlockedUntil = now.Add(window)
			next.ExpiresAt = next.BlockedUntil.Add(window)
		}
		result, err := r.loginAttempts.ReplaceOne(
			ctx,
			bson.D{
				{Key: "_id", Value: key},
				{Key: "revision", Value: current.Revision},
			},
			next,
		)
		if err != nil {
			return false, time.Time{},
				fmt.Errorf("update login attempt: %w", err)
		}
		if result.MatchedCount == 1 {
			return true, time.Time{}, nil
		}
	}
	// Extreme contention must not turn into an authentication bypass. Refuse
	// the attempt for one window; a later request can retry normally.
	return false, now.Add(window), nil
}

func (r *MongoRepository) ResetLoginAttempts(
	ctx context.Context,
	key string,
) error {
	if len(key) != 64 {
		return biz.ErrLoginRateLimited
	}
	if _, err := r.loginAttempts.DeleteOne(
		ctx,
		bson.D{{Key: "_id", Value: key}},
	); err != nil {
		return fmt.Errorf("reset login attempts: %w", err)
	}
	return nil
}
