package migration

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var (
	ErrLocked           = errors.New("schema migration lock is held")
	ErrInvalidMigration = errors.New("invalid schema migration")
)

const (
	migrationsCollection = "schema_migrations"
	lockCollection       = "schema_migration_locks"
	globalLockID         = "global"
)

type Clock func() time.Time

type Migration struct {
	Version int64
	Name    string
	Up      func(context.Context, *mongo.Database) error
}

type Runner struct {
	database *mongo.Database
	owner    string
	now      Clock
	lease    time.Duration
}

func NewRunner(database *mongo.Database, owner string) *Runner {
	return &Runner{
		database: database,
		owner:    strings.TrimSpace(owner),
		now:      time.Now,
		lease:    time.Minute,
	}
}

func (r *Runner) Run(ctx context.Context, migrations []Migration) error {
	if r == nil || r.database == nil || r.owner == "" {
		return fmt.Errorf("%w: database and owner are required", ErrInvalidMigration)
	}
	ordered := append([]Migration(nil), migrations...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Version < ordered[j].Version })
	if err := validate(ordered); err != nil {
		return err
	}
	if err := r.ensureMetadataIndexes(ctx); err != nil {
		return err
	}
	token := r.owner + ":" + fmt.Sprint(r.now().UTC().UnixNano())
	if err := r.acquire(ctx, token); err != nil {
		return err
	}
	defer func() {
		releaseContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.release(releaseContext, token)
	}()

	for _, item := range ordered {
		appliedName, applied, err := r.applied(ctx, item.Version)
		if err != nil {
			return err
		}
		if applied {
			if appliedName != item.Name {
				return fmt.Errorf("%w: version %d was recorded as %q, not %q", ErrInvalidMigration, item.Version, appliedName, item.Name)
			}
			continue
		}
		if err := item.Up(ctx, r.database); err != nil {
			return fmt.Errorf("apply migration %d %q: %w", item.Version, item.Name, err)
		}
		_, err = r.database.Collection(migrationsCollection).InsertOne(ctx, bson.D{
			{Key: "version", Value: item.Version},
			{Key: "name", Value: item.Name},
			{Key: "applied_at", Value: r.now().UTC()},
		})
		if err != nil {
			return fmt.Errorf("record migration %d: %w", item.Version, err)
		}
	}
	return nil
}

func validate(migrations []Migration) error {
	var previous int64
	for _, item := range migrations {
		if item.Version <= 0 || item.Version == previous || strings.TrimSpace(item.Name) == "" || item.Up == nil {
			return fmt.Errorf("%w: versions must be unique and positive, and name/up are required", ErrInvalidMigration)
		}
		previous = item.Version
	}
	return nil
}

func (r *Runner) ensureMetadataIndexes(ctx context.Context) error {
	_, err := r.database.Collection(migrationsCollection).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "version", Value: 1}},
		Options: options.Index().SetName("uniq_schema_migration_version").SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("ensure schema migration index: %w", err)
	}
	return nil
}

func (r *Runner) acquire(ctx context.Context, token string) error {
	now := r.now().UTC()
	filter := bson.D{
		{Key: "_id", Value: globalLockID},
		{Key: "$or", Value: bson.A{
			bson.D{{Key: "locked_until", Value: bson.D{{Key: "$lte", Value: now}}}},
			bson.D{{Key: "token", Value: token}},
		}},
	}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "owner", Value: r.owner},
		{Key: "token", Value: token},
		{Key: "locked_until", Value: now.Add(r.lease)},
	}}}
	result := r.database.Collection(lockCollection).FindOneAndUpdate(
		ctx,
		filter,
		update,
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	)
	if err := result.Err(); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrLocked
		}
		return fmt.Errorf("acquire schema migration lock: %w", err)
	}
	return nil
}

func (r *Runner) release(ctx context.Context, token string) error {
	_, err := r.database.Collection(lockCollection).UpdateOne(
		ctx,
		bson.D{{Key: "_id", Value: globalLockID}, {Key: "token", Value: token}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "locked_until", Value: r.now().UTC()}}}},
	)
	if err != nil {
		return fmt.Errorf("release schema migration lock: %w", err)
	}
	return nil
}

func (r *Runner) applied(ctx context.Context, version int64) (string, bool, error) {
	var record struct {
		Name string `bson:"name"`
	}
	err := r.database.Collection(migrationsCollection).
		FindOne(ctx, bson.D{{Key: "version", Value: version}}).
		Decode(&record)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read migration %d: %w", version, err)
	}
	return record.Name, true, nil
}
