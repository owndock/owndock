package migration

import (
	"context"
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

func TestValidateMigrations(t *testing.T) {
	valid := []Migration{
		{Version: 2, Name: "two", Up: func(context.Context, *mongo.Database) error { return nil }},
		{Version: 1, Name: "one", Up: func(context.Context, *mongo.Database) error { return nil }},
	}
	if err := validate(sorted(valid)); err != nil {
		t.Fatalf("validate() error = %v", err)
	}
	invalid := []Migration{
		{Version: 1, Name: "one", Up: func(context.Context, *mongo.Database) error { return nil }},
		{Version: 1, Name: "duplicate", Up: func(context.Context, *mongo.Database) error { return nil }},
	}
	if err := validate(invalid); !errors.Is(err, ErrInvalidMigration) {
		t.Fatalf("validate() error = %v, want ErrInvalidMigration", err)
	}
}

func TestDefaultMigrationsRemainContiguous(t *testing.T) {
	items := Default()
	if len(items) != 50 {
		t.Fatalf("Default() migration count = %d, want 50", len(items))
	}
	for index, item := range items {
		if item.Version != int64(index+1) {
			t.Fatalf("migration[%d].Version = %d", index, item.Version)
		}
	}
	last := items[len(items)-1]
	if last.Name != "index_application_build_retirement" || last.Up == nil {
		t.Fatalf("latest migration = %+v", last)
	}
}

func sorted(items []Migration) []Migration {
	result := append([]Migration(nil), items...)
	if result[0].Version > result[1].Version {
		result[0], result[1] = result[1], result[0]
	}
	return result
}
