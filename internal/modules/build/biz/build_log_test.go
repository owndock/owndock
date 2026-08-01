package biz

import (
	"errors"
	"testing"
	"time"
)

func TestBuildLogAppendAndQueryValidation(t *testing.T) {
	item := BuildLogAppend{
		BuildID: "build-1", ProjectID: "project-1", Stage: BuildLogStageBuild,
		Message: "step completed", CreatedAt: time.Unix(100, 0),
	}
	if err := item.Validate(); err != nil {
		t.Fatal(err)
	}
	item.Stage = "raw"
	if !errors.Is(item.Validate(), ErrInvalidBuildLog) {
		t.Fatalf("invalid stage error = %v", item.Validate())
	}
	query, err := (BuildLogQuery{}).Normalize()
	if err != nil || query.Limit != DefaultBuildLogPageSize {
		t.Fatalf("default query = %+v/%v", query, err)
	}
	if _, err := (BuildLogQuery{Limit: MaximumBuildLogPageSize + 1}).Normalize(); !errors.Is(err, ErrInvalidBuildLogQuery) {
		t.Fatalf("oversized query error = %v", err)
	}
}
