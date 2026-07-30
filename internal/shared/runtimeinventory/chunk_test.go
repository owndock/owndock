package runtimeinventory

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSplitHonorsExactByteAndItemLimits(t *testing.T) {
	resources := []Resource{
		testResource("container-1", strings.Repeat("a", 100)),
		testResource("container-2", strings.Repeat("b", 100)),
		testResource("container-3", strings.Repeat("c", 100)),
	}
	chunks, err := Split(resources, 700, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("chunk count = %d, want at least 2", len(chunks))
	}
	for index, chunk := range chunks {
		if chunk.Index != index {
			t.Fatalf("chunk index = %d, want %d", chunk.Index, index)
		}
		payload, marshalErr := json.Marshal(chunk)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if len(payload) > 700 || len(chunk.Resources) > 2 {
			t.Fatalf("chunk size/items = %d/%d", len(payload), len(chunk.Resources))
		}
		if err := chunk.Validate(700); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSplitRejectsOneOversizedResource(t *testing.T) {
	resource := testResource("container-1", strings.Repeat("a", 512))
	_, err := Split([]Resource{resource}, 128, 1)
	if !errors.Is(err, ErrSnapshotTooLarge) {
		t.Fatalf("error = %v, want %v", err, ErrSnapshotTooLarge)
	}
}

func TestAllowedLabelUsesExactAllowlist(t *testing.T) {
	if !AllowedLabel("net.owndock.deployment_id") {
		t.Fatal("deployment label should be allowed")
	}
	for _, key := range []string{
		"net.owndock.deployment_id.secret",
		"net.owndock.environment_id",
		"net.owndock.fencing_token",
		"com.example.password",
	} {
		if AllowedLabel(key) {
			t.Fatalf("label %q should not be allowed", key)
		}
	}
}

func testResource(id, description string) Resource {
	return Resource{
		Kind:      KindContainer,
		RuntimeID: id,
		Name:      id,
		Container: &ContainerSummary{
			State:          "running",
			ImageReference: description,
		},
		Labels: map[string]string{
			"net.owndock.deployment_id": id,
		},
		ObservedAt:    time.Unix(100, 0).UTC(),
		SchemaVersion: SchemaVersion,
	}
}
