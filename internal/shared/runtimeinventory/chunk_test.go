package runtimeinventory

import (
	"encoding/json"
	"errors"
	"fmt"
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

func TestSplitLargeHostSnapshotRemainsBoundedAndLossless(t *testing.T) {
	const resourceCount = 10_000
	resources := make([]Resource, resourceCount)
	for index := range resources {
		id := fmt.Sprintf("container-%05d", index)
		resources[index] = testResource(id, "registry.example.com/team/api:1")
	}
	chunks, err := Split(resources, DefaultChunkBytes, MaxResourcesPerChunk)
	if err != nil {
		t.Fatalf("Split() error = %v", err)
	}
	seen := make(map[string]struct{}, resourceCount)
	for index, chunk := range chunks {
		if chunk.Index != index || len(chunk.Resources) > MaxResourcesPerChunk {
			t.Fatalf("chunk %d metadata = index:%d resources:%d", index, chunk.Index, len(chunk.Resources))
		}
		payload, marshalErr := json.Marshal(chunk)
		if marshalErr != nil || len(payload) > DefaultChunkBytes ||
			chunk.Validate(DefaultChunkBytes) != nil {
			t.Fatalf("chunk %d size/validation = %d/%v/%v", index, len(payload), marshalErr, chunk.Validate(DefaultChunkBytes))
		}
		for _, resource := range chunk.Resources {
			if _, duplicate := seen[resource.RuntimeID]; duplicate {
				t.Fatalf("duplicate resource %q", resource.RuntimeID)
			}
			seen[resource.RuntimeID] = struct{}{}
		}
	}
	if len(seen) != resourceCount || len(chunks) > MaxChunks {
		t.Fatalf("reconstructed resources/chunks = %d/%d", len(seen), len(chunks))
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
