package agentruntime

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileCutoverStorePersistsAndRejectsOlderDeployment(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewFileCutoverStore(directory, 8)
	if err != nil {
		t.Fatal(err)
	}
	if stale, err := store.Observe(
		"owndock-slot",
		"deployment-10",
		10,
	); err != nil || stale {
		t.Fatalf("observe first watermark = %t, %v", stale, err)
	}

	reloaded, err := NewFileCutoverStore(directory, 8)
	if err != nil {
		t.Fatal(err)
	}
	if stale, err := reloaded.Observe(
		"owndock-slot",
		"deployment-9",
		9,
	); err != nil || !stale {
		t.Fatalf("older watermark = %t, %v", stale, err)
	}
	if stale, err := reloaded.Observe(
		"owndock-slot",
		"different-deployment",
		10,
	); err != nil || !stale {
		t.Fatalf("conflicting watermark = %t, %v", stale, err)
	}
	if stale, err := reloaded.Observe(
		"owndock-slot",
		"deployment-11",
		11,
	); err != nil || stale {
		t.Fatalf("newer watermark = %t, %v", stale, err)
	}
}

func TestFileCutoverStoreFailsClosedAtCapacity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewFileCutoverStore(directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Observe(
		"owndock-first",
		"deployment-1",
		1,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Observe(
		"owndock-second",
		"deployment-2",
		1,
	); !errors.Is(err, ErrCutoverStoreFull) {
		t.Fatalf("capacity error = %v", err)
	}
	reloaded, err := NewFileCutoverStore(directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	if stale, err := reloaded.Observe(
		"owndock-first",
		"older-deployment",
		0,
	); !errors.Is(err, ErrInvalidCutoverStore) || stale {
		t.Fatalf("invalid sequence = %t, %v", stale, err)
	}
	if stale, err := reloaded.Observe(
		"owndock-first",
		"older-deployment",
		1,
	); err != nil || !stale {
		t.Fatalf("retained watermark = %t, %v", stale, err)
	}
}

func TestFileCutoverStoreReleasesOnlyExactWatermark(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewFileCutoverStore(directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Observe(
		"owndock-first", "deployment-2", 2,
	); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		deploymentID string
		sequence     uint64
	}{
		{deploymentID: "deployment-1", sequence: 2},
		{deploymentID: "deployment-2", sequence: 1},
		{deploymentID: "deployment-2", sequence: 3},
	} {
		if released, releaseErr := store.Release(
			"owndock-first", input.deploymentID, input.sequence,
		); released || !errors.Is(releaseErr, ErrCutoverConflict) {
			t.Fatalf("release %+v = %t, %v", input, released, releaseErr)
		}
	}
	if _, err := store.Observe(
		"owndock-second", "deployment-1", 1,
	); !errors.Is(err, ErrCutoverStoreFull) {
		t.Fatalf("mismatch released capacity: %v", err)
	}
	if released, err := store.Release(
		"owndock-first", "deployment-2", 2,
	); err != nil || !released {
		t.Fatalf("exact release = %t, %v", released, err)
	}
	if released, err := store.Release(
		"owndock-first", "deployment-2", 2,
	); err != nil || released {
		t.Fatalf("replayed release = %t, %v", released, err)
	}
	if _, err := store.Observe(
		"owndock-second", "deployment-1", 1,
	); err != nil {
		t.Fatalf("released capacity not reusable: %v", err)
	}
	reloaded, err := NewFileCutoverStore(directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	if stale, err := reloaded.Observe(
		"owndock-second", "older-deployment", 1,
	); err != nil || !stale {
		t.Fatalf("reloaded watermark = %t, %v", stale, err)
	}
}

func TestFileCutoverStoreProtectsOlderStableRuntime(t *testing.T) {
	store, err := NewFileCutoverStore(filepath.Join(t.TempDir(), "state"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Observe("owndock-slot", "deployment-new", 3); err != nil {
		t.Fatal(err)
	}
	if err := store.ProtectsRemoval("owndock-slot", "deployment-stable", 2); err != nil {
		t.Fatalf("newer watermark did not protect older stable runtime: %v", err)
	}
	for _, input := range []struct {
		deploymentID string
		sequence     uint64
	}{
		{deploymentID: "other-deployment", sequence: 3},
		{deploymentID: "future-deployment", sequence: 4},
	} {
		if err := store.ProtectsRemoval(
			"owndock-slot", input.deploymentID, input.sequence,
		); !errors.Is(err, ErrCutoverConflict) {
			t.Fatalf("unsafe removal %+v = %v", input, err)
		}
	}
}

func TestFileCutoverStoreRejectsInvalidRelease(t *testing.T) {
	store, err := NewFileCutoverStore(
		filepath.Join(t.TempDir(), "state"),
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if released, err := store.Release("", "deployment-1", 1); released || !errors.Is(err, ErrInvalidCutoverStore) {
		t.Fatalf("invalid release = %t, %v", released, err)
	}
}

func TestFileCutoverStoreRestoresWatermarkAfterReleasePersistenceFailure(
	t *testing.T,
) {
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewFileCutoverStore(directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Observe("owndock-slot", "deployment-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store.path, 0o700); err != nil {
		t.Fatal(err)
	}
	if released, err := store.Release("owndock-slot", "deployment-1", 1); released || err == nil {
		t.Fatalf("release with blocked persistence = %t, %v", released, err)
	}
	if err := os.Remove(store.path); err != nil {
		t.Fatal(err)
	}
	if released, err := store.Release("owndock-slot", "deployment-1", 1); !released || err != nil {
		t.Fatalf("restored watermark release = %t, %v", released, err)
	}
}

func TestFileCutoverStoreSerializesConcurrentUpdates(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	store, err := NewFileCutoverStore(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for sequence := uint64(1); sequence <= 32; sequence++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, observeError := store.Observe(
				"owndock-slot",
				"deployment-"+string(rune('a'+sequence%26)),
				sequence,
			)
			if observeError != nil {
				t.Errorf("observe sequence %d: %v", sequence, observeError)
			}
		}()
	}
	wait.Wait()
	reloaded, err := NewFileCutoverStore(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	if stale, err := reloaded.Observe(
		"owndock-slot",
		"deployment-z",
		31,
	); err != nil || !stale {
		t.Fatalf("sequence below maximum = %t, %v", stale, err)
	}
}

func TestFileCutoverStoreRejectsCorruptOrInsecureState(t *testing.T) {
	t.Run("corrupt", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(directory, "deployment-cutovers.json"),
			[]byte(`{"version":1,"entries":[{"container_name":"slot"}]}`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileCutoverStore(
			directory,
			4,
		); !errors.Is(err, ErrInvalidCutoverStore) {
			t.Fatalf("corrupt state error = %v", err)
		}
	})

	t.Run("insecure mode", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileCutoverStore(
			directory,
			4,
		); !errors.Is(err, ErrInvalidCutoverStore) {
			t.Fatalf("insecure directory error = %v", err)
		}
	})
}
