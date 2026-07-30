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
