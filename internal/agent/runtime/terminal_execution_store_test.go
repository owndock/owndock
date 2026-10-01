package agentruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileTerminalExecutionStorePersistsRestrictedRecords(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileTerminalExecutionStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	entry := terminalExecution{
		execID: strings.Repeat("a", 64), containerID: strings.Repeat("b", 64),
		marker: "/tmp/.owndock-terminal-" + strings.Repeat("c", 32),
		shell:  "/bin/sh",
	}
	if err := store.Add(entry); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	path := filepath.Join(directory, "terminal-executions.json")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("terminal execution store mode = %s", info.Mode())
	}
	reloaded, err := NewFileTerminalExecutionStore(directory)
	if err != nil {
		t.Fatalf("reload error = %v", err)
	}
	entries, err := reloaded.List()
	if err != nil || len(entries) != 1 || entries[0] != entry {
		t.Fatalf("reloaded entries = %#v, %v", entries, err)
	}
	if err := reloaded.Remove(entry.execID); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	entries, err = reloaded.List()
	if err != nil || len(entries) != 0 {
		t.Fatalf("entries after remove = %#v, %v", entries, err)
	}
}

func TestFileTerminalExecutionStoreRejectsUnsafeRecords(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileTerminalExecutionStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	entry := terminalExecution{
		execID: strings.Repeat("a", 64), containerID: strings.Repeat("b", 64),
		marker: "/etc/passwd", shell: "/bin/sh -c attacker",
	}
	if err := store.Add(entry); !errors.Is(err, ErrInvalidTerminalExecutionStore) {
		t.Fatalf("unsafe Add() error = %v", err)
	}
}

func TestFileTerminalExecutionStoreRejectsUnknownFields(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "terminal-executions.json")
	value := []byte(`{"version":1,"entries":[],"secret":"must-not-be-accepted"}`)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewFileTerminalExecutionStore(directory)
	if !errors.Is(err, ErrInvalidTerminalExecutionStore) {
		t.Fatalf("unknown-field load error = %v", err)
	}
}

func TestNewTerminalMarkerIsConstrainedAndUnique(t *testing.T) {
	first, err := newTerminalMarker()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newTerminalMarker()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !terminalMarkerRule.MatchString(first) ||
		!terminalMarkerRule.MatchString(second) {
		t.Fatalf("terminal markers = %q, %q", first, second)
	}
}
