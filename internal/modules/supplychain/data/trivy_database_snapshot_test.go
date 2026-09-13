package data

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func validTrivyDatabaseUpdaterScript(databaseContent string) string {
	return `
if [ "$1" = "image" ]; then
  [ "$2" = "--download-db-only" ]
  [ "$3" = "--db-repository" ] && [ "$4" = "mirror.gcr.io/aquasec/trivy-db:2" ]
  [ "$5" = "--db-repository" ] && [ "$6" = "ghcr.io/aquasecurity/trivy-db:2" ]
  [ "$7" = "--cache-dir" ]
  cache=$8
  [ "$9" = "--no-progress" ]
  [ "$TRIVY_CACHE_DIR" = "$cache" ]
  [ "$TRIVY_NO_PROGRESS" = "true" ]
  [ "$TRIVY_CHECK_FOR_APP_UPDATE" = "false" ]
  [ -z "${TRIVY_SKIP_DB_UPDATE:-}" ]
  [ -z "${TRIVY_OFFLINE_SCAN:-}" ]
  mkdir -p "$cache/db"
  printf '%s' '` + databaseContent + `' >"$cache/db/trivy.db"
  printf '%s' '{"Version":2}' >"$cache/db/metadata.json"
  exit 0
fi
[ "$1" = "version" ]
printf '%s' '` + trivyVersionJSON + `'
`
}

func newTrivyDatabaseSnapshotManagerForTest(t *testing.T, executable, root string) *TrivyDatabaseSnapshotManager {
	t.Helper()
	manager, err := NewTrivyDatabaseSnapshotManager(TrivyDatabaseSnapshotOptions{
		Executable: executable, ExpectedVersion: PinnedTrivyVersion, RootDirectory: root,
		RetainSnapshots: 3, MinimumRetention: 72 * time.Hour,
		Now: func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestTrivyDatabaseSnapshotManagerPublishesVerifiedAtomicCurrentLink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "trivy-db")
	manager := newTrivyDatabaseSnapshotManagerForTest(t,
		writeFakeTrivy(t, validTrivyDatabaseUpdaterScript("database-v1")), root)
	snapshot, err := manager.Update(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || target != filepath.Join("snapshots", snapshot.Name) ||
		snapshot.CurrentPath != filepath.Join(root, "current") ||
		!strings.HasPrefix(snapshot.DatabaseDigest, "sha256:") || snapshot.Database.SchemaVersion != 2 {
		t.Fatalf("snapshot = %+v, target=%q, error=%v", snapshot, target, err)
	}
	content, err := os.ReadFile(filepath.Join(root, "current", "db", "trivy.db"))
	if err != nil || string(content) != "database-v1" {
		t.Fatalf("published database = %q, %v", content, err)
	}
	info, err := os.Lstat(filepath.Join(root, "current"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("current info = %+v, %v", info, err)
	}
	if matches, _ := filepath.Glob(filepath.Join(root, ".staging-*")); len(matches) != 0 {
		t.Fatalf("staging directories were not removed: %v", matches)
	}
}

func TestTrivyDatabaseSnapshotManagerPassesOnlyExplicitProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://ambient.invalid:8080")
	t.Setenv("NO_PROXY", "*")
	script := strings.Replace(validTrivyDatabaseUpdaterScript("database-v1"),
		`if [ "$1" = "image" ]; then`, `if [ "$1" = "image" ]; then
  [ "$HTTP_PROXY" = "http://172.31.242.2:3128" ]
  [ "$HTTPS_PROXY" = "$HTTP_PROXY" ]
  [ "$http_proxy" = "$HTTP_PROXY" ]
  [ "$https_proxy" = "$HTTP_PROXY" ]
  [ -z "$NO_PROXY" ]
  [ -z "$no_proxy" ]`, 1)
	manager, err := NewTrivyDatabaseSnapshotManager(TrivyDatabaseSnapshotOptions{
		Executable: writeFakeTrivy(t, script), ExpectedVersion: PinnedTrivyVersion,
		RootDirectory: filepath.Join(t.TempDir(), "trivy-db"),
		HTTPSProxy:    "http://172.31.242.2:3128", RetainSnapshots: 3,
		MinimumRetention: 72 * time.Hour,
		Now:              func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Update(t.Context()); err != nil {
		t.Fatalf("update through explicit proxy environment: %v", err)
	}
}

func TestTrivyDatabaseSnapshotManagerPreservesCurrentOnFailedUpdate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "trivy-db")
	executable := writeFakeTrivy(t, validTrivyDatabaseUpdaterScript("database-v1"))
	manager := newTrivyDatabaseSnapshotManagerForTest(t, executable, root)
	first, err := manager.Update(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 19\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Update(t.Context()); !errors.Is(err, ErrTrivyDatabaseUpdate) {
		t.Fatalf("failed update error = %v", err)
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || target != filepath.Join("snapshots", first.Name) {
		t.Fatalf("current changed after failure: target=%q error=%v", target, err)
	}
	content, err := os.ReadFile(filepath.Join(root, "current", "db", "trivy.db"))
	if err != nil || string(content) != "database-v1" {
		t.Fatalf("preserved database = %q, %v", content, err)
	}
}

func TestTrivyDatabaseSnapshotManagerRejectsConcurrentUpdaterAndUnsafeCurrent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "trivy-db")
	manager := newTrivyDatabaseSnapshotManagerForTest(t,
		writeFakeTrivy(t, validTrivyDatabaseUpdaterScript("database-v1")), root)
	if err := ensureSnapshotRoot(root); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(root, ".update.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Update(t.Context()); !errors.Is(err, ErrTrivyDatabaseUpdateBusy) {
		t.Fatalf("concurrent update error = %v", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "current"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Update(t.Context()); !errors.Is(err, ErrTrivyDatabaseUpdate) {
		t.Fatalf("unsafe current error = %v", err)
	}
}

func TestTrivyDatabaseSnapshotManagerRejectsExpiredDownloadedDatabase(t *testing.T) {
	root := filepath.Join(t.TempDir(), "trivy-db")
	manager, err := NewTrivyDatabaseSnapshotManager(TrivyDatabaseSnapshotOptions{
		Executable:      writeFakeTrivy(t, validTrivyDatabaseUpdaterScript("expired-database")),
		ExpectedVersion: PinnedTrivyVersion, RootDirectory: root,
		RetainSnapshots: 3, MinimumRetention: 72 * time.Hour,
		Now: func() time.Time { return time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Update(t.Context()); !errors.Is(err, ErrTrivyDatabaseUpdate) {
		t.Fatalf("expired database error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired database was published: %v", err)
	}
}

func TestTrivyDatabaseSnapshotConfigurationFailsClosed(t *testing.T) {
	valid := TrivyDatabaseSnapshotOptions{Executable: "/usr/local/bin/trivy",
		ExpectedVersion: PinnedTrivyVersion, RootDirectory: "/var/lib/owndock/trivy-db",
		RetainSnapshots: 3, MinimumRetention: 72 * time.Hour}
	invalid := []TrivyDatabaseSnapshotOptions{
		{},
		func() TrivyDatabaseSnapshotOptions { item := valid; item.Executable = "trivy"; return item }(),
		func() TrivyDatabaseSnapshotOptions { item := valid; item.ExpectedVersion = "latest"; return item }(),
		func() TrivyDatabaseSnapshotOptions { item := valid; item.RootDirectory = "/"; return item }(),
		func() TrivyDatabaseSnapshotOptions {
			item := valid
			item.Repositories = []string{"registry.example.com/trivy-db:latest"}
			return item
		}(),
		func() TrivyDatabaseSnapshotOptions { item := valid; item.RetainSnapshots = 1; return item }(),
		func() TrivyDatabaseSnapshotOptions { item := valid; item.MinimumRetention = time.Minute; return item }(),
		func() TrivyDatabaseSnapshotOptions {
			item := valid
			item.HTTPSProxy = "http://user:secret@proxy.internal:3128"
			return item
		}(),
	}
	for _, item := range invalid {
		if _, err := NewTrivyDatabaseSnapshotManager(item); !errors.Is(err, ErrTrivyDatabaseUpdate) {
			t.Fatalf("options %+v error = %v", item, err)
		}
	}
}

func TestTrivyDatabaseUpdateEnvironmentUsesOnlyExplicitProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://ambient.invalid:8080")
	t.Setenv("HTTPS_PROXY", "http://ambient.invalid:8080")
	t.Setenv("NO_PROXY", "*")
	withoutProxy := trivyDatabaseUpdateEnvironment("/tmp/cache", "")
	for _, value := range withoutProxy {
		if strings.Contains(value, "PROXY=") || strings.Contains(value, "proxy=") {
			t.Fatalf("ambient proxy leaked into updater: %v", withoutProxy)
		}
	}
	withProxy := trivyDatabaseUpdateEnvironment("/tmp/cache", "http://172.31.242.2:3128")
	for _, expected := range []string{
		"HTTP_PROXY=http://172.31.242.2:3128", "HTTPS_PROXY=http://172.31.242.2:3128",
		"http_proxy=http://172.31.242.2:3128", "https_proxy=http://172.31.242.2:3128",
		"NO_PROXY=", "no_proxy=",
	} {
		if !slices.Contains(withProxy, expected) {
			t.Fatalf("explicit updater environment %v does not contain %q", withProxy, expected)
		}
	}
}
