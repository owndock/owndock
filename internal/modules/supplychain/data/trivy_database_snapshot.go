package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"golang.org/x/sys/unix"
)

const (
	maximumTrivyDatabaseBytes       = int64(4 * 1024 * 1024 * 1024)
	DefaultTrivyDatabaseRepository  = "mirror.gcr.io/aquasec/trivy-db:2"
	FallbackTrivyDatabaseRepository = "ghcr.io/aquasecurity/trivy-db:2"
)

var (
	ErrTrivyDatabaseUpdateBusy = errors.New("Trivy database snapshot update is already running")
	ErrTrivyDatabaseUpdate     = errors.New("Trivy database snapshot update failed")
)

type TrivyDatabaseSnapshotOptions struct {
	Executable       string
	ExpectedVersion  string
	RootDirectory    string
	Repositories     []string
	HTTPSProxy       string
	CACertFile       string
	RetainSnapshots  int
	MinimumRetention time.Duration
	Now              func() time.Time
}

type TrivyDatabaseSnapshot struct {
	Name           string
	SnapshotPath   string
	CurrentPath    string
	DatabaseDigest string
	Database       biz.VulnerabilityDatabase
}

type TrivyDatabaseSnapshotManager struct {
	executable       string
	expectedVersion  string
	rootDirectory    string
	repositories     []string
	httpsProxy       string
	caCertFile       string
	retainSnapshots  int
	minimumRetention time.Duration
	now              func() time.Time
}

func NewTrivyDatabaseSnapshotManager(options TrivyDatabaseSnapshotOptions) (
	*TrivyDatabaseSnapshotManager, error) {
	executable := strings.TrimSpace(options.Executable)
	expectedVersion := strings.TrimPrefix(strings.TrimSpace(options.ExpectedVersion), "v")
	rootDirectory := filepath.Clean(strings.TrimSpace(options.RootDirectory))
	repositories, err := validateTrivyDatabaseRepositories(options.Repositories)
	if !filepath.IsAbs(executable) || expectedVersion != PinnedTrivyVersion ||
		!filepath.IsAbs(rootDirectory) || rootDirectory == string(filepath.Separator) ||
		options.RetainSnapshots < 2 || options.RetainSnapshots > 32 ||
		options.MinimumRetention < time.Hour || options.MinimumRetention > 30*24*time.Hour || err != nil {
		return nil, ErrTrivyDatabaseUpdate
	}
	if !validRegistryHTTPSProxy(options.HTTPSProxy) || !validRegistryCACertFile(options.CACertFile) {
		return nil, ErrTrivyDatabaseUpdate
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &TrivyDatabaseSnapshotManager{
		executable: executable, expectedVersion: expectedVersion, rootDirectory: rootDirectory,
		repositories: repositories, httpsProxy: options.HTTPSProxy, caCertFile: options.CACertFile,
		retainSnapshots: options.RetainSnapshots, minimumRetention: options.MinimumRetention,
		now: options.Now,
	}, nil
}

func (m *TrivyDatabaseSnapshotManager) Update(ctx context.Context) (TrivyDatabaseSnapshot, error) {
	if err := ensureSnapshotRoot(m.rootDirectory); err != nil {
		return TrivyDatabaseSnapshot{}, err
	}
	lock, err := os.OpenFile(filepath.Join(m.rootDirectory, ".update.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return TrivyDatabaseSnapshot{}, ErrTrivyDatabaseUpdate
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return TrivyDatabaseSnapshot{}, ErrTrivyDatabaseUpdateBusy
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck -- releasing a process-owned lock is best effort

	staging, err := os.MkdirTemp(m.rootDirectory, ".staging-")
	if err != nil {
		return TrivyDatabaseSnapshot{}, ErrTrivyDatabaseUpdate
	}
	defer os.RemoveAll(staging)
	if err := m.download(ctx, staging); err != nil {
		return TrivyDatabaseSnapshot{}, err
	}
	database, err := readTrivyDatabaseMetadata(ctx, m.executable, m.expectedVersion, staging)
	if err != nil {
		return TrivyDatabaseSnapshot{}, ErrTrivyDatabaseUpdate
	}
	now := m.now().UTC()
	if now.IsZero() || !database.NextUpdate.After(now) || database.UpdatedAt.After(now.Add(15*time.Minute)) ||
		database.DownloadedAt.After(now.Add(15*time.Minute)) {
		return TrivyDatabaseSnapshot{}, ErrTrivyDatabaseUpdate
	}
	digest, err := hashTrivyDatabase(filepath.Join(staging, "db", "trivy.db"))
	if err != nil {
		return TrivyDatabaseSnapshot{}, err
	}
	name := fmt.Sprintf("v%d-%s-%s", database.SchemaVersion,
		database.UpdatedAt.UTC().Format("20060102T150405Z"), strings.TrimPrefix(digest, "sha256:")[:16])
	snapshotsDirectory := filepath.Join(m.rootDirectory, "snapshots")
	if err := os.MkdirAll(snapshotsDirectory, 0o750); err != nil {
		return TrivyDatabaseSnapshot{}, ErrTrivyDatabaseUpdate
	}
	destination := filepath.Join(snapshotsDirectory, name)
	if err := prepareSnapshotDirectory(staging); err != nil {
		return TrivyDatabaseSnapshot{}, err
	}
	if err := installSnapshot(ctx, staging, destination, digest, database, m); err != nil {
		return TrivyDatabaseSnapshot{}, err
	}
	target := filepath.Join("snapshots", name)
	if err := pruneTrivySnapshots(m.rootDirectory, target, m.retainSnapshots,
		m.minimumRetention, now); err != nil {
		return TrivyDatabaseSnapshot{}, err
	}
	if err := switchCurrentSnapshot(m.rootDirectory, target); err != nil {
		return TrivyDatabaseSnapshot{}, err
	}
	return TrivyDatabaseSnapshot{Name: name, SnapshotPath: destination,
		CurrentPath: filepath.Join(m.rootDirectory, "current"), DatabaseDigest: digest, Database: database}, nil
}

func ensureSnapshotRoot(root string) error {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return ErrTrivyDatabaseUpdate
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrTrivyDatabaseUpdate
	}
	return nil
}

func (m *TrivyDatabaseSnapshotManager) download(ctx context.Context, staging string) error {
	arguments := []string{"image", "--download-db-only"}
	for _, repository := range m.repositories {
		arguments = append(arguments, "--db-repository", repository)
	}
	arguments = append(arguments, "--cache-dir", staging, "--no-progress")
	command := exec.CommandContext(ctx, m.executable, arguments...)
	command.Env = trivyDatabaseUpdateEnvironment(staging, m.httpsProxy, m.caCertFile)
	output := &boundedBuffer{maximum: 4096}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		command.Env = nil
		return ErrTrivyDatabaseUpdate
	}
	command.Env = nil
	return nil
}

func validateTrivyDatabaseRepositories(values []string) ([]string, error) {
	if len(values) == 0 {
		values = []string{DefaultTrivyDatabaseRepository, FallbackTrivyDatabaseRepository}
	}
	if len(values) > 4 {
		return nil, ErrTrivyDatabaseUpdate
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		named, err := reference.ParseNormalizedNamed(value)
		tagged, taggedOK := named.(reference.Tagged)
		if err != nil || !taggedOK || tagged.Tag() != "2" || value != reference.FamiliarString(named) ||
			len(value) > 256 || seen[value] {
			return nil, ErrTrivyDatabaseUpdate
		}
		seen[value] = true
		result = append(result, value)
	}
	return result, nil
}

func trivyDatabaseUpdateEnvironment(cacheDirectory, httpsProxy, caCertFile string) []string {
	values := []string{"HOME=/tmp", "TRIVY_CACHE_DIR=" + cacheDirectory,
		"TRIVY_NO_PROGRESS=true", "TRIVY_CHECK_FOR_APP_UPDATE=false"}
	return registryProxyEnvironment(registryCAEnvironment(values, caCertFile), httpsProxy)
}

func hashTrivyDatabase(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maximumTrivyDatabaseBytes {
		return "", ErrTrivyDatabaseUpdate
	}
	file, err := os.Open(path)
	if err != nil {
		return "", ErrTrivyDatabaseUpdate
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumTrivyDatabaseBytes+1)); err != nil {
		return "", ErrTrivyDatabaseUpdate
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func prepareSnapshotDirectory(root string) error {
	directories := make([]string, 0, 4)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrTrivyDatabaseUpdate
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return os.Chmod(path, 0o750)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrTrivyDatabaseUpdate
		}
		if err := os.Chmod(path, 0o640); err != nil {
			return ErrTrivyDatabaseUpdate
		}
		file, err := os.Open(path)
		if err != nil {
			return ErrTrivyDatabaseUpdate
		}
		err = file.Sync()
		_ = file.Close()
		return err
	}); err != nil {
		return ErrTrivyDatabaseUpdate
	}
	sort.Slice(directories, func(left, right int) bool {
		return strings.Count(directories[left], string(filepath.Separator)) >
			strings.Count(directories[right], string(filepath.Separator))
	})
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func installSnapshot(ctx context.Context, staging, destination, digest string, database biz.VulnerabilityDatabase,
	manager *TrivyDatabaseSnapshotManager) error {
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(staging, destination); err != nil {
			return ErrTrivyDatabaseUpdate
		}
		return syncDirectory(filepath.Dir(destination))
	} else if err != nil {
		return ErrTrivyDatabaseUpdate
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrTrivyDatabaseUpdate
	}
	existingDigest, err := hashTrivyDatabase(filepath.Join(destination, "db", "trivy.db"))
	if err != nil || existingDigest != digest {
		return ErrTrivyDatabaseUpdate
	}
	existingDatabase, err := readTrivyDatabaseMetadata(ctx, manager.executable,
		manager.expectedVersion, destination)
	if err != nil || !existingDatabase.Equal(database) {
		return ErrTrivyDatabaseUpdate
	}
	return nil
}

func switchCurrentSnapshot(root, target string) error {
	current := filepath.Join(root, "current")
	if info, err := os.Lstat(current); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return ErrTrivyDatabaseUpdate
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrTrivyDatabaseUpdate
	}
	temporary, err := os.CreateTemp(root, ".current-")
	if err != nil {
		return ErrTrivyDatabaseUpdate
	}
	temporaryPath := temporary.Name()
	_ = temporary.Close()
	_ = os.Remove(temporaryPath)
	defer os.Remove(temporaryPath)
	if err := os.Symlink(target, temporaryPath); err != nil {
		return ErrTrivyDatabaseUpdate
	}
	if err := os.Rename(temporaryPath, current); err != nil {
		return ErrTrivyDatabaseUpdate
	}
	return syncDirectory(root)
}

type trivySnapshotEntry struct {
	name     string
	path     string
	modified time.Time
}

func pruneTrivySnapshots(root, futureTarget string, retain int, minimumAge time.Duration, now time.Time) error {
	snapshots := filepath.Join(root, "snapshots")
	entries, err := os.ReadDir(snapshots)
	if err != nil {
		return ErrTrivyDatabaseUpdate
	}
	items := make([]trivySnapshotEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || strings.HasPrefix(entry.Name(), ".") {
			return ErrTrivyDatabaseUpdate
		}
		items = append(items, trivySnapshotEntry{name: entry.Name(), path: filepath.Join(snapshots, entry.Name()),
			modified: info.ModTime().UTC()})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].modified.After(items[right].modified) })
	preserve := map[string]bool{filepath.Base(futureTarget): true}
	if currentTarget, err := os.Readlink(filepath.Join(root, "current")); err == nil {
		if currentTarget != filepath.Join("snapshots", filepath.Base(currentTarget)) ||
			filepath.Base(currentTarget) == "." {
			return ErrTrivyDatabaseUpdate
		}
		preserve[filepath.Base(currentTarget)] = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrTrivyDatabaseUpdate
	}
	for index, item := range items {
		if index < retain || preserve[item.name] || now.Sub(item.modified) < minimumAge {
			continue
		}
		if err := os.RemoveAll(item.path); err != nil {
			return ErrTrivyDatabaseUpdate
		}
	}
	return syncDirectory(snapshots)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrTrivyDatabaseUpdate
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrTrivyDatabaseUpdate
	}
	return nil
}
