package agentruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
)

const cutoverStoreVersion = 1
const maximumCutoverStoreBytes = 4 * 1024 * 1024

var (
	ErrInvalidCutoverStore = errors.New("agent cutover store is invalid")
	ErrCutoverStoreFull    = errors.New("agent cutover store is full")
	ErrCutoverConflict     = errors.New("agent cutover watermark does not match")
)

var (
	cutoverContainerNameRule = regexp.MustCompile(
		`^[a-z0-9][a-z0-9_.-]{0,127}$`,
	)
	cutoverDeploymentIDRule = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`,
	)
)

type CutoverStore interface {
	Observe(
		containerName string,
		deploymentID string,
		sequence uint64,
	) (stale bool, err error)
	Release(
		containerName string,
		deploymentID string,
		sequence uint64,
	) (released bool, err error)
	ProtectsRemoval(containerName string, deploymentID string, sequence uint64) error
}

type cutoverWatermark struct {
	deploymentID string
	sequence     uint64
}

// FileCutoverStore is independent from the command result cache: result
// eviction must never make an older Deployment current again. Capacity never
// evicts entries. An entry can only be removed by an exact lifecycle release
// sent after the Server has fenced and drained every operation for that slot.
type FileCutoverStore struct {
	mu sync.Mutex

	directory string
	path      string
	maximum   int
	entries   map[string]cutoverWatermark
}

func NewFileCutoverStore(
	directory string,
	maximum int,
) (*FileCutoverStore, error) {
	if maximum < 1 || maximum > 65536 {
		return nil, ErrInvalidCutoverStore
	}
	directory, err := prepareStateDirectory(
		directory,
		ErrInvalidCutoverStore,
	)
	if err != nil {
		return nil, err
	}
	store := &FileCutoverStore{
		directory: directory,
		path: filepath.Join(
			directory,
			"deployment-cutovers.json",
		),
		maximum: maximum,
		entries: make(map[string]cutoverWatermark),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileCutoverStore) Observe(
	containerName string,
	deploymentID string,
	sequence uint64,
) (bool, error) {
	if !validCutoverEntry(containerName, deploymentID, sequence) {
		return false, ErrInvalidCutoverStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.entries[containerName]
	if exists {
		if sequence < current.sequence ||
			(sequence == current.sequence &&
				deploymentID != current.deploymentID) {
			return true, nil
		}
		if sequence == current.sequence {
			return false, nil
		}
	} else if len(s.entries) >= s.maximum {
		return false, ErrCutoverStoreFull
	}
	s.entries[containerName] = cutoverWatermark{
		deploymentID: deploymentID,
		sequence:     sequence,
	}
	if err := s.persistLocked(); err != nil {
		if exists {
			s.entries[containerName] = current
		} else {
			delete(s.entries, containerName)
		}
		return false, err
	}
	return false, nil
}

// Release removes only the exact current slot watermark. A missing entry is an
// idempotent success, which lets a durable release command be replayed after an
// ambiguous response. A different Deployment or sequence fails closed.
func (s *FileCutoverStore) Release(
	containerName string,
	deploymentID string,
	sequence uint64,
) (bool, error) {
	if !validCutoverEntry(containerName, deploymentID, sequence) {
		return false, ErrInvalidCutoverStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.entries[containerName]
	if !exists {
		return false, nil
	}
	if current.deploymentID != deploymentID || current.sequence != sequence {
		return false, ErrCutoverConflict
	}
	delete(s.entries, containerName)
	if err := s.persistLocked(); err != nil {
		s.entries[containerName] = current
		return false, err
	}
	return true, nil
}

// ProtectsRemoval verifies that the durable watermark will reject every
// delayed command which could recreate or replace the selected stable
// runtime. A newer watermark safely protects an older stable container after
// a later deployment failed; Release remains exact and separate.
func (s *FileCutoverStore) ProtectsRemoval(
	containerName string,
	deploymentID string,
	sequence uint64,
) error {
	if !validCutoverEntry(containerName, deploymentID, sequence) {
		return ErrInvalidCutoverStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.entries[containerName]
	if !exists || current.sequence < sequence ||
		(current.sequence == sequence && current.deploymentID != deploymentID) {
		return ErrCutoverConflict
	}
	return nil
}

func (s *FileCutoverStore) load() error {
	value, exists, err := readRestrictedStateFile(
		s.path,
		maximumCutoverStoreBytes,
		ErrInvalidCutoverStore,
	)
	if err != nil || !exists {
		return err
	}
	var document cutoverStoreDocument
	if decodeStrictJSON(value, &document) != nil ||
		document.Version != cutoverStoreVersion ||
		len(document.Entries) > s.maximum {
		return ErrInvalidCutoverStore
	}
	for _, entry := range document.Entries {
		if !validCutoverEntry(
			entry.ContainerName,
			entry.DeploymentID,
			entry.Sequence,
		) {
			return ErrInvalidCutoverStore
		}
		if _, duplicate := s.entries[entry.ContainerName]; duplicate {
			return ErrInvalidCutoverStore
		}
		s.entries[entry.ContainerName] = cutoverWatermark{
			deploymentID: entry.DeploymentID,
			sequence:     entry.Sequence,
		}
	}
	return nil
}

func (s *FileCutoverStore) persistLocked() error {
	names := make([]string, 0, len(s.entries))
	for name := range s.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	document := cutoverStoreDocument{
		Version: cutoverStoreVersion,
		Entries: make([]cutoverStoreEntryDocument, 0, len(names)),
	}
	for _, name := range names {
		entry := s.entries[name]
		document.Entries = append(
			document.Entries,
			cutoverStoreEntryDocument{
				ContainerName: name,
				DeploymentID:  entry.deploymentID,
				Sequence:      entry.sequence,
			},
		)
	}
	value, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode Agent cutover store: %w", err)
	}
	if len(value) > maximumCutoverStoreBytes {
		return ErrCutoverStoreFull
	}
	return replaceRestrictedStateFile(
		s.directory,
		s.path,
		".deployment-cutovers-*",
		value,
	)
}

func validCutoverEntry(
	containerName string,
	deploymentID string,
	sequence uint64,
) bool {
	return sequence > 0 &&
		cutoverContainerNameRule.MatchString(containerName) &&
		cutoverDeploymentIDRule.MatchString(deploymentID)
}

type cutoverStoreDocument struct {
	Version int                         `json:"version"`
	Entries []cutoverStoreEntryDocument `json:"entries"`
}

type cutoverStoreEntryDocument struct {
	ContainerName string `json:"container_name"`
	DeploymentID  string `json:"deployment_id"`
	Sequence      uint64 `json:"sequence"`
}
