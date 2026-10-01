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

const terminalExecutionStoreVersion = 1
const maximumTerminalExecutionStoreBytes = 64 * 1024
const maximumTerminalExecutions = 32

var (
	ErrInvalidTerminalExecutionStore = errors.New(
		"agent terminal execution store is invalid",
	)
	ErrTerminalExecutionStoreFull = errors.New(
		"agent terminal execution store is full",
	)
	terminalExecutionIDRule = regexp.MustCompile(`^[0-9a-f]{64}$`)
	terminalMarkerRule      = regexp.MustCompile(
		`^/tmp/\.owndock-terminal-[0-9a-f]{32}$`,
	)
)

type terminalExecution struct {
	execID      string
	containerID string
	marker      string
	shell       string
}

type terminalExecutionStore interface {
	Add(terminalExecution) error
	Remove(execID string) error
	List() ([]terminalExecution, error)
}

// FileTerminalExecutionStore records only Docker object IDs for active
// fixed-shell execs. A restarted Agent uses the file to close a shell left by
// an abrupt process loss before it accepts another container terminal.
type FileTerminalExecutionStore struct {
	mu sync.Mutex

	directory string
	path      string
	entries   map[string]terminalExecution
}

func NewFileTerminalExecutionStore(
	directory string,
) (*FileTerminalExecutionStore, error) {
	directory, err := prepareStateDirectory(
		directory,
		ErrInvalidTerminalExecutionStore,
	)
	if err != nil {
		return nil, err
	}
	store := &FileTerminalExecutionStore{
		directory: directory,
		path:      filepath.Join(directory, "terminal-executions.json"),
		entries:   make(map[string]terminalExecution),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileTerminalExecutionStore) Add(entry terminalExecution) error {
	if !validTerminalExecution(entry) {
		return ErrInvalidTerminalExecutionStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.entries[entry.execID]; exists {
		if current != entry {
			return ErrInvalidTerminalExecutionStore
		}
		return nil
	}
	if len(s.entries) >= maximumTerminalExecutions {
		return ErrTerminalExecutionStoreFull
	}
	s.entries[entry.execID] = entry
	if err := s.persistLocked(); err != nil {
		delete(s.entries, entry.execID)
		return err
	}
	return nil
}

func (s *FileTerminalExecutionStore) Remove(execID string) error {
	if !terminalExecutionIDRule.MatchString(execID) {
		return ErrInvalidTerminalExecutionStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.entries[execID]
	if !exists {
		return nil
	}
	delete(s.entries, execID)
	if err := s.persistLocked(); err != nil {
		s.entries[execID] = entry
		return err
	}
	return nil
}

func (s *FileTerminalExecutionStore) List() ([]terminalExecution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	execIDs := make([]string, 0, len(s.entries))
	for execID := range s.entries {
		execIDs = append(execIDs, execID)
	}
	sort.Strings(execIDs)
	entries := make([]terminalExecution, 0, len(execIDs))
	for _, execID := range execIDs {
		entries = append(entries, s.entries[execID])
	}
	return entries, nil
}

func (s *FileTerminalExecutionStore) load() error {
	value, exists, err := readRestrictedStateFile(
		s.path,
		maximumTerminalExecutionStoreBytes,
		ErrInvalidTerminalExecutionStore,
	)
	if err != nil || !exists {
		return err
	}
	var document terminalExecutionStoreDocument
	if decodeStrictJSON(value, &document) != nil ||
		document.Version != terminalExecutionStoreVersion ||
		len(document.Entries) > maximumTerminalExecutions {
		return ErrInvalidTerminalExecutionStore
	}
	for _, entry := range document.Entries {
		domain := terminalExecution{
			execID: entry.ExecID, containerID: entry.ContainerID,
			marker: entry.Marker, shell: entry.Shell,
		}
		if !validTerminalExecution(domain) {
			return ErrInvalidTerminalExecutionStore
		}
		if _, duplicate := s.entries[entry.ExecID]; duplicate {
			return ErrInvalidTerminalExecutionStore
		}
		s.entries[entry.ExecID] = domain
	}
	return nil
}

func (s *FileTerminalExecutionStore) persistLocked() error {
	execIDs := make([]string, 0, len(s.entries))
	for execID := range s.entries {
		execIDs = append(execIDs, execID)
	}
	sort.Strings(execIDs)
	document := terminalExecutionStoreDocument{
		Version: terminalExecutionStoreVersion,
		Entries: make([]terminalExecutionStoreEntry, 0, len(execIDs)),
	}
	for _, execID := range execIDs {
		entry := s.entries[execID]
		document.Entries = append(document.Entries, terminalExecutionStoreEntry{
			ExecID: entry.execID, ContainerID: entry.containerID,
			Marker: entry.marker, Shell: entry.shell,
		})
	}
	value, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode Agent terminal execution store: %w", err)
	}
	if len(value) > maximumTerminalExecutionStoreBytes {
		return ErrTerminalExecutionStoreFull
	}
	return replaceRestrictedStateFile(
		s.directory,
		s.path,
		".terminal-executions-*",
		value,
	)
}

func validTerminalExecution(entry terminalExecution) bool {
	return terminalExecutionIDRule.MatchString(entry.execID) &&
		terminalExecutionIDRule.MatchString(entry.containerID) &&
		terminalMarkerRule.MatchString(entry.marker) &&
		(entry.shell == "/bin/sh" || entry.shell == "/bin/bash" ||
			entry.shell == "/bin/ash")
}

type terminalExecutionStoreDocument struct {
	Version int                           `json:"version"`
	Entries []terminalExecutionStoreEntry `json:"entries"`
}

type terminalExecutionStoreEntry struct {
	ExecID      string `json:"exec_id"`
	ContainerID string `json:"container_id"`
	Marker      string `json:"marker"`
	Shell       string `json:"shell"`
}
