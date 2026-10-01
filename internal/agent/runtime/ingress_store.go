package agentruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const ingressStoreVersion = 1
const maximumIngressStoreBytes = 4 * 1024 * 1024

var (
	ErrInvalidIngressStore  = errors.New("agent ingress fence store is invalid")
	ErrIngressStoreFull     = errors.New("agent ingress fence store is full")
	ErrIngressFenceStale    = errors.New("agent ingress fence is stale")
	ErrIngressFenceConflict = errors.New("agent ingress fence conflicts")
)

var (
	ingressStateDigest     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	ingressStateIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type IngressFenceStore interface {
	Check(agentprotocol.IngressCommand) (idempotent bool, err error)
	Commit(agentprotocol.IngressCommand) error
}

type ingressFence struct {
	revision        uint64
	deploymentID    string
	cutoverSequence uint64
	specDigest      string
	active          bool
}

// FileIngressFenceStore retains every Route high-water mark independently of
// the current active gateway config. Removing a route from a complete config
// therefore cannot let a delayed command reintroduce it after Agent restart.
type FileIngressFenceStore struct {
	mu sync.Mutex

	directory    string
	path         string
	maximum      int
	hostRevision uint64
	configDigest string
	entries      map[string]ingressFence
}

func NewFileIngressFenceStore(directory string, maximum int) (*FileIngressFenceStore, error) {
	if maximum < 1 || maximum > 65536 {
		return nil, ErrInvalidIngressStore
	}
	directory, err := prepareStateDirectory(directory, ErrInvalidIngressStore)
	if err != nil {
		return nil, err
	}
	store := &FileIngressFenceStore{directory: directory,
		path: filepath.Join(directory, "ingress-fences.json"), maximum: maximum,
		entries: make(map[string]ingressFence)}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileIngressFenceStore) Check(command agentprotocol.IngressCommand) (bool, error) {
	if command.Validate() != nil {
		return false, ErrInvalidIngressStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkLocked(command)
}

func (s *FileIngressFenceStore) checkLocked(command agentprotocol.IngressCommand) (bool, error) {
	if command.HostRevision < s.hostRevision {
		return false, ErrIngressFenceStale
	}
	if command.HostRevision == s.hostRevision {
		if command.ConfigDigest == s.configDigest && s.hostRevision != 0 {
			return true, nil
		}
		return false, ErrIngressFenceConflict
	}
	newEntries := 0
	for _, route := range command.Routes {
		current, exists := s.entries[route.RouteID]
		if !exists {
			newEntries++
			continue
		}
		specDigest, _ := agentprotocol.IngressRouteSpecDigest(route)
		if route.Revision < current.revision || route.CutoverSequence < current.cutoverSequence {
			return false, ErrIngressFenceStale
		}
		if !current.active && route.Revision == current.revision {
			return false, ErrIngressFenceConflict
		}
		if (route.Revision == current.revision && specDigest != current.specDigest) ||
			(route.CutoverSequence == current.cutoverSequence && route.DeploymentID != current.deploymentID) {
			return false, ErrIngressFenceConflict
		}
	}
	if len(s.entries)+newEntries > s.maximum {
		return false, ErrIngressStoreFull
	}
	return false, nil
}

func (s *FileIngressFenceStore) Commit(command agentprotocol.IngressCommand) error {
	if command.Validate() != nil {
		return ErrInvalidIngressStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idempotent, err := s.checkLocked(command)
	if err != nil || idempotent {
		return err
	}
	oldRevision, oldDigest := s.hostRevision, s.configDigest
	oldEntries := make(map[string]ingressFence, len(s.entries))
	for id, entry := range s.entries {
		oldEntries[id] = entry
	}
	s.hostRevision, s.configDigest = command.HostRevision, command.ConfigDigest
	for id, entry := range s.entries {
		entry.active = false
		s.entries[id] = entry
	}
	for _, route := range command.Routes {
		specDigest, _ := agentprotocol.IngressRouteSpecDigest(route)
		s.entries[route.RouteID] = ingressFence{revision: route.Revision,
			deploymentID: route.DeploymentID, cutoverSequence: route.CutoverSequence,
			specDigest: specDigest, active: true}
	}
	if err := s.persistLocked(); err != nil {
		s.hostRevision, s.configDigest, s.entries = oldRevision, oldDigest, oldEntries
		return err
	}
	return nil
}

func (s *FileIngressFenceStore) load() error {
	value, exists, err := readRestrictedStateFile(s.path, maximumIngressStoreBytes, ErrInvalidIngressStore)
	if err != nil || !exists {
		return err
	}
	var document ingressStoreDocument
	if decodeStrictJSON(value, &document) != nil || document.Version != ingressStoreVersion ||
		document.HostRevision == 0 || !ingressStateDigest.MatchString(document.ConfigDigest) ||
		len(document.Entries) > s.maximum {
		return ErrInvalidIngressStore
	}
	for _, entry := range document.Entries {
		if !validIngressStoreEntry(entry) {
			return ErrInvalidIngressStore
		}
		if _, duplicate := s.entries[entry.RouteID]; duplicate {
			return ErrInvalidIngressStore
		}
		s.entries[entry.RouteID] = ingressFence{revision: entry.Revision,
			deploymentID: entry.DeploymentID, cutoverSequence: entry.CutoverSequence,
			specDigest: entry.SpecDigest, active: entry.Active}
	}
	s.hostRevision, s.configDigest = document.HostRevision, document.ConfigDigest
	return nil
}

func (s *FileIngressFenceStore) persistLocked() error {
	ids := make([]string, 0, len(s.entries))
	for id := range s.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	document := ingressStoreDocument{Version: ingressStoreVersion,
		HostRevision: s.hostRevision, ConfigDigest: s.configDigest,
		Entries: make([]ingressStoreEntryDocument, 0, len(ids))}
	for _, id := range ids {
		entry := s.entries[id]
		document.Entries = append(document.Entries, ingressStoreEntryDocument{RouteID: id,
			Revision: entry.revision, DeploymentID: entry.deploymentID,
			CutoverSequence: entry.cutoverSequence, SpecDigest: entry.specDigest, Active: entry.active})
	}
	value, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode Agent ingress fence store: %w", err)
	}
	if len(value) > maximumIngressStoreBytes {
		return ErrIngressStoreFull
	}
	return replaceRestrictedStateFile(s.directory, s.path, ".ingress-fences-*", value)
}

func validIngressStoreEntry(entry ingressStoreEntryDocument) bool {
	return ingressStateIdentifier.MatchString(entry.RouteID) && entry.Revision > 0 &&
		ingressStateIdentifier.MatchString(entry.DeploymentID) &&
		entry.CutoverSequence > 0 && ingressStateDigest.MatchString(entry.SpecDigest)
}

type ingressStoreDocument struct {
	Version      int                         `json:"version"`
	HostRevision uint64                      `json:"host_revision"`
	ConfigDigest string                      `json:"config_digest"`
	Entries      []ingressStoreEntryDocument `json:"entries"`
}

type ingressStoreEntryDocument struct {
	RouteID         string `json:"route_id"`
	Revision        uint64 `json:"revision"`
	DeploymentID    string `json:"deployment_id"`
	CutoverSequence uint64 `json:"cutover_sequence"`
	SpecDigest      string `json:"spec_digest"`
	Active          bool   `json:"active"`
}

var _ IngressFenceStore = (*FileIngressFenceStore)(nil)
