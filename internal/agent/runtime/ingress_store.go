package agentruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"sync"

	"github.com/owndock/owndock/internal/shared/agentprotocol"
)

const ingressStoreVersion = 2
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

type IngressPrepareState uint8

const (
	IngressPrepareNew IngressPrepareState = iota + 1
	IngressPreparePending
	IngressPrepareCommitted
)

type IngressFenceStore interface {
	Begin(agentprotocol.IngressCommand) (IngressPrepareState, error)
	CanCommit(agentprotocol.IngressCommand) (alreadyCommitted bool, err error)
	CanAbort(agentprotocol.IngressCommand) (alreadyAborted bool, err error)
	Commit(agentprotocol.IngressCommand) error
	Abort(agentprotocol.IngressCommand) error
	Committed() (agentprotocol.IngressCommand, bool)
}

func (s *FileIngressFenceStore) CanCommit(command agentprotocol.IngressCommand) (bool, error) {
	if command.Validate() != nil {
		return false, ErrInvalidIngressStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.committed != nil && sameIngressConfig(*s.committed, command) {
		return true, nil
	}
	if s.pending == nil || !sameIngressConfig(*s.pending, command) {
		return false, ErrIngressFenceConflict
	}
	return false, nil
}

func (s *FileIngressFenceStore) CanAbort(command agentprotocol.IngressCommand) (bool, error) {
	if command.Validate() != nil {
		return false, ErrInvalidIngressStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.committed != nil && sameIngressConfig(*s.committed, command) {
		return false, ErrIngressFenceConflict
	}
	if s.pending == nil {
		if s.committed == nil || command.HostRevision > s.committed.HostRevision {
			return true, nil
		}
		return false, ErrIngressFenceStale
	}
	if !sameIngressConfig(*s.pending, command) {
		return false, ErrIngressFenceConflict
	}
	return false, nil
}

type ingressFence struct {
	revision        uint64
	deploymentID    string
	cutoverSequence uint64
	specDigest      string
	active          bool
}

// FileIngressFenceStore persists both sides of the Agent ingress transaction.
// Prepared state is not promoted to irreversible Host/Route watermarks until
// Server commits its Mongo transaction and sends the matching commit command.
type FileIngressFenceStore struct {
	mu sync.Mutex

	directory string
	path      string
	maximum   int
	committed *agentprotocol.IngressCommand
	pending   *agentprotocol.IngressCommand
	entries   map[string]ingressFence
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

func (s *FileIngressFenceStore) Begin(command agentprotocol.IngressCommand) (IngressPrepareState, error) {
	if command.Validate() != nil {
		return 0, ErrInvalidIngressStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil {
		if sameIngressConfig(*s.pending, command) {
			return IngressPreparePending, nil
		}
		return 0, ErrIngressFenceConflict
	}
	if s.committed != nil && sameIngressConfig(*s.committed, command) {
		return IngressPrepareCommitted, nil
	}
	if err := s.checkCandidateLocked(command); err != nil {
		return 0, err
	}
	s.pending = cloneIngressCommand(&command)
	if err := s.persistLocked(); err != nil {
		s.pending = nil
		return 0, err
	}
	return IngressPrepareNew, nil
}

func (s *FileIngressFenceStore) checkCandidateLocked(command agentprotocol.IngressCommand) error {
	if s.committed != nil {
		if command.HostRevision < s.committed.HostRevision {
			return ErrIngressFenceStale
		}
		if command.HostRevision == s.committed.HostRevision {
			return ErrIngressFenceConflict
		}
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
			return ErrIngressFenceStale
		}
		if !current.active && route.Revision == current.revision {
			return ErrIngressFenceConflict
		}
		if route.Revision == current.revision && specDigest != current.specDigest ||
			route.CutoverSequence == current.cutoverSequence && route.DeploymentID != current.deploymentID {
			return ErrIngressFenceConflict
		}
	}
	if len(s.entries)+newEntries > s.maximum {
		return ErrIngressStoreFull
	}
	return nil
}

func (s *FileIngressFenceStore) Commit(command agentprotocol.IngressCommand) error {
	if command.Validate() != nil {
		return ErrInvalidIngressStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.committed != nil && sameIngressConfig(*s.committed, command) {
		return nil
	}
	if s.pending == nil || !sameIngressConfig(*s.pending, command) {
		return ErrIngressFenceConflict
	}
	oldCommitted := cloneIngressCommand(s.committed)
	oldPending := cloneIngressCommand(s.pending)
	oldEntries := cloneIngressEntries(s.entries)
	s.committed = cloneIngressCommand(&command)
	s.pending = nil
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
		s.committed, s.pending, s.entries = oldCommitted, oldPending, oldEntries
		return err
	}
	return nil
}

func (s *FileIngressFenceStore) Abort(command agentprotocol.IngressCommand) error {
	if command.Validate() != nil {
		return ErrInvalidIngressStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.committed != nil && sameIngressConfig(*s.committed, command) {
		return ErrIngressFenceConflict
	}
	if s.pending == nil {
		if s.committed == nil || command.HostRevision > s.committed.HostRevision {
			return nil
		}
		return ErrIngressFenceStale
	}
	if !sameIngressConfig(*s.pending, command) {
		return ErrIngressFenceConflict
	}
	oldPending := s.pending
	s.pending = nil
	if err := s.persistLocked(); err != nil {
		s.pending = oldPending
		return err
	}
	return nil
}

func (s *FileIngressFenceStore) Committed() (agentprotocol.IngressCommand, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.committed == nil {
		return agentprotocol.IngressCommand{}, false
	}
	return *cloneIngressCommand(s.committed), true
}

func sameIngressConfig(left, right agentprotocol.IngressCommand) bool {
	return left.HostRevision == right.HostRevision && left.ConfigDigest == right.ConfigDigest &&
		slices.Equal(left.ProbeRouteIDs, right.ProbeRouteIDs)
}

func cloneIngressCommand(value *agentprotocol.IngressCommand) *agentprotocol.IngressCommand {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Routes = append([]agentprotocol.IngressRoute(nil), value.Routes...)
	cloned.ProbeRouteIDs = append([]string(nil), value.ProbeRouteIDs...)
	return &cloned
}

func cloneIngressEntries(entries map[string]ingressFence) map[string]ingressFence {
	cloned := make(map[string]ingressFence, len(entries))
	for id, entry := range entries {
		cloned[id] = entry
	}
	return cloned
}

func (s *FileIngressFenceStore) load() error {
	value, exists, err := readRestrictedStateFile(s.path, maximumIngressStoreBytes, ErrInvalidIngressStore)
	if err != nil || !exists {
		return err
	}
	var document ingressStoreDocument
	if decodeStrictJSON(value, &document) != nil || document.Version != ingressStoreVersion ||
		len(document.Entries) > s.maximum {
		return ErrInvalidIngressStore
	}
	s.committed, err = document.Committed.domain()
	if err != nil {
		return err
	}
	s.pending, err = document.Pending.domain()
	if err != nil {
		return err
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
	if !s.validLoadedState() {
		return ErrInvalidIngressStore
	}
	return nil
}

func (s *FileIngressFenceStore) validLoadedState() bool {
	active := make(map[string]agentprotocol.IngressRoute)
	if s.committed != nil {
		for _, route := range s.committed.Routes {
			active[route.RouteID] = route
		}
	}
	for id, entry := range s.entries {
		route, exists := active[id]
		if entry.active != exists {
			return false
		}
		if exists {
			specDigest, _ := agentprotocol.IngressRouteSpecDigest(route)
			if entry.revision != route.Revision || entry.deploymentID != route.DeploymentID ||
				entry.cutoverSequence != route.CutoverSequence || entry.specDigest != specDigest {
				return false
			}
		}
	}
	for id := range active {
		if _, exists := s.entries[id]; !exists {
			return false
		}
	}
	if s.pending != nil {
		if s.committed != nil && s.pending.HostRevision <= s.committed.HostRevision {
			return false
		}
		return s.checkCandidateLocked(*s.pending) == nil
	}
	return true
}

func (s *FileIngressFenceStore) persistLocked() error {
	ids := make([]string, 0, len(s.entries))
	for id := range s.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	document := ingressStoreDocument{Version: ingressStoreVersion,
		Committed: ingressConfigDocumentFromDomain(s.committed),
		Pending:   ingressConfigDocumentFromDomain(s.pending),
		Entries:   make([]ingressStoreEntryDocument, 0, len(ids))}
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
	Version   int                         `json:"version"`
	Committed *ingressConfigDocument      `json:"committed,omitempty"`
	Pending   *ingressConfigDocument      `json:"pending,omitempty"`
	Entries   []ingressStoreEntryDocument `json:"entries"`
}

type ingressConfigDocument struct {
	HostRevision  uint64                 `json:"host_revision"`
	ConfigDigest  string                 `json:"config_digest"`
	Routes        []ingressRouteDocument `json:"routes"`
	ProbeRouteIDs []string               `json:"probe_route_ids,omitempty"`
}

type ingressRouteDocument struct {
	RouteID         string                       `json:"route_id"`
	Revision        uint64                       `json:"revision"`
	DeploymentID    string                       `json:"deployment_id"`
	CutoverSequence uint64                       `json:"cutover_sequence"`
	RuntimeTargetID string                       `json:"runtime_target_id"`
	Hostname        string                       `json:"hostname"`
	BackendAlias    string                       `json:"backend_alias"`
	BackendPort     uint16                       `json:"backend_port"`
	TLSMode         agentprotocol.IngressTLSMode `json:"tls_mode"`
}

func ingressConfigDocumentFromDomain(value *agentprotocol.IngressCommand) *ingressConfigDocument {
	if value == nil {
		return nil
	}
	document := &ingressConfigDocument{HostRevision: value.HostRevision,
		ConfigDigest: value.ConfigDigest, Routes: make([]ingressRouteDocument, len(value.Routes)),
		ProbeRouteIDs: append([]string(nil), value.ProbeRouteIDs...)}
	for index, route := range value.Routes {
		document.Routes[index] = ingressRouteDocument{RouteID: route.RouteID,
			Revision: route.Revision, DeploymentID: route.DeploymentID,
			CutoverSequence: route.CutoverSequence, RuntimeTargetID: route.RuntimeTargetID,
			Hostname: route.Hostname, BackendAlias: route.BackendAlias,
			BackendPort: route.BackendPort, TLSMode: route.TLSMode}
	}
	return document
}

func (d *ingressConfigDocument) domain() (*agentprotocol.IngressCommand, error) {
	if d == nil {
		return nil, nil
	}
	command := &agentprotocol.IngressCommand{HostRevision: d.HostRevision,
		ConfigDigest: d.ConfigDigest, Routes: make([]agentprotocol.IngressRoute, len(d.Routes)),
		ProbeRouteIDs: append([]string(nil), d.ProbeRouteIDs...)}
	for index, route := range d.Routes {
		command.Routes[index] = agentprotocol.IngressRoute{RouteID: route.RouteID,
			Revision: route.Revision, DeploymentID: route.DeploymentID,
			CutoverSequence: route.CutoverSequence, RuntimeTargetID: route.RuntimeTargetID,
			Hostname: route.Hostname, BackendAlias: route.BackendAlias,
			BackendPort: route.BackendPort, TLSMode: route.TLSMode}
	}
	if command.Validate() != nil {
		return nil, ErrInvalidIngressStore
	}
	return command, nil
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
