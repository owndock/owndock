package data

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/adapters/dockerengine"
	"github.com/owndock/owndock/internal/adapters/dockerinventory"
	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	transport "github.com/owndock/owndock/internal/shared/runtimeinventory"
	"github.com/owndock/owndock/internal/shared/secretref"
)

var (
	ErrDirectCredentialUnavailable = errors.New(
		"direct runtime inventory credential is unavailable",
	)
	ErrInvalidDirectCollector = errors.New(
		"direct runtime inventory collector is invalid",
	)
)

type DirectCredentialResolver interface {
	ResolveDirectCredential(
		context.Context,
		runtimeaccess.Connection,
	) (dockerengine.TLSCredential, error)
}

type DirectEngine interface {
	dockerinventory.Engine
	dockerinventory.EventEngine
	Close() error
}

type DirectEngineFactory func(
	runtimeaccess.Connection,
	dockerengine.TLSCredential,
) (DirectEngine, error)

// DirectTargetCollector resolves a credential only for the duration of a
// single collection and builds a fresh Docker client. The persisted Target and
// observation never contain PEM material.
type DirectTargetCollector struct {
	credentials   DirectCredentialResolver
	repository    biz.Repository
	newID         func() (string, error)
	now           func() time.Time
	maxChunkBytes int
	openEngine    DirectEngineFactory
	eventHints    biz.EventHintRepository
}

func (c *DirectTargetCollector) WithEventHints(
	repository biz.EventHintRepository,
) *DirectTargetCollector {
	c.eventHints = repository
	return c
}

func NewDirectTargetCollector(
	credentials DirectCredentialResolver,
	repository biz.Repository,
	newID func() (string, error),
	now func() time.Time,
	maxChunkBytes int,
) (*DirectTargetCollector, error) {
	if credentials == nil || repository == nil || newID == nil || now == nil ||
		maxChunkBytes < 4*1024 || maxChunkBytes > transport.MaxChunkBytes {
		return nil, ErrInvalidDirectCollector
	}
	collector := &DirectTargetCollector{
		credentials: credentials, repository: repository,
		newID: newID, now: now, maxChunkBytes: maxChunkBytes,
		openEngine: func(
			connection runtimeaccess.Connection,
			credential dockerengine.TLSCredential,
		) (DirectEngine, error) {
			return dockerengine.NewTLS(connection, credential)
		},
	}
	return collector, nil
}

func (c *DirectTargetCollector) Collect(
	ctx context.Context,
	target biz.Target,
) error {
	if err := target.Validate(); err != nil ||
		target.Connection.Mode != runtimeaccess.ModeDirectDocker {
		return biz.ErrInvalidTarget
	}
	credential, err := c.credentials.ResolveDirectCredential(
		ctx,
		target.Connection,
	)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return ErrDirectCredentialUnavailable
	}
	defer clearDirectCredential(&credential)
	engine, err := c.openEngine(target.Connection, credential)
	if err != nil {
		return fmt.Errorf("%w: create Docker client", ErrDirectInventoryUnavailable)
	}
	defer func() { _ = engine.Close() }()
	eventSince := c.now().UTC()
	collector, err := NewDirectCollector(
		dockerinventory.NewReader(engine),
		c.repository,
		c.newID,
		c.now,
		c.maxChunkBytes,
	)
	if err != nil {
		return err
	}
	if err := collector.Synchronize(
		ctx,
		target.OrganizationID,
		target.ManagedHostID,
		target.RuntimeTargetID,
	); err != nil {
		return err
	}
	return c.recordSnapshotWindowEvents(ctx, target, engine, eventSince)
}

func (c *DirectTargetCollector) recordSnapshotWindowEvents(
	ctx context.Context,
	target biz.Target,
	engine dockerinventory.EventEngine,
	since time.Time,
) error {
	if c.eventHints == nil {
		return nil
	}
	receivedAt := c.now().UTC()
	if !receivedAt.After(since) {
		return nil
	}
	batch, err := dockerinventory.NewEventReader(engine).ReadWindow(
		ctx,
		since,
		receivedAt,
		transport.MaxEventsPerWindow,
	)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return fmt.Errorf("%w: read Docker event window", ErrDirectInventoryUnavailable)
	}
	for _, event := range batch.Events {
		hint, err := biz.NewEventHint(
			target.OrganizationID,
			target.RuntimeTargetID,
			biz.Kind(event.Kind),
			event.RuntimeID,
			biz.EventAction(event.Action),
			event.OccurredAt,
			receivedAt,
		)
		if err != nil {
			return fmt.Errorf("%w: project Docker event", ErrDirectInventoryUnavailable)
		}
		if err := c.eventHints.RecordEventHint(ctx, hint); err != nil {
			return err
		}
	}
	return nil
}

type EnvironmentDirectCredentialResolver struct {
	lookup func(string) (string, bool)
}

func NewEnvironmentDirectCredentialResolver() *EnvironmentDirectCredentialResolver {
	return &EnvironmentDirectCredentialResolver{lookup: os.LookupEnv}
}

func (r *EnvironmentDirectCredentialResolver) ResolveDirectCredential(
	ctx context.Context,
	connection runtimeaccess.Connection,
) (dockerengine.TLSCredential, error) {
	if err := ctx.Err(); err != nil {
		return dockerengine.TLSCredential{}, err
	}
	if err := connection.Validate(); err != nil ||
		connection.Mode != runtimeaccess.ModeDirectDocker {
		return dockerengine.TLSCredential{}, ErrDirectCredentialUnavailable
	}
	alias, err := secretref.Alias(connection.DirectDocker.CredentialRef)
	if err != nil {
		return dockerengine.TLSCredential{}, ErrDirectCredentialUnavailable
	}
	prefix := "OWNDOCK_RUNTIME_" +
		strings.ToUpper(strings.ReplaceAll(alias, "-", "_"))
	values := make([][]byte, 3)
	for index, suffix := range []string{"_CA_PEM", "_CERT_PEM", "_KEY_PEM"} {
		value, ok := r.lookup(prefix + suffix)
		if !ok || strings.TrimSpace(value) == "" {
			clearByteSlices(values...)
			return dockerengine.TLSCredential{}, ErrDirectCredentialUnavailable
		}
		values[index] = []byte(value)
	}
	return dockerengine.TLSCredential{
		CACertificate: values[0], ClientCertificate: values[1], ClientKey: values[2],
	}, nil
}

func clearDirectCredential(credential *dockerengine.TLSCredential) {
	clearByteSlices(
		credential.CACertificate,
		credential.ClientCertificate,
		credential.ClientKey,
	)
}

func clearByteSlices(values ...[]byte) {
	for _, value := range values {
		for index := range value {
			value[index] = 0
		}
	}
}

var _ biz.Collector = (*DirectTargetCollector)(nil)
