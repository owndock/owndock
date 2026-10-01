package data

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	"github.com/owndock/owndock/internal/shared/agentprotocol"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const (
	reconciliationStateAllocated = "allocated"
	reconciliationStatePrepared  = "prepared"
	reconciliationActor          = "system:application-route-reconciliation"
)

// MongoReconciliationStore serializes Route-only config changes with
// Deployment cutovers and Route retirements on the same Host config document.
type MongoReconciliationStore MongoCutoverStore

func NewMongoReconciliationStore(
	database *mongo.Database,
	manager transaction.Manager,
	now func() time.Time,
) (*MongoReconciliationStore, error) {
	store, err := NewMongoCutoverStore(database, manager, now)
	if err != nil {
		return nil, applicationroutebiz.ErrReconciliationUnavailable
	}
	return (*MongoReconciliationStore)(store), nil
}

func (s *MongoReconciliationStore) WithAudit(
	recorder sharedaudit.Recorder,
	newID func() (string, error),
) *MongoReconciliationStore {
	s.audit, s.newID = recorder, newID
	return s
}

func (s *MongoReconciliationStore) Begin(
	ctx context.Context,
	requested applicationroutebiz.ApplicationRoute,
	backend applicationroutebiz.ActiveBackend,
) (applicationroutebiz.RouteReconciliationTransaction, bool, error) {
	var transactionValue applicationroutebiz.RouteReconciliationTransaction
	settled := false
	err := s.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var document routeDocument
		if err := s.routes.routes.FindOne(tx, bson.D{{Key: "_id", Value: requested.ID}}).
			Decode(&document); errors.Is(err, mongo.ErrNoDocuments) {
			return applicationroutebiz.ErrReconciliationConflict
		} else if err != nil {
			return fmt.Errorf("find application route for reconciliation: %w", err)
		}
		route, err := document.domain()
		if err != nil {
			return err
		}
		if route.OrganizationID != requested.OrganizationID || route.ProjectID != requested.ProjectID ||
			route.Revision != requested.Revision || !backendValidForRoute(backend, route) {
			return applicationroutebiz.ErrReconciliationConflict
		}
		if route.Status == applicationroutebiz.StatusReady && route.Observation != nil &&
			route.Observation.Revision == route.Revision &&
			route.Observation.DeploymentID == backend.DeploymentID &&
			route.Observation.CutoverSequence == backend.CutoverSequence {
			settled = true
			return nil
		}
		if route.Status != applicationroutebiz.StatusPending &&
			route.Status != applicationroutebiz.StatusProvisioning {
			return applicationroutebiz.ErrReconciliationConflict
		}

		var host hostConfigDocument
		hostErr := s.hostConfigs.FindOne(tx, bson.D{{Key: "_id", Value: backend.ManagedHostID}}).
			Decode(&host)
		hostExists := hostErr == nil
		if hostErr != nil && !errors.Is(hostErr, mongo.ErrNoDocuments) {
			return fmt.Errorf("find application route host for reconciliation: %w", hostErr)
		}
		if hostExists && host.OrganizationID != route.OrganizationID {
			return applicationroutebiz.ErrReconciliationConflict
		}
		if host.Reconciliation != nil {
			current, decodeErr := host.Reconciliation.domain(host.ID, host.OrganizationID)
			if decodeErr != nil {
				return decodeErr
			}
			if current.RouteID != route.ID || current.RouteRevision != route.Revision ||
				current.Backend != backend {
				return applicationroutebiz.ErrReconciliationPending
			}
			transactionValue = current
			return nil
		}
		if host.Pending != nil || host.Retirement != nil {
			return applicationroutebiz.ErrHostOperationPending
		}

		desired, desiredErr := buildReconciliationDesired(host, route, backend)
		if desiredErr != nil {
			return desiredErr
		}
		transactionValue = applicationroutebiz.RouteReconciliationTransaction{
			RouteID: route.ID, RouteRevision: route.Revision,
			OrganizationID: route.OrganizationID, Backend: backend, Desired: desired,
		}
		reconciliation := routeReconciliationDocumentFromDomain(transactionValue)
		reconciliation.State = reconciliationStateAllocated
		if !hostExists {
			_, hostErr = s.hostConfigs.InsertOne(tx, hostConfigDocument{
				ID: backend.ManagedHostID, OrganizationID: route.OrganizationID,
				Revision: desired.HostRevision, Reconciliation: reconciliation,
			})
		} else {
			var result *mongo.UpdateResult
			result, hostErr = s.hostConfigs.UpdateOne(tx, bson.D{
				{Key: "_id", Value: backend.ManagedHostID},
				{Key: "organization_id", Value: route.OrganizationID},
				{Key: "revision", Value: host.Revision},
				{Key: "pending", Value: bson.D{{Key: "$exists", Value: false}}},
				{Key: "retirement", Value: bson.D{{Key: "$exists", Value: false}}},
				{Key: "reconciliation", Value: bson.D{{Key: "$exists", Value: false}}},
			}, bson.D{{Key: "$set", Value: bson.D{
				{Key: "revision", Value: desired.HostRevision},
				{Key: "reconciliation", Value: reconciliation},
			}}})
			if hostErr == nil && result.ModifiedCount != 1 {
				hostErr = applicationroutebiz.ErrReconciliationPending
			}
		}
		if mongo.IsDuplicateKeyError(hostErr) {
			return applicationroutebiz.ErrReconciliationPending
		}
		if hostErr != nil {
			return fmt.Errorf("allocate application route reconciliation: %w", hostErr)
		}
		if route.Status == applicationroutebiz.StatusPending {
			next, transitionErr := route.Transition(
				applicationroutebiz.StatusProvisioning, reconciliationActor, s.now().UTC(),
			)
			if transitionErr != nil {
				return transitionErr
			}
			if _, saveErr := s.routes.Save(tx, next, route.Version); saveErr != nil {
				return saveErr
			}
			if auditErr := s.recordReconciliationAudit(
				tx, next, "application_route.provisioning",
			); auditErr != nil {
				return auditErr
			}
		}
		return nil
	})
	return transactionValue, settled, err
}

func backendValidForRoute(
	backend applicationroutebiz.ActiveBackend,
	route applicationroutebiz.ApplicationRoute,
) bool {
	return backend.OrganizationID == route.OrganizationID &&
		backend.ProjectID == route.ProjectID && backend.ApplicationID == route.ApplicationID &&
		backend.EnvironmentID == route.EnvironmentID &&
		backend.RuntimeTargetID == route.RuntimeTargetID &&
		backend.ManagedHostID != "" && backend.DeploymentID != "" &&
		backend.CutoverSequence > 0 && backend.Port > 0
}

func buildReconciliationDesired(
	host hostConfigDocument,
	route applicationroutebiz.ApplicationRoute,
	backend applicationroutebiz.ActiveBackend,
) (applicationroutebiz.HostDesiredConfig, error) {
	alias, err := agentprotocol.DeploymentBackendAlias(backend.DeploymentID)
	if err != nil {
		return applicationroutebiz.HostDesiredConfig{}, applicationroutebiz.ErrReconciliationConfiguration
	}
	byID := make(map[string]applicationroutebiz.GatewayRoute, len(host.Committed)+1)
	for _, committed := range host.Committed {
		domain := committed.domain()
		byID[domain.RouteID] = domain
	}
	byID[route.ID] = applicationroutebiz.GatewayRoute{
		RouteID: route.ID, Revision: route.Revision, DeploymentID: backend.DeploymentID,
		CutoverSequence: backend.CutoverSequence, RuntimeTargetID: route.RuntimeTargetID,
		Hostname: route.Hostname, BackendAlias: alias, BackendPort: backend.Port,
		TLSMode: route.TLSMode,
	}
	if len(byID) > agentprotocol.MaxIngressRoutes {
		return applicationroutebiz.HostDesiredConfig{}, applicationroutebiz.ErrReconciliationConfiguration
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	routes := make([]applicationroutebiz.GatewayRoute, 0, len(ids))
	for _, id := range ids {
		routes = append(routes, byID[id])
	}
	return applicationroutebiz.HostDesiredConfig{
		ManagedHostID: backend.ManagedHostID, HostRevision: host.Revision + 1,
		Routes: routes, ProbeRouteIDs: []string{route.ID},
	}, nil
}

func (s *MongoReconciliationStore) MarkPrepared(
	ctx context.Context,
	transactionValue applicationroutebiz.RouteReconciliationTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if observation.HostRevision != transactionValue.Desired.HostRevision ||
		observation.ConfigDigest == "" {
		return applicationroutebiz.ErrReconciliationConflict
	}
	result, err := s.hostConfigs.UpdateOne(ctx, reconciliationFilter(
		transactionValue,
		bson.D{{Key: "$in", Value: bson.A{reconciliationStateAllocated, reconciliationStatePrepared}}},
	), bson.D{{Key: "$set", Value: bson.D{
		{Key: "reconciliation.state", Value: reconciliationStatePrepared},
		{Key: "reconciliation.observation", Value: gatewayObservationDocument{
			HostRevision: observation.HostRevision, ConfigDigest: observation.ConfigDigest,
		}},
	}}})
	if err != nil {
		return fmt.Errorf("record prepared application route reconciliation: %w", err)
	}
	if result.MatchedCount != 1 {
		return applicationroutebiz.ErrReconciliationConflict
	}
	return nil
}

func (s *MongoReconciliationStore) Complete(
	ctx context.Context,
	transactionValue applicationroutebiz.RouteReconciliationTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if observation.HostRevision != transactionValue.Desired.HostRevision ||
		observation.ConfigDigest == "" {
		return applicationroutebiz.ErrReconciliationConflict
	}
	return s.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var document routeDocument
		if err := s.routes.routes.FindOne(tx, bson.D{
			{Key: "_id", Value: transactionValue.RouteID},
			{Key: "organization_id", Value: transactionValue.OrganizationID},
			{Key: "revision", Value: transactionValue.RouteRevision},
		}).Decode(&document); err != nil {
			return applicationroutebiz.ErrReconciliationConflict
		}
		route, err := document.domain()
		if err != nil || route.Status != applicationroutebiz.StatusProvisioning {
			return applicationroutebiz.ErrReconciliationConflict
		}
		certificate := applicationroutebiz.CertificateStatusNotApplicable
		if route.TLSMode == applicationroutebiz.TLSModeAutomatic {
			certificate = applicationroutebiz.CertificateStatusReady
		}
		ready, err := route.ObserveReady(applicationroutebiz.Observation{
			Revision: route.Revision, DeploymentID: transactionValue.Backend.DeploymentID,
			CutoverSequence: transactionValue.Backend.CutoverSequence,
			ConfigDigest:    observation.ConfigDigest, CertificateStatus: certificate,
			ObservedAt: s.now().UTC(),
		}, reconciliationActor, s.now().UTC())
		if err != nil {
			return err
		}
		if _, err := s.routes.Save(tx, ready, route.Version); err != nil {
			return err
		}
		if err := s.recordReconciliationAudit(tx, ready, "application_route.ready"); err != nil {
			return err
		}
		committed := make([]gatewayRouteDocument, len(transactionValue.Desired.Routes))
		for index, desiredRoute := range transactionValue.Desired.Routes {
			committed[index] = gatewayRouteDocumentFromDomain(desiredRoute)
		}
		result, err := s.hostConfigs.UpdateOne(tx, reconciliationFilter(
			transactionValue, reconciliationStatePrepared,
		), bson.D{
			{Key: "$set", Value: bson.D{{Key: "committed", Value: committed}}},
			{Key: "$unset", Value: bson.D{{Key: "reconciliation", Value: ""}}},
		})
		if err != nil {
			return fmt.Errorf("complete application route reconciliation: %w", err)
		}
		if result.MatchedCount != 1 {
			return applicationroutebiz.ErrReconciliationConflict
		}
		return nil
	})
}

func (s *MongoReconciliationStore) Abort(
	ctx context.Context,
	transactionValue applicationroutebiz.RouteReconciliationTransaction,
	failure applicationroutebiz.FailureCode,
) error {
	if !failure.Valid() {
		failure = applicationroutebiz.FailureUnknown
	}
	return s.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var document routeDocument
		if err := s.routes.routes.FindOne(tx, bson.D{
			{Key: "_id", Value: transactionValue.RouteID},
			{Key: "organization_id", Value: transactionValue.OrganizationID},
			{Key: "revision", Value: transactionValue.RouteRevision},
		}).Decode(&document); err != nil {
			return applicationroutebiz.ErrReconciliationConflict
		}
		route, err := document.domain()
		if err != nil || route.Status != applicationroutebiz.StatusProvisioning {
			return applicationroutebiz.ErrReconciliationConflict
		}
		degraded, err := route.Degrade(failure, reconciliationActor, s.now().UTC())
		if err != nil {
			return err
		}
		if _, err := s.routes.Save(tx, degraded, route.Version); err != nil {
			return err
		}
		if err := s.recordReconciliationAudit(tx, degraded, "application_route.degraded"); err != nil {
			return err
		}
		result, err := s.hostConfigs.UpdateOne(tx, reconciliationFilter(
			transactionValue,
			bson.D{{Key: "$in", Value: bson.A{reconciliationStateAllocated, reconciliationStatePrepared}}},
		), bson.D{{Key: "$unset", Value: bson.D{{Key: "reconciliation", Value: ""}}}})
		if err != nil {
			return fmt.Errorf("abort application route reconciliation: %w", err)
		}
		if result.MatchedCount != 1 {
			return applicationroutebiz.ErrReconciliationConflict
		}
		return nil
	})
}

func (s *MongoReconciliationStore) Degrade(
	ctx context.Context,
	requested applicationroutebiz.ApplicationRoute,
	failure applicationroutebiz.FailureCode,
) error {
	if !failure.Valid() {
		return applicationroutebiz.ErrReconciliationConfiguration
	}
	return s.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var document routeDocument
		if err := s.routes.routes.FindOne(tx, bson.D{
			{Key: "_id", Value: requested.ID},
			{Key: "organization_id", Value: requested.OrganizationID},
			{Key: "revision", Value: requested.Revision},
		}).Decode(&document); err != nil {
			return applicationroutebiz.ErrReconciliationConflict
		}
		route, err := document.domain()
		if err != nil {
			return err
		}
		if route.Status == applicationroutebiz.StatusDegraded && route.FailureCode == failure {
			return nil
		}
		if route.Status != applicationroutebiz.StatusPending {
			return applicationroutebiz.ErrReconciliationConflict
		}
		degraded, err := route.Degrade(failure, reconciliationActor, s.now().UTC())
		if err != nil {
			return err
		}
		if _, err := s.routes.Save(tx, degraded, route.Version); err != nil {
			return err
		}
		return s.recordReconciliationAudit(tx, degraded, "application_route.degraded")
	})
}

func (s *MongoReconciliationStore) recordReconciliationAudit(
	ctx context.Context,
	route applicationroutebiz.ApplicationRoute,
	action string,
) error {
	if s.audit == nil && s.newID == nil {
		return nil
	}
	if s.audit == nil || s.newID == nil {
		return applicationroutebiz.ErrReconciliationUnavailable
	}
	auditID, err := s.newID()
	if err != nil {
		return err
	}
	return s.audit.Record(ctx, sharedaudit.Event{
		ID: auditID, OrganizationID: route.OrganizationID, ProjectID: route.ProjectID,
		ActorID: reconciliationActor, Action: action, ResourceType: "application_route",
		ResourceID: route.ID, CreatedAt: route.UpdatedAt,
	})
}

func reconciliationFilter(
	transactionValue applicationroutebiz.RouteReconciliationTransaction,
	state any,
) bson.D {
	return bson.D{
		{Key: "_id", Value: transactionValue.Desired.ManagedHostID},
		{Key: "organization_id", Value: transactionValue.OrganizationID},
		{Key: "reconciliation.route_id", Value: transactionValue.RouteID},
		{Key: "reconciliation.route_revision", Value: transactionValue.RouteRevision},
		{Key: "reconciliation.desired.host_revision", Value: transactionValue.Desired.HostRevision},
		{Key: "reconciliation.state", Value: state},
	}
}

type routeReconciliationDocument struct {
	RouteID       string                      `bson:"route_id"`
	RouteRevision uint64                      `bson:"route_revision"`
	Backend       activeBackendDocument       `bson:"backend"`
	Desired       hostDesiredDocument         `bson:"desired"`
	State         string                      `bson:"state"`
	Observation   *gatewayObservationDocument `bson:"observation,omitempty"`
}

type activeBackendDocument struct {
	OrganizationID  string `bson:"organization_id"`
	ProjectID       string `bson:"project_id"`
	ApplicationID   string `bson:"application_id"`
	EnvironmentID   string `bson:"environment_id"`
	RuntimeTargetID string `bson:"runtime_target_id"`
	ManagedHostID   string `bson:"managed_host_id"`
	DeploymentID    string `bson:"deployment_id"`
	CutoverSequence uint64 `bson:"cutover_sequence"`
	Port            uint16 `bson:"port"`
}

func routeReconciliationDocumentFromDomain(
	value applicationroutebiz.RouteReconciliationTransaction,
) *routeReconciliationDocument {
	routes := make([]gatewayRouteDocument, len(value.Desired.Routes))
	for index, route := range value.Desired.Routes {
		routes[index] = gatewayRouteDocumentFromDomain(route)
	}
	return &routeReconciliationDocument{
		RouteID: value.RouteID, RouteRevision: value.RouteRevision,
		Backend: activeBackendDocumentFromDomain(value.Backend),
		Desired: hostDesiredDocument{HostRevision: value.Desired.HostRevision,
			Routes: routes, ProbeRouteIDs: append([]string(nil), value.Desired.ProbeRouteIDs...)},
	}
}

func activeBackendDocumentFromDomain(value applicationroutebiz.ActiveBackend) activeBackendDocument {
	return activeBackendDocument{
		OrganizationID: value.OrganizationID, ProjectID: value.ProjectID,
		ApplicationID: value.ApplicationID, EnvironmentID: value.EnvironmentID,
		RuntimeTargetID: value.RuntimeTargetID, ManagedHostID: value.ManagedHostID,
		DeploymentID: value.DeploymentID, CutoverSequence: value.CutoverSequence,
		Port: value.Port,
	}
}

func (d activeBackendDocument) domain() applicationroutebiz.ActiveBackend {
	return applicationroutebiz.ActiveBackend{
		OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		ApplicationID: d.ApplicationID, EnvironmentID: d.EnvironmentID,
		RuntimeTargetID: d.RuntimeTargetID, ManagedHostID: d.ManagedHostID,
		DeploymentID: d.DeploymentID, CutoverSequence: d.CutoverSequence, Port: d.Port,
	}
}

func (d *routeReconciliationDocument) domain(
	managedHostID, organizationID string,
) (applicationroutebiz.RouteReconciliationTransaction, error) {
	if d == nil || d.RouteID == "" || d.RouteRevision == 0 || d.Desired.HostRevision == 0 ||
		(d.State != reconciliationStateAllocated && d.State != reconciliationStatePrepared) {
		return applicationroutebiz.RouteReconciliationTransaction{}, applicationroutebiz.ErrReconciliationConflict
	}
	routes := make([]applicationroutebiz.GatewayRoute, len(d.Desired.Routes))
	for index, route := range d.Desired.Routes {
		routes[index] = route.domain()
	}
	backend := d.Backend.domain()
	if backend.ManagedHostID != managedHostID || backend.OrganizationID != organizationID {
		return applicationroutebiz.RouteReconciliationTransaction{}, applicationroutebiz.ErrReconciliationConflict
	}
	return applicationroutebiz.RouteReconciliationTransaction{
		RouteID: d.RouteID, RouteRevision: d.RouteRevision, OrganizationID: organizationID,
		Backend: backend,
		Desired: applicationroutebiz.HostDesiredConfig{
			ManagedHostID: managedHostID, HostRevision: d.Desired.HostRevision,
			Routes: routes, ProbeRouteIDs: append([]string(nil), d.Desired.ProbeRouteIDs...),
		},
		Prepared: d.State == reconciliationStatePrepared,
	}, nil
}

var _ applicationroutebiz.RouteReconciliationStore = (*MongoReconciliationStore)(nil)
