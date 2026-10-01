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
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	cutoverStateAllocated             = "allocated"
	cutoverStatePrepared              = "prepared"
	cutoverStateControlPlaneCommitted = "control_plane_committed"
	cutoverStateGatewayCommitted      = "gateway_committed"
)

type MongoCutoverStore struct {
	routes      *MongoRepository
	hostConfigs *mongo.Collection
	transaction transaction.Manager
	now         func() time.Time
	audit       sharedaudit.Recorder
	newID       func() (string, error)
}

func (s *MongoCutoverStore) WithAudit(
	recorder sharedaudit.Recorder,
	newID func() (string, error),
) *MongoCutoverStore {
	s.audit, s.newID = recorder, newID
	return s
}

func NewMongoCutoverStore(
	database *mongo.Database,
	manager transaction.Manager,
	now func() time.Time,
) (*MongoCutoverStore, error) {
	if database == nil || manager == nil || now == nil {
		return nil, applicationroutebiz.ErrCutoverUnavailable
	}
	return &MongoCutoverStore{routes: NewMongoRepository(database),
		hostConfigs: database.Collection("application_route_host_configs"),
		transaction: manager, now: now}, nil
}

func (s *MongoCutoverStore) Required(
	ctx context.Context,
	request applicationroutebiz.CutoverRequest,
) (bool, error) {
	if request.Validate() != nil {
		return false, applicationroutebiz.ErrCutoverUnavailable
	}
	count, err := s.routes.routes.CountDocuments(ctx, cutoverRouteFilter(request),
		options.Count().SetLimit(1))
	if err != nil {
		return false, fmt.Errorf("find application routes for cutover: %w", err)
	}
	return count == 1, nil
}

func (s *MongoCutoverStore) Begin(
	ctx context.Context,
	request applicationroutebiz.CutoverRequest,
) (applicationroutebiz.CutoverTransaction, error) {
	if request.Validate() != nil {
		return applicationroutebiz.CutoverTransaction{}, applicationroutebiz.ErrCutoverUnavailable
	}
	var result applicationroutebiz.CutoverTransaction
	err := s.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var beginErr error
		result, beginErr = s.begin(tx, request)
		return beginErr
	})
	return result, err
}

func (s *MongoCutoverStore) begin(
	ctx context.Context,
	request applicationroutebiz.CutoverRequest,
) (applicationroutebiz.CutoverTransaction, error) {
	var document hostConfigDocument
	err := s.hostConfigs.FindOne(ctx, bson.D{{Key: "_id", Value: request.ManagedHostID}}).Decode(&document)
	hostExists := err == nil
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		return applicationroutebiz.CutoverTransaction{}, fmt.Errorf("find application route host config: %w", err)
	}
	if hostExists && document.OrganizationID != request.OrganizationID {
		return applicationroutebiz.CutoverTransaction{}, applicationroutebiz.ErrCutoverConflict
	}
	if document.Pending != nil {
		transactionValue, decodeErr := document.Pending.domain(request.ManagedHostID)
		if decodeErr != nil {
			return applicationroutebiz.CutoverTransaction{}, decodeErr
		}
		if !request.SameCutover(transactionValue.Request) {
			return applicationroutebiz.CutoverTransaction{}, applicationroutebiz.ErrCutoverConflict
		}
		return transactionValue, nil
	}
	routes, err := s.listCutoverRoutes(ctx, request)
	if err != nil {
		return applicationroutebiz.CutoverTransaction{}, err
	}
	if len(routes) == 0 {
		return applicationroutebiz.CutoverTransaction{}, applicationroutebiz.ErrCutoverConflict
	}
	desired, err := buildDesiredConfig(document, request, routes)
	if err != nil {
		return applicationroutebiz.CutoverTransaction{}, err
	}
	pending := cutoverDocumentFromDomain(applicationroutebiz.CutoverTransaction{
		Request: request, Desired: desired,
	})
	pending.State = cutoverStateAllocated
	if !hostExists {
		_, err = s.hostConfigs.InsertOne(ctx, hostConfigDocument{ID: request.ManagedHostID,
			OrganizationID: request.OrganizationID, Revision: desired.HostRevision, Pending: pending})
	} else {
		var updateResult *mongo.UpdateResult
		updateResult, err = s.hostConfigs.UpdateOne(ctx, bson.D{
			{Key: "_id", Value: request.ManagedHostID}, {Key: "revision", Value: document.Revision},
			{Key: "pending", Value: bson.D{{Key: "$exists", Value: false}}},
		}, bson.D{{Key: "$set", Value: bson.D{
			{Key: "revision", Value: desired.HostRevision}, {Key: "pending", Value: pending},
		}}})
		if err == nil && updateResult.ModifiedCount != 1 {
			err = applicationroutebiz.ErrCutoverConflict
		}
	}
	if mongo.IsDuplicateKeyError(err) {
		return applicationroutebiz.CutoverTransaction{}, applicationroutebiz.ErrCutoverConflict
	}
	if err != nil {
		return applicationroutebiz.CutoverTransaction{}, fmt.Errorf("allocate application route cutover: %w", err)
	}
	for _, route := range routes {
		if route.Status == applicationroutebiz.StatusProvisioning {
			continue
		}
		next, transitionErr := route.Transition(applicationroutebiz.StatusProvisioning,
			"system:deployment-worker", s.now().UTC())
		if transitionErr != nil {
			return applicationroutebiz.CutoverTransaction{}, transitionErr
		}
		if _, saveErr := s.routes.Save(ctx, next, route.Version); saveErr != nil {
			return applicationroutebiz.CutoverTransaction{}, saveErr
		}
		if auditErr := s.recordRouteAudit(ctx, next, "application_route.provisioning"); auditErr != nil {
			return applicationroutebiz.CutoverTransaction{}, auditErr
		}
	}
	return applicationroutebiz.CutoverTransaction{Request: request, Desired: desired}, nil
}

func (s *MongoCutoverStore) Prepared(
	ctx context.Context,
	transactionValue applicationroutebiz.CutoverTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if observation.HostRevision != transactionValue.Desired.HostRevision || observation.ConfigDigest == "" {
		return applicationroutebiz.ErrCutoverConflict
	}
	result, err := s.hostConfigs.UpdateOne(ctx, pendingFilter(transactionValue,
		bson.D{{Key: "$in", Value: bson.A{cutoverStateAllocated, cutoverStatePrepared}}}),
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "pending.state", Value: cutoverStatePrepared},
			{Key: "pending.observation", Value: gatewayObservationDocument{
				HostRevision: observation.HostRevision, ConfigDigest: observation.ConfigDigest}},
		}}})
	if err != nil {
		return fmt.Errorf("record prepared application route cutover: %w", err)
	}
	if result.MatchedCount != 1 {
		return applicationroutebiz.ErrCutoverConflict
	}
	return nil
}

func (s *MongoCutoverStore) MarkControlPlaneCommitted(
	ctx context.Context,
	request applicationroutebiz.CutoverRequest,
) error {
	transactionValue, exists, err := s.Get(ctx, request.DeploymentID)
	if err != nil || !exists {
		return err
	}
	if !request.SameCutover(transactionValue.Request) {
		return applicationroutebiz.ErrCutoverConflict
	}
	if transactionValue.ControlPlaneCommitted {
		return nil
	}
	var document hostConfigDocument
	err = s.hostConfigs.FindOne(ctx, bson.D{{Key: "_id", Value: request.ManagedHostID},
		{Key: "organization_id", Value: request.OrganizationID},
		{Key: "pending.request.deployment_id", Value: request.DeploymentID}}).Decode(&document)
	if err != nil || document.Pending == nil || document.Pending.Observation == nil ||
		document.Pending.State != cutoverStatePrepared {
		return applicationroutebiz.ErrCutoverConflict
	}
	routes, err := s.routesByIDs(ctx, request.OrganizationID, transactionValue.Desired.ProbeRouteIDs)
	if err != nil {
		return err
	}
	if len(routes) != len(transactionValue.Desired.ProbeRouteIDs) {
		return applicationroutebiz.ErrCutoverConflict
	}
	for _, route := range routes {
		if route.Status == applicationroutebiz.StatusReady && route.Observation != nil &&
			route.Observation.DeploymentID == request.DeploymentID &&
			route.Observation.CutoverSequence == request.CutoverSequence &&
			route.Observation.ConfigDigest == document.Pending.Observation.ConfigDigest {
			continue
		}
		if route.Status != applicationroutebiz.StatusProvisioning {
			return applicationroutebiz.ErrCutoverConflict
		}
		certificate := applicationroutebiz.CertificateStatusNotApplicable
		if route.TLSMode == applicationroutebiz.TLSModeAutomatic {
			certificate = applicationroutebiz.CertificateStatusReady
		}
		ready, observeErr := route.ObserveReady(applicationroutebiz.Observation{
			Revision: route.Revision, DeploymentID: request.DeploymentID,
			CutoverSequence:   request.CutoverSequence,
			ConfigDigest:      document.Pending.Observation.ConfigDigest,
			CertificateStatus: certificate, ObservedAt: s.now().UTC(),
		}, "system:deployment-worker", s.now().UTC())
		if observeErr != nil {
			return observeErr
		}
		if _, saveErr := s.routes.Save(ctx, ready, route.Version); saveErr != nil {
			return saveErr
		}
		if auditErr := s.recordRouteAudit(ctx, ready, "application_route.ready"); auditErr != nil {
			return auditErr
		}
	}
	result, err := s.hostConfigs.UpdateOne(ctx, pendingFilter(transactionValue,
		cutoverStatePrepared), bson.D{{Key: "$set", Value: bson.D{
		{Key: "pending.state", Value: cutoverStateControlPlaneCommitted},
	}}})
	if err != nil {
		return fmt.Errorf("commit application route control plane: %w", err)
	}
	if result.MatchedCount != 1 {
		return applicationroutebiz.ErrCutoverConflict
	}
	return nil
}

func (s *MongoCutoverStore) Get(
	ctx context.Context,
	deploymentID string,
) (applicationroutebiz.CutoverTransaction, bool, error) {
	var document hostConfigDocument
	err := s.hostConfigs.FindOne(ctx, bson.D{
		{Key: "pending.request.deployment_id", Value: deploymentID},
	}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return applicationroutebiz.CutoverTransaction{}, false, nil
	}
	if err != nil {
		return applicationroutebiz.CutoverTransaction{}, false,
			fmt.Errorf("find application route cutover: %w", err)
	}
	value, err := document.Pending.domain(document.ID)
	if err == nil && value.Request.OrganizationID != document.OrganizationID {
		err = applicationroutebiz.ErrCutoverConflict
	}
	return value, err == nil, err
}

func (s *MongoCutoverStore) Complete(
	ctx context.Context,
	transactionValue applicationroutebiz.CutoverTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if observation.HostRevision != transactionValue.Desired.HostRevision ||
		observation.ConfigDigest == "" {
		return applicationroutebiz.ErrCutoverConflict
	}
	committed := make([]gatewayRouteDocument, len(transactionValue.Desired.Routes))
	for index, route := range transactionValue.Desired.Routes {
		committed[index] = gatewayRouteDocumentFromDomain(route)
	}
	result, err := s.hostConfigs.UpdateOne(ctx, pendingFilter(transactionValue,
		bson.D{{Key: "$in", Value: bson.A{cutoverStateControlPlaneCommitted, cutoverStateGatewayCommitted}}}),
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "committed", Value: committed},
			{Key: "pending.state", Value: cutoverStateGatewayCommitted},
			{Key: "pending.observation", Value: gatewayObservationDocument{
				HostRevision: observation.HostRevision, ConfigDigest: observation.ConfigDigest}},
		}}})
	if err != nil {
		return fmt.Errorf("record committed application route gateway: %w", err)
	}
	if result.MatchedCount != 1 {
		return applicationroutebiz.ErrCutoverConflict
	}
	return nil
}

func (s *MongoCutoverStore) Finish(
	ctx context.Context,
	transactionValue applicationroutebiz.CutoverTransaction,
) error {
	result, err := s.hostConfigs.UpdateOne(ctx, pendingFilter(transactionValue,
		cutoverStateGatewayCommitted), bson.D{{Key: "$unset", Value: bson.D{{Key: "pending", Value: ""}}}})
	if err != nil {
		return fmt.Errorf("finish application route cutover: %w", err)
	}
	if result.MatchedCount != 1 {
		return applicationroutebiz.ErrCutoverConflict
	}
	return nil
}

func (s *MongoCutoverStore) Abort(
	ctx context.Context,
	transactionValue applicationroutebiz.CutoverTransaction,
) error {
	return s.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var document hostConfigDocument
		err := s.hostConfigs.FindOne(tx, pendingFilter(transactionValue,
			bson.D{{Key: "$in", Value: bson.A{cutoverStateAllocated, cutoverStatePrepared}}})).Decode(&document)
		if errors.Is(err, mongo.ErrNoDocuments) {
			return applicationroutebiz.ErrCutoverConflict
		}
		if err != nil {
			return err
		}
		routes, err := s.routesByIDs(tx, transactionValue.Request.OrganizationID,
			transactionValue.Desired.ProbeRouteIDs)
		if err != nil {
			return err
		}
		for _, route := range routes {
			if route.Status != applicationroutebiz.StatusProvisioning {
				continue
			}
			degraded, transitionErr := route.Transition(applicationroutebiz.StatusDegraded,
				"system:deployment-worker", s.now().UTC())
			if transitionErr != nil {
				return transitionErr
			}
			if _, saveErr := s.routes.Save(tx, degraded, route.Version); saveErr != nil {
				return saveErr
			}
			if auditErr := s.recordRouteAudit(tx, degraded, "application_route.degraded"); auditErr != nil {
				return auditErr
			}
		}
		result, err := s.hostConfigs.UpdateOne(tx, pendingFilter(transactionValue,
			bson.D{{Key: "$in", Value: bson.A{cutoverStateAllocated, cutoverStatePrepared}}}),
			bson.D{{Key: "$unset", Value: bson.D{{Key: "pending", Value: ""}}}})
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return applicationroutebiz.ErrCutoverConflict
		}
		return nil
	})
}

func (s *MongoCutoverStore) recordRouteAudit(
	ctx context.Context,
	route applicationroutebiz.ApplicationRoute,
	action string,
) error {
	if s.audit == nil && s.newID == nil {
		return nil
	}
	if s.audit == nil || s.newID == nil {
		return applicationroutebiz.ErrCutoverUnavailable
	}
	auditID, err := s.newID()
	if err != nil {
		return err
	}
	return s.audit.Record(ctx, sharedaudit.Event{ID: auditID,
		OrganizationID: route.OrganizationID, ProjectID: route.ProjectID,
		ActorID: "system:deployment-worker", Action: action,
		ResourceType: "application_route", ResourceID: route.ID,
		CreatedAt: route.UpdatedAt})
}

func (s *MongoCutoverStore) listCutoverRoutes(
	ctx context.Context,
	request applicationroutebiz.CutoverRequest,
) ([]applicationroutebiz.ApplicationRoute, error) {
	cursor, err := s.routes.routes.Find(ctx, cutoverRouteFilter(request),
		options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find application routes for cutover: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []routeDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, err
	}
	routes := make([]applicationroutebiz.ApplicationRoute, len(documents))
	for index, document := range documents {
		routes[index], err = document.domain()
		if err != nil {
			return nil, err
		}
	}
	return routes, nil
}

func (s *MongoCutoverStore) routesByIDs(
	ctx context.Context,
	organizationID string,
	ids []string,
) ([]applicationroutebiz.ApplicationRoute, error) {
	cursor, err := s.routes.routes.Find(ctx, bson.D{
		{Key: "organization_id", Value: organizationID},
		{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}},
	}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var documents []routeDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, err
	}
	routes := make([]applicationroutebiz.ApplicationRoute, len(documents))
	for index, document := range documents {
		routes[index], err = document.domain()
		if err != nil {
			return nil, err
		}
	}
	return routes, nil
}

func cutoverRouteFilter(request applicationroutebiz.CutoverRequest) bson.D {
	return bson.D{{Key: "organization_id", Value: request.OrganizationID},
		{Key: "project_id", Value: request.ProjectID},
		{Key: "application_id", Value: request.ApplicationID},
		{Key: "environment_id", Value: request.EnvironmentID},
		{Key: "runtime_target_id", Value: request.RuntimeTargetID},
		{Key: "status", Value: activeStatusExpression()}}
}

func buildDesiredConfig(
	document hostConfigDocument,
	request applicationroutebiz.CutoverRequest,
	routes []applicationroutebiz.ApplicationRoute,
) (applicationroutebiz.HostDesiredConfig, error) {
	byID := make(map[string]applicationroutebiz.GatewayRoute, len(document.Committed)+len(routes))
	for _, route := range document.Committed {
		domain := route.domain()
		byID[domain.RouteID] = domain
	}
	alias, err := agentprotocol.DeploymentBackendAlias(request.DeploymentID)
	if err != nil {
		return applicationroutebiz.HostDesiredConfig{}, applicationroutebiz.ErrCutoverUnavailable
	}
	probeIDs := make([]string, 0, len(routes))
	for _, route := range routes {
		port, exists := request.Ports[route.PortName]
		if !exists {
			return applicationroutebiz.HostDesiredConfig{}, applicationroutebiz.ErrCutoverConflict
		}
		byID[route.ID] = applicationroutebiz.GatewayRoute{RouteID: route.ID,
			Revision: route.Revision, DeploymentID: request.DeploymentID,
			CutoverSequence: request.CutoverSequence, RuntimeTargetID: request.RuntimeTargetID,
			Hostname: route.Hostname, BackendAlias: alias, BackendPort: port, TLSMode: route.TLSMode}
		probeIDs = append(probeIDs, route.ID)
	}
	if len(byID) > agentprotocol.MaxIngressRoutes {
		return applicationroutebiz.HostDesiredConfig{}, applicationroutebiz.ErrCutoverConflict
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	desiredRoutes := make([]applicationroutebiz.GatewayRoute, 0, len(ids))
	for _, id := range ids {
		desiredRoutes = append(desiredRoutes, byID[id])
	}
	sort.Strings(probeIDs)
	return applicationroutebiz.HostDesiredConfig{ManagedHostID: request.ManagedHostID,
		HostRevision: document.Revision + 1, Routes: desiredRoutes, ProbeRouteIDs: probeIDs}, nil
}

func pendingFilter(transactionValue applicationroutebiz.CutoverTransaction, state any) bson.D {
	return bson.D{{Key: "_id", Value: transactionValue.Request.ManagedHostID},
		{Key: "organization_id", Value: transactionValue.Request.OrganizationID},
		{Key: "pending.request.deployment_id", Value: transactionValue.Request.DeploymentID},
		{Key: "pending.desired.host_revision", Value: transactionValue.Desired.HostRevision},
		{Key: "pending.state", Value: state}}
}

type hostConfigDocument struct {
	ID             string                 `bson:"_id"`
	OrganizationID string                 `bson:"organization_id"`
	Revision       uint64                 `bson:"revision"`
	Committed      []gatewayRouteDocument `bson:"committed,omitempty"`
	Pending        *cutoverDocument       `bson:"pending,omitempty"`
}

type cutoverDocument struct {
	Request     cutoverRequestDocument      `bson:"request"`
	Desired     hostDesiredDocument         `bson:"desired"`
	State       string                      `bson:"state"`
	Observation *gatewayObservationDocument `bson:"observation,omitempty"`
}

type cutoverRequestDocument struct {
	OrganizationID  string         `bson:"organization_id"`
	ProjectID       string         `bson:"project_id"`
	ApplicationID   string         `bson:"application_id"`
	EnvironmentID   string         `bson:"environment_id"`
	RuntimeTargetID string         `bson:"runtime_target_id"`
	ManagedHostID   string         `bson:"managed_host_id"`
	DeploymentID    string         `bson:"deployment_id"`
	WorkerID        string         `bson:"worker_id"`
	ContainerName   string         `bson:"container_name"`
	FencingToken    uint64         `bson:"fencing_token"`
	CutoverSequence uint64         `bson:"cutover_sequence"`
	Ports           []portDocument `bson:"ports"`
}

type portDocument struct {
	Name string `bson:"name"`
	Port uint16 `bson:"port"`
}

type hostDesiredDocument struct {
	HostRevision  uint64                 `bson:"host_revision"`
	Routes        []gatewayRouteDocument `bson:"routes"`
	ProbeRouteIDs []string               `bson:"probe_route_ids"`
}

type gatewayRouteDocument struct {
	RouteID         string                      `bson:"route_id"`
	Revision        uint64                      `bson:"revision"`
	DeploymentID    string                      `bson:"deployment_id"`
	CutoverSequence uint64                      `bson:"cutover_sequence"`
	RuntimeTargetID string                      `bson:"runtime_target_id"`
	Hostname        string                      `bson:"hostname"`
	BackendAlias    string                      `bson:"backend_alias"`
	BackendPort     uint16                      `bson:"backend_port"`
	TLSMode         applicationroutebiz.TLSMode `bson:"tls_mode"`
}

type gatewayObservationDocument struct {
	HostRevision uint64 `bson:"host_revision"`
	ConfigDigest string `bson:"config_digest"`
}

func cutoverDocumentFromDomain(value applicationroutebiz.CutoverTransaction) *cutoverDocument {
	names := make([]string, 0, len(value.Request.Ports))
	for name := range value.Request.Ports {
		names = append(names, name)
	}
	sort.Strings(names)
	ports := make([]portDocument, 0, len(names))
	for _, name := range names {
		ports = append(ports, portDocument{Name: name, Port: value.Request.Ports[name]})
	}
	routes := make([]gatewayRouteDocument, len(value.Desired.Routes))
	for index, route := range value.Desired.Routes {
		routes[index] = gatewayRouteDocumentFromDomain(route)
	}
	return &cutoverDocument{Request: cutoverRequestDocument{
		OrganizationID: value.Request.OrganizationID, ProjectID: value.Request.ProjectID,
		ApplicationID: value.Request.ApplicationID, EnvironmentID: value.Request.EnvironmentID,
		RuntimeTargetID: value.Request.RuntimeTargetID, ManagedHostID: value.Request.ManagedHostID,
		DeploymentID: value.Request.DeploymentID, WorkerID: value.Request.WorkerID,
		ContainerName: value.Request.ContainerName, FencingToken: value.Request.FencingToken,
		CutoverSequence: value.Request.CutoverSequence, Ports: ports,
	}, Desired: hostDesiredDocument{HostRevision: value.Desired.HostRevision, Routes: routes,
		ProbeRouteIDs: append([]string(nil), value.Desired.ProbeRouteIDs...)}}
}

func (d *cutoverDocument) domain(managedHostID string) (applicationroutebiz.CutoverTransaction, error) {
	if d == nil {
		return applicationroutebiz.CutoverTransaction{}, applicationroutebiz.ErrCutoverConflict
	}
	ports := make(map[string]uint16, len(d.Request.Ports))
	for _, port := range d.Request.Ports {
		if _, exists := ports[port.Name]; exists {
			return applicationroutebiz.CutoverTransaction{}, applicationroutebiz.ErrCutoverConflict
		}
		ports[port.Name] = port.Port
	}
	request := applicationroutebiz.CutoverRequest{OrganizationID: d.Request.OrganizationID,
		ProjectID: d.Request.ProjectID, ApplicationID: d.Request.ApplicationID,
		EnvironmentID: d.Request.EnvironmentID, RuntimeTargetID: d.Request.RuntimeTargetID,
		ManagedHostID: managedHostID, DeploymentID: d.Request.DeploymentID,
		WorkerID: d.Request.WorkerID, ContainerName: d.Request.ContainerName,
		FencingToken: d.Request.FencingToken, CutoverSequence: d.Request.CutoverSequence,
		Ports: ports}
	if request.Validate() != nil || request.ManagedHostID != d.Request.ManagedHostID {
		return applicationroutebiz.CutoverTransaction{}, applicationroutebiz.ErrCutoverConflict
	}
	routes := make([]applicationroutebiz.GatewayRoute, len(d.Desired.Routes))
	for index, route := range d.Desired.Routes {
		routes[index] = route.domain()
	}
	value := applicationroutebiz.CutoverTransaction{Request: request,
		Desired: applicationroutebiz.HostDesiredConfig{ManagedHostID: managedHostID,
			HostRevision: d.Desired.HostRevision, Routes: routes,
			ProbeRouteIDs: append([]string(nil), d.Desired.ProbeRouteIDs...)},
		ControlPlaneCommitted: d.State == cutoverStateControlPlaneCommitted ||
			d.State == cutoverStateGatewayCommitted}
	return value, nil
}

func gatewayRouteDocumentFromDomain(route applicationroutebiz.GatewayRoute) gatewayRouteDocument {
	return gatewayRouteDocument{RouteID: route.RouteID, Revision: route.Revision,
		DeploymentID: route.DeploymentID, CutoverSequence: route.CutoverSequence,
		RuntimeTargetID: route.RuntimeTargetID, Hostname: route.Hostname,
		BackendAlias: route.BackendAlias, BackendPort: route.BackendPort, TLSMode: route.TLSMode}
}

func (d gatewayRouteDocument) domain() applicationroutebiz.GatewayRoute {
	return applicationroutebiz.GatewayRoute{RouteID: d.RouteID, Revision: d.Revision,
		DeploymentID: d.DeploymentID, CutoverSequence: d.CutoverSequence,
		RuntimeTargetID: d.RuntimeTargetID, Hostname: d.Hostname,
		BackendAlias: d.BackendAlias, BackendPort: d.BackendPort, TLSMode: d.TLSMode}
}

var _ applicationroutebiz.CutoverStore = (*MongoCutoverStore)(nil)
