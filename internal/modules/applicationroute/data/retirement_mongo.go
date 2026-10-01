package data

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	applicationroutebiz "github.com/owndock/owndock/internal/modules/applicationroute/biz"
	sharedaudit "github.com/owndock/owndock/internal/shared/audit"
	"github.com/owndock/owndock/internal/shared/transaction"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const (
	retirementStateAllocated        = "allocated"
	retirementStatePrepared         = "prepared"
	retirementStateGatewayCommitted = "gateway_committed"
	retirementActor                 = "system:application-route-retirement"
)

// MongoRetirementStore uses the same host-config collection and transaction
// boundary as deployment cutover while exposing an independent operation set.
type MongoRetirementStore MongoCutoverStore

func NewMongoRetirementStore(
	database *mongo.Database,
	manager transaction.Manager,
	now func() time.Time,
) (*MongoRetirementStore, error) {
	store, err := NewMongoCutoverStore(database, manager, now)
	if err != nil {
		return nil, applicationroutebiz.ErrRetirementUnavailable
	}
	return (*MongoRetirementStore)(store), nil
}

func (s *MongoRetirementStore) WithAudit(
	recorder sharedaudit.Recorder,
	newID func() (string, error),
) *MongoRetirementStore {
	s.audit, s.newID = recorder, newID
	return s
}

func (s *MongoRetirementStore) Begin(
	ctx context.Context,
	routeID string,
) (applicationroutebiz.RouteRetirementTransaction, bool, error) {
	var transactionValue applicationroutebiz.RouteRetirementTransaction
	completed := false
	err := s.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var routeDocumentValue routeDocument
		if err := s.routes.routes.FindOne(tx, bson.D{{Key: "_id", Value: routeID}}).
			Decode(&routeDocumentValue); errors.Is(err, mongo.ErrNoDocuments) {
			return applicationroutebiz.ErrRetirementConflict
		} else if err != nil {
			return fmt.Errorf("find retiring application route: %w", err)
		}
		route, err := routeDocumentValue.domain()
		if err != nil {
			return err
		}
		if route.Status == applicationroutebiz.StatusRetired {
			completed = true
			return nil
		}
		if route.Status != applicationroutebiz.StatusRetiring || route.Retirement == nil {
			return applicationroutebiz.ErrRetirementConflict
		}

		var host hostConfigDocument
		err = s.hostConfigs.FindOne(tx, bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "committed.route_id", Value: route.ID}},
			bson.D{{Key: "pending.desired.routes.route_id", Value: route.ID}},
			bson.D{{Key: "retirement.route_id", Value: route.ID}},
		}}}).Decode(&host)
		if errors.Is(err, mongo.ErrNoDocuments) {
			if err := s.completeRouteRetirement(tx, route); err != nil {
				return err
			}
			completed = true
			return nil
		}
		if err != nil {
			return fmt.Errorf("find application route host for retirement: %w", err)
		}
		if host.OrganizationID != route.OrganizationID {
			return applicationroutebiz.ErrRetirementConflict
		}
		if host.Retirement != nil {
			if host.Retirement.RouteID != route.ID {
				return applicationroutebiz.ErrRetirementPending
			}
			var decodeErr error
			transactionValue, decodeErr = host.Retirement.domain(host.ID, host.OrganizationID)
			return decodeErr
		}
		if host.Pending != nil {
			return applicationroutebiz.ErrRetirementPending
		}

		desired, found := buildRetirementDesired(host, route.ID)
		if !found {
			return applicationroutebiz.ErrRetirementPending
		}
		transactionValue = applicationroutebiz.RouteRetirementTransaction{
			RouteID: route.ID, OrganizationID: route.OrganizationID,
			Desired: desired,
		}
		document := routeRetirementDocumentFromDomain(transactionValue)
		document.State = retirementStateAllocated
		result, updateErr := s.hostConfigs.UpdateOne(tx, bson.D{
			{Key: "_id", Value: host.ID}, {Key: "organization_id", Value: route.OrganizationID},
			{Key: "revision", Value: host.Revision},
			{Key: "committed.route_id", Value: route.ID},
			{Key: "pending", Value: bson.D{{Key: "$exists", Value: false}}},
			{Key: "retirement", Value: bson.D{{Key: "$exists", Value: false}}},
		}, bson.D{{Key: "$set", Value: bson.D{
			{Key: "revision", Value: transactionValue.Desired.HostRevision},
			{Key: "retirement", Value: document},
		}}})
		if updateErr != nil {
			return fmt.Errorf("allocate application route retirement: %w", updateErr)
		}
		if result.ModifiedCount != 1 {
			return applicationroutebiz.ErrRetirementPending
		}
		return nil
	})
	return transactionValue, completed, err
}

func buildRetirementDesired(
	host hostConfigDocument,
	routeID string,
) (applicationroutebiz.HostDesiredConfig, bool) {
	desiredRoutes := make([]applicationroutebiz.GatewayRoute, 0, len(host.Committed))
	found := false
	for _, committed := range host.Committed {
		if committed.RouteID == routeID {
			found = true
			continue
		}
		desiredRoutes = append(desiredRoutes, committed.domain())
	}
	sort.Slice(desiredRoutes, func(i, j int) bool {
		return desiredRoutes[i].RouteID < desiredRoutes[j].RouteID
	})
	return applicationroutebiz.HostDesiredConfig{ManagedHostID: host.ID,
		HostRevision: host.Revision + 1, Routes: desiredRoutes,
		ProbeRouteIDs: []string{}}, found
}

func (s *MongoRetirementStore) MarkPrepared(
	ctx context.Context,
	transactionValue applicationroutebiz.RouteRetirementTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if observation.HostRevision != transactionValue.Desired.HostRevision ||
		observation.ConfigDigest == "" {
		return applicationroutebiz.ErrRetirementConflict
	}
	result, err := s.hostConfigs.UpdateOne(ctx, retirementFilter(transactionValue,
		bson.D{{Key: "$in", Value: bson.A{retirementStateAllocated, retirementStatePrepared}}}),
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "retirement.state", Value: retirementStatePrepared},
			{Key: "retirement.observation", Value: gatewayObservationDocument{
				HostRevision: observation.HostRevision, ConfigDigest: observation.ConfigDigest}},
		}}})
	if err != nil {
		return fmt.Errorf("record prepared application route retirement: %w", err)
	}
	if result.MatchedCount != 1 {
		return applicationroutebiz.ErrRetirementConflict
	}
	return nil
}

func (s *MongoRetirementStore) MarkGatewayCommitted(
	ctx context.Context,
	transactionValue applicationroutebiz.RouteRetirementTransaction,
	observation applicationroutebiz.GatewayObservation,
) error {
	if observation.HostRevision != transactionValue.Desired.HostRevision ||
		observation.ConfigDigest == "" {
		return applicationroutebiz.ErrRetirementConflict
	}
	committed := make([]gatewayRouteDocument, len(transactionValue.Desired.Routes))
	for index, route := range transactionValue.Desired.Routes {
		committed[index] = gatewayRouteDocumentFromDomain(route)
	}
	result, err := s.hostConfigs.UpdateOne(ctx, retirementFilter(transactionValue,
		bson.D{{Key: "$in", Value: bson.A{retirementStatePrepared, retirementStateGatewayCommitted}}}),
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "committed", Value: committed},
			{Key: "retirement.state", Value: retirementStateGatewayCommitted},
			{Key: "retirement.observation", Value: gatewayObservationDocument{
				HostRevision: observation.HostRevision, ConfigDigest: observation.ConfigDigest}},
		}}})
	if err != nil {
		return fmt.Errorf("record committed application route retirement: %w", err)
	}
	if result.MatchedCount != 1 {
		return applicationroutebiz.ErrRetirementConflict
	}
	return nil
}

func (s *MongoRetirementStore) Finish(
	ctx context.Context,
	transactionValue applicationroutebiz.RouteRetirementTransaction,
) error {
	return s.transaction.WithinTransaction(ctx, func(tx context.Context) error {
		var document routeDocument
		err := s.routes.routes.FindOne(tx, bson.D{{Key: "_id", Value: transactionValue.RouteID},
			{Key: "organization_id", Value: transactionValue.OrganizationID}}).Decode(&document)
		if err != nil {
			return fmt.Errorf("find application route to finish retirement: %w", err)
		}
		route, err := document.domain()
		if err != nil {
			return err
		}
		if route.Status != applicationroutebiz.StatusRetiring || route.Retirement == nil {
			return applicationroutebiz.ErrRetirementConflict
		}
		if err := s.completeRouteRetirement(tx, route); err != nil {
			return err
		}
		result, err := s.hostConfigs.UpdateOne(tx, retirementFilter(transactionValue,
			retirementStateGatewayCommitted), bson.D{{Key: "$unset", Value: bson.D{
			{Key: "retirement", Value: ""},
		}}})
		if err != nil {
			return fmt.Errorf("finish application route retirement: %w", err)
		}
		if result.MatchedCount != 1 {
			return applicationroutebiz.ErrRetirementConflict
		}
		return nil
	})
}

func (s *MongoRetirementStore) completeRouteRetirement(
	ctx context.Context,
	route applicationroutebiz.ApplicationRoute,
) error {
	retirement := route.Retirement
	if retirement == nil {
		return applicationroutebiz.ErrRetirementConflict
	}
	retired, err := route.CompleteRetirement(retirementActor, s.now().UTC())
	if err != nil {
		return err
	}
	if _, err := s.routes.Save(ctx, retired, route.Version); err != nil {
		return err
	}
	if s.audit == nil && s.newID == nil {
		return nil
	}
	if s.audit == nil || s.newID == nil {
		return applicationroutebiz.ErrRetirementUnavailable
	}
	auditID, err := s.newID()
	if err != nil {
		return err
	}
	return s.audit.Record(ctx, sharedaudit.Event{ID: auditID,
		OrganizationID: route.OrganizationID, ProjectID: route.ProjectID,
		ActorID: retirement.ActorID, Action: "application_route.retired",
		ResourceType: "application_route", ResourceID: route.ID,
		RequestID: retirement.RequestID, CreatedAt: retired.UpdatedAt})
}

func retirementFilter(
	transactionValue applicationroutebiz.RouteRetirementTransaction,
	state any,
) bson.D {
	return bson.D{{Key: "_id", Value: transactionValue.Desired.ManagedHostID},
		{Key: "organization_id", Value: transactionValue.OrganizationID},
		{Key: "retirement.route_id", Value: transactionValue.RouteID},
		{Key: "retirement.desired.host_revision", Value: transactionValue.Desired.HostRevision},
		{Key: "retirement.state", Value: state}}
}

type routeRetirementDocument struct {
	RouteID     string                      `bson:"route_id"`
	Desired     hostDesiredDocument         `bson:"desired"`
	State       string                      `bson:"state"`
	Observation *gatewayObservationDocument `bson:"observation,omitempty"`
}

func routeRetirementDocumentFromDomain(
	value applicationroutebiz.RouteRetirementTransaction,
) *routeRetirementDocument {
	routes := make([]gatewayRouteDocument, len(value.Desired.Routes))
	for index, route := range value.Desired.Routes {
		routes[index] = gatewayRouteDocumentFromDomain(route)
	}
	return &routeRetirementDocument{RouteID: value.RouteID,
		Desired: hostDesiredDocument{HostRevision: value.Desired.HostRevision,
			Routes: routes, ProbeRouteIDs: append([]string(nil), value.Desired.ProbeRouteIDs...)}}
}

func (d *routeRetirementDocument) domain(
	managedHostID, organizationID string,
) (applicationroutebiz.RouteRetirementTransaction, error) {
	if d == nil || d.RouteID == "" || d.Desired.HostRevision == 0 {
		return applicationroutebiz.RouteRetirementTransaction{}, applicationroutebiz.ErrRetirementConflict
	}
	routes := make([]applicationroutebiz.GatewayRoute, len(d.Desired.Routes))
	for index, route := range d.Desired.Routes {
		routes[index] = route.domain()
	}
	value := applicationroutebiz.RouteRetirementTransaction{RouteID: d.RouteID,
		OrganizationID: organizationID,
		Desired: applicationroutebiz.HostDesiredConfig{ManagedHostID: managedHostID,
			HostRevision: d.Desired.HostRevision, Routes: routes,
			ProbeRouteIDs: append([]string(nil), d.Desired.ProbeRouteIDs...)},
		Prepared:         d.State == retirementStatePrepared || d.State == retirementStateGatewayCommitted,
		GatewayCommitted: d.State == retirementStateGatewayCommitted}
	if d.State != retirementStateAllocated && d.State != retirementStatePrepared &&
		d.State != retirementStateGatewayCommitted {
		return applicationroutebiz.RouteRetirementTransaction{}, applicationroutebiz.ErrRetirementConflict
	}
	return value, nil
}

var _ applicationroutebiz.RouteRetirementStore = (*MongoRetirementStore)(nil)
