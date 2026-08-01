package data

import (
	"context"
	"fmt"
	"strings"

	"github.com/owndock/owndock/internal/modules/runtimeinventory/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	deploymentIDLabel  = "net.owndock.deployment_id"
	projectIDLabel     = "net.owndock.project_id"
	applicationIDLabel = "net.owndock.application_id"
)

type MongoOwnershipVerifier struct {
	deployments *mongo.Collection
}

func NewMongoOwnershipVerifier(database *mongo.Database) *MongoOwnershipVerifier {
	return &MongoOwnershipVerifier{deployments: database.Collection("deployments")}
}

func (v *MongoOwnershipVerifier) VerifyContainers(
	ctx context.Context,
	resources []biz.Resource,
) (map[string]biz.Ownership, error) {
	result := make(map[string]biz.Ownership)
	if len(resources) == 0 {
		return result, nil
	}
	type candidate struct {
		resource      biz.Resource
		deploymentID  string
		projectID     string
		applicationID string
	}
	candidates := make([]candidate, 0, len(resources))
	deploymentIDs := make([]string, 0, len(resources))
	seenDeployments := make(map[string]struct{}, len(resources))
	organizationID := resources[0].OrganizationID
	for _, resource := range resources {
		if resource.Kind != biz.KindContainer || resource.Validate() != nil ||
			resource.OrganizationID != organizationID {
			return nil, biz.ErrInvalidResource
		}
		item := candidate{
			resource:      resource,
			deploymentID:  strings.TrimSpace(resource.Labels[deploymentIDLabel]),
			projectID:     strings.TrimSpace(resource.Labels[projectIDLabel]),
			applicationID: strings.TrimSpace(resource.Labels[applicationIDLabel]),
		}
		if item.deploymentID == "" || item.projectID == "" || item.applicationID == "" {
			continue
		}
		candidates = append(candidates, item)
		if _, exists := seenDeployments[item.deploymentID]; !exists {
			seenDeployments[item.deploymentID] = struct{}{}
			deploymentIDs = append(deploymentIDs, item.deploymentID)
		}
	}
	if len(candidates) == 0 {
		return result, nil
	}
	cursor, err := v.deployments.Find(ctx, bson.D{
		{Key: "_id", Value: bson.D{{Key: "$in", Value: deploymentIDs}}},
		{Key: "organization_id", Value: organizationID},
		{Key: "status", Value: "succeeded"},
	}, options.Find().SetProjection(bson.D{
		{Key: "_id", Value: 1}, {Key: "project_id", Value: 1},
		{Key: "application_id", Value: 1}, {Key: "runtime_target_id", Value: 1},
	}))
	if err != nil {
		return nil, fmt.Errorf("find owning deployments: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	type deploymentMatch struct {
		ID              string `bson:"_id"`
		ProjectID       string `bson:"project_id"`
		ApplicationID   string `bson:"application_id"`
		RuntimeTargetID string `bson:"runtime_target_id"`
	}
	matches := make(map[string]deploymentMatch, len(deploymentIDs))
	for cursor.Next(ctx) {
		var match deploymentMatch
		if err := cursor.Decode(&match); err != nil {
			return nil, fmt.Errorf("decode owning deployment: %w", err)
		}
		matches[match.ID] = match
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("iterate owning deployments: %w", err)
	}
	for _, candidate := range candidates {
		match, found := matches[candidate.deploymentID]
		if !found || match.ProjectID != candidate.projectID ||
			match.ApplicationID != candidate.applicationID ||
			match.RuntimeTargetID != candidate.resource.RuntimeTargetID {
			continue
		}
		result[candidate.resource.RuntimeID] = biz.Ownership{
			ProjectID: match.ProjectID, DeploymentID: match.ID,
		}
	}
	return result, nil
}

var _ biz.OwnershipVerifier = (*MongoOwnershipVerifier)(nil)
