package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type deploymentPolicyRequirementsDocument struct {
	RequireSBOM                  bool                      `bson:"require_sbom"`
	RequireProvenance            bool                      `bson:"require_provenance"`
	AllowedSignaturePolicyIDs    []string                  `bson:"allowed_signature_policy_ids"`
	MaximumVulnerabilitySeverity biz.VulnerabilitySeverity `bson:"maximum_vulnerability_severity,omitempty"`
	MaximumScanAgeSeconds        int64                     `bson:"maximum_scan_age_seconds,omitempty"`
}

type deploymentPolicyDocument struct {
	ID             string                               `bson:"_id"`
	OrganizationID string                               `bson:"organization_id"`
	ProjectID      string                               `bson:"project_id"`
	Name           string                               `bson:"name"`
	Scope          biz.DeploymentPolicyScope            `bson:"scope"`
	EnvironmentID  string                               `bson:"environment_id,omitempty"`
	Mode           biz.DeploymentPolicyMode             `bson:"mode"`
	Requirements   deploymentPolicyRequirementsDocument `bson:"requirements"`
	Enabled        bool                                 `bson:"enabled"`
	Version        uint64                               `bson:"version"`
	CreatedBy      string                               `bson:"created_by"`
	UpdatedBy      string                               `bson:"updated_by"`
	CreatedAt      time.Time                            `bson:"created_at"`
	UpdatedAt      time.Time                            `bson:"updated_at"`
}

func deploymentPolicyDocumentFromDomain(item biz.DeploymentPolicy) deploymentPolicyDocument {
	return deploymentPolicyDocument{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		Name: item.Name, Scope: item.Scope, EnvironmentID: item.EnvironmentID, Mode: item.Mode,
		Requirements: deploymentPolicyRequirementsDocument{
			RequireSBOM: item.Requirements.RequireSBOM, RequireProvenance: item.Requirements.RequireProvenance,
			AllowedSignaturePolicyIDs:    append([]string(nil), item.Requirements.AllowedSignaturePolicyIDs...),
			MaximumVulnerabilitySeverity: item.Requirements.MaximumVulnerabilitySeverity,
			MaximumScanAgeSeconds:        int64(item.Requirements.MaximumScanAge / time.Second),
		},
		Enabled: item.Enabled, Version: item.Version, CreatedBy: item.CreatedBy, UpdatedBy: item.UpdatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func deploymentPolicyInputFromDomain(item biz.DeploymentPolicy) biz.DeploymentPolicyInput {
	return biz.DeploymentPolicyInput{
		ID: item.ID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		Name: item.Name, Scope: item.Scope, EnvironmentID: item.EnvironmentID, Mode: item.Mode,
		Requirements: biz.DeploymentPolicyRequirements{
			RequireSBOM: item.Requirements.RequireSBOM, RequireProvenance: item.Requirements.RequireProvenance,
			AllowedSignaturePolicyIDs:    append([]string(nil), item.Requirements.AllowedSignaturePolicyIDs...),
			MaximumVulnerabilitySeverity: item.Requirements.MaximumVulnerabilitySeverity,
			MaximumScanAge:               item.Requirements.MaximumScanAge,
		},
		Enabled: item.Enabled, Version: item.Version, CreatedBy: item.CreatedBy, UpdatedBy: item.UpdatedBy,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func (d deploymentPolicyDocument) domain() (biz.DeploymentPolicy, error) {
	item, err := biz.NewDeploymentPolicy(biz.DeploymentPolicyInput{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID,
		Name: d.Name, Scope: d.Scope, EnvironmentID: d.EnvironmentID, Mode: d.Mode,
		Requirements: biz.DeploymentPolicyRequirements{
			RequireSBOM: d.Requirements.RequireSBOM, RequireProvenance: d.Requirements.RequireProvenance,
			AllowedSignaturePolicyIDs:    append([]string(nil), d.Requirements.AllowedSignaturePolicyIDs...),
			MaximumVulnerabilitySeverity: d.Requirements.MaximumVulnerabilitySeverity,
			MaximumScanAge:               time.Duration(d.Requirements.MaximumScanAgeSeconds) * time.Second,
		},
		Enabled: d.Enabled, Version: d.Version, CreatedBy: d.CreatedBy, UpdatedBy: d.UpdatedBy,
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	})
	if err != nil {
		return biz.DeploymentPolicy{}, fmt.Errorf("decode invalid deployment policy: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) CreateDeploymentPolicy(ctx context.Context,
	item biz.DeploymentPolicy) (biz.DeploymentPolicy, error) {
	normalized, err := biz.NewDeploymentPolicy(deploymentPolicyInputFromDomain(item))
	if err != nil {
		return biz.DeploymentPolicy{}, err
	}
	if _, err := r.deploymentPolicies.InsertOne(ctx,
		deploymentPolicyDocumentFromDomain(normalized)); mongo.IsDuplicateKeyError(err) {
		return biz.DeploymentPolicy{}, biz.ErrDeploymentPolicyConflict
	} else if err != nil {
		return biz.DeploymentPolicy{}, fmt.Errorf("insert deployment policy: %w", err)
	}
	return normalized, nil
}

func (r *MongoRepository) ListDeploymentPolicies(ctx context.Context,
	organizationID, projectID string) ([]biz.DeploymentPolicy, error) {
	cursor, err := r.deploymentPolicies.Find(ctx, bson.D{{Key: "organization_id", Value: organizationID},
		{Key: "project_id", Value: projectID}}, options.Find().SetSort(bson.D{
		{Key: "scope", Value: 1}, {Key: "environment_id", Value: 1}, {Key: "_id", Value: 1},
	}))
	if err != nil {
		return nil, fmt.Errorf("find deployment policies: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []deploymentPolicyDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode deployment policies: %w", err)
	}
	items := make([]biz.DeploymentPolicy, len(documents))
	for index := range documents {
		items[index], err = documents[index].domain()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (r *MongoRepository) GetDeploymentPolicy(ctx context.Context,
	organizationID, projectID, policyID string) (biz.DeploymentPolicy, error) {
	var document deploymentPolicyDocument
	err := r.deploymentPolicies.FindOne(ctx, bson.D{{Key: "_id", Value: policyID},
		{Key: "organization_id", Value: organizationID}, {Key: "project_id", Value: projectID}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.DeploymentPolicy{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.DeploymentPolicy{}, fmt.Errorf("find deployment policy: %w", err)
	}
	return document.domain()
}

func (r *MongoRepository) SaveDeploymentPolicy(ctx context.Context, item biz.DeploymentPolicy,
	expectedVersion uint64) (biz.DeploymentPolicy, error) {
	normalized, err := biz.NewDeploymentPolicy(deploymentPolicyInputFromDomain(item))
	if err != nil || expectedVersion == 0 || normalized.Version != expectedVersion+1 {
		return biz.DeploymentPolicy{}, biz.ErrInvalidDeploymentPolicy
	}
	filter := bson.D{{Key: "_id", Value: normalized.ID},
		{Key: "organization_id", Value: normalized.OrganizationID}, {Key: "project_id", Value: normalized.ProjectID},
		{Key: "scope", Value: normalized.Scope}, {Key: "version", Value: expectedVersion}}
	if normalized.Scope == biz.DeploymentPolicyScopeProject {
		filter = append(filter, bson.E{Key: "environment_id", Value: bson.D{{Key: "$exists", Value: false}}})
	} else {
		filter = append(filter, bson.E{Key: "environment_id", Value: normalized.EnvironmentID})
	}
	result, err := r.deploymentPolicies.ReplaceOne(ctx, filter, deploymentPolicyDocumentFromDomain(normalized))
	if err != nil {
		return biz.DeploymentPolicy{}, fmt.Errorf("save deployment policy: %w", err)
	}
	if result.MatchedCount != 1 {
		return biz.DeploymentPolicy{}, biz.ErrDeploymentPolicyConflict
	}
	return normalized, nil
}

var _ biz.DeploymentPolicyRepository = (*MongoRepository)(nil)
