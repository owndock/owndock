package data

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/deployment/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// MongoRepository is the persistence boundary for formal deployments. Worker
// lease updates always include the expected version to prevent stale workers.
type MongoRepository struct {
	deployments      *mongo.Collection
	cutoverSequences *mongo.Collection
}

func NewMongoRepository(database *mongo.Database) *MongoRepository {
	return &MongoRepository{
		deployments:      database.Collection("deployments"),
		cutoverSequences: database.Collection("deployment_cutover_sequences"),
	}
}

func (r *MongoRepository) List(ctx context.Context, projectID, applicationID, environmentID string) ([]biz.Deployment, error) {
	filter := bson.D{{Key: "project_id", Value: projectID}}
	if applicationID != "" {
		filter = append(filter, bson.E{Key: "application_id", Value: applicationID})
	}
	if environmentID != "" {
		filter = append(filter, bson.E{Key: "environment_id", Value: environmentID})
	}
	cursor, err := r.deployments.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("find deployments: %w", err)
	}
	defer cursor.Close(ctx)
	var docs []deploymentDocument
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, fmt.Errorf("decode deployments: %w", err)
	}
	items := make([]biz.Deployment, len(docs))
	for i := range docs {
		items[i], err = docs[i].domain()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (r *MongoRepository) ListForRuntimeTarget(
	ctx context.Context,
	projectID, runtimeTargetID string,
) ([]biz.Deployment, error) {
	cursor, err := r.deployments.Find(ctx, bson.D{
		{Key: "project_id", Value: projectID},
		{Key: "runtime_target_id", Value: runtimeTargetID},
	}, options.Find().SetSort(bson.D{{Key: "cutover_sequence", Value: -1}}))
	if err != nil {
		return nil, fmt.Errorf("find runtime target deployments: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []deploymentDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode runtime target deployments: %w", err)
	}
	items := make([]biz.Deployment, len(documents))
	for index := range documents {
		items[index], err = documents[index].domain()
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (r *MongoRepository) GetByIdempotency(ctx context.Context, projectID, key string) (biz.Deployment, error) {
	var doc deploymentDocument
	err := r.deployments.FindOne(ctx, bson.D{{Key: "project_id", Value: projectID}, {Key: "idempotency_key", Value: key}}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return biz.Deployment{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("find deployment idempotency: %w", err)
	}
	return doc.domain()
}

func (r *MongoRepository) Get(ctx context.Context, projectID, deploymentID string) (biz.Deployment, error) {
	var doc deploymentDocument
	err := r.deployments.FindOne(ctx, bson.D{
		{Key: "_id", Value: deploymentID},
		{Key: "project_id", Value: projectID},
	}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return biz.Deployment{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("find deployment: %w", err)
	}
	return doc.domain()
}

// CurrentSucceededForSlot returns the deployment that currently owns the
// successful cutover for one application/environment/runtime-target slot.
// Terminal callers use this to reject stale deployment IDs before resolving a
// running container.
func (r *MongoRepository) CurrentSucceededForSlot(
	ctx context.Context,
	projectID, applicationID, environmentID, runtimeTargetID string,
) (biz.Deployment, error) {
	var document deploymentDocument
	err := r.deployments.FindOne(ctx, bson.D{
		{Key: "project_id", Value: projectID},
		{Key: "application_id", Value: applicationID},
		{Key: "environment_id", Value: environmentID},
		{Key: "runtime_target_id", Value: runtimeTargetID},
		{Key: "status", Value: string(biz.StatusSucceeded)},
	}, options.FindOne().SetSort(bson.D{
		{Key: "cutover_sequence", Value: -1}, {Key: "updated_at", Value: -1}, {Key: "_id", Value: -1},
	})).Decode(&document)
	if err == mongo.ErrNoDocuments {
		return biz.Deployment{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("find current successful deployment: %w", err)
	}
	return document.domain()
}

func (r *MongoRepository) HasSucceeded(
	ctx context.Context,
	projectID, releaseID, applicationID, environmentID, runtimeTargetID string,
) (bool, error) {
	err := r.deployments.FindOne(
		ctx,
		bson.D{
			{Key: "project_id", Value: projectID},
			{Key: "application_id", Value: applicationID},
			{Key: "environment_id", Value: environmentID},
			{Key: "runtime_target_id", Value: runtimeTargetID},
			{Key: "release_id", Value: releaseID},
			{Key: "status", Value: string(biz.StatusSucceeded)},
		},
		options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}}),
	).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find successful deployment: %w", err)
	}
	return true, nil
}

func (r *MongoRepository) Create(ctx context.Context, item biz.Deployment) (biz.Deployment, error) {
	if mongo.SessionFromContext(ctx) != nil {
		return r.createWithinTransaction(ctx, item)
	}
	session, err := r.deployments.Database().Client().StartSession()
	if err != nil {
		return biz.Deployment{}, fmt.Errorf(
			"start deployment creation transaction: %w",
			err,
		)
	}
	defer session.EndSession(ctx)
	var created biz.Deployment
	_, err = session.WithTransaction(
		ctx,
		func(transactionContext context.Context) (any, error) {
			var createErr error
			created, createErr = r.createWithinTransaction(
				transactionContext,
				item,
			)
			return nil, createErr
		},
	)
	if err != nil {
		return biz.Deployment{}, err
	}
	return created, nil
}

func (r *MongoRepository) createWithinTransaction(
	ctx context.Context,
	item biz.Deployment,
) (biz.Deployment, error) {
	sequence, err := r.nextCutoverSequence(ctx, item)
	if err != nil {
		return biz.Deployment{}, err
	}
	item.CutoverSequence = sequence
	_, err = r.deployments.InsertOne(ctx, deploymentDocumentFromDomain(item))
	if mongo.IsDuplicateKeyError(err) {
		var serverError mongo.ServerError
		if errors.As(err, &serverError) && serverError.HasErrorMessage("uniq_deployment_idempotency") {
			return biz.Deployment{}, biz.ErrDuplicateIdempotency
		}
		return biz.Deployment{}, biz.ErrConflict
	}
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("insert deployment: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) nextCutoverSequence(
	ctx context.Context,
	item biz.Deployment,
) (uint64, error) {
	scopeHash := sha256.Sum256([]byte(item.CutoverScope()))
	var counter struct {
		Sequence uint64 `bson:"sequence"`
	}
	result := r.cutoverSequences.FindOneAndUpdate(
		ctx,
		bson.D{{Key: "_id", Value: fmt.Sprintf("%x", scopeHash[:])}},
		bson.D{
			{Key: "$inc", Value: bson.D{{Key: "sequence", Value: 1}}},
			{Key: "$setOnInsert", Value: bson.D{
				{Key: "project_id", Value: item.ProjectID},
				{Key: "application_id", Value: item.ApplicationID},
				{Key: "environment_id", Value: item.EnvironmentID},
				{Key: "runtime_target_id", Value: item.RuntimeTargetID},
			}},
		},
		options.FindOneAndUpdate().
			SetUpsert(true).
			SetReturnDocument(options.After),
	)
	if err := result.Decode(&counter); err != nil {
		return 0, fmt.Errorf("allocate deployment cutover sequence: %w", err)
	}
	if counter.Sequence == 0 {
		return 0, fmt.Errorf("allocate deployment cutover sequence: zero sequence")
	}
	return counter.Sequence, nil
}

func (r *MongoRepository) Save(ctx context.Context, item biz.Deployment, expectedVersion uint64) (biz.Deployment, error) {
	item.Version = expectedVersion + 1
	result, err := r.deployments.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: item.ID},
		{Key: "project_id", Value: item.ProjectID},
		{Key: "version", Value: expectedVersion},
	}, deploymentDocumentFromDomain(item))
	if err != nil {
		return biz.Deployment{}, fmt.Errorf("save deployment: %w", err)
	}
	if result.ModifiedCount != 1 {
		if _, findErr := r.Get(ctx, item.ProjectID, item.ID); errors.Is(findErr, biz.ErrNotFound) {
			return biz.Deployment{}, biz.ErrNotFound
		}
		return biz.Deployment{}, biz.ErrConflict
	}
	return item, nil
}

func (r *MongoRepository) ClaimNext(ctx context.Context, claim biz.Claim) (biz.Deployment, bool, error) {
	if err := claim.Validate(); err != nil {
		return biz.Deployment{}, false, err
	}
	base := bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$lte", Value: claim.Now}}}}, bson.D{{Key: "lease.expires_at", Value: bson.D{{Key: "$exists", Value: false}}}}}}}
	var doc deploymentDocument
	claimUpdate := bson.D{
		{Key: "$set", Value: bson.D{
			{Key: "lease.owner", Value: claim.WorkerID},
			{Key: "lease.expires_at", Value: claim.ExpiresAt.UTC()},
			{Key: "updated_at", Value: claim.Now.UTC()},
		}},
		{Key: "$inc", Value: bson.D{
			{Key: "lease.generation", Value: 1},
			{Key: "version", Value: 1},
		}},
	}
	result := r.deployments.FindOneAndUpdate(ctx, append(base, bson.E{Key: "status", Value: string(biz.StatusQueued)}), claimUpdate, options.FindOneAndUpdate().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetReturnDocument(options.After))
	err := result.Decode(&doc)
	if err == nil {
		item, domainErr := doc.domain()
		return item, domainErr == nil, domainErr
	}
	if err != mongo.ErrNoDocuments {
		return biz.Deployment{}, false, err
	}
	result = r.deployments.FindOneAndUpdate(ctx, append(base, bson.E{Key: "status", Value: bson.D{{Key: "$in", Value: []string{string(biz.StatusPreparing), string(biz.StatusDeploying)}}}}), claimUpdate, options.FindOneAndUpdate().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetReturnDocument(options.After))
	if err := result.Decode(&doc); err == mongo.ErrNoDocuments {
		result = r.deployments.FindOneAndUpdate(
			ctx,
			append(base, bson.E{Key: "status", Value: string(biz.StatusCanceling)}),
			claimUpdate,
			options.FindOneAndUpdate().SetSort(bson.D{{Key: "created_at", Value: 1}}).SetReturnDocument(options.After),
		)
		if cancelErr := result.Decode(&doc); cancelErr == mongo.ErrNoDocuments {
			return biz.Deployment{}, false, nil
		} else if cancelErr != nil {
			return biz.Deployment{}, false, cancelErr
		}
		item, domainErr := doc.domain()
		return item, domainErr == nil, domainErr
	} else if err != nil {
		return biz.Deployment{}, false, err
	}
	item, domainErr := doc.domain()
	return item, domainErr == nil, domainErr
}

func (r *MongoRepository) SaveClaimed(ctx context.Context, item biz.Deployment, expectedVersion uint64, workerID string, now time.Time) (biz.Deployment, error) {
	if !item.Terminal() && (item.Lease.Owner != workerID || !item.Lease.Active(now)) {
		return biz.Deployment{}, biz.ErrLeaseExpired
	}
	item.Version = expectedVersion + 1
	result, err := r.deployments.ReplaceOne(ctx, bson.D{
		{Key: "_id", Value: item.ID},
		{Key: "version", Value: expectedVersion},
		{Key: "lease.owner", Value: workerID},
		{Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
	}, deploymentDocumentFromDomain(item))
	if err != nil {
		return biz.Deployment{}, err
	}
	if result.ModifiedCount != 1 {
		return biz.Deployment{}, biz.ErrConflict
	}
	return item, nil
}

// RenewLease extends a live worker lease only when owner and version still
// match. A stale worker therefore cannot keep a reclaimed deployment alive.
func (r *MongoRepository) RenewLease(ctx context.Context, deploymentID, workerID string, expectedVersion uint64, now, expiresAt time.Time) (biz.Deployment, error) {
	if workerID == "" || !expiresAt.After(now) {
		return biz.Deployment{}, biz.ErrInvalidLease
	}
	var document deploymentDocument
	result := r.deployments.FindOneAndUpdate(
		ctx,
		bson.D{{Key: "_id", Value: deploymentID}, {Key: "version", Value: expectedVersion}, {Key: "lease.owner", Value: workerID}, {Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now}}}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "lease.expires_at", Value: expiresAt.UTC()}, {Key: "updated_at", Value: now.UTC()}}}, {Key: "$inc", Value: bson.D{{Key: "version", Value: 1}}}},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if err := result.Decode(&document); err == mongo.ErrNoDocuments {
		return biz.Deployment{}, biz.ErrConflict
	} else if err != nil {
		return biz.Deployment{}, err
	}
	return document.domain()
}

func (r *MongoRepository) ValidateFence(
	ctx context.Context,
	projectID, deploymentID, workerID string,
	generation uint64,
	now time.Time,
) error {
	if projectID == "" || deploymentID == "" || workerID == "" || generation == 0 || now.IsZero() {
		return biz.ErrStaleExecution
	}
	var deployment struct {
		ProjectID       string `bson:"project_id"`
		ApplicationID   string `bson:"application_id"`
		EnvironmentID   string `bson:"environment_id"`
		RuntimeTargetID string `bson:"runtime_target_id"`
		CutoverSequence uint64 `bson:"cutover_sequence"`
	}
	err := r.deployments.FindOne(ctx, bson.D{
		{Key: "_id", Value: deploymentID},
		{Key: "project_id", Value: projectID},
		{Key: "lease.owner", Value: workerID},
		{Key: "lease.generation", Value: generation},
		{Key: "lease.expires_at", Value: bson.D{{Key: "$gt", Value: now.UTC()}}},
		{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{
			string(biz.StatusPreparing), string(biz.StatusDeploying), string(biz.StatusCanceling),
		}}}},
	}, options.FindOne().SetProjection(bson.D{
		{Key: "project_id", Value: 1},
		{Key: "application_id", Value: 1},
		{Key: "environment_id", Value: 1},
		{Key: "runtime_target_id", Value: 1},
		{Key: "cutover_sequence", Value: 1},
	})).Decode(&deployment)
	if err == mongo.ErrNoDocuments {
		return biz.ErrStaleExecution
	}
	if err != nil {
		return fmt.Errorf("validate deployment fence: %w", err)
	}
	scope := deployment.ProjectID + "\x00" + deployment.ApplicationID + "\x00" +
		deployment.EnvironmentID + "\x00" + deployment.RuntimeTargetID
	scopeHash := sha256.Sum256([]byte(scope))
	var counter struct {
		Sequence uint64 `bson:"sequence"`
	}
	err = r.cutoverSequences.FindOne(
		ctx,
		bson.D{{Key: "_id", Value: fmt.Sprintf("%x", scopeHash[:])}},
		options.FindOne().SetProjection(bson.D{{Key: "sequence", Value: 1}}),
	).Decode(&counter)
	if err == mongo.ErrNoDocuments {
		return biz.ErrStaleExecution
	}
	if err != nil {
		return fmt.Errorf("validate deployment cutover sequence: %w", err)
	}
	if counter.Sequence != deployment.CutoverSequence {
		return biz.ErrStaleExecution
	}
	return nil
}

type admissionRequirementsDocument struct {
	RequireSBOM                  bool     `bson:"require_sbom"`
	RequireProvenance            bool     `bson:"require_provenance"`
	AllowedSignaturePolicyIDs    []string `bson:"allowed_signature_policy_ids"`
	MaximumVulnerabilitySeverity string   `bson:"maximum_vulnerability_severity,omitempty"`
	MaximumScanAgeSeconds        int64    `bson:"maximum_scan_age_seconds,omitempty"`
}

type admissionPolicyDocument struct {
	ID            string                        `bson:"id"`
	Version       uint64                        `bson:"version"`
	Scope         string                        `bson:"scope"`
	EnvironmentID string                        `bson:"environment_id,omitempty"`
	Mode          string                        `bson:"mode"`
	Requirements  admissionRequirementsDocument `bson:"requirements"`
}

type admissionEvidenceDocument struct {
	ID               string `bson:"id"`
	Kind             string `bson:"kind"`
	DescriptorDigest string `bson:"descriptor_digest"`
	ContentDigest    string `bson:"content_digest"`
}

type admissionVerificationDocument struct {
	ID                 string `bson:"id"`
	TrustPolicyID      string `bson:"trust_policy_id"`
	TrustPolicyVersion uint64 `bson:"trust_policy_version"`
	BundleSetDigest    string `bson:"bundle_set_digest"`
}

type admissionVulnerabilityCountsDocument struct {
	Unknown  uint64 `bson:"unknown"`
	Low      uint64 `bson:"low"`
	Medium   uint64 `bson:"medium"`
	High     uint64 `bson:"high"`
	Critical uint64 `bson:"critical"`
	Total    uint64 `bson:"total"`
}

type admissionVulnerabilityDocument struct {
	ObservationID     string                               `bson:"observation_id"`
	EvidenceID        string                               `bson:"evidence_id"`
	DescriptorDigest  string                               `bson:"descriptor_digest"`
	ContentDigest     string                               `bson:"content_digest"`
	Scanner           string                               `bson:"scanner"`
	ScannerVersion    string                               `bson:"scanner_version"`
	DatabaseVersion   uint64                               `bson:"database_version"`
	DatabaseUpdatedAt time.Time                            `bson:"database_updated_at"`
	ScannedAt         time.Time                            `bson:"scanned_at"`
	FreshUntil        time.Time                            `bson:"fresh_until"`
	OriginalCounts    admissionVulnerabilityCountsDocument `bson:"original_counts"`
	RemainingCounts   admissionVulnerabilityCountsDocument `bson:"remaining_counts"`
	HighestRemaining  string                               `bson:"highest_remaining"`
}

type admissionWaiverDocument struct {
	ID              string    `bson:"id"`
	Version         uint64    `bson:"version"`
	Scope           string    `bson:"scope"`
	VulnerabilityID string    `bson:"vulnerability_id"`
	ExpiresAt       time.Time `bson:"expires_at"`
}

type admissionViolationDocument struct {
	PolicyID string `bson:"policy_id,omitempty"`
	Code     string `bson:"code"`
}

type admissionDocument struct {
	EvaluatedAt       time.Time                       `bson:"evaluated_at"`
	EnvironmentStage  string                          `bson:"environment_stage"`
	ArtifactID        string                          `bson:"artifact_id,omitempty"`
	SubjectDigest     string                          `bson:"subject_digest,omitempty"`
	Policies          []admissionPolicyDocument       `bson:"policies"`
	Evidence          []admissionEvidenceDocument     `bson:"evidence"`
	Verifications     []admissionVerificationDocument `bson:"verifications"`
	Vulnerability     *admissionVulnerabilityDocument `bson:"vulnerability,omitempty"`
	Waivers           []admissionWaiverDocument       `bson:"waivers"`
	Violations        []admissionViolationDocument    `bson:"violations"`
	Decision          string                          `bson:"decision"`
	EvidenceSetDigest string                          `bson:"evidence_set_digest"`
	EvaluationDigest  string                          `bson:"evaluation_digest"`
}

type deploymentDocument struct {
	ID                   string                  `bson:"_id"`
	OrganizationID       string                  `bson:"organization_id,omitempty"`
	ProjectID            string                  `bson:"project_id"`
	ReleaseID            string                  `bson:"release_id"`
	ApplicationID        string                  `bson:"application_id"`
	EnvironmentID        string                  `bson:"environment_id"`
	RuntimeTargetID      string                  `bson:"runtime_target_id"`
	IdempotencyKey       string                  `bson:"idempotency_key"`
	Operation            string                  `bson:"operation"`
	TriggerSource        string                  `bson:"trigger_source"`
	SourceArtifactID     string                  `bson:"source_artifact_id,omitempty"`
	SourceBuildID        string                  `bson:"source_build_id,omitempty"`
	BuildConfigurationID string                  `bson:"build_configuration_id,omitempty"`
	SourceDeploymentID   string                  `bson:"source_deployment_id,omitempty"`
	Revision             string                  `bson:"revision"`
	Status               string                  `bson:"status"`
	FailureCategory      string                  `bson:"failure_category,omitempty"`
	CutoverSequence      uint64                  `bson:"cutover_sequence,omitempty"`
	CreatedAt            time.Time               `bson:"created_at"`
	UpdatedAt            time.Time               `bson:"updated_at"`
	Version              uint64                  `bson:"version"`
	Lease                deploymentLeaseDocument `bson:"lease"`
	Admission            *admissionDocument      `bson:"admission,omitempty"`
}
type deploymentLeaseDocument struct {
	Owner      string    `bson:"owner,omitempty"`
	ExpiresAt  time.Time `bson:"expires_at,omitempty"`
	Generation uint64    `bson:"generation,omitempty"`
}

func deploymentDocumentFromDomain(d biz.Deployment) deploymentDocument {
	var admission *admissionDocument
	if d.Admission.EvaluationDigest != "" {
		admission = admissionDocumentFromDomain(d.Admission)
	}
	return deploymentDocument{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID, ReleaseID: d.ReleaseID,
		ApplicationID: d.ApplicationID, EnvironmentID: d.EnvironmentID,
		RuntimeTargetID: d.RuntimeTargetID, IdempotencyKey: d.IdempotencyKey,
		Operation: string(d.Operation), TriggerSource: string(d.TriggerSource),
		SourceArtifactID: d.SourceArtifactID, SourceBuildID: d.SourceBuildID,
		BuildConfigurationID: d.BuildConfigurationID,
		SourceDeploymentID:   d.SourceDeploymentID,
		Revision:             d.Revision, Status: string(d.Status), FailureCategory: string(d.FailureCategory),
		CutoverSequence: d.CutoverSequence, CreatedAt: d.CreatedAt,
		UpdatedAt: d.UpdatedAt, Version: d.Version,
		Lease: deploymentLeaseDocument{
			Owner: d.Lease.Owner, ExpiresAt: d.Lease.ExpiresAt,
			Generation: d.Lease.Generation,
		},
		Admission: admission,
	}
}
func (d deploymentDocument) domain() (biz.Deployment, error) {
	operation := biz.Operation(d.Operation)
	if operation == "" {
		operation = biz.OperationDeploy
	}
	triggerSource := biz.TriggerSource(d.TriggerSource)
	if triggerSource == "" {
		triggerSource = biz.TriggerSourceManual
	}
	item := biz.Deployment{
		ID: d.ID, OrganizationID: d.OrganizationID, ProjectID: d.ProjectID, ReleaseID: d.ReleaseID,
		ApplicationID: d.ApplicationID, EnvironmentID: d.EnvironmentID,
		RuntimeTargetID: d.RuntimeTargetID, IdempotencyKey: d.IdempotencyKey,
		Operation: operation, TriggerSource: triggerSource,
		SourceArtifactID: d.SourceArtifactID, SourceBuildID: d.SourceBuildID,
		BuildConfigurationID: d.BuildConfigurationID,
		SourceDeploymentID:   d.SourceDeploymentID,
		Revision:             d.Revision, Status: biz.Status(d.Status), FailureCategory: biz.FailureCategory(d.FailureCategory),
		CutoverSequence: d.CutoverSequence, CreatedAt: d.CreatedAt,
		UpdatedAt: d.UpdatedAt, Version: d.Version,
		Lease: biz.Lease{
			Owner: d.Lease.Owner, ExpiresAt: d.Lease.ExpiresAt,
			Generation: d.Lease.Generation,
		},
	}
	if d.Admission != nil {
		admission := d.Admission.domain()
		if err := admission.Validate(); err != nil {
			return biz.Deployment{}, fmt.Errorf("decode invalid deployment admission snapshot: %w", err)
		}
		item.Admission = admission
	}
	return item, nil
}

func admissionDocumentFromDomain(snapshot biz.AdmissionSnapshot) *admissionDocument {
	document := &admissionDocument{EvaluatedAt: snapshot.EvaluatedAt,
		EnvironmentStage: snapshot.EnvironmentStage, ArtifactID: snapshot.ArtifactID,
		SubjectDigest: snapshot.SubjectDigest, Decision: string(snapshot.Decision),
		EvidenceSetDigest: snapshot.EvidenceSetDigest, EvaluationDigest: snapshot.EvaluationDigest,
		Policies:      make([]admissionPolicyDocument, len(snapshot.Policies)),
		Evidence:      make([]admissionEvidenceDocument, len(snapshot.Evidence)),
		Verifications: make([]admissionVerificationDocument, len(snapshot.Verifications)),
		Waivers:       make([]admissionWaiverDocument, len(snapshot.Waivers)),
		Violations:    make([]admissionViolationDocument, len(snapshot.Violations))}
	for index, policy := range snapshot.Policies {
		document.Policies[index] = admissionPolicyDocument{ID: policy.ID, Version: policy.Version,
			Scope: policy.Scope, EnvironmentID: policy.EnvironmentID, Mode: policy.Mode,
			Requirements: admissionRequirementsDocument{RequireSBOM: policy.Requirements.RequireSBOM,
				RequireProvenance:            policy.Requirements.RequireProvenance,
				AllowedSignaturePolicyIDs:    append([]string{}, policy.Requirements.AllowedSignaturePolicyIDs...),
				MaximumVulnerabilitySeverity: policy.Requirements.MaximumVulnerabilitySeverity,
				MaximumScanAgeSeconds:        policy.Requirements.MaximumScanAgeSeconds}}
	}
	for index, evidence := range snapshot.Evidence {
		document.Evidence[index] = admissionEvidenceDocument{ID: evidence.ID, Kind: evidence.Kind,
			DescriptorDigest: evidence.DescriptorDigest, ContentDigest: evidence.ContentDigest}
	}
	for index, verification := range snapshot.Verifications {
		document.Verifications[index] = admissionVerificationDocument{ID: verification.ID,
			TrustPolicyID: verification.TrustPolicyID, TrustPolicyVersion: verification.TrustPolicyVersion,
			BundleSetDigest: verification.BundleSetDigest}
	}
	if snapshot.Vulnerability != nil {
		vulnerability := snapshot.Vulnerability
		document.Vulnerability = &admissionVulnerabilityDocument{ObservationID: vulnerability.ObservationID,
			EvidenceID: vulnerability.EvidenceID, DescriptorDigest: vulnerability.DescriptorDigest,
			ContentDigest: vulnerability.ContentDigest, Scanner: vulnerability.Scanner,
			ScannerVersion: vulnerability.ScannerVersion, DatabaseVersion: vulnerability.DatabaseVersion,
			DatabaseUpdatedAt: vulnerability.DatabaseUpdatedAt, ScannedAt: vulnerability.ScannedAt,
			FreshUntil: vulnerability.FreshUntil, OriginalCounts: admissionCountsDocument(vulnerability.OriginalCounts),
			RemainingCounts:  admissionCountsDocument(vulnerability.RemainingCounts),
			HighestRemaining: vulnerability.HighestRemaining}
	}
	for index, waiver := range snapshot.Waivers {
		document.Waivers[index] = admissionWaiverDocument{ID: waiver.ID, Version: waiver.Version,
			Scope: waiver.Scope, VulnerabilityID: waiver.VulnerabilityID, ExpiresAt: waiver.ExpiresAt}
	}
	for index, violation := range snapshot.Violations {
		document.Violations[index] = admissionViolationDocument{PolicyID: violation.PolicyID,
			Code: string(violation.Code)}
	}
	return document
}

func (d admissionDocument) domain() biz.AdmissionSnapshot {
	snapshot := biz.AdmissionSnapshot{EvaluatedAt: d.EvaluatedAt, EnvironmentStage: d.EnvironmentStage,
		ArtifactID: d.ArtifactID, SubjectDigest: d.SubjectDigest, Decision: biz.AdmissionDecision(d.Decision),
		EvidenceSetDigest: d.EvidenceSetDigest, EvaluationDigest: d.EvaluationDigest,
		Policies:      make([]biz.AdmissionPolicySnapshot, len(d.Policies)),
		Evidence:      make([]biz.AdmissionEvidenceSnapshot, len(d.Evidence)),
		Verifications: make([]biz.AdmissionVerificationSnapshot, len(d.Verifications)),
		Waivers:       make([]biz.AdmissionWaiverSnapshot, len(d.Waivers)),
		Violations:    make([]biz.AdmissionViolation, len(d.Violations))}
	for index, policy := range d.Policies {
		snapshot.Policies[index] = biz.AdmissionPolicySnapshot{ID: policy.ID, Version: policy.Version,
			Scope: policy.Scope, EnvironmentID: policy.EnvironmentID, Mode: policy.Mode,
			Requirements: biz.AdmissionRequirementsSnapshot{RequireSBOM: policy.Requirements.RequireSBOM,
				RequireProvenance:            policy.Requirements.RequireProvenance,
				AllowedSignaturePolicyIDs:    append([]string{}, policy.Requirements.AllowedSignaturePolicyIDs...),
				MaximumVulnerabilitySeverity: policy.Requirements.MaximumVulnerabilitySeverity,
				MaximumScanAgeSeconds:        policy.Requirements.MaximumScanAgeSeconds}}
	}
	for index, evidence := range d.Evidence {
		snapshot.Evidence[index] = biz.AdmissionEvidenceSnapshot{ID: evidence.ID, Kind: evidence.Kind,
			DescriptorDigest: evidence.DescriptorDigest, ContentDigest: evidence.ContentDigest}
	}
	for index, verification := range d.Verifications {
		snapshot.Verifications[index] = biz.AdmissionVerificationSnapshot{ID: verification.ID,
			TrustPolicyID: verification.TrustPolicyID, TrustPolicyVersion: verification.TrustPolicyVersion,
			BundleSetDigest: verification.BundleSetDigest}
	}
	if d.Vulnerability != nil {
		vulnerability := d.Vulnerability
		snapshot.Vulnerability = &biz.AdmissionVulnerabilitySnapshot{ObservationID: vulnerability.ObservationID,
			EvidenceID: vulnerability.EvidenceID, DescriptorDigest: vulnerability.DescriptorDigest,
			ContentDigest: vulnerability.ContentDigest, Scanner: vulnerability.Scanner,
			ScannerVersion: vulnerability.ScannerVersion, DatabaseVersion: vulnerability.DatabaseVersion,
			DatabaseUpdatedAt: vulnerability.DatabaseUpdatedAt, ScannedAt: vulnerability.ScannedAt,
			FreshUntil: vulnerability.FreshUntil, OriginalCounts: vulnerability.OriginalCounts.domain(),
			RemainingCounts: vulnerability.RemainingCounts.domain(), HighestRemaining: vulnerability.HighestRemaining}
	}
	for index, waiver := range d.Waivers {
		snapshot.Waivers[index] = biz.AdmissionWaiverSnapshot{ID: waiver.ID, Version: waiver.Version,
			Scope: waiver.Scope, VulnerabilityID: waiver.VulnerabilityID, ExpiresAt: waiver.ExpiresAt}
	}
	for index, violation := range d.Violations {
		snapshot.Violations[index] = biz.AdmissionViolation{PolicyID: violation.PolicyID,
			Code: biz.AdmissionViolationCode(violation.Code)}
	}
	return snapshot
}

func admissionCountsDocument(counts biz.AdmissionVulnerabilityCounts) admissionVulnerabilityCountsDocument {
	return admissionVulnerabilityCountsDocument{Unknown: counts.Unknown, Low: counts.Low,
		Medium: counts.Medium, High: counts.High, Critical: counts.Critical, Total: counts.Total}
}

func (d admissionVulnerabilityCountsDocument) domain() biz.AdmissionVulnerabilityCounts {
	return biz.AdmissionVulnerabilityCounts{Unknown: d.Unknown, Low: d.Low, Medium: d.Medium,
		High: d.High, Critical: d.Critical, Total: d.Total}
}
