package data

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/platform/mongotx"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type vulnerabilityDatabaseDocument struct {
	SchemaVersion uint64    `bson:"schema_version"`
	UpdatedAt     time.Time `bson:"updated_at"`
	DownloadedAt  time.Time `bson:"downloaded_at"`
	NextUpdate    time.Time `bson:"next_update"`
}

type vulnerabilityCountsDocument struct {
	Unknown  uint64 `bson:"unknown"`
	Low      uint64 `bson:"low"`
	Medium   uint64 `bson:"medium"`
	High     uint64 `bson:"high"`
	Critical uint64 `bson:"critical"`
	Total    uint64 `bson:"total"`
	Fixable  uint64 `bson:"fixable"`
}

type vulnerabilityObservationDocument struct {
	ID               string                        `bson:"_id"`
	OrganizationID   string                        `bson:"organization_id"`
	ProjectID        string                        `bson:"project_id"`
	ArtifactID       string                        `bson:"artifact_id"`
	SubjectDigest    string                        `bson:"subject_digest"`
	EvidenceID       string                        `bson:"evidence_id"`
	DescriptorDigest string                        `bson:"descriptor_digest"`
	Scanner          string                        `bson:"scanner"`
	ScannerVersion   string                        `bson:"scanner_version"`
	Database         vulnerabilityDatabaseDocument `bson:"database"`
	ScannedAt        time.Time                     `bson:"scanned_at"`
	FreshUntil       time.Time                     `bson:"fresh_until"`
	Counts           vulnerabilityCountsDocument   `bson:"counts"`
	HighestSeverity  biz.VulnerabilitySeverity     `bson:"highest_severity"`
}

func vulnerabilityObservationDocumentFromDomain(item biz.VulnerabilityObservation) vulnerabilityObservationDocument {
	return vulnerabilityObservationDocument{ID: item.ID, OrganizationID: item.OrganizationID,
		ProjectID: item.ProjectID, ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest,
		EvidenceID: item.EvidenceID, DescriptorDigest: item.DescriptorDigest,
		Scanner: item.Scanner, ScannerVersion: item.ScannerVersion,
		Database: vulnerabilityDatabaseDocument{SchemaVersion: item.Database.SchemaVersion,
			UpdatedAt: item.Database.UpdatedAt, DownloadedAt: item.Database.DownloadedAt,
			NextUpdate: item.Database.NextUpdate},
		ScannedAt: item.ScannedAt, FreshUntil: item.FreshUntil,
		Counts: vulnerabilityCountsDocument{Unknown: item.Counts.Unknown, Low: item.Counts.Low,
			Medium: item.Counts.Medium, High: item.Counts.High, Critical: item.Counts.Critical,
			Total: item.Counts.Total, Fixable: item.Counts.Fixable}, HighestSeverity: item.HighestSeverity}
}

func (d vulnerabilityObservationDocument) domain() (biz.VulnerabilityObservation, error) {
	return biz.NewVulnerabilityObservation(biz.VulnerabilityObservation{ID: d.ID,
		OrganizationID: d.OrganizationID, ProjectID: d.ProjectID, ArtifactID: d.ArtifactID,
		SubjectDigest: d.SubjectDigest, EvidenceID: d.EvidenceID, DescriptorDigest: d.DescriptorDigest,
		Scanner: d.Scanner, ScannerVersion: d.ScannerVersion,
		Database: biz.VulnerabilityDatabase{SchemaVersion: d.Database.SchemaVersion,
			UpdatedAt: d.Database.UpdatedAt, DownloadedAt: d.Database.DownloadedAt,
			NextUpdate: d.Database.NextUpdate}, ScannedAt: d.ScannedAt, FreshUntil: d.FreshUntil,
		Counts: biz.VulnerabilityCounts{Unknown: d.Counts.Unknown, Low: d.Counts.Low,
			Medium: d.Counts.Medium, High: d.Counts.High, Critical: d.Counts.Critical,
			Total: d.Counts.Total, Fixable: d.Counts.Fixable}, HighestSeverity: d.HighestSeverity})
}

func (r *MongoRepository) GetLatestVulnerabilityObservation(ctx context.Context,
	projectID, artifactID string) (biz.VulnerabilityObservation, error) {
	var document vulnerabilityObservationDocument
	err := r.vulnerabilityObservations.FindOne(ctx, bson.D{{Key: "project_id", Value: projectID},
		{Key: "artifact_id", Value: artifactID}, {Key: "scanner", Value: "trivy"}}).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return biz.VulnerabilityObservation{}, biz.ErrNotFound
	}
	if err != nil {
		return biz.VulnerabilityObservation{}, fmt.Errorf("find vulnerability observation: %w", err)
	}
	item, err := document.domain()
	if err != nil {
		return biz.VulnerabilityObservation{}, fmt.Errorf("decode vulnerability observation: %w", err)
	}
	return item, nil
}

func (r *MongoRepository) ListDueVulnerabilityObservations(
	ctx context.Context,
	now time.Time,
	afterFreshUntil time.Time,
	afterID string,
	limit int,
) ([]biz.VulnerabilityObservation, error) {
	if now.IsZero() || limit < 1 || limit > biz.MaximumVulnerabilityRescanCandidates {
		return nil, biz.ErrInvalidVulnerabilityReport
	}
	filter := bson.D{
		{Key: "scanner", Value: "trivy"},
		{Key: "fresh_until", Value: bson.D{{Key: "$lte", Value: now.UTC()}}},
	}
	if !afterFreshUntil.IsZero() || afterID != "" {
		if afterFreshUntil.IsZero() || afterID == "" {
			return nil, biz.ErrInvalidVulnerabilityReport
		}
		filter = append(filter, bson.E{Key: "$or", Value: bson.A{
			bson.D{{Key: "fresh_until", Value: bson.D{{Key: "$gt", Value: afterFreshUntil.UTC()}}}},
			bson.D{{Key: "fresh_until", Value: afterFreshUntil.UTC()},
				{Key: "_id", Value: bson.D{{Key: "$gt", Value: afterID}}}},
		}})
	}
	cursor, err := r.vulnerabilityObservations.Find(ctx, filter,
		options.Find().SetSort(bson.D{{Key: "fresh_until", Value: 1}, {Key: "_id", Value: 1}}).
			SetLimit(int64(limit)))
	if err != nil {
		return nil, fmt.Errorf("find due vulnerability observations: %w", err)
	}
	defer cursor.Close(ctx)
	var documents []vulnerabilityObservationDocument
	if err := cursor.All(ctx, &documents); err != nil {
		return nil, fmt.Errorf("decode due vulnerability observations: %w", err)
	}
	items := make([]biz.VulnerabilityObservation, len(documents))
	for index := range documents {
		items[index], err = documents[index].domain()
		if err != nil {
			return nil, fmt.Errorf("decode due vulnerability observation: %w", err)
		}
	}
	return items, nil
}

func (r *MongoRepository) HasActiveVulnerabilityScan(
	ctx context.Context,
	artifactID string,
) (bool, error) {
	count, err := r.jobs.CountDocuments(ctx, bson.D{
		{Key: "artifact_id", Value: artifactID},
		{Key: "kind", Value: biz.EvidenceKindVulnerabilityReport},
		{Key: "active", Value: true},
	}, options.Count().SetLimit(1))
	if err != nil {
		return false, fmt.Errorf("find active vulnerability scan: %w", err)
	}
	return count > 0, nil
}

func (r *MongoRepository) PublishClaimedVulnerabilityObservation(ctx context.Context,
	item biz.EvidenceJob, evidence biz.Evidence, observation biz.VulnerabilityObservation,
	expectedVersion uint64, workerID string, generation uint64, now time.Time,
) (biz.EvidenceJob, biz.Evidence, biz.VulnerabilityObservation, error) {
	if err := validateEvidencePublication(item, evidence, workerID, generation, now); err != nil {
		return biz.EvidenceJob{}, biz.Evidence{}, biz.VulnerabilityObservation{}, err
	}
	normalized, err := biz.NewVulnerabilityObservation(observation)
	if err != nil || item.Kind != biz.EvidenceKindVulnerabilityReport ||
		normalized.OrganizationID != item.OrganizationID || normalized.ProjectID != item.ProjectID ||
		normalized.ArtifactID != item.ArtifactID || normalized.SubjectDigest != item.SubjectDigest ||
		normalized.EvidenceID != evidence.ID || normalized.DescriptorDigest != evidence.DescriptorDigest ||
		normalized.Scanner != "trivy" || normalized.ScannerVersion != PinnedTrivyVersion {
		return biz.EvidenceJob{}, biz.Evidence{}, biz.VulnerabilityObservation{}, biz.ErrInvalidVulnerabilityReport
	}
	item.Version = expectedVersion + 1
	session, err := r.client.StartSession()
	if err != nil {
		return biz.EvidenceJob{}, biz.Evidence{}, biz.VulnerabilityObservation{}, fmt.Errorf("start vulnerability publication session: %w", err)
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(ctx, func(transactionContext context.Context) (any, error) {
		if _, insertErr := r.evidence.InsertOne(transactionContext, documentFromDomain(evidence)); insertErr != nil {
			if mongo.IsDuplicateKeyError(insertErr) {
				return nil, biz.ErrDuplicate
			}
			return nil, fmt.Errorf("insert vulnerability evidence: %w", insertErr)
		}
		if _, replaceErr := r.vulnerabilityObservations.ReplaceOne(transactionContext,
			bson.D{{Key: "_id", Value: normalized.ID}}, vulnerabilityObservationDocumentFromDomain(normalized),
			options.Replace().SetUpsert(true)); replaceErr != nil {
			return nil, fmt.Errorf("replace vulnerability observation: %w", replaceErr)
		}
		result, replaceErr := r.jobs.ReplaceOne(transactionContext,
			activeEvidenceFence(item.ID, workerID, generation, expectedVersion, now), evidenceJobDocumentFromDomain(item))
		if replaceErr != nil {
			return nil, fmt.Errorf("complete vulnerability job: %w", replaceErr)
		}
		if result.ModifiedCount != 1 {
			return nil, biz.ErrEvidenceLeaseExpired
		}
		return nil, nil
	}, mongotx.Options())
	if err != nil {
		return biz.EvidenceJob{}, biz.Evidence{}, biz.VulnerabilityObservation{}, err
	}
	return item, evidence, normalized, nil
}

var _ biz.VulnerabilityObservationPublisherRepository = (*MongoRepository)(nil)
var _ biz.VulnerabilityObservationRepository = (*MongoRepository)(nil)
var _ biz.VulnerabilityRescanRepository = (*MongoRepository)(nil)
