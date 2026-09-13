package data

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func vulnerabilityObservationFixture(t *testing.T) biz.VulnerabilityObservation {
	t.Helper()
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	item, err := biz.NewVulnerabilityObservation(biz.VulnerabilityObservation{
		ID: "vulnerability-observation-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", EvidenceID: "evidence-1",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64), DescriptorDigest: "sha256:" + strings.Repeat("b", 64),
		Scanner: "trivy", ScannerVersion: PinnedTrivyVersion,
		Database: biz.VulnerabilityDatabase{SchemaVersion: 2, UpdatedAt: now.Add(-time.Hour),
			DownloadedAt: now.Add(-30 * time.Minute), NextUpdate: now.Add(6 * time.Hour)},
		ScannedAt: now, FreshUntil: now.Add(6 * time.Hour),
		Counts:          biz.VulnerabilityCounts{Medium: 1, Critical: 2, Total: 3, Fixable: 2},
		HighestSeverity: biz.VulnerabilitySeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func TestListDueVulnerabilityObservationsRejectsInvalidBounds(t *testing.T) {
	repository := &MongoRepository{}
	now := time.Now().UTC()
	for _, test := range []struct {
		now       time.Time
		afterTime time.Time
		afterID   string
		limit     int
	}{
		{limit: 1},
		{now: now, limit: 0},
		{now: now, afterTime: now.Add(-time.Hour), limit: 1},
		{now: now, afterID: "observation-1", limit: 1},
	} {
		if _, err := repository.ListDueVulnerabilityObservations(
			context.Background(), test.now, test.afterTime, test.afterID, test.limit,
		); !errors.Is(err, biz.ErrInvalidVulnerabilityReport) {
			t.Fatalf("invalid rescan cursor %+v error = %v", test, err)
		}
	}
}

func TestVulnerabilityObservationBSONRoundTripRejectsCorruption(t *testing.T) {
	item := vulnerabilityObservationFixture(t)
	encoded, err := bson.Marshal(vulnerabilityObservationDocumentFromDomain(item))
	if err != nil {
		t.Fatal(err)
	}
	var document vulnerabilityObservationDocument
	if err := bson.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	restored, err := document.domain()
	if err != nil || restored.Counts != item.Counts || restored.Database != item.Database ||
		restored.HighestSeverity != item.HighestSeverity {
		t.Fatalf("round trip = %+v, %v", restored, err)
	}
	document.Counts.Total++
	if _, err := document.domain(); !errors.Is(err, biz.ErrInvalidVulnerabilityReport) {
		t.Fatalf("corrupt counts error = %v", err)
	}
}
