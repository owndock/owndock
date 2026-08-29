package data

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type trivyReportEnvelope struct {
	SchemaVersion uint64    `json:"SchemaVersion"`
	CreatedAt     time.Time `json:"CreatedAt"`
	ArtifactName  string    `json:"ArtifactName"`
	Results       []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			Severity        string `json:"Severity"`
			FixedVersion    string `json:"FixedVersion"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func newTrivyV2Report(content []byte, maximumBytes int64, canonicalSubject, scannerVersion string,
	database biz.VulnerabilityDatabase) (biz.VulnerabilityReport, error) {
	document, counts, err := parseTrivyV2Report(content, maximumBytes, canonicalSubject)
	if err != nil {
		return biz.VulnerabilityReport{}, err
	}
	return biz.NewVulnerabilityReport(content, maximumBytes, scannerVersion, database, document.CreatedAt, counts)
}

func validateTrivyV2Report(content []byte, maximumBytes int64, canonicalSubject string) error {
	_, _, err := parseTrivyV2Report(content, maximumBytes, canonicalSubject)
	return err
}

func parseTrivyV2Report(content []byte, maximumBytes int64,
	canonicalSubject string) (trivyReportEnvelope, biz.VulnerabilityCounts, error) {
	if maximumBytes <= 0 || maximumBytes > biz.MaximumVulnerabilityReportSize || int64(len(content)) > maximumBytes {
		return trivyReportEnvelope{}, biz.VulnerabilityCounts{}, biz.ErrVulnerabilityReportSize
	}
	var document trivyReportEnvelope
	if err := json.Unmarshal(content, &document); err != nil || document.SchemaVersion != 2 ||
		document.CreatedAt.IsZero() || document.ArtifactName != canonicalSubject || len(document.Results) > 100_000 {
		return trivyReportEnvelope{}, biz.VulnerabilityCounts{}, biz.ErrInvalidVulnerabilityReport
	}
	counts := biz.VulnerabilityCounts{}
	for _, result := range document.Results {
		if len(result.Vulnerabilities) > 1_000_000 || counts.Total > 1_000_000-uint64(len(result.Vulnerabilities)) {
			return trivyReportEnvelope{}, biz.VulnerabilityCounts{}, biz.ErrInvalidVulnerabilityReport
		}
		for _, finding := range result.Vulnerabilities {
			if finding.VulnerabilityID != strings.TrimSpace(finding.VulnerabilityID) ||
				len(finding.VulnerabilityID) == 0 || len(finding.VulnerabilityID) > 256 {
				return trivyReportEnvelope{}, biz.VulnerabilityCounts{}, biz.ErrInvalidVulnerabilityReport
			}
			switch strings.ToUpper(strings.TrimSpace(finding.Severity)) {
			case "UNKNOWN":
				counts.Unknown++
			case "LOW":
				counts.Low++
			case "MEDIUM":
				counts.Medium++
			case "HIGH":
				counts.High++
			case "CRITICAL":
				counts.Critical++
			default:
				return trivyReportEnvelope{}, biz.VulnerabilityCounts{}, biz.ErrInvalidVulnerabilityReport
			}
			counts.Total++
			if strings.TrimSpace(finding.FixedVersion) != "" {
				counts.Fixable++
			}
		}
	}
	return document, counts, nil
}
