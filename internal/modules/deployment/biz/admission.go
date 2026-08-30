package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	ErrAdmissionUnavailable = errors.New("deployment admission evaluation is unavailable")
	ErrAdmissionDenied      = errors.New("deployment admission policy denied the deployment")
)

type AdmissionDeniedError struct {
	Snapshot AdmissionSnapshot
}

func (e AdmissionDeniedError) Error() string { return ErrAdmissionDenied.Error() }
func (e AdmissionDeniedError) Unwrap() error { return ErrAdmissionDenied }

var admissionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type AdmissionDecision string

const (
	AdmissionNotConfigured       AdmissionDecision = "not_configured"
	AdmissionAdmitted            AdmissionDecision = "admitted"
	AdmissionAdmittedWithWarning AdmissionDecision = "admitted_with_warnings"
	AdmissionDenied              AdmissionDecision = "denied"
)

func (d AdmissionDecision) Valid() bool {
	return d == AdmissionNotConfigured || d == AdmissionAdmitted ||
		d == AdmissionAdmittedWithWarning || d == AdmissionDenied
}

type AdmissionViolationCode string

const (
	AdmissionPolicyUnavailable          AdmissionViolationCode = "policy_unavailable"
	AdmissionArtifactUnavailable        AdmissionViolationCode = "artifact_unavailable"
	AdmissionSBOMMissing                AdmissionViolationCode = "sbom_missing"
	AdmissionProvenanceMissing          AdmissionViolationCode = "provenance_missing"
	AdmissionEvidenceUnavailable        AdmissionViolationCode = "evidence_unavailable"
	AdmissionSignatureMissing           AdmissionViolationCode = "signature_missing"
	AdmissionVulnerabilityMissing       AdmissionViolationCode = "vulnerability_observation_missing"
	AdmissionVulnerabilityStale         AdmissionViolationCode = "vulnerability_observation_stale"
	AdmissionVulnerabilityIntegrity     AdmissionViolationCode = "vulnerability_report_integrity"
	AdmissionVulnerabilityUnknown       AdmissionViolationCode = "vulnerability_severity_unknown"
	AdmissionVulnerabilityLimitExceeded AdmissionViolationCode = "vulnerability_severity_exceeded"
)

func (c AdmissionViolationCode) Valid() bool {
	switch c {
	case AdmissionPolicyUnavailable, AdmissionArtifactUnavailable, AdmissionSBOMMissing,
		AdmissionProvenanceMissing, AdmissionEvidenceUnavailable, AdmissionSignatureMissing,
		AdmissionVulnerabilityMissing, AdmissionVulnerabilityStale,
		AdmissionVulnerabilityIntegrity, AdmissionVulnerabilityUnknown,
		AdmissionVulnerabilityLimitExceeded:
		return true
	default:
		return false
	}
}

type AdmissionRequirementsSnapshot struct {
	RequireSBOM                  bool
	RequireProvenance            bool
	AllowedSignaturePolicyIDs    []string
	MaximumVulnerabilitySeverity string
	MaximumScanAgeSeconds        int64
}

type AdmissionPolicySnapshot struct {
	ID            string
	Version       uint64
	Scope         string
	EnvironmentID string
	Mode          string
	Requirements  AdmissionRequirementsSnapshot
}

type AdmissionEvidenceSnapshot struct {
	ID               string
	Kind             string
	DescriptorDigest string
	ContentDigest    string
}

type AdmissionVerificationSnapshot struct {
	ID                 string
	TrustPolicyID      string
	TrustPolicyVersion uint64
	BundleSetDigest    string
}

type AdmissionVulnerabilityCounts struct {
	Unknown  uint64
	Low      uint64
	Medium   uint64
	High     uint64
	Critical uint64
	Total    uint64
}

type AdmissionVulnerabilitySnapshot struct {
	ObservationID     string
	EvidenceID        string
	DescriptorDigest  string
	ContentDigest     string
	Scanner           string
	ScannerVersion    string
	DatabaseVersion   uint64
	DatabaseUpdatedAt time.Time
	ScannedAt         time.Time
	FreshUntil        time.Time
	OriginalCounts    AdmissionVulnerabilityCounts
	RemainingCounts   AdmissionVulnerabilityCounts
	HighestRemaining  string
}

type AdmissionWaiverSnapshot struct {
	ID              string
	Version         uint64
	Scope           string
	VulnerabilityID string
	ExpiresAt       time.Time
}

type AdmissionViolation struct {
	PolicyID string
	Code     AdmissionViolationCode
}

type AdmissionSnapshot struct {
	EvaluatedAt       time.Time
	EnvironmentStage  string
	ArtifactID        string
	SubjectDigest     string
	Policies          []AdmissionPolicySnapshot
	Evidence          []AdmissionEvidenceSnapshot
	Verifications     []AdmissionVerificationSnapshot
	Vulnerability     *AdmissionVulnerabilitySnapshot
	Waivers           []AdmissionWaiverSnapshot
	Violations        []AdmissionViolation
	Decision          AdmissionDecision
	EvidenceSetDigest string
	EvaluationDigest  string
}

type AdmissionRequest struct {
	OrganizationID string
	ProjectID      string
	ReleaseID      string
	ApplicationID  string
	EnvironmentID  string
}

type AdmissionEvaluator interface {
	EvaluateAdmission(context.Context, AdmissionRequest) (AdmissionSnapshot, error)
}

func (s AdmissionSnapshot) Seal() (AdmissionSnapshot, error) {
	s.EvaluatedAt = s.EvaluatedAt.UTC().Truncate(time.Millisecond)
	if s.Vulnerability != nil {
		s.Vulnerability.DatabaseUpdatedAt = s.Vulnerability.DatabaseUpdatedAt.UTC().Truncate(time.Millisecond)
		s.Vulnerability.ScannedAt = s.Vulnerability.ScannedAt.UTC().Truncate(time.Millisecond)
		s.Vulnerability.FreshUntil = s.Vulnerability.FreshUntil.UTC().Truncate(time.Millisecond)
	}
	for index := range s.Waivers {
		s.Waivers[index].ExpiresAt = s.Waivers[index].ExpiresAt.UTC().Truncate(time.Millisecond)
	}
	s.Policies = append([]AdmissionPolicySnapshot{}, s.Policies...)
	for index := range s.Policies {
		s.Policies[index].Requirements.AllowedSignaturePolicyIDs = append([]string{},
			s.Policies[index].Requirements.AllowedSignaturePolicyIDs...)
	}
	s.Evidence = append([]AdmissionEvidenceSnapshot{}, s.Evidence...)
	s.Verifications = append([]AdmissionVerificationSnapshot{}, s.Verifications...)
	s.Waivers = append([]AdmissionWaiverSnapshot{}, s.Waivers...)
	s.Violations = append([]AdmissionViolation{}, s.Violations...)
	slices.SortFunc(s.Policies, func(a, b AdmissionPolicySnapshot) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(s.Evidence, func(a, b AdmissionEvidenceSnapshot) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(s.Verifications, func(a, b AdmissionVerificationSnapshot) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(s.Waivers, func(a, b AdmissionWaiverSnapshot) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(s.Violations, func(a, b AdmissionViolation) int {
		if result := strings.Compare(a.PolicyID, b.PolicyID); result != 0 {
			return result
		}
		return strings.Compare(string(a.Code), string(b.Code))
	})
	s.EvidenceSetDigest = ""
	s.EvaluationDigest = ""
	evidenceContent, err := json.Marshal(struct {
		Evidence      []AdmissionEvidenceSnapshot
		Verifications []AdmissionVerificationSnapshot
		Vulnerability *AdmissionVulnerabilitySnapshot
		Waivers       []AdmissionWaiverSnapshot
	}{s.Evidence, s.Verifications, s.Vulnerability, s.Waivers})
	if err != nil {
		return AdmissionSnapshot{}, ErrAdmissionUnavailable
	}
	evidenceDigest := sha256.Sum256(evidenceContent)
	s.EvidenceSetDigest = "sha256:" + hex.EncodeToString(evidenceDigest[:])
	evaluationContent, err := json.Marshal(s)
	if err != nil {
		return AdmissionSnapshot{}, ErrAdmissionUnavailable
	}
	evaluationDigest := sha256.Sum256(evaluationContent)
	s.EvaluationDigest = "sha256:" + hex.EncodeToString(evaluationDigest[:])
	if err := s.Validate(); err != nil {
		return AdmissionSnapshot{}, err
	}
	return s, nil
}

func (s AdmissionSnapshot) Validate() error {
	if s.EvaluatedAt.IsZero() ||
		(s.EnvironmentStage != "development" && s.EnvironmentStage != "staging" && s.EnvironmentStage != "production") ||
		!s.Decision.Valid() || !validAdmissionDigest(s.EvidenceSetDigest) || !validAdmissionDigest(s.EvaluationDigest) ||
		len(s.Policies) > 2 || len(s.Evidence) > 8 || len(s.Verifications) > 16 ||
		len(s.Waivers) > 10_000 || len(s.Violations) > 64 {
		return ErrAdmissionUnavailable
	}
	if s.Decision == AdmissionNotConfigured && (len(s.Policies) != 0 || len(s.Violations) != 0) ||
		s.Decision == AdmissionAdmitted && len(s.Violations) != 0 ||
		s.Decision == AdmissionAdmittedWithWarning && len(s.Violations) == 0 ||
		s.Decision == AdmissionDenied && len(s.Violations) == 0 {
		return ErrAdmissionUnavailable
	}
	if (s.ArtifactID == "") != (s.SubjectDigest == "") ||
		s.ArtifactID != "" && (!validAdmissionID(s.ArtifactID) || !validAdmissionDigest(s.SubjectDigest)) {
		return ErrAdmissionUnavailable
	}
	for _, policy := range s.Policies {
		vulnerabilityGate := policy.Requirements.MaximumVulnerabilitySeverity != "" ||
			policy.Requirements.MaximumScanAgeSeconds != 0
		if !validAdmissionID(policy.ID) || policy.Version == 0 ||
			(policy.Scope != "project" && policy.Scope != "environment") ||
			(policy.Mode != "advisory" && policy.Mode != "enforced") ||
			(policy.Scope == "project" && policy.EnvironmentID != "") ||
			(policy.Scope == "environment" && !validAdmissionID(policy.EnvironmentID)) ||
			len(policy.Requirements.AllowedSignaturePolicyIDs) > 16 ||
			vulnerabilityGate && (!validAdmissionMaximumSeverity(policy.Requirements.MaximumVulnerabilitySeverity) ||
				policy.Requirements.MaximumScanAgeSeconds < 3600 || policy.Requirements.MaximumScanAgeSeconds > 2_592_000) ||
			!policy.Requirements.RequireSBOM && !policy.Requirements.RequireProvenance &&
				len(policy.Requirements.AllowedSignaturePolicyIDs) == 0 && !vulnerabilityGate {
			return ErrAdmissionUnavailable
		}
		for _, id := range policy.Requirements.AllowedSignaturePolicyIDs {
			if !validAdmissionID(id) {
				return ErrAdmissionUnavailable
			}
		}
	}
	for _, evidence := range s.Evidence {
		if !validAdmissionID(evidence.ID) || evidence.Kind == "" ||
			!validAdmissionDigest(evidence.DescriptorDigest) || !validAdmissionDigest(evidence.ContentDigest) {
			return ErrAdmissionUnavailable
		}
	}
	for _, verification := range s.Verifications {
		if !validAdmissionID(verification.ID) || !validAdmissionID(verification.TrustPolicyID) ||
			verification.TrustPolicyVersion == 0 || !validAdmissionDigest(verification.BundleSetDigest) {
			return ErrAdmissionUnavailable
		}
	}
	if s.Vulnerability != nil {
		vulnerability := s.Vulnerability
		if !validAdmissionID(vulnerability.ObservationID) || !validAdmissionID(vulnerability.EvidenceID) ||
			!validAdmissionDigest(vulnerability.DescriptorDigest) || !validAdmissionDigest(vulnerability.ContentDigest) ||
			vulnerability.Scanner == "" || vulnerability.ScannerVersion == "" || vulnerability.DatabaseVersion == 0 ||
			vulnerability.DatabaseUpdatedAt.IsZero() || vulnerability.ScannedAt.IsZero() ||
			vulnerability.FreshUntil.IsZero() || !vulnerability.FreshUntil.After(vulnerability.ScannedAt) ||
			!validAdmissionCounts(vulnerability.OriginalCounts) ||
			!validAdmissionCounts(vulnerability.RemainingCounts) ||
			!validAdmissionSeverity(vulnerability.HighestRemaining) ||
			vulnerability.HighestRemaining != highestAdmissionSeverity(vulnerability.RemainingCounts) {
			return ErrAdmissionUnavailable
		}
	}
	for _, waiver := range s.Waivers {
		if !validAdmissionID(waiver.ID) || waiver.Version == 0 ||
			(waiver.Scope != "project" && waiver.Scope != "artifact") ||
			strings.TrimSpace(waiver.VulnerabilityID) == "" || waiver.ExpiresAt.IsZero() {
			return ErrAdmissionUnavailable
		}
	}
	for _, violation := range s.Violations {
		if !violation.Code.Valid() || violation.PolicyID != "" && !validAdmissionID(violation.PolicyID) {
			return ErrAdmissionUnavailable
		}
	}
	copy := s
	wantEvaluation, wantEvidence := copy.EvaluationDigest, copy.EvidenceSetDigest
	copy.EvaluationDigest, copy.EvidenceSetDigest = "", ""
	evidenceContent, _ := json.Marshal(struct {
		Evidence      []AdmissionEvidenceSnapshot
		Verifications []AdmissionVerificationSnapshot
		Vulnerability *AdmissionVulnerabilitySnapshot
		Waivers       []AdmissionWaiverSnapshot
	}{copy.Evidence, copy.Verifications, copy.Vulnerability, copy.Waivers})
	evidenceDigest := sha256.Sum256(evidenceContent)
	copy.EvidenceSetDigest = wantEvidence
	evaluationContent, _ := json.Marshal(copy)
	evaluationDigest := sha256.Sum256(evaluationContent)
	if wantEvidence != "sha256:"+hex.EncodeToString(evidenceDigest[:]) ||
		wantEvaluation != "sha256:"+hex.EncodeToString(evaluationDigest[:]) {
		return ErrAdmissionUnavailable
	}
	return nil
}

func validAdmissionID(value string) bool {
	return admissionIDPattern.MatchString(value) && strings.TrimSpace(value) == value
}

func validAdmissionDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validAdmissionCounts(counts AdmissionVulnerabilityCounts) bool {
	return counts.Total == counts.Unknown+counts.Low+counts.Medium+counts.High+counts.Critical &&
		counts.Total <= 1_000_000
}

func validAdmissionSeverity(value string) bool {
	switch value {
	case "none", "unknown", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validAdmissionMaximumSeverity(value string) bool {
	switch value {
	case "none", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func highestAdmissionSeverity(counts AdmissionVulnerabilityCounts) string {
	switch {
	case counts.Critical > 0:
		return "critical"
	case counts.High > 0:
		return "high"
	case counts.Medium > 0:
		return "medium"
	case counts.Low > 0:
		return "low"
	case counts.Unknown > 0:
		return "unknown"
	default:
		return "none"
	}
}
