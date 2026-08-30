package data

import (
	"context"
	"strings"
	"time"

	deploymentbiz "github.com/owndock/owndock/internal/modules/deployment/biz"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

type deploymentAdmissionReleaseLookup interface {
	EnvironmentStage(context.Context, string, string) (string, error)
	ReleaseSourceArtifactID(context.Context, string, string, string) (string, error)
}

type applicableVulnerabilityWaiverRepository interface {
	ListApplicableVulnerabilityWaivers(context.Context, string, string, string, string,
		time.Time) ([]biz.VulnerabilityWaiver, error)
}

type DeploymentAdmissionOptions struct {
	Releases        deploymentAdmissionReleaseLookup
	Artifacts       biz.ArtifactLookup
	Policies        biz.DeploymentPolicyRepository
	Evidence        biz.Repository
	Content         biz.EvidenceContentReader
	Verifications   biz.EvidenceVerificationRepository
	TrustPolicies   biz.SignatureTrustPolicyRepository
	Vulnerabilities biz.VulnerabilityObservationRepository
	Waivers         applicableVulnerabilityWaiverRepository
	Now             func() time.Time
}

type DeploymentAdmissionEvaluator struct {
	releases        deploymentAdmissionReleaseLookup
	artifacts       biz.ArtifactLookup
	policies        biz.DeploymentPolicyRepository
	evidence        biz.Repository
	content         biz.EvidenceContentReader
	verifications   biz.EvidenceVerificationRepository
	trustPolicies   biz.SignatureTrustPolicyRepository
	vulnerabilities biz.VulnerabilityObservationRepository
	waivers         applicableVulnerabilityWaiverRepository
	now             func() time.Time
}

func NewDeploymentAdmissionEvaluator(options DeploymentAdmissionOptions) (*DeploymentAdmissionEvaluator, error) {
	if options.Releases == nil || options.Artifacts == nil || options.Policies == nil ||
		options.Evidence == nil || options.Content == nil || options.Verifications == nil ||
		options.TrustPolicies == nil || options.Vulnerabilities == nil || options.Waivers == nil || options.Now == nil {
		return nil, deploymentbiz.ErrAdmissionUnavailable
	}
	return &DeploymentAdmissionEvaluator{releases: options.Releases, artifacts: options.Artifacts,
		policies: options.Policies, evidence: options.Evidence, content: options.Content,
		verifications: options.Verifications, trustPolicies: options.TrustPolicies,
		vulnerabilities: options.Vulnerabilities, waivers: options.Waivers, now: options.Now}, nil
}

func (e *DeploymentAdmissionEvaluator) EvaluateAdmission(ctx context.Context,
	request deploymentbiz.AdmissionRequest) (deploymentbiz.AdmissionSnapshot, error) {
	now := e.now().UTC()
	stage, err := e.releases.EnvironmentStage(ctx, request.ProjectID, request.EnvironmentID)
	if err != nil || now.IsZero() {
		return deploymentbiz.AdmissionSnapshot{}, deploymentbiz.ErrAdmissionUnavailable
	}
	snapshot := deploymentbiz.AdmissionSnapshot{EvaluatedAt: now, EnvironmentStage: stage,
		Policies: []deploymentbiz.AdmissionPolicySnapshot{}, Evidence: []deploymentbiz.AdmissionEvidenceSnapshot{},
		Verifications: []deploymentbiz.AdmissionVerificationSnapshot{}, Waivers: []deploymentbiz.AdmissionWaiverSnapshot{},
		Violations: []deploymentbiz.AdmissionViolation{}}
	policies, err := e.policies.ListDeploymentPolicies(ctx, request.OrganizationID, request.ProjectID)
	if err != nil {
		snapshot.Violations = append(snapshot.Violations, deploymentbiz.AdmissionViolation{
			Code: deploymentbiz.AdmissionPolicyUnavailable})
		return sealAdmission(snapshot, stage != "development")
	}
	effectiveModes := make(map[string]biz.DeploymentPolicyMode)
	for _, policy := range policies {
		if !policy.Enabled || policy.Scope == biz.DeploymentPolicyScopeEnvironment &&
			policy.EnvironmentID != request.EnvironmentID {
			continue
		}
		mode, enabled, modeErr := policy.EffectiveMode(stage)
		if modeErr != nil || !enabled {
			return deploymentbiz.AdmissionSnapshot{}, deploymentbiz.ErrAdmissionUnavailable
		}
		effectiveModes[policy.ID] = mode
		snapshot.Policies = append(snapshot.Policies, deploymentPolicyAdmissionSnapshot(policy, mode))
	}
	if len(snapshot.Policies) == 0 {
		snapshot.Decision = deploymentbiz.AdmissionNotConfigured
		return snapshot.Seal()
	}
	artifactID, err := e.releases.ReleaseSourceArtifactID(ctx, request.ProjectID,
		request.ApplicationID, request.ReleaseID)
	if err != nil || strings.TrimSpace(artifactID) == "" {
		addPolicyViolation(&snapshot, effectiveModes, deploymentbiz.AdmissionArtifactUnavailable)
		return finishAdmission(snapshot, effectiveModes)
	}
	subject, err := e.artifacts.ResolveArtifact(ctx, request.OrganizationID, request.ProjectID, artifactID)
	if err != nil {
		addPolicyViolation(&snapshot, effectiveModes, deploymentbiz.AdmissionArtifactUnavailable)
		return finishAdmission(snapshot, effectiveModes)
	}
	snapshot.ArtifactID, snapshot.SubjectDigest = subject.ID, subject.SubjectDigest
	evidence, err := e.evidence.ListEvidence(ctx, request.ProjectID, subject.ID)
	if err != nil {
		addPolicyViolation(&snapshot, effectiveModes, deploymentbiz.AdmissionEvidenceUnavailable)
		return finishAdmission(snapshot, effectiveModes)
	}
	state := admissionEvidenceState{ctx: ctx, evaluator: e, subject: subject, items: evidence,
		snapshot: &snapshot, capturedEvidence: make(map[string]bool), capturedVerifications: make(map[string]bool)}
	for _, policy := range snapshot.Policies {
		if policy.Requirements.RequireSBOM {
			found, unavailable := state.captureKind(biz.EvidenceKindSBOM)
			if !found {
				code := deploymentbiz.AdmissionSBOMMissing
				if unavailable {
					code = deploymentbiz.AdmissionEvidenceUnavailable
				}
				snapshot.Violations = append(snapshot.Violations,
					deploymentbiz.AdmissionViolation{PolicyID: policy.ID, Code: code})
			}
		}
		if policy.Requirements.RequireProvenance {
			found, unavailable := state.captureKind(biz.EvidenceKindProvenance)
			if !found {
				code := deploymentbiz.AdmissionProvenanceMissing
				if unavailable {
					code = deploymentbiz.AdmissionEvidenceUnavailable
				}
				snapshot.Violations = append(snapshot.Violations,
					deploymentbiz.AdmissionViolation{PolicyID: policy.ID, Code: code})
			}
		}
		if len(policy.Requirements.AllowedSignaturePolicyIDs) > 0 &&
			!state.captureSignature(request.OrganizationID, policy.Requirements.AllowedSignaturePolicyIDs) {
			snapshot.Violations = append(snapshot.Violations, deploymentbiz.AdmissionViolation{
				PolicyID: policy.ID, Code: deploymentbiz.AdmissionSignatureMissing})
		}
	}
	if hasVulnerabilityRequirement(snapshot.Policies) {
		state.evaluateVulnerabilities(request, now)
	}
	return finishAdmission(snapshot, effectiveModes)
}

func deploymentPolicyAdmissionSnapshot(policy biz.DeploymentPolicy,
	mode biz.DeploymentPolicyMode) deploymentbiz.AdmissionPolicySnapshot {
	return deploymentbiz.AdmissionPolicySnapshot{ID: policy.ID, Version: policy.Version,
		Scope: string(policy.Scope), EnvironmentID: policy.EnvironmentID, Mode: string(mode),
		Requirements: deploymentbiz.AdmissionRequirementsSnapshot{
			RequireSBOM: policy.Requirements.RequireSBOM, RequireProvenance: policy.Requirements.RequireProvenance,
			AllowedSignaturePolicyIDs:    append([]string{}, policy.Requirements.AllowedSignaturePolicyIDs...),
			MaximumVulnerabilitySeverity: string(policy.Requirements.MaximumVulnerabilitySeverity),
			MaximumScanAgeSeconds:        int64(policy.Requirements.MaximumScanAge / time.Second),
		}}
}

type admissionEvidenceState struct {
	ctx                   context.Context
	evaluator             *DeploymentAdmissionEvaluator
	subject               biz.ArtifactSubject
	items                 []biz.Evidence
	snapshot              *deploymentbiz.AdmissionSnapshot
	capturedEvidence      map[string]bool
	capturedVerifications map[string]bool
}

func (s *admissionEvidenceState) captureKind(kind biz.EvidenceKind) (bool, bool) {
	unavailable := false
	for index := len(s.items) - 1; index >= 0; index-- {
		item := s.items[index]
		if item.Kind != kind || item.ArtifactID != s.subject.ID || item.SubjectDigest != s.subject.SubjectDigest {
			continue
		}
		content, err := s.evaluator.content.ReadEvidence(s.ctx, s.subject, item)
		if err != nil {
			unavailable = true
			continue
		}
		s.captureEvidence(item, content.Digest)
		return true, unavailable
	}
	return false, unavailable
}

func (s *admissionEvidenceState) captureEvidence(item biz.Evidence, contentDigest string) {
	if s.capturedEvidence[item.ID] {
		return
	}
	s.capturedEvidence[item.ID] = true
	s.snapshot.Evidence = append(s.snapshot.Evidence, deploymentbiz.AdmissionEvidenceSnapshot{
		ID: item.ID, Kind: string(item.Kind), DescriptorDigest: item.DescriptorDigest,
		ContentDigest: contentDigest})
}

func (s *admissionEvidenceState) captureSignature(organizationID string, allowedPolicyIDs []string) bool {
	verifications, err := s.evaluator.verifications.ListEvidenceVerifications(s.ctx,
		s.subject.ProjectID, s.subject.ID)
	if err != nil {
		return false
	}
	for _, policyID := range allowedPolicyIDs {
		policy, err := s.evaluator.trustPolicies.GetSignatureTrustPolicy(s.ctx,
			s.subject.ProjectID, policyID)
		if err != nil || !policy.Enabled || policy.OrganizationID != organizationID {
			continue
		}
		for index := len(verifications) - 1; index >= 0; index-- {
			verification := verifications[index]
			if verification.ArtifactID != s.subject.ID ||
				verification.SubjectDigest != s.subject.SubjectDigest ||
				verification.PolicyID != policy.ID || verification.PolicyVersion != policy.Version ||
				verification.VerificationStatus != biz.VerificationVerified {
				continue
			}
			if !s.capturedVerifications[verification.ID] {
				s.capturedVerifications[verification.ID] = true
				s.snapshot.Verifications = append(s.snapshot.Verifications,
					deploymentbiz.AdmissionVerificationSnapshot{ID: verification.ID,
						TrustPolicyID: verification.PolicyID, TrustPolicyVersion: verification.PolicyVersion,
						BundleSetDigest: verification.BundleSetDigest})
			}
			return true
		}
	}
	return false
}

func (s *admissionEvidenceState) evaluateVulnerabilities(request deploymentbiz.AdmissionRequest,
	now time.Time) {
	observation, err := s.evaluator.vulnerabilities.GetLatestVulnerabilityObservation(
		s.ctx, request.ProjectID, s.subject.ID)
	if err != nil || observation.SubjectDigest != s.subject.SubjectDigest {
		addVulnerabilityViolation(s.snapshot, deploymentbiz.AdmissionVulnerabilityMissing)
		return
	}
	var evidence biz.Evidence
	for _, candidate := range s.items {
		if candidate.ID == observation.EvidenceID && candidate.Kind == biz.EvidenceKindVulnerabilityReport &&
			candidate.DescriptorDigest == observation.DescriptorDigest &&
			candidate.SubjectDigest == s.subject.SubjectDigest {
			evidence = candidate
			break
		}
	}
	if evidence.ID == "" {
		addVulnerabilityViolation(s.snapshot, deploymentbiz.AdmissionVulnerabilityIntegrity)
		return
	}
	content, err := s.evaluator.content.ReadEvidence(s.ctx, s.subject, evidence)
	if err != nil {
		addVulnerabilityViolation(s.snapshot, deploymentbiz.AdmissionVulnerabilityIntegrity)
		return
	}
	document, counts, err := parseTrivyV2Report(content.Content, biz.MaximumVulnerabilityReportSize,
		s.subject.RegistryRepository+"@"+s.subject.SubjectDigest)
	if err != nil || counts != observation.Counts || !document.CreatedAt.Equal(observation.ScannedAt) ||
		observation.ScannedAt.After(now.Add(5*time.Minute)) {
		addVulnerabilityViolation(s.snapshot, deploymentbiz.AdmissionVulnerabilityIntegrity)
		return
	}
	s.captureEvidence(evidence, content.Digest)
	waivers, err := s.evaluator.waivers.ListApplicableVulnerabilityWaivers(s.ctx,
		request.OrganizationID, request.ProjectID, s.subject.ID, s.subject.SubjectDigest, now)
	if err != nil {
		addVulnerabilityViolation(s.snapshot, deploymentbiz.AdmissionVulnerabilityIntegrity)
		return
	}
	waiverByFinding := make(map[string]biz.VulnerabilityWaiver, len(waivers))
	for _, waiver := range waivers {
		waiverByFinding[waiver.VulnerabilityID] = waiver
	}
	remaining := biz.VulnerabilityCounts{}
	applied := make(map[string]biz.VulnerabilityWaiver)
	for _, result := range document.Results {
		for _, finding := range result.Vulnerabilities {
			if waiver, ok := waiverByFinding[strings.ToUpper(finding.VulnerabilityID)]; ok {
				applied[waiver.ID] = waiver
				continue
			}
			incrementVulnerabilityCounts(&remaining, finding.Severity, strings.TrimSpace(finding.FixedVersion) != "")
		}
	}
	for _, waiver := range applied {
		s.snapshot.Waivers = append(s.snapshot.Waivers, deploymentbiz.AdmissionWaiverSnapshot{
			ID: waiver.ID, Version: waiver.Version, Scope: string(waiver.Scope),
			VulnerabilityID: waiver.VulnerabilityID, ExpiresAt: waiver.ExpiresAt})
	}
	s.snapshot.Vulnerability = &deploymentbiz.AdmissionVulnerabilitySnapshot{
		ObservationID: observation.ID, EvidenceID: evidence.ID, DescriptorDigest: evidence.DescriptorDigest,
		ContentDigest: content.Digest, Scanner: observation.Scanner, ScannerVersion: observation.ScannerVersion,
		DatabaseVersion: observation.Database.SchemaVersion, DatabaseUpdatedAt: observation.Database.UpdatedAt,
		ScannedAt: observation.ScannedAt, FreshUntil: observation.FreshUntil,
		OriginalCounts: admissionCounts(observation.Counts), RemainingCounts: admissionCounts(remaining),
		HighestRemaining: string(remaining.HighestSeverity()),
	}
	for _, policy := range s.snapshot.Policies {
		if policy.Requirements.MaximumVulnerabilitySeverity == "" {
			continue
		}
		maximumAge := time.Duration(policy.Requirements.MaximumScanAgeSeconds) * time.Second
		deadline := observation.ScannedAt.Add(maximumAge)
		if observation.FreshUntil.Before(deadline) {
			deadline = observation.FreshUntil
		}
		if !now.Before(deadline) {
			s.snapshot.Violations = append(s.snapshot.Violations, deploymentbiz.AdmissionViolation{
				PolicyID: policy.ID, Code: deploymentbiz.AdmissionVulnerabilityStale})
			continue
		}
		if remaining.Unknown > 0 {
			s.snapshot.Violations = append(s.snapshot.Violations, deploymentbiz.AdmissionViolation{
				PolicyID: policy.ID, Code: deploymentbiz.AdmissionVulnerabilityUnknown})
			continue
		}
		if vulnerabilitySeverityExceeds(remaining.HighestSeverity(),
			biz.VulnerabilitySeverity(policy.Requirements.MaximumVulnerabilitySeverity)) {
			s.snapshot.Violations = append(s.snapshot.Violations, deploymentbiz.AdmissionViolation{
				PolicyID: policy.ID, Code: deploymentbiz.AdmissionVulnerabilityLimitExceeded})
		}
	}
}

func incrementVulnerabilityCounts(counts *biz.VulnerabilityCounts, severity string, fixable bool) {
	switch strings.ToUpper(severity) {
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
	}
	counts.Total++
	if fixable {
		counts.Fixable++
	}
}

func admissionCounts(counts biz.VulnerabilityCounts) deploymentbiz.AdmissionVulnerabilityCounts {
	return deploymentbiz.AdmissionVulnerabilityCounts{Unknown: counts.Unknown, Low: counts.Low,
		Medium: counts.Medium, High: counts.High, Critical: counts.Critical, Total: counts.Total}
}

func vulnerabilitySeverityExceeds(actual, maximum biz.VulnerabilitySeverity) bool {
	rank := map[biz.VulnerabilitySeverity]int{biz.VulnerabilitySeverityNone: 0,
		biz.VulnerabilitySeverityLow: 1, biz.VulnerabilitySeverityMedium: 2,
		biz.VulnerabilitySeverityHigh: 3, biz.VulnerabilitySeverityCritical: 4,
		biz.VulnerabilitySeverityUnknown: 5}
	return rank[actual] > rank[maximum]
}

func hasVulnerabilityRequirement(policies []deploymentbiz.AdmissionPolicySnapshot) bool {
	for _, policy := range policies {
		if policy.Requirements.MaximumVulnerabilitySeverity != "" {
			return true
		}
	}
	return false
}

func addPolicyViolation(snapshot *deploymentbiz.AdmissionSnapshot,
	modes map[string]biz.DeploymentPolicyMode, code deploymentbiz.AdmissionViolationCode) {
	for policyID := range modes {
		snapshot.Violations = append(snapshot.Violations,
			deploymentbiz.AdmissionViolation{PolicyID: policyID, Code: code})
	}
}

func addVulnerabilityViolation(snapshot *deploymentbiz.AdmissionSnapshot,
	code deploymentbiz.AdmissionViolationCode) {
	for _, policy := range snapshot.Policies {
		if policy.Requirements.MaximumVulnerabilitySeverity != "" {
			snapshot.Violations = append(snapshot.Violations,
				deploymentbiz.AdmissionViolation{PolicyID: policy.ID, Code: code})
		}
	}
}

func finishAdmission(snapshot deploymentbiz.AdmissionSnapshot,
	modes map[string]biz.DeploymentPolicyMode) (deploymentbiz.AdmissionSnapshot, error) {
	blocking := false
	for _, violation := range snapshot.Violations {
		if modes[violation.PolicyID] == biz.DeploymentPolicyEnforced {
			blocking = true
			break
		}
	}
	return sealAdmission(snapshot, blocking)
}

func sealAdmission(snapshot deploymentbiz.AdmissionSnapshot,
	blocking bool) (deploymentbiz.AdmissionSnapshot, error) {
	switch {
	case blocking:
		snapshot.Decision = deploymentbiz.AdmissionDenied
	case len(snapshot.Violations) > 0:
		snapshot.Decision = deploymentbiz.AdmissionAdmittedWithWarning
	default:
		snapshot.Decision = deploymentbiz.AdmissionAdmitted
	}
	sealed, err := snapshot.Seal()
	if err != nil {
		return deploymentbiz.AdmissionSnapshot{}, deploymentbiz.ErrAdmissionUnavailable
	}
	if blocking {
		return sealed, deploymentbiz.AdmissionDeniedError{Snapshot: sealed}
	}
	return sealed, nil
}

var _ deploymentbiz.AdmissionEvaluator = (*DeploymentAdmissionEvaluator)(nil)
