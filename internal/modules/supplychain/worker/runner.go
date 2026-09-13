package worker

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

var (
	ErrMissingGenerator = errors.New("SBOM generator is required")
	ErrMissingPublisher = errors.New("SBOM publisher is required")
	ErrMissingID        = errors.New("evidence id generator is required")
	ErrInvalidWorkerID  = errors.New("evidence worker id is invalid")
)

type IDGenerator func() (string, error)

// Runner generates one fixed-format SBOM and publishes it through the fenced
// job protocol. The process itself must run in the dedicated restricted
// Evidence Worker container; it is not embedded in the API Server or Agent.
type Runner struct {
	controller             *Controller
	generator              biz.SBOMGenerator
	publisher              biz.SBOMPublisher
	provenanceGenerator    biz.ProvenanceGenerator
	provenancePublisher    biz.ProvenancePublisher
	signatureVerifier      biz.SignatureVerifier
	trustResolver          biz.SignatureTrustResolver
	signatureSigner        biz.SignatureSigner
	vulnerabilityScanner   biz.VulnerabilityScanner
	vulnerabilityPublisher biz.VulnerabilityPublisher
	vulnerabilityFreshness time.Duration
	newID                  IDGenerator
	now                    Clock
	workerID               string
	leaseDuration          time.Duration
}

func (r *Runner) WithVulnerabilityScanning(scanner biz.VulnerabilityScanner,
	publisher biz.VulnerabilityPublisher, freshness time.Duration) (*Runner, error) {
	if scanner == nil {
		return nil, ErrMissingGenerator
	}
	if publisher == nil {
		return nil, ErrMissingPublisher
	}
	if freshness < time.Hour || freshness > 30*24*time.Hour {
		return nil, biz.ErrInvalidVulnerabilityReport
	}
	r.vulnerabilityScanner, r.vulnerabilityPublisher, r.vulnerabilityFreshness = scanner, publisher, freshness
	r.refreshClaimKinds()
	return r, nil
}

func (r *Runner) refreshClaimKinds() {
	kinds := []biz.EvidenceKind{biz.EvidenceKindSBOM}
	if r.provenanceGenerator != nil && r.provenancePublisher != nil {
		kinds = append(kinds, biz.EvidenceKindProvenance)
	}
	if r.signatureVerifier != nil && r.trustResolver != nil {
		kinds = append(kinds, biz.EvidenceKindSignature)
	}
	if r.vulnerabilityScanner != nil && r.vulnerabilityPublisher != nil {
		kinds = append(kinds, biz.EvidenceKindVulnerabilityReport)
	}
	r.controller.WithClaimKinds(kinds...)
}

func (r *Runner) WithSigning(signer biz.SignatureSigner) (*Runner, error) {
	if signer == nil {
		return nil, ErrMissingGenerator
	}
	r.signatureSigner = signer
	return r, nil
}

func (r *Runner) WithSignatures(verifier biz.SignatureVerifier,
	resolver biz.SignatureTrustResolver) (*Runner, error) {
	if verifier == nil || resolver == nil {
		return nil, ErrMissingGenerator
	}
	r.signatureVerifier, r.trustResolver = verifier, resolver
	r.refreshClaimKinds()
	return r, nil
}

func (r *Runner) WithProvenance(generator biz.ProvenanceGenerator,
	publisher biz.ProvenancePublisher) (*Runner, error) {
	if generator == nil {
		return nil, ErrMissingGenerator
	}
	if publisher == nil {
		return nil, ErrMissingPublisher
	}
	r.provenanceGenerator, r.provenancePublisher = generator, publisher
	r.refreshClaimKinds()
	return r, nil
}

func NewRunner(controller *Controller, generator biz.SBOMGenerator, publisher biz.SBOMPublisher,
	newID IDGenerator, now Clock, workerID string, leaseDuration time.Duration) (*Runner, error) {
	workerID = strings.TrimSpace(workerID)
	if controller == nil {
		return nil, ErrMissingQueue
	}
	if generator == nil {
		return nil, ErrMissingGenerator
	}
	if publisher == nil {
		return nil, ErrMissingPublisher
	}
	if newID == nil {
		return nil, ErrMissingID
	}
	if now == nil {
		return nil, ErrMissingClock
	}
	if !workerIdentifierPattern.MatchString(workerID) || leaseDuration <= 0 {
		return nil, ErrInvalidWorkerID
	}
	controller.WithClaimKinds(biz.EvidenceKindSBOM)
	return &Runner{
		controller: controller, generator: generator, publisher: publisher,
		newID: newID, now: now, workerID: workerID, leaseDuration: leaseDuration,
	}, nil
}

func (r *Runner) RunOnce(ctx context.Context) error {
	item, found, err := r.controller.Claim(ctx, r.workerID)
	if err != nil || !found {
		return err
	}
	if item.Status == biz.EvidenceJobQueued {
		next := biz.EvidenceJobGenerating
		if item.Kind == biz.EvidenceKindSignature {
			next = biz.EvidenceJobVerifying
		}
		item, err = r.controller.Advance(ctx, item, r.workerID, next)
		if err != nil {
			return err
		}
	}
	if item.Status != biz.EvidenceJobGenerating && item.Status != biz.EvidenceJobPublishing &&
		item.Status != biz.EvidenceJobVerifying {
		return biz.ErrInvalidEvidenceJob
	}
	switch item.Kind {
	case biz.EvidenceKindSBOM:
		return r.runSBOM(ctx, item)
	case biz.EvidenceKindProvenance:
		return r.runProvenance(ctx, item)
	case biz.EvidenceKindSignature:
		return r.runSignature(ctx, item)
	case biz.EvidenceKindVulnerabilityReport:
		return r.runVulnerabilityScan(ctx, item)
	default:
		return biz.ErrInvalidEvidenceJob
	}
}

func (r *Runner) runVulnerabilityScan(ctx context.Context, item biz.EvidenceJob) error {
	if r.vulnerabilityScanner == nil || r.vulnerabilityPublisher == nil || r.vulnerabilityFreshness == 0 {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureGeneration)
	}
	var report biz.VulnerabilityReport
	item, err := r.withHeartbeat(ctx, item, func(stepContext context.Context) error {
		var scanErr error
		report, scanErr = r.vulnerabilityScanner.ScanVulnerabilities(stepContext,
			biz.VulnerabilityScanRequest{ProjectID: item.ProjectID,
				RegistryCredentialID: item.RegistryCredentialID, RegistryRepository: item.RegistryRepository,
				SubjectDigest: item.SubjectDigest, FormatVersion: item.FormatVersion})
		return scanErr
	})
	if err != nil {
		failure := biz.EvidenceJobFailureGeneration
		if errors.Is(err, biz.ErrVulnerabilityReportSize) {
			failure = biz.EvidenceJobFailureResourceLimit
		} else if errors.Is(err, biz.ErrRegistryAuthentication) {
			failure = biz.EvidenceJobFailureImagePull
		}
		return r.recordFailure(ctx, item, failure)
	}
	if err := r.controller.ValidateFence(ctx, item, r.workerID); err != nil {
		return err
	}
	if item.Status == biz.EvidenceJobGenerating {
		item, err = r.controller.Advance(ctx, item, r.workerID, biz.EvidenceJobPublishing)
		if err != nil {
			return err
		}
	}
	var descriptor biz.PublishedDescriptor
	item, err = r.withHeartbeat(ctx, item, func(stepContext context.Context) error {
		var publishErr error
		descriptor, publishErr = r.vulnerabilityPublisher.PublishVulnerabilityReport(stepContext,
			biz.VulnerabilityPublication{ProjectID: item.ProjectID,
				RegistryCredentialID: item.RegistryCredentialID, RegistryRepository: item.RegistryRepository,
				SubjectDigest: item.SubjectDigest, Report: report, CreatedAt: item.CreatedAt})
		return publishErr
	})
	if err != nil || !validPublishedDescriptor(descriptor) {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureRegistryPublish)
	}
	evidenceID, err := r.newID()
	if err != nil {
		return err
	}
	evidence, err := biz.NewEvidence(biz.EvidenceInput{ID: evidenceID,
		OrganizationID: item.OrganizationID, ProjectID: item.ProjectID, ArtifactID: item.ArtifactID,
		SubjectDigest: item.SubjectDigest, Kind: item.Kind, MediaType: report.MediaType,
		FormatVersion: report.FormatVersion, Producer: item.Producer,
		RegistryRepository: item.RegistryRepository, DescriptorDigest: descriptor.Digest,
		VerificationStatus: biz.VerificationUnverified, CreatedAt: r.now().UTC()})
	if err != nil {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureRegistryPublish)
	}
	observationID, err := biz.VulnerabilityObservationID(item.ArtifactID, "trivy")
	if err != nil {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureGeneration)
	}
	freshUntil := report.ScannedAt.Add(r.vulnerabilityFreshness)
	if report.Database.NextUpdate.Before(freshUntil) {
		freshUntil = report.Database.NextUpdate
	}
	observation, err := biz.NewVulnerabilityObservation(biz.VulnerabilityObservation{
		ID: observationID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest, EvidenceID: evidence.ID,
		DescriptorDigest: evidence.DescriptorDigest, Scanner: "trivy", ScannerVersion: report.ScannerVersion,
		Database: report.Database, ScannedAt: report.ScannedAt, FreshUntil: freshUntil,
		Counts: report.Counts, HighestSeverity: report.HighestSeverity})
	if err != nil {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureGeneration)
	}
	_, _, _, err = r.controller.PublishVulnerabilityObservation(ctx, item, evidence, observation, r.workerID)
	return err
}

func (r *Runner) runSignature(ctx context.Context, item biz.EvidenceJob) error {
	if r.signatureVerifier == nil || r.trustResolver == nil || item.Status != biz.EvidenceJobVerifying {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureSignatureTrust)
	}
	var signingResult biz.SignatureSigningResult
	var err error
	if item.SignatureOperation == biz.SignatureOperationSignAndVerify {
		if r.signatureSigner == nil {
			return r.recordFailure(ctx, item, biz.EvidenceJobFailureSignatureSign)
		}
		item, err = r.withHeartbeat(ctx, item, func(stepContext context.Context) error {
			var signErr error
			signingResult, signErr = r.signatureSigner.SignSignature(stepContext, biz.SignatureSigningRequest{
				ProjectID: item.ProjectID, ProfileID: item.Signing.ProfileID,
				RegistryCredentialID: item.RegistryCredentialID, RegistryRepository: item.RegistryRepository,
				SubjectDigest: item.SubjectDigest, KeyReference: item.Signing.KeyReference})
			return signErr
		})
		if err != nil || signingResult.Provider != item.Signing.Provider ||
			signingResult.KeyReferenceFingerprint != item.Signing.KeyReferenceFingerprint {
			return r.recordFailure(ctx, item, biz.EvidenceJobFailureSignatureSign)
		}
		if err := r.controller.ValidateFence(ctx, item, r.workerID); err != nil {
			return err
		}
	}
	trust, err := r.trustResolver.ResolveSignatureTrust(ctx, item.Signature)
	if err != nil {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureSignatureTrust)
	}
	defer clear(trust.PublicKeyPEM)
	defer clear(trust.TrustedRootJSON)
	var result biz.SignatureVerificationResult
	item, err = r.withHeartbeat(ctx, item, func(stepContext context.Context) error {
		var verifyErr error
		result, verifyErr = r.signatureVerifier.VerifySignature(stepContext, biz.SignatureVerificationRequest{
			ProjectID: item.ProjectID, RegistryCredentialID: item.RegistryCredentialID,
			RegistryRepository: item.RegistryRepository, SubjectDigest: item.SubjectDigest, Trust: trust,
		})
		return verifyErr
	})
	if err != nil {
		failure := biz.EvidenceJobFailureSignatureVerify
		if errors.Is(err, biz.ErrRegistryAuthentication) {
			failure = biz.EvidenceJobFailureImagePull
		}
		return r.recordFailure(ctx, item, failure)
	}
	expectedTrustHash := item.Signature.TrustedRootHash
	if item.Signature.Mode == biz.SignatureTrustPublicKey {
		expectedTrustHash = item.Signature.PublicKeyFingerprint
	}
	if result.TrustMode != item.Signature.Mode || result.TrustRootHash != expectedTrustHash ||
		result.SignerIdentity != item.Signature.CertificateIdentity || result.OIDCIssuer != item.Signature.OIDCIssuer {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureSignatureVerify)
	}
	if err := r.controller.ValidateFence(ctx, item, r.workerID); err != nil {
		return err
	}
	verificationID, err := r.newID()
	if err != nil {
		return err
	}
	verification, err := biz.NewEvidenceVerification(biz.EvidenceVerification{
		ID: verificationID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest,
		PolicyID: item.Signature.PolicyID, PolicyVersion: item.Signature.PolicyVersion,
		SigningProfileID: item.Signing.ProfileID, SigningProfileVersion: item.Signing.ProfileVersion,
		SigningKeyProvider: signingResult.Provider, SigningKeyFingerprint: signingResult.KeyReferenceFingerprint,
		TrustMode: result.TrustMode, TrustRootHash: result.TrustRootHash,
		SignerIdentity: result.SignerIdentity, OIDCIssuer: result.OIDCIssuer,
		BundleSetDigest: result.BundleSetDigest, Verifier: "cosign", VerifierVersion: result.VerifierVersion,
		VerificationStatus: biz.VerificationVerified, CreatedAt: r.now().UTC(),
	})
	if err != nil {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureSignatureVerify)
	}
	_, _, err = r.controller.PublishSignatureVerification(ctx, item, verification, r.workerID)
	return err
}

func (r *Runner) runSBOM(ctx context.Context, item biz.EvidenceJob) error {
	var document biz.SBOMDocument
	item, err := r.withHeartbeat(ctx, item, func(stepContext context.Context) error {
		var generationErr error
		document, generationErr = r.generator.GenerateSBOM(stepContext, biz.SBOMRequest{
			ProjectID: item.ProjectID, RegistryCredentialID: item.RegistryCredentialID,
			RegistryRepository: item.RegistryRepository, SubjectDigest: item.SubjectDigest,
			FormatVersion: item.FormatVersion,
		})
		return generationErr
	})
	if err != nil {
		return r.recordFailure(ctx, item, categorizeSBOMGeneration(err))
	}
	if err := r.controller.ValidateFence(ctx, item, r.workerID); err != nil {
		return err
	}
	if item.Status == biz.EvidenceJobGenerating {
		item, err = r.controller.Advance(ctx, item, r.workerID, biz.EvidenceJobPublishing)
		if err != nil {
			return err
		}
	}
	var descriptor biz.PublishedDescriptor
	item, err = r.withHeartbeat(ctx, item, func(stepContext context.Context) error {
		var publishErr error
		descriptor, publishErr = r.publisher.PublishSBOM(stepContext, biz.SBOMPublication{
			ProjectID: item.ProjectID, RegistryCredentialID: item.RegistryCredentialID,
			RegistryRepository: item.RegistryRepository, SubjectDigest: item.SubjectDigest,
			Document: document, CreatedAt: item.CreatedAt,
		})
		return publishErr
	})
	if err != nil || !validPublishedDescriptor(descriptor) {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureRegistryPublish)
	}
	evidenceID, err := r.newID()
	if err != nil {
		return err
	}
	evidence, err := biz.NewEvidence(biz.EvidenceInput{
		ID: evidenceID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest, Kind: item.Kind,
		MediaType: document.MediaType, FormatVersion: document.FormatVersion,
		Producer: item.Producer, RegistryRepository: item.RegistryRepository,
		DescriptorDigest: descriptor.Digest, VerificationStatus: biz.VerificationUnverified,
		CreatedAt: r.now().UTC(),
	})
	if err != nil {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureRegistryPublish)
	}
	_, _, err = r.controller.Publish(ctx, item, evidence, r.workerID)
	return err
}

func (r *Runner) runProvenance(ctx context.Context, item biz.EvidenceJob) error {
	if r.provenanceGenerator == nil || r.provenancePublisher == nil {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureGeneration)
	}
	var document biz.ProvenanceDocument
	item, err := r.withHeartbeat(ctx, item, func(stepContext context.Context) error {
		var generationErr error
		document, generationErr = r.provenanceGenerator.GenerateProvenance(stepContext,
			biz.ProvenanceRequest{
				RegistryRepository: item.RegistryRepository,
				SubjectDigest:      item.SubjectDigest,
				Recipe:             item.Provenance,
			})
		return generationErr
	})
	if err != nil {
		return r.recordFailure(ctx, item, categorizeProvenanceGeneration(err))
	}
	if err := r.controller.ValidateFence(ctx, item, r.workerID); err != nil {
		return err
	}
	if item.Status == biz.EvidenceJobGenerating {
		item, err = r.controller.Advance(ctx, item, r.workerID, biz.EvidenceJobPublishing)
		if err != nil {
			return err
		}
	}
	var descriptor biz.PublishedDescriptor
	item, err = r.withHeartbeat(ctx, item, func(stepContext context.Context) error {
		var publishErr error
		descriptor, publishErr = r.provenancePublisher.PublishProvenance(stepContext,
			biz.ProvenancePublication{
				ProjectID: item.ProjectID, RegistryCredentialID: item.RegistryCredentialID,
				RegistryRepository: item.RegistryRepository, SubjectDigest: item.SubjectDigest,
				Document: document, CreatedAt: item.CreatedAt,
			})
		return publishErr
	})
	if err != nil || !validPublishedDescriptor(descriptor) {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureRegistryPublish)
	}
	evidenceID, err := r.newID()
	if err != nil {
		return err
	}
	evidence, err := biz.NewEvidence(biz.EvidenceInput{
		ID: evidenceID, OrganizationID: item.OrganizationID, ProjectID: item.ProjectID,
		ArtifactID: item.ArtifactID, SubjectDigest: item.SubjectDigest, Kind: item.Kind,
		MediaType: document.MediaType, FormatVersion: document.FormatVersion,
		PredicateType: document.PredicateType, Producer: item.Producer,
		RegistryRepository: item.RegistryRepository, DescriptorDigest: descriptor.Digest,
		VerificationStatus: biz.VerificationUnverified, CreatedAt: r.now().UTC(),
	})
	if err != nil {
		return r.recordFailure(ctx, item, biz.EvidenceJobFailureRegistryPublish)
	}
	_, _, err = r.controller.Publish(ctx, item, evidence, r.workerID)
	return err
}

func (r *Runner) withHeartbeat(ctx context.Context, item biz.EvidenceJob,
	operation func(context.Context) error) (biz.EvidenceJob, error) {
	stepContext, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- operation(stepContext) }()
	interval := r.leaseDuration / 3
	if interval <= 0 {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case err := <-result:
			return item, err
		case <-ctx.Done():
			return item, ctx.Err()
		case <-ticker.C:
			updated, err := r.controller.Heartbeat(ctx, item, r.workerID)
			if err != nil {
				cancel()
				return item, err
			}
			item = updated
		}
	}
}

func (r *Runner) recordFailure(ctx context.Context, item biz.EvidenceJob,
	failure biz.EvidenceJobFailure) error {
	if errors.Is(context.Cause(ctx), context.Canceled) || errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return context.Cause(ctx)
	}
	_, err := r.controller.Fail(ctx, item, r.workerID, failure)
	return err
}

func categorizeSBOMGeneration(err error) biz.EvidenceJobFailure {
	if errors.Is(err, biz.ErrSBOMTooLarge) || errors.Is(err, biz.ErrSBOMImageTooLarge) {
		return biz.EvidenceJobFailureResourceLimit
	}
	return biz.EvidenceJobFailureGeneration
}

func categorizeProvenanceGeneration(err error) biz.EvidenceJobFailure {
	if errors.Is(err, biz.ErrProvenanceTooLarge) {
		return biz.EvidenceJobFailureResourceLimit
	}
	return biz.EvidenceJobFailureGeneration
}

func validPublishedDescriptor(descriptor biz.PublishedDescriptor) bool {
	parsed, err := digest.Parse(strings.TrimSpace(descriptor.Digest))
	return err == nil && parsed.Algorithm() == digest.SHA256 && parsed.Validate() == nil &&
		descriptor.MediaType == "application/vnd.oci.image.manifest.v1+json"
}

var workerIdentifierPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
