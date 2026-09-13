package worker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	supplychaindata "github.com/owndock/owndock/internal/modules/supplychain/data"
)

type sbomGeneratorProbe struct {
	document biz.SBOMDocument
	err      error
	request  biz.SBOMRequest
}

func (g *sbomGeneratorProbe) GenerateSBOM(_ context.Context, request biz.SBOMRequest) (biz.SBOMDocument, error) {
	g.request = request
	return g.document, g.err
}

type sbomPublisherProbe struct {
	descriptor  biz.PublishedDescriptor
	err         error
	publication biz.SBOMPublication
}

type provenanceGeneratorProbe struct {
	document biz.ProvenanceDocument
	err      error
	request  biz.ProvenanceRequest
}

func (g *provenanceGeneratorProbe) GenerateProvenance(_ context.Context,
	request biz.ProvenanceRequest) (biz.ProvenanceDocument, error) {
	g.request = request
	return g.document, g.err
}

type provenancePublisherProbe struct {
	descriptor  biz.PublishedDescriptor
	err         error
	publication biz.ProvenancePublication
}

type vulnerabilityScannerProbe struct {
	report  biz.VulnerabilityReport
	err     error
	request biz.VulnerabilityScanRequest
}

func (s *vulnerabilityScannerProbe) ScanVulnerabilities(_ context.Context,
	request biz.VulnerabilityScanRequest) (biz.VulnerabilityReport, error) {
	s.request = request
	return s.report, s.err
}

type vulnerabilityPublisherProbe struct {
	descriptor  biz.PublishedDescriptor
	err         error
	publication biz.VulnerabilityPublication
}

func (p *vulnerabilityPublisherProbe) PublishVulnerabilityReport(_ context.Context,
	publication biz.VulnerabilityPublication) (biz.PublishedDescriptor, error) {
	p.publication = publication
	return p.descriptor, p.err
}

type signatureTrustResolverProbe struct {
	material biz.SignatureTrustMaterial
	err      error
}

func (r signatureTrustResolverProbe) ResolveSignatureTrust(context.Context,
	biz.SignatureTrustSnapshot) (biz.SignatureTrustMaterial, error) {
	return r.material, r.err
}

type signatureVerifierProbe struct {
	result  biz.SignatureVerificationResult
	err     error
	request biz.SignatureVerificationRequest
}

type signatureSignerProbe struct {
	result  biz.SignatureSigningResult
	err     error
	request biz.SignatureSigningRequest
}

func (s *signatureSignerProbe) SignSignature(_ context.Context,
	request biz.SignatureSigningRequest) (biz.SignatureSigningResult, error) {
	s.request = request
	return s.result, s.err
}

func (v *signatureVerifierProbe) VerifySignature(_ context.Context,
	request biz.SignatureVerificationRequest) (biz.SignatureVerificationResult, error) {
	v.request = request
	return v.result, v.err
}

func (p *provenancePublisherProbe) PublishProvenance(_ context.Context,
	publication biz.ProvenancePublication) (biz.PublishedDescriptor, error) {
	p.publication = publication
	return p.descriptor, p.err
}

func (p *sbomPublisherProbe) PublishSBOM(_ context.Context,
	publication biz.SBOMPublication) (biz.PublishedDescriptor, error) {
	p.publication = publication
	return p.descriptor, p.err
}

func validSBOMDocument(t *testing.T) biz.SBOMDocument {
	t.Helper()
	document, err := biz.NewCycloneDX16Document(
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`), 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func newRunnerFixture(t *testing.T, generator biz.SBOMGenerator,
	publisher biz.SBOMPublisher) (*Runner, *queueProbe) {
	t.Helper()
	now := func() time.Time { return time.Unix(110, 0) }
	queue := &queueProbe{item: workerJobFixture(t), wantWorker: "worker-1", wantGeneration: 1}
	controller, err := NewController(queue, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(controller, generator, publisher, func() (string, error) {
		return "evidence-result-1", nil
	}, now, "worker-1", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return runner, queue
}

func TestRunnerGeneratesPublishesAndCommitsSBOMEvidence(t *testing.T) {
	document := validSBOMDocument(t)
	generator := &sbomGeneratorProbe{document: document}
	publisher := &sbomPublisherProbe{descriptor: biz.PublishedDescriptor{
		Digest:    "sha256:" + strings.Repeat("c", 64),
		MediaType: "application/vnd.oci.image.manifest.v1+json",
	}}
	runner, queue := newRunnerFixture(t, generator, publisher)
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if queue.item.Status != biz.EvidenceJobSucceeded || queue.publishedEvidence.ID != "evidence-result-1" ||
		queue.publishedEvidence.DescriptorDigest != publisher.descriptor.Digest {
		t.Fatalf("published queue = %+v evidence = %+v", queue.item, queue.publishedEvidence)
	}
	if generator.request.CanonicalSubject() != queue.item.RegistryRepository+"@"+queue.item.SubjectDigest ||
		publisher.publication.Document.ContentDigest != document.ContentDigest {
		t.Fatalf("generator request / publication = %+v / %+v", generator.request, publisher.publication)
	}
}

func TestRunnerGeneratesPublishesAndCommitsProvenanceEvidence(t *testing.T) {
	now := func() time.Time { return time.Unix(210, 0).UTC() }
	recipe := biz.ProvenanceRecipe{
		BuildID: "build-1", ApplicationID: "application-1",
		SourceURI: "git+https://git.example.com/team/api.git",
		SourceRef: "refs/heads/main", CommitSHA: strings.Repeat("b", 40),
		ConfigurationID: "configuration-1", ConfigurationVersion: 7,
		DockerfilePath: "Dockerfile", ContextPath: ".", TargetPlatform: "linux/amd64",
		CPUMilli: 2000, MemoryBytes: 2 * 1024 * 1024 * 1024,
		DiskBytes: 10 * 1024 * 1024 * 1024, TimeoutSeconds: 1800,
		BuilderID:      biz.OwnDockBuildKitBuilderIDV1,
		BuilderVersion: "0.1.0", BuilderCommit: strings.Repeat("c", 40),
		BuildKitVersion: "v0.31.2",
		BuildKitImage:   "moby/buildkit:v0.31.2-rootless@sha256:" + strings.Repeat("d", 64),
		FrontendImage:   "docker/dockerfile:1.25.0@sha256:" + strings.Repeat("e", 64),
		StartedAt:       time.Unix(100, 0).UTC(), FinishedAt: time.Unix(200, 0).UTC(),
	}
	job, err := biz.NewEvidenceJob(biz.EvidenceJobInput{
		ID: "provenance-job-1", OrganizationID: "organization-1", ProjectID: "project-1",
		ArtifactID: "artifact-1", SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", RegistryCredentialID: "registry-1",
		Kind: biz.EvidenceKindProvenance, FormatVersion: biz.SLSAProvenanceFormatVersion,
		Producer: "owndock-build-worker/0.1.0", Provenance: recipe, CreatedAt: time.Unix(200, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	realGenerator, _ := supplychaindata.NewSLSAProvenanceGenerator(64 * 1024)
	document, err := realGenerator.GenerateProvenance(t.Context(), biz.ProvenanceRequest{
		RegistryRepository: job.RegistryRepository, SubjectDigest: job.SubjectDigest, Recipe: recipe,
	})
	if err != nil {
		t.Fatal(err)
	}
	generator := &provenanceGeneratorProbe{document: document}
	publisher := &provenancePublisherProbe{descriptor: biz.PublishedDescriptor{
		Digest: "sha256:" + strings.Repeat("c", 64), MediaType: "application/vnd.oci.image.manifest.v1+json",
	}}
	queue := &queueProbe{item: job, wantWorker: "worker-1", wantGeneration: 1}
	controller, _ := NewController(queue, now, 30*time.Second)
	runner, _ := NewRunner(controller, &sbomGeneratorProbe{}, &sbomPublisherProbe{},
		func() (string, error) { return "provenance-result-1", nil }, now, "worker-1", 30*time.Second)
	runner, err = runner.WithProvenance(generator, publisher)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if queue.item.Status != biz.EvidenceJobSucceeded ||
		queue.publishedEvidence.Kind != biz.EvidenceKindProvenance ||
		queue.publishedEvidence.PredicateType != biz.SLSAProvenancePredicateV1 ||
		queue.publishedEvidence.DescriptorDigest != publisher.descriptor.Digest {
		t.Fatalf("published provenance = %+v, job = %+v", queue.publishedEvidence, queue.item)
	}
	if generator.request.Recipe.CommitSHA != recipe.CommitSHA ||
		publisher.publication.Document.ContentDigest != document.ContentDigest {
		t.Fatalf("request / publication = %+v / %+v", generator.request, publisher.publication)
	}
}

func TestRunnerScansPublishesAndAtomicallyProjectsLatestVulnerabilityObservation(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC) }
	job, err := biz.NewEvidenceJob(biz.EvidenceJobInput{ID: "vulnerability-job-1",
		OrganizationID: "organization-1", ProjectID: "project-1", ArtifactID: "artifact-1",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64), RegistryRepository: "registry.example.com/team/api",
		RegistryCredentialID: "registry-1", Kind: biz.EvidenceKindVulnerabilityReport,
		FormatVersion: biz.TrivyReportFormatVersion, Producer: "trivy/0.74.0", CreatedAt: now()})
	if err != nil {
		t.Fatal(err)
	}
	subject := job.RegistryRepository + "@" + job.SubjectDigest
	database := biz.VulnerabilityDatabase{SchemaVersion: 2,
		UpdatedAt: now().Add(-time.Hour), DownloadedAt: now().Add(-30 * time.Minute),
		NextUpdate: now().Add(6 * time.Hour)}
	report, err := biz.NewVulnerabilityReport([]byte(`{"validated":"trivy-report"}`), 4096,
		supplychaindata.PinnedTrivyVersion, database, now(),
		biz.VulnerabilityCounts{High: 1, Total: 1, Fixable: 1})
	if err != nil {
		t.Fatal(err)
	}
	scanner := &vulnerabilityScannerProbe{report: report}
	publisher := &vulnerabilityPublisherProbe{descriptor: biz.PublishedDescriptor{
		Digest: "sha256:" + strings.Repeat("c", 64), MediaType: "application/vnd.oci.image.manifest.v1+json"}}
	queue := &queueProbe{item: job, wantWorker: "worker-1", wantGeneration: 1}
	controller, _ := NewController(queue, now, 30*time.Second)
	runner, _ := NewRunner(controller, &sbomGeneratorProbe{}, &sbomPublisherProbe{},
		func() (string, error) { return "vulnerability-evidence-1", nil }, now, "worker-1", 30*time.Second)
	runner, err = runner.WithVulnerabilityScanning(scanner, publisher, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if queue.item.Status != biz.EvidenceJobSucceeded ||
		queue.publishedEvidence.Kind != biz.EvidenceKindVulnerabilityReport ||
		queue.publishedObservation.EvidenceID != queue.publishedEvidence.ID ||
		queue.publishedObservation.HighestSeverity != biz.VulnerabilitySeverityHigh ||
		!queue.publishedObservation.FreshUntil.Equal(database.NextUpdate) ||
		scanner.request.CanonicalSubject() != subject || publisher.publication.Report.ContentDigest != report.ContentDigest {
		t.Fatalf("job=%+v evidence=%+v observation=%+v", queue.item, queue.publishedEvidence, queue.publishedObservation)
	}
}

func TestRunnerVerifiesSignatureWithFrozenTrustSnapshot(t *testing.T) {
	now := func() time.Time { return time.Unix(310, 0).UTC() }
	snapshot := biz.SignatureTrustSnapshot{PolicyID: "policy-1", PolicyVersion: 3,
		Mode: biz.SignatureTrustKeyless, TrustedRootID: "offline-root-1",
		TrustedRootHash:     "sha256:" + strings.Repeat("b", 64),
		CertificateIdentity: "https://git.example.com/team/api/.ci/release@refs/tags/v1.0.0",
		OIDCIssuer:          "https://issuer.example.com"}
	job, err := biz.NewEvidenceJob(biz.EvidenceJobInput{ID: "signature-job-1",
		OrganizationID: "organization-1", ProjectID: "project-1", ArtifactID: "artifact-1",
		SubjectDigest:      "sha256:" + strings.Repeat("a", 64),
		RegistryRepository: "registry.example.com/team/api", RegistryCredentialID: "registry-1",
		Kind: biz.EvidenceKindSignature, FormatVersion: biz.CosignSignatureFormatV03,
		Producer: "cosign/3.0.6", Signature: snapshot, CreatedAt: time.Unix(300, 0)})
	if err != nil {
		t.Fatal(err)
	}
	root := append([]byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json","tlogs":[]}`),
		[]byte(strings.Repeat(" ", 64))...)
	verifier := &signatureVerifierProbe{result: biz.SignatureVerificationResult{
		TrustMode: snapshot.Mode, TrustRootHash: snapshot.TrustedRootHash,
		SignerIdentity: snapshot.CertificateIdentity, OIDCIssuer: snapshot.OIDCIssuer,
		BundleSetDigest: "sha256:" + strings.Repeat("c", 64), VerifierVersion: "3.0.6"}}
	queue := &queueProbe{item: job, wantWorker: "worker-1", wantGeneration: 1}
	controller, _ := NewController(queue, now, 30*time.Second)
	runner, _ := NewRunner(controller, &sbomGeneratorProbe{}, &sbomPublisherProbe{},
		func() (string, error) { return "verification-1", nil }, now, "worker-1", 30*time.Second)
	runner, err = runner.WithSignatures(verifier, signatureTrustResolverProbe{material: biz.SignatureTrustMaterial{
		Mode: snapshot.Mode, TrustedRootJSON: root, CertificateIdentity: snapshot.CertificateIdentity,
		OIDCIssuer: snapshot.OIDCIssuer}})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if queue.item.Status != biz.EvidenceJobSucceeded || queue.publishedVerification.PolicyVersion != 3 ||
		queue.publishedVerification.BundleSetDigest != verifier.result.BundleSetDigest ||
		verifier.request.CanonicalSubject() != job.RegistryRepository+"@"+job.SubjectDigest {
		t.Fatalf("signature result = %+v job = %+v request = %+v", queue.publishedVerification, queue.item, verifier.request)
	}
}

func TestRunnerSignsWithKMSAndThenVerifiesUsingFrozenPublicKey(t *testing.T) {
	now := func() time.Time { return time.Unix(410, 0).UTC() }
	job, trust, signing, canonical := signingJobFixture(t)
	signer := &signatureSignerProbe{result: biz.SignatureSigningResult{Provider: signing.Provider,
		KeyReferenceFingerprint: signing.KeyReferenceFingerprint}}
	verifier := &signatureVerifierProbe{result: biz.SignatureVerificationResult{TrustMode: trust.Mode,
		TrustRootHash: trust.PublicKeyFingerprint, BundleSetDigest: "sha256:" + strings.Repeat("c", 64),
		VerifierVersion: "3.0.6"}}
	queue := &queueProbe{item: job, wantWorker: "worker-1", wantGeneration: 1}
	controller, _ := NewController(queue, now, 30*time.Second)
	runner, _ := NewRunner(controller, &sbomGeneratorProbe{}, &sbomPublisherProbe{},
		func() (string, error) { return "verification-1", nil }, now, "worker-1", 30*time.Second)
	runner, _ = runner.WithSignatures(verifier, signatureTrustResolverProbe{material: biz.SignatureTrustMaterial{
		Mode: trust.Mode, PublicKeyPEM: append([]byte(nil), canonical...)}})
	runner, _ = runner.WithSigning(signer)
	if err := runner.RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if queue.item.Status != biz.EvidenceJobSucceeded || queue.publishedVerification.SigningProfileID != signing.ProfileID ||
		signer.request.KeyReference != signing.KeyReference || verifier.request.SubjectDigest != job.SubjectDigest {
		t.Fatalf("sign and verify = %+v signer=%+v verifier=%+v", queue.publishedVerification, signer.request, verifier.request)
	}
}

func TestRunnerFailsClosedWhenSigningOrPostSigningVerificationFails(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		signer      *signatureSignerProbe
		verifierErr error
		wantFailure biz.EvidenceJobFailure
	}{
		{name: "KMS signing failure", signer: &signatureSignerProbe{err: biz.ErrSignatureSigning},
			wantFailure: biz.EvidenceJobFailureSignatureSign},
		{name: "signing identity mismatch", signer: &signatureSignerProbe{result: biz.SignatureSigningResult{
			Provider: biz.SigningKeyAWSKMS, KeyReferenceFingerprint: "sha256:" + strings.Repeat("f", 64)}},
			wantFailure: biz.EvidenceJobFailureSignatureSign},
		{name: "post signing verification failure", signer: nil, verifierErr: biz.ErrSignatureVerification,
			wantFailure: biz.EvidenceJobFailureSignatureVerify},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			job, trust, signing, canonical := signingJobFixture(t)
			signer := testCase.signer
			if signer == nil {
				signer = &signatureSignerProbe{result: biz.SignatureSigningResult{Provider: signing.Provider,
					KeyReferenceFingerprint: signing.KeyReferenceFingerprint}}
			}
			verifier := &signatureVerifierProbe{err: testCase.verifierErr}
			now := func() time.Time { return time.Unix(410, 0).UTC() }
			queue := &queueProbe{item: job, wantWorker: "worker-1", wantGeneration: 1}
			controller, _ := NewController(queue, now, 30*time.Second)
			runner, _ := NewRunner(controller, &sbomGeneratorProbe{}, &sbomPublisherProbe{},
				func() (string, error) { return "verification-1", nil }, now, "worker-1", 30*time.Second)
			runner, _ = runner.WithSignatures(verifier, signatureTrustResolverProbe{material: biz.SignatureTrustMaterial{
				Mode: trust.Mode, PublicKeyPEM: append([]byte(nil), canonical...)}})
			runner, _ = runner.WithSigning(signer)
			if err := runner.RunOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			if queue.item.Status != biz.EvidenceJobFailed || queue.item.Failure != testCase.wantFailure ||
				queue.publishedVerification.ID != "" {
				t.Fatalf("failed signature job = %+v verification=%+v", queue.item, queue.publishedVerification)
			}
		})
	}
}

func signingJobFixture(t *testing.T) (biz.EvidenceJob, biz.SignatureTrustSnapshot,
	biz.SignatureSigningSnapshot, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	canonical, fingerprint, err := biz.NormalizeSignaturePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	trust := biz.SignatureTrustSnapshot{PolicyID: "policy-1", PolicyVersion: 2,
		Mode: biz.SignatureTrustPublicKey, PublicKeyPEM: string(canonical), PublicKeyFingerprint: fingerprint}
	keyReference := "hashivault://release-signing-key"
	signing := biz.SignatureSigningSnapshot{ProfileID: "profile-1", ProfileVersion: 3,
		Provider: biz.SigningKeyVault, KeyReference: keyReference,
		KeyReferenceFingerprint: biz.SigningKeyReferenceFingerprint(keyReference), TrustPolicyID: trust.PolicyID}
	job, err := biz.NewEvidenceJob(biz.EvidenceJobInput{ID: "signature-sign-job-1",
		OrganizationID: "organization-1", ProjectID: "project-1", ArtifactID: "artifact-1",
		SubjectDigest: "sha256:" + strings.Repeat("a", 64), RegistryRepository: "registry.example.com/team/api",
		RegistryCredentialID: "registry-1", Kind: biz.EvidenceKindSignature,
		FormatVersion: biz.CosignSignatureFormatV03, Producer: biz.CosignVerifierProducerV306,
		Signature: trust, SignatureOperation: biz.SignatureOperationSignAndVerify, Signing: signing,
		CreatedAt: time.Unix(400, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return job, trust, signing, canonical
}

func TestRunnerRecordsBoundedGenerationAndRegistryFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		generator biz.SBOMGenerator
		publisher biz.SBOMPublisher
		failure   biz.EvidenceJobFailure
	}{
		{
			name: "oversized SBOM", generator: &sbomGeneratorProbe{err: biz.ErrSBOMTooLarge},
			publisher: &sbomPublisherProbe{}, failure: biz.EvidenceJobFailureResourceLimit,
		},
		{
			name: "oversized image layer", generator: &sbomGeneratorProbe{err: biz.ErrSBOMImageTooLarge},
			publisher: &sbomPublisherProbe{}, failure: biz.EvidenceJobFailureResourceLimit,
		},
		{
			name: "generation", generator: &sbomGeneratorProbe{err: biz.ErrSBOMGeneration},
			publisher: &sbomPublisherProbe{}, failure: biz.EvidenceJobFailureGeneration,
		},
		{
			name: "registry", generator: &sbomGeneratorProbe{document: validSBOMDocument(t)},
			publisher: &sbomPublisherProbe{err: errors.New("secret upstream detail")},
			failure:   biz.EvidenceJobFailureRegistryPublish,
		},
		{
			name: "invalid descriptor", generator: &sbomGeneratorProbe{document: validSBOMDocument(t)},
			publisher: &sbomPublisherProbe{descriptor: biz.PublishedDescriptor{Digest: "bad"}},
			failure:   biz.EvidenceJobFailureRegistryPublish,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner, queue := newRunnerFixture(t, test.generator, test.publisher)
			if err := runner.RunOnce(t.Context()); err != nil {
				t.Fatalf("RunOnce() error = %v", err)
			}
			if queue.item.Status != biz.EvidenceJobFailed || queue.item.Failure != test.failure ||
				queue.publishedEvidence.ID != "" {
				t.Fatalf("failed queue = %+v", queue.item)
			}
		})
	}
}

func TestNewRunnerValidatesIsolationDependencies(t *testing.T) {
	clock := func() time.Time { return time.Unix(110, 0) }
	queue := &queueProbe{item: workerJobFixture(t)}
	controller, _ := NewController(queue, clock, time.Minute)
	generator := &sbomGeneratorProbe{}
	publisher := &sbomPublisherProbe{}
	id := func() (string, error) { return "id-1", nil }
	for _, test := range []struct {
		name       string
		controller *Controller
		generator  biz.SBOMGenerator
		publisher  biz.SBOMPublisher
		id         IDGenerator
		clock      Clock
		worker     string
		lease      time.Duration
		want       error
	}{
		{name: "controller", generator: generator, publisher: publisher, id: id, clock: clock, worker: "worker-1", lease: time.Minute, want: ErrMissingQueue},
		{name: "generator", controller: controller, publisher: publisher, id: id, clock: clock, worker: "worker-1", lease: time.Minute, want: ErrMissingGenerator},
		{name: "publisher", controller: controller, generator: generator, id: id, clock: clock, worker: "worker-1", lease: time.Minute, want: ErrMissingPublisher},
		{name: "id", controller: controller, generator: generator, publisher: publisher, clock: clock, worker: "worker-1", lease: time.Minute, want: ErrMissingID},
		{name: "clock", controller: controller, generator: generator, publisher: publisher, id: id, worker: "worker-1", lease: time.Minute, want: ErrMissingClock},
		{name: "worker", controller: controller, generator: generator, publisher: publisher, id: id, clock: clock, worker: "bad worker", lease: time.Minute, want: ErrInvalidWorkerID},
		{name: "lease", controller: controller, generator: generator, publisher: publisher, id: id, clock: clock, worker: "worker-1", want: ErrInvalidWorkerID},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRunner(test.controller, test.generator, test.publisher, test.id,
				test.clock, test.worker, test.lease)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewRunner() error = %v, want %v", err, test.want)
			}
		})
	}
}
