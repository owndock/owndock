package data

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type ORASPublisherOptions struct {
	Credentials      biz.RegistryCredentialProvider
	AllowPlainHTTP   bool
	MaxDocumentBytes int64
	RegistryCABundle []byte
}

const ORASGoVersion = "2.6.2"

type ORASPublisher struct {
	credentials      biz.RegistryCredentialProvider
	allowPlainHTTP   bool
	maxDocumentBytes int64
	client           *http.Client
}

func NewORASPublisher(options ORASPublisherOptions) (*ORASPublisher, error) {
	if options.MaxDocumentBytes < 1024 || options.MaxDocumentBytes > 64*1024*1024 {
		return nil, biz.ErrInvalidEvidenceJob
	}
	publisher := &ORASPublisher{
		credentials: options.Credentials, allowPlainHTTP: options.AllowPlainHTTP,
		maxDocumentBytes: options.MaxDocumentBytes,
	}
	client, err := newRegistryHTTPClient(publisher.allowPlainHTTP, options.RegistryCABundle)
	if err != nil {
		return nil, biz.ErrInvalidEvidenceJob
	}
	publisher.client = client
	return publisher, nil
}

func (p *ORASPublisher) PublishSBOM(ctx context.Context,
	publication biz.SBOMPublication) (biz.PublishedDescriptor, error) {
	if err := validateSBOMPublication(publication, p.maxDocumentBytes); err != nil {
		return biz.PublishedDescriptor{}, err
	}
	return p.publish(ctx, publication.ProjectID, publication.RegistryCredentialID,
		publication.RegistryRepository, publication.SubjectDigest,
		publication.Document.MediaType, publication.Document.Content,
		publication.Document.ContentDigest, publication.CreatedAt)
}

func (p *ORASPublisher) PublishProvenance(ctx context.Context,
	publication biz.ProvenancePublication) (biz.PublishedDescriptor, error) {
	if err := validateProvenancePublication(publication, p.maxDocumentBytes); err != nil {
		return biz.PublishedDescriptor{}, err
	}
	return p.publish(ctx, publication.ProjectID, publication.RegistryCredentialID,
		publication.RegistryRepository, publication.SubjectDigest,
		publication.Document.MediaType, publication.Document.Content,
		publication.Document.ContentDigest, publication.CreatedAt)
}

func (p *ORASPublisher) PublishVulnerabilityReport(ctx context.Context,
	publication biz.VulnerabilityPublication) (biz.PublishedDescriptor, error) {
	if err := validateVulnerabilityPublication(publication, p.maxDocumentBytes); err != nil {
		return biz.PublishedDescriptor{}, err
	}
	return p.publish(ctx, publication.ProjectID, publication.RegistryCredentialID,
		publication.RegistryRepository, publication.SubjectDigest,
		publication.Report.MediaType, publication.Report.Content,
		publication.Report.ContentDigest, publication.CreatedAt)
}

func (p *ORASPublisher) publish(ctx context.Context, projectID, credentialID,
	registryRepository, subjectDigest, documentMediaType string,
	documentContent []byte, documentDigest string, createdAt time.Time,
) (biz.PublishedDescriptor, error) {
	named, _ := reference.ParseNormalizedNamed(registryRepository)
	registry := reference.Domain(named)
	if p.allowPlainHTTP && !loopbackRegistry(registry) {
		return biz.PublishedDescriptor{}, biz.ErrInvalidEvidenceJob
	}
	repository, err := remote.NewRepository(registryRepository)
	if err != nil {
		return biz.PublishedDescriptor{}, biz.ErrInvalidEvidenceJob
	}
	repository.PlainHTTP = p.allowPlainHTTP
	credential := biz.RegistryCredential{AuthenticationMode: registryauth.ModeAnonymous}
	if p.credentials != nil {
		credential, err = p.credentials.ResolveRegistryCredential(ctx, projectID,
			credentialID, registry)
		if err != nil || !validCosignCredential(credential) {
			clear(credential.Password)
			return biz.PublishedDescriptor{}, biz.ErrRegistryAuthentication
		}
		defer clear(credential.Password)
	}
	authClient := &auth.Client{
		Client: p.client, Cache: auth.NewSingleContextCache(),
		Credential: auth.StaticCredential(registry, auth.Credential{
			Username: credential.Username, Password: string(credential.Password),
		}),
	}
	authClient.SetUserAgent("owndock-evidence-worker")
	repository.Client = authClient
	defer func() { authClient.Credential = nil }()
	subject, err := repository.Resolve(ctx, subjectDigest)
	if err != nil {
		return biz.PublishedDescriptor{}, stableRegistryError(err)
	}
	store := memory.New()
	layer, err := oras.PushBytes(ctx, store, documentMediaType, documentContent)
	if err != nil || layer.Digest.String() != documentDigest {
		return biz.PublishedDescriptor{}, biz.ErrInvalidEvidence
	}
	manifest, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1,
		documentMediaType, oras.PackManifestOptions{
			Subject: &subject, Layers: []ocispec.Descriptor{layer},
			ManifestAnnotations: map[string]string{
				ocispec.AnnotationCreated: createdAt.UTC().Format(time.RFC3339Nano),
			},
		})
	if err != nil {
		return biz.PublishedDescriptor{}, biz.ErrInvalidEvidence
	}
	if err := oras.CopyGraph(ctx, store, repository, manifest, oras.DefaultCopyGraphOptions); err != nil {
		return biz.PublishedDescriptor{}, stableRegistryError(err)
	}
	return biz.PublishedDescriptor{Digest: manifest.Digest.String(), MediaType: manifest.MediaType}, nil
}

func validateProvenancePublication(publication biz.ProvenancePublication, maximum int64) error {
	if publication.ProjectID == "" || publication.RegistryCredentialID == "" ||
		publication.CreatedAt.IsZero() || !validRegistryPublicationIdentity(
		publication.RegistryRepository, publication.SubjectDigest) ||
		publication.Document.MediaType != biz.SLSAProvenanceMediaType ||
		publication.Document.FormatVersion != biz.SLSAProvenanceFormatVersion ||
		publication.Document.PredicateType != biz.SLSAProvenancePredicateV1 {
		return biz.ErrInvalidEvidenceJob
	}
	document, err := NewSLSAProvenanceV1Document(
		publication.Document.Content, minInt64(maximum, biz.MaximumProvenanceDocumentSize),
		publication.RegistryRepository, publication.SubjectDigest,
	)
	if err != nil || document.ContentDigest != publication.Document.ContentDigest {
		return biz.ErrInvalidProvenance
	}
	return nil
}

func validRegistryPublicationIdentity(repository, subjectDigest string) bool {
	named, err := reference.ParseNormalizedNamed(repository)
	if err != nil || named.Name() != repository || !reference.IsNameOnly(named) {
		return false
	}
	parsed, err := digest.Parse(subjectDigest)
	return err == nil && parsed.Algorithm() == digest.SHA256 && parsed.Validate() == nil
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func validateSBOMPublication(publication biz.SBOMPublication, maximum int64) error {
	request := biz.SBOMRequest{
		ProjectID: publication.ProjectID, RegistryCredentialID: publication.RegistryCredentialID,
		RegistryRepository: publication.RegistryRepository,
		SubjectDigest:      publication.SubjectDigest, FormatVersion: publication.Document.FormatVersion,
	}
	if err := request.Validate(); err != nil || publication.ProjectID == "" ||
		publication.RegistryCredentialID == "" || publication.CreatedAt.IsZero() ||
		publication.Document.MediaType != biz.CycloneDXJSONMediaType {
		return biz.ErrInvalidEvidenceJob
	}
	document, err := biz.NewCycloneDX16Document(publication.Document.Content, maximum)
	if err != nil || document.ContentDigest != publication.Document.ContentDigest {
		return biz.ErrInvalidSBOM
	}
	return nil
}

func validateVulnerabilityPublication(publication biz.VulnerabilityPublication, maximum int64) error {
	request := biz.VulnerabilityScanRequest{ProjectID: publication.ProjectID,
		RegistryCredentialID: publication.RegistryCredentialID,
		RegistryRepository:   publication.RegistryRepository, SubjectDigest: publication.SubjectDigest,
		FormatVersion: publication.Report.FormatVersion}
	if request.Validate() != nil || publication.CreatedAt.IsZero() ||
		publication.Report.MediaType != biz.TrivyReportMediaType ||
		publication.Report.ScannerVersion != PinnedTrivyVersion || publication.Report.Database.Validate() != nil {
		return biz.ErrInvalidEvidenceJob
	}
	document, err := newTrivyV2Report(publication.Report.Content,
		minInt64(maximum, biz.MaximumVulnerabilityReportSize), request.CanonicalSubject(),
		publication.Report.ScannerVersion, publication.Report.Database)
	if err != nil || document.ContentDigest != publication.Report.ContentDigest ||
		document.Counts != publication.Report.Counts || document.HighestSeverity != publication.Report.HighestSeverity ||
		!document.ScannedAt.Equal(publication.Report.ScannedAt) {
		return biz.ErrInvalidVulnerabilityReport
	}
	return nil
}

func stableRegistryError(err error) error {
	var response *errcode.ErrorResponse
	if errors.As(err, &response) && (response.StatusCode == http.StatusUnauthorized ||
		response.StatusCode == http.StatusForbidden) {
		return biz.ErrRegistryAuthentication
	}
	return biz.ErrUnavailable
}

func (p *ORASPublisher) String() string {
	return fmt.Sprintf("oras-go/%s", ORASGoVersion)
}
