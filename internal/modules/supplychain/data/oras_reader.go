package data

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

const maximumEvidenceManifestBytes = int64(1024 * 1024)

type OCIContentReaderOptions struct {
	Credentials        biz.RegistryCredentialProvider
	AllowPlainHTTP     bool
	MaxDocumentBytes   int64
	RegistryCABundle   []byte
	RegistryHTTPSProxy string
}

// OCIContentReader returns only the single evidence layer referenced by the
// immutable manifest in Evidence.DescriptorDigest. It verifies the manifest,
// subject, media type, layer digest and document schema before bytes reach the
// HTTP response.
type OCIContentReader struct {
	credentials      biz.RegistryCredentialProvider
	allowPlainHTTP   bool
	maxDocumentBytes int64
	client           *http.Client
}

func NewOCIContentReader(options OCIContentReaderOptions) (*OCIContentReader, error) {
	if options.MaxDocumentBytes < 1024 || options.MaxDocumentBytes > 64*1024*1024 {
		return nil, biz.ErrInvalidEvidence
	}
	reader := &OCIContentReader{
		credentials: options.Credentials, allowPlainHTTP: options.AllowPlainHTTP,
		maxDocumentBytes: options.MaxDocumentBytes,
	}
	client, err := newRegistryHTTPClient(
		reader.allowPlainHTTP, options.RegistryCABundle, options.RegistryHTTPSProxy,
	)
	if err != nil {
		return nil, biz.ErrInvalidEvidence
	}
	reader.client = client
	return reader, nil
}

func (r *OCIContentReader) ReadEvidence(ctx context.Context,
	subject biz.ArtifactSubject, evidence biz.Evidence) (biz.EvidenceContent, error) {
	if r == nil || subject.ID != evidence.ArtifactID || subject.ProjectID != evidence.ProjectID ||
		subject.SubjectDigest != evidence.SubjectDigest ||
		subject.RegistryRepository != evidence.RegistryRepository ||
		!validRegistryPublicationIdentity(evidence.RegistryRepository, evidence.SubjectDigest) {
		return biz.EvidenceContent{}, biz.ErrInvalidEvidence
	}
	named, _ := reference.ParseNormalizedNamed(evidence.RegistryRepository)
	registry := reference.Domain(named)
	if r.allowPlainHTTP && !loopbackRegistry(registry) {
		return biz.EvidenceContent{}, biz.ErrInvalidEvidence
	}
	repository, err := remote.NewRepository(evidence.RegistryRepository)
	if err != nil {
		return biz.EvidenceContent{}, biz.ErrInvalidEvidence
	}
	repository.PlainHTTP = r.allowPlainHTTP
	credential := biz.RegistryCredential{AuthenticationMode: registryauth.ModeAnonymous}
	if r.credentials != nil {
		credential, err = r.credentials.ResolveRegistryCredential(ctx, subject.ProjectID,
			subject.RegistryCredentialID, registry)
		if err != nil || !validCosignCredential(credential) {
			clear(credential.Password)
			return biz.EvidenceContent{}, biz.ErrRegistryAuthentication
		}
		defer clear(credential.Password)
	}
	authClient := &auth.Client{
		Client: r.client, Cache: auth.NewSingleContextCache(),
		Credential: auth.StaticCredential(registry, auth.Credential{
			Username: credential.Username, Password: string(credential.Password),
		}),
	}
	authClient.SetUserAgent("owndock-server")
	repository.Client = authClient
	defer func() { authClient.Credential = nil }()

	manifestDescriptor, manifestStream, err := repository.FetchReference(ctx, evidence.DescriptorDigest)
	if err != nil {
		return biz.EvidenceContent{}, stableRegistryError(err)
	}
	manifestBytes, err := readBounded(manifestStream, maximumEvidenceManifestBytes)
	if err != nil {
		return biz.EvidenceContent{}, err
	}
	if manifestDescriptor.Digest.String() != evidence.DescriptorDigest ||
		digest.FromBytes(manifestBytes) != manifestDescriptor.Digest {
		return biz.EvidenceContent{}, biz.ErrEvidenceIntegrity
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil ||
		manifest.SchemaVersion != 2 || manifest.MediaType != ocispec.MediaTypeImageManifest ||
		manifest.ArtifactType != evidence.MediaType || manifest.Subject == nil ||
		manifest.Subject.Digest.String() != evidence.SubjectDigest || len(manifest.Layers) != 1 {
		return biz.EvidenceContent{}, biz.ErrEvidenceIntegrity
	}
	layer := manifest.Layers[0]
	if layer.MediaType != evidence.MediaType || layer.Size < 0 || layer.Size > r.maxDocumentBytes {
		return biz.EvidenceContent{}, biz.ErrEvidenceContentTooLarge
	}
	layerStream, err := repository.Fetch(ctx, layer)
	if err != nil {
		return biz.EvidenceContent{}, stableRegistryError(err)
	}
	content, err := readBounded(layerStream, r.maxDocumentBytes)
	if err != nil {
		return biz.EvidenceContent{}, err
	}
	if int64(len(content)) != layer.Size || digest.FromBytes(content) != layer.Digest {
		return biz.EvidenceContent{}, biz.ErrEvidenceIntegrity
	}
	if err := validateDownloadedEvidence(content, evidence, r.maxDocumentBytes); err != nil {
		return biz.EvidenceContent{}, err
	}
	return biz.EvidenceContent{
		Content: content, MediaType: evidence.MediaType, Digest: layer.Digest.String(),
	}, nil
}

func readBounded(stream io.ReadCloser, maximum int64) ([]byte, error) {
	defer stream.Close()
	content, err := io.ReadAll(io.LimitReader(stream, maximum+1))
	if err != nil {
		return nil, biz.ErrUnavailable
	}
	if int64(len(content)) > maximum {
		return nil, biz.ErrEvidenceContentTooLarge
	}
	return content, nil
}

func validateDownloadedEvidence(content []byte, evidence biz.Evidence, maximum int64) error {
	switch evidence.Kind {
	case biz.EvidenceKindSBOM:
		document, err := biz.NewCycloneDX16Document(content, maximum)
		if err != nil || document.MediaType != evidence.MediaType ||
			document.FormatVersion != evidence.FormatVersion {
			return biz.ErrEvidenceIntegrity
		}
	case biz.EvidenceKindProvenance:
		document, err := NewSLSAProvenanceV1Document(
			content, minInt64(maximum, biz.MaximumProvenanceDocumentSize),
			evidence.RegistryRepository, evidence.SubjectDigest,
		)
		if err != nil || document.MediaType != evidence.MediaType ||
			document.FormatVersion != evidence.FormatVersion ||
			document.PredicateType != evidence.PredicateType {
			return biz.ErrEvidenceIntegrity
		}
	case biz.EvidenceKindVulnerabilityReport:
		if evidence.MediaType != biz.TrivyReportMediaType ||
			evidence.FormatVersion != biz.TrivyReportFormatVersion ||
			validateTrivyV2Report(content, minInt64(maximum, biz.MaximumVulnerabilityReportSize),
				evidence.RegistryRepository+"@"+evidence.SubjectDigest) != nil {
			return biz.ErrEvidenceIntegrity
		}
	default:
		return biz.ErrUnavailable
	}
	return nil
}
