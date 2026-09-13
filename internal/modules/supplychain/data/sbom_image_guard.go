package data

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

const maximumSBOMImageManifests = 64

type SBOMImageGuard interface {
	ValidateSBOMImage(context.Context, biz.SBOMRequest, int64, biz.RegistryCredential) error
}

type OCIImageGuardOptions struct {
	AllowPlainHTTP     bool
	RegistryCABundle   []byte
	RegistryHTTPSProxy string
}

type OCIImageGuard struct {
	allowPlainHTTP bool
	client         *http.Client
}

type sbomImageManifestChild struct {
	mediaType string
	digest    digest.Digest
	size      int64
}

func NewOCIImageGuard(options OCIImageGuardOptions) (*OCIImageGuard, error) {
	client, err := newRegistryHTTPClient(
		options.AllowPlainHTTP, options.RegistryCABundle, options.RegistryHTTPSProxy,
	)
	if err != nil {
		return nil, biz.ErrGeneratorVersion
	}
	return &OCIImageGuard{
		allowPlainHTTP: options.AllowPlainHTTP, client: client,
	}, nil
}

func (g *OCIImageGuard) ValidateSBOMImage(ctx context.Context, request biz.SBOMRequest,
	maximumLayerBytes int64, credential biz.RegistryCredential) error {
	if g == nil || request.Validate() != nil || maximumLayerBytes < 1024*1024 ||
		maximumLayerBytes > 4*1024*1024*1024 || !validCosignCredential(credential) {
		return biz.ErrInvalidEvidenceJob
	}
	named, _ := reference.ParseNormalizedNamed(request.RegistryRepository)
	registry := reference.Domain(named)
	if g.allowPlainHTTP && !loopbackRegistry(registry) {
		return biz.ErrInvalidEvidenceJob
	}
	repository, err := remote.NewRepository(request.RegistryRepository)
	if err != nil {
		return biz.ErrInvalidEvidenceJob
	}
	repository.PlainHTTP = g.allowPlainHTTP
	authClient := &auth.Client{
		Client: g.client, Cache: auth.NewSingleContextCache(),
		Credential: auth.StaticCredential(registry, auth.Credential{
			Username: credential.Username, Password: string(credential.Password),
		}),
	}
	authClient.SetUserAgent("owndock-evidence-worker")
	repository.Client = authClient
	defer func() { authClient.Credential = nil }()
	return g.inspectManifest(ctx, repository, request.SubjectDigest, maximumLayerBytes,
		0, -1, "", map[digest.Digest]bool{})
}

func (g *OCIImageGuard) inspectManifest(ctx context.Context, repository *remote.Repository,
	referenceDigest string, maximumLayerBytes int64, depth int, expectedSize int64, expectedMediaType string,
	seen map[digest.Digest]bool) error {
	if depth > 1 || len(seen) >= maximumSBOMImageManifests {
		return biz.ErrSBOMGeneration
	}
	requested, err := digest.Parse(referenceDigest)
	if err != nil || requested.Algorithm() != digest.SHA256 || seen[requested] {
		return biz.ErrSBOMGeneration
	}
	seen[requested] = true
	descriptor, stream, err := repository.FetchReference(ctx, requested.String())
	if err != nil {
		return sbomImageRegistryError(err)
	}
	content, err := readSBOMImageManifest(stream)
	if err != nil || descriptor.Digest != requested || digest.FromBytes(content) != requested ||
		(descriptor.Size >= 0 && descriptor.Size != int64(len(content))) ||
		(expectedSize >= 0 && expectedSize != int64(len(content))) ||
		(expectedMediaType != "" && expectedMediaType != descriptor.MediaType) ||
		!supportedArtifactManifestMediaType(descriptor.MediaType) {
		return biz.ErrSBOMGeneration
	}
	children, err := validateSBOMImageManifest(content, descriptor.MediaType, maximumLayerBytes, depth)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := g.inspectManifest(ctx, repository, child.digest.String(), maximumLayerBytes,
			depth+1, child.size, child.mediaType, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateSBOMImageManifest(content []byte, descriptorMediaType string,
	maximumLayerBytes int64, depth int) ([]sbomImageManifestChild, error) {
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Layers        []struct {
			Digest digest.Digest `json:"digest"`
			Size   int64         `json:"size"`
		} `json:"layers"`
		Manifests []struct {
			MediaType string        `json:"mediaType"`
			Digest    digest.Digest `json:"digest"`
			Size      int64         `json:"size"`
		} `json:"manifests"`
	}
	if json.Unmarshal(content, &manifest) != nil || manifest.SchemaVersion != 2 ||
		manifest.MediaType != descriptorMediaType {
		return nil, biz.ErrSBOMGeneration
	}
	switch manifest.MediaType {
	case mediaTypeOCIManifest, mediaTypeDockerManifest:
		if len(manifest.Layers) > 1024 {
			return nil, biz.ErrSBOMGeneration
		}
		for _, layer := range manifest.Layers {
			if !validSBOMImageDigest(layer.Digest) || layer.Size < 0 {
				return nil, biz.ErrSBOMGeneration
			}
			if layer.Size > maximumLayerBytes {
				return nil, biz.ErrSBOMImageTooLarge
			}
		}
		return nil, nil
	case mediaTypeOCIIndex, mediaTypeDockerManifestList:
		if depth != 0 || len(manifest.Manifests) == 0 ||
			len(manifest.Manifests) >= maximumSBOMImageManifests {
			return nil, biz.ErrSBOMGeneration
		}
		children := make([]sbomImageManifestChild, 0, len(manifest.Manifests))
		for _, child := range manifest.Manifests {
			if !supportedArtifactManifestMediaType(child.MediaType) ||
				child.MediaType == mediaTypeOCIIndex || child.MediaType == mediaTypeDockerManifestList ||
				!validSBOMImageDigest(child.Digest) || child.Size <= 0 {
				return nil, biz.ErrSBOMGeneration
			}
			children = append(children, sbomImageManifestChild{
				mediaType: child.MediaType, digest: child.Digest, size: child.Size,
			})
		}
		return children, nil
	default:
		return nil, biz.ErrSBOMGeneration
	}
}

func validSBOMImageDigest(value digest.Digest) bool {
	parsed, err := digest.Parse(value.String())
	return err == nil && parsed.Algorithm() == digest.SHA256
}

func readSBOMImageManifest(stream io.ReadCloser) ([]byte, error) {
	if stream == nil {
		return nil, biz.ErrSBOMGeneration
	}
	defer stream.Close()
	content, err := io.ReadAll(io.LimitReader(stream, maximumArtifactManifestBytes+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximumArtifactManifestBytes {
		return nil, biz.ErrSBOMGeneration
	}
	return content, nil
}

func sbomImageRegistryError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var response *errcode.ErrorResponse
	if errors.As(err, &response) && (response.StatusCode == http.StatusUnauthorized ||
		response.StatusCode == http.StatusForbidden) {
		return biz.ErrRegistryAuthentication
	}
	return biz.ErrSBOMGeneration
}

var _ SBOMImageGuard = (*OCIImageGuard)(nil)
