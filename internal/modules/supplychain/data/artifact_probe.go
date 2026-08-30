package data

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	buildbiz "github.com/owndock/owndock/internal/modules/build/biz"
	supplychainbiz "github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

const maximumArtifactManifestBytes = int64(8 * 1024 * 1024)

const (
	mediaTypeOCIManifest        = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeOCIIndex           = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

type OCIArtifactProberOptions struct {
	Credentials      supplychainbiz.RegistryCredentialProvider
	AllowPlainHTTP   bool
	RegistryCABundle []byte
}

// OCIArtifactProber proves that the exact digest selected by an external
// producer is readable from the configured Registry. It never resolves a tag.
type OCIArtifactProber struct {
	credentials    supplychainbiz.RegistryCredentialProvider
	allowPlainHTTP bool
	client         *http.Client
}

func NewOCIArtifactProber(options OCIArtifactProberOptions) (*OCIArtifactProber, error) {
	prober := &OCIArtifactProber{
		credentials: options.Credentials, allowPlainHTTP: options.AllowPlainHTTP,
	}
	client, err := newRegistryHTTPClient(prober.allowPlainHTTP, options.RegistryCABundle)
	if err != nil {
		return nil, buildbiz.ErrInvalidArtifact
	}
	prober.client = client
	return prober, nil
}

func (p *OCIArtifactProber) ProbeArtifact(ctx context.Context, projectID, credentialID,
	repositoryName, subjectDigest string) error {
	if p == nil || strings.TrimSpace(projectID) == "" || strings.TrimSpace(credentialID) == "" ||
		!validRegistryPublicationIdentity(repositoryName, subjectDigest) {
		return buildbiz.ErrInvalidArtifact
	}
	named, _ := reference.ParseNormalizedNamed(repositoryName)
	registry := reference.Domain(named)
	if p.allowPlainHTTP && !loopbackRegistry(registry) {
		return buildbiz.ErrInvalidArtifact
	}
	repository, err := remote.NewRepository(repositoryName)
	if err != nil {
		return buildbiz.ErrInvalidArtifact
	}
	repository.PlainHTTP = p.allowPlainHTTP
	credential := supplychainbiz.RegistryCredential{AuthenticationMode: registryauth.ModeAnonymous}
	if p.credentials != nil {
		credential, err = p.credentials.ResolveRegistryCredential(ctx, projectID, credentialID, registry)
		if err != nil || !validCosignCredential(credential) {
			clear(credential.Password)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return buildbiz.ErrArtifactRegistryAuthentication
		}
		defer clear(credential.Password)
	}
	authClient := &auth.Client{
		Client: p.client, Cache: auth.NewSingleContextCache(),
		Credential: auth.StaticCredential(registry, auth.Credential{
			Username: credential.Username, Password: string(credential.Password),
		}),
	}
	authClient.SetUserAgent("owndock-server")
	repository.Client = authClient
	defer func() { authClient.Credential = nil }()

	descriptor, stream, err := repository.FetchReference(ctx, subjectDigest)
	if err != nil {
		return artifactRegistryError(err)
	}
	content, err := readArtifactManifest(stream)
	if err != nil {
		return err
	}
	requested, _ := digest.Parse(subjectDigest)
	if descriptor.Digest != requested || digest.FromBytes(content) != requested ||
		(descriptor.Size >= 0 && descriptor.Size != int64(len(content))) ||
		!supportedArtifactManifestMediaType(descriptor.MediaType) {
		return buildbiz.ErrArtifactRegistryIntegrity
	}
	var envelope struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
	}
	if json.Unmarshal(content, &envelope) != nil || envelope.SchemaVersion != 2 ||
		envelope.MediaType != descriptor.MediaType || !supportedArtifactManifestMediaType(envelope.MediaType) {
		return buildbiz.ErrArtifactRegistryIntegrity
	}
	return nil
}

func readArtifactManifest(stream io.ReadCloser) ([]byte, error) {
	defer stream.Close()
	content, err := io.ReadAll(io.LimitReader(stream, maximumArtifactManifestBytes+1))
	if err != nil {
		return nil, buildbiz.ErrArtifactRegistryUnavailable
	}
	if len(content) == 0 || int64(len(content)) > maximumArtifactManifestBytes {
		return nil, buildbiz.ErrArtifactRegistryIntegrity
	}
	return content, nil
}

func supportedArtifactManifestMediaType(value string) bool {
	switch value {
	case mediaTypeOCIManifest, mediaTypeOCIIndex, mediaTypeDockerManifest, mediaTypeDockerManifestList:
		return true
	default:
		return false
	}
}

func artifactRegistryError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var response *errcode.ErrorResponse
	if errors.As(err, &response) && (response.StatusCode == http.StatusUnauthorized ||
		response.StatusCode == http.StatusForbidden) {
		return buildbiz.ErrArtifactRegistryAuthentication
	}
	return buildbiz.ErrArtifactRegistryUnavailable
}

var _ buildbiz.ArtifactAvailabilityProbe = (*OCIArtifactProber)(nil)
