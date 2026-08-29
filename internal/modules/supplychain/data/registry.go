package data

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

const (
	ociImageIndexMediaType       = "application/vnd.oci.image.index.v1+json"
	defaultRegistryResponseBytes = int64(1024 * 1024)
)

type ReferrerCapability struct {
	Supported bool
	Count     int
	Mode      ReferrerDiscoveryMode
}

type ReferrerDiscoveryMode string

const (
	ReferrerDiscoveryNative    ReferrerDiscoveryMode = "referrers_api"
	ReferrerDiscoveryTagSchema ReferrerDiscoveryMode = "tag_schema"
)

type OCIReferrerClientOptions struct {
	Transport        http.RoundTripper
	AllowPlainHTTP   bool
	MaxResponseBytes int64
}

type OCIReferrerClient struct {
	client           *http.Client
	allowPlainHTTP   bool
	maxResponseBytes int64
}

func NewOCIReferrerClient(options OCIReferrerClientOptions) (*OCIReferrerClient, error) {
	maximum := options.MaxResponseBytes
	if maximum == 0 {
		maximum = defaultRegistryResponseBytes
	}
	if maximum < 1024 || maximum > 8*1024*1024 {
		return nil, biz.ErrInvalidEvidence
	}
	transport := options.Transport
	if transport == nil {
		clone := http.DefaultTransport.(*http.Transport).Clone()
		clone.Proxy = nil
		clone.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		transport = clone
	}
	return &OCIReferrerClient{
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("registry redirects are disabled")
			},
		},
		allowPlainHTTP: options.AllowPlainHTTP, maxResponseBytes: maximum,
	}, nil
}

func (c *OCIReferrerClient) Probe(
	ctx context.Context,
	repository string,
	subjectDigest string,
) (ReferrerCapability, error) {
	endpoint, err := c.referrersURL(repository, subjectDigest)
	if err != nil {
		return ReferrerCapability{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ReferrerCapability{}, biz.ErrInvalidEvidence
	}
	request.Header.Set("Accept", ociImageIndexMediaType)
	response, err := c.client.Do(request)
	if err != nil {
		return ReferrerCapability{}, biz.ErrUnavailable
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		return c.decodeReferrers(response, ReferrerDiscoveryNative)
	case http.StatusUnauthorized, http.StatusForbidden:
		return ReferrerCapability{}, biz.ErrRegistryAuthentication
	case http.StatusNotFound:
		return c.probeReferrersTag(ctx, repository, subjectDigest)
	case http.StatusMethodNotAllowed:
		return ReferrerCapability{}, biz.ErrReferrersUnsupported
	default:
		return ReferrerCapability{}, biz.ErrUnavailable
	}
}

func (c *OCIReferrerClient) probeReferrersTag(
	ctx context.Context,
	repository string,
	subjectDigest string,
) (ReferrerCapability, error) {
	parsedDigest, err := digest.Parse(strings.TrimSpace(subjectDigest))
	if err != nil || parsedDigest.Algorithm() != digest.SHA256 || parsedDigest.Validate() != nil {
		return ReferrerCapability{}, biz.ErrInvalidEvidence
	}
	endpoint, err := c.registryURL(repository, "/manifests/"+parsedDigest.Algorithm().String()+"-"+parsedDigest.Encoded())
	if err != nil {
		return ReferrerCapability{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ReferrerCapability{}, biz.ErrInvalidEvidence
	}
	request.Header.Set("Accept", ociImageIndexMediaType)
	response, err := c.client.Do(request)
	if err != nil {
		return ReferrerCapability{}, biz.ErrUnavailable
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		return c.decodeReferrers(response, ReferrerDiscoveryTagSchema)
	case http.StatusUnauthorized, http.StatusForbidden:
		return ReferrerCapability{}, biz.ErrRegistryAuthentication
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return ReferrerCapability{}, biz.ErrReferrersUnsupported
	default:
		return ReferrerCapability{}, biz.ErrUnavailable
	}
}

func (c *OCIReferrerClient) referrersURL(repository, subjectDigest string) (string, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(repository))
	if err != nil || named.Name() != strings.TrimSpace(repository) || !reference.IsNameOnly(named) {
		return "", biz.ErrInvalidEvidence
	}
	parsedDigest, err := digest.Parse(strings.TrimSpace(subjectDigest))
	if err != nil || parsedDigest.Algorithm() != digest.SHA256 || parsedDigest.Validate() != nil {
		return "", biz.ErrInvalidEvidence
	}
	return c.registryURL(named.Name(), "/referrers/"+parsedDigest.String())
}

func (c *OCIReferrerClient) registryURL(repository, suffix string) (string, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(repository))
	if err != nil || named.Name() != strings.TrimSpace(repository) || !reference.IsNameOnly(named) {
		return "", biz.ErrInvalidEvidence
	}
	domain := reference.Domain(named)
	scheme := "https"
	if c.allowPlainHTTP {
		if !loopbackRegistry(domain) {
			return "", biz.ErrInvalidEvidence
		}
		scheme = "http"
	}
	endpoint := url.URL{
		Scheme: scheme,
		Host:   domain,
		Path:   "/v2/" + reference.Path(named) + suffix,
	}
	return endpoint.String(), nil
}

func loopbackRegistry(domain string) bool {
	host := domain
	if parsedHost, _, err := net.SplitHostPort(domain); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

type referrerIndex struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	Manifests     []referrerDescriptor `json:"manifests"`
}

type referrerDescriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

func (c *OCIReferrerClient) decodeReferrers(response *http.Response, mode ReferrerDiscoveryMode) (ReferrerCapability, error) {
	mediaType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	if mediaType != ociImageIndexMediaType && mediaType != "application/json" {
		return ReferrerCapability{}, biz.ErrInvalidRegistryResponse
	}
	limited := io.LimitReader(response.Body, c.maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil || int64(len(body)) > c.maxResponseBytes {
		return ReferrerCapability{}, biz.ErrInvalidRegistryResponse
	}
	var index referrerIndex
	if err := json.Unmarshal(body, &index); err != nil || index.SchemaVersion != 2 ||
		index.MediaType != "" && index.MediaType != ociImageIndexMediaType || len(index.Manifests) > 10000 {
		return ReferrerCapability{}, biz.ErrInvalidRegistryResponse
	}
	for _, descriptor := range index.Manifests {
		parsed, parseErr := digest.Parse(descriptor.Digest)
		if parseErr != nil || parsed.Algorithm() != digest.SHA256 || parsed.Validate() != nil ||
			descriptor.Size < 0 || descriptor.Size > 256*1024*1024 ||
			strings.TrimSpace(descriptor.MediaType) == "" || len(descriptor.MediaType) > 255 ||
			len(descriptor.ArtifactType) > 255 || len(descriptor.Annotations) > 64 {
			return ReferrerCapability{}, biz.ErrInvalidRegistryResponse
		}
		for key, value := range descriptor.Annotations {
			if len(key) == 0 || len(key) > 128 || len(value) > 1024 {
				return ReferrerCapability{}, biz.ErrInvalidRegistryResponse
			}
		}
	}
	return ReferrerCapability{Supported: true, Count: len(index.Manifests), Mode: mode}, nil
}
