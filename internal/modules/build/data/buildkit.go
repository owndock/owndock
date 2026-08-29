package data

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	containertypes "github.com/docker/cli/cli/config/types"
	buildkitclient "github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/tonistiigi/fsutil"
)

const (
	PinnedBuildKitVersion    = "v0.31.2"
	PinnedBuildKitImage      = "moby/buildkit:v0.31.2-rootless@sha256:0eeb84626c0cd01aecae7848c5ed8f095aec279dd936d0cdb5a64110f42ca65b"
	PinnedDockerfileFrontend = "docker/dockerfile:1.25.0@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12"
	maximumDockerfileBytes   = int64(1024 * 1024)
)

var (
	ErrInvalidBuildKitConfiguration = errors.New("BuildKit configuration is invalid")
	ErrBuildKitVersionMismatch      = errors.New("BuildKit version does not match the pinned version")
)

type BuildKitOptions struct {
	Endpoint        string
	ServerName      string
	CACertFile      string
	ClientCertFile  string
	ClientKeyFile   string
	ExpectedVersion string
	EgressProxyURL  string
}

type buildKitClient interface {
	Info(context.Context) (*buildkitclient.Info, error)
	Solve(context.Context, *llb.Definition, buildkitclient.SolveOpt, chan *buildkitclient.SolveStatus) (*buildkitclient.SolveResponse, error)
	Close() error
}

type buildKitClientFactory func(context.Context) (buildKitClient, error)

type BuildKitGateway struct {
	resolver       biz.RegistrySecretResolver
	newClient      buildKitClientFactory
	egressProxyURL string
}

func NewBuildKitGateway(ctx context.Context, resolver biz.RegistrySecretResolver, options BuildKitOptions) (*BuildKitGateway, error) {
	factory, expectedVersion, err := buildKitFactory(options)
	if err != nil || resolver == nil {
		return nil, ErrInvalidBuildKitConfiguration
	}
	proxyURL := strings.TrimSpace(options.EgressProxyURL)
	if !validBuildEgressProxyURL(proxyURL) {
		return nil, ErrInvalidBuildKitConfiguration
	}
	return newBuildKitGateway(ctx, resolver, expectedVersion, proxyURL, factory)
}

func newBuildKitGateway(ctx context.Context, resolver biz.RegistrySecretResolver, expectedVersion string,
	egressProxyURL string, factory buildKitClientFactory) (*BuildKitGateway, error) {
	if resolver == nil || factory == nil || strings.TrimSpace(expectedVersion) == "" ||
		!validBuildEgressProxyURL(egressProxyURL) {
		return nil, ErrInvalidBuildKitConfiguration
	}
	client, err := factory(ctx)
	if err != nil {
		return nil, biz.ErrBuildKitUnavailable
	}
	defer func() { _ = client.Close() }()
	info, err := client.Info(ctx)
	if err != nil {
		return nil, biz.ErrBuildKitUnavailable
	}
	if info == nil || strings.TrimSpace(info.BuildkitVersion.Version) != expectedVersion {
		return nil, ErrBuildKitVersionMismatch
	}
	return &BuildKitGateway{
		resolver: resolver, newClient: factory, egressProxyURL: egressProxyURL,
	}, nil
}

func buildKitFactory(options BuildKitOptions) (buildKitClientFactory, string, error) {
	endpoint := strings.TrimSpace(options.Endpoint)
	expected := strings.TrimSpace(options.ExpectedVersion)
	if expected == "" {
		expected = PinnedBuildKitVersion
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "", ErrInvalidBuildKitConfiguration
	}
	clientOptions := make([]buildkitclient.ClientOpt, 0, 2)
	switch parsed.Scheme {
	case "unix":
		if parsed.Host != "" || !filepath.IsAbs(parsed.Path) || parsed.Path == "/var/run/docker.sock" ||
			strings.Contains(strings.ToLower(parsed.Path), "docker.sock") {
			return nil, "", ErrInvalidBuildKitConfiguration
		}
		if options.ServerName != "" || options.CACertFile != "" ||
			options.ClientCertFile != "" || options.ClientKeyFile != "" {
			return nil, "", ErrInvalidBuildKitConfiguration
		}
	case "tcp":
		if parsed.Path != "" || parsed.Hostname() == "" {
			return nil, "", ErrInvalidBuildKitConfiguration
		}
		if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
			return nil, "", ErrInvalidBuildKitConfiguration
		}
		if strings.TrimSpace(options.ServerName) == "" ||
			!secureBuildKitFile(options.CACertFile, false) ||
			!secureBuildKitFile(options.ClientCertFile, false) ||
			!secureBuildKitFile(options.ClientKeyFile, true) {
			return nil, "", ErrInvalidBuildKitConfiguration
		}
		clientOptions = append(clientOptions,
			buildkitclient.WithServerConfig(options.ServerName, options.CACertFile),
			buildkitclient.WithCredentials(options.ClientCertFile, options.ClientKeyFile),
		)
	default:
		return nil, "", ErrInvalidBuildKitConfiguration
	}
	return func(ctx context.Context) (buildKitClient, error) {
		return buildkitclient.New(ctx, endpoint, clientOptions...)
	}, expected, nil
}

func secureBuildKitFile(value string, private bool) bool {
	value = strings.TrimSpace(value)
	if !filepath.IsAbs(value) {
		return false
	}
	info, err := os.Lstat(value)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return !private || info.Mode().Perm()&0o077 == 0
}

func (g *BuildKitGateway) Build(ctx context.Context, request biz.BuildExecutionRequest) (biz.BuildExecutionOutput, error) {
	if err := request.Validate(); err != nil {
		return biz.BuildExecutionOutput{}, err
	}
	contextDirectory, dockerfileName, err := buildInputPaths(request)
	if err != nil {
		return biz.BuildExecutionOutput{}, biz.ErrInvalidBuildExecution
	}
	if err := validateDockerfileFrontend(filepath.Join(contextDirectory, dockerfileName)); err != nil {
		return biz.BuildExecutionOutput{}, err
	}
	local, err := fsutil.NewFS(contextDirectory)
	if err != nil {
		return biz.BuildExecutionOutput{}, biz.ErrInvalidBuildExecution
	}
	password, err := g.resolver.ResolveRegistryPassword(ctx, request.Credential)
	if err != nil {
		if ctx.Err() != nil {
			return biz.BuildExecutionOutput{}, ctx.Err()
		}
		return biz.BuildExecutionOutput{}, biz.ErrRegistryAuthentication
	}
	defer clearBytes(password)
	client, err := g.newClient(ctx)
	if err != nil {
		return biz.BuildExecutionOutput{}, biz.ErrBuildKitUnavailable
	}
	defer func() { _ = client.Close() }()
	operationContext, cancel := context.WithTimeout(ctx, time.Duration(request.Configuration.TimeoutSeconds)*time.Second)
	defer cancel()
	imageName := buildImageName(request.Configuration.ImageRepository, request.BuildID)
	auth := authprovider.NewDockerAuthProvider(authprovider.DockerAuthProviderConfig{
		AuthConfigProvider: registryAuthProvider(request.Credential, password),
	})
	statusChannel := make(chan *buildkitclient.SolveStatus, 16)
	statusDone := make(chan struct{})
	logger := newBuildKitStatusLogger(request.LogSink, request.Credential.Username, password)
	go func() {
		logger.Consume(operationContext, statusChannel)
		close(statusDone)
	}()
	response, err := client.Solve(operationContext, nil, buildkitclient.SolveOpt{
		Frontend: "gateway.v0",
		FrontendAttrs: map[string]string{
			"source":                PinnedDockerfileFrontend,
			"filename":              dockerfileName,
			"platform":              string(request.Configuration.TargetPlatform),
			"build-arg:HTTP_PROXY":  g.egressProxyURL,
			"build-arg:HTTPS_PROXY": g.egressProxyURL,
			"build-arg:http_proxy":  g.egressProxyURL,
			"build-arg:https_proxy": g.egressProxyURL,
			"build-arg:NO_PROXY":    "",
			"build-arg:no_proxy":    "",
		},
		LocalMounts: map[string]fsutil.FS{"context": local, "dockerfile": local},
		Exports: []buildkitclient.ExportEntry{{
			Type: "image",
			Attrs: map[string]string{
				"name": imageName, "push": "true", "name-canonical": "true", "oci-mediatypes": "true",
			},
		}},
		Session: []session.Attachable{auth},
		Ref:     fmt.Sprintf("%s/%d", request.BuildID, request.Generation),
	}, statusChannel)
	<-statusDone
	if err != nil {
		if logger.NetworkDenied() {
			return biz.BuildExecutionOutput{}, biz.ErrBuildNetworkDenied
		}
		return biz.BuildExecutionOutput{}, classifyBuildKitError(ctx, operationContext, err)
	}
	if response == nil {
		return biz.BuildExecutionOutput{}, biz.ErrInvalidBuildOutput
	}
	value := strings.TrimSpace(response.ExporterResponse[exptypes.ExporterImageDigestKey])
	descriptor, err := digest.Parse(value)
	if err != nil || descriptor.Algorithm() != digest.SHA256 {
		return biz.BuildExecutionOutput{}, biz.ErrInvalidBuildOutput
	}
	return biz.BuildExecutionOutput{ImageDigest: request.Configuration.ImageRepository + "@" + descriptor.String()}, nil
}

func validBuildEgressProxyURL(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.String() != value {
		return false
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber >= 1 && portNumber <= 65535
}

func buildInputPaths(request biz.BuildExecutionRequest) (string, string, error) {
	workspace, err := filepath.Abs(request.Workspace)
	if err != nil || !filepath.IsAbs(request.Workspace) {
		return "", "", biz.ErrInvalidBuildExecution
	}
	contextDirectory := filepath.Join(workspace, filepath.FromSlash(request.Configuration.ContextPath))
	dockerfilePath := filepath.Join(workspace, filepath.FromSlash(request.Configuration.DockerfilePath))
	if !pathWithinRoot(workspace, contextDirectory) || !pathWithinRoot(contextDirectory, dockerfilePath) ||
		!symlinkFreePath(workspace, contextDirectory, true) || !symlinkFreePath(workspace, dockerfilePath, false) {
		return "", "", biz.ErrInvalidBuildExecution
	}
	relative, err := filepath.Rel(contextDirectory, dockerfilePath)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", "", biz.ErrInvalidBuildExecution
	}
	return contextDirectory, filepath.ToSlash(relative), nil
}

func pathWithinRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func symlinkFreePath(root, target string, directory bool) bool {
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	info, err := os.Stat(target)
	return err == nil && ((directory && info.IsDir()) || (!directory && info.Mode().IsRegular()))
}

func validateDockerfileFrontend(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return biz.ErrInvalidBuildExecution
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, maximumDockerfileBytes+1))
	var consumed int64
	for {
		line, readErr := reader.ReadString('\n')
		consumed += int64(len(line))
		if consumed > maximumDockerfileBytes {
			return biz.ErrInvalidBuildExecution
		}
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "# syntax=") {
			value := strings.TrimSpace(trimmed[len("# syntax="):])
			if value != PinnedDockerfileFrontend {
				return biz.ErrInvalidBuildExecution
			}
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return biz.ErrInvalidBuildExecution
		}
	}
	return nil
}

func registryAuthProvider(credential biz.BuildRegistryCredential, password []byte) authprovider.AuthConfigProvider {
	server, username := credential.Server, credential.Username
	return func(ctx context.Context, host string, _ []string, _ authprovider.ExpireCachedAuthCheck) (containertypes.AuthConfig, error) {
		if err := ctx.Err(); err != nil {
			return containertypes.AuthConfig{}, err
		}
		if host != server {
			return containertypes.AuthConfig{}, nil
		}
		return containertypes.AuthConfig{ServerAddress: server, Username: username, Password: string(password)}, nil
	}
}

func buildImageName(repository, buildID string) string {
	sum := sha256.Sum256([]byte(buildID))
	return fmt.Sprintf("%s:owndock-%x", repository, sum[:16])
}

func classifyBuildKitError(parentContext, operationContext context.Context, err error) error {
	if parentErr := parentContext.Err(); parentErr != nil {
		return parentErr
	}
	if operationContext.Err() != nil {
		return biz.ErrBuildExecutionFailed
	}
	if errors.Is(err, biz.ErrRegistryAuthentication) || errors.Is(err, biz.ErrRegistryPushFailed) {
		return err
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "no space left on device") ||
		strings.Contains(message, "disk quota exceeded") ||
		strings.Contains(message, "resource exhausted") ||
		strings.Contains(message, "resourceexhausted") ||
		strings.Contains(message, "out of memory") {
		return biz.ErrBuildResourceLimit
	}
	if strings.Contains(message, "451 unavailable for legal reasons") {
		return biz.ErrBuildNetworkDenied
	}
	if strings.Contains(message, "unauthorized") || strings.Contains(message, "authentication required") ||
		strings.Contains(message, "pull access denied") ||
		strings.Contains(message, "requested access to the resource is denied") {
		return biz.ErrRegistryAuthentication
	}
	if strings.Contains(message, "push") || strings.Contains(message, "registry") {
		return biz.ErrRegistryPushFailed
	}
	return biz.ErrBuildExecutionFailed
}

var _ biz.BuildExecutor = (*BuildKitGateway)(nil)
