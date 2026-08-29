package data

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	buildkitclient "github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/opencontainers/go-digest"
	"github.com/owndock/owndock/internal/modules/build/biz"
)

type buildKitClientStub struct {
	version  string
	opt      buildkitclient.SolveOpt
	result   *buildkitclient.SolveResponse
	err      error
	statuses []*buildkitclient.SolveStatus
}

func (c *buildKitClientStub) Info(context.Context) (*buildkitclient.Info, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &buildkitclient.Info{BuildkitVersion: buildkitclient.BuildkitVersion{Version: c.version}}, nil
}

func (c *buildKitClientStub) Solve(_ context.Context, _ *llb.Definition, opt buildkitclient.SolveOpt,
	statusChannel chan *buildkitclient.SolveStatus) (*buildkitclient.SolveResponse, error) {
	c.opt = opt
	if statusChannel != nil {
		for _, status := range c.statuses {
			statusChannel <- status
		}
		close(statusChannel)
	}
	return c.result, c.err
}

func (*buildKitClientStub) Close() error { return nil }

type registrySecretResolverStub struct{ secret []byte }

func (s registrySecretResolverStub) ResolveRegistryPassword(context.Context, biz.BuildRegistryCredential) ([]byte, error) {
	return s.secret, nil
}

func TestBuildKitGatewayUsesPinnedFrontendAndReturnsCanonicalDigest(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := []byte("registry-password-do-not-leak")
	client := &buildKitClientStub{
		version: PinnedBuildKitVersion,
		result: &buildkitclient.SolveResponse{ExporterResponse: map[string]string{
			exptypes.ExporterImageDigestKey: "sha256:" + strings.Repeat("a", 64),
		}},
	}
	gateway, err := newBuildKitGateway(t.Context(), registrySecretResolverStub{secret: secret},
		PinnedBuildKitVersion, "http://build-egress-gateway:3128", func(context.Context) (buildKitClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	output, err := gateway.Build(t.Context(), buildExecutionRequestFixture(workspace))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if output.ImageDigest != "registry.example.com/team/api@sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("image digest = %q", output.ImageDigest)
	}
	if client.opt.Frontend != "gateway.v0" ||
		client.opt.FrontendAttrs["source"] != PinnedDockerfileFrontend ||
		client.opt.FrontendAttrs["filename"] != "Dockerfile" ||
		client.opt.FrontendAttrs["platform"] != "linux/amd64" {
		t.Fatalf("frontend options = %+v", client.opt)
	}
	for _, name := range []string{
		"build-arg:HTTP_PROXY", "build-arg:HTTPS_PROXY", "build-arg:http_proxy", "build-arg:https_proxy",
	} {
		if client.opt.FrontendAttrs[name] != "http://build-egress-gateway:3128" {
			t.Fatalf("%s = %q", name, client.opt.FrontendAttrs[name])
		}
	}
	if client.opt.FrontendAttrs["build-arg:NO_PROXY"] != "" || client.opt.FrontendAttrs["build-arg:no_proxy"] != "" {
		t.Fatalf("NO_PROXY bypass was configured: %+v", client.opt.FrontendAttrs)
	}
	if len(client.opt.Exports) != 1 || client.opt.Exports[0].Attrs["push"] != "true" ||
		client.opt.Exports[0].Attrs["name-canonical"] != "true" ||
		len(client.opt.AllowedEntitlements) != 0 {
		t.Fatalf("export/security options = %+v", client.opt)
	}
	if strings.Contains(fmt.Sprintf("%+v", client.opt), "registry-password-do-not-leak") {
		t.Fatal("registry password appeared in Solve options")
	}
	for _, value := range secret {
		if value != 0 {
			t.Fatal("registry password was not cleared")
		}
	}
}

func TestBuildKitGatewayPersistsOnlyRedactedStreamingStatus(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vertex := digest.FromString("step")
	secret := []byte("registry-password-do-not-leak")
	client := &buildKitClientStub{
		version: PinnedBuildKitVersion,
		result: &buildkitclient.SolveResponse{ExporterResponse: map[string]string{
			exptypes.ExporterImageDigestKey: "sha256:" + strings.Repeat("a", 64),
		}},
		statuses: []*buildkitclient.SolveStatus{
			{Logs: []*buildkitclient.VertexLog{{Vertex: vertex, Stream: 1, Data: []byte("token=registry-password-")}}},
			{Logs: []*buildkitclient.VertexLog{{Vertex: vertex, Stream: 1, Data: []byte("do-not-leak\n")}}},
		},
	}
	gateway, err := newBuildKitGateway(t.Context(), registrySecretResolverStub{secret: secret},
		PinnedBuildKitVersion, "http://build-egress-gateway:3128", func(context.Context) (buildKitClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	var messages []string
	request := buildExecutionRequestFixture(workspace)
	request.LogSink = func(_ context.Context, _ biz.BuildLogStage, message string) {
		messages = append(messages, message)
	}
	if _, err := gateway.Build(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || strings.Contains(messages[0], "registry-password-do-not-leak") ||
		!strings.Contains(messages[0], "[REDACTED]") {
		t.Fatalf("messages = %#v", messages)
	}
}

func TestBuildKitGatewayRejectsMutableDockerfileFrontend(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"),
		[]byte("# syntax=docker/dockerfile:1\nFROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &buildKitClientStub{version: PinnedBuildKitVersion}
	gateway, err := newBuildKitGateway(t.Context(), registrySecretResolverStub{secret: []byte("secret")},
		PinnedBuildKitVersion, "http://build-egress-gateway:3128", func(context.Context) (buildKitClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Build(t.Context(), buildExecutionRequestFixture(workspace)); err != biz.ErrInvalidBuildExecution {
		t.Fatalf("mutable frontend error = %v", err)
	}
	if client.opt.Frontend != "" {
		t.Fatal("BuildKit was invoked for a mutable frontend")
	}
}

func TestBuildKitGatewayRejectsOversizedAndSymlinkedBuildInputsBeforeSolve(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "oversized Dockerfile",
			setup: func(t *testing.T, workspace string) {
				t.Helper()
				value := append([]byte("# "), bytes.Repeat([]byte("x"), int(maximumDockerfileBytes))...)
				if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), value, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlinked Dockerfile",
			setup: func(t *testing.T, workspace string) {
				t.Helper()
				outside := filepath.Join(t.TempDir(), "outside.Dockerfile")
				if err := os.WriteFile(outside, []byte("FROM scratch\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(workspace, "Dockerfile")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			workspace := t.TempDir()
			test.setup(t, workspace)
			client := &buildKitClientStub{version: PinnedBuildKitVersion}
			secret := []byte("must-not-be-resolved")
			gateway, err := newBuildKitGateway(t.Context(), registrySecretResolverStub{secret: secret},
				PinnedBuildKitVersion, "http://build-egress-gateway:3128", func(context.Context) (buildKitClient, error) { return client, nil })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := gateway.Build(t.Context(), buildExecutionRequestFixture(workspace)); err != biz.ErrInvalidBuildExecution {
				t.Fatalf("invalid build input error = %v", err)
			}
			if client.opt.Frontend != "" {
				t.Fatal("BuildKit was invoked for an invalid build input")
			}
			if string(secret) != "must-not-be-resolved" {
				t.Fatal("Registry secret resolver was reached before build input validation")
			}
		})
	}
}

func TestBuildKitGatewayRequiresExactDaemonVersion(t *testing.T) {
	client := &buildKitClientStub{version: "v0.31.1"}
	_, err := newBuildKitGateway(t.Context(), registrySecretResolverStub{secret: []byte("secret")},
		PinnedBuildKitVersion, "http://build-egress-gateway:3128", func(context.Context) (buildKitClient, error) { return client, nil })
	if err != ErrBuildKitVersionMismatch {
		t.Fatalf("version mismatch error = %v", err)
	}
}

func TestBuildKitGatewayPreservesCancellationAndClassifiesSafeErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := classifyBuildKitError(ctx, ctx, errors.New("token=must-not-leak")); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
	if err := classifyBuildKitError(t.Context(), t.Context(), errors.New("registry unauthorized: token=must-not-leak")); err != biz.ErrRegistryAuthentication || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("classified error = %v", err)
	}
	for _, message := range []string{
		"executor failed: no space left on device: path=/secret/workspace",
		"snapshot write failed: disk quota exceeded",
		"rpc error: code = ResourceExhausted desc = cache full",
		"executor failed: out of memory",
	} {
		if err := classifyBuildKitError(t.Context(), t.Context(), errors.New(message)); err != biz.ErrBuildResourceLimit {
			t.Fatalf("resource error %q classified as %v", message, err)
		}
	}
	if err := classifyBuildKitError(t.Context(), t.Context(),
		errors.New("wget: server returned error: HTTP/1.1 451 Unavailable For Legal Reasons")); err != biz.ErrBuildNetworkDenied {
		t.Fatalf("egress policy error classified as %v", err)
	}
	if err := classifyBuildKitError(t.Context(), t.Context(),
		errors.New("process failed while contacting denied-egress.example")); err != biz.ErrBuildExecutionFailed {
		t.Fatalf("hostname containing denied classified as %v", err)
	}
}

func TestReaderContainsAcrossChunkBoundary(t *testing.T) {
	secret := []byte("registry-secret-value")
	prefix := bytes.Repeat([]byte("x"), 64*1024+len(secret)-2)
	payload := append(append(prefix, secret...), []byte("tail")...)
	if found, err := readerContains(bytes.NewReader(payload), secret); err != nil || !found {
		t.Fatalf("boundary secret scan = %t/%v", found, err)
	}
	if found, err := readerContains(bytes.NewReader(prefix), secret); err != nil || found {
		t.Fatalf("clean stream scan = %t/%v", found, err)
	}
}

func TestBuildKitFactoryRejectsDockerSocketAndUnauthenticatedTCP(t *testing.T) {
	for _, options := range []BuildKitOptions{
		{Endpoint: "unix:///var/run/docker.sock"},
		{Endpoint: "docker-container://buildkitd"},
		{Endpoint: "tcp://buildkitd:1234"},
	} {
		if _, _, err := buildKitFactory(options); err != ErrInvalidBuildKitConfiguration {
			t.Fatalf("buildKitFactory(%q) error = %v", options.Endpoint, err)
		}
	}
	if _, _, err := buildKitFactory(BuildKitOptions{Endpoint: "unix:///run/owndock/buildkitd.sock"}); err != nil {
		t.Fatalf("dedicated Unix socket rejected: %v", err)
	}
}

func buildExecutionRequestFixture(workspace string) biz.BuildExecutionRequest {
	return biz.BuildExecutionRequest{
		BuildID: "build-1", ProjectID: "project-1", Generation: 1, Workspace: workspace,
		Configuration: biz.BuildConfigurationSnapshot{
			ConfigurationID: "configuration-1", ConfigurationVersion: 1, SourceRepositoryID: "source-1",
			DockerfilePath: "Dockerfile", ContextPath: ".",
			RegistryCredentialID: "registry-1", ImageRepository: "registry.example.com/team/api",
			TargetPlatform: biz.BuildPlatformLinuxAMD64, TimeoutSeconds: 300,
			Resources: biz.BuildResources{CPUMilli: 2000, MemoryBytes: 2 * 1024 * 1024 * 1024, DiskBytes: 10 * 1024 * 1024 * 1024},
		},
		Credential: biz.BuildRegistryCredential{
			ID: "registry-1", ProjectID: "project-1", Server: "registry.example.com",
			Username: "builder", PasswordRef: "secret://production",
		},
	}
}
