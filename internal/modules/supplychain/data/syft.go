package data

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
)

const PinnedSyftVersion = "1.50.0"

type SyftOptions struct {
	Executable         string
	ExpectedVersion    string
	MaxOutputBytes     int64
	MaxLayerBytes      int64
	Credentials        biz.RegistryCredentialProvider
	RegistryCACertFile string
	RegistryHTTPSProxy string
}

type SyftGenerator struct {
	executable         string
	expectedVersion    string
	maxOutputBytes     int64
	maxLayerBytes      int64
	credentials        biz.RegistryCredentialProvider
	registryCACertFile string
	registryHTTPSProxy string
}

func NewSyftGenerator(options SyftOptions) (*SyftGenerator, error) {
	executable := strings.TrimSpace(options.Executable)
	version := strings.TrimPrefix(strings.TrimSpace(options.ExpectedVersion), "v")
	if executable == "" || !filepath.IsAbs(executable) || version == "" ||
		version != PinnedSyftVersion || options.MaxOutputBytes < 1024 ||
		options.MaxOutputBytes > 64*1024*1024 || options.MaxLayerBytes < 1024*1024 ||
		options.MaxLayerBytes > 4*1024*1024*1024 || options.Credentials == nil ||
		!validRegistryCACertFile(options.RegistryCACertFile) ||
		!validRegistryHTTPSProxy(options.RegistryHTTPSProxy) {
		return nil, biz.ErrGeneratorVersion
	}
	return &SyftGenerator{
		executable: executable, expectedVersion: version, maxOutputBytes: options.MaxOutputBytes,
		maxLayerBytes: options.MaxLayerBytes, credentials: options.Credentials,
		registryCACertFile: options.RegistryCACertFile, registryHTTPSProxy: options.RegistryHTTPSProxy,
	}, nil
}

func (g *SyftGenerator) Verify(ctx context.Context) error {
	command := exec.CommandContext(ctx, g.executable, "version", "-o", "json")
	command.Env = registryCAEnvironment(syftEnvironment(), g.registryCACertFile)
	output := &boundedBuffer{maximum: 64 * 1024}
	command.Stdout, command.Stderr = output, &boundedBuffer{maximum: 4096}
	if err := command.Run(); err != nil {
		return biz.ErrGeneratorVersion
	}
	var result struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil ||
		strings.TrimPrefix(strings.TrimSpace(result.Version), "v") != g.expectedVersion {
		return biz.ErrGeneratorVersion
	}
	return nil
}

func (g *SyftGenerator) GenerateSBOM(ctx context.Context, request biz.SBOMRequest) (biz.SBOMDocument, error) {
	if err := request.Validate(); err != nil {
		return biz.SBOMDocument{}, err
	}
	named, _ := reference.ParseNormalizedNamed(request.RegistryRepository)
	registry := reference.Domain(named)
	credential, err := g.credentials.ResolveRegistryCredential(
		ctx, request.ProjectID, request.RegistryCredentialID, registry,
	)
	if err != nil || !validCosignCredential(credential) {
		clear(credential.Password)
		return biz.SBOMDocument{}, biz.ErrRegistryAuthentication
	}
	defer clear(credential.Password)
	output := &boundedBuffer{maximum: g.maxOutputBytes}
	command := exec.CommandContext(ctx, g.executable,
		"scan", "registry:"+request.CanonicalSubject(), "-o", "cyclonedx-json@1.6")
	command.Env = append(registryProxyEnvironment(
		registryCAEnvironment(syftEnvironment(), g.registryCACertFile), g.registryHTTPSProxy),
		"SYFT_SOURCE_IMAGE_MAX_LAYER_SIZE="+strconv.FormatInt(g.maxLayerBytes, 10))
	if credential.AuthenticationMode == registryauth.ModeBasic {
		command.Env = append(command.Env,
			"SYFT_REGISTRY_AUTH_AUTHORITY="+registry,
			"SYFT_REGISTRY_AUTH_USERNAME="+credential.Username,
			"SYFT_REGISTRY_AUTH_PASSWORD="+string(credential.Password))
	}
	command.Stdout, command.Stderr = output, &boundedBuffer{maximum: 4096}
	if err := command.Run(); err != nil {
		command.Env = nil
		if errors.Is(output.Error(), errOutputLimit) {
			return biz.SBOMDocument{}, biz.ErrSBOMTooLarge
		}
		return biz.SBOMDocument{}, biz.ErrSBOMGeneration
	}
	command.Env = nil
	return biz.NewCycloneDX16Document(output.Bytes(), g.maxOutputBytes)
}

func syftEnvironment() []string {
	return []string{
		"HOME=/tmp", "SYFT_CHECK_FOR_APP_UPDATE=false", "SYFT_LOG_QUIET=true",
		"SYFT_FORMAT_PRETTY=false", "SYFT_CACHE_DIR=/tmp/syft-cache", "SYFT_CACHE_TTL=0",
	}
}

var errOutputLimit = errors.New("command output exceeded its limit")

type boundedBuffer struct {
	buffer  bytes.Buffer
	maximum int64
	err     error
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	remaining := b.maximum - int64(b.buffer.Len())
	if int64(len(value)) > remaining {
		if remaining > 0 {
			_, _ = b.buffer.Write(value[:remaining])
		}
		b.err = errOutputLimit
		return int(remaining), b.err
	}
	return b.buffer.Write(value)
}

func (b *boundedBuffer) Bytes() []byte { return b.buffer.Bytes() }
func (b *boundedBuffer) Error() error  { return b.err }

var _ io.Writer = (*boundedBuffer)(nil)

func (g *SyftGenerator) String() string {
	return fmt.Sprintf("syft/%s", g.expectedVersion)
}
