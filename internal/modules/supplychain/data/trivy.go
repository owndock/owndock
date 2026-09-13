package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/owndock/owndock/internal/modules/supplychain/biz"
	"github.com/owndock/owndock/internal/shared/registryauth"
)

const PinnedTrivyVersion = biz.PinnedTrivyVersion

type TrivyOptions struct {
	Executable         string
	ExpectedVersion    string
	CacheDirectory     string
	MaxOutputBytes     int64
	Credentials        biz.RegistryCredentialProvider
	AllowPlainHTTP     bool
	RegistryCACertFile string
}

type TrivyScanner struct {
	executable         string
	expectedVersion    string
	cacheDirectory     string
	maxOutputBytes     int64
	credentials        biz.RegistryCredentialProvider
	allowPlainHTTP     bool
	registryCACertFile string
}

func NewTrivyScanner(options TrivyOptions) (*TrivyScanner, error) {
	executable := strings.TrimSpace(options.Executable)
	version := strings.TrimPrefix(strings.TrimSpace(options.ExpectedVersion), "v")
	cacheDirectory := strings.TrimSpace(options.CacheDirectory)
	if !filepath.IsAbs(executable) || version != PinnedTrivyVersion || !filepath.IsAbs(cacheDirectory) ||
		options.MaxOutputBytes < 1024 || options.MaxOutputBytes > biz.MaximumVulnerabilityReportSize ||
		options.Credentials == nil || !validRegistryCACertFile(options.RegistryCACertFile) {
		return nil, biz.ErrVulnerabilityScannerVersion
	}
	return &TrivyScanner{executable: executable, expectedVersion: version,
		cacheDirectory: cacheDirectory, maxOutputBytes: options.MaxOutputBytes,
		credentials: options.Credentials, allowPlainHTTP: options.AllowPlainHTTP,
		registryCACertFile: options.RegistryCACertFile}, nil
}

type trivyVersionOutput struct {
	Version         string `json:"Version"`
	VulnerabilityDB struct {
		Version      uint64 `json:"Version"`
		UpdatedAt    string `json:"UpdatedAt"`
		DownloadedAt string `json:"DownloadedAt"`
		NextUpdate   string `json:"NextUpdate"`
	} `json:"VulnerabilityDB"`
}

func (s *TrivyScanner) databaseMetadata(ctx context.Context) (biz.VulnerabilityDatabase, error) {
	return readTrivyDatabaseMetadata(ctx, s.executable, s.expectedVersion, s.cacheDirectory)
}

func readTrivyDatabaseMetadata(ctx context.Context, executable, expectedVersion,
	cacheDirectory string) (biz.VulnerabilityDatabase, error) {
	command := exec.CommandContext(ctx, executable, "version", "--format", "json", "--cache-dir", cacheDirectory)
	command.Env = trivyEnvironment(cacheDirectory)
	output := &boundedBuffer{maximum: 64 * 1024}
	command.Stdout, command.Stderr = output, &boundedBuffer{maximum: 4096}
	if err := command.Run(); err != nil {
		return biz.VulnerabilityDatabase{}, biz.ErrVulnerabilityScannerVersion
	}
	var result trivyVersionOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil ||
		strings.TrimPrefix(strings.TrimSpace(result.Version), "v") != expectedVersion {
		return biz.VulnerabilityDatabase{}, biz.ErrVulnerabilityScannerVersion
	}
	database := biz.VulnerabilityDatabase{SchemaVersion: result.VulnerabilityDB.Version}
	var err error
	if database.UpdatedAt, err = parseTrivyTime(result.VulnerabilityDB.UpdatedAt); err != nil {
		return biz.VulnerabilityDatabase{}, biz.ErrVulnerabilityDatabase
	}
	if database.DownloadedAt, err = parseTrivyTime(result.VulnerabilityDB.DownloadedAt); err != nil {
		return biz.VulnerabilityDatabase{}, biz.ErrVulnerabilityDatabase
	}
	if database.NextUpdate, err = parseTrivyTime(result.VulnerabilityDB.NextUpdate); err != nil ||
		database.Validate() != nil {
		return biz.VulnerabilityDatabase{}, biz.ErrVulnerabilityDatabase
	}
	return database, nil
}

func parseTrivyTime(value string) (result time.Time, err error) {
	result, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	return result.UTC(), err
}

func (s *TrivyScanner) Verify(ctx context.Context) error {
	_, err := s.databaseMetadata(ctx)
	return err
}

func (s *TrivyScanner) ScanVulnerabilities(ctx context.Context,
	request biz.VulnerabilityScanRequest) (biz.VulnerabilityReport, error) {
	if err := request.Validate(); err != nil {
		return biz.VulnerabilityReport{}, err
	}
	databaseBefore, err := s.databaseMetadata(ctx)
	if err != nil {
		return biz.VulnerabilityReport{}, err
	}
	named, _ := reference.ParseNormalizedNamed(request.RegistryRepository)
	registry := reference.Domain(named)
	if s.allowPlainHTTP && !loopbackRegistry(registry) {
		return biz.VulnerabilityReport{}, biz.ErrInvalidEvidenceJob
	}
	credential, err := s.credentials.ResolveRegistryCredential(
		ctx, request.ProjectID, request.RegistryCredentialID, registry,
	)
	if err != nil || !validCosignCredential(credential) {
		clear(credential.Password)
		return biz.VulnerabilityReport{}, biz.ErrRegistryAuthentication
	}
	defer clear(credential.Password)
	output := &boundedBuffer{maximum: s.maxOutputBytes}
	arguments := []string{"image",
		"--format", "json", "--scanners", "vuln", "--skip-db-update", "--offline-scan",
		"--no-progress", "--cache-backend", "memory", "--cache-dir", s.cacheDirectory,
	}
	if s.allowPlainHTTP {
		arguments = append(arguments, "--insecure")
	}
	arguments = append(arguments, request.CanonicalSubject())
	command := exec.CommandContext(ctx, s.executable, arguments...)
	command.Env = registryCAEnvironment(trivyEnvironment(s.cacheDirectory), s.registryCACertFile)
	if credential.AuthenticationMode == registryauth.ModeBasic {
		command.Env = append(command.Env,
			"TRIVY_USERNAME="+credential.Username,
			"TRIVY_PASSWORD="+string(credential.Password))
	}
	command.Stdout, command.Stderr = output, &boundedBuffer{maximum: 4096}
	if err := command.Run(); err != nil {
		command.Env = nil
		if errors.Is(output.Error(), errOutputLimit) {
			return biz.VulnerabilityReport{}, biz.ErrVulnerabilityReportSize
		}
		return biz.VulnerabilityReport{}, biz.ErrVulnerabilityScan
	}
	command.Env = nil
	databaseAfter, err := s.databaseMetadata(ctx)
	if err != nil || !databaseBefore.Equal(databaseAfter) {
		return biz.VulnerabilityReport{}, biz.ErrVulnerabilityDatabase
	}
	return newTrivyV2Report(output.Bytes(), s.maxOutputBytes, request.CanonicalSubject(),
		s.expectedVersion, databaseBefore)
}

func trivyEnvironment(cacheDirectory string) []string {
	return []string{
		"HOME=/tmp", "TRIVY_CACHE_DIR=" + cacheDirectory, "TRIVY_NO_PROGRESS=true",
		"TRIVY_SKIP_DB_UPDATE=true", "TRIVY_OFFLINE_SCAN=true", "TRIVY_CHECK_FOR_APP_UPDATE=false",
	}
}

func (s *TrivyScanner) String() string { return fmt.Sprintf("trivy/%s", s.expectedVersion) }

var _ biz.VulnerabilityScanner = (*TrivyScanner)(nil)
