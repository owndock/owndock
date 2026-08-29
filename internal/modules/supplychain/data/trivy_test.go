package data

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func writeFakeTrivy(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trivy")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

const trivyVersionJSON = `{"Version":"0.74.0","VulnerabilityDB":{"Version":2,"NextUpdate":"2026-08-23T07:04:53.306059725Z","UpdatedAt":"2026-08-22T07:04:53.306059926Z","DownloadedAt":"2026-08-22T09:39:00.270021094Z"}}`

func trivyRequest() biz.VulnerabilityScanRequest {
	return biz.VulnerabilityScanRequest{ProjectID: "project-1", RegistryCredentialID: "registry-1",
		RegistryRepository: "registry.example.com/team/api",
		SubjectDigest:      "sha256:" + strings.Repeat("a", 64), FormatVersion: biz.TrivyReportFormatVersion}
}

func validTrivyScript(subject, cache string) string {
	return `
if [ "$1" = "version" ]; then
  [ "$2" = "--format" ] && [ "$3" = "json" ] && [ "$4" = "--cache-dir" ] && [ "$5" = "` + cache + `" ]
  printf '%s' '` + trivyVersionJSON + `'
  exit 0
fi
[ "$1" = "image" ]
[ "$2" = "--format" ] && [ "$3" = "json" ]
[ "$4" = "--scanners" ] && [ "$5" = "vuln" ]
[ "$6" = "--skip-db-update" ] && [ "$7" = "--offline-scan" ]
[ "$8" = "--no-progress" ] && [ "$9" = "--cache-backend" ] && [ "${10}" = "memory" ]
[ "${11}" = "--cache-dir" ] && [ "${12}" = "` + cache + `" ] && [ "${13}" = "` + subject + `" ]
[ "$TRIVY_CACHE_DIR" = "` + cache + `" ]
[ "$TRIVY_USERNAME" = "publisher" ] && [ "$TRIVY_PASSWORD" = "registry-password" ]
[ "$TRIVY_SKIP_DB_UPDATE" = "true" ] && [ "$TRIVY_OFFLINE_SCAN" = "true" ]
printf '%s' '{"SchemaVersion":2,"CreatedAt":"2026-08-22T09:40:00Z","ArtifactName":"` + subject + `","Results":[]}'
`
}

func TestTrivyScannerVerifiesPinnedDatabaseAndScansExactDigest(t *testing.T) {
	cache := t.TempDir()
	executable := writeFakeTrivy(t, validTrivyScript(trivyRequest().CanonicalSubject(), cache))
	scanner, err := NewTrivyScanner(TrivyOptions{Executable: executable,
		ExpectedVersion: PinnedTrivyVersion, CacheDirectory: cache, MaxOutputBytes: 4096,
		Credentials: validSyftCredentialProvider()})
	if err != nil {
		t.Fatal(err)
	}
	if err := scanner.Verify(t.Context()); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	report, err := scanner.ScanVulnerabilities(t.Context(), trivyRequest())
	if err != nil || report.ScannerVersion != PinnedTrivyVersion || report.Database.SchemaVersion != 2 ||
		report.HighestSeverity != biz.VulnerabilitySeverityNone || scanner.String() != "trivy/0.74.0" {
		t.Fatalf("ScanVulnerabilities() = %+v, %v", report, err)
	}
}

func TestTrivyScannerFailsClosedForVersionDatabaseAndOutput(t *testing.T) {
	tests := []struct {
		name   string
		script string
		verify bool
		want   error
	}{
		{name: "wrong version", verify: true, script: `printf '%s' '{"Version":"0.73.0"}'`, want: biz.ErrVulnerabilityScannerVersion},
		{name: "missing database", verify: true, script: `printf '%s' '{"Version":"0.74.0"}'`, want: biz.ErrVulnerabilityDatabase},
		{name: "scan failure", script: `if [ "$1" = version ]; then printf '%s' '` + trivyVersionJSON + `'; else exit 19; fi`, want: biz.ErrVulnerabilityScan},
		{name: "invalid report", script: `if [ "$1" = version ]; then printf '%s' '` + trivyVersionJSON + `'; else printf broken; fi`, want: biz.ErrInvalidVulnerabilityReport},
		{name: "oversized", script: `if [ "$1" = version ]; then printf '%s' '` + trivyVersionJSON + `'; else i=0; while [ "$i" -lt 2000 ]; do printf x; i=$((i + 1)); done; fi`, want: biz.ErrVulnerabilityReportSize},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			scanner, err := NewTrivyScanner(TrivyOptions{Executable: writeFakeTrivy(t, testCase.script),
				ExpectedVersion: PinnedTrivyVersion, CacheDirectory: t.TempDir(), MaxOutputBytes: 1024,
				Credentials: validSyftCredentialProvider()})
			if err != nil {
				t.Fatal(err)
			}
			if testCase.verify {
				err = scanner.Verify(t.Context())
			} else {
				_, err = scanner.ScanVulnerabilities(t.Context(), trivyRequest())
			}
			if !errors.Is(err, testCase.want) {
				t.Fatalf("error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestTrivyScannerFailsClosedWhenDatabaseChangesDuringScan(t *testing.T) {
	cache := t.TempDir()
	counter := filepath.Join(t.TempDir(), "version-calls")
	script := `
if [ "$1" = "version" ]; then
  calls=0
  if [ -f "` + counter + `" ]; then calls=$(cat "` + counter + `"); fi
  calls=$((calls + 1))
  printf '%s' "$calls" >"` + counter + `"
  if [ "$calls" -eq 1 ]; then
    printf '%s' '` + trivyVersionJSON + `'
  else
    printf '%s' '{"Version":"0.74.0","VulnerabilityDB":{"Version":2,"NextUpdate":"2026-08-23T07:04:53.306059725Z","UpdatedAt":"2026-08-22T07:04:53.306059926Z","DownloadedAt":"2026-08-22T09:41:00.270021094Z"}}'
  fi
  exit 0
fi
printf '%s' '{"SchemaVersion":2,"CreatedAt":"2026-08-22T09:40:00Z","ArtifactName":"` + trivyRequest().CanonicalSubject() + `","Results":[]}'
`
	scanner, err := NewTrivyScanner(TrivyOptions{Executable: writeFakeTrivy(t, script),
		ExpectedVersion: PinnedTrivyVersion, CacheDirectory: cache, MaxOutputBytes: 4096,
		Credentials: validSyftCredentialProvider()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.ScanVulnerabilities(t.Context(), trivyRequest()); !errors.Is(err, biz.ErrVulnerabilityDatabase) {
		t.Fatalf("database mutation error = %v", err)
	}
}

func TestTrivyReportAdapterRejectsSchemaSubjectAndFindingDrift(t *testing.T) {
	subject := trivyRequest().CanonicalSubject()
	valid := `{"SchemaVersion":2,"CreatedAt":"2026-08-22T08:00:00Z","ArtifactName":"` + subject + `","Results":[]}`
	for name, content := range map[string]string{
		"invalid JSON":  `{`,
		"wrong schema":  strings.Replace(valid, `"SchemaVersion":2`, `"SchemaVersion":1`, 1),
		"wrong subject": strings.Replace(valid, "team/api@", "team/other@", 1),
		"unknown severity": `{"SchemaVersion":2,"CreatedAt":"2026-08-22T08:00:00Z","ArtifactName":"` + subject +
			`","Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"BLOCKER"}]}]}`,
		"unbounded ID": `{"SchemaVersion":2,"CreatedAt":"2026-08-22T08:00:00Z","ArtifactName":"` + subject +
			`","Results":[{"Vulnerabilities":[{"VulnerabilityID":" CVE-1 ","Severity":"HIGH"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newTrivyV2Report([]byte(content), 4096, subject, PinnedTrivyVersion,
				biz.VulnerabilityDatabase{SchemaVersion: 2, UpdatedAt: time.Unix(100, 0).UTC(),
					DownloadedAt: time.Unix(110, 0).UTC(), NextUpdate: time.Unix(200, 0).UTC()}); !errors.Is(err, biz.ErrInvalidVulnerabilityReport) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTrivyScannerRejectsUnsafeConfigurationAndClearsCredential(t *testing.T) {
	options := []TrivyOptions{
		{Executable: "trivy", ExpectedVersion: PinnedTrivyVersion, CacheDirectory: "/cache", MaxOutputBytes: 1024, Credentials: validSyftCredentialProvider()},
		{Executable: "/trivy", ExpectedVersion: "latest", CacheDirectory: "/cache", MaxOutputBytes: 1024, Credentials: validSyftCredentialProvider()},
		{Executable: "/trivy", ExpectedVersion: PinnedTrivyVersion, CacheDirectory: "cache", MaxOutputBytes: 1024, Credentials: validSyftCredentialProvider()},
		{Executable: "/trivy", ExpectedVersion: PinnedTrivyVersion, CacheDirectory: "/cache", MaxOutputBytes: 1, Credentials: validSyftCredentialProvider()},
		{Executable: "/trivy", ExpectedVersion: PinnedTrivyVersion, CacheDirectory: "/cache", MaxOutputBytes: 1024},
	}
	for _, option := range options {
		if _, err := NewTrivyScanner(option); !errors.Is(err, biz.ErrVulnerabilityScannerVersion) {
			t.Fatalf("options %+v error = %v", option, err)
		}
	}
	secret := "trivy-secret-sentinel"
	credentials := &credentialCaptureProvider{username: "publisher", password: secret}
	scanner, err := NewTrivyScanner(TrivyOptions{Executable: writeFakeTrivy(t,
		`if [ "$1" = version ]; then printf '%s' '`+trivyVersionJSON+`'; else printf '%s' "$TRIVY_PASSWORD" >&2; exit 1; fi`),
		ExpectedVersion: PinnedTrivyVersion, CacheDirectory: t.TempDir(), MaxOutputBytes: 1024, Credentials: credentials})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanner.ScanVulnerabilities(t.Context(), trivyRequest())
	if !errors.Is(err, biz.ErrVulnerabilityScan) || strings.Contains(err.Error(), secret) || !credentials.cleared() {
		t.Fatalf("secret failure = %v, cleared=%t", err, credentials.cleared())
	}
}
