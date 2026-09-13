package releasepackaging_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifierBindsSignatureIdentityVersionAndArtifact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release verifier is a POSIX script")
	}
	directory := t.TempDir()
	version := "1.2.3"
	archiveName := "owndock-agent_" + version + "_linux_amd64.tar.gz"
	archive := filepath.Join(directory, archiveName)
	writeFile(t, archive, "release archive", 0o644)
	checksums := filepath.Join(directory, "SHA256SUMS")
	writeManifest(t, checksums, version, map[string]string{
		archiveName: "release archive",
		"owndock-agent_" + version + "_linux_arm64.tar.gz": "arm64 archive",
		"RELEASE.txt":                  "release metadata",
		"verify-owndock-agent-release": "verification script",
	})
	bundle := filepath.Join(directory, "SHA256SUMS.sigstore.json")
	writeFile(t, bundle, "signed bundle", 0o644)
	argumentLog := filepath.Join(directory, "cosign-arguments")
	cosign := filepath.Join(directory, "cosign")
	writeFile(t, cosign, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$OWNDOCK_TEST_ARGUMENT_LOG\"\n", 0o755)

	output, err := runVerifier(t, version, archive, checksums, bundle, cosign, argumentLog)
	if err != nil {
		t.Fatalf("verify valid release: %v\n%s", err, output)
	}
	arguments := readFile(t, argumentLog)
	for _, expected := range []string{
		"verify-blob\n",
		"--offline\n",
		"--certificate-identity\nhttps://github.com/owndock/owndock/.github/workflows/release.yml@refs/tags/v1.2.3\n",
		"--certificate-oidc-issuer\nhttps://token.actions.githubusercontent.com\n",
	} {
		if !strings.Contains(arguments, expected) {
			t.Fatalf("cosign arguments are missing %q:\n%s", expected, arguments)
		}
	}
	if !strings.Contains(string(output), "Verified OwnDock Agent 1.2.3") {
		t.Fatalf("unexpected verifier output: %s", output)
	}
}

func TestVerifierRejectsTamperingWrongVersionAndBadSignature(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release verifier is a POSIX script")
	}
	for _, testCase := range []struct {
		name          string
		requested     string
		archiveName   string
		archiveBefore string
		archiveAfter  string
		cosignExit    string
	}{
		{
			name: "tampered artifact", requested: "2.0.0",
			archiveName:   "owndock-agent_2.0.0_linux_amd64.tar.gz",
			archiveBefore: "original", archiveAfter: "tampered", cosignExit: "0",
		},
		{
			name: "wrong version", requested: "2.0.1",
			archiveName:   "owndock-agent_2.0.0_linux_amd64.tar.gz",
			archiveBefore: "original", archiveAfter: "original", cosignExit: "0",
		},
		{
			name: "wrong signer", requested: "2.0.0",
			archiveName:   "owndock-agent_2.0.0_linux_amd64.tar.gz",
			archiveBefore: "original", archiveAfter: "original", cosignExit: "7",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			archive := filepath.Join(directory, testCase.archiveName)
			writeFile(t, archive, testCase.archiveBefore, 0o644)
			checksums := filepath.Join(directory, "SHA256SUMS")
			writeManifest(t, checksums, "2.0.0", map[string]string{
				"owndock-agent_2.0.0_linux_amd64.tar.gz": testCase.archiveBefore,
				"owndock-agent_2.0.0_linux_arm64.tar.gz": "arm64",
				"RELEASE.txt":                            "metadata",
				"verify-owndock-agent-release":           "script",
			})
			writeFile(t, archive, testCase.archiveAfter, 0o644)
			bundle := filepath.Join(directory, "SHA256SUMS.sigstore.json")
			writeFile(t, bundle, "bundle", 0o644)
			cosign := filepath.Join(directory, "cosign")
			writeFile(t, cosign, "#!/bin/sh\nexit "+testCase.cosignExit+"\n", 0o755)
			if output, err := runVerifier(t, testCase.requested, archive, checksums, bundle, cosign, ""); err == nil {
				t.Fatalf("invalid release unexpectedly passed:\n%s", output)
			}
		})
	}
}

func TestVerifierRejectsUnsafeChecksumManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release verifier is a POSIX script")
	}
	directory := t.TempDir()
	version := "3.0.0"
	archive := filepath.Join(directory, "owndock-agent_3.0.0_linux_amd64.tar.gz")
	writeFile(t, archive, "archive", 0o644)
	checksums := filepath.Join(directory, "SHA256SUMS")
	digest := strings.Repeat("a", 64)
	writeFile(t, checksums, digest+"  ../../unexpected\n", 0o644)
	bundle := filepath.Join(directory, "SHA256SUMS.sigstore.json")
	writeFile(t, bundle, "bundle", 0o644)
	cosign := filepath.Join(directory, "cosign")
	writeFile(t, cosign, "#!/bin/sh\nexit 0\n", 0o755)
	if output, err := runVerifier(t, version, archive, checksums, bundle, cosign, ""); err == nil {
		t.Fatalf("unsafe manifest unexpectedly passed:\n%s", output)
	}
}

func TestCommunityVerifierBindsReportsImagesAndReleaseIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release verifier is a POSIX script")
	}
	directory := t.TempDir()
	version := "1.2.3"
	files := map[string]string{
		"owndock-community_1.2.3.tar.gz":    "community archive",
		"CONTAINER_IMAGES.txt":              communityImageManifest(),
		"COMMUNITY_COMPATIBILITY_amd64.txt": communityReport(version, "amd64"),
		"COMMUNITY_COMPATIBILITY_arm64.txt": communityReport(version, "arm64"),
		"verify-community-release": readFile(
			t, filepath.Join(repositoryRoot(t), "packaging/release/verify-community-release"),
		),
	}
	for name, value := range files {
		mode := os.FileMode(0o644)
		if name == "verify-community-release" {
			mode = 0o755
		}
		writeFile(t, filepath.Join(directory, name), value, mode)
	}
	var checksums strings.Builder
	for _, name := range []string{
		"owndock-community_1.2.3.tar.gz",
		"CONTAINER_IMAGES.txt",
		"COMMUNITY_COMPATIBILITY_amd64.txt",
		"COMMUNITY_COMPATIBILITY_arm64.txt",
		"verify-community-release",
	} {
		digest := sha256.Sum256([]byte(files[name]))
		checksums.WriteString(hex.EncodeToString(digest[:]) + "  " + name + "\n")
	}
	writeFile(t, filepath.Join(directory, "COMMUNITY_SHA256SUMS"), checksums.String(), 0o644)
	writeFile(t, filepath.Join(directory, "COMMUNITY_SHA256SUMS.sigstore.json"), "bundle", 0o644)
	writeFile(t, filepath.Join(directory, "CONTAINER_IMAGES.sigstore.json"), "bundle", 0o644)
	argumentLog := filepath.Join(directory, "cosign-arguments")
	cosign := filepath.Join(directory, "cosign")
	writeFile(t, cosign, "#!/bin/sh\nprintf '%s\\n' \"$@\" >>\"$OWNDOCK_TEST_ARGUMENT_LOG\"\n", 0o755)

	run := func() ([]byte, error) {
		command := exec.Command("sh", filepath.Join(directory, "verify-community-release"), version, directory)
		command.Env = append(os.Environ(),
			"OWNDOCK_COSIGN_BINARY="+cosign,
			"OWNDOCK_TEST_ARGUMENT_LOG="+argumentLog,
		)
		return command.CombinedOutput()
	}
	if output, err := run(); err != nil {
		t.Fatalf("verify community release: %v: %s", err, output)
	}
	arguments := readFile(t, argumentLog)
	if strings.Count(arguments, "verify-blob\n") != 2 ||
		!strings.Contains(arguments,
			"--certificate-identity\nhttps://github.com/owndock/owndock/.github/workflows/release.yml@refs/tags/v1.2.3\n") {
		t.Fatalf("unexpected Cosign arguments:\n%s", arguments)
	}

	writeFile(t, filepath.Join(directory, "COMMUNITY_COMPATIBILITY_arm64.txt"),
		communityReport(version, "amd64"), 0o644)
	if output, err := run(); err == nil {
		t.Fatalf("tampered compatibility report passed: %s", output)
	}
}

func communityImageManifest() string {
	images := []string{
		"ghcr.io/owndock/owndock",
		"ghcr.io/owndock/owndock-build-worker",
		"ghcr.io/owndock/owndock-build-egress-gateway",
		"ghcr.io/owndock/owndock-evidence-worker",
		"ghcr.io/owndock/owndock-vulnerability-db-updater",
	}
	var value strings.Builder
	for index, image := range images {
		value.WriteString(image + "@sha256:" + strings.Repeat(string(rune('a'+index)), 64) + "\n")
	}
	return value.String()
}

func communityReport(version, architecture string) string {
	return "schema=owndock-community-compatibility-v1\n" +
		"result=passed\ncurrent_version=" + version + "\narchitecture=" + architecture + "\n"
}

func runVerifier(
	t *testing.T,
	version, archive, checksums, bundle, cosign, argumentLog string,
) ([]byte, error) {
	t.Helper()
	script := filepath.Join(repositoryRoot(t), "packaging/release/verify-agent-release")
	command := exec.Command("sh", script, version, archive, checksums, bundle)
	command.Env = append(
		os.Environ(),
		"OWNDOCK_COSIGN_BINARY="+cosign,
		"OWNDOCK_TEST_ARGUMENT_LOG="+argumentLog,
	)
	return command.CombinedOutput()
}

func writeManifest(t *testing.T, path, version string, files map[string]string) {
	t.Helper()
	ordered := []string{
		"RELEASE.txt",
		"owndock-agent_" + version + "_linux_amd64.tar.gz",
		"owndock-agent_" + version + "_linux_arm64.tar.gz",
		"verify-owndock-agent-release",
	}
	var value strings.Builder
	for _, name := range ordered {
		digest := sha256.Sum256([]byte(files[name]))
		value.WriteString(hex.EncodeToString(digest[:]) + "  " + name + "\n")
	}
	writeFile(t, path, value.String(), 0o644)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func writeFile(t *testing.T, path, value string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}
