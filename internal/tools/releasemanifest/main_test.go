package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateManifestBindsArtifactsVersionAndCommit(t *testing.T) {
	output := t.TempDir()
	version := "1.2.3-rc.1"
	writeTestFile(t, filepath.Join(output, "owndock-agent_"+version+"_linux_amd64.tar.gz"), "amd64", 0o644)
	writeTestFile(t, filepath.Join(output, "owndock-agent_"+version+"_linux_arm64.tar.gz"), "arm64", 0o644)
	verifier := filepath.Join(t.TempDir(), "verify")
	writeTestFile(t, verifier, "#!/bin/sh\n", 0o755)
	commit := strings.Repeat("a", 40)

	if err := createManifest(manifestConfig{
		Version: version, Commit: commit, OutputDir: output, VerifierPath: verifier,
	}); err != nil {
		t.Fatal(err)
	}
	metadata := readTestFile(t, filepath.Join(output, "RELEASE.txt"))
	for _, expected := range []string{
		"schema=owndock-agent-release-v1\n",
		"product=owndock-agent\n",
		"version=" + version + "\n",
		"git_tag=v" + version + "\n",
		"git_commit=" + commit + "\n",
		"source=https://github.com/owndock/owndock\n",
	} {
		if !strings.Contains(metadata, expected) {
			t.Fatalf("release metadata is missing %q:\n%s", expected, metadata)
		}
	}
	checksums := readTestFile(t, filepath.Join(output, "SHA256SUMS"))
	lines := strings.Split(strings.TrimSpace(checksums), "\n")
	if len(lines) != 4 {
		t.Fatalf("checksum line count = %d:\n%s", len(lines), checksums)
	}
	if !sortIsStable(lines) {
		t.Fatalf("checksum entries are not sorted:\n%s", checksums)
	}
	for _, name := range []string{
		"RELEASE.txt",
		"owndock-agent_" + version + "_linux_amd64.tar.gz",
		"owndock-agent_" + version + "_linux_arm64.tar.gz",
		verifierFileName,
	} {
		value := []byte(readTestFile(t, filepath.Join(output, name)))
		digest := sha256.Sum256(value)
		expected := hex.EncodeToString(digest[:]) + "  " + name
		if !strings.Contains(checksums, expected+"\n") {
			t.Fatalf("checksum is missing %q:\n%s", expected, checksums)
		}
	}
	mode, err := os.Stat(filepath.Join(output, verifierFileName))
	if err != nil {
		t.Fatal(err)
	}
	if mode.Mode().Perm() != 0o755 {
		t.Fatalf("verifier mode = %#o", mode.Mode().Perm())
	}
}

func TestCreateManifestRejectsInvalidOrUnsafeInput(t *testing.T) {
	validCommit := strings.Repeat("b", 40)
	for name, config := range map[string]manifestConfig{
		"tag prefix":   {Version: "v1.0.0", Commit: validCommit, OutputDir: t.TempDir()},
		"short commit": {Version: "1.0.0", Commit: "abc", OutputDir: t.TempDir()},
		"empty output": {Version: "1.0.0", Commit: validCommit, OutputDir: " "},
	} {
		t.Run(name, func(t *testing.T) {
			if err := createManifest(config); err == nil {
				t.Fatal("invalid manifest unexpectedly succeeded")
			}
		})
	}

	output := t.TempDir()
	verifierTarget := filepath.Join(t.TempDir(), "target")
	writeTestFile(t, verifierTarget, "#!/bin/sh\n", 0o755)
	verifierLink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(verifierTarget, verifierLink); err != nil {
		t.Fatal(err)
	}
	if err := createManifest(manifestConfig{
		Version: "1.0.0", Commit: validCommit, OutputDir: output, VerifierPath: verifierLink,
	}); err == nil {
		t.Fatal("symlink verifier unexpectedly succeeded")
	}
}

func sortIsStable(lines []string) bool {
	previous := ""
	for _, line := range lines {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || (previous != "" && parts[1] < previous) {
			return false
		}
		previous = parts[1]
	}
	return true
}

func writeTestFile(t *testing.T, path, value string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), mode); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}
