package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildPackageIsDeterministicAndSelfVerifying(t *testing.T) {
	directory := t.TempDir()
	files := map[string]struct {
		value string
		mode  os.FileMode
	}{
		"owndock-agent":         {value: "agent-binary", mode: 0o755},
		"owndock-agentctl":      {value: "manager", mode: 0o755},
		"owndock-agent.service": {value: "unit", mode: 0o644},
		"agent.yaml":            {value: "control: {}", mode: 0o640},
	}
	for name, file := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(file.value), file.mode); err != nil {
			t.Fatal(err)
		}
	}
	base := packageConfig{
		Binary:        filepath.Join(directory, "owndock-agent"),
		Manager:       filepath.Join(directory, "owndock-agentctl"),
		ServiceUnit:   filepath.Join(directory, "owndock-agent.service"),
		ConfigExample: filepath.Join(directory, "agent.yaml"),
		Version:       "1.2.3", GOOS: "linux", GOARCH: "amd64",
	}
	first := base
	first.OutputDir = filepath.Join(directory, "first")
	firstArchive, firstChecksum, err := buildPackage(first)
	if err != nil {
		t.Fatal(err)
	}
	second := base
	second.OutputDir = filepath.Join(directory, "second")
	secondArchive, _, err := buildPackage(second)
	if err != nil {
		t.Fatal(err)
	}
	firstValue, err := os.ReadFile(firstArchive)
	if err != nil {
		t.Fatal(err)
	}
	secondValue, err := os.ReadFile(secondArchive)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstValue, secondValue) {
		t.Fatal("identical inputs did not produce an identical Agent archive")
	}
	digest := sha256.Sum256(firstValue)
	checksum, err := os.ReadFile(firstChecksum)
	if err != nil {
		t.Fatal(err)
	}
	expectedChecksum := hex.EncodeToString(digest[:]) + "  " + filepath.Base(firstArchive) + "\n"
	if string(checksum) != expectedChecksum {
		t.Fatalf("archive checksum = %q", checksum)
	}
	entries := readArchive(t, firstArchive)
	expectedNames := []string{
		"owndock-agent_1.2.3_linux_amd64/",
		"owndock-agent_1.2.3_linux_amd64/INSTALL.md",
		"owndock-agent_1.2.3_linux_amd64/VERSION",
		"owndock-agent_1.2.3_linux_amd64/agent.yaml.example",
		"owndock-agent_1.2.3_linux_amd64/owndock-agent",
		"owndock-agent_1.2.3_linux_amd64/owndock-agent.service",
		"owndock-agent_1.2.3_linux_amd64/owndock-agent.sha256",
		"owndock-agent_1.2.3_linux_amd64/owndock-agentctl",
	}
	if !reflect.DeepEqual(entries.names, expectedNames) {
		t.Fatalf("archive entries = %#v", entries.names)
	}
	if entries.modes["owndock-agent_1.2.3_linux_amd64/owndock-agent"] != 0o755 ||
		entries.modes["owndock-agent_1.2.3_linux_amd64/agent.yaml.example"] != 0o640 {
		t.Fatalf("archive modes = %#v", entries.modes)
	}
	binaryDigest := sha256.Sum256([]byte("agent-binary"))
	if entries.values["owndock-agent_1.2.3_linux_amd64/owndock-agent.sha256"] !=
		hex.EncodeToString(binaryDigest[:])+"\n" {
		t.Fatalf("binary checksum = %q", entries.values["owndock-agent_1.2.3_linux_amd64/owndock-agent.sha256"])
	}
}

func TestBuildPackageRejectsUnsafeInputs(t *testing.T) {
	config := packageConfig{Version: "../escape", GOOS: "linux", GOARCH: "amd64"}
	if _, _, err := buildPackage(config); err == nil {
		t.Fatal("unsafe version was accepted")
	}
	config = packageConfig{Version: "1.0.0", GOOS: "linux", GOARCH: "386", OutputDir: t.TempDir()}
	if _, _, err := buildPackage(config); err == nil {
		t.Fatal("unsupported architecture was accepted")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "binary")
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "binary-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(link); err == nil {
		t.Fatal("symbolic link package input was accepted")
	}
}

type archiveContents struct {
	names  []string
	modes  map[string]int64
	values map[string]string
}

func readArchive(t *testing.T, path string) archiveContents {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	contents := archiveContents{modes: map[string]int64{}, values: map[string]string{}}
	reader := tar.NewReader(gzipReader)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(header.Name, "..") || strings.HasPrefix(header.Name, "/") ||
			header.Uid != 0 || header.Gid != 0 {
			t.Fatalf("unsafe archive header = %+v", header)
		}
		contents.names = append(contents.names, header.Name)
		contents.modes[header.Name] = header.Mode
		if header.Typeflag == tar.TypeReg {
			value, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			contents.values[header.Name] = string(value)
		}
	}
	return contents
}
