package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	productName      = "owndock-agent"
	releaseSchema    = "owndock-agent-release-v1"
	releaseSource    = "https://github.com/owndock/owndock"
	verifierFileName = "verify-owndock-agent-release"
	maximumFileSize  = 512 * 1024 * 1024
)

var (
	validVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	validCommit  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	errInvalid   = errors.New("release manifest input is invalid")
)

type manifestConfig struct {
	Version      string
	Commit       string
	OutputDir    string
	VerifierPath string
}

type releaseFile struct {
	Name   string
	Source string
}

func main() {
	var config manifestConfig
	flag.StringVar(&config.Version, "version", "", "release version without the v prefix")
	flag.StringVar(&config.Commit, "commit", "", "full lowercase Git commit SHA")
	flag.StringVar(&config.OutputDir, "output", "dist", "release artifact directory")
	flag.StringVar(
		&config.VerifierPath,
		"verifier",
		"packaging/release/verify-agent-release",
		"customer verification script",
	)
	flag.Parse()
	if err := createManifest(config); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func createManifest(config manifestConfig) error {
	if !validVersion.MatchString(config.Version) || len(config.Version) > 64 ||
		!validCommit.MatchString(config.Commit) || strings.TrimSpace(config.OutputDir) == "" {
		return errInvalid
	}
	if err := os.MkdirAll(config.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create release output: %w", err)
	}
	verifier, err := readReleaseFile(config.VerifierPath)
	if err != nil {
		return fmt.Errorf("read release verifier: %w", err)
	}
	verifierPath := filepath.Join(config.OutputDir, verifierFileName)
	if err := writeFileAtomically(verifierPath, verifier, 0o755); err != nil {
		return fmt.Errorf("write release verifier: %w", err)
	}

	releaseText := fmt.Sprintf(
		"schema=%s\nproduct=%s\nversion=%s\ngit_tag=v%s\ngit_commit=%s\nsource=%s\n",
		releaseSchema,
		productName,
		config.Version,
		config.Version,
		config.Commit,
		releaseSource,
	)
	releasePath := filepath.Join(config.OutputDir, "RELEASE.txt")
	if err := writeFileAtomically(releasePath, []byte(releaseText), 0o644); err != nil {
		return fmt.Errorf("write release metadata: %w", err)
	}

	files := []releaseFile{
		{Name: "RELEASE.txt", Source: releasePath},
		{
			Name:   fmt.Sprintf("owndock-agent_%s_linux_amd64.tar.gz", config.Version),
			Source: filepath.Join(config.OutputDir, fmt.Sprintf("owndock-agent_%s_linux_amd64.tar.gz", config.Version)),
		},
		{
			Name:   fmt.Sprintf("owndock-agent_%s_linux_arm64.tar.gz", config.Version),
			Source: filepath.Join(config.OutputDir, fmt.Sprintf("owndock-agent_%s_linux_arm64.tar.gz", config.Version)),
		},
		{Name: verifierFileName, Source: verifierPath},
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Name < files[right].Name })
	var checksums strings.Builder
	for _, file := range files {
		value, err := readReleaseFile(file.Source)
		if err != nil {
			return fmt.Errorf("read release artifact %s: %w", file.Name, err)
		}
		digest := sha256.Sum256(value)
		_, _ = fmt.Fprintf(&checksums, "%s  %s\n", hex.EncodeToString(digest[:]), file.Name)
	}
	if err := writeFileAtomically(
		filepath.Join(config.OutputDir, "SHA256SUMS"),
		[]byte(checksums.String()),
		0o644,
	); err != nil {
		return fmt.Errorf("write release checksums: %w", err)
	}
	return nil
}

func readReleaseFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximumFileSize {
		return nil, errInvalid
	}
	return os.ReadFile(path)
}

func writeFileAtomically(path string, value []byte, mode os.FileMode) (result error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".owndock-release-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if result != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return nil
}
