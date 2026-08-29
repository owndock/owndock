package main

import (
	"archive/tar"
	"compress/gzip"
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
	"time"
)

var (
	validReleaseValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	validVersion      = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	errInvalidPackage = errors.New("Agent package input is invalid")
)

type packageConfig struct {
	Binary        string
	Manager       string
	ServiceUnit   string
	ConfigExample string
	OutputDir     string
	Version       string
	GOOS          string
	GOARCH        string
}

type packageEntry struct {
	Name string
	Mode int64
	Data []byte
}

func main() {
	var config packageConfig
	flag.StringVar(&config.Binary, "binary", "", "path to the owndock-agent binary")
	flag.StringVar(&config.Manager, "manager", "packaging/agent/owndock-agentctl", "path to owndock-agentctl")
	flag.StringVar(&config.ServiceUnit, "service-unit", "packaging/agent/owndock-agent.service", "path to the systemd unit")
	flag.StringVar(&config.ConfigExample, "config-example", "configs/agent.yaml", "path to the Agent configuration example")
	flag.StringVar(&config.OutputDir, "output", "dist", "output directory")
	flag.StringVar(&config.Version, "version", "", "release version")
	flag.StringVar(&config.GOOS, "os", "linux", "target operating system")
	flag.StringVar(&config.GOARCH, "arch", "amd64", "target architecture")
	flag.Parse()
	archive, checksum, err := buildPackage(config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintf(os.Stdout, "%s\n%s\n", archive, checksum)
}

func buildPackage(config packageConfig) (string, string, error) {
	if !validVersion.MatchString(config.Version) || len(config.Version) > 64 {
		return "", "", errInvalidPackage
	}
	for _, value := range []string{config.GOOS, config.GOARCH} {
		if !validReleaseValue.MatchString(value) {
			return "", "", errInvalidPackage
		}
	}
	if config.GOOS != "linux" ||
		(config.GOARCH != "amd64" && config.GOARCH != "arm64") ||
		strings.TrimSpace(config.OutputDir) == "" {
		return "", "", errInvalidPackage
	}
	inputs := []struct {
		name string
		path string
		mode int64
	}{
		{name: "owndock-agent", path: config.Binary, mode: 0o755},
		{name: "owndock-agentctl", path: config.Manager, mode: 0o755},
		{name: "owndock-agent.service", path: config.ServiceUnit, mode: 0o644},
		{name: "agent.yaml.example", path: config.ConfigExample, mode: 0o640},
	}
	entries := make([]packageEntry, 0, len(inputs)+3)
	var binaryDigest string
	for _, input := range inputs {
		value, err := readRegularFile(input.path)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", input.name, err)
		}
		entries = append(entries, packageEntry{Name: input.name, Mode: input.mode, Data: value})
		if input.name == "owndock-agent" {
			digest := sha256.Sum256(value)
			binaryDigest = hex.EncodeToString(digest[:])
		}
	}
	entries = append(entries,
		packageEntry{Name: "VERSION", Mode: 0o644, Data: []byte(config.Version + "\n")},
		packageEntry{Name: "owndock-agent.sha256", Mode: 0o644, Data: []byte(binaryDigest + "\n")},
		packageEntry{Name: "INSTALL.md", Mode: 0o644, Data: []byte(installInstructions(config.Version))},
	)
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name < entries[right].Name })
	if err := os.MkdirAll(config.OutputDir, 0o755); err != nil {
		return "", "", fmt.Errorf("create Agent package output: %w", err)
	}
	baseName := fmt.Sprintf("owndock-agent_%s_%s_%s", config.Version, config.GOOS, config.GOARCH)
	archivePath := filepath.Join(config.OutputDir, baseName+".tar.gz")
	if err := writeArchive(archivePath, baseName, entries); err != nil {
		return "", "", err
	}
	archiveValue, err := os.ReadFile(archivePath)
	if err != nil {
		return "", "", fmt.Errorf("read Agent package: %w", err)
	}
	digest := sha256.Sum256(archiveValue)
	checksumPath := archivePath + ".sha256"
	checksum := hex.EncodeToString(digest[:]) + "  " + filepath.Base(archivePath) + "\n"
	if err := writeFileAtomically(checksumPath, []byte(checksum), 0o644); err != nil {
		return "", "", err
	}
	return archivePath, checksumPath, nil
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 256*1024*1024 {
		return nil, errInvalidPackage
	}
	return os.ReadFile(path)
}

func writeArchive(path, root string, entries []packageEntry) (result error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".owndock-agent-package-*")
	if err != nil {
		return fmt.Errorf("create Agent package: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if result != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	gzipWriter, err := gzip.NewWriterLevel(temporary, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create Agent package compressor: %w", err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	directoryHeader := &tar.Header{
		Name: root + "/", Typeflag: tar.TypeDir, Mode: 0o755,
		Uid: 0, Gid: 0, Uname: "root", Gname: "root", ModTime: time.Unix(0, 0).UTC(),
		Format: tar.FormatPAX,
	}
	if err := tarWriter.WriteHeader(directoryHeader); err != nil {
		return fmt.Errorf("write Agent package directory: %w", err)
	}
	for _, entry := range entries {
		header := &tar.Header{
			Name: root + "/" + entry.Name, Typeflag: tar.TypeReg,
			Mode: entry.Mode, Size: int64(len(entry.Data)), Uid: 0, Gid: 0,
			Uname: "root", Gname: "root", ModTime: time.Unix(0, 0).UTC(),
			Format: tar.FormatPAX,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("write Agent package header: %w", err)
		}
		if _, err := tarWriter.Write(entry.Data); err != nil {
			return fmt.Errorf("write Agent package content: %w", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("close Agent package archive: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("close Agent package compressor: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync Agent package: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Agent package: %w", err)
	}
	if err := os.Chmod(temporaryPath, 0o644); err != nil {
		return fmt.Errorf("protect Agent package: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace Agent package: %w", err)
	}
	return nil
}

func writeFileAtomically(path string, value []byte, mode os.FileMode) (result error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".owndock-agent-checksum-*")
	if err != nil {
		return fmt.Errorf("create Agent package checksum: %w", err)
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

func installInstructions(version string) string {
	return fmt.Sprintf(`# OwnDock Agent %s

1. Verify the archive checksum before extraction.
2. Install the versioned release without starting the service:

       sudo ./owndock-agentctl install

3. Put the one-time enrollment token in a root-owned 0600 regular file, then
   generate the private key locally and enroll:

       sudo owndock-agentctl enroll \
         --enrollment-endpoint https://console.example.com/api/v1/agent/enrollments:exchange \
         --control-endpoint https://control.example.com:8443/api/v1/agent/connect \
         --token-file /root/owndock-agent-enrollment.token

Never pass the token in an argument or environment variable. If local install
fails with an ambiguous network result, rerun the same command with the same
token file; the persisted private key and CSR are reused. If local install was
interrupted after the response was persisted, use:

       sudo owndock-agentctl enroll --recover

Rollback keeps configuration, identity and state unchanged:

       sudo owndock-agentctl rollback --version <previous-version>
`, version)
}
