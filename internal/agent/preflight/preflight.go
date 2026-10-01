package preflight

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const (
	SupportedOS              = "ubuntu"
	SupportedOSVersion       = "24.04"
	SupportedDockerVersion   = "29.6.1"
	maximumOSReleaseFileSize = 64 * 1024
)

var ErrUnsupportedHost = errors.New("unsupported Agent host")

type Result struct {
	Status       string `json:"status"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Architecture string `json:"architecture"`
	DockerEngine string `json:"docker_engine"`
	DockerAPI    string `json:"docker_api"`
	DockerCgroup string `json:"docker_cgroup"`
	Systemd      bool   `json:"systemd"`
	CgroupV2     bool   `json:"cgroup_v2"`
	DockerSocket bool   `json:"docker_socket"`
}

type Environment struct {
	GOOS                  string
	GOARCH                string
	OSReleasePath         string
	SystemdRuntimePath    string
	CgroupControllersPath string
	DockerBinaryPath      string
	DockerSocketPath      string
	ReadFile              func(string) ([]byte, error)
	Stat                  func(string) (os.FileInfo, error)
	Lstat                 func(string) (os.FileInfo, error)
	Run                   func(context.Context, string, ...string) ([]byte, error)
}

func DefaultEnvironment() Environment {
	return Environment{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		OSReleasePath: "/etc/os-release", SystemdRuntimePath: "/run/systemd/system",
		CgroupControllersPath: "/sys/fs/cgroup/cgroup.controllers",
		DockerBinaryPath:      "/usr/bin/docker", DockerSocketPath: "/var/run/docker.sock",
		ReadFile: os.ReadFile, Stat: os.Stat, Lstat: os.Lstat,
		Run: func(ctx context.Context, name string, arguments ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, arguments...).Output()
		},
	}
}

func Check(ctx context.Context, environment Environment) (Result, error) {
	if environment.GOOS != "linux" ||
		(environment.GOARCH != "amd64" && environment.GOARCH != "arm64") {
		return Result{}, unsupported("requires linux/amd64 or linux/arm64")
	}
	osRelease, err := environment.ReadFile(environment.OSReleasePath)
	if err != nil || len(osRelease) == 0 || len(osRelease) > maximumOSReleaseFileSize {
		return Result{}, unsupported("cannot read a bounded OS release identity")
	}
	osID, osVersion := parseOSRelease(osRelease)
	if osID != SupportedOS || osVersion != SupportedOSVersion {
		return Result{}, unsupported("requires Ubuntu Server 24.04 LTS")
	}
	if info, statErr := environment.Stat(environment.SystemdRuntimePath); statErr != nil || !info.IsDir() {
		return Result{}, unsupported("requires a running systemd system instance")
	}
	controllers, err := environment.ReadFile(environment.CgroupControllersPath)
	if err != nil || len(strings.TrimSpace(string(controllers))) == 0 {
		return Result{}, unsupported("requires cgroup v2")
	}
	if info, statErr := environment.Lstat(environment.DockerBinaryPath); statErr != nil ||
		!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Result{}, unsupported("requires Docker CLI at /usr/bin/docker")
	}
	if info, statErr := environment.Lstat(environment.DockerSocketPath); statErr != nil ||
		info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return Result{}, unsupported("requires a local Docker Unix socket")
	}
	versionOutput, err := environment.Run(ctx, environment.DockerBinaryPath, "version", "--format",
		"{{.Server.Version}}\\t{{.Server.APIVersion}}")
	if err != nil {
		return Result{}, unsupported("cannot reach Docker Engine")
	}
	versionFields := strings.Split(strings.TrimSpace(string(versionOutput)), "\t")
	if len(versionFields) != 2 || versionFields[0] != SupportedDockerVersion ||
		!safeValue(versionFields[1]) {
		return Result{}, unsupported("requires Docker Engine 29.6.1")
	}
	infoOutput, err := environment.Run(ctx, environment.DockerBinaryPath, "info", "--format",
		"{{.OSType}}\\t{{.Architecture}}\\t{{.CgroupVersion}}")
	if err != nil {
		return Result{}, unsupported("cannot inspect Docker Engine")
	}
	infoFields := strings.Split(strings.TrimSpace(string(infoOutput)), "\t")
	if len(infoFields) != 3 || infoFields[0] != "linux" ||
		normalizeArchitecture(infoFields[1]) != environment.GOARCH || infoFields[2] != "2" {
		return Result{}, unsupported("Docker Engine host, architecture, or cgroup mode is incompatible")
	}
	return Result{
		Status: "passed", OS: osID, OSVersion: osVersion, Architecture: environment.GOARCH,
		DockerEngine: versionFields[0], DockerAPI: versionFields[1], DockerCgroup: infoFields[2],
		Systemd: true, CgroupV2: true, DockerSocket: true,
	}, nil
}

func parseOSRelease(value []byte) (string, string) {
	fields := make(map[string]string, 2)
	for _, line := range strings.Split(string(value), "\n") {
		key, raw, found := strings.Cut(line, "=")
		if !found || key != "ID" && key != "VERSION_ID" {
			continue
		}
		raw = strings.TrimSpace(raw)
		if len(raw) >= 2 && ((raw[0] == '"' && raw[len(raw)-1] == '"') ||
			(raw[0] == '\'' && raw[len(raw)-1] == '\'')) {
			raw = raw[1 : len(raw)-1]
		}
		fields[key] = strings.ToLower(raw)
	}
	return fields["ID"], fields["VERSION_ID"]
}

func normalizeArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return ""
	}
}

func safeValue(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' || character == '.' || character == '-' ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}

func unsupported(reason string) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedHost, reason)
}
