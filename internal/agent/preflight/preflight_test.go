package preflight

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"
)

type fakeFileInfo struct {
	name string
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func TestCheckAcceptsExactSupportedHostWithoutExposingIdentity(t *testing.T) {
	result, err := Check(t.Context(), supportedEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "passed" || result.OS != "ubuntu" || result.OSVersion != "24.04" ||
		result.Architecture != "arm64" || result.DockerEngine != "29.6.1" ||
		result.DockerAPI != "1.55" || !result.Systemd || !result.CgroupV2 || !result.DockerSocket {
		t.Fatalf("result = %#v", result)
	}
}

func TestCheckRejectsUnsupportedOrUntrustedHostsBeforeInstallation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Environment)
	}{
		{name: "operating system", mutate: func(e *Environment) { e.GOOS = "darwin" }},
		{name: "architecture", mutate: func(e *Environment) { e.GOARCH = "riscv64" }},
		{name: "distribution", mutate: func(e *Environment) {
			e.ReadFile = fileReader(map[string][]byte{"/etc/os-release": []byte("ID=debian\nVERSION_ID=24.04\n")})
		}},
		{name: "systemd", mutate: func(e *Environment) {
			e.Stat = func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist }
		}},
		{name: "cgroup v1", mutate: func(e *Environment) {
			e.ReadFile = fileReader(map[string][]byte{
				"/etc/os-release":                   []byte("ID=ubuntu\nVERSION_ID=24.04\n"),
				"/sys/fs/cgroup/cgroup.controllers": nil,
			})
		}},
		{name: "Docker binary symlink", mutate: func(e *Environment) {
			e.Lstat = func(path string) (os.FileInfo, error) {
				if path == "/usr/bin/docker" {
					return fakeFileInfo{name: "docker", mode: os.ModeSymlink}, nil
				}
				return fakeFileInfo{name: "docker.sock", mode: os.ModeSocket}, nil
			}
		}},
		{name: "Docker socket", mutate: func(e *Environment) {
			e.Lstat = func(path string) (os.FileInfo, error) {
				if path == "/usr/bin/docker" {
					return fakeFileInfo{name: "docker", mode: 0o755}, nil
				}
				return fakeFileInfo{name: "docker.sock", mode: 0o600}, nil
			}
		}},
		{name: "Docker version", mutate: func(e *Environment) {
			e.Run = commandOutputs("29.6.2\t1.55\n", "linux\taarch64\t2\n")
		}},
		{name: "Docker architecture", mutate: func(e *Environment) {
			e.Run = commandOutputs("29.6.1\t1.55\n", "linux\tx86_64\t2\n")
		}},
		{name: "Docker cgroup", mutate: func(e *Environment) {
			e.Run = commandOutputs("29.6.1\t1.55\n", "linux\taarch64\t1\n")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment := supportedEnvironment()
			test.mutate(&environment)
			if _, err := Check(t.Context(), environment); !errors.Is(err, ErrUnsupportedHost) {
				t.Fatalf("Check() error = %v", err)
			}
		})
	}
}

func supportedEnvironment() Environment {
	return Environment{
		GOOS: "linux", GOARCH: "arm64", OSReleasePath: "/etc/os-release",
		SystemdRuntimePath:    "/run/systemd/system",
		CgroupControllersPath: "/sys/fs/cgroup/cgroup.controllers",
		DockerBinaryPath:      "/usr/bin/docker", DockerSocketPath: "/var/run/docker.sock",
		ReadFile: fileReader(map[string][]byte{
			"/etc/os-release":                   []byte("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"24.04\"\n"),
			"/sys/fs/cgroup/cgroup.controllers": []byte("cpu memory pids\n"),
		}),
		Stat: func(string) (os.FileInfo, error) {
			return fakeFileInfo{name: "system", mode: os.ModeDir | 0o755}, nil
		},
		Lstat: func(path string) (os.FileInfo, error) {
			if path == "/usr/bin/docker" {
				return fakeFileInfo{name: "docker", mode: 0o755}, nil
			}
			return fakeFileInfo{name: "docker.sock", mode: os.ModeSocket | 0o660}, nil
		},
		Run: commandOutputs("29.6.1\t1.55\n", "linux\taarch64\t2\n"),
	}
}

func fileReader(files map[string][]byte) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		value, ok := files[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return append([]byte(nil), value...), nil
	}
}

func commandOutputs(values ...string) func(context.Context, string, ...string) ([]byte, error) {
	index := 0
	return func(context.Context, string, ...string) ([]byte, error) {
		if index >= len(values) {
			return nil, errors.New("unexpected command")
		}
		value := values[index]
		index++
		return []byte(value), nil
	}
}
