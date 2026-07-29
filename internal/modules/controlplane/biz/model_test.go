package biz

import (
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/shared/runtimeaccess"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

func TestNewReleaseRequiresSHA256Digest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	release, err := NewRelease(
		"release", "project", "application",
		"registry.example.com/team/app@sha256:"+digest,
		"user", time.Unix(1, 0),
	)
	if err != nil {
		t.Fatalf("NewRelease() error = %v", err)
	}
	if release.ImageDigest != "registry.example.com/team/app@sha256:"+digest {
		t.Fatalf("image digest = %q", release.ImageDigest)
	}
	if _, err := NewRelease("release", "project", "application", "registry.example.com/team/app:latest", "user", time.Now()); err != ErrInvalidImage {
		t.Fatalf("tag-only NewRelease() error = %v, want ErrInvalidImage", err)
	}
}

func TestNewRegistryCredentialAndReleaseRuntimeSpec(t *testing.T) {
	credential, err := NewRegistryCredential(
		"credential", "project", "Private registry", "REGISTRY.EXAMPLE.COM:5443",
		"robot", "secret://registry-password", "user", time.Unix(1, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Server != "registry.example.com:5443" {
		t.Fatalf("server = %q", credential.Server)
	}
	release, err := NewReleaseWithRuntimeSpec(
		"release", "project", "application",
		"registry.example.com:5443/team/api@sha256:"+strings.Repeat("a", 64),
		credential.ID,
		runtimespec.Spec{
			Ports:           []runtimespec.Port{{Name: "http", ContainerPort: 8080}},
			EnvironmentKeys: []string{"DATABASE_URL"},
			HealthCheck:     &runtimespec.HealthCheck{Command: []string{"/healthcheck"}},
		},
		"user", time.Unix(1, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if release.RuntimeSpec.Resources.CPUMilli != runtimespec.DefaultCPUMilli {
		t.Fatalf("runtime spec = %+v", release.RuntimeSpec)
	}
	for _, server := range []string{"https://registry.example.com", "registry.example.com/path", ""} {
		if _, err := NewRegistryCredential(
			"credential", "project", "Registry", server,
			"robot", "secret://password", "user", time.Now(),
		); err != ErrInvalidRegistry {
			t.Fatalf("server %q error = %v", server, err)
		}
	}
}

func TestNewRuntimeTargetRequiresTLSReference(t *testing.T) {
	target, err := NewRuntimeTarget(
		"target", "project", "production", "host",
		runtimeaccess.ModeDirectDocker,
		"tcp://docker.example.com:2376", "docker.example.com", "secret://project-docker",
		"user", time.Unix(1, 0),
	)
	if err != nil {
		t.Fatalf("NewRuntimeTarget() error = %v", err)
	}
	if target.Status != RuntimeTargetStatusPending {
		t.Fatalf("status = %s", target.Status)
	}
	for _, endpoint := range []string{
		"unix:///var/run/docker.sock",
		"tcp://user:password@docker.example.com:2376",
		"tcp://docker.example.com",
	} {
		if _, err := NewRuntimeTarget(
			"target", "project", "production", "host",
			runtimeaccess.ModeDirectDocker,
			endpoint, "docker.example.com", "secret", "user", time.Now(),
		); err != ErrInvalidRuntimeTarget {
			t.Errorf("endpoint %q error = %v, want ErrInvalidRuntimeTarget", endpoint, err)
		}
	}
	if _, err := NewRuntimeTarget(
		"target", "project", "production", "host",
		runtimeaccess.ModeDirectDocker, "tcp://docker.example.com:2376",
		"docker.example.com", "env://ARBITRARY_SECRET", "user", time.Now(),
	); err != ErrInvalidRuntimeTarget {
		t.Fatalf("arbitrary credential reference error = %v", err)
	}
}

func TestNewRuntimeTargetEnforcesConnectionModeFields(t *testing.T) {
	agent, err := NewRuntimeTarget(
		"target", "project", "production", "host",
		runtimeaccess.ModeAgent, "", "", "", "user", time.Unix(1, 0),
	)
	if err != nil || agent.ConnectionMode != runtimeaccess.ModeAgent {
		t.Fatalf("agent target = %+v, error = %v", agent, err)
	}
	if _, err := NewRuntimeTarget(
		"target", "project", "production", "host",
		runtimeaccess.ModeAgent, "tcp://docker.example.com:2376", "", "", "user", time.Now(),
	); err != ErrInvalidRuntimeTarget {
		t.Fatalf("agent target with direct endpoint error = %v", err)
	}
}

func TestNewEnvironmentRequiresKnownStage(t *testing.T) {
	item, err := NewEnvironment("env", "project", "Production", string(EnvironmentStageProduction), "user", time.Unix(1, 0))
	if err != nil {
		t.Fatalf("NewEnvironment() error = %v", err)
	}
	if item.Stage != string(EnvironmentStageProduction) {
		t.Fatalf("stage = %q", item.Stage)
	}
	for _, stage := range []string{"", "qa", "prod"} {
		if _, err := NewEnvironment("env", "project", "Production", stage, "user", time.Now()); err != ErrInvalidName {
			t.Errorf("stage %q error = %v, want ErrInvalidName", stage, err)
		}
	}
}

func TestNewEnvironmentValidatesVariables(t *testing.T) {
	item, err := NewEnvironmentWithVariables(
		"env", "project", "Production", string(EnvironmentStageProduction),
		map[string]string{"DATABASE_URL": "secret://database-url"},
		"user", time.Unix(1, 0),
	)
	if err != nil || item.Variables["DATABASE_URL"] == "" {
		t.Fatalf("environment = %+v, error = %v", item, err)
	}
	if _, err := NewEnvironmentWithVariables(
		"env", "project", "Production", string(EnvironmentStageProduction),
		map[string]string{"INVALID-NAME": "value"},
		"user", time.Now(),
	); err != ErrInvalidRuntimeSpec {
		t.Fatalf("invalid variables error = %v", err)
	}
}
