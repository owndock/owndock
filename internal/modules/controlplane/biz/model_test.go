package biz

import (
	"strings"
	"testing"
	"time"
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

func TestNewRuntimeTargetRequiresTLSReference(t *testing.T) {
	target, err := NewRuntimeTarget(
		"target", "project", "production",
		"tcp://docker.example.com:2376", "docker.example.com", "secret://project/docker",
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
		if _, err := NewRuntimeTarget("target", "project", "production", endpoint, "docker.example.com", "secret", "user", time.Now()); err != ErrInvalidRuntimeTarget {
			t.Errorf("endpoint %q error = %v, want ErrInvalidRuntimeTarget", endpoint, err)
		}
	}
}
