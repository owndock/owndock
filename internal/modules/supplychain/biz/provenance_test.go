package biz

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func provenanceRecipeFixture() ProvenanceRecipe {
	return ProvenanceRecipe{
		BuildID: "build-1", ApplicationID: "application-1",
		SourceURI: "git+https://git.example.com/team/api.git",
		SourceRef: "refs/heads/main", CommitSHA: strings.Repeat("b", 40),
		ConfigurationID: "configuration-1", ConfigurationVersion: 7,
		DockerfilePath: "deploy/Dockerfile", ContextPath: ".", TargetPlatform: "linux/amd64",
		CPUMilli: 2000, MemoryBytes: 2 * 1024 * 1024 * 1024,
		DiskBytes: 10 * 1024 * 1024 * 1024, TimeoutSeconds: 1800,
		BuilderID:      OwnDockBuildKitBuilderIDV1,
		BuilderVersion: "0.1.0", BuilderCommit: strings.Repeat("c", 40),
		BuildKitVersion: "v0.31.2",
		BuildKitImage:   "moby/buildkit:v0.31.2-rootless@sha256:" + strings.Repeat("d", 64),
		FrontendImage:   "docker/dockerfile:1.25.0@sha256:" + strings.Repeat("e", 64),
		StartedAt:       time.Unix(100, 0).UTC(), FinishedAt: time.Unix(200, 0).UTC(),
	}
}

func TestProvenanceRecipeRejectsMutableOrUnboundedInputs(t *testing.T) {
	valid := provenanceRecipeFixture()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid recipe = %v", err)
	}
	invalid := []ProvenanceRecipe{
		func() ProvenanceRecipe { item := valid; item.CommitSHA = "main"; return item }(),
		func() ProvenanceRecipe {
			item := valid
			item.SourceURI = "https://user:secret@git.example.com/api"
			return item
		}(),
		func() ProvenanceRecipe {
			item := valid
			item.SourceURI = "git+https://git.example.com/api?access_token=secret"
			return item
		}(),
		func() ProvenanceRecipe { item := valid; item.BuildKitImage = "moby/buildkit:latest"; return item }(),
		func() ProvenanceRecipe {
			item := valid
			item.FinishedAt = item.StartedAt.Add(-time.Second)
			return item
		}(),
	}
	for index, item := range invalid {
		if err := item.Validate(); !errors.Is(err, ErrInvalidEvidenceJob) {
			t.Errorf("invalid recipe %d error = %v", index, err)
		}
	}
}
