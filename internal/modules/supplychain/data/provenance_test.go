package data

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

func provenanceRequestFixture() biz.ProvenanceRequest {
	return biz.ProvenanceRequest{
		RegistryRepository: "registry.example.com/team/api",
		SubjectDigest:      "sha256:" + strings.Repeat("a", 64),
		Recipe: biz.ProvenanceRecipe{
			BuildID: "build-1", ApplicationID: "application-1",
			SourceURI: "git+https://git.example.com/team/api.git",
			SourceRef: "refs/heads/main", CommitSHA: strings.Repeat("b", 40),
			ConfigurationID: "configuration-1", ConfigurationVersion: 7,
			DockerfilePath: "deploy/Dockerfile", ContextPath: ".", TargetPlatform: "linux/amd64",
			CPUMilli: 2000, MemoryBytes: 2 * 1024 * 1024 * 1024,
			DiskBytes: 10 * 1024 * 1024 * 1024, TimeoutSeconds: 1800,
			BuilderID:      biz.OwnDockBuildKitBuilderIDV1,
			BuilderVersion: "0.1.0", BuilderCommit: strings.Repeat("c", 40),
			BuildKitVersion: "v0.31.2",
			BuildKitImage:   "moby/buildkit:v0.31.2-rootless@sha256:" + strings.Repeat("d", 64),
			FrontendImage:   "docker/dockerfile:1.25.0@sha256:" + strings.Repeat("e", 64),
			StartedAt:       time.Unix(100, 0).UTC(), FinishedAt: time.Unix(200, 0).UTC(),
		},
	}
}

func TestSLSAProvenanceGeneratorCreatesDeterministicDigestBoundStatement(t *testing.T) {
	generator, err := NewSLSAProvenanceGenerator(64 * 1024)
	if err != nil {
		t.Fatal(err)
	}
	request := provenanceRequestFixture()
	first, err := generator.GenerateProvenance(t.Context(), request)
	if err != nil {
		t.Fatalf("GenerateProvenance() error = %v", err)
	}
	second, err := generator.GenerateProvenance(t.Context(), request)
	if err != nil || !bytes.Equal(first.Content, second.Content) || first.ContentDigest != second.ContentDigest {
		t.Fatalf("provenance is not deterministic: %v", err)
	}
	if first.MediaType != biz.SLSAProvenanceMediaType ||
		first.PredicateType != biz.SLSAProvenancePredicateV1 ||
		first.FormatVersion != biz.SLSAProvenanceFormatVersion {
		t.Fatalf("document metadata = %+v", first)
	}
	var statement map[string]any
	if err := json.Unmarshal(first.Content, &statement); err != nil {
		t.Fatal(err)
	}
	if statement["_type"] != biz.InTotoStatementV1 || statement["predicateType"] != biz.SLSAProvenancePredicateV1 {
		t.Fatalf("statement envelope = %#v", statement)
	}
	predicate := statement["predicate"].(map[string]any)
	definition := predicate["buildDefinition"].(map[string]any)
	dependencies := definition["resolvedDependencies"].([]any)
	dependency := dependencies[0].(map[string]any)
	if dependency["digest"].(map[string]any)["gitCommit"] != request.Recipe.CommitSHA {
		t.Fatalf("resolved source = %#v", dependency)
	}
	runDetails := predicate["runDetails"].(map[string]any)
	if runDetails["builder"].(map[string]any)["id"] != biz.OwnDockBuildKitBuilderIDV1 ||
		runDetails["metadata"].(map[string]any)["invocationId"] != request.Recipe.BuildID {
		t.Fatalf("run details = %#v", runDetails)
	}
}

func TestSLSAProvenanceValidationFailsClosedOnTamperingAndBounds(t *testing.T) {
	generator, _ := NewSLSAProvenanceGenerator(64 * 1024)
	request := provenanceRequestFixture()
	document, _ := generator.GenerateProvenance(t.Context(), request)
	if _, err := NewSLSAProvenanceV1Document(document.Content, int64(len(document.Content)-1),
		request.RegistryRepository, request.SubjectDigest); !errors.Is(err, biz.ErrProvenanceTooLarge) {
		t.Fatalf("oversized error = %v", err)
	}
	for _, test := range []struct {
		name, old, replacement string
	}{
		{name: "subject", old: strings.Repeat("a", 64), replacement: strings.Repeat("f", 64)},
		{name: "commit", old: strings.Repeat("b", 40), replacement: "mutable-main-ref"},
		{name: "builder", old: biz.OwnDockBuildKitBuilderIDV1, replacement: "https://attacker.example/builder"},
		{name: "configuration digest", old: "build-configuration-snapshot", replacement: "changed-configuration-snapshot"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tampered := bytes.Replace(document.Content, []byte(test.old), []byte(test.replacement), 1)
			_, err := NewSLSAProvenanceV1Document(tampered, 64*1024,
				request.RegistryRepository, request.SubjectDigest)
			if !errors.Is(err, biz.ErrInvalidProvenance) {
				t.Fatalf("tampered statement error = %v", err)
			}
		})
	}
	if _, err := NewSLSAProvenanceV1Document(document.Content, 64*1024,
		"registry.example.com/other/api", request.SubjectDigest); !errors.Is(err, biz.ErrInvalidProvenance) {
		t.Fatalf("wrong subject name error = %v", err)
	}
}
