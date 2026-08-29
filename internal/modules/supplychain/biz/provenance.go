package biz

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	InTotoStatementV1             = "https://in-toto.io/Statement/v1"
	SLSAProvenancePredicateV1     = "https://slsa.dev/provenance/v1"
	SLSAProvenanceMediaType       = "application/vnd.in-toto+json"
	SLSAProvenanceFormatVersion   = "1"
	OwnDockDockerfileBuildTypeV1  = "https://owndock.net/build-types/dockerfile/v1"
	OwnDockBuildKitBuilderIDV1    = "https://owndock.net/builders/buildkit/v1"
	MaximumProvenanceDocumentSize = int64(4 * 1024 * 1024)
)

var (
	ErrProvenanceGeneration = errors.New("provenance generation failed")
	ErrProvenanceTooLarge   = errors.New("provenance exceeds the configured size limit")
	ErrInvalidProvenance    = errors.New("generated provenance is invalid")
	gitCommitPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ProvenanceRecipe is the immutable, secret-free input captured when a Build
// publishes its Artifact. Evidence Workers must not query mutable Build or
// Source Repository state while generating provenance.
type ProvenanceRecipe struct {
	BuildID              string
	ApplicationID        string
	SourceURI            string
	SourceRef            string
	CommitSHA            string
	ConfigurationID      string
	ConfigurationVersion uint64
	DockerfilePath       string
	ContextPath          string
	TargetPlatform       string
	CPUMilli             int64
	MemoryBytes          int64
	DiskBytes            int64
	TimeoutSeconds       int64
	BuilderID            string
	BuilderVersion       string
	BuilderCommit        string
	BuildKitVersion      string
	BuildKitImage        string
	FrontendImage        string
	StartedAt            time.Time
	FinishedAt           time.Time
}

func (r ProvenanceRecipe) Empty() bool { return r == (ProvenanceRecipe{}) }

func (r ProvenanceRecipe) Validate() error {
	if !validID(strings.TrimSpace(r.BuildID)) || !validID(strings.TrimSpace(r.ApplicationID)) ||
		!validProvenanceURI(r.SourceURI, "git+https", "git+ssh") ||
		!validText(strings.TrimSpace(r.SourceRef), 512) || !gitCommitPattern.MatchString(r.CommitSHA) ||
		!validID(strings.TrimSpace(r.ConfigurationID)) || r.ConfigurationVersion == 0 ||
		!validRelativeBuildPath(r.DockerfilePath, false) || !validRelativeBuildPath(r.ContextPath, true) ||
		(r.TargetPlatform != "linux/amd64" && r.TargetPlatform != "linux/arm64") ||
		r.CPUMilli < 100 || r.CPUMilli > 16000 ||
		r.MemoryBytes < 128*1024*1024 || r.MemoryBytes > 32*1024*1024*1024 ||
		r.DiskBytes < 1024*1024*1024 || r.DiskBytes > 200*1024*1024*1024 ||
		r.TimeoutSeconds < 60 || r.TimeoutSeconds > 2*60*60 ||
		r.BuilderID != OwnDockBuildKitBuilderIDV1 ||
		!validText(strings.TrimSpace(r.BuilderVersion), 128) ||
		!validText(strings.TrimSpace(r.BuilderCommit), 128) ||
		!validText(strings.TrimSpace(r.BuildKitVersion), 128) ||
		!validDigestPinnedImage(r.BuildKitImage) || !validDigestPinnedImage(r.FrontendImage) ||
		r.StartedAt.IsZero() || r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
		return ErrInvalidEvidenceJob
	}
	return nil
}

type ProvenanceRequest struct {
	RegistryRepository string
	SubjectDigest      string
	Recipe             ProvenanceRecipe
}

func (r ProvenanceRequest) Validate() error {
	if !validRepository(strings.TrimSpace(r.RegistryRepository)) ||
		!validDigest(strings.TrimSpace(r.SubjectDigest)) || r.Recipe.Validate() != nil {
		return ErrInvalidEvidenceJob
	}
	return nil
}

type ProvenanceDocument struct {
	Content       []byte
	MediaType     string
	FormatVersion string
	PredicateType string
	ContentDigest string
}

type ProvenanceGenerator interface {
	GenerateProvenance(context.Context, ProvenanceRequest) (ProvenanceDocument, error)
}

type ProvenancePublication struct {
	ProjectID            string
	RegistryCredentialID string
	RegistryRepository   string
	SubjectDigest        string
	Document             ProvenanceDocument
	CreatedAt            time.Time
}

type ProvenancePublisher interface {
	PublishProvenance(context.Context, ProvenancePublication) (PublishedDescriptor, error)
}

func validProvenanceURI(value string, schemes ...string) bool {
	if len(value) == 0 || len(value) > 2048 || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	for _, scheme := range schemes {
		if parsed.Scheme == scheme {
			return true
		}
	}
	return false
}

func validRelativeBuildPath(value string, allowDot bool) bool {
	if value == "." {
		return allowDot
	}
	return value != "" && len(value) <= 1024 && strings.TrimSpace(value) == value &&
		!strings.HasPrefix(value, "/") && !strings.Contains(value, "..") &&
		!strings.ContainsAny(value, "\\\x00\r\n")
}

func validDigestPinnedImage(value string) bool {
	marker := "@sha256:"
	index := strings.LastIndex(value, marker)
	if index <= 0 || len(value[index+len(marker):]) != 64 {
		return false
	}
	_, err := hex.DecodeString(value[index+len(marker):])
	return err == nil
}
