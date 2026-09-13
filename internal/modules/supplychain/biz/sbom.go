package biz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/registryauth"
)

const (
	CycloneDXJSONMediaType = "application/vnd.cyclonedx+json"
	CycloneDXVersion16     = "1.6"
)

var (
	ErrSBOMGeneration    = errors.New("SBOM generation failed")
	ErrSBOMTooLarge      = errors.New("SBOM exceeds the configured size limit")
	ErrSBOMImageTooLarge = errors.New("SBOM image layer exceeds the configured size limit")
	ErrInvalidSBOM       = errors.New("generated SBOM is invalid")
	ErrGeneratorVersion  = errors.New("SBOM generator version is not allowed")
)

type SBOMRequest struct {
	ProjectID            string
	RegistryCredentialID string
	RegistryRepository   string
	SubjectDigest        string
	FormatVersion        string
}

func (r SBOMRequest) Validate() error {
	if !validID(strings.TrimSpace(r.ProjectID)) || !validID(strings.TrimSpace(r.RegistryCredentialID)) ||
		!validRepository(strings.TrimSpace(r.RegistryRepository)) ||
		!validDigest(strings.TrimSpace(r.SubjectDigest)) || r.FormatVersion != CycloneDXVersion16 {
		return ErrInvalidEvidenceJob
	}
	return nil
}

func (r SBOMRequest) CanonicalSubject() string {
	return strings.TrimSpace(r.RegistryRepository) + "@" + strings.TrimSpace(r.SubjectDigest)
}

type SBOMDocument struct {
	Content       []byte
	MediaType     string
	FormatVersion string
	ContentDigest string
}

func NewCycloneDX16Document(content []byte, maximumBytes int64) (SBOMDocument, error) {
	if maximumBytes <= 0 || int64(len(content)) > maximumBytes {
		return SBOMDocument{}, ErrSBOMTooLarge
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(content, &header); err != nil || len(header) > 128 {
		return SBOMDocument{}, ErrInvalidSBOM
	}
	var bomFormat, specVersion string
	var version uint64
	var components []json.RawMessage
	if json.Unmarshal(header["bomFormat"], &bomFormat) != nil ||
		json.Unmarshal(header["specVersion"], &specVersion) != nil ||
		json.Unmarshal(header["version"], &version) != nil ||
		bomFormat != "CycloneDX" || specVersion != CycloneDXVersion16 || version == 0 {
		return SBOMDocument{}, ErrInvalidSBOM
	}
	if raw, found := header["components"]; found && json.Unmarshal(raw, &components) != nil || len(components) > 100000 {
		return SBOMDocument{}, ErrInvalidSBOM
	}
	for _, component := range components {
		var identity map[string]json.RawMessage
		var componentType, name string
		if err := json.Unmarshal(component, &identity); err != nil || len(identity) > 128 ||
			json.Unmarshal(identity["type"], &componentType) != nil ||
			json.Unmarshal(identity["name"], &name) != nil ||
			!validText(strings.TrimSpace(componentType), 64) || !validText(strings.TrimSpace(name), 1024) {
			return SBOMDocument{}, ErrInvalidSBOM
		}
	}
	digest := sha256.Sum256(content)
	return SBOMDocument{
		Content: append([]byte(nil), content...), MediaType: CycloneDXJSONMediaType,
		FormatVersion: CycloneDXVersion16,
		ContentDigest: "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

type SBOMGenerator interface {
	GenerateSBOM(context.Context, SBOMRequest) (SBOMDocument, error)
}

type SBOMPublication struct {
	ProjectID            string
	RegistryCredentialID string
	RegistryRepository   string
	SubjectDigest        string
	Document             SBOMDocument
	CreatedAt            time.Time
}

type PublishedDescriptor struct {
	Digest    string
	MediaType string
}

type SBOMPublisher interface {
	PublishSBOM(context.Context, SBOMPublication) (PublishedDescriptor, error)
}

type RegistryCredential struct {
	AuthenticationMode registryauth.Mode
	Username           string
	Password           []byte
}

type RegistryCredentialProvider interface {
	ResolveRegistryCredential(context.Context, string, string, string) (RegistryCredential, error)
}
