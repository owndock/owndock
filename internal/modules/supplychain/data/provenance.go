package data

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/supplychain/biz"
)

// SLSAProvenanceGenerator is a standard-format adapter. The immutable Recipe
// remains a domain value; JSON wire names and in-toto serialization stay in
// the data boundary rather than leaking transport tags into biz types.
type SLSAProvenanceGenerator struct {
	maximumBytes int64
}

func NewSLSAProvenanceGenerator(maximumBytes int64) (*SLSAProvenanceGenerator, error) {
	if maximumBytes < 1024 || maximumBytes > biz.MaximumProvenanceDocumentSize {
		return nil, biz.ErrInvalidEvidenceJob
	}
	return &SLSAProvenanceGenerator{maximumBytes: maximumBytes}, nil
}

func (g *SLSAProvenanceGenerator) GenerateProvenance(_ context.Context,
	request biz.ProvenanceRequest) (biz.ProvenanceDocument, error) {
	if g == nil || request.Validate() != nil {
		return biz.ProvenanceDocument{}, biz.ErrProvenanceGeneration
	}
	statement, err := provenanceStatementFromRequest(request)
	if err != nil {
		return biz.ProvenanceDocument{}, err
	}
	content, err := json.Marshal(statement)
	if err != nil {
		return biz.ProvenanceDocument{}, biz.ErrProvenanceGeneration
	}
	return NewSLSAProvenanceV1Document(content, g.maximumBytes,
		request.RegistryRepository, request.SubjectDigest)
}

// NewSLSAProvenanceV1Document verifies the standard statement envelope and
// exact Artifact subject before content is published or returned. Unknown
// extension fields remain allowed by in-toto parsing rules, while every
// security-relevant OwnDock build field is bounded and cross-checked.
func NewSLSAProvenanceV1Document(content []byte, maximumBytes int64,
	expectedSubjectName, expectedSubjectDigest string) (biz.ProvenanceDocument, error) {
	if maximumBytes <= 0 || int64(len(content)) > maximumBytes {
		return biz.ProvenanceDocument{}, biz.ErrProvenanceTooLarge
	}
	if !validRegistryPublicationIdentity(expectedSubjectName, expectedSubjectDigest) {
		return biz.ProvenanceDocument{}, biz.ErrInvalidProvenance
	}
	var statement provenanceStatement
	if err := json.Unmarshal(content, &statement); err != nil ||
		statement.Type != biz.InTotoStatementV1 ||
		statement.PredicateType != biz.SLSAProvenancePredicateV1 ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != expectedSubjectName ||
		statement.Subject[0].Digest.SHA256 != strings.TrimPrefix(expectedSubjectDigest, "sha256:") ||
		statement.Predicate.BuildDefinition.BuildType != biz.OwnDockDockerfileBuildTypeV1 ||
		statement.Predicate.RunDetails.Builder.ID != biz.OwnDockBuildKitBuilderIDV1 ||
		!validProvenanceStatementFields(statement) {
		return biz.ProvenanceDocument{}, biz.ErrInvalidProvenance
	}
	digest := sha256.Sum256(content)
	return biz.ProvenanceDocument{
		Content: append([]byte(nil), content...), MediaType: biz.SLSAProvenanceMediaType,
		FormatVersion: biz.SLSAProvenanceFormatVersion,
		PredicateType: biz.SLSAProvenancePredicateV1,
		ContentDigest: "sha256:" + hex.EncodeToString(digest[:]),
	}, nil
}

type provenanceStatement struct {
	Type          string              `json:"_type"`
	Subject       []provenanceSubject `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     provenancePredicate `json:"predicate"`
}

type provenanceSubject struct {
	Name   string           `json:"name"`
	Digest provenanceDigest `json:"digest"`
}

type provenanceDigest struct {
	SHA256    string `json:"sha256,omitempty"`
	GitCommit string `json:"gitCommit,omitempty"`
}

type provenanceResource struct {
	URI    string           `json:"uri"`
	Name   string           `json:"name,omitempty"`
	Digest provenanceDigest `json:"digest"`
}

type provenanceExternalParameters struct {
	Source             provenanceSourceParameter        `json:"source"`
	BuildConfiguration provenanceConfigurationParameter `json:"buildConfiguration"`
	Dockerfile         string                           `json:"dockerfile"`
	Context            string                           `json:"context"`
	Platform           string                           `json:"platform"`
}

type provenanceSourceParameter struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref"`
}

type provenanceConfigurationParameter struct {
	ID            string `json:"id"`
	Version       uint64 `json:"version"`
	ApplicationID string `json:"applicationId"`
}

type provenanceInternalParameters struct {
	Resources      provenanceResources `json:"resources"`
	TimeoutSeconds int64               `json:"timeoutSeconds"`
	BuildKitImage  string              `json:"buildKitImage"`
	FrontendImage  string              `json:"dockerfileFrontend"`
}

type provenanceResources struct {
	CPUMilli    int64 `json:"cpuMilli"`
	MemoryBytes int64 `json:"memoryBytes"`
	DiskBytes   int64 `json:"diskBytes"`
}

type provenanceBuildDefinition struct {
	BuildType            string                       `json:"buildType"`
	ExternalParameters   provenanceExternalParameters `json:"externalParameters"`
	InternalParameters   provenanceInternalParameters `json:"internalParameters"`
	ResolvedDependencies []provenanceResource         `json:"resolvedDependencies"`
}

type provenanceBuilder struct {
	ID                  string               `json:"id"`
	Version             map[string]string    `json:"version"`
	BuilderDependencies []provenanceResource `json:"builderDependencies"`
}

type provenanceMetadata struct {
	InvocationID string    `json:"invocationId"`
	StartedOn    time.Time `json:"startedOn"`
	FinishedOn   time.Time `json:"finishedOn"`
}

type provenanceRunDetails struct {
	Builder    provenanceBuilder    `json:"builder"`
	Metadata   provenanceMetadata   `json:"metadata"`
	Byproducts []provenanceResource `json:"byproducts"`
}

type provenancePredicate struct {
	BuildDefinition provenanceBuildDefinition `json:"buildDefinition"`
	RunDetails      provenanceRunDetails      `json:"runDetails"`
}

func provenanceStatementFromRequest(request biz.ProvenanceRequest) (provenanceStatement, error) {
	recipe := request.Recipe
	external := provenanceExternalParameters{
		Source: provenanceSourceParameter{Repository: recipe.SourceURI, Ref: recipe.SourceRef},
		BuildConfiguration: provenanceConfigurationParameter{
			ID: recipe.ConfigurationID, Version: recipe.ConfigurationVersion,
			ApplicationID: recipe.ApplicationID,
		},
		Dockerfile: recipe.DockerfilePath, Context: recipe.ContextPath, Platform: recipe.TargetPlatform,
	}
	internal := provenanceInternalParameters{
		Resources: provenanceResources{
			CPUMilli: recipe.CPUMilli, MemoryBytes: recipe.MemoryBytes, DiskBytes: recipe.DiskBytes,
		},
		TimeoutSeconds: recipe.TimeoutSeconds, BuildKitImage: recipe.BuildKitImage,
		FrontendImage: recipe.FrontendImage,
	}
	configurationDigest, err := provenanceConfigurationDigest(external, internal)
	if err != nil {
		return provenanceStatement{}, biz.ErrProvenanceGeneration
	}
	buildKitDigest, err := digestFromPinnedImage(recipe.BuildKitImage)
	if err != nil {
		return provenanceStatement{}, biz.ErrProvenanceGeneration
	}
	frontendDigest, err := digestFromPinnedImage(recipe.FrontendImage)
	if err != nil {
		return provenanceStatement{}, biz.ErrProvenanceGeneration
	}
	return provenanceStatement{
		Type: biz.InTotoStatementV1,
		Subject: []provenanceSubject{{Name: request.RegistryRepository,
			Digest: provenanceDigest{SHA256: strings.TrimPrefix(request.SubjectDigest, "sha256:")}}},
		PredicateType: biz.SLSAProvenancePredicateV1,
		Predicate: provenancePredicate{
			BuildDefinition: provenanceBuildDefinition{
				BuildType:          biz.OwnDockDockerfileBuildTypeV1,
				ExternalParameters: external, InternalParameters: internal,
				ResolvedDependencies: []provenanceResource{{
					URI:  recipe.SourceURI + "@" + recipe.SourceRef,
					Name: "source", Digest: provenanceDigest{GitCommit: recipe.CommitSHA},
				}},
			},
			RunDetails: provenanceRunDetails{
				Builder: provenanceBuilder{
					ID: recipe.BuilderID,
					Version: map[string]string{
						"owndock": recipe.BuilderVersion, "commit": recipe.BuilderCommit,
						"buildkit": recipe.BuildKitVersion,
					},
					BuilderDependencies: []provenanceResource{
						{URI: recipe.BuildKitImage, Name: "buildkit", Digest: provenanceDigest{SHA256: buildKitDigest}},
						{URI: recipe.FrontendImage, Name: "dockerfile-frontend", Digest: provenanceDigest{SHA256: frontendDigest}},
					},
				},
				Metadata: provenanceMetadata{
					InvocationID: recipe.BuildID, StartedOn: recipe.StartedAt.UTC(),
					FinishedOn: recipe.FinishedAt.UTC(),
				},
				Byproducts: []provenanceResource{{
					URI:    provenanceConfigurationURI(recipe.ConfigurationID, recipe.ConfigurationVersion),
					Name:   "build-configuration-snapshot",
					Digest: provenanceDigest{SHA256: configurationDigest},
				}},
			},
		},
	}, nil
}

func validProvenanceStatementFields(statement provenanceStatement) bool {
	definition := statement.Predicate.BuildDefinition
	external, internal := definition.ExternalParameters, definition.InternalParameters
	metadata, builder := statement.Predicate.RunDetails.Metadata, statement.Predicate.RunDetails.Builder
	if len(builder.Version) != 3 || len(builder.BuilderDependencies) != 2 ||
		len(definition.ResolvedDependencies) != 1 || len(statement.Predicate.RunDetails.Byproducts) != 1 {
		return false
	}
	dependency := definition.ResolvedDependencies[0]
	recipe := biz.ProvenanceRecipe{
		BuildID: metadata.InvocationID, ApplicationID: external.BuildConfiguration.ApplicationID,
		SourceURI: external.Source.Repository, SourceRef: external.Source.Ref,
		CommitSHA:            dependency.Digest.GitCommit,
		ConfigurationID:      external.BuildConfiguration.ID,
		ConfigurationVersion: external.BuildConfiguration.Version,
		DockerfilePath:       external.Dockerfile, ContextPath: external.Context,
		TargetPlatform: external.Platform,
		CPUMilli:       internal.Resources.CPUMilli, MemoryBytes: internal.Resources.MemoryBytes,
		DiskBytes: internal.Resources.DiskBytes, TimeoutSeconds: internal.TimeoutSeconds,
		BuilderID: builder.ID, BuilderVersion: builder.Version["owndock"],
		BuilderCommit: builder.Version["commit"], BuildKitVersion: builder.Version["buildkit"],
		BuildKitImage: internal.BuildKitImage, FrontendImage: internal.FrontendImage,
		StartedAt: metadata.StartedOn, FinishedAt: metadata.FinishedOn,
	}
	if recipe.Validate() != nil || dependency.URI != recipe.SourceURI+"@"+recipe.SourceRef ||
		dependency.Name != "source" || dependency.Digest.SHA256 != "" {
		return false
	}
	buildKitDigest, buildKitErr := digestFromPinnedImage(recipe.BuildKitImage)
	frontendDigest, frontendErr := digestFromPinnedImage(recipe.FrontendImage)
	if buildKitErr != nil || frontendErr != nil ||
		builder.BuilderDependencies[0].URI != recipe.BuildKitImage ||
		builder.BuilderDependencies[0].Name != "buildkit" ||
		builder.BuilderDependencies[0].Digest.SHA256 != buildKitDigest ||
		builder.BuilderDependencies[1].URI != recipe.FrontendImage ||
		builder.BuilderDependencies[1].Name != "dockerfile-frontend" ||
		builder.BuilderDependencies[1].Digest.SHA256 != frontendDigest {
		return false
	}
	configurationDigest, err := provenanceConfigurationDigest(external, internal)
	if err != nil {
		return false
	}
	byproduct := statement.Predicate.RunDetails.Byproducts[0]
	return byproduct.URI == provenanceConfigurationURI(
		recipe.ConfigurationID, recipe.ConfigurationVersion,
	) && byproduct.Name == "build-configuration-snapshot" &&
		byproduct.Digest.SHA256 == configurationDigest
}

func provenanceConfigurationDigest(external provenanceExternalParameters,
	internal provenanceInternalParameters) (string, error) {
	content, err := json.Marshal(struct {
		External provenanceExternalParameters `json:"externalParameters"`
		Internal provenanceInternalParameters `json:"internalParameters"`
	}{External: external, Internal: internal})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func digestFromPinnedImage(value string) (string, error) {
	marker := "@sha256:"
	index := strings.LastIndex(value, marker)
	if index <= 0 || len(value[index+len(marker):]) != 64 {
		return "", biz.ErrInvalidProvenance
	}
	hexDigest := value[index+len(marker):]
	if _, err := hex.DecodeString(hexDigest); err != nil {
		return "", biz.ErrInvalidProvenance
	}
	return hexDigest, nil
}

func provenanceConfigurationURI(id string, version uint64) string {
	return "https://owndock.net/build-configurations/" + id + "/versions/" + strconv.FormatUint(version, 10)
}
