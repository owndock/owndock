package biz

import (
	"path"
	"sort"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/owndock/owndock/internal/shared/runtimespec"
)

const (
	DefaultBuildCPUMilli        int64 = 2_000
	DefaultBuildMemoryBytes     int64 = 2 * 1024 * 1024 * 1024
	DefaultBuildDiskBytes       int64 = 10 * 1024 * 1024 * 1024
	DefaultBuildTimeoutSeconds  int64 = 30 * 60
	DefaultBuildConcurrency           = 1
	DefaultAutoCreateRelease          = true
	MaximumAutomaticDeployments       = 8
)

// AutomaticDeploymentRule is an explicit development delivery target copied
// into every Build snapshot. Presence means enabled; an empty list means that
// every Environment remains manual.
type AutomaticDeploymentRule struct {
	EnvironmentID   string
	RuntimeTargetID string
}

func normalizeAutomaticDeployments(values []AutomaticDeploymentRule) ([]AutomaticDeploymentRule, bool) {
	if len(values) > MaximumAutomaticDeployments {
		return nil, false
	}
	result := append([]AutomaticDeploymentRule(nil), values...)
	seen := make(map[string]struct{}, len(result))
	for index := range result {
		result[index].EnvironmentID = strings.TrimSpace(result[index].EnvironmentID)
		result[index].RuntimeTargetID = strings.TrimSpace(result[index].RuntimeTargetID)
		if !validIdentifier(result[index].EnvironmentID) || !validIdentifier(result[index].RuntimeTargetID) {
			return nil, false
		}
		key := result[index].EnvironmentID + "\x00" + result[index].RuntimeTargetID
		if _, duplicate := seen[key]; duplicate {
			return nil, false
		}
		seen[key] = struct{}{}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].EnvironmentID == result[j].EnvironmentID {
			return result[i].RuntimeTargetID < result[j].RuntimeTargetID
		}
		return result[i].EnvironmentID < result[j].EnvironmentID
	})
	return result, true
}

func cloneAutomaticDeployments(values []AutomaticDeploymentRule) []AutomaticDeploymentRule {
	return append([]AutomaticDeploymentRule(nil), values...)
}

type BuildPlatform string

const (
	BuildPlatformLinuxAMD64 BuildPlatform = "linux/amd64"
	BuildPlatformLinuxARM64 BuildPlatform = "linux/arm64"
)

func (p BuildPlatform) Valid() bool {
	return p == BuildPlatformLinuxAMD64 || p == BuildPlatformLinuxARM64
}

type BuildResources struct {
	CPUMilli    int64
	MemoryBytes int64
	DiskBytes   int64
}

func (r BuildResources) withDefaults() BuildResources {
	if r == (BuildResources{}) {
		return BuildResources{
			CPUMilli:    DefaultBuildCPUMilli,
			MemoryBytes: DefaultBuildMemoryBytes,
			DiskBytes:   DefaultBuildDiskBytes,
		}
	}
	return r
}

func (r BuildResources) valid() bool {
	return r.CPUMilli >= 100 && r.CPUMilli <= 16_000 &&
		r.MemoryBytes >= 128*1024*1024 && r.MemoryBytes <= 32*1024*1024*1024 &&
		r.DiskBytes >= 1024*1024*1024 && r.DiskBytes <= 200*1024*1024*1024
}

type BuildConfiguration struct {
	ID                   string
	ProjectID            string
	ApplicationID        string
	Name                 string
	SourceRepositoryID   string
	DockerfilePath       string
	ContextPath          string
	AllowedRefs          []string
	RegistryCredentialID string
	ImageRepository      string
	TargetPlatform       BuildPlatform
	Resources            BuildResources
	TimeoutSeconds       int64
	MaxConcurrency       int
	AutoCreateRelease    bool
	ReleaseRuntimeSpec   runtimespec.Spec
	AutomaticDeployments []AutomaticDeploymentRule
	Version              uint64
	CreatedBy            string
	UpdatedBy            string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type BuildConfigurationPatch struct {
	Name                 *string
	SourceRepositoryID   *string
	DockerfilePath       *string
	ContextPath          *string
	AllowedRefs          *[]string
	RegistryCredentialID *string
	ImageRepository      *string
	TargetPlatform       *BuildPlatform
	Resources            *BuildResources
	TimeoutSeconds       *int64
	MaxConcurrency       *int
	AutoCreateRelease    *bool
	ReleaseRuntimeSpec   *runtimespec.Spec
	AutomaticDeployments *[]AutomaticDeploymentRule
}

func (p BuildConfigurationPatch) Empty() bool {
	return p.Name == nil && p.SourceRepositoryID == nil &&
		p.DockerfilePath == nil && p.ContextPath == nil && p.AllowedRefs == nil &&
		p.RegistryCredentialID == nil && p.ImageRepository == nil &&
		p.TargetPlatform == nil && p.Resources == nil && p.TimeoutSeconds == nil &&
		p.MaxConcurrency == nil && p.AutoCreateRelease == nil && p.ReleaseRuntimeSpec == nil &&
		p.AutomaticDeployments == nil
}

func NewBuildConfiguration(
	id, projectID, applicationID, name, sourceRepositoryID,
	dockerfilePath, contextPath string,
	allowedRefs []string,
	registryCredentialID, imageRepository string,
	targetPlatform BuildPlatform,
	resources BuildResources,
	timeoutSeconds int64,
	maxConcurrency int,
	autoCreateRelease bool,
	createdBy string,
	now time.Time,
) (BuildConfiguration, error) {
	return NewBuildConfigurationWithReleaseSpec(
		id, projectID, applicationID, name, sourceRepositoryID,
		dockerfilePath, contextPath, allowedRefs, registryCredentialID,
		imageRepository, targetPlatform, resources, timeoutSeconds,
		maxConcurrency, autoCreateRelease, runtimespec.Spec{}, createdBy, now,
	)
}

func NewBuildConfigurationWithReleaseSpec(
	id, projectID, applicationID, name, sourceRepositoryID,
	dockerfilePath, contextPath string,
	allowedRefs []string,
	registryCredentialID, imageRepository string,
	targetPlatform BuildPlatform,
	resources BuildResources,
	timeoutSeconds int64,
	maxConcurrency int,
	autoCreateRelease bool,
	releaseRuntimeSpec runtimespec.Spec,
	createdBy string,
	now time.Time,
) (BuildConfiguration, error) {
	return NewBuildConfigurationWithDeliverySpec(
		id, projectID, applicationID, name, sourceRepositoryID,
		dockerfilePath, contextPath, allowedRefs, registryCredentialID,
		imageRepository, targetPlatform, resources, timeoutSeconds,
		maxConcurrency, autoCreateRelease, releaseRuntimeSpec, nil, createdBy, now,
	)
}

func NewBuildConfigurationWithDeliverySpec(
	id, projectID, applicationID, name, sourceRepositoryID,
	dockerfilePath, contextPath string,
	allowedRefs []string,
	registryCredentialID, imageRepository string,
	targetPlatform BuildPlatform,
	resources BuildResources,
	timeoutSeconds int64,
	maxConcurrency int,
	autoCreateRelease bool,
	releaseRuntimeSpec runtimespec.Spec,
	automaticDeployments []AutomaticDeploymentRule,
	createdBy string,
	now time.Time,
) (BuildConfiguration, error) {
	if strings.TrimSpace(dockerfilePath) == "" {
		dockerfilePath = "Dockerfile"
	}
	if strings.TrimSpace(contextPath) == "" {
		contextPath = "."
	}
	if targetPlatform == "" {
		targetPlatform = BuildPlatformLinuxAMD64
	}
	resources = resources.withDefaults()
	if timeoutSeconds == 0 {
		timeoutSeconds = DefaultBuildTimeoutSeconds
	}
	if maxConcurrency == 0 {
		maxConcurrency = DefaultBuildConcurrency
	}
	item := BuildConfiguration{
		ID: id, ProjectID: projectID, ApplicationID: applicationID,
		Name: name, SourceRepositoryID: sourceRepositoryID,
		DockerfilePath: dockerfilePath, ContextPath: contextPath,
		AllowedRefs: allowedRefs, RegistryCredentialID: registryCredentialID,
		ImageRepository: imageRepository, TargetPlatform: targetPlatform,
		Resources: resources, TimeoutSeconds: timeoutSeconds,
		MaxConcurrency: maxConcurrency, AutoCreateRelease: autoCreateRelease,
		ReleaseRuntimeSpec:   releaseRuntimeSpec,
		AutomaticDeployments: cloneAutomaticDeployments(automaticDeployments),
		Version:              1, CreatedBy: createdBy, UpdatedBy: createdBy,
		CreatedAt: now, UpdatedAt: now,
	}
	return normalizeBuildConfiguration(item)
}

func (c BuildConfiguration) Apply(
	patch BuildConfigurationPatch,
	updatedBy string,
	now time.Time,
) (BuildConfiguration, error) {
	if patch.Name != nil {
		c.Name = *patch.Name
	}
	if patch.SourceRepositoryID != nil {
		c.SourceRepositoryID = *patch.SourceRepositoryID
	}
	if patch.DockerfilePath != nil {
		c.DockerfilePath = *patch.DockerfilePath
	}
	if patch.ContextPath != nil {
		c.ContextPath = *patch.ContextPath
	}
	if patch.AllowedRefs != nil {
		c.AllowedRefs = *patch.AllowedRefs
	}
	if patch.RegistryCredentialID != nil {
		c.RegistryCredentialID = *patch.RegistryCredentialID
	}
	if patch.ImageRepository != nil {
		c.ImageRepository = *patch.ImageRepository
	}
	if patch.TargetPlatform != nil {
		c.TargetPlatform = *patch.TargetPlatform
	}
	if patch.Resources != nil {
		c.Resources = *patch.Resources
	}
	if patch.TimeoutSeconds != nil {
		c.TimeoutSeconds = *patch.TimeoutSeconds
	}
	if patch.MaxConcurrency != nil {
		c.MaxConcurrency = *patch.MaxConcurrency
	}
	if patch.AutoCreateRelease != nil {
		c.AutoCreateRelease = *patch.AutoCreateRelease
	}
	if patch.ReleaseRuntimeSpec != nil {
		c.ReleaseRuntimeSpec = *patch.ReleaseRuntimeSpec
	}
	if patch.AutomaticDeployments != nil {
		c.AutomaticDeployments = cloneAutomaticDeployments(*patch.AutomaticDeployments)
	}
	c.UpdatedBy = updatedBy
	c.UpdatedAt = now
	c.Version++
	return normalizeBuildConfiguration(c)
}

func normalizeBuildConfiguration(item BuildConfiguration) (BuildConfiguration, error) {
	item.ID = strings.TrimSpace(item.ID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.ApplicationID = strings.TrimSpace(item.ApplicationID)
	item.Name = strings.TrimSpace(item.Name)
	item.SourceRepositoryID = strings.TrimSpace(item.SourceRepositoryID)
	item.RegistryCredentialID = strings.TrimSpace(item.RegistryCredentialID)
	item.CreatedBy = strings.TrimSpace(item.CreatedBy)
	item.UpdatedBy = strings.TrimSpace(item.UpdatedBy)
	if !validIdentifier(item.ID) || !validIdentifier(item.ProjectID) ||
		!validIdentifier(item.ApplicationID) || !validIdentifier(item.SourceRepositoryID) ||
		!validIdentifier(item.RegistryCredentialID) || !validIdentifier(item.CreatedBy) ||
		!validIdentifier(item.UpdatedBy) || !validName(item.Name) ||
		item.Version == 0 || item.CreatedAt.IsZero() || item.UpdatedAt.IsZero() {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	var ok bool
	item.ContextPath, ok = safeRepositoryPath(item.ContextPath, true)
	if !ok {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	item.DockerfilePath, ok = safeRepositoryPath(item.DockerfilePath, false)
	if !ok || !pathWithinContext(item.ContextPath, item.DockerfilePath) {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	item.AllowedRefs, ok = normalizeAllowedRefs(item.AllowedRefs)
	if !ok {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	item.ImageRepository, ok = normalizeImageRepository(item.ImageRepository)
	if !ok {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	if !item.TargetPlatform.Valid() || !item.Resources.valid() ||
		item.TimeoutSeconds < 60 || item.TimeoutSeconds > 2*60*60 ||
		item.MaxConcurrency < 1 || item.MaxConcurrency > 4 {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	automaticDeployments, ok := normalizeAutomaticDeployments(item.AutomaticDeployments)
	if !ok || (len(automaticDeployments) > 0 && !item.AutoCreateRelease) {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	item.AutomaticDeployments = automaticDeployments
	releaseRuntimeSpec, err := runtimespec.Normalize(item.ReleaseRuntimeSpec)
	if err != nil {
		return BuildConfiguration{}, ErrInvalidBuildConfiguration
	}
	item.ReleaseRuntimeSpec = releaseRuntimeSpec
	item.CreatedAt = item.CreatedAt.UTC()
	item.UpdatedAt = item.UpdatedAt.UTC()
	return item, nil
}

func safeRepositoryPath(value string, allowRoot bool) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" && allowRoot {
		value = "."
	}
	if value == "" || len(value) > 255 || strings.Contains(value, "\\") ||
		strings.ContainsRune(value, 0) || path.IsAbs(value) {
		return "", false
	}
	cleaned := path.Clean(value)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") ||
		(!allowRoot && cleaned == ".") {
		return "", false
	}
	return cleaned, cleaned == value || value == ""
}

func pathWithinContext(contextPath, filePath string) bool {
	return contextPath == "." || filePath == contextPath || strings.HasPrefix(filePath, contextPath+"/")
}

func normalizeAllowedRefs(values []string) ([]string, bool) {
	if len(values) == 0 || len(values) > 32 {
		return nil, false
	}
	unique := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		var short string
		switch {
		case strings.HasPrefix(value, "refs/heads/"):
			short = strings.TrimPrefix(value, "refs/heads/")
		case strings.HasPrefix(value, "refs/tags/"):
			short = strings.TrimPrefix(value, "refs/tags/")
		default:
			return nil, false
		}
		if !validGitBranch(short) {
			return nil, false
		}
		if _, found := unique[value]; found {
			return nil, false
		}
		unique[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, true
}

func normalizeImageRepository(value string) (string, bool) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(value))
	if err != nil || !reference.IsNameOnly(named) {
		return "", false
	}
	return strings.ToLower(named.Name()), true
}

func ImageRepositoryRegistry(value string) (string, error) {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(value))
	if err != nil || !reference.IsNameOnly(named) {
		return "", ErrInvalidBuildConfiguration
	}
	return strings.ToLower(reference.Domain(named)), nil
}
