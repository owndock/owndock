package biz

import (
	"context"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/shared/secretref"
)

type WebhookProvider string

const (
	WebhookProviderGitHub  WebhookProvider = "github"
	WebhookProviderGitLab  WebhookProvider = "gitlab"
	WebhookProviderGitea   WebhookProvider = "gitea"
	WebhookProviderForgejo WebhookProvider = "forgejo"
)

func (p WebhookProvider) Valid() bool {
	return p == WebhookProviderGitHub || p == WebhookProviderGitLab ||
		p == WebhookProviderGitea || p == WebhookProviderForgejo
}

type BuildHookStatus string

const (
	BuildHookStatusActive  BuildHookStatus = "active"
	BuildHookStatusRevoked BuildHookStatus = "revoked"
)

type BuildHook struct {
	ID, OrganizationID, ProjectID, ApplicationID, BuildConfigurationID string
	Name                                                               string
	Provider                                                           WebhookProvider
	AllowedRefs                                                        []string
	SecretRef                                                          string
	Status                                                             BuildHookStatus
	Version                                                            uint64
	CreatedBy                                                          string
	CreatedAt                                                          time.Time
	RevokedBy                                                          string
	RevokedAt                                                          time.Time
}

type BuildHookSummary struct {
	ID, ProjectID, ApplicationID, BuildConfigurationID string
	Name                                               string
	Provider                                           WebhookProvider
	AllowedRefs                                        []string
	SecretConfigured                                   bool
	Status                                             BuildHookStatus
	Version                                            uint64
	CreatedBy                                          string
	CreatedAt                                          time.Time
	RevokedBy                                          string
	RevokedAt                                          time.Time
}

func (h BuildHook) Summary() BuildHookSummary {
	return BuildHookSummary{
		ID: h.ID, ProjectID: h.ProjectID, ApplicationID: h.ApplicationID,
		BuildConfigurationID: h.BuildConfigurationID, Name: h.Name,
		Provider: h.Provider, AllowedRefs: append([]string(nil), h.AllowedRefs...),
		SecretConfigured: h.SecretRef != "", Status: h.Status, Version: h.Version,
		CreatedBy: h.CreatedBy, CreatedAt: h.CreatedAt, RevokedBy: h.RevokedBy, RevokedAt: h.RevokedAt,
	}
}

func NewBuildHook(
	id, organizationID, projectID, applicationID, configurationID, name string,
	provider WebhookProvider, allowedRefs []string, secretReference, createdBy string, now time.Time,
) (BuildHook, error) {
	name, secretReference = strings.TrimSpace(name), strings.TrimSpace(secretReference)
	refs, refsOK := normalizeAllowedRefs(allowedRefs)
	if !validIdentifier(strings.TrimSpace(id)) || !validIdentifier(strings.TrimSpace(organizationID)) ||
		!validIdentifier(strings.TrimSpace(projectID)) || !validIdentifier(strings.TrimSpace(applicationID)) ||
		!validIdentifier(strings.TrimSpace(configurationID)) || !validIdentifier(strings.TrimSpace(createdBy)) ||
		len(name) < 2 || len(name) > 80 || !provider.Valid() || !refsOK || now.IsZero() {
		return BuildHook{}, ErrInvalidBuildHook
	}
	if _, err := secretref.Alias(secretReference); err != nil {
		return BuildHook{}, ErrInvalidBuildHook
	}
	return BuildHook{
		ID: strings.TrimSpace(id), OrganizationID: strings.TrimSpace(organizationID),
		ProjectID: strings.TrimSpace(projectID), ApplicationID: strings.TrimSpace(applicationID),
		BuildConfigurationID: strings.TrimSpace(configurationID), Name: name, Provider: provider,
		AllowedRefs: refs, SecretRef: secretReference, Status: BuildHookStatusActive,
		Version: 1, CreatedBy: strings.TrimSpace(createdBy), CreatedAt: now.UTC(),
	}, nil
}

func (h BuildHook) AllowsRef(ref string) bool {
	return h.Status == BuildHookStatusActive && containsString(h.AllowedRefs, strings.TrimSpace(ref))
}

func (h BuildHook) Revoke(userID string, now time.Time) (BuildHook, error) {
	userID = strings.TrimSpace(userID)
	if h.Status != BuildHookStatusActive || !validIdentifier(userID) || now.IsZero() {
		return BuildHook{}, ErrInvalidBuildHook
	}
	h.Status, h.Version = BuildHookStatusRevoked, h.Version+1
	h.RevokedBy, h.RevokedAt = userID, now.UTC()
	return h, nil
}

type WebhookEnvelope struct {
	DeliveryID string
	Event      string
	Signature  string
	Timestamp  string
	Body       []byte
}

type WebhookEvent struct {
	Supported bool
	Ref       string
	CommitSHA string
}

type WebhookVerifier interface {
	VerifyAndParse(context.Context, BuildHook, WebhookEnvelope) (WebhookEvent, error)
}

type WebhookDeliveryStatus string

const (
	WebhookDeliveryStatusAccepted WebhookDeliveryStatus = "accepted"
	WebhookDeliveryStatusIgnored  WebhookDeliveryStatus = "ignored"
)

type WebhookDelivery struct {
	ID, OrganizationID, ProjectID, HookID string
	Provider                              WebhookProvider
	DeliveryID, Event, Ref, CommitSHA     string
	Status                                WebhookDeliveryStatus
	BuildID                               string
	CreatedAt                             time.Time
}

type WebhookReceipt struct {
	Status  WebhookDeliveryStatus
	BuildID string
}
