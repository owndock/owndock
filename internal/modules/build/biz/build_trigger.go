package biz

import (
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"
)

type BuildTriggerStatus string

const (
	BuildTriggerStatusActive  BuildTriggerStatus = "active"
	BuildTriggerStatusRevoked BuildTriggerStatus = "revoked"
)

// BuildTrigger is an automation credential bound to one Build Configuration.
// TokenHash is internal-only and must never be returned by an API.
type BuildTrigger struct {
	ID                   string
	OrganizationID       string
	ProjectID            string
	ApplicationID        string
	BuildConfigurationID string
	Name                 string
	AllowedRefs          []string
	TokenHash            string
	Status               BuildTriggerStatus
	Version              uint64
	CreatedBy            string
	CreatedAt            time.Time
	RevokedBy            string
	RevokedAt            time.Time
}

type BuildTriggerCredential struct {
	Trigger BuildTrigger
	Token   string
}

type BuildTriggerTokens interface {
	New() (raw string, hash string, err error)
	Hash(raw string) string
}

func NewBuildTrigger(
	id, organizationID, projectID, applicationID, configurationID, name string,
	allowedRefs []string, tokenHash, createdBy string, now time.Time,
) (BuildTrigger, error) {
	name = strings.TrimSpace(name)
	tokenHash = strings.ToLower(strings.TrimSpace(tokenHash))
	refs, refsOK := normalizeAllowedRefs(allowedRefs)
	if !validIdentifier(strings.TrimSpace(id)) ||
		!validIdentifier(strings.TrimSpace(organizationID)) ||
		!validIdentifier(strings.TrimSpace(projectID)) ||
		!validIdentifier(strings.TrimSpace(applicationID)) ||
		!validIdentifier(strings.TrimSpace(configurationID)) ||
		!validIdentifier(strings.TrimSpace(createdBy)) ||
		len(name) < 2 || len(name) > 80 || !refsOK || len(tokenHash) != 64 ||
		now.IsZero() {
		return BuildTrigger{}, ErrInvalidBuildTrigger
	}
	if _, err := hex.DecodeString(tokenHash); err != nil {
		return BuildTrigger{}, ErrInvalidBuildTrigger
	}
	return BuildTrigger{
		ID: strings.TrimSpace(id), OrganizationID: strings.TrimSpace(organizationID),
		ProjectID: strings.TrimSpace(projectID), ApplicationID: strings.TrimSpace(applicationID),
		BuildConfigurationID: strings.TrimSpace(configurationID), Name: name,
		AllowedRefs: refs, TokenHash: tokenHash, Status: BuildTriggerStatusActive,
		Version: 1, CreatedBy: strings.TrimSpace(createdBy), CreatedAt: now.UTC(),
	}, nil
}

func (t BuildTrigger) AllowsRef(ref string) bool {
	return t.Status == BuildTriggerStatusActive && containsString(t.AllowedRefs, strings.TrimSpace(ref))
}

func (t BuildTrigger) MatchesToken(hash string) bool {
	expected, expectedErr := hex.DecodeString(t.TokenHash)
	actual, actualErr := hex.DecodeString(strings.ToLower(strings.TrimSpace(hash)))
	return expectedErr == nil && actualErr == nil && len(expected) == 32 && len(actual) == 32 &&
		subtle.ConstantTimeCompare(expected, actual) == 1
}

func (t BuildTrigger) Revoke(userID string, now time.Time) (BuildTrigger, error) {
	userID = strings.TrimSpace(userID)
	if t.Status != BuildTriggerStatusActive || !validIdentifier(userID) || now.IsZero() {
		return BuildTrigger{}, ErrInvalidBuildTrigger
	}
	t.Status = BuildTriggerStatusRevoked
	t.Version++
	t.RevokedBy = userID
	t.RevokedAt = now.UTC()
	return t, nil
}
