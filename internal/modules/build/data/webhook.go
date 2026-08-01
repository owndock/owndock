package data

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
	"github.com/owndock/owndock/internal/shared/secretref"
)

type WebhookSecretResolver interface {
	ResolveWebhookSecret(context.Context, biz.BuildHook) ([]byte, error)
}

type EnvironmentWebhookSecretResolver struct{ lookup func(string) (string, bool) }

func NewEnvironmentWebhookSecretResolver() *EnvironmentWebhookSecretResolver {
	return &EnvironmentWebhookSecretResolver{lookup: os.LookupEnv}
}

func (r *EnvironmentWebhookSecretResolver) ResolveWebhookSecret(ctx context.Context, hook biz.BuildHook) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	alias, err := secretref.Alias(hook.SecretRef)
	if err != nil || !hook.Provider.Valid() {
		return nil, biz.ErrWebhookSecretUnavailable
	}
	name := "OWNDOCK_WEBHOOK_" + strings.ToUpper(strings.ReplaceAll(alias, "-", "_")) + "_SECRET"
	value, found := r.lookup(name)
	if !found || strings.TrimSpace(value) == "" {
		return nil, biz.ErrWebhookSecretUnavailable
	}
	return []byte(value), nil
}

const defaultWebhookTimestampTolerance = 5 * time.Minute

type WebhookVerifier struct {
	secrets   WebhookSecretResolver
	now       func() time.Time
	tolerance time.Duration
}

func NewWebhookVerifier(secrets WebhookSecretResolver) *WebhookVerifier {
	return &WebhookVerifier{secrets: secrets, now: time.Now, tolerance: defaultWebhookTimestampTolerance}
}

func (v *WebhookVerifier) WithClock(now func() time.Time) *WebhookVerifier {
	if now != nil {
		v.now = now
	}
	return v
}

func (v *WebhookVerifier) VerifyAndParse(ctx context.Context, hook biz.BuildHook, envelope biz.WebhookEnvelope) (biz.WebhookEvent, error) {
	if v == nil || v.secrets == nil || hook.Provider.Valid() == false ||
		strings.TrimSpace(envelope.DeliveryID) == "" || len(envelope.DeliveryID) > 255 ||
		strings.TrimSpace(envelope.Event) == "" || len(envelope.Event) > 128 ||
		len(envelope.Body) == 0 {
		return biz.WebhookEvent{}, biz.ErrInvalidWebhook
	}
	if hook.Provider == biz.WebhookProviderGitLab && !v.validGitLabTimestamp(envelope) {
		return biz.WebhookEvent{}, biz.ErrInvalidWebhookSignature
	}
	secret, err := v.secrets.ResolveWebhookSecret(ctx, hook)
	if err != nil {
		return biz.WebhookEvent{}, biz.ErrWebhookSecretUnavailable
	}
	defer clearBytes(secret)
	if !verifyWebhookSignature(hook.Provider, secret, envelope) {
		return biz.WebhookEvent{}, biz.ErrInvalidWebhookSignature
	}
	if !pushEvent(hook.Provider, envelope.Event) {
		return biz.WebhookEvent{Supported: false}, nil
	}
	var payload struct {
		ObjectKind string `json:"object_kind"`
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Deleted    bool   `json:"deleted"`
	}
	if err := json.Unmarshal(envelope.Body, &payload); err != nil {
		return biz.WebhookEvent{}, biz.ErrInvalidWebhook
	}
	if hook.Provider == biz.WebhookProviderGitLab && payload.ObjectKind != "push" {
		return biz.WebhookEvent{Supported: false}, nil
	}
	commit := strings.ToLower(strings.TrimSpace(payload.After))
	if payload.Deleted || commit == strings.Repeat("0", 40) {
		return biz.WebhookEvent{Supported: false, Ref: strings.TrimSpace(payload.Ref)}, nil
	}
	return biz.WebhookEvent{Supported: true, Ref: strings.TrimSpace(payload.Ref), CommitSHA: commit}, nil
}

func (v *WebhookVerifier) validGitLabTimestamp(envelope biz.WebhookEnvelope) bool {
	value := strings.TrimSpace(envelope.Timestamp)
	if value == "" || strings.Contains(envelope.DeliveryID, ".") {
		return false
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != value {
		return false
	}
	now := time.Now().UTC()
	if v.now != nil {
		now = v.now().UTC()
	}
	tolerance := v.tolerance
	if tolerance <= 0 {
		tolerance = defaultWebhookTimestampTolerance
	}
	timestamp := time.Unix(seconds, 0).UTC()
	return !timestamp.Before(now.Add(-tolerance)) && !timestamp.After(now.Add(tolerance))
}

func pushEvent(provider biz.WebhookProvider, event string) bool {
	event = strings.TrimSpace(event)
	if provider == biz.WebhookProviderGitLab {
		return event == "Push Hook"
	}
	return event == "push"
}

func verifyWebhookSignature(provider biz.WebhookProvider, secret []byte, envelope biz.WebhookEnvelope) bool {
	switch provider {
	case biz.WebhookProviderGitHub:
		return verifyHexHMAC(secret, envelope.Body, envelope.Signature, true)
	case biz.WebhookProviderGitea, biz.WebhookProviderForgejo:
		return verifyHexHMAC(secret, envelope.Body, envelope.Signature, false)
	case biz.WebhookProviderGitLab:
		return verifyGitLabSignature(secret, envelope)
	default:
		return false
	}
}

func verifyHexHMAC(secret, body []byte, signature string, requirePrefix bool) bool {
	signature = strings.TrimSpace(signature)
	if requirePrefix {
		if !strings.HasPrefix(signature, "sha256=") {
			return false
		}
		signature = strings.TrimPrefix(signature, "sha256=")
	}
	provided, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return subtle.ConstantTimeCompare(mac.Sum(nil), provided) == 1
}

func verifyGitLabSignature(secret []byte, envelope biz.WebhookEnvelope) bool {
	value := strings.TrimSpace(string(secret))
	if !strings.HasPrefix(value, "whsec_") || strings.TrimSpace(envelope.Timestamp) == "" {
		return false
	}
	encoded := strings.TrimPrefix(value, "whsec_")
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil || len(key) < 16 {
		return false
	}
	defer clearBytes(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(envelope.DeliveryID + "." + envelope.Timestamp + "."))
	_, _ = mac.Write(envelope.Body)
	expected := []byte("v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	for _, signature := range strings.Fields(envelope.Signature) {
		if subtle.ConstantTimeCompare(expected, []byte(signature)) == 1 {
			return true
		}
	}
	return false
}

var _ biz.WebhookVerifier = (*WebhookVerifier)(nil)
