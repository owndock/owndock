package data

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/owndock/owndock/internal/modules/build/biz"
)

type webhookSecretsStub struct{ value []byte }

func (s webhookSecretsStub) ResolveWebhookSecret(context.Context, biz.BuildHook) ([]byte, error) {
	return append([]byte(nil), s.value...), nil
}

func TestWebhookVerifierProviderSignatures(t *testing.T) {
	body := []byte(`{"ref":"refs/heads/main","after":"a975c10d68a2d7461634f13b15c52a2efba72d16","object_kind":"push"}`)
	secret := []byte("webhook-secret")
	tests := []struct {
		name      string
		provider  biz.WebhookProvider
		event     string
		signature func(string, string, []byte) string
	}{
		{name: "github", provider: biz.WebhookProviderGitHub, event: "push", signature: func(_, _ string, body []byte) string { return "sha256=" + hexHMAC(secret, body) }},
		{name: "gitea", provider: biz.WebhookProviderGitea, event: "push", signature: func(_, _ string, body []byte) string { return hexHMAC(secret, body) }},
		{name: "forgejo", provider: biz.WebhookProviderForgejo, event: "push", signature: func(_, _ string, body []byte) string { return hexHMAC(secret, body) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := NewWebhookVerifier(webhookSecretsStub{value: secret})
			envelope := biz.WebhookEnvelope{DeliveryID: "delivery-1", Event: test.event, Body: body}
			envelope.Signature = test.signature(envelope.DeliveryID, envelope.Timestamp, body)
			event, err := verifier.VerifyAndParse(context.Background(), biz.BuildHook{Provider: test.provider}, envelope)
			if err != nil || !event.Supported || event.Ref != "refs/heads/main" || event.CommitSHA != "a975c10d68a2d7461634f13b15c52a2efba72d16" {
				t.Fatalf("VerifyAndParse() = %+v, %v", event, err)
			}
		})
	}
}

func TestWebhookVerifierGitLabStandardSignature(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	secret := []byte("whsec_" + base64.StdEncoding.EncodeToString(key))
	body := []byte(`{"object_kind":"push","ref":"refs/tags/v1.0.0","after":"a975c10d68a2d7461634f13b15c52a2efba72d16"}`)
	envelope := biz.WebhookEnvelope{DeliveryID: "delivery-1", Event: "Push Hook", Timestamp: "1770000000", Body: body}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(envelope.DeliveryID + "." + envelope.Timestamp + "."))
	_, _ = mac.Write(body)
	envelope.Signature = "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	event, err := NewWebhookVerifier(webhookSecretsStub{value: secret}).WithClock(
		func() time.Time { return time.Unix(1770000000, 0) },
	).VerifyAndParse(
		context.Background(), biz.BuildHook{Provider: biz.WebhookProviderGitLab}, envelope,
	)
	if err != nil || !event.Supported || event.Ref != "refs/tags/v1.0.0" {
		t.Fatalf("VerifyAndParse() = %+v, %v", event, err)
	}
}

func TestWebhookVerifierRejectsStaleFutureAndAmbiguousGitLabMessages(t *testing.T) {
	now := time.Unix(1770000000, 0).UTC()
	key := []byte("0123456789abcdef0123456789abcdef")
	secret := []byte("whsec_" + base64.StdEncoding.EncodeToString(key))
	body := []byte(`{"object_kind":"push","ref":"refs/heads/main","after":"a975c10d68a2d7461634f13b15c52a2efba72d16"}`)
	for _, test := range []struct {
		name       string
		deliveryID string
		timestamp  string
	}{
		{name: "stale", deliveryID: "delivery-stale", timestamp: strconv.FormatInt(now.Add(-5*time.Minute-time.Second).Unix(), 10)},
		{name: "future", deliveryID: "delivery-future", timestamp: strconv.FormatInt(now.Add(5*time.Minute+time.Second).Unix(), 10)},
		{name: "non-canonical", deliveryID: "delivery-leading-zero", timestamp: "01770000000"},
		{name: "ambiguous-id", deliveryID: "delivery.with-dot", timestamp: strconv.FormatInt(now.Unix(), 10)},
	} {
		t.Run(test.name, func(t *testing.T) {
			envelope := biz.WebhookEnvelope{
				DeliveryID: test.deliveryID, Event: "Push Hook", Timestamp: test.timestamp, Body: body,
			}
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write([]byte(envelope.DeliveryID + "." + envelope.Timestamp + "."))
			_, _ = mac.Write(body)
			envelope.Signature = "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
			_, err := NewWebhookVerifier(webhookSecretsStub{value: secret}).WithClock(
				func() time.Time { return now },
			).VerifyAndParse(context.Background(), biz.BuildHook{Provider: biz.WebhookProviderGitLab}, envelope)
			if !errors.Is(err, biz.ErrInvalidWebhookSignature) {
				t.Fatalf("invalid timestamp error = %v", err)
			}
		})
	}
}

func TestWebhookVerifierAuthenticatesBeforeParsing(t *testing.T) {
	verifier := NewWebhookVerifier(webhookSecretsStub{value: []byte("webhook-secret")})
	envelope := biz.WebhookEnvelope{DeliveryID: "delivery-1", Event: "push", Signature: "sha256=invalid", Body: []byte("not-json")}
	_, err := verifier.VerifyAndParse(context.Background(), biz.BuildHook{Provider: biz.WebhookProviderGitHub}, envelope)
	if !errors.Is(err, biz.ErrInvalidWebhookSignature) {
		t.Fatalf("VerifyAndParse() error = %v", err)
	}

	envelope.Signature = "sha256=" + hexHMAC([]byte("webhook-secret"), envelope.Body)
	_, err = verifier.VerifyAndParse(context.Background(), biz.BuildHook{Provider: biz.WebhookProviderGitHub}, envelope)
	if !errors.Is(err, biz.ErrInvalidWebhook) {
		t.Fatalf("authenticated malformed payload error = %v", err)
	}
}

func TestWebhookVerifierIgnoresUnsupportedAndDeletedEvents(t *testing.T) {
	secret := []byte("webhook-secret")
	verifier := NewWebhookVerifier(webhookSecretsStub{value: secret})
	for _, envelope := range []biz.WebhookEnvelope{
		{DeliveryID: "delivery-unsupported", Event: "issues", Body: []byte(`{"action":"opened"}`)},
		{DeliveryID: "delivery-deleted", Event: "push", Body: []byte(`{"ref":"refs/heads/old","after":"0000000000000000000000000000000000000000","deleted":true}`)},
	} {
		envelope.Signature = "sha256=" + hexHMAC(secret, envelope.Body)
		event, err := verifier.VerifyAndParse(context.Background(), biz.BuildHook{Provider: biz.WebhookProviderGitHub}, envelope)
		if err != nil || event.Supported {
			t.Fatalf("VerifyAndParse() = %+v, %v", event, err)
		}
	}
}

func TestEnvironmentWebhookSecretResolverUsesOnlyAliasEnvironment(t *testing.T) {
	t.Setenv("OWNDOCK_WEBHOOK_GITHUB_MAIN_HOOK_SECRET", "signed-secret")
	resolver := NewEnvironmentWebhookSecretResolver()
	secret, err := resolver.ResolveWebhookSecret(context.Background(), biz.BuildHook{
		Provider: biz.WebhookProviderGitHub, SecretRef: "secret://github-main-hook",
	})
	if err != nil || string(secret) != "signed-secret" {
		t.Fatalf("ResolveWebhookSecret() = %q, %v", secret, err)
	}
	if _, err := resolver.ResolveWebhookSecret(context.Background(), biz.BuildHook{
		Provider: biz.WebhookProviderGitHub, SecretRef: "secret://missing-hook",
	}); !errors.Is(err, biz.ErrWebhookSecretUnavailable) {
		t.Fatalf("missing secret error = %v", err)
	}
}

func hexHMAC(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
