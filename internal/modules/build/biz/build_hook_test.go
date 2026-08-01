package biz

import (
	"errors"
	"testing"
	"time"
)

func TestBuildHookValidationSummaryAndRevocation(t *testing.T) {
	now := time.Unix(100, 0)
	hook, err := NewBuildHook(
		"hook-1", "organization-1", "project-1", "application-1", "configuration-1",
		"GitHub main", WebhookProviderGitHub, []string{"refs/heads/main"},
		"secret://github-main", "user-1", now,
	)
	if err != nil || len(hook.AllowedRefs) != 1 || !hook.AllowsRef("refs/heads/main") || hook.Summary().SecretConfigured == false {
		t.Fatalf("NewBuildHook() = %+v, %v", hook, err)
	}
	summary := hook.Summary()
	summary.AllowedRefs[0] = "refs/heads/changed"
	if hook.AllowedRefs[0] != "refs/heads/main" {
		t.Fatal("BuildHookSummary aliases domain allowed refs")
	}
	revoked, err := hook.Revoke("user-2", now.Add(time.Minute))
	if err != nil || revoked.Status != BuildHookStatusRevoked || revoked.Version != 2 || revoked.AllowsRef("refs/heads/main") {
		t.Fatalf("Revoke() = %+v, %v", revoked, err)
	}
	if _, err := revoked.Revoke("user-2", now.Add(2*time.Minute)); !errors.Is(err, ErrInvalidBuildHook) {
		t.Fatalf("second revoke error = %v", err)
	}
}

func TestBuildHookRejectsInvalidProviderRefsAndSecret(t *testing.T) {
	tests := []struct {
		provider WebhookProvider
		refs     []string
		secret   string
	}{
		{provider: "unknown", refs: []string{"refs/heads/main"}, secret: "secret://hook"},
		{provider: WebhookProviderGitHub, refs: []string{"main"}, secret: "secret://hook"},
		{provider: WebhookProviderGitHub, refs: []string{"refs/heads/main"}, secret: "inline-secret"},
	}
	for _, test := range tests {
		_, err := NewBuildHook("hook-1", "organization-1", "project-1", "application-1", "configuration-1",
			"Webhook", test.provider, test.refs, test.secret, "user-1", time.Unix(100, 0))
		if !errors.Is(err, ErrInvalidBuildHook) {
			t.Errorf("NewBuildHook(%+v) error = %v", test, err)
		}
	}
}
