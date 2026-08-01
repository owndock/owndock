package biz

import (
	"strings"
	"testing"
	"time"
)

func TestBuildTriggerTokenAndRevocation(t *testing.T) {
	item, err := NewBuildTrigger("trigger-1", "organization-1", "project-1", "application-1",
		"configuration-1", "Git automation", []string{"refs/heads/main"}, strings.Repeat("a", 64),
		"user-1", time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !item.MatchesToken(strings.Repeat("a", 64)) || item.MatchesToken(strings.Repeat("b", 64)) ||
		!item.AllowsRef("refs/heads/main") || item.AllowsRef("refs/heads/develop") {
		t.Fatalf("unexpected trigger behavior: %+v", item)
	}
	revoked, err := item.Revoke("user-2", time.Unix(200, 0))
	if err != nil || revoked.Status != BuildTriggerStatusRevoked || revoked.Version != 2 ||
		revoked.AllowsRef("refs/heads/main") {
		t.Fatalf("Revoke() = %+v, %v", revoked, err)
	}
}
