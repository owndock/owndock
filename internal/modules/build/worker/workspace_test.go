package worker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalWorkspaceIsContainedAndCleansOnlyOneBuild(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspaces")
	workspace, err := NewLocalWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := workspace.Prepare("build-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := workspace.Prepare("build-2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !withinWorkspace(root, first) || !withinWorkspace(root, second) {
		t.Fatalf("workspace escaped root: %q %q", first, second)
	}
	if err := os.WriteFile(filepath.Join(first, "source"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Cleanup("build-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("first workspace still exists: %v", err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("unrelated workspace was removed: %v", err)
	}
}

func TestLocalWorkspaceRejectsBroadOrRelativeTargets(t *testing.T) {
	if _, err := NewLocalWorkspace("relative"); err == nil {
		t.Fatal("relative workspace root was accepted")
	}
	workspace, err := NewLocalWorkspace(filepath.Join(t.TempDir(), "workspaces"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", ".", "..", "../escape", "build/escape"} {
		if _, err := workspace.Prepare(value, 1); err == nil {
			t.Fatalf("unsafe build ID %q was accepted", value)
		}
	}
}

func TestLocalWorkspaceCleanupDoesNotFollowAttackerSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspaces")
	workspace, err := NewLocalWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "must-survive")
	if err := os.WriteFile(outside, []byte("protected"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "build-1-checkout-attacker")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Cleanup("build-1"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "protected" {
		t.Fatalf("cleanup followed attacker symlink: %q, %v", content, err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("workspace symlink still exists: %v", err)
	}
}
