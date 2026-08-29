package worker

import (
	"errors"
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

func TestHardQuotaWorkspaceRequiresIndependentBoundedFilesystem(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspaces")
	const hardLimit = int64(8 * 1024 * 1024)
	inspect := func(path string) (workspaceFilesystem, error) {
		if filepath.Clean(path) == filepath.Clean(root) {
			return workspaceFilesystem{device: 2, totalBytes: hardLimit}, nil
		}
		return workspaceFilesystem{device: 1, totalBytes: 1024 * 1024 * 1024}, nil
	}
	workspace, err := newHardQuotaWorkspace(root, hardLimit, inspect)
	if err != nil || workspace.root != root {
		t.Fatalf("hard-quota workspace = %+v/%v", workspace, err)
	}

	for _, test := range []struct {
		name    string
		limit   int64
		inspect workspaceFilesystemInspector
	}{
		{name: "invalid limit", limit: 0, inspect: inspect},
		{name: "missing inspector", limit: hardLimit},
		{name: "shared parent filesystem", limit: hardLimit, inspect: func(string) (workspaceFilesystem, error) {
			return workspaceFilesystem{device: 1, totalBytes: hardLimit}, nil
		}},
		{name: "filesystem exceeds boundary", limit: hardLimit, inspect: func(path string) (workspaceFilesystem, error) {
			if filepath.Clean(path) == filepath.Clean(root) {
				return workspaceFilesystem{device: 2, totalBytes: hardLimit + 1}, nil
			}
			return workspaceFilesystem{device: 1, totalBytes: hardLimit * 2}, nil
		}},
		{name: "inspection failure", limit: hardLimit, inspect: func(string) (workspaceFilesystem, error) {
			return workspaceFilesystem{}, errors.New("statfs failed")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := newHardQuotaWorkspace(root, test.limit, test.inspect)
			if !errors.Is(err, ErrWorkspaceHardQuotaRequired) {
				t.Fatalf("hard-quota error = %v", err)
			}
		})
	}
}

func TestHardQuotaFilesystemInspectionFailsClosedOnSharedOrUnsafePath(t *testing.T) {
	root := t.TempDir()
	filesystem, err := inspectWorkspaceFilesystem(root)
	if err != nil || filesystem.totalBytes <= 0 {
		t.Fatalf("filesystem inspection = %+v/%v", filesystem, err)
	}
	if err := ValidateHardQuotaFilesystem(root, 1<<62); !errors.Is(err, ErrWorkspaceHardQuotaRequired) {
		t.Fatalf("shared filesystem validation = %v", err)
	}
	if err := ValidateHardQuotaFilesystem("relative", 1<<20); !errors.Is(err, ErrWorkspaceHardQuotaRequired) {
		t.Fatalf("relative filesystem validation = %v", err)
	}
	link := filepath.Join(t.TempDir(), "quota-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHardQuotaFilesystem(link, 1<<62); !errors.Is(err, ErrWorkspaceHardQuotaRequired) {
		t.Fatalf("symlink filesystem validation = %v", err)
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
