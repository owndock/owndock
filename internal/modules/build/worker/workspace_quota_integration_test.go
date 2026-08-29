package worker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

const pinnedWorkspaceQuotaFixtureImage = "busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"

func TestWorkspaceHardQuotaDockerIntegration(t *testing.T) {
	if os.Getenv("OWNDOCK_RUN_STORAGE_QUOTA_INTEGRATION") != "1" {
		t.Skip("set OWNDOCK_RUN_STORAGE_QUOTA_INTEGRATION=1 to run the hard-quota integration")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI is unavailable")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("the storage fixture supports linux/amd64 and linux/arm64")
	}
	repositoryRoot := workspaceRepositoryRoot(t)
	preflightBinary := filepath.Join(t.TempDir(), "owndock-build-worker")
	compilePreflight := exec.CommandContext(t.Context(), "go", "build", "-o", preflightBinary,
		"./cmd/build-worker")
	compilePreflight.Dir = repositoryRoot
	compilePreflight.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := compilePreflight.CombinedOutput(); err != nil {
		t.Fatalf("compile Linux storage preflight: %v: %s", err, output)
	}
	preflight := exec.CommandContext(t.Context(), "docker", "run", "--rm", "--network", "none",
		"--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--tmpfs", "/quota:rw,nosuid,nodev,size=4194304,mode=0700,uid=1000,gid=1000",
		"--volume", preflightBinary+":/owndock-build-worker:ro",
		pinnedWorkspaceQuotaFixtureImage,
		"/owndock-build-worker", "-check-storage-root", "/quota",
		"-check-storage-hard-quota-bytes", "4194304",
	)
	if output, err := preflight.CombinedOutput(); err != nil {
		t.Fatalf("Build Worker storage preflight: %v: %s", err, output)
	}

	binary := filepath.Join(t.TempDir(), "workspace-quota.test")
	compile := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", binary,
		"./internal/modules/build/worker")
	compile.Dir = repositoryRoot
	compile.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile Linux workspace quota fixture: %v: %s", err, output)
	}

	command := exec.CommandContext(t.Context(), "docker", "run", "--rm", "--network", "none",
		"--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--tmpfs", "/quota:rw,nosuid,nodev,size=4194304,mode=0700,uid=1000,gid=1000",
		"--env", "OWNDOCK_WORKSPACE_QUOTA_FIXTURE=1",
		"--volume", binary+":/workspace-quota.test:ro",
		pinnedWorkspaceQuotaFixtureImage,
		"/workspace-quota.test", "-test.run", "^TestWorkspaceHardQuotaFixture$", "-test.v",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("hard-quota fixture: %v: %s", err, output)
	}
}

func TestWorkspaceHardQuotaFixture(t *testing.T) {
	if os.Getenv("OWNDOCK_WORKSPACE_QUOTA_FIXTURE") != "1" {
		t.Skip("Docker hard-quota helper")
	}
	const quotaBytes = int64(4 * 1024 * 1024)
	workspace, err := NewHardQuotaWorkspace("/quota", quotaBytes)
	if err != nil {
		t.Fatalf("verify mounted hard quota: %v", err)
	}
	offending, err := workspace.Prepare("quota-exhaustion", 1)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(offending, "oversized-pack"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0xa5}, 256*1024)
	var writeErr error
	for range 32 {
		if _, writeErr = file.Write(payload); writeErr != nil {
			break
		}
	}
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if !errors.Is(writeErr, syscall.ENOSPC) {
		t.Fatalf("quota exhaustion error = %v", writeErr)
	}
	if err := workspace.Cleanup("quota-exhaustion"); err != nil {
		t.Fatalf("clean exhausted workspace: %v", err)
	}

	adjacent, err := workspace.Prepare("adjacent-build", 1)
	if err != nil {
		t.Fatalf("prepare adjacent Build: %v", err)
	}
	if err := os.WriteFile(filepath.Join(adjacent, "source"), payload, 0o600); err != nil {
		t.Fatalf("adjacent Build remained affected: %v", err)
	}
	if err := workspace.Cleanup("adjacent-build"); err != nil {
		t.Fatalf("clean adjacent Build: %v", err)
	}
}

func workspaceRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve workspace integration source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	if !filepath.IsAbs(root) || strings.TrimSpace(root) == "" {
		t.Fatal(fmt.Errorf("invalid repository root %q", root))
	}
	return root
}
