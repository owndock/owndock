package worker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrInvalidWorkspace = errors.New("build workspace is invalid")
	ErrWorkspaceEscape  = errors.New("build workspace escaped its root")
)

type Workspace interface {
	Prepare(string, uint64) (string, error)
	Cleanup(string) error
}

type LocalWorkspace struct {
	root string
}

func NewLocalWorkspace(root string) (*LocalWorkspace, error) {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return nil, ErrInvalidWorkspace
	}
	clean := filepath.Clean(root)
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return nil, fmt.Errorf("create build workspace root: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrInvalidWorkspace
	}
	return &LocalWorkspace{root: clean}, nil
}

func (w *LocalWorkspace) Prepare(buildID string, generation uint64) (string, error) {
	if !safeWorkspaceID(buildID) || generation == 0 {
		return "", ErrInvalidWorkspace
	}
	if err := w.Cleanup(buildID); err != nil {
		return "", err
	}
	destination, err := os.MkdirTemp(w.root, buildID+"-checkout-")
	if err != nil {
		return "", fmt.Errorf("create build workspace: %w", err)
	}
	if err := os.Chmod(destination, 0o700); err != nil {
		_ = os.RemoveAll(destination)
		return "", fmt.Errorf("secure build workspace: %w", err)
	}
	if !withinWorkspace(w.root, destination) {
		_ = os.RemoveAll(destination)
		return "", ErrWorkspaceEscape
	}
	return destination, nil
}

func (w *LocalWorkspace) Cleanup(buildID string) error {
	if !safeWorkspaceID(buildID) {
		return ErrInvalidWorkspace
	}
	entries, err := os.ReadDir(w.root)
	if err != nil {
		return fmt.Errorf("read build workspace root: %w", err)
	}
	prefix := buildID + "-checkout-"
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		target := filepath.Join(w.root, entry.Name())
		if !withinWorkspace(w.root, target) {
			return ErrWorkspaceEscape
		}
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("clean build workspace: %w", err)
		}
	}
	return nil
}

func withinWorkspace(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != "." && relative != "" && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func safeWorkspaceID(value string) bool {
	if value == "" || len(value) > 128 || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' && character != ':' &&
			(character < '0' || character > '9') &&
			(character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}
