package agentruntime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func prepareStateDirectory(
	directory string,
	invalid error,
) (string, error) {
	directory = filepath.Clean(directory)
	if !filepath.IsAbs(directory) {
		return "", invalid
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create Agent state directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", fmt.Errorf(
			"%w: inspect state directory: %v",
			invalid,
			err,
		)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf(
			"%w: state directory mode %s",
			invalid,
			info.Mode(),
		)
	}
	return directory, nil
}

func readRestrictedStateFile(
	path string,
	maximumBytes int64,
	invalid error,
) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect Agent state file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, false, fmt.Errorf(
			"%w: state file mode %s",
			invalid,
			info.Mode(),
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("open Agent state file: %w", err)
	}
	defer func() { _ = file.Close() }()
	value, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read Agent state file: %w", err)
	}
	if int64(len(value)) > maximumBytes {
		return nil, false, invalid
	}
	return value, true, nil
}

func replaceRestrictedStateFile(
	directory, path, pattern string,
	value []byte,
) error {
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return fmt.Errorf("create Agent state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict Agent state file permissions: %w", err)
	}
	if _, err := temporary.Write(value); err != nil {
		return fmt.Errorf("write Agent state file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync Agent state file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Agent state file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace Agent state file: %w", err)
	}
	renamed = true
	stateDirectory, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open Agent state directory: %w", err)
	}
	defer func() { _ = stateDirectory.Close() }()
	if err := stateDirectory.Sync(); err != nil {
		return fmt.Errorf("sync Agent state directory: %w", err)
	}
	return nil
}
