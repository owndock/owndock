//go:build linux || darwin

package worker

import (
	"errors"
	"math"

	"golang.org/x/sys/unix"
)

func inspectWorkspaceFilesystem(path string) (workspaceFilesystem, error) {
	var filesystem unix.Statfs_t
	if err := unix.Statfs(path, &filesystem); err != nil {
		return workspaceFilesystem{}, err
	}
	if filesystem.Bsize <= 0 || filesystem.Blocks > uint64(math.MaxInt64)/uint64(filesystem.Bsize) {
		return workspaceFilesystem{}, errors.New("workspace filesystem capacity is invalid")
	}
	var metadata unix.Stat_t
	if err := unix.Stat(path, &metadata); err != nil {
		return workspaceFilesystem{}, err
	}
	return workspaceFilesystem{
		device:     uint64(metadata.Dev),
		totalBytes: int64(filesystem.Blocks) * int64(filesystem.Bsize),
	}, nil
}
