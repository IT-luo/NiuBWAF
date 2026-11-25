//go:build linux

package monitor

import (
	"fmt"
	"syscall"
)

func platformDiskUsage(path string) (DiskUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return DiskUsage{}, err
	}
	if stat.Bsize <= 0 {
		return DiskUsage{}, fmt.Errorf("invalid filesystem block size %d", stat.Bsize)
	}
	blockSize := uint64(stat.Bsize)
	return DiskUsage{
		TotalBytes:     stat.Blocks * blockSize,
		AvailableBytes: stat.Bavail * blockSize,
	}, nil
}
