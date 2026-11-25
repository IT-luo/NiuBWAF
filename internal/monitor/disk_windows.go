//go:build windows

package monitor

import (
	"golang.org/x/sys/windows"
)

func platformDiskUsage(path string) (DiskUsage, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return DiskUsage{}, err
	}
	var available, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &available, &total, &free); err != nil {
		return DiskUsage{}, err
	}
	return DiskUsage{TotalBytes: total, AvailableBytes: available}, nil
}
