//go:build !windows && !linux

package monitor

import "fmt"

func platformDiskUsage(path string) (DiskUsage, error) {
	return DiskUsage{}, fmt.Errorf("disk inspection is unsupported on this platform")
}
