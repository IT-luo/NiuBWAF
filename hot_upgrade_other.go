//go:build !linux

package main

import "fmt"

func startHotUpgrade(enabled bool, _ []string) (*upgradeWorker, bool, error) {
	if enabled {
		return nil, false, fmt.Errorf("当前系统不支持进程热升级")
	}
	return nil, false, nil
}
