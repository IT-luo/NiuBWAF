//go:build !windows

package main

import (
	"io/fs"
	"os"
)

func privateStateProtector() (func(string, fs.FileInfo) error, error) {
	return func(path string, info fs.FileInfo) error {
		mode := fs.FileMode(0600)
		if info.IsDir() {
			mode = 0700
		}
		if info.Mode().Perm() == mode {
			return nil
		}
		return os.Chmod(path, mode)
	}, nil
}
