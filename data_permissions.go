package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Set permissions before opening SQLite or loading certificate material.
func preparePrivateDataDir(dir string) error {
	root, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if filepath.Dir(root) == root {
		return fmt.Errorf("数据目录需使用专用子目录: %s", root)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	protect, err := privateStateProtector()
	if err != nil {
		return err
	}
	secure := func(path string, dir bool) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if (dir && !info.IsDir()) || (!dir && !info.Mode().IsRegular()) {
			return fmt.Errorf("数据路径类型无效（不接受符号链接或特殊文件）: %s", path)
		}
		if err := protect(path, info); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return nil
	}
	if err := secure(root, true); err != nil {
		return err
	}
	for _, name := range []string{"niubwaf.db", "niubwaf.db-wal", "niubwaf.db-shm", "niubwaf.db-journal", "default_key.pem", "admin_key.pem"} {
		if err := secure(filepath.Join(root, name), false); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, name := range []string{"backups", "acme"} {
		path := filepath.Join(root, name)
		if err := secure(path, true); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := filepath.WalkDir(path, func(child string, entry fs.DirEntry, err error) error {
			if err != nil || child == path {
				return err
			}
			return secure(child, entry.IsDir())
		}); err != nil {
			return err
		}
	}
	return nil
}
