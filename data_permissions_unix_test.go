//go:build !windows

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparePrivateDataDirRestrictsExistingUnixFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	backupDir := filepath.Join(dir, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		t.Fatal(err)
	}
	files := []string{filepath.Join(dir, "niubwaf.db"), filepath.Join(dir, "admin_key.pem"), filepath.Join(backupDir, "snapshot.db")}
	for _, path := range files {
		if err := os.WriteFile(path, []byte("fixture"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := preparePrivateDataDir(dir); err != nil {
		t.Fatal(err)
	}
	for _, path := range append(files, dir, backupDir) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		expected := fs.FileMode(0600)
		if info.IsDir() {
			expected = 0700
		}
		if info.Mode().Perm() != expected {
			t.Errorf("%s permission = %o; expected %o", path, info.Mode().Perm(), expected)
		}
	}
}

func TestPreparePrivateDataDirRejectsManagedSymlink(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "admin_key.pem")); err != nil {
		t.Fatal(err)
	}
	if err := preparePrivateDataDir(dir); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
	info, err := os.Stat(outside)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("linked file was changed: %v, %v", info, err)
	}
}
