package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPreparePrivateDataDirRestrictsExistingWindowsACL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	account, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := account.User.Sid
	setTestACL := func(path string) {
		t.Helper()
		descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FR;;;BU)(A;;FA;;;" + sid.String() + ")")
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(root, "admin_key.pem")
	if err := os.WriteFile(key, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	setTestACL(key)
	if hasPrivateStateACL(key, sid, false) {
		t.Fatal("managed file with read access for built-in users was accepted")
	}
	if err := preparePrivateDataDir(root); err != nil {
		t.Fatal(err)
	}
	if !hasPrivateStateACL(root, sid, true) || !hasPrivateStateACL(key, sid, false) {
		t.Fatal("private ACL was not applied to directory and existing key")
	}
	db := filepath.Join(root, "niubwaf.db")
	if err := os.WriteFile(db, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if !hasPrivateStateACL(db, sid, false) {
		t.Fatal("new file did not inherit the private ACL")
	}
	if err := preparePrivateDataDir(root); err != nil {
		t.Fatal(err)
	}
}
