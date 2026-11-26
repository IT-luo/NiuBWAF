package main

import (
	"io/fs"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privateStateProtector() (func(string, fs.FileInfo) error, error) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	account := tokenUser.User.Sid
	return func(path string, info fs.FileInfo) error {
		if hasPrivateStateACL(path, account, info.IsDir()) {
			return nil
		}
		inheritance := ""
		if info.IsDir() {
			inheritance = "OICI"
		}
		sddl := "D:P(A;" + inheritance + ";FA;;;SY)(A;" + inheritance + ";FA;;;BA)(A;" + inheritance + ";FA;;;" + account.String() + ")"
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}, nil
}

func hasPrivateStateACL(path string, account *windows.SID, dir bool) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	if dir {
		control, _, err := descriptor.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			return false
		}
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	accountAllowed := false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		// A basic allow ACE stores its variable-length SID starting at SidStart.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(account) {
			inheritance := uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
			flags := ace.Header.AceFlags
			appliesToDirectoryTree := flags&inheritance == inheritance && flags&windows.NO_PROPAGATE_INHERIT_ACE == 0
			accountAllowed = accountAllowed || (flags&windows.INHERIT_ONLY_ACE == 0 && (!dir || appliesToDirectoryTree))
		} else if !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return false
		}
	}
	return accountAllowed
}
