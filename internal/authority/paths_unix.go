//go:build !windows

package authority

import (
	"os"
	"syscall"
)

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func protectedAncestor(info os.FileInfo, path string) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return false
	}
	if info.Mode().Perm()&0022 == 0 {
		return true
	}
	// A root-owned sticky temporary directory cannot let another UID replace
	// the authority-owned next path component. Other writable ancestors fail.
	return path == "/tmp" && stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
}

func checkPlatformSupported() error {
	return nil
}
