//go:build linux

package harness

import (
	"io/fs"
	"syscall"
)

// statOwner returns the file's owning uid/gid on Linux.
func statOwner(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
