//go:build !linux

package harness

import "io/fs"

// statOwner cannot determine ownership off Linux; callers fall back to mode bits.
func statOwner(fs.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}
