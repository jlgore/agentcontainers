//go:build linux

package harness

import "golang.org/x/sys/unix"

// fsImmutableFL is the immutable inode flag (linux/fs.h FS_IMMUTABLE_FL). Setting
// it (chattr +i) blocks write, rename, unlink, and link — everything the
// enforcer's file_open inode-deny cannot cover (it never sees rename/unlink) —
// and clearing it requires CAP_LINUX_IMMUTABLE, which a hardened agent lacks. A
// fixed kernel ABI value, defined here to avoid x/sys version skew.
const fsImmutableFL = 0x00000010

// setImmutable sets (on) or clears (off) the immutable bit on path. Requires
// CAP_LINUX_IMMUTABLE. Opening O_RDONLY is sufficient — the flag ioctl does not
// need write permission on the file.
func setImmutable(path string, on bool) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return err
	}
	if on {
		flags |= fsImmutableFL
	} else {
		flags &^= fsImmutableFL
	}
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, flags)
}

// isImmutable reports whether path currently has the immutable bit set.
func isImmutable(path string) (bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	flags, err := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
	if err != nil {
		return false, err
	}
	return flags&fsImmutableFL != 0, nil
}
