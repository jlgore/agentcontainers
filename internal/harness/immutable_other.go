//go:build !linux

package harness

import "errors"

// errUnsupported is returned off Linux, where the immutable inode flag and its
// FS_IOC_SETFLAGS ioctl do not exist.
var errUnsupported = errors.New("harness: immutable protection is only supported on Linux")

func setImmutable(string, bool) error       { return errUnsupported }
func isImmutable(string) (bool, error)      { return false, errUnsupported }
