package approval

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the UID of the process on the other end of a Unix domain
// socket connection via SO_PEERCRED. Kernel-asserted: the client cannot
// forge it.
func peerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("approval: not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("approval: accessing socket fd: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, fmt.Errorf("approval: reading peer credentials: %w", err)
	}
	if credErr != nil {
		return -1, fmt.Errorf("approval: reading peer credentials: %w", credErr)
	}
	return int(cred.Uid), nil
}
