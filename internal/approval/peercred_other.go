//go:build !linux

package approval

import (
	"fmt"
	"net"
)

// peerUID is unsupported off Linux: without a kernel-asserted peer identity
// the socket channel fails closed and connections are dropped.
func peerUID(net.Conn) (int, error) {
	return -1, fmt.Errorf("approval: SO_PEERCRED peer verification requires linux")
}
