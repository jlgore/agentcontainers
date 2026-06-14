package guard

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// DefaultSocket is where the in-container hook looks for the guard socket
// unless AC_GUARD_SOCKET or --socket overrides it. The host serve side
// bind-mounts its socket here, read-only.
const DefaultSocket = "/run/ac/guard.sock"

// Ask forwards a raw Claude Code PreToolUse payload to the guard socket and
// returns the verdict. dialTimeout bounds the connection; readTimeout bounds
// the wait for a verdict (which may include a human approval, so callers
// should allow several minutes). A failure is returned as an error; the
// caller decides the fail-closed response.
func Ask(socket string, payload []byte, dialTimeout, readTimeout time.Duration) (Verdict, error) {
	conn, err := net.DialTimeout("unix", socket, dialTimeout)
	if err != nil {
		return Verdict{}, fmt.Errorf("guard: dial %s: %w", socket, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetWriteDeadline(time.Now().Add(dialTimeout)); err != nil {
		return Verdict{}, err
	}
	if _, err := conn.Write(payload); err != nil {
		return Verdict{}, fmt.Errorf("guard: write: %w", err)
	}
	// Half-close the write side so the server sees a clean end of request
	// even if the payload has trailing bytes.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}

	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return Verdict{}, err
	}
	var v Verdict
	if err := json.NewDecoder(conn).Decode(&v); err != nil {
		return Verdict{}, fmt.Errorf("guard: read verdict: %w", err)
	}
	return v, nil
}

// Report sends a PostToolUse payload to the guard (inline mode resolves its
// pending-escalation ledger) and discards the trivial verdict. It reuses Ask,
// which reads the server's response — a plain dial-and-close would leave the
// server writing into a broken pipe. readTimeout can be short: a PostToolUse
// report never waits on a human.
func Report(socket string, payload []byte, dialTimeout, readTimeout time.Duration) error {
	_, err := Ask(socket, payload, dialTimeout, readTimeout)
	return err
}
