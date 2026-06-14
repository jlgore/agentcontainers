package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// Listener serves Decide over a Unix domain socket: one JSON Request per
// connection, one JSON Verdict back. The thin hook client dials, writes the
// PreToolUse payload, reads the verdict, and closes. The socket is created
// 0600 and is intended to be bind-mounted read-only into the agent container
// — the decision logic stays on this side of the boundary.
type Listener struct {
	ln  net.Listener
	svc *Service
	log *zap.Logger
}

// Listen creates the socket at path (replacing any stale socket) and returns
// a Listener ready to Serve.
func Listen(path string, svc *Service, log *zap.Logger) (*Listener, error) {
	if log == nil {
		log = zap.NewNop()
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("guard: creating socket dir %s: %w", dir, err)
		}
	}
	// A leftover socket file from a crashed serve blocks bind; remove it.
	if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("guard: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("guard: chmod %s: %w", path, err)
	}
	return &Listener{ln: ln, svc: svc, log: log}, nil
}

// Path returns the socket path.
func (l *Listener) Path() string { return l.ln.Addr().String() }

// Close stops accepting and removes the socket.
func (l *Listener) Close() error { return l.ln.Close() }

// Serve accepts connections until ctx is canceled or the listener closes.
func (l *Listener) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("guard: accept: %w", err)
		}
		go l.handle(ctx, conn)
	}
}

func (l *Listener) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Bound the request read; the hook sends its payload immediately. The
	// decision itself (which may block on human approval) is governed by the
	// broker's own timeout, so clear the deadline before deciding.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		l.write(conn, Verdict{Decision: DecisionDeny, Reason: "guard: malformed request"})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Dispatch on the hook event. PostToolUse reports execution (inline mode
	// resolves its ledger); everything else ("PreToolUse", or "" from older
	// hooks that sent no event name) is a policy decision.
	var v Verdict
	switch req.HookEventName {
	case "PostToolUse":
		v = l.svc.Report(ctx, req)
	default:
		v = l.svc.Decide(ctx, req)
	}
	l.write(conn, v)
}

func (l *Listener) write(conn net.Conn, v Verdict) {
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(v); err != nil {
		l.log.Warn("guard: writing verdict", zap.Error(err))
	}
}
