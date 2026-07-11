package approval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
)

// DefaultSocketPath returns the daemonized approval socket location
// (SPEC §9 Phase 4): ~/.agentcontainers/approval.sock.
func DefaultSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("approval: resolving home directory: %w", err)
	}
	return filepath.Join(home, ".agentcontainers", "approval.sock"), nil
}

// socketRequest is one client→server message on the approval socket
// (newline-delimited JSON, multiple requests per connection).
type socketRequest struct {
	Op      string `json:"op"` // "list" | "resolve"
	ID      string `json:"id,omitempty"`
	Approve bool   `json:"approve,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// socketResponse is the server's reply to one socketRequest.
type socketResponse struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	Pending []ToolCallRequest `json:"pending,omitempty"`
}

// SocketServer exposes pending approvals over a Unix domain socket so a
// separate `agentcontainer approve` process can decide them. The socket is
// a security boundary: mode 0600 plus an SO_PEERCRED UID check — only the
// owning user can approve.
type SocketServer struct {
	broker *ToolCallBroker
	ln     net.Listener
	path   string
	uid    int

	mu     sync.Mutex
	closed bool
}

// ListenSocket creates the approval socket at path (empty: DefaultSocketPath)
// and starts serving. A stale socket file from a crashed session is removed;
// a live one (another proxy still listening) is an error.
func ListenSocket(path string, broker *ToolCallBroker) (*SocketServer, error) {
	if path == "" {
		p, err := DefaultSocketPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("approval: creating socket directory: %w", err)
	}

	// Detect a live listener before clobbering its socket.
	if _, err := os.Stat(path); err == nil {
		if conn, err := net.Dial("unix", path); err == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("approval: socket %s is already in use by another session", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("approval: removing stale socket: %w", err)
		}
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("approval: listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("approval: setting socket permissions: %w", err)
	}

	s := &SocketServer{broker: broker, ln: ln, path: path, uid: os.Getuid()}
	go s.acceptLoop()
	return s, nil
}

// Path returns the socket path.
func (s *SocketServer) Path() string { return s.path }

// Close stops the listener and removes the socket file.
func (s *SocketServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	err := s.ln.Close()
	_ = os.Remove(s.path)
	return err
}

func (s *SocketServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handleConn(conn)
	}
}

// handleConn verifies the peer's UID, then serves list/resolve requests
// until the client disconnects. A peer that is not the owning user is
// dropped without serving anything.
func (s *SocketServer) handleConn(conn net.Conn) {
	defer conn.Close() //nolint:errcheck

	uid, err := peerUID(conn)
	if err != nil || uid != s.uid {
		return
	}
	decider := usernameForUID(uid)

	scanner := bufio.NewScanner(conn)
	enc := json.NewEncoder(conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req socketRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(socketResponse{OK: false, Error: "malformed request: " + err.Error()})
			continue
		}
		_ = enc.Encode(s.serve(req, decider))
	}
}

func (s *SocketServer) serve(req socketRequest, decider string) socketResponse {
	switch req.Op {
	case "list":
		pending := s.broker.Pending()
		if pending == nil {
			pending = []ToolCallRequest{}
		}
		return socketResponse{OK: true, Pending: pending}
	case "resolve":
		d := ToolCallDecision{Approved: req.Approve, Reason: req.Reason, Decider: decider}
		if !d.Approved && d.Reason == "" {
			d.Reason = "denied by examiner"
		}
		if err := s.broker.Resolve(req.ID, d); err != nil {
			return socketResponse{OK: false, Error: err.Error()}
		}
		return socketResponse{OK: true}
	default:
		return socketResponse{OK: false, Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// usernameForUID resolves a UID to a username for audit actor fields,
// falling back to the numeric form.
func usernameForUID(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return u.Username
	}
	return "uid:" + strconv.Itoa(uid)
}

// SocketClient is the `agentcontainer approve` side of the protocol.
type SocketClient struct {
	conn    net.Conn
	scanner *bufio.Scanner
	enc     *json.Encoder
}

// DialSocket connects to a running session's approval socket.
func DialSocket(path string) (*SocketClient, error) {
	if path == "" {
		p, err := DefaultSocketPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("approval: connecting to %s (is an `agentcontainer mcp start` session running?): %w", path, err)
	}
	return &SocketClient{conn: conn, scanner: bufio.NewScanner(conn), enc: json.NewEncoder(conn)}, nil
}

// Close closes the connection.
func (c *SocketClient) Close() error { return c.conn.Close() }

func (c *SocketClient) roundTrip(req socketRequest) (socketResponse, error) {
	if err := c.enc.Encode(req); err != nil {
		return socketResponse{}, fmt.Errorf("approval: sending request: %w", err)
	}
	if !c.scanner.Scan() {
		if err := c.scanner.Err(); err != nil {
			return socketResponse{}, fmt.Errorf("approval: reading response: %w", err)
		}
		return socketResponse{}, fmt.Errorf("approval: connection closed (peer credential check failed?)")
	}
	var resp socketResponse
	if err := json.Unmarshal(c.scanner.Bytes(), &resp); err != nil {
		return socketResponse{}, fmt.Errorf("approval: parsing response: %w", err)
	}
	return resp, nil
}

// List returns the pending approval requests.
func (c *SocketClient) List() ([]ToolCallRequest, error) {
	resp, err := c.roundTrip(socketRequest{Op: "list"})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("approval: %s", resp.Error)
	}
	return resp.Pending, nil
}

// Resolve approves or denies one pending request.
func (c *SocketClient) Resolve(id string, approve bool, reason string) error {
	resp, err := c.roundTrip(socketRequest{Op: "resolve", ID: id, Approve: approve, Reason: reason})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("approval: %s", resp.Error)
	}
	return nil
}
