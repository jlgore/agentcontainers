//go:build linux

package approval

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestSocket(t *testing.T, b *ToolCallBroker) *SocketServer {
	t.Helper()
	// Keep the socket path short: sun_path is 108 bytes and TMPDIR-based
	// test dirs can blow past it.
	dir, err := os.MkdirTemp("/tmp", "ac-approval-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	s, err := ListenSocket(filepath.Join(dir, "approval.sock"), b)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSocketPermissions(t *testing.T) {
	s := newTestSocket(t, NewToolCallBroker(time.Minute))
	info, err := os.Stat(s.Path())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %o, want 0600", perm)
	}
}

func TestSocketListAndResolve(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	s := newTestSocket(t, b)

	done := make(chan ToolCallDecision, 1)
	go func() {
		done <- b.Request(context.Background(), ToolCallRequest{
			ID: "req-1", Server: "sift-gateway", Tool: "run_privileged_command", ArgsSummary: "vol3 --write",
		})
	}()
	awaitPending(t, b, 1)

	c, err := DialSocket(s.Path())
	if err != nil {
		t.Fatalf("DialSocket: %v", err)
	}
	defer c.Close() //nolint:errcheck

	pending, err := c.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != "req-1" || pending[0].Server != "sift-gateway" {
		t.Fatalf("pending = %+v, want one req-1 from sift-gateway", pending)
	}

	if err := c.Resolve("req-1", true, ""); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	d := <-done
	if !d.Approved {
		t.Fatalf("decision = %+v, want approved", d)
	}
	// The decider comes from the kernel-asserted peer UID, not client input.
	if d.Decider == "" {
		t.Error("decider is empty, want the connecting user")
	}

	// Empty queue after resolution.
	pending, err = c.List()
	if err != nil {
		t.Fatalf("List after resolve: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %+v, want empty", pending)
	}
}

func TestSocketDenyDefaultsReason(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	s := newTestSocket(t, b)

	done := make(chan ToolCallDecision, 1)
	go func() {
		done <- b.Request(context.Background(), ToolCallRequest{ID: "req-1", Tool: "x"})
	}()
	awaitPending(t, b, 1)

	c, err := DialSocket(s.Path())
	if err != nil {
		t.Fatalf("DialSocket: %v", err)
	}
	defer c.Close() //nolint:errcheck

	if err := c.Resolve("req-1", false, ""); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	d := <-done
	if d.Approved || d.Reason == "" {
		t.Errorf("decision = %+v, want denial with a default reason", d)
	}
}

func TestSocketResolveUnknownID(t *testing.T) {
	s := newTestSocket(t, NewToolCallBroker(time.Minute))
	c, err := DialSocket(s.Path())
	if err != nil {
		t.Fatalf("DialSocket: %v", err)
	}
	defer c.Close() //nolint:errcheck
	if err := c.Resolve("ghost", true, ""); err == nil {
		t.Fatal("expected error resolving unknown request")
	}
}

func TestSocketStaleFileReplaced(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ac-approval-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "approval.sock")

	// A stale file with no listener behind it (crashed session) is removed
	// and replaced.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("creating stale file: %v", err)
	}

	s, err := ListenSocket(path, NewToolCallBroker(time.Minute))
	if err != nil {
		t.Fatalf("ListenSocket over stale file: %v", err)
	}
	_ = s.Close()
}

func TestSocketLiveListenerRefused(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	s := newTestSocket(t, b)
	if _, err := ListenSocket(s.Path(), b); err == nil {
		t.Fatal("expected error when socket is already in use")
	}
}
