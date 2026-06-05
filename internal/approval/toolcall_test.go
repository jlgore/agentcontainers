package approval

import (
	"context"
	"strings"
	"testing"
	"time"
)

// awaitPending polls until the broker shows n pending requests.
func awaitPending(t *testing.T, b *ToolCallBroker, n int) []ToolCallRequest {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := b.Pending(); len(p) == n {
			return p
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d pending requests (have %d)", n, len(b.Pending()))
	return nil
}

func TestBrokerResolveApproves(t *testing.T) {
	b := NewToolCallBroker(time.Minute)

	done := make(chan ToolCallDecision, 1)
	go func() {
		done <- b.Request(context.Background(), ToolCallRequest{
			ID: "req-1", Server: "sift-gateway", Tool: "run_privileged_command", ArgsSummary: "vol3 --write",
		})
	}()

	pending := awaitPending(t, b, 1)
	if pending[0].ID != "req-1" || pending[0].Tool != "run_privileged_command" {
		t.Fatalf("pending = %+v, want req-1/run_privileged_command", pending[0])
	}

	if err := b.Resolve("req-1", ToolCallDecision{Approved: true, Decider: "jgore"}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	d := <-done
	if !d.Approved || d.Decider != "jgore" {
		t.Errorf("decision = %+v, want approved by jgore", d)
	}
	if len(b.Pending()) != 0 {
		t.Errorf("pending after resolve = %d, want 0", len(b.Pending()))
	}
}

func TestBrokerTimeoutDenies(t *testing.T) {
	b := NewToolCallBroker(50 * time.Millisecond)
	d := b.Request(context.Background(), ToolCallRequest{ID: "req-1", Tool: "x"})
	if d.Approved {
		t.Fatal("expected timeout denial")
	}
	if !strings.Contains(d.Reason, "timed out") {
		t.Errorf("reason = %q, want timeout reason", d.Reason)
	}
	if d.Decider != "" {
		t.Errorf("decider = %q, want empty for synthesized denial", d.Decider)
	}
}

func TestBrokerContextCancelDenies(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan ToolCallDecision, 1)
	go func() {
		done <- b.Request(ctx, ToolCallRequest{ID: "req-1", Tool: "x"})
	}()
	awaitPending(t, b, 1)
	cancel()
	d := <-done
	if d.Approved {
		t.Fatal("expected denial on context cancellation")
	}
	if !strings.Contains(d.Reason, "disconnected") {
		t.Errorf("reason = %q, want client-disconnect reason", d.Reason)
	}
}

func TestBrokerResolveUnknownID(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	if err := b.Resolve("ghost", ToolCallDecision{Approved: true}); err == nil {
		t.Fatal("expected error resolving unknown request")
	}
}

func TestBrokerSubscribeReceivesRequests(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	sub := b.Subscribe()
	go b.Request(context.Background(), ToolCallRequest{ID: "req-1", Tool: "x"})
	select {
	case req := <-sub:
		if req.ID != "req-1" {
			t.Errorf("subscribed request ID = %q, want req-1", req.ID)
		}
		_ = b.Resolve("req-1", ToolCallDecision{Approved: false, Reason: "test"})
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber never notified")
	}
}

func TestTTYChannelApprove(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	in := strings.NewReader("a\n")
	var out strings.Builder
	ch := NewTTYChannelWith(b, in, &out, "jgore")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ch.Run(ctx)

	d := b.Request(context.Background(), ToolCallRequest{
		ID: "req-1", Server: "sift-gateway", Tool: "run_privileged_command", ArgsSummary: "vol3 --write",
	})
	if !d.Approved || d.Decider != "jgore" {
		t.Fatalf("decision = %+v, want approved by jgore", d)
	}
	for _, want := range []string{"sift-gateway", "run_privileged_command", "vol3 --write", "req-1"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("prompt output missing %q:\n%s", want, out.String())
		}
	}
}

func TestTTYChannelDenyWithReason(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	in := strings.NewReader("d\nwrites to evidence not permitted\n")
	var out strings.Builder
	ch := NewTTYChannelWith(b, in, &out, "jgore")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ch.Run(ctx)

	d := b.Request(context.Background(), ToolCallRequest{ID: "req-1", Tool: "x"})
	if d.Approved {
		t.Fatal("expected denial")
	}
	if d.Reason != "writes to evidence not permitted" {
		t.Errorf("reason = %q", d.Reason)
	}
}

func TestTTYChannelInvalidThenValid(t *testing.T) {
	b := NewToolCallBroker(time.Minute)
	in := strings.NewReader("bogus\na\n")
	var out strings.Builder
	ch := NewTTYChannelWith(b, in, &out, "jgore")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ch.Run(ctx)

	d := b.Request(context.Background(), ToolCallRequest{ID: "req-1", Tool: "x"})
	if !d.Approved {
		t.Fatalf("decision = %+v, want approved after retry", d)
	}
	if !strings.Contains(out.String(), "Invalid choice") {
		t.Error("expected invalid-choice feedback")
	}
}
