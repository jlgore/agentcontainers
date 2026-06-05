package approval

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// DefaultToolCallTimeout is how long a tool call waits for a human decision
// before it is denied (SPEC §9 Phase 4: configurable, default 5 minutes).
const DefaultToolCallTimeout = 5 * time.Minute

// ToolCallRequest describes a proxied tools/call awaiting human approval.
type ToolCallRequest struct {
	// ID is the tool call's correlation ID — the same UUID that threads
	// proxy.jsonl, enforcer.jsonl, and approval.jsonl together.
	ID          string    `json:"id"`
	Server      string    `json:"server"`
	Tool        string    `json:"tool"`
	ArgsSummary string    `json:"argsSummary"`
	RequestedAt time.Time `json:"requestedAt"`
}

// ToolCallDecision is the human's verdict on a pending tool call.
type ToolCallDecision struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
	// Decider is the approving/denying user. Empty when the decision was
	// synthesized (timeout, client cancellation).
	Decider string `json:"decider,omitempty"`
}

// pendingToolCall pairs a request with its single-shot decision channel.
type pendingToolCall struct {
	req      ToolCallRequest
	decision chan ToolCallDecision
}

// ToolCallBroker queues tool calls that require human approval and lets any
// connected channel (TTY prompt, Unix socket CLI) resolve them. A request
// that nobody resolves within the timeout is denied — the broker fails
// closed, never open.
type ToolCallBroker struct {
	timeout time.Duration

	mu          sync.Mutex
	pending     map[string]*pendingToolCall
	subscribers []chan ToolCallRequest
}

// NewToolCallBroker creates a broker. A non-positive timeout uses
// DefaultToolCallTimeout.
func NewToolCallBroker(timeout time.Duration) *ToolCallBroker {
	if timeout <= 0 {
		timeout = DefaultToolCallTimeout
	}
	return &ToolCallBroker{
		timeout: timeout,
		pending: make(map[string]*pendingToolCall),
	}
}

// Timeout returns the per-request decision deadline.
func (b *ToolCallBroker) Timeout() time.Duration { return b.timeout }

// Subscribe returns a channel that receives each new pending request.
// Channels are buffered; a slow subscriber misses notifications but can
// always recover the full queue via Pending().
func (b *ToolCallBroker) Subscribe() <-chan ToolCallRequest {
	ch := make(chan ToolCallRequest, 64)
	b.mu.Lock()
	b.subscribers = append(b.subscribers, ch)
	b.mu.Unlock()
	return ch
}

// Request registers the tool call and blocks until a channel resolves it,
// the timeout elapses, or ctx is canceled. The latter two deny.
func (b *ToolCallBroker) Request(ctx context.Context, req ToolCallRequest) ToolCallDecision {
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now().UTC()
	}
	p := &pendingToolCall{req: req, decision: make(chan ToolCallDecision, 1)}

	b.mu.Lock()
	b.pending[req.ID] = p
	subs := make([]chan ToolCallRequest, len(b.subscribers))
	copy(subs, b.subscribers)
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.pending, req.ID)
		b.mu.Unlock()
	}()

	for _, s := range subs {
		select {
		case s <- req:
		default: // slow subscriber; it can poll Pending()
		}
	}

	timer := time.NewTimer(b.timeout)
	defer timer.Stop()

	select {
	case d := <-p.decision:
		return d
	case <-timer.C:
		return ToolCallDecision{Approved: false, Reason: fmt.Sprintf("approval timed out after %s", b.timeout)}
	case <-ctx.Done():
		return ToolCallDecision{Approved: false, Reason: "client disconnected while awaiting approval"}
	}
}

// Pending returns the requests still awaiting a decision, oldest first.
func (b *ToolCallBroker) Pending() []ToolCallRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]ToolCallRequest, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, p.req)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.Before(out[j].RequestedAt) })
	return out
}

// Resolve delivers a decision for a pending request. It errors when the ID
// is unknown — already resolved, timed out, or never existed — so a late
// approval can never apply to the wrong call.
func (b *ToolCallBroker) Resolve(id string, d ToolCallDecision) error {
	b.mu.Lock()
	p := b.pending[id]
	if p != nil {
		delete(b.pending, id)
	}
	b.mu.Unlock()

	if p == nil {
		return fmt.Errorf("approval: no pending request %q (expired or already resolved)", id)
	}
	p.decision <- d
	return nil
}
