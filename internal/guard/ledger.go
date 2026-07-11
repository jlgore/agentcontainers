package guard

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// pendingEscalation is an inline escalation awaiting an execution report. In
// inline mode the guard returns "ask" (Claude Code renders its native prompt)
// instead of blocking on a human; the agent's PostToolUse hook later reports
// that the tool ran, which resolves the entry to "executed". Anything left
// unresolved past the grace window is reaped as denied-inferred.
type pendingEscalation struct {
	escalationID string
	toolUseID    string
	tool         string
	subject      string
	sessionID    string
	askedAt      time.Time
}

// ledger tracks inline escalations keyed by tool_use_id. Claude Code emits the
// same tool_use_id on both the PreToolUse and PostToolUse payloads for a tool
// call (verified empirically), so the key is exact and unique — no correlation
// hashing or per-key collision handling is needed. onReap is invoked for each
// entry that expires unresolved; the serve layer wires it to the
// denied-inferred audit record.
type ledger struct {
	mu      sync.Mutex
	grace   time.Duration
	pending map[string]*pendingEscalation
	log     *zap.Logger
	onReap  func(*pendingEscalation)
	now     func() time.Time // injectable for tests
}

func newLedger(grace time.Duration, log *zap.Logger, onReap func(*pendingEscalation)) *ledger {
	if log == nil {
		log = zap.NewNop()
	}
	if grace <= 0 {
		grace = 5 * time.Minute
	}
	return &ledger{
		grace:   grace,
		pending: make(map[string]*pendingEscalation),
		log:     log,
		onReap:  onReap,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// add records a newly-issued inline escalation.
func (l *ledger) add(p *pendingEscalation) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending[p.toolUseID] = p
}

// resolve pops the pending entry for a tool_use_id (it executed = was
// approved). The bool is false when there is no matching pending escalation —
// e.g. a PostToolUse for a policy-allowed tool that was never escalated.
func (l *ledger) resolve(toolUseID string) (*pendingEscalation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, ok := l.pending[toolUseID]
	if ok {
		delete(l.pending, toolUseID)
	}
	return p, ok
}

// reapExpired removes and returns entries older than the grace window.
func (l *ledger) reapExpired() []*pendingEscalation {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.grace)
	var reaped []*pendingEscalation
	for id, p := range l.pending {
		if p.askedAt.Before(cutoff) {
			reaped = append(reaped, p)
			delete(l.pending, id)
		}
	}
	return reaped
}

// drainAll removes and returns every pending entry, for shutdown.
func (l *ledger) drainAll() []*pendingEscalation {
	l.mu.Lock()
	defer l.mu.Unlock()
	var all []*pendingEscalation
	for id, p := range l.pending {
		all = append(all, p)
		delete(l.pending, id)
	}
	return all
}

// reconcileLoop reaps expired entries on a ticker until ctx is canceled, then
// drains everything remaining — so in-flight escalations are recorded (as
// denied-inferred) rather than vanishing when the guard shuts down.
func (l *ledger) reconcileLoop(ctx context.Context) {
	tick := l.grace / 4
	if tick < time.Second {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, p := range l.drainAll() {
				if l.onReap != nil {
					l.onReap(p)
				}
			}
			return
		case <-t.C:
			for _, p := range l.reapExpired() {
				if l.onReap != nil {
					l.onReap(p)
				}
			}
		}
	}
}
