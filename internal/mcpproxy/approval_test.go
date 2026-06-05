package mcpproxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap/zaptest"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// approvalCfg builds a remote backend whose echo tool requires approval.
func approvalCfg(url string) *config.AgentContainer {
	return remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {
			Type: "remote",
			URL:  url,
			Policy: &config.MCPServerPolicy{
				RequireApproval: []string{"echo"},
			},
		},
	})
}

// newApprovalProxy builds a proxy with the given broker and returns it plus
// its audit dir.
func newApprovalProxy(t *testing.T, url string, broker *approval.ToolCallBroker) *Proxy {
	t.Helper()
	p, err := New(t.Context(), Deps{Logger: zaptest.NewLogger(t)}, approvalCfg(url), "apprsess01", &Options{
		AuditDir: t.TempDir(),
		Approval: broker,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(context.Background()) })
	return p
}

// autoResolve resolves every pending request with the given decision as it
// arrives.
func autoResolve(t *testing.T, broker *approval.ToolCallBroker, d approval.ToolCallDecision) {
	t.Helper()
	sub := broker.Subscribe()
	go func() {
		for req := range sub {
			_ = broker.Resolve(req.ID, d)
		}
	}()
}

func TestProxyRequireApprovalApproved(t *testing.T) {
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	broker := approval.NewToolCallBroker(time.Minute)
	autoResolve(t, broker, approval.ToolCallDecision{Approved: true, Decider: "jgore"})

	p := newApprovalProxy(t, url, broker)
	session := connectClient(t, p)

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"msg": "hi"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected approved call to succeed, got error result: %+v", res.Content)
	}

	// proxy.jsonl: one allow entry flagged approvalRequired.
	entries, err := audit.ReadLog(p.AuditPath())
	if err != nil {
		t.Fatalf("ReadLog(proxy): %v", err)
	}
	if len(entries) != 1 || entries[0].Verdict != audit.VerdictAllow {
		t.Fatalf("proxy entries = %+v, want one allow", entries)
	}
	if req, _ := entries[0].Metadata["approvalRequired"].(bool); !req {
		t.Error("proxy metadata.approvalRequired = false, want true")
	}

	// approval.jsonl: the authoritative decision record (SPEC §7.3).
	decisions, err := audit.ReadLog(p.ApprovalAuditPath())
	if err != nil {
		t.Fatalf("ReadLog(approval): %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected 1 approval entry, got %d", len(decisions))
	}
	d := decisions[0]
	if d.EventType != audit.EventApprovalDecision {
		t.Errorf("eventType = %q, want approval_decision", d.EventType)
	}
	if d.Verdict != audit.VerdictAllow {
		t.Errorf("verdict = %q, want allow", d.Verdict)
	}
	if d.Actor.Type != "user" || d.Actor.Name != "jgore" {
		t.Errorf("actor = %+v, want {user jgore}", d.Actor)
	}
	if server, _ := d.Metadata["server"].(string); server != "backend-a" {
		t.Errorf("metadata.server = %v, want backend-a", d.Metadata["server"])
	}
	if _, ok := d.Metadata["promptDurationMs"].(float64); !ok {
		t.Errorf("metadata.promptDurationMs = %#v, want number", d.Metadata["promptDurationMs"])
	}
	// Approval and proxy entries correlate by ID across files.
	if d.Metadata["correlationId"] != entries[0].Metadata["correlationId"] {
		t.Error("approval and proxy correlationId differ")
	}
	if err := audit.ValidateChain(decisions); err != nil {
		t.Errorf("ValidateChain(approval): %v", err)
	}
}

func TestProxyRequireApprovalDenied(t *testing.T) {
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	broker := approval.NewToolCallBroker(time.Minute)
	autoResolve(t, broker, approval.ToolCallDecision{Approved: false, Reason: "writes to evidence not permitted", Decider: "jgore"})

	p := newApprovalProxy(t, url, broker)
	session := connectClient(t, p)

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected denied call to return isError result")
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "Approval denied") || !strings.Contains(text, "writes to evidence not permitted") {
		t.Errorf("denial text = %q", text)
	}

	entries, err := audit.ReadLog(p.AuditPath())
	if err != nil {
		t.Fatalf("ReadLog(proxy): %v", err)
	}
	if len(entries) != 1 || entries[0].Verdict != audit.VerdictDeny {
		t.Fatalf("proxy entries = %+v, want one deny", entries)
	}

	decisions, err := audit.ReadLog(p.ApprovalAuditPath())
	if err != nil {
		t.Fatalf("ReadLog(approval): %v", err)
	}
	if len(decisions) != 1 || decisions[0].Verdict != audit.VerdictDeny {
		t.Fatalf("approval entries = %+v, want one deny", decisions)
	}
	if reason, _ := decisions[0].Metadata["reason"].(string); reason != "writes to evidence not permitted" {
		t.Errorf("metadata.reason = %v", decisions[0].Metadata["reason"])
	}
}

func TestProxyRequireApprovalTimeout(t *testing.T) {
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	// Nobody resolves: the gate must deny on its own.
	broker := approval.NewToolCallBroker(100 * time.Millisecond)

	p := newApprovalProxy(t, url, broker)
	session := connectClient(t, p)

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected timed-out call to return isError result")
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "timed out") {
		t.Errorf("denial text = %q, want timeout reason", text)
	}

	// Synthesized denials are attributed to the system, not a person.
	decisions, err := audit.ReadLog(p.ApprovalAuditPath())
	if err != nil {
		t.Fatalf("ReadLog(approval): %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected 1 approval entry, got %d", len(decisions))
	}
	if decisions[0].Actor.Type != "system" {
		t.Errorf("actor = %+v, want system actor for timeout", decisions[0].Actor)
	}
}

func TestProxyRequireApprovalWithoutBrokerFailsStartup(t *testing.T) {
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	_, err := New(t.Context(), Deps{Logger: zaptest.NewLogger(t)}, approvalCfg(url), "apprsess02", &Options{
		AuditDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected startup error: requireApproval without a broker")
	}
	if !strings.Contains(err.Error(), "requireApproval") {
		t.Errorf("error = %v, want requireApproval mention", err)
	}
}

func TestProxyNoApprovalNoApprovalAudit(t *testing.T) {
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: url},
	})
	p := newTestProxy(t, cfg, Deps{})
	if got := p.ApprovalAuditPath(); got != "" {
		t.Errorf("ApprovalAuditPath = %q, want empty when nothing requires approval", got)
	}
}
