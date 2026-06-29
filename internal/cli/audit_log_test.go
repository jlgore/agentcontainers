package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/identity"
)

func TestAuditListEmpty(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	err := runAuditList(&buf, dir)
	if err != nil {
		t.Fatalf("runAuditList: %v", err)
	}
	if !strings.Contains(buf.String(), "No audit logs found") {
		t.Errorf("expected 'No audit logs found', got %q", buf.String())
	}
}

func TestAuditList(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger("sess-abc", audit.WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := l.Log(audit.EventLifecycle, audit.Actor{Type: "system", Name: "init"}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()

	var buf bytes.Buffer
	err = runAuditList(&buf, dir)
	if err != nil {
		t.Fatalf("runAuditList: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "sess-abc") {
		t.Errorf("expected session ID in output, got %q", output)
	}
	if !strings.Contains(output, "1") {
		t.Errorf("expected entry count in output, got %q", output)
	}
}

func TestAuditShow(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger("show-test", audit.WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	actor := audit.Actor{Type: "agent", Name: "claude"}
	if err := l.Log(audit.EventExec, actor, audit.WithCommand("ls"), audit.WithVerdict(audit.VerdictAllow)); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Log(audit.EventApproval, actor, audit.WithVerdict(audit.VerdictPrompt)); err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()

	var buf bytes.Buffer
	err = runAuditShow(&buf, dir, "show-test")
	if err != nil {
		t.Fatalf("runAuditShow: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "exec") {
		t.Errorf("expected 'exec' event type in output, got %q", output)
	}
	if !strings.Contains(output, "approval") {
		t.Errorf("expected 'approval' event type in output, got %q", output)
	}
	if !strings.Contains(output, "agent/claude") {
		t.Errorf("expected 'agent/claude' actor in output, got %q", output)
	}
}

func TestAuditVerify(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger("verify-test", audit.WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	actor := audit.Actor{Type: "system", Name: "enforcer"}
	for i := 0; i < 3; i++ {
		if err := l.Log(audit.EventEnforcement, actor, audit.WithVerdict(audit.VerdictDeny)); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	_ = l.Close()

	var buf bytes.Buffer
	err = runAuditVerify(&buf, dir, "verify-test", false)
	if err != nil {
		t.Fatalf("runAuditVerify: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "OK") {
		t.Errorf("expected 'OK' in output, got %q", output)
	}
	if !strings.Contains(output, "3 entries") {
		t.Errorf("expected '3 entries' in output, got %q", output)
	}
}

func TestAuditVerifySignatures(t *testing.T) {
	dir := t.TempDir()
	ks, err := identity.LoadOrCreateKeyStore(filepath.Join(t.TempDir(), "id.pem"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	l, err := audit.NewLogger("sig-test", audit.WithDir(dir), audit.WithSigner(ks))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	actor := audit.Actor{Type: "tool", Name: "run"}
	for range 3 {
		if err := l.Log(audit.EventToolCall, actor, audit.WithVerdict(audit.VerdictAllow)); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	_ = l.Close()

	// Signed chain verifies.
	var buf bytes.Buffer
	if err := runAuditVerify(&buf, dir, "sig-test", true); err != nil {
		t.Fatalf("runAuditVerify: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "3 signed entries verified") {
		t.Errorf("expected signed verification, got %q", out)
	}

	// Tamper one entry on disk; signature verification must fail.
	path := filepath.Join(dir, "sig-test.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"verdict":"allow"`), []byte(`"verdict":"deny"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("tamper replacement did not apply")
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The hash chain itself breaks first (verdict is hashed), which is a valid
	// detection path; assert verify fails either way.
	var buf2 bytes.Buffer
	if err := runAuditVerify(&buf2, dir, "sig-test", true); err == nil {
		t.Fatalf("expected tampered log to fail verification, output: %q", buf2.String())
	}
}

func TestAuditExport(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.NewLogger("export-test", audit.WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	actor := audit.Actor{Type: "tool", Name: "bash"}
	if err := l.Log(audit.EventExec, actor, audit.WithCommand("echo hi")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := l.Log(audit.EventExec, actor, audit.WithCommand("pwd")); err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()

	var buf bytes.Buffer
	err = runAuditExport(&buf, dir, "export-test")
	if err != nil {
		t.Fatalf("runAuditExport: %v", err)
	}

	// Each line should be valid JSON.
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for i, line := range lines {
		var entry audit.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d: invalid JSON: %v", i, err)
		}
		if entry.EventType != audit.EventExec {
			t.Errorf("line %d: eventType = %q, want %q", i, entry.EventType, audit.EventExec)
		}
	}
}

func TestAuditFlagDefaults(t *testing.T) {
	cmd := newAuditCmd()

	subs := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subs[sub.Name()] = true
	}

	for _, want := range []string{"list", "show", "verify", "export"} {
		if !subs[want] {
			t.Errorf("expected subcommand %q, not found in %v", want, subs)
		}
	}
}
