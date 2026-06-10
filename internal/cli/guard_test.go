package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hookOutput is the Claude Code PreToolUse hook output schema.
type hookOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func TestEmitDecisionSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := emitDecision(&buf, "deny", "nope"); err != nil {
		t.Fatalf("emitDecision: %v", err)
	}
	var out hookOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if out.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q", out.HookSpecificOutput.HookEventName)
	}
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q", out.HookSpecificOutput.PermissionDecision)
	}
	if out.HookSpecificOutput.PermissionDecisionReason != "nope" {
		t.Errorf("reason = %q", out.HookSpecificOutput.PermissionDecisionReason)
	}
}

// The hook must fail CLOSED: an unreachable guard socket yields a deny.
func TestGuardHookFailsClosed(t *testing.T) {
	cmd := newGuardHookCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`))
	cmd.SetArgs([]string{"--socket", filepath.Join(t.TempDir(), "absent.sock"), "--timeout", "1s"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var parsed hookOutput
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out.String())
	}
	if parsed.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("decision = %q, want deny (fail-closed)", parsed.HookSpecificOutput.PermissionDecision)
	}
}

func TestInstallHookPrint(t *testing.T) {
	cmd := newGuardInstallHookCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var frag map[string]any
	if err := json.Unmarshal(out.Bytes(), &frag); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out.String())
	}
	hooks, ok := frag["hooks"].(map[string]any)
	if !ok || hooks["PreToolUse"] == nil {
		t.Fatalf("missing hooks.PreToolUse in %s", out.String())
	}
}

func TestInstallHookMergeIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")

	run := func() string {
		cmd := newGuardInstallHookCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--write", path})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
		return out.String()
	}

	run()
	second := run()
	if !strings.Contains(second, "already present") {
		t.Errorf("second install should be a no-op, got: %s", second)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var settings struct {
		Hooks struct {
			PreToolUse []any `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if len(settings.Hooks.PreToolUse) != 1 {
		t.Fatalf("PreToolUse entries = %d, want 1 (no duplicate)", len(settings.Hooks.PreToolUse))
	}
}
