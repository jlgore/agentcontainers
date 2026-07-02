package mcpproxy

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// TestEmitCedar_Golden asserts the structured-membership categories translate to
// the expected Cedar forbid policies, including the per-tool dangerous-flag
// exception carve-out (the one piece of set algebra that is easy to get wrong).
func TestEmitCedar_Golden(t *testing.T) {
	sec := &SecurityPolicy{
		DeniedBinaries:   []string{"dd", "MKFS"}, // case-folded + sorted by ToData
		DangerousFlags:   []string{"--force", "-rf"},
		ToolAllowedFlags: map[string][]string{"tar": {"--force"}},
		ToolBlockedFlags: map[string][]string{"find": {"-delete"}},
	}
	sec.applyDefaults()
	cfg := &config.MCPServerPolicy{
		Shell: &config.ShellCaps{Commands: []config.ShellCommand{
			{Binary: "ls"},
			{Binary: "cat", DenyArgs: []string{"-v"}},
		}},
	}
	cp, err := Compile(sec, cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	got := cp.CedarPolicies

	wants := []string{
		`@id("denied_binaries")`,
		`when { ["dd", "mkfs"].contains(resource.binary_lc) };`,
		// dangerous default excludes tar (it has an effective exception) and
		// applies the full set to everyone else.
		`!(["tar"].contains(resource.binary)) &&`,
		`resource.flags.containsAny(["--force", "-rf"])`,
		// tar's own policy carries the reduced set (--force removed).
		`@id("dangerous_flags::tar")`,
		`when { resource.binary == "tar" && resource.flags.containsAny(["-rf"]) };`,
		`@id("tool_blocked_flags::find")`,
		`resource.flags.containsAny(["-delete"])`,
		`@id("capabilities_allowlist")`,
		`!(["cat", "ls"].contains(resource.binary_lc))`,
		`@id("capabilities_denyargs::cat")`,
		`resource.flags.containsAny(["-v"])`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("emitted Cedar missing %q\n--- full output ---\n%s", w, got)
		}
	}

	// tar must NOT appear under the full default set: its --force is excepted.
	if strings.Contains(got, `resource.binary == "tar" && resource.flags.containsAny(["--force", "-rf"])`) {
		t.Errorf("tar exception was not applied:\n%s", got)
	}

	if !strings.Contains(cp.CedarSchema, "entity Command {") {
		t.Errorf("schema missing Command entity:\n%s", cp.CedarSchema)
	}
}

// TestEmitCedar_EmptyPolicyOmitsForbids confirms a defaults-only policy (no
// denylist, no flags, no shell) emits no forbid rules — nothing to deny.
func TestEmitCedar_EmptyPolicyOmitsForbids(t *testing.T) {
	cp, err := Compile(DefaultSecurityPolicy(), nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if strings.Contains(cp.CedarPolicies, "forbid(") {
		t.Errorf("expected no forbid policies for a defaults-only policy:\n%s", cp.CedarPolicies)
	}
}

// TestNewCedarEvaluator_FailsClosedOnBadPolicy asserts that a malformed emitted
// Cedar policy is a hard, fail-closed construction error — never a silent
// fall-through to a permissive engine.
func TestNewCedarEvaluator_FailsClosedOnBadPolicy(t *testing.T) {
	cp := compileCanonical(t, nil)
	cp.CedarPolicies = "this is not valid cedar @@@"
	if _, err := NewCedarEvaluator(t.Context(), "test-server", cp); err == nil {
		t.Fatal("expected NewCedarEvaluator to fail closed on unparseable policies")
	}
}

// TestCedarMembershipReasons asserts the embedded Cedar engine reconstructs the
// OPA-identical, per-atom membership reason strings (not category-level), so
// audit records are byte-identical across engines.
func TestCedarMembershipReasons(t *testing.T) {
	// engineFor builds an embedded Cedar engine for a security + config policy.
	engineFor := func(sec *SecurityPolicy, cfg *config.MCPServerPolicy) *CedarEvaluator {
		t.Helper()
		cp, err := Compile(sec, cfg)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		e, err := NewCedarEvaluator(t.Context(), "test-server", cp)
		if err != nil {
			t.Fatalf("NewCedarEvaluator: %v", err)
		}
		return e
	}
	checkOn := func(e *CedarEvaluator, binary string, flags []string, wantDeny bool, wantReason string) {
		t.Helper()
		input := map[string]any{
			"parsed":  map[string]any{"binary": binary, "flags": sliceAny(flags)},
			"context": map[string]any{},
		}
		d, err := e.Evaluate(t.Context(), input)
		if err != nil {
			t.Fatalf("Evaluate(%s %v): %v", binary, flags, err)
		}
		if d.Allowed == wantDeny {
			t.Fatalf("%s %v: allowed=%v want deny=%v (reasons %v)", binary, flags, d.Allowed, wantDeny, d.Reasons)
		}
		if wantReason != "" && !containsStr(d.Reasons, wantReason) {
			t.Errorf("%s %v: missing reason %q in %v", binary, flags, wantReason, d.Reasons)
		}
	}

	// Denylist / flag categories (no shell allowlist, so an arbitrary binary
	// is otherwise allowed and we isolate the flag/binary verdict).
	sec := &SecurityPolicy{
		DeniedBinaries:   []string{"dd"},
		DangerousFlags:   []string{"--force", "-rf"},
		ToolAllowedFlags: map[string][]string{"tar": {"--force"}},
		ToolBlockedFlags: map[string][]string{"find": {"-delete"}},
	}
	sec.applyDefaults()
	e := engineFor(sec, nil)
	checkOn(e, "dd", nil, true, "sift.denied_binaries: binary 'dd' is blocked by security policy and cannot be overridden")
	checkOn(e, "sometool", []string{"--force"}, true, "sift.dangerous_flags: flag '--force' is globally dangerous")
	checkOn(e, "tar", []string{"--force"}, false, "")                                                  // excepted for tar
	checkOn(e, "tar", []string{"-rf"}, true, "sift.dangerous_flags: flag '-rf' is globally dangerous") // not excepted
	checkOn(e, "find", []string{"-delete"}, true, "sift.tool_blocked_flags: flag '-delete' is not permitted on 'find'")

	// Capabilities (workspace shell allowlist + per-binary denyArgs).
	caps := engineFor(DefaultSecurityPolicy(), &config.MCPServerPolicy{Shell: &config.ShellCaps{Commands: []config.ShellCommand{
		{Binary: "ls"},
		{Binary: "cat", DenyArgs: []string{"-v"}},
	}}})
	checkOn(caps, "wget", nil, true, "sift.capabilities: binary 'wget' is not in the shell command allowlist")
	checkOn(caps, "cat", []string{"-v"}, true, "sift.capabilities: arg '-v' is denied for 'cat'")
	checkOn(caps, "ls", nil, false, "")
}

// TestCedarVerdicts is the core policy gate: for a corpus of commands, the
// embedded Cedar engine must reach each command's expected verdict.
func TestCedarVerdicts(t *testing.T) {
	cp := compileCanonical(t, nil)
	cedar, err := NewCedarEvaluator(t.Context(), "test-server", cp)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}

	cwd, _ := os.Getwd()
	caseDir := t.TempDir()
	for _, tc := range parityCorpus(t) {
		name := tc.category + "/" + strings.Join(tc.command, "_")
		t.Run(name, func(t *testing.T) {
			cmd := make([]string, len(tc.command))
			for i, tok := range tc.command {
				switch tok {
				case "OUTPUT_INSIDE":
					cmd[i] = filepath.Join(caseDir, "out", "o.csv")
				case "RM_INSIDE_CASE":
					cmd[i] = filepath.Join(caseDir, "f.txt")
				default:
					cmd[i] = tok
				}
			}
			activeCase := ""
			if tc.requiresCase {
				activeCase = caseDir
			}
			input := buildTestInput(DecomposeCommand(cmd, defaultOutputFlags), activeCase, cwd)

			cedarDec, err := cedar.Evaluate(t.Context(), input)
			if err != nil {
				t.Fatalf("cedar Evaluate: %v", err)
			}
			if cedarDec.Allowed != tc.expectAllowed() {
				t.Errorf("verdict on %q: cedar allowed=%v want %v (reasons %v)",
					strings.Join(cmd, " "), cedarDec.Allowed, tc.expectAllowed(), cedarDec.Reasons)
			}
		})
	}
}

func sortedCopy(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
