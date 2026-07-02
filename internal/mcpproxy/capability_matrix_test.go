package mcpproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"gopkg.in/yaml.v3"
)

// capabilityFixture is the parsed form of testdata/capability-matrix.yaml — the
// shared, language-neutral capability matrix consumed by the deterministic
// oracle here and (eventually) the on-VM behavioral runner. See the design at
// docs project/test-matrix.
type capabilityFixture struct {
	Policy struct {
		Shell []struct {
			Binary   string   `yaml:"binary"`
			DenyArgs []string `yaml:"denyArgs"`
		} `yaml:"shell"`
		DeniedBinaries   []string            `yaml:"denied_binaries"`
		DangerousFlags   []string            `yaml:"dangerous_flags"`
		ToolAllowedFlags map[string][]string `yaml:"tool_allowed_flags"`
		ToolBlockedFlags map[string][]string `yaml:"tool_blocked_flags"`
	} `yaml:"policy"`
	Cases []capabilityCase `yaml:"cases"`
}

type capabilityCase struct {
	Class          string   `yaml:"class"`
	Name           string   `yaml:"name"`
	Command        []string `yaml:"command"`
	Expect         string   `yaml:"expect"` // "allow" | "deny"
	ReasonContains string   `yaml:"reasonContains"`
}

func loadCapabilityFixture(t *testing.T) capabilityFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/capability-matrix.yaml")
	if err != nil {
		t.Fatalf("read capability-matrix.yaml: %v", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // typos in the fixture are test failures, not silent drops
	var fx capabilityFixture
	if err := dec.Decode(&fx); err != nil {
		t.Fatalf("parse capability-matrix.yaml: %v", err)
	}
	return fx
}

// compile turns the fixture's policy section into a CompiledPolicy the same way
// a container server with a security.yaml + shell caps would.
func (fx capabilityFixture) compile(t *testing.T) *CompiledPolicy {
	t.Helper()
	sec := &SecurityPolicy{
		DeniedBinaries:   fx.Policy.DeniedBinaries,
		DangerousFlags:   fx.Policy.DangerousFlags,
		ToolAllowedFlags: fx.Policy.ToolAllowedFlags,
		ToolBlockedFlags: fx.Policy.ToolBlockedFlags,
	}
	sec.applyDefaults()

	cmds := make([]config.ShellCommand, len(fx.Policy.Shell))
	for i, s := range fx.Policy.Shell {
		cmds[i] = config.ShellCommand{Binary: s.Binary, DenyArgs: s.DenyArgs}
	}
	cfg := &config.MCPServerPolicy{Shell: &config.ShellCaps{Commands: cmds}}

	cp, err := Compile(sec, cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return cp
}

// TestCapabilityMatrixOracle is the Layer-1 deterministic policy gate: every
// case in the capability matrix must reach its declared verdict through the
// embedded Cedar engine. This is the proof that capabilities are allowed only
// explicitly — model-free, so it can gate every PR.
func TestCapabilityMatrixOracle(t *testing.T) {
	fx := loadCapabilityFixture(t)
	cp := fx.compile(t)

	cedar, err := NewCedarEvaluator(t.Context(), "test-server", cp)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}

	cwd, _ := os.Getwd()
	seen := map[string]bool{}

	for _, tc := range fx.Cases {
		seen[tc.Class] = true
		wantAllow := tc.Expect == "allow"
		if tc.Expect != "allow" && tc.Expect != "deny" {
			t.Fatalf("%s/%s: invalid expect %q (want allow|deny)", tc.Class, tc.Name, tc.Expect)
		}
		t.Run(tc.Class+"/"+tc.Name, func(t *testing.T) {
			input := buildTestInput(DecomposeCommand(tc.Command, defaultOutputFlags), "", cwd)

			cedarDec, err := cedar.Evaluate(t.Context(), input)
			if err != nil {
				t.Fatalf("cedar Evaluate: %v", err)
			}

			// 1) The verdict must match the fixture's explicit expectation.
			if cedarDec.Allowed != wantAllow {
				t.Errorf("cedar allowed=%v want %v (reasons %v)", cedarDec.Allowed, wantAllow, cedarDec.Reasons)
			}
			// 2) A deny must fire for the RIGHT mechanism, not incidentally.
			if !wantAllow && tc.ReasonContains != "" {
				if !anyReasonContains(cedarDec.Reasons, tc.ReasonContains) {
					t.Errorf("missing expected reason %q in %v", tc.ReasonContains, cedarDec.Reasons)
				}
			}
		})
	}

	// Coverage guard: the policy-decided classes must all be present, so a future
	// edit can't silently drop a capability class from the matrix.
	for _, class := range []string{"C1", "C2", "C3", "C4", "C5", "C6"} {
		if !seen[class] {
			t.Errorf("capability matrix is missing class %s", class)
		}
	}
}

// TestCapabilityMatrixGuardPath proves the guard's policy loader
// (LoadGuardPolicyYAML, the engine behind `agentcontainer guard serve
// --security-yaml`) compiles the SAME decisions as the Layer-1 oracle when fed
// the fixture's `policy` block alone — the exact file the on-VM Phase 4 runner
// derives via `yq '.policy' capability-matrix.yaml`. This is the CI guarantee
// that the live guard cell cannot drift from the oracle: same fixture, same
// verdicts, through the production guard code path (Cedar) rather than the
// test's own compile() helper.
func TestCapabilityMatrixGuardPath(t *testing.T) {
	raw, err := os.ReadFile("testdata/capability-matrix.yaml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// Extract just the `policy:` block, exactly like `yq '.policy'` does on the VM.
	var whole map[string]any
	if err := yaml.Unmarshal(raw, &whole); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	policyOnly, err := yaml.Marshal(whole["policy"])
	if err != nil {
		t.Fatalf("marshal policy block: %v", err)
	}
	path := filepath.Join(t.TempDir(), "guard-policy.yaml")
	if err := os.WriteFile(path, policyOnly, 0o644); err != nil {
		t.Fatalf("write guard policy: %v", err)
	}

	sec, cfg, err := LoadGuardPolicyYAML(path)
	if err != nil {
		t.Fatalf("LoadGuardPolicyYAML: %v", err)
	}
	if cfg == nil || cfg.Shell == nil || len(cfg.Shell.Commands) == 0 {
		t.Fatalf("guard policy carried no shell allowlist (cfg=%+v) — C1/C2/C6 would not enforce", cfg)
	}
	cp, err := Compile(sec, cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cedar, err := NewCedarEvaluator(t.Context(), "guard", cp)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}

	fx := loadCapabilityFixture(t)
	cwd, _ := os.Getwd()
	for _, tc := range fx.Cases {
		wantAllow := tc.Expect == "allow"
		t.Run(tc.Class+"/"+tc.Name, func(t *testing.T) {
			input := buildTestInput(DecomposeCommand(tc.Command, defaultOutputFlags), "", cwd)
			dec, err := cedar.Evaluate(t.Context(), input)
			if err != nil {
				t.Fatalf("cedar Evaluate: %v", err)
			}
			if dec.Allowed != wantAllow {
				t.Errorf("guard-path allowed=%v want %v (reasons %v)", dec.Allowed, wantAllow, dec.Reasons)
			}
			if !wantAllow && tc.ReasonContains != "" && !anyReasonContains(dec.Reasons, tc.ReasonContains) {
				t.Errorf("guard-path missing expected reason %q in %v", tc.ReasonContains, dec.Reasons)
			}
		})
	}
}

func anyReasonContains(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}
