package mcpproxy

import (
	"os"
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
// case in the capability matrix must reach its declared verdict, AND the
// embedded Cedar engine (default) and the legacy OPA engine must agree. This is
// the proof that capabilities are allowed only explicitly — model-free and
// engine-parity-checked, so it can gate every PR.
func TestCapabilityMatrixOracle(t *testing.T) {
	fx := loadCapabilityFixture(t)
	cp := fx.compile(t)

	cedar, err := NewCedarEvaluator(t.Context(), "test-server", cp)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}
	opa, err := NewEvaluator(t.Context(), "test-server", cp)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
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
			opaDec, err := opa.Evaluate(t.Context(), input)
			if err != nil {
				t.Fatalf("opa Evaluate: %v", err)
			}

			// 1) The verdict must match the fixture's explicit expectation.
			if cedarDec.Allowed != wantAllow {
				t.Errorf("cedar allowed=%v want %v (reasons %v)", cedarDec.Allowed, wantAllow, cedarDec.Reasons)
			}
			// 2) Both engines must agree — the Cedar-first migration's core gate.
			if cedarDec.Allowed != opaDec.Allowed {
				t.Errorf("ENGINE MISMATCH: cedar allowed=%v opa allowed=%v (cedar %v / opa %v)",
					cedarDec.Allowed, opaDec.Allowed, cedarDec.Reasons, opaDec.Reasons)
			}
			if a, b := sortedCopy(cedarDec.Reasons), sortedCopy(opaDec.Reasons); !equalStrings(a, b) {
				t.Errorf("REASON MISMATCH:\n cedar: %v\n opa:   %v", a, b)
			}
			// 3) A deny must fire for the RIGHT mechanism, not incidentally.
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

func anyReasonContains(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}
