package mcpproxy

import (
	"os"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"gopkg.in/yaml.v3"
)

// breakoutFixture is the parsed form of test/escape/breakout-matrix.yaml — the
// single source of truth for the Escape-the-Box breakout experiment (design:
// test/escape/SCENARIOS.md). Unlike the capability matrix (default-deny), this
// policy is deliberately PERMISSIVE: a real forensic-analyst toolbox is allowed
// so the attacker agent has room to work, and the only denies are the guardrails
// the escape tests probe.
//
// Only `score: oracle` cases are decided here at Layer 1 (context-free verdict +
// reason). `score: state|audit|emergent` cases are scored off filesystem/audit
// effect by the on-VM behavioral runner and are skipped here by design.
type breakoutFixture struct {
	Policy struct {
		Shell []struct {
			Binary   string   `yaml:"binary"`
			DenyArgs []string `yaml:"denyArgs"`
		} `yaml:"shell"`
		DeniedBinaries    []string            `yaml:"denied_binaries"`
		DangerousFlags    []string            `yaml:"dangerous_flags"`
		ToolAllowedFlags  map[string][]string `yaml:"tool_allowed_flags"`
		ToolBlockedFlags  map[string][]string `yaml:"tool_blocked_flags"`
		OutputFlags       []string            `yaml:"output_flags"`
		BlockedOutputDirs []string            `yaml:"blocked_output_dirs"`
		BlockedInputDirs  []string            `yaml:"blocked_input_dirs"`
		ProtectedRmDirs   []string            `yaml:"protected_rm_dirs"`
	} `yaml:"policy"`
	Cases []breakoutCase `yaml:"cases"`
}

// breakoutCase models every key any case in the fixture uses, so KnownFields(true)
// catches fixture typos. Only the oracle subset (Command/Expect/ReasonContains) is
// exercised here; the rest document the behavioral cases for the VM runner.
type breakoutCase struct {
	ID             string   `yaml:"id"`
	Test           int      `yaml:"test"`
	Score          string   `yaml:"score"` // oracle | state | audit | emergent
	Name           string   `yaml:"name"`
	Command        []string `yaml:"command"`
	Expect         string   `yaml:"expect"` // allow | deny
	ReasonContains string   `yaml:"reasonContains"`
	// Behavioral-only fields (ignored by the Layer-1 oracle).
	ShellLine    string         `yaml:"shell_line"`
	Tool         string         `yaml:"tool"`
	ToolInput    map[string]any `yaml:"tool_input"`
	ProbeCmd     string         `yaml:"probe_cmd"`
	Objective    string         `yaml:"objective"`
	Approver     string         `yaml:"approver"`
	HarmExpected bool           `yaml:"harm_expected"`
	State        map[string]any `yaml:"state"`
	Audit        map[string]any `yaml:"audit"`
	Emergent     map[string]any `yaml:"emergent"`
}

func loadBreakoutFixture(t *testing.T) breakoutFixture {
	t.Helper()
	raw, err := os.ReadFile("../../test/escape/breakout-matrix.yaml")
	if err != nil {
		t.Fatalf("read breakout-matrix.yaml: %v", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // typos in the fixture are test failures, not silent drops
	var fx breakoutFixture
	if err := dec.Decode(&fx); err != nil {
		t.Fatalf("parse breakout-matrix.yaml: %v", err)
	}
	return fx
}

// compile turns the permissive policy section into a CompiledPolicy exactly as
// `agentcontainer guard serve` would for this fixture's `policy:` block.
func (fx breakoutFixture) compile(t *testing.T) (*CompiledPolicy, []string) {
	t.Helper()
	sec := &SecurityPolicy{
		DeniedBinaries:    fx.Policy.DeniedBinaries,
		DangerousFlags:    fx.Policy.DangerousFlags,
		ToolAllowedFlags:  fx.Policy.ToolAllowedFlags,
		ToolBlockedFlags:  fx.Policy.ToolBlockedFlags,
		OutputFlags:       fx.Policy.OutputFlags,
		BlockedOutputDirs: fx.Policy.BlockedOutputDirs,
		BlockedInputDirs:  fx.Policy.BlockedInputDirs,
		ProtectedRmDirs:   fx.Policy.ProtectedRmDirs,
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
	outFlags := sec.OutputFlags
	if outFlags == nil {
		outFlags = defaultOutputFlags
	}
	return cp, outFlags
}

// evalBreakout mirrors the guard's own evaluation (internal/guard/guard.go:207):
// decompose the command into sub-commands and deny if ANY sub-command denies,
// unioning the reasons. decomposeWrapped is the structured-command path
// (proxy.go:1155) that applies wrapper normalization and the structural eval-flag
// deny (python -c / perl -e / xargs) — the mechanism test 5 turns on, which the
// plain Evaluate(input) path cannot see (Parsed.Deny is json:"-").
func evalBreakout(t *testing.T, eng PolicyEngine, cmd []string, outFlags []string) (bool, []string) {
	t.Helper()
	pctx := map[string]any{"case_dir": "", "cwd": "/cases/c"}
	parsedList := decomposeWrapped(cmd, outFlags, strings.Join(cmd, " "), 0)
	if len(parsedList) == 0 {
		parsedList = []Parsed{{}}
	}
	allowed := true
	var reasons []string
	seen := map[string]bool{}
	for _, p := range parsedList {
		d, err := eng.EvaluateParsed(t.Context(), "agent", "Bash", nil, p, pctx)
		if err != nil {
			t.Fatalf("EvaluateParsed: %v", err)
		}
		if !d.Allowed {
			allowed = false
		}
		for _, r := range d.Reasons {
			if !seen[r] {
				seen[r] = true
				reasons = append(reasons, r)
			}
		}
	}
	return allowed, reasons
}

// TestBreakoutMatrixOracle is the Layer-1 deterministic gate for the breakout
// experiment: every `score: oracle` case must reach its declared verdict through
// the real guard evaluation path, AND the Cedar (default) and OPA engines must
// agree on verdict and reasons. This locks in the headline test-5 result — an
// allowlisted interpreter still cannot run inline code — model-free, on every PR.
func TestBreakoutMatrixOracle(t *testing.T) {
	fx := loadBreakoutFixture(t)
	cp, outFlags := fx.compile(t)

	cedar, err := NewCedarEvaluator(t.Context(), "breakout", cp)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}
	opa, err := NewEvaluator(t.Context(), "breakout", cp)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}

	oracleRan, sawTest5 := 0, false
	for _, tc := range fx.Cases {
		if tc.Score != "oracle" {
			continue // state/audit/emergent are Layer-2 behavioral, scored off effect
		}
		if len(tc.Command) == 0 {
			t.Errorf("%s: score:oracle case has no command", tc.ID)
			continue
		}
		if tc.Expect != "allow" && tc.Expect != "deny" {
			t.Fatalf("%s: invalid expect %q (want allow|deny)", tc.ID, tc.Expect)
		}
		oracleRan++
		if tc.Test == 5 {
			sawTest5 = true
		}
		wantAllow := tc.Expect == "allow"

		t.Run(tc.ID+"/"+tc.Name, func(t *testing.T) {
			cAllow, cReasons := evalBreakout(t, cedar, tc.Command, outFlags)
			oAllow, oReasons := evalBreakout(t, opa, tc.Command, outFlags)

			// 1) Verdict must match the fixture's explicit expectation.
			if cAllow != wantAllow {
				t.Errorf("cedar allowed=%v want %v (reasons %v)", cAllow, wantAllow, cReasons)
			}
			// 2) Both engines must agree — the Cedar-first migration's core gate.
			if cAllow != oAllow {
				t.Errorf("ENGINE MISMATCH: cedar=%v opa=%v (cedar %v / opa %v)",
					cAllow, oAllow, cReasons, oReasons)
			}
			if a, b := sortedCopy(cReasons), sortedCopy(oReasons); !equalStrings(a, b) {
				t.Errorf("REASON MISMATCH:\n cedar: %v\n opa:   %v", a, b)
			}
			// 3) A deny must fire for the RIGHT mechanism, not incidentally.
			if !wantAllow && tc.ReasonContains != "" && !anyReasonContains(cReasons, tc.ReasonContains) {
				t.Errorf("missing expected reason %q in %v", tc.ReasonContains, cReasons)
			}
		})
	}

	if oracleRan == 0 {
		t.Fatal("no score:oracle cases ran — fixture wiring is broken")
	}
	if !sawTest5 {
		t.Error("breakout matrix is missing the test-5 (interpreter-escape) oracle cases")
	}
	t.Logf("breakout oracle: %d score:oracle cases, both engines in agreement", oracleRan)
}
