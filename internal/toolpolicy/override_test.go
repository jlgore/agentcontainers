package toolpolicy

import (
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// evalDeniedBinary compiles a policy that denies "dd", with the given override
// ceiling, and evaluates a `dd` command with the supplied operator_override
// context. It returns the decision so tests can assert allow/deny + waiver.
func evalDeniedBinary(t *testing.T, ceiling []string, override map[string]any) Decision {
	t.Helper()
	sec := &SecurityPolicy{DeniedBinaries: []string{"dd"}}
	sec.applyDefaults()
	cfgPolicy := &config.MCPServerPolicy{OverrideCeiling: ceiling}
	cp, err := Compile(sec, cfgPolicy)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ev, err := NewCedarEvaluator(t.Context(), "srv", cp)
	if err != nil {
		t.Fatalf("NewCedarEvaluator: %v", err)
	}
	ctx := map[string]any{"correlationId": "c1"}
	if override != nil {
		ctx["operator_override"] = override
	}
	d, err := ev.Evaluate(t.Context(), map[string]any{
		"server":  "srv",
		"tool":    "run_command",
		"args":    map[string]any{},
		"parsed":  Parsed{Binary: "dd", Args: []string{"if=/dev/zero"}}.toInput(),
		"context": ctx,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return d
}

// A denied binary stays denied with no override.
func TestOverrideAbsentStaysDenied(t *testing.T) {
	d := evalDeniedBinary(t, []string{"denied_binaries"}, nil)
	if d.Allowed {
		t.Fatal("dd allowed without an override")
	}
}

// An override naming a category inside the ceiling waives that deny and flips
// the decision to allowed; the waived reason is surfaced for audit.
func TestOverrideWaivesWithinCeiling(t *testing.T) {
	d := evalDeniedBinary(t, []string{"denied_binaries"}, map[string]any{
		"iss":          "did:key:zOperator",
		"capabilities": []any{"denied_binaries"},
	})
	if !d.Allowed {
		t.Fatalf("override within ceiling did not allow; reasons=%v", d.Reasons)
	}
	if !d.OverrideActive {
		t.Error("override_active not reported")
	}
	if len(d.WaivedReasons) == 0 {
		t.Error("waived_reasons empty; expected the denied_binaries reason")
	}
}

// An override for a category OUTSIDE the ceiling is impotent — the deny stands.
func TestOverrideOutsideCeilingRejected(t *testing.T) {
	d := evalDeniedBinary(t, []string{"network"}, map[string]any{
		"iss":          "did:key:zOperator",
		"capabilities": []any{"denied_binaries"},
	})
	if d.Allowed {
		t.Fatal("override waived a category outside the ceiling")
	}
	if len(d.WaivedReasons) != 0 {
		t.Errorf("waived_reasons = %v, want none", d.WaivedReasons)
	}
}

// An empty ceiling (the default) waives nothing even with a matching override.
func TestOverrideEmptyCeilingWaivesNothing(t *testing.T) {
	d := evalDeniedBinary(t, nil, map[string]any{
		"iss":          "did:key:zOperator",
		"capabilities": []any{"denied_binaries"},
	})
	if d.Allowed {
		t.Fatal("empty ceiling allowed an override to widen policy")
	}
}
