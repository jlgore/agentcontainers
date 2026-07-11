package toolpolicy

import (
	"context"
	"encoding/json"
)

// Decision is the structured policy decision document (SPEC §6).
type Decision struct {
	Allowed           bool
	Reasons           []string
	PoliciesEvaluated []string
	// EgressTargets are host:port pairs the policy approved for URI-scoped
	// transient egress on this tool call (G4). Empty unless the server opts
	// into policy.network.uriEgress and a user-supplied https URI was found.
	EgressTargets []EgressTarget

	// OverrideActive reports that a ceiling-bounded operator override (G3)
	// participated in this decision. WaivedReasons are the deny reasons the
	// override cleared (within the operator ceiling) — recorded for audit
	// provenance, not shown to the agent.
	OverrideActive bool
	WaivedReasons  []string

	// OverrideIssuer is the DID of an applied override's signer (set Go-side
	// after VC verification). OverrideRejected is non-empty when an override
	// was present but refused (bad signature, expired, or untrusted issuer);
	// the call then proceeds under static policy, with the reason audited.
	OverrideIssuer   string
	OverrideRejected string
}

// EgressTarget is one approved transient egress destination.
type EgressTarget struct {
	Host     string
	Port     int
	Protocol string // always "tcp" for URI-scoped egress
}

// PolicyEngine is the engine-agnostic authorization boundary. A server's
// compiled policy is evaluated by exactly one PolicyEngine — the embedded
// *CedarEvaluator. It consumes the compiled data and policy-input envelope and
// returns a Decision.
type PolicyEngine interface {
	// Evaluate runs one policy-input document (server/tool/args/parsed/context)
	// and returns the structured decision. An error means the engine could not
	// reach a verdict; the caller fails closed (deny).
	Evaluate(ctx context.Context, input map[string]any) (Decision, error)
	// PoliciesEvaluated returns the fully qualified package list this engine
	// reports for audit (static per server).
	PoliciesEvaluated() []string
	// EvaluateParsed evaluates one decomposed command using the standard policy
	// input envelope, applying the structural-deny short-circuit. Callers
	// outside the proxy (the agent-tool guard) use this to reuse the exact
	// input shape and engine contract. Fail-closed handling is the caller's.
	EvaluateParsed(ctx context.Context, server, tool string, args any, parsed Parsed, pctx map[string]any) (Decision, error)
}

// EvaluateParsed evaluates one decomposed command against any PolicyEngine
// using the standard policy-input envelope (server/tool/args/parsed/context).
// The structural-deny short-circuit and the envelope shape live in ONE place
// for every engine: a decomposition-level deny (parsed.Deny) is a denial the
// policy language cannot express, so it must hold regardless of engine, and it
// short-circuits before the engine is ever consulted. Fail-closed handling (an
// error means deny) is the caller's responsibility.
func EvaluateParsed(ctx context.Context, eng PolicyEngine, server, tool string, args any, parsed Parsed, pctx map[string]any) (Decision, error) {
	if parsed.Deny {
		reasons := parsed.DenyReasons
		if len(reasons) == 0 {
			reasons = []string{"command decomposition denied"}
		}
		return Decision{Allowed: false, Reasons: reasons, PoliciesEvaluated: eng.PoliciesEvaluated()}, nil
	}
	return eng.Evaluate(ctx, map[string]any{
		"server":  server,
		"tool":    tool,
		"args":    args,
		"parsed":  parsed.toInput(),
		"context": pctx,
	})
}

// regoNumberToInt coerces a JSON number (json.Number, float64, or int) to an
// int. Returns 0 when absent or unparseable; the enforcer treats port 0 as
// "any port" for the host.
func regoNumberToInt(v any) int {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}
