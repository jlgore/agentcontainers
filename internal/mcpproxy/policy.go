package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
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
// compiled policy is evaluated by exactly one PolicyEngine, selected by
// policy.engine: the embedded *CedarEvaluator (default) or the legacy in-process
// OPA *Evaluator (policy.engine: opa). Both consume the same compiled data and
// policy-input envelope and return the same Decision shape, so swapping engines
// never changes the input contract — only how the allow/deny is computed.
type PolicyEngine interface {
	// Evaluate runs one policy-input document (server/tool/args/parsed/context)
	// and returns the structured decision. An error means the engine could not
	// reach a verdict; the caller fails closed (deny).
	Evaluate(ctx context.Context, input map[string]any) (Decision, error)
	// PoliciesEvaluated returns the fully qualified package list this engine
	// reports for audit (static per server, identical across engines).
	PoliciesEvaluated() []string
	// EvaluateParsed evaluates one decomposed command using the standard policy
	// input envelope, applying the structural-deny short-circuit. Callers
	// outside the proxy (the agent-tool guard) use this to reuse the exact
	// input shape and engine contract. Fail-closed handling is the caller's.
	EvaluateParsed(ctx context.Context, server, tool string, args any, parsed Parsed, pctx map[string]any) (Decision, error)
}

// evaluateParsed evaluates one decomposed command against any PolicyEngine
// using the standard policy-input envelope (server/tool/args/parsed/context).
// Lifted out of the OPA *Evaluator so the structural-deny short-circuit and
// the envelope shape live in ONE place for every engine: a decomposition-level
// deny (parsed.Deny) is a denial the policy language cannot express, so it must
// hold regardless of which engine is configured, and it short-circuits before
// the engine is ever consulted. Fail-closed handling (an error means deny) is
// the caller's responsibility.
func evaluateParsed(ctx context.Context, eng PolicyEngine, server, tool string, args any, parsed Parsed, pctx map[string]any) (Decision, error) {
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

// Evaluator evaluates a single server's compiled policy in-process. The
// Rego modules and data are compiled once at startup (PrepareForEval);
// each tools/call evaluates against the prepared query.
type Evaluator struct {
	pq     rego.PreparedEvalQuery
	pkgs   []string
	server string
}

// NewEvaluator compiles a server's policy modules + data into a prepared
// OPA query.
func NewEvaluator(ctx context.Context, server string, cp *CompiledPolicy) (*Evaluator, error) {
	opts := []func(*rego.Rego){
		rego.Query("data.sift.decision"),
		rego.Data(cp.Data),
	}
	for name, src := range cp.Modules {
		opts = append(opts, rego.Module(name, src))
	}
	pq, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: compiling policy for %s: %w", server, err)
	}

	pkgs := make([]string, len(cp.PolicyPackages))
	for i, p := range cp.PolicyPackages {
		pkgs[i] = "sift." + p
	}
	return &Evaluator{pq: pq, pkgs: pkgs, server: server}, nil
}

// PoliciesEvaluated returns the fully qualified package list this
// evaluator runs (static per server).
func (e *Evaluator) PoliciesEvaluated() []string {
	return append([]string(nil), e.pkgs...)
}

// EvaluateParsed evaluates one decomposed command against the prepared query
// using the standard policy input envelope. It exists so callers outside the
// proxy — the agent-tool guard — reuse the exact input shape and engine
// contract the MCP tool path uses. It delegates to the engine-agnostic
// evaluateParsed so the structural-deny short-circuit lives in one place.
// Fail-closed handling (an error means deny) is the caller's responsibility.
func (e *Evaluator) EvaluateParsed(ctx context.Context, server, tool string, args any, parsed Parsed, pctx map[string]any) (Decision, error) {
	return evaluateParsed(ctx, e, server, tool, args, parsed, pctx)
}

// Evaluate runs the prepared query against one policy input document
// (SPEC §5). An evaluation error is returned to the caller, which must
// fail closed (deny) — a broken policy engine never falls open.
func (e *Evaluator) Evaluate(ctx context.Context, input map[string]any) (Decision, error) {
	rs, err := e.pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, fmt.Errorf("mcpproxy: policy evaluation for %s: %w", e.server, err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{}, fmt.Errorf("mcpproxy: policy evaluation for %s returned no decision", e.server)
	}
	doc, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{}, fmt.Errorf("mcpproxy: policy decision for %s has unexpected shape %T", e.server, rs[0].Expressions[0].Value)
	}

	d := Decision{PoliciesEvaluated: e.pkgs}
	if allowed, ok := doc["allowed"].(bool); ok {
		d.Allowed = allowed
	}
	if reasons, ok := doc["reasons"].([]any); ok {
		for _, r := range reasons {
			if s, ok := r.(string); ok {
				d.Reasons = append(d.Reasons, s)
			}
		}
	}
	if targets, ok := doc["egress_targets"].([]any); ok {
		for _, raw := range targets {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			host, _ := m["host"].(string)
			if host == "" {
				continue
			}
			d.EgressTargets = append(d.EgressTargets, EgressTarget{
				Host:     host,
				Port:     regoNumberToInt(m["port"]),
				Protocol: "tcp",
			})
		}
	}
	if active, ok := doc["override_active"].(bool); ok {
		d.OverrideActive = active
	}
	if waived, ok := doc["waived_reasons"].([]any); ok {
		for _, r := range waived {
			if s, ok := r.(string); ok {
				d.WaivedReasons = append(d.WaivedReasons, s)
			}
		}
	}
	return d, nil
}

// regoNumberToInt coerces an OPA-returned JSON number (json.Number, float64,
// or int) to an int. Returns 0 when absent or unparseable; the enforcer
// treats port 0 as "any port" for the host.
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
