package mcpproxy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Decision is the structured policy decision document (SPEC §6).
type Decision struct {
	Allowed           bool
	Reasons           []string
	PoliciesEvaluated []string
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
// using the standard policy input envelope (server/tool/args/parsed/context).
// It exists so callers outside the proxy — the agent-tool guard — reuse the
// exact input shape and Rego contract the MCP tool path uses, keeping the
// envelope in one place. Fail-closed handling (an error means deny) is the
// caller's responsibility.
func (e *Evaluator) EvaluateParsed(ctx context.Context, server, tool string, args any, parsed Parsed, pctx map[string]any) (Decision, error) {
	return e.Evaluate(ctx, map[string]any{
		"server":  server,
		"tool":    tool,
		"args":    args,
		"parsed":  parsed.toInput(),
		"context": pctx,
	})
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
	return d, nil
}
