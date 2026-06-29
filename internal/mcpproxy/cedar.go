package mcpproxy

import (
	"context"
	"fmt"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// CedarEvaluator is the first-class, in-process Cedar policy backend
// (policy.engine == "cedar"). It embeds cedar-go (no subprocess, no external
// binary) and is self-contained: the structured-membership categories
// (denied_binaries, dangerous_flags, tool_blocked_flags, capabilities) are
// decided by Cedar against the baked-in forbid policies, and the remaining
// categories — paths, content, filesystem, egress/override — are decided by
// native-Go evaluators it owns. It NEVER calls OPA, so a Cedar deployment does
// not depend on the legacy engine. It satisfies PolicyEngine.
type CedarEvaluator struct {
	server     string
	ps         *cedar.PolicySet
	idByPolicy map[cedar.PolicyID]string // cedar-assigned id -> our @id annotation
	pkgs       []string                  // fully-qualified "sift.<pkg>" list for audit
	membership membershipData
	content    *contentEvaluator
	paths      *pathEvaluator
	context    *contextEvaluator
}

// NewCedarEvaluator builds the embedded Cedar backend for a server from its
// compiled policy. It parses the emitted Cedar policies (a baseline permit plus
// the membership forbids) and constructs the native-Go evaluators for the other
// categories. Construction FAILS CLOSED when the policies do not parse — a
// server configured for engine: cedar must never silently degrade to allow.
func NewCedarEvaluator(ctx context.Context, server string, cp *CompiledPolicy) (*CedarEvaluator, error) {
	ps, err := cedar.NewPolicySetFromBytes("policies.cedar", []byte(cp.CedarPolicies))
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: cedar engine for %s: parsing policies: %w", server, err)
	}

	// Map cedar-go's positional policy ids (policy0, policy1, …) back to the
	// @id annotation we emitted, so a determining forbid resolves to its
	// category. cedar-go does not key policies by the @id annotation.
	idByPolicy := make(map[cedar.PolicyID]string)
	for pid, p := range ps.All() {
		idByPolicy[pid] = string(p.Annotations()[types.Ident("id")])
	}

	cnt, err := newContentEvaluator(cp)
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: cedar engine for %s: %w", server, err)
	}

	pkgs := make([]string, len(cp.PolicyPackages))
	for i, p := range cp.PolicyPackages {
		pkgs[i] = "sift." + p
	}

	return &CedarEvaluator{
		server:     server,
		ps:         ps,
		idByPolicy: idByPolicy,
		pkgs:       pkgs,
		membership: newMembershipData(cp),
		content:    cnt,
		paths:      newPathEvaluator(cp),
		context:    newContextEvaluator(cp),
	}, nil
}

// PoliciesEvaluated returns the same fully-qualified package list as the OPA
// engine — the audit record must not reveal which backend ran, only which
// policy categories applied (they are identical).
func (e *CedarEvaluator) PoliciesEvaluated() []string {
	return append([]string(nil), e.pkgs...)
}

// EvaluateParsed evaluates one decomposed command against this engine using the
// standard policy-input envelope, delegating to the engine-agnostic
// evaluateParsed so the structural-deny short-circuit lives in one place
// (mirrors *Evaluator.EvaluateParsed). Fail-closed handling is the caller's.
func (e *CedarEvaluator) EvaluateParsed(ctx context.Context, server, tool string, args any, parsed Parsed, pctx map[string]any) (Decision, error) {
	return evaluateParsed(ctx, e, server, tool, args, parsed, pctx)
}

// Evaluate decides one policy-input document. Membership comes from the Cedar
// subprocess-free authorizer; paths/content/filesystem from the native-Go
// evaluators; egress/override from the context evaluator. The deny reasons are
// unioned, override waivers (G3) are filtered out, and the call denies if any
// reason remains. Any Cedar evaluation error fails CLOSED.
func (e *CedarEvaluator) Evaluate(ctx context.Context, input map[string]any) (Decision, error) {
	parsed := parseFields(input["parsed"])
	pctx, _ := input["context"].(map[string]any)
	caseDir := str(pctx["case_dir"])
	cwd := str(pctx["cwd"])

	var raw denyset
	memReasons, err := e.membershipDeny(parsed)
	if err != nil {
		return Decision{}, err
	}
	for _, r := range memReasons {
		raw.add(r)
	}
	for _, r := range e.content.evaluate(parsed) {
		raw.add(r)
	}
	for _, r := range e.paths.evaluate(parsed, caseDir, cwd) {
		raw.add(r)
	}

	// Override waiver (G3): partition the deny reasons into those that stand
	// and those a ceiling-bounded operator override cleared.
	cleared := e.context.clearedPackages(pctx)
	var reasons, waivedReasons []string
	for _, r := range raw.list {
		if waived(r, cleared) {
			waivedReasons = append(waivedReasons, r)
		} else {
			reasons = append(reasons, r)
		}
	}

	return Decision{
		Allowed:           len(reasons) == 0,
		Reasons:           reasons,
		PoliciesEvaluated: append([]string(nil), e.pkgs...),
		EgressTargets:     e.context.egressTargets(pctx),
		OverrideActive:    e.context.overrideActive(pctx),
		WaivedReasons:     waivedReasons,
	}, nil
}

// membershipDeny runs the Cedar authorizer for the decomposed command and
// reconstructs OPA-identical per-atom reasons for whatever forbid(s) determined
// a deny. Cedar owns the allow/deny verdict; Go only annotates which atom(s)
// triggered the determining category. A Cedar-reported error, or a deny with no
// attributable reason, fails closed.
func (e *CedarEvaluator) membershipDeny(p parsedFields) ([]string, error) {
	entities, req := cedarRequest(p.binary, p.flags)
	decision, diag := cedar.Authorize(e.ps, entities, req)
	if len(diag.Errors) > 0 {
		return nil, fmt.Errorf("mcpproxy: cedar authorize for %s: policy errors: %v", e.server, diag.Errors)
	}
	if decision == cedar.Allow {
		return nil, nil
	}

	bases := make(map[string]bool)
	for _, r := range diag.Reasons {
		id := e.idByPolicy[r.PolicyID]
		if id == "" || id == "baseline_allow" {
			continue
		}
		base := id
		if i := strings.Index(id, "::"); i >= 0 {
			base = id[:i]
		}
		bases[base] = true
	}

	reasons := e.membership.reasons(bases, p)
	if len(reasons) == 0 {
		// Deny with no attributable reason — never fall open.
		return []string{"sift.cedar: request denied by cedar policy"}, nil
	}
	return reasons, nil
}

// cedarRequest builds the entities + request for one membership authorization:
// the Agent principal and the Command resource carrying the decomposed
// attributes the forbid policies read. binary is exact-case; binary_lc and
// flags are lowercased to match the comparisons baked into the policies.
func cedarRequest(binary string, flags []string) (types.EntityMap, types.Request) {
	flagVals := make([]types.Value, 0, len(flags))
	for _, f := range flags {
		flagVals = append(flagVals, types.String(strings.ToLower(f)))
	}
	agentUID := types.NewEntityUID("Agent", "agent")
	cmdUID := types.NewEntityUID("Command", "cmd")
	entities := types.EntityMap{
		agentUID: types.Entity{UID: agentUID},
		cmdUID: types.Entity{UID: cmdUID, Attributes: types.NewRecord(types.RecordMap{
			"binary":    types.String(binary),
			"binary_lc": types.String(strings.ToLower(binary)),
			"flags":     types.NewSet(flagVals...),
		})},
	}
	req := types.Request{
		Principal: agentUID,
		Action:    types.NewEntityUID("Action", "Invoke"),
		Resource:  cmdUID,
		Context:   types.NewRecord(types.RecordMap{}),
	}
	return entities, req
}

// membershipData holds the lowercased lookup sets the membership reason
// reconstruction needs, mirroring the rego data the equivalent modules read.
type membershipData struct {
	dangerousLC   map[string]struct{}
	toolAllowedLC map[string]map[string]struct{} // binary -> lowered allowed flags
	toolBlockedLC map[string]map[string]struct{} // binary -> lowered blocked flags
	denyArgsLC    map[string]map[string]struct{} // binary -> lowered denied args
}

func newMembershipData(cp *CompiledPolicy) membershipData {
	lcMap := func(m map[string][]string) map[string]map[string]struct{} {
		out := make(map[string]map[string]struct{}, len(m))
		for k, v := range m {
			out[k] = toSet(lowerAll(v))
		}
		return out
	}
	return membershipData{
		dangerousLC:   toSet(lowerAll(dataStrings(cp.Data["dangerous_flags"]))),
		toolAllowedLC: lcMap(dataStringMap(cp.Data["tool_allowed_flags"])),
		toolBlockedLC: lcMap(dataStringMap(cp.Data["tool_blocked_flags"])),
		denyArgsLC:    lcMap(dataStringSetMap(cp.Data["shell_commands"], "denyArgs")),
	}
}

// reasons reconstructs the OPA-shaped, per-atom deny reasons for the membership
// categories Cedar flagged. Only categories present in bases are reconstructed
// (Cedar already decided they fired); each enumerates the offending atoms to
// match OPA's per-flag set, prefixed with the source package.
func (m membershipData) reasons(bases map[string]bool, p parsedFields) []string {
	var out denyset
	if bases["denied_binaries"] {
		out.add(fmt.Sprintf("sift.denied_binaries: binary '%s' is blocked by security policy and cannot be overridden", p.binary))
	}
	if bases["dangerous_flags"] {
		for _, f := range p.flags {
			lf := strings.ToLower(f)
			if _, dangerous := m.dangerousLC[lf]; !dangerous {
				continue
			}
			if m.hasException(p.binary, lf) {
				continue
			}
			out.add(fmt.Sprintf("sift.dangerous_flags: flag '%s' is globally dangerous", f))
		}
	}
	if bases["tool_blocked_flags"] {
		blocked := m.toolBlockedLC[p.binary]
		for _, f := range p.flags {
			if _, ok := blocked[strings.ToLower(f)]; ok {
				out.add(fmt.Sprintf("sift.tool_blocked_flags: flag '%s' is not permitted on '%s'", f, p.binary))
			}
		}
	}
	if bases["capabilities_allowlist"] {
		out.add(fmt.Sprintf("sift.capabilities: binary '%s' is not in the shell command allowlist", p.binary))
	}
	if bases["capabilities_denyargs"] {
		denied := m.denyArgsLC[p.binary]
		for _, f := range p.flags {
			if _, ok := denied[strings.ToLower(f)]; ok {
				out.add(fmt.Sprintf("sift.capabilities: arg '%s' is denied for '%s'", f, p.binary))
			}
		}
	}
	return out.list
}

func (m membershipData) hasException(binary, loweredFlag string) bool {
	_, ok := m.toolAllowedLC[binary][loweredFlag]
	return ok
}

// parsedFields is the subset of the decomposed command the native-Go evaluators
// read, extracted from the input.parsed map.
type parsedFields struct {
	binary      string
	flags       []string
	paths       []string
	outputPaths []string
	args        []string
}

func parseFields(v any) parsedFields {
	m, _ := v.(map[string]any)
	return parsedFields{
		binary:      str(m["binary"]),
		flags:       anySliceToStrings(m["flags"]),
		paths:       anySliceToStrings(m["paths"]),
		outputPaths: anySliceToStrings(m["output_paths"]),
		args:        anySliceToStrings(m["args"]),
	}
}

// CedarCheck builds the embedded Cedar engine from cp and evaluates one
// representative (binary, flags) command, returning the decision and reasons.
// Used by `ac policy verify` to confirm the emitted policies parse and enforce
// (e.g. a denied binary is denied). No external binary required.
func CedarCheck(ctx context.Context, cp *CompiledPolicy, binary string, flags []string) (allowed bool, reasons []string, err error) {
	e, err := NewCedarEvaluator(ctx, "verify", cp)
	if err != nil {
		return false, nil, err
	}
	d, err := e.Evaluate(ctx, map[string]any{
		"parsed":  map[string]any{"binary": binary, "flags": sliceAny(flags)},
		"context": map[string]any{},
	})
	if err != nil {
		return false, nil, err
	}
	return d.Allowed, d.Reasons, nil
}

func anySliceToStrings(v any) []string {
	switch xs := v.(type) {
	case []string:
		return append([]string(nil), xs...)
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
