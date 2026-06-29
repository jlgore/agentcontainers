package mcpproxy

import (
	"strconv"
	"strings"
)

// contextEvaluator ports the two always-compiled, never-denying packages that
// read input.context: uri_egress (G4 — approved transient egress targets) and
// override (G3 — ceiling-bounded operator waivers). Neither contributes a deny;
// uri_egress surfaces egress targets and override waives existing denies within
// the operator ceiling. Faithful native port of uri_egress.rego + override.rego
// and the decision.rego waiver filter.
type contextEvaluator struct {
	uriEgressDenylist map[string]struct{}
	overrideCeiling   map[string]struct{}
}

func newContextEvaluator(cp *CompiledPolicy) *contextEvaluator {
	return &contextEvaluator{
		uriEgressDenylist: toSet(dataStrings(cp.Data["uri_egress_denylist"])),
		overrideCeiling:   toSet(dataStrings(cp.Data["override_ceiling"])),
	}
}

// egressTargets ports uri_egress.rego. A requested URI qualifies when it is
// https, carries no ".." traversal, its host is not denylisted, and it clears
// the provenance gate: when any user_message URI is present, only user_message
// URIs qualify; otherwise tool_args URIs do (Phase-A fallback).
func (e *contextEvaluator) egressTargets(pctx map[string]any) []EgressTarget {
	uris := anySliceOfMaps(pctx["requested_uris"])
	if len(uris) == 0 {
		return nil
	}
	hasUserMessage := false
	for _, u := range uris {
		if str(u["source"]) == "user_message" {
			hasUserMessage = true
			break
		}
	}
	wantSource := "tool_args"
	if hasUserMessage {
		wantSource = "user_message"
	}

	var targets []EgressTarget
	seen := make(map[string]struct{})
	for _, u := range uris {
		host := str(u["host"])
		if str(u["scheme"]) != "https" || strings.Contains(str(u["uri"]), "..") {
			continue
		}
		if _, denied := e.uriEgressDenylist[host]; denied {
			continue
		}
		if str(u["source"]) != wantSource {
			continue
		}
		port := regoNumberToInt(u["port"])
		key := host + ":" + strconv.Itoa(port)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, EgressTarget{Host: host, Port: port, Protocol: "tcp"})
	}
	return targets
}

// clearedPackages ports override.rego: the intersection of the override's
// requested capabilities with the operator ceiling. A category outside the
// ceiling can never be waived (default empty ceiling waives nothing).
func (e *contextEvaluator) clearedPackages(pctx map[string]any) map[string]struct{} {
	ov, ok := pctx["operator_override"].(map[string]any)
	if !ok {
		return nil
	}
	cleared := make(map[string]struct{})
	for _, cap := range anySliceToStrings(ov["capabilities"]) {
		if _, inCeiling := e.overrideCeiling[cap]; inCeiling {
			cleared[cap] = struct{}{}
		}
	}
	return cleared
}

// overrideActive ports override.rego `active`: a verified override accompanied
// this call (it carries an issuer).
func (e *contextEvaluator) overrideActive(pctx map[string]any) bool {
	ov, ok := pctx["operator_override"].(map[string]any)
	if !ok {
		return false
	}
	return str(ov["iss"]) != ""
}

// waived mirrors decision.rego `waived`: a reason is cleared when a
// cleared package's "sift.<pkg>:" prefix matches it.
func waived(reason string, cleared map[string]struct{}) bool {
	for pkg := range cleared {
		if strings.HasPrefix(reason, "sift."+pkg+":") {
			return true
		}
	}
	return false
}

// anySliceOfMaps coerces a []any of map[string]any (e.g. requested_uris).
func anySliceOfMaps(v any) []map[string]any {
	xs, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(xs))
	for _, x := range xs {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
