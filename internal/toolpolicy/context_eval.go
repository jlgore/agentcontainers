package toolpolicy

import (
	"net/url"
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

// anySliceOfMaps coerces requested_uris to []map[string]any. It accepts both
// the native []map[string]any the proxy builds (extractRequestedURIs) and the
// []any a JSON-decoded context carries — the OPA engine normalized these via
// rego.EvalInput; the native Cedar evaluator must handle both directly.
func anySliceOfMaps(v any) []map[string]any {
	switch xs := v.(type) {
	case []map[string]any:
		return xs
	case []any:
		out := make([]map[string]any, 0, len(xs))
		for _, x := range xs {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// ExtractRequestedURIs scans a tool call's decomposed arguments for https
// URLs and returns them as policy input objects {uri, scheme, host, port,
// source}. This is Phase A provenance: the URL is taken from the tool's own
// arguments (the link the agent is about to fetch), tagged source
// "tool_args". URL parsing is done here (Go net/url), not in Rego, so the
// policy only applies allow-logic over already-parsed fields. Phase B
// (harness-attested source "user_message" via request _meta) layers on top.
func ExtractRequestedURIs(parsedList []Parsed, args any) []map[string]any {
	seen := make(map[string]bool)
	var out []map[string]any
	consider := func(tok string) {
		if seen[tok] {
			return
		}
		u, ok := parseHTTPSURI(tok)
		if !ok {
			return
		}
		seen[tok] = true
		u["source"] = "tool_args"
		out = append(out, u)
	}
	for _, p := range parsedList {
		for _, a := range p.Args {
			consider(a)
		}
		for _, pth := range p.Paths {
			consider(pth)
		}
	}
	// Also scan raw string argument values (non-shell tools whose args carry
	// a URL directly, e.g. {"url": "https://..."}).
	scanArgStrings(args, consider)
	return out
}

// parseHTTPSURI parses an https URL into the policy-input fields
// {uri, scheme, host, port}, or reports false for anything that is not a
// well-formed https URL. The caller adds the "source" provenance tag. https
// only: http/file/ftp never qualify for transient egress.
func parseHTTPSURI(tok string) (map[string]any, bool) {
	if !strings.HasPrefix(tok, "https://") {
		return nil, false
	}
	u, err := url.Parse(tok)
	if err != nil || u.Host == "" {
		return nil, false
	}
	portNum := 443
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			portNum = n
		}
	}
	return map[string]any{
		"uri":    tok,
		"scheme": u.Scheme,
		"host":   u.Hostname(),
		"port":   portNum,
	}, true
}

// ExtractMetaURIs reads harness-attested URIs from a tool call's _meta field
// (Phase B provenance, G4). The harness — the Claude Code PreToolUse guard or
// the MCP client — attaches the URLs the *user* actually supplied under
// _meta.requested_uris, so the policy can grant egress to a user-named host
// without inferring intent from the tool's own arguments. Each entry may be a
// bare string ("https://x") or an object carrying a "uri" field; both are
// normalized and tagged source "user_message". This is the channel that
// delivers the PRD's "no implicit grants from tool output" guarantee: a URL
// the model merely echoed from prior output never arrives here.
func ExtractMetaURIs(meta map[string]any) []map[string]any {
	raw, ok := meta["requested_uris"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	seen := make(map[string]bool)
	var out []map[string]any
	for _, item := range list {
		var tok string
		switch v := item.(type) {
		case string:
			tok = v
		case map[string]any:
			tok, _ = v["uri"].(string)
		}
		if seen[tok] {
			continue
		}
		if u, ok := parseHTTPSURI(tok); ok {
			seen[tok] = true
			u["source"] = "user_message"
			out = append(out, u)
		}
	}
	return out
}

// scanArgStrings walks a decoded JSON argument value, invoking fn on every
// string it finds (recursing through objects and arrays).
func scanArgStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case []any:
		for _, e := range t {
			scanArgStrings(e, fn)
		}
	case map[string]any:
		for _, e := range t {
			scanArgStrings(e, fn)
		}
	}
}
