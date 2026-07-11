package toolpolicy

import "testing"

func newTestContextEval() *contextEvaluator {
	return newContextEvaluator(&CompiledPolicy{Data: map[string]any{
		"uri_egress_denylist": sliceAny([]string{"evil.example"}),
		"override_ceiling":    sliceAny([]string{"dangerous_flags"}),
	}})
}

func uri(scheme, host string, port int, source string) map[string]any {
	return map[string]any{
		"uri":    scheme + "://" + host,
		"scheme": scheme,
		"host":   host,
		"port":   port,
		"source": source,
	}
}

func TestEgressTargets_QualifyAndReject(t *testing.T) {
	ce := newTestContextEval()
	pctx := map[string]any{"requested_uris": []any{
		uri("https", "good.example", 443, "tool_args"),
		uri("http", "insecure.example", 80, "tool_args"), // not https
		uri("https", "evil.example", 443, "tool_args"),   // denylisted
		map[string]any{"uri": "https://x/..%2f", "scheme": "https", "host": "trav.example", "port": 443, "source": "tool_args"}, // traversal
	}}
	got := ce.egressTargets(pctx)
	if len(got) != 1 || got[0].Host != "good.example" || got[0].Port != 443 || got[0].Protocol != "tcp" {
		t.Fatalf("egressTargets = %+v, want only good.example:443", got)
	}
}

func TestEgressTargets_ProvenanceGate(t *testing.T) {
	ce := newTestContextEval()
	// When any user_message URI is present, tool_args URIs do NOT qualify.
	pctx := map[string]any{"requested_uris": []any{
		uri("https", "user.example", 443, "user_message"),
		uri("https", "tool.example", 443, "tool_args"),
	}}
	got := ce.egressTargets(pctx)
	if len(got) != 1 || got[0].Host != "user.example" {
		t.Fatalf("with a user_message URI present, only it qualifies; got %+v", got)
	}
}

func TestOverrideWaiverAndActive(t *testing.T) {
	ce := newTestContextEval()
	pctx := map[string]any{"operator_override": map[string]any{
		"iss":          "did:key:operator",
		"capabilities": sliceAny([]string{"dangerous_flags", "denied_binaries"}),
	}}
	if !ce.overrideActive(pctx) {
		t.Error("expected override active (issuer present)")
	}
	cleared := ce.clearedPackages(pctx)
	// dangerous_flags is in the ceiling; denied_binaries is NOT.
	if _, ok := cleared["dangerous_flags"]; !ok {
		t.Error("dangerous_flags should be cleared (in ceiling)")
	}
	if _, ok := cleared["denied_binaries"]; ok {
		t.Error("denied_binaries must NOT be cleared (outside ceiling)")
	}
	if !waived("sift.dangerous_flags: flag '-rf' is globally dangerous", cleared) {
		t.Error("a dangerous_flags reason should be waived by the cleared package")
	}
	if waived("sift.denied_binaries: binary 'dd' is blocked", cleared) {
		t.Error("a denied_binaries reason must not be waived (outside ceiling)")
	}
}
