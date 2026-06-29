package mcpproxy

import (
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// evalWithURIs compiles the default policy and evaluates a single empty
// command with the given requested_uris in the policy context, returning the
// approved egress targets.
func evalWithURIs(t *testing.T, requested []map[string]any) []EgressTarget {
	t.Helper()
	return evalWithURIsPolicy(t, nil, requested)
}

// evalWithURIsPolicy is evalWithURIs with an explicit server policy, so tests
// can exercise the config-driven uri_egress denylist.
func evalWithURIsPolicy(t *testing.T, cfgPolicy *config.MCPServerPolicy, requested []map[string]any) []EgressTarget {
	t.Helper()
	cp, err := Compile(DefaultSecurityPolicy(), cfgPolicy)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ev, err := NewEvaluator(t.Context(), "srv", cp)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	d, err := ev.Evaluate(t.Context(), map[string]any{
		"server": "srv",
		"tool":   "run_command",
		"args":   map[string]any{},
		"parsed": Parsed{}.toInput(),
		"context": map[string]any{
			"requested_uris": requested,
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return d.EgressTargets
}

func hasTarget(targets []EgressTarget, host string, port int) bool {
	for _, t := range targets {
		if t.Host == host && t.Port == port {
			return true
		}
	}
	return false
}

// An https URI with no traversal and an un-denied host becomes an approved
// egress target carrying its parsed host and port.
func TestURIEgressApprovesHTTPS(t *testing.T) {
	targets := evalWithURIs(t, []map[string]any{
		{"uri": "https://example.com/api/v1/data", "scheme": "https", "host": "example.com", "port": 443, "source": "tool_args"},
	})
	if !hasTarget(targets, "example.com", 443) {
		t.Fatalf("targets = %+v, want example.com:443", targets)
	}
	if len(targets) != 1 || targets[0].Protocol != "tcp" {
		t.Errorf("targets = %+v, want exactly one tcp target", targets)
	}
}

// Non-https schemes and path-traversal URIs are never approved.
func TestURIEgressRejectsNonHTTPSAndTraversal(t *testing.T) {
	cases := []struct {
		name string
		uri  map[string]any
	}{
		{"http", map[string]any{"uri": "http://example.com/x", "scheme": "http", "host": "example.com", "port": 80, "source": "tool_args"}},
		{"file", map[string]any{"uri": "file:///etc/passwd", "scheme": "file", "host": "", "port": 0, "source": "tool_args"}},
		{"traversal", map[string]any{"uri": "https://example.com/../secret", "scheme": "https", "host": "example.com", "port": 443, "source": "tool_args"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if targets := evalWithURIs(t, []map[string]any{tc.uri}); len(targets) != 0 {
				t.Errorf("targets = %+v, want none", targets)
			}
		})
	}
}

// No requested_uris in context → no egress targets (the default for a server
// not opted into uriEgress, or a call with no URLs).
func TestURIEgressEmptyWhenNoURIs(t *testing.T) {
	if targets := evalWithURIs(t, nil); len(targets) != 0 {
		t.Errorf("targets = %+v, want none", targets)
	}
}

// extractRequestedURIs pulls https URLs from decomposed command args and from
// raw string argument values, defaulting the port to 443, and ignores
// non-https tokens.
func TestExtractRequestedURIs(t *testing.T) {
	parsed := []Parsed{{
		Binary: "curl",
		Args:   []string{"-sS", "https://example.com/report.pdf", "http://skip.me/x"},
	}}
	args := map[string]any{"url": "https://api.example.org:8443/v1"}

	uris := extractRequestedURIs(parsed, args)

	var gotHosts []string
	for _, u := range uris {
		gotHosts = append(gotHosts, u["host"].(string))
		if u["scheme"].(string) != "https" {
			t.Errorf("non-https URI leaked: %v", u)
		}
	}
	if !containsStr(gotHosts, "example.com") || !containsStr(gotHosts, "api.example.org") {
		t.Fatalf("hosts = %v, want example.com and api.example.org", gotHosts)
	}
	if containsStr(gotHosts, "skip.me") {
		t.Error("http URL was not skipped")
	}
	for _, u := range uris {
		switch u["host"] {
		case "example.com":
			if u["port"].(int) != 443 {
				t.Errorf("default port = %v, want 443", u["port"])
			}
		case "api.example.org":
			if u["port"].(int) != 8443 {
				t.Errorf("explicit port = %v, want 8443", u["port"])
			}
		}
	}
}

// When a user_message URI is present, tool_args URIs are NOT granted egress —
// the harness attestation is authoritative ("no implicit grants from tool
// output"). The user_message host is the only target.
func TestURIEgressPrefersUserMessage(t *testing.T) {
	targets := evalWithURIs(t, []map[string]any{
		{"uri": "https://attacker.example/x", "scheme": "https", "host": "attacker.example", "port": 443, "source": "tool_args"},
		{"uri": "https://trusted.example/y", "scheme": "https", "host": "trusted.example", "port": 443, "source": "user_message"},
	})
	if hasTarget(targets, "attacker.example", 443) {
		t.Error("tool_args host granted egress despite a user_message attestation present")
	}
	if !hasTarget(targets, "trusted.example", 443) {
		t.Errorf("user_message host missing; targets = %+v", targets)
	}
	if len(targets) != 1 {
		t.Errorf("targets = %+v, want exactly the user_message host", targets)
	}
}

// Absent any user_message attestation, tool_args URIs are granted (Phase-A
// fallback).
func TestURIEgressFallsBackToToolArgs(t *testing.T) {
	targets := evalWithURIs(t, []map[string]any{
		{"uri": "https://a.example/x", "scheme": "https", "host": "a.example", "port": 443, "source": "tool_args"},
		{"uri": "https://b.example/y", "scheme": "https", "host": "b.example", "port": 443, "source": "tool_args"},
	})
	if !hasTarget(targets, "a.example", 443) || !hasTarget(targets, "b.example", 443) {
		t.Errorf("targets = %+v, want both tool_args hosts", targets)
	}
}

// A host in policy.network.uriEgressDeny is rejected even when the user
// attests it — the denylist is a hard ceiling.
func TestURIEgressDenylistFromConfig(t *testing.T) {
	cfgPolicy := &config.MCPServerPolicy{
		Network: &config.NetworkCaps{URIEgressDeny: []string{"blocked.example"}},
	}
	targets := evalWithURIsPolicy(t, cfgPolicy, []map[string]any{
		{"uri": "https://blocked.example/x", "scheme": "https", "host": "blocked.example", "port": 443, "source": "user_message"},
		{"uri": "https://ok.example/y", "scheme": "https", "host": "ok.example", "port": 443, "source": "user_message"},
	})
	if hasTarget(targets, "blocked.example", 443) {
		t.Error("denylisted host granted egress despite user_message attestation")
	}
	if !hasTarget(targets, "ok.example", 443) {
		t.Errorf("un-denied host missing; targets = %+v", targets)
	}
}

// extractMetaURIs reads _meta.requested_uris (string or {uri} forms) and tags
// them user_message; non-https entries are dropped.
func TestExtractMetaURIs(t *testing.T) {
	meta := map[string]any{
		"requested_uris": []any{
			"https://str.example/a",
			map[string]any{"uri": "https://obj.example/b"},
			"http://skip.example/c",
			map[string]any{"uri": "ftp://skip2.example"},
		},
	}
	uris := extractMetaURIs(meta)
	var hosts []string
	for _, u := range uris {
		hosts = append(hosts, u["host"].(string))
		if u["source"].(string) != "user_message" {
			t.Errorf("source = %v, want user_message", u["source"])
		}
	}
	if !containsStr(hosts, "str.example") || !containsStr(hosts, "obj.example") {
		t.Fatalf("hosts = %v, want str.example and obj.example", hosts)
	}
	if containsStr(hosts, "skip.example") || containsStr(hosts, "skip2.example") {
		t.Error("non-https _meta URI leaked")
	}
}

// extractMetaURIs tolerates absent or malformed _meta.
func TestExtractMetaURIsEmpty(t *testing.T) {
	if got := extractMetaURIs(nil); got != nil {
		t.Errorf("nil meta = %+v, want nil", got)
	}
	if got := extractMetaURIs(map[string]any{"requested_uris": "not-a-list"}); got != nil {
		t.Errorf("malformed = %+v, want nil", got)
	}
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
