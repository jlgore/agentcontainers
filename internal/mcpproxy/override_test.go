package mcpproxy

import (
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/identity"
)

// verifyOverride: a valid VC from a trusted issuer is accepted; an untrusted
// issuer, an expired VC, and a missing override are each handled fail-closed.
func TestVerifyOverride(t *testing.T) {
	ks, err := identity.LoadOrCreateKeyStore(t.TempDir() + "/k.pem")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	good, err := identity.IssueVC(ks, identity.VCClaims{Capabilities: []string{"network"}}, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Trusted issuer → accepted.
	claims, reason := verifyOverride(map[string]any{"operator_override": good}, []string{ks.DID()})
	if claims == nil || reason != "" {
		t.Fatalf("trusted override rejected: %q", reason)
	}
	if len(claims.Capabilities) != 1 || claims.Capabilities[0] != "network" {
		t.Errorf("capabilities = %v", claims.Capabilities)
	}

	// Untrusted issuer → rejected with a reason.
	if c, r := verifyOverride(map[string]any{"operator_override": good}, nil); c != nil || r == "" {
		t.Errorf("untrusted issuer accepted: claims=%v reason=%q", c, r)
	}

	// No override present → (nil, "").
	if c, r := verifyOverride(map[string]any{}, []string{ks.DID()}); c != nil || r != "" {
		t.Errorf("absent override produced claims=%v reason=%q", c, r)
	}

	// Tampered token → rejected.
	if c, r := verifyOverride(map[string]any{"operator_override": good[:len(good)-2] + "AA"}, []string{ks.DID()}); c != nil || r == "" {
		t.Errorf("tampered override accepted")
	}

	// Expired VC → rejected (reverts to static policy).
	expired, err := identity.IssueVC(ks, identity.VCClaims{
		Capabilities: []string{"network"},
		Exp:          time.Now().Add(-time.Hour).Unix(),
	}, 0)
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	if c, r := verifyOverride(map[string]any{"operator_override": expired}, []string{ks.DID()}); c != nil || r == "" {
		t.Errorf("expired override accepted: claims=%v reason=%q", c, r)
	}
}
