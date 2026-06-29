package identity

import (
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDIDRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	did := DIDFromPublicKey(pub)
	if !strings.HasPrefix(did, "did:key:z") {
		t.Fatalf("did %q lacks did:key:z prefix", did)
	}
	got, err := PublicKeyFromDID(did)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("resolved key != original")
	}
}

func TestPublicKeyFromDIDRejects(t *testing.T) {
	cases := []string{
		"did:web:example.com",
		"did:key:znotbase58!!",
		"did:key:z" + base58Encode([]byte{0x12, 0x34, 0x56}), // wrong multicodec
	}
	for _, c := range cases {
		if _, err := PublicKeyFromDID(c); err == nil {
			t.Errorf("expected error for %q, got nil", c)
		}
	}
}

func TestBase58RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00, 0x01},
		{0xff, 0xfe, 0xfd},
		[]byte("hello agentcontainers"),
	}
	for _, in := range cases {
		enc := base58Encode(in)
		dec, err := base58Decode(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if string(dec) != string(in) {
			t.Errorf("round trip mismatch: in=%x enc=%q dec=%x", in, enc, dec)
		}
	}
}

func TestLoadOrCreateKeyStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id", "ed25519.pem")
	ks1, err := LoadOrCreateKeyStore(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ks2, err := LoadOrCreateKeyStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if ks1.DID() != ks2.DID() {
		t.Fatalf("DID changed across reload: %q vs %q", ks1.DID(), ks2.DID())
	}
	// Sign/verify through the did:key resolver.
	msg := []byte("entry-hash")
	sig, err := ks1.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := (DIDKeyResolver{}).Verify(ks1.DID(), msg, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVCRoundTripAndExpiry(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	ks := NewKeyStore(priv)
	res := DIDKeyResolver{}

	claims := VCClaims{
		EnforcementModel:     []string{"opa_proxy", "ebpf_kernel"},
		EvidenceImmutability: "append_only",
		AuditChainType:       "sha256_hash_chain",
		PolicySource:         "sha256:deadbeef",
	}
	tok, err := IssueVC(ks, claims, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := VerifyVC(tok, res)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Iss != ks.DID() {
		t.Errorf("iss = %q, want %q", got.Iss, ks.DID())
	}
	if got.PolicySource != "sha256:deadbeef" {
		t.Errorf("policy_source = %q", got.PolicySource)
	}

	// Foreign resolver with no shared state still verifies (self-certifying).
	if _, err := VerifyVC(tok, DIDKeyResolver{}); err != nil {
		t.Errorf("foreign resolve failed: %v", err)
	}

	// Expired credential fails closed (explicit past exp; ttl<=0 keeps it).
	expired := forceExp(t, ks, claims, time.Now().Add(-time.Hour))
	if _, err := VerifyVC(expired, res); err == nil {
		t.Errorf("expected expired VC to fail")
	}

	// Tampered signature fails.
	bad := tok[:len(tok)-2] + "AA"
	if _, err := VerifyVC(bad, res); err == nil {
		t.Errorf("expected tampered VC to fail")
	}
}

// forceExp issues a VC with an explicit (past) exp by bypassing IssueVC's
// clock — exercises the expiry branch deterministically.
func forceExp(t *testing.T, ks KeyStore, claims VCClaims, exp time.Time) string {
	t.Helper()
	claims.Exp = exp.Unix()
	// Re-sign manually with the same structure IssueVC uses.
	tok, err := IssueVC(ks, claims, 0)
	if err != nil {
		t.Fatalf("force exp: %v", err)
	}
	return tok
}
