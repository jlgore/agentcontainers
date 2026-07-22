package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VCClaims is the payload of an enforcement-attestation verifiable credential.
// It is a JWT body: the standard registered claims (iss/sub/iat/exp) plus the
// ARD enforcement-posture claims a relying party uses to decide how much to
// trust a published capability or an operator override.
//
// VCs are EdDSA JWTs signed by the issuer's did:key (see the package doc for
// why EdDSA over the audit key, not the OIDC ES256 key).
type VCClaims struct {
	Iss string `json:"iss"`           // issuer DID (did:key)
	Sub string `json:"sub,omitempty"` // subject DID, when distinct from issuer
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp,omitempty"`

	// Enforcement attestation (ARD §G1). EnforcementModel lists the active
	// layers (e.g. ["cedar_proxy","ebpf_kernel"]); PolicySource is the compiled
	// policy hash (CompiledPolicy.Hash) so the claim is pinned to a specific
	// rule set.
	EnforcementModel     []string `json:"enforcement_model,omitempty"`
	EvidenceImmutability string   `json:"evidence_immutability,omitempty"`
	AuditChainType       string   `json:"audit_chain_type,omitempty"`
	PolicySource         string   `json:"policy_source,omitempty"`

	// Capabilities optionally names what an operator-override VC widens (G3).
	// The override ceiling in Rego decides which of these are honored.
	Capabilities []string `json:"capabilities,omitempty"`

	// Bind pins an operator-override VC to a single tool invocation. It is the
	// OverrideBinding hash of the exact (tool name, arguments) the operator
	// authorized. The proxy recomputes it for the live call and refuses the
	// override unless it matches, so a captured override cannot be replayed
	// against a *different* tool call. Empty on non-override credentials
	// (e.g. the long-lived publisher VC), which are never accepted as overrides.
	Bind string `json:"bind,omitempty"`
}

// OverrideBinding is the canonical single-invocation binding for an operator
// override: a SHA-256 over the tool name and its arguments. Both the issuer
// (when minting the VC's Bind claim) and the proxy (when verifying) call this
// exact function so their hashes agree.
//
// Determinism matters — a mismatch rejects a legitimate override. Arguments are
// re-encoded from a json.Number-preserving decode so object key order and
// insignificant whitespace do not affect the result, and large integers keep
// their exact literal form rather than being rounded through float64. Arguments
// that are absent or not valid JSON are folded to a single canonical empty form.
func OverrideBinding(toolName string, argsJSON []byte) string {
	h := sha256.New()
	h.Write([]byte(toolName))
	h.Write([]byte{0})
	h.Write(canonicalArgs(argsJSON))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// canonicalArgs returns a stable byte representation of a JSON arguments blob:
// decoded with UseNumber (so numeric literals are preserved exactly) and
// re-marshaled (so Go sorts object keys and drops whitespace). Empty or
// unparseable input canonicalizes to "null".
func canonicalArgs(argsJSON []byte) []byte {
	trimmed := bytes.TrimSpace(argsJSON)
	if len(trimmed) == 0 {
		return []byte("null")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return []byte("null")
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return canon
}

type vcHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// IssueVC mints an EdDSA JWT credential signed by ks. iss/iat (and exp when
// ttl>0) are filled from ks and the clock; the caller supplies the attestation
// claims. A non-positive ttl issues a credential with no expiry (used for
// long-lived publisher credentials); operator overrides should always set one.
func IssueVC(ks KeyStore, claims VCClaims, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.Iss = ks.DID()
	claims.Iat = now.Unix()
	if ttl > 0 {
		claims.Exp = now.Add(ttl).Unix()
	}

	header := vcHeader{Alg: "EdDSA", Typ: "JWT", Kid: ks.DID()}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("identity: marshaling vc header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("identity: marshaling vc claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := ks.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("identity: signing vc: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyVC parses and verifies an EdDSA JWT credential, returning its claims.
// It fails closed: a malformed token, an unsupported alg, a bad signature, an
// unresolvable issuer, or an expired credential all return an error. The
// issuer key is resolved from the credential's own `iss` DID via resolver.
func VerifyVC(token string, resolver Resolver) (*VCClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("identity: vc is not a 3-part JWT")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("identity: decoding vc header: %w", err)
	}
	var header vcHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("identity: parsing vc header: %w", err)
	}
	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("identity: unsupported vc alg %q (want EdDSA)", header.Alg)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("identity: decoding vc payload: %w", err)
	}
	var claims VCClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("identity: parsing vc claims: %w", err)
	}
	if claims.Iss == "" {
		return nil, fmt.Errorf("identity: vc has no issuer")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("identity: decoding vc signature: %w", err)
	}
	pub, err := resolver.Resolve(claims.Iss)
	if err != nil {
		return nil, fmt.Errorf("identity: resolving vc issuer: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, fmt.Errorf("identity: vc signature verification failed")
	}

	if claims.Exp != 0 && time.Now().Unix() >= claims.Exp {
		return nil, fmt.Errorf("identity: vc expired at %d", claims.Exp)
	}
	return &claims, nil
}
