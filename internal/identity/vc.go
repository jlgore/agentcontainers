package identity

import (
	"crypto/ed25519"
	"encoding/base64"
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
	// layers (e.g. ["opa_proxy","ebpf_kernel"]); PolicySource is the compiled
	// policy hash (CompiledPolicy.Hash) so the claim is pinned to a specific
	// rule set.
	EnforcementModel     []string `json:"enforcement_model,omitempty"`
	EvidenceImmutability string   `json:"evidence_immutability,omitempty"`
	AuditChainType       string   `json:"audit_chain_type,omitempty"`
	PolicySource         string   `json:"policy_source,omitempty"`

	// Capabilities optionally names what an operator-override VC widens (G3).
	// The override ceiling in Rego decides which of these are honored.
	Capabilities []string `json:"capabilities,omitempty"`
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
