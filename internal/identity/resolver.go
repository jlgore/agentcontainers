package identity

import (
	"crypto/ed25519"
	"fmt"
)

// Resolver maps a DID to its Ed25519 public key.
type Resolver interface {
	Resolve(did string) (ed25519.PublicKey, error)
}

// DIDKeyResolver resolves did:key DIDs self-certifyingly: the public key is
// recovered from the DID string itself, with no shared state or registry. This
// is sufficient to verify audit chains and VCs produced by any agentcontainers
// instance — the verifier needs only the DID, which travels in the data it is
// checking.
//
// DIDKeyResolver also satisfies audit.SignatureVerifier (the Verify method), so
// `ac audit verify --verify-signatures` can pass it straight through.
type DIDKeyResolver struct{}

func (DIDKeyResolver) Resolve(did string) (ed25519.PublicKey, error) {
	return PublicKeyFromDID(did)
}

// Verify reports whether sig is a valid signature by did over message. It fails
// closed: an unresolvable DID or a bad signature is an error, never a silent
// pass.
func (r DIDKeyResolver) Verify(did string, message, sig []byte) error {
	pub, err := r.Resolve(did)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, message, sig) {
		return fmt.Errorf("identity: signature verification failed for %s", did)
	}
	return nil
}
