package identity

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// did:key for an Ed25519 public key encodes the multicodec-prefixed key with
// multibase base58btc (the "z" prefix):
//
//	did:key:z<base58btc( 0xed 0x01 ‖ pubkey )>
//
// 0xed01 is the unsigned-varint multicodec identifier for "ed25519-pub". This
// is self-certifying: the public key is recoverable from the DID string with
// no registry lookup, which is exactly what audit-chain verification needs.
var ed25519PubMulticodec = []byte{0xed, 0x01}

const didKeyPrefix = "did:key:z"

// DIDFromPublicKey returns the did:key string for an Ed25519 public key.
func DIDFromPublicKey(pub ed25519.PublicKey) string {
	buf := make([]byte, 0, len(ed25519PubMulticodec)+len(pub))
	buf = append(buf, ed25519PubMulticodec...)
	buf = append(buf, pub...)
	return didKeyPrefix + base58Encode(buf)
}

// PublicKeyFromDID resolves a did:key string back to its Ed25519 public key.
// It is the inverse of DIDFromPublicKey and the core of the DID resolver. Only
// Ed25519 did:keys are supported; anything else is an error (fail closed).
func PublicKeyFromDID(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, didKeyPrefix) {
		return nil, fmt.Errorf("identity: %q is not an ed25519 did:key (want %q prefix)", did, didKeyPrefix)
	}
	raw, err := base58Decode(did[len(didKeyPrefix):])
	if err != nil {
		return nil, fmt.Errorf("identity: decoding did:key %q: %w", did, err)
	}
	if len(raw) != len(ed25519PubMulticodec)+ed25519.PublicKeySize ||
		raw[0] != ed25519PubMulticodec[0] || raw[1] != ed25519PubMulticodec[1] {
		return nil, fmt.Errorf("identity: did:key %q is not an ed25519-pub key", did)
	}
	return ed25519.PublicKey(raw[len(ed25519PubMulticodec):]), nil
}

// base58Alphabet is the Bitcoin/IPFS base58btc alphabet.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode encodes bytes using the base58btc alphabet. Leading zero bytes
// map to leading '1' characters, per the standard.
func base58Encode(input []byte) string {
	// Count leading zeros (encoded as '1').
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// Big-number base conversion: repeatedly divide the byte string (base 256)
	// by 58, collecting remainders.
	in := make([]byte, len(input))
	copy(in, input)
	var out []byte
	for start := zeros; start < len(in); {
		remainder := 0
		for i := start; i < len(in); i++ {
			acc := int(in[i]) + remainder*256
			in[i] = byte(acc / 58)
			remainder = acc % 58
		}
		out = append(out, base58Alphabet[remainder])
		if in[start] == 0 {
			start++
		}
	}

	var sb strings.Builder
	for i := 0; i < zeros; i++ {
		sb.WriteByte('1')
	}
	// out holds digits least-significant first; emit reversed.
	for i := len(out) - 1; i >= 0; i-- {
		sb.WriteByte(out[i])
	}
	return sb.String()
}

// base58Decode reverses base58Encode. An invalid character is an error.
func base58Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}

	var out []byte
	for i := zeros; i < len(s); i++ {
		idx := strings.IndexByte(base58Alphabet, s[i])
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", s[i])
		}
		carry := idx
		for j := 0; j < len(out); j++ {
			carry += int(out[j]) * 58
			out[j] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			out = append(out, byte(carry&0xff))
			carry >>= 8
		}
	}

	// out is little-endian; prepend leading zeros and reverse to big-endian.
	res := make([]byte, zeros+len(out))
	for i, b := range out {
		res[zeros+len(out)-1-i] = b
	}
	return res, nil
}
