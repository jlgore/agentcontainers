// Package identity provides the agent's cryptographic identity: a single
// Ed25519 key that roots a did:key, signs audit-log entries, and signs the
// verifiable credentials (VCs) the instance issues. One key across all three
// means a verifier needs exactly one trust anchor (the did:key, which is
// self-certifying) to check an audit chain, a published catalog credential,
// and an operator override VC.
//
// This package deliberately reuses the same Ed25519 primitive already used for
// OCI org-policy signing (internal/oci/orgsig.go); it does NOT reuse the OIDC
// ES256 ephemeral key (internal/oidc), whose key rotates per process and is
// scoped to short-lived workload tokens. A durable, did:key-rooted identity is
// the wrong fit for that ephemeral key, so VCs here are EdDSA-signed over the
// same key as the audit chain.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// envKeyPath overrides the default identity key location when set.
const envKeyPath = "AC_IDENTITY_KEY"

// KeyStore is the agent's Ed25519 signing identity. Sign satisfies the
// audit.Signer interface (DID + Sign), so a KeyStore can be handed directly to
// the audit sinks.
type KeyStore interface {
	// DID returns the did:key string for this identity's public key.
	DID() string
	// PublicKey returns the Ed25519 public key.
	PublicKey() ed25519.PublicKey
	// Sign signs message with the private key. The signature is raw Ed25519
	// (64 bytes); callers encode it as they see fit.
	Sign(message []byte) ([]byte, error)
}

// FileKeyStore is a KeyStore backed by an on-disk Ed25519 private key.
type FileKeyStore struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	did  string
}

// NewKeyStore wraps an existing Ed25519 private key as a KeyStore. Useful for
// tests and for callers that already hold a key.
func NewKeyStore(priv ed25519.PrivateKey) *FileKeyStore {
	pub := priv.Public().(ed25519.PublicKey)
	return &FileKeyStore{priv: priv, pub: pub, did: DIDFromPublicKey(pub)}
}

// DefaultKeyPath returns the identity key path: $AC_IDENTITY_KEY if set,
// otherwise ~/.agentcontainers/identity/ed25519.pem.
func DefaultKeyPath() (string, error) {
	if p := os.Getenv(envKeyPath); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("identity: resolving home directory: %w", err)
	}
	return filepath.Join(home, ".agentcontainers", "identity", "ed25519.pem"), nil
}

// LoadOrCreateKeyStore loads the Ed25519 key at path, generating and persisting
// a fresh one (PKCS#8 PEM, 0600) if the file does not exist. An empty path uses
// DefaultKeyPath. The directory is created with 0700 when missing.
func LoadOrCreateKeyStore(path string) (*FileKeyStore, error) {
	if path == "" {
		p, err := DefaultKeyPath()
		if err != nil {
			return nil, err
		}
		path = p
	}

	if priv, err := loadKey(path); err == nil {
		return NewKeyStore(priv), nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// Generate a new identity. Fail closed: a key we cannot persist is not a
	// usable identity (the next run would mint a different DID).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generating key: %w", err)
	}
	if err := saveKey(path, priv); err != nil {
		return nil, err
	}
	return NewKeyStore(priv), nil
}

func (k *FileKeyStore) DID() string                  { return k.did }
func (k *FileKeyStore) PublicKey() ed25519.PublicKey { return k.pub }

func (k *FileKeyStore) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(k.priv, message), nil
}

// loadKey reads an Ed25519 private key, accepting either a PKCS#8 "PRIVATE KEY"
// PEM block (standard Go output) or a raw 32-byte seed. Mirrors the loader in
// internal/cli/build.go so operator-provided keys interoperate.
func loadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(data); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity: parsing PEM private key %q: %w", path, err)
		}
		ed, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("identity: key %q is not Ed25519 (got %T)", path, key)
		}
		return ed, nil
	}
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}
	return nil, fmt.Errorf("identity: unrecognized key format in %q: want PEM PRIVATE KEY or %d-byte seed", path, ed25519.SeedSize)
}

// saveKey writes priv as a PKCS#8 PEM file with 0600 permissions, creating the
// parent directory (0700) if needed. The write is atomic (temp + rename) so a
// crash never leaves a truncated key file.
func saveKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("identity: marshaling key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("identity: creating key directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pemBytes, 0o600); err != nil {
		return fmt.Errorf("identity: writing key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("identity: finalizing key: %w", err)
	}
	return nil
}
