package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"
)

// fakeSigner is a minimal Ed25519 Signer + SignatureVerifier so the audit
// package's signing tests stay self-contained (no dependency on the identity
// package). did is an opaque key id mapped back to the public key on verify.
type fakeSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	did  string
}

func newFakeSigner(t *testing.T, did string) *fakeSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return &fakeSigner{priv: priv, pub: pub, did: did}
}

func (f *fakeSigner) DID() string                     { return f.did }
func (f *fakeSigner) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(f.priv, msg), nil }
func (f *fakeSigner) Verify(did string, msg, sig []byte) error {
	if did != f.did {
		return errUnknownDID
	}
	if !ed25519.Verify(f.pub, msg, sig) {
		return errBadSig
	}
	return nil
}

var (
	errUnknownDID = &verifyErr{"unknown did"}
	errBadSig     = &verifyErr{"bad signature"}
)

type verifyErr struct{ s string }

func (e *verifyErr) Error() string { return e.s }

func TestSignedEntriesChainAndVerify(t *testing.T) {
	dir := t.TempDir()
	signer := newFakeSigner(t, "did:key:zTestSigner")

	logger, err := NewLogger("sess-signed", WithDir(dir), WithSigner(signer))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	for range 3 {
		if err := logger.Log(EventToolCall, Actor{Type: "tool", Name: "run"}, WithVerdict(VerdictAllow)); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	entries, err := ReadLog(filepath.Join(dir, "sess-signed.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Hash chain is unaffected by signing.
	if err := ValidateChain(entries); err != nil {
		t.Fatalf("chain invalid: %v", err)
	}
	// Every entry is signed and verifies.
	n, err := VerifySignatures(entries, signer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d entries, want 3", n)
	}
	for i, e := range entries {
		if e.DID != signer.DID() {
			t.Errorf("entry %d DID = %q", i, e.DID)
		}
		if e.Signature == "" {
			t.Errorf("entry %d unsigned", i)
		}
	}
}

func TestVerifySignaturesDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	signer := newFakeSigner(t, "did:key:zTamper")
	logger, _ := NewLogger("sess-tamper", WithDir(dir), WithSigner(signer))
	_ = logger.Log(EventToolCall, Actor{Type: "tool", Name: "run"}, WithCommand("ls"))
	_ = logger.Close()

	entries, err := ReadLog(filepath.Join(dir, "sess-tamper.jsonl"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Tamper an attested field. EntryHash no longer matches recomputation, so
	// the signature check fails closed even though the raw signature bytes are
	// untouched.
	entries[0].Command = "rm -rf /"
	if _, err := VerifySignatures(entries, signer); err == nil {
		t.Fatalf("expected tamper to be detected")
	}

	// Flipping the signature bytes also fails.
	entries[0].Command = "ls"
	entries[0].Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := VerifySignatures(entries, signer); err == nil {
		t.Fatalf("expected bad signature to be detected")
	}
}

func TestUnsignedEntriesSkipped(t *testing.T) {
	dir := t.TempDir()
	logger, _ := NewLogger("sess-unsigned", WithDir(dir)) // no signer
	_ = logger.Log(EventToolCall, Actor{Type: "tool", Name: "run"})
	_ = logger.Close()

	entries, _ := ReadLog(filepath.Join(dir, "sess-unsigned.jsonl"))
	n, err := VerifySignatures(entries, newFakeSigner(t, "did:key:zX"))
	if err != nil {
		t.Fatalf("unsigned should not error: %v", err)
	}
	if n != 0 {
		t.Fatalf("verified %d, want 0 (all unsigned)", n)
	}
}
