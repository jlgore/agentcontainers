package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// entryVersion is the hash-scheme version written on new entries. Version 1
// hashes the full canonicalized entry (all fields except EntryHash); the
// legacy version 0 covered only the chain fields, leaving Metadata and
// Detail outside the hash.
const entryVersion = 1

// envAuditDir overrides the default audit directory when set.
const envAuditDir = "AC_AUDIT_DIR"

// DefaultDir returns the audit directory to use when none is specified:
// $AC_AUDIT_DIR if set, otherwise ~/.ac/audit.
func DefaultDir() (string, error) {
	if dir := os.Getenv(envAuditDir); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("audit: resolving home directory: %w", err)
	}
	return filepath.Join(home, ".ac", "audit"), nil
}

// Signer signs audit entries with a stable cryptographic identity (G1).
// internal/identity.FileKeyStore satisfies it. A nil signer leaves entries
// unsigned (DID/Signature empty), which still hash-chain and verify.
type Signer interface {
	// DID returns the signer's did:key.
	DID() string
	// Sign returns a raw signature over message.
	Sign(message []byte) ([]byte, error)
}

// Logger provides append-only audit logging with hash chain integrity.
type Logger struct {
	mu        sync.Mutex
	file      *os.File
	dir       string
	sessionID string
	sequence  uint64
	prevHash  string
	closed    bool
	signer    Signer
}

// LoggerOption configures a Logger.
type LoggerOption func(*Logger)

// WithDir sets the base audit directory (default: ~/.ac/audit/).
func WithDir(dir string) LoggerOption {
	return func(l *Logger) {
		l.dir = dir
	}
}

// WithSigner attaches a signing identity. Every appended entry is then stamped
// with the signer's DID and an Ed25519 signature over its EntryHash. A nil
// signer is a no-op (entries stay unsigned).
func WithSigner(s Signer) LoggerOption {
	return func(l *Logger) {
		l.signer = s
	}
}

// NewLogger creates a new audit logger for the given session.
func NewLogger(sessionID string, opts ...LoggerOption) (*Logger, error) {
	l := &Logger{
		sessionID: sessionID,
		prevHash:  zeroHash,
	}

	for _, opt := range opts {
		opt(l)
	}

	if l.dir == "" {
		dir, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		l.dir = dir
	}

	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: creating directory %s: %w", l.dir, err)
	}

	path := filepath.Join(l.dir, sessionID+".jsonl")
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		entries, err := ReadLog(path)
		if err != nil {
			return nil, fmt.Errorf("audit: reading existing log: %w", err)
		}
		if err := ValidateChain(entries); err != nil {
			return nil, fmt.Errorf("audit: refusing to append to invalid existing log: %w", err)
		}
		for i := range entries {
			if entries[i].SessionID != sessionID {
				return nil, fmt.Errorf("audit: existing log entry %d has session ID %q, want %q", i, entries[i].SessionID, sessionID)
			}
		}
		l.sequence = uint64(len(entries))
		l.prevHash = entries[len(entries)-1].EntryHash
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("audit: inspecting existing log: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log file: %w", err)
	}
	l.file = f

	return l, nil
}

// LogEntryOption configures optional fields on an audit entry.
type LogEntryOption func(*Entry)

// WithVerdict sets the verdict on an entry.
func WithVerdict(v Verdict) LogEntryOption {
	return func(e *Entry) { e.Verdict = v }
}

// WithCommand sets the command on an entry.
func WithCommand(cmd string) LogEntryOption {
	return func(e *Entry) { e.Command = cmd }
}

// WithResource sets the resource on an entry.
func WithResource(res string) LogEntryOption {
	return func(e *Entry) { e.Resource = res }
}

// WithDetail sets the detail on an entry.
func WithDetail(detail string) LogEntryOption {
	return func(e *Entry) { e.Detail = detail }
}

// WithMetadata adds a string key-value pair to the entry metadata.
func WithMetadata(key, value string) LogEntryOption {
	return WithMetadataAny(key, value)
}

// WithMetadataAny adds a typed value to the entry metadata. Values must be
// JSON-serializable; they are covered by the entry hash.
func WithMetadataAny(key string, value any) LogEntryOption {
	return func(e *Entry) {
		if e.Metadata == nil {
			e.Metadata = make(map[string]any)
		}
		e.Metadata[key] = value
	}
}

// Log appends an entry to the audit log.
func (l *Logger) Log(eventType EventType, actor Actor, opts ...LogEntryOption) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("audit: logger is closed")
	}

	entry := Entry{
		Timestamp: time.Now().UTC(),
		SessionID: l.sessionID,
		Sequence:  l.sequence,
		EventType: eventType,
		Actor:     actor,
		Version:   entryVersion,
		PrevHash:  l.prevHash,
	}

	for _, opt := range opts {
		opt(&entry)
	}

	// Set DID before hashing (it is attested content covered by the hash),
	// then sign over the computed hash. Signature is excluded from the hash
	// (computeHashCanonical zeroes it), so this ordering is consistent.
	if l.signer != nil {
		entry.DID = l.signer.DID()
	}

	hash, err := computeHash(entry)
	if err != nil {
		return err
	}
	entry.EntryHash = hash

	if l.signer != nil {
		sig, err := l.signer.Sign([]byte(entry.EntryHash))
		if err != nil {
			return fmt.Errorf("audit: signing entry: %w", err)
		}
		entry.Signature = base64.StdEncoding.EncodeToString(sig)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshalling entry: %w", err)
	}

	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		return fmt.Errorf("audit: writing entry: %w", err)
	}

	l.prevHash = entry.EntryHash
	l.sequence++

	return nil
}

// Close flushes and closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	return l.file.Close()
}

// Path returns the log file path.
func (l *Logger) Path() string {
	return filepath.Join(l.dir, l.sessionID+".jsonl")
}

// computeHash computes the SHA-256 hash for an entry, dispatching on the
// entry's hash-scheme version.
func computeHash(e Entry) (string, error) {
	if e.Version >= 1 {
		return computeHashCanonical(e)
	}
	return computeHashLegacy(e), nil
}

// computeHashCanonical hashes the full entry as canonicalized JSON: the
// entry is serialized, decoded into generic values, and re-serialized so
// map keys are emitted in sorted order regardless of the in-memory
// representation (e.g. int vs. float64 after a JSON round trip). EntryHash
// is zeroed first, since it is the output of this function.
func computeHashCanonical(e Entry) (string, error) {
	e.EntryHash = ""
	// Signature is excluded from the hash for the same reason as EntryHash:
	// it is computed *over* the hash, so it cannot also be an input to it.
	// DID is intentionally NOT excluded — it is attested content.
	e.Signature = ""
	raw, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("audit: canonicalizing entry: %w", err)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return "", fmt.Errorf("audit: canonicalizing entry: %w", err)
	}
	canon, err := json.Marshal(generic)
	if err != nil {
		return "", fmt.Errorf("audit: canonicalizing entry: %w", err)
	}
	sum := sha256.Sum256(canon)
	return fmt.Sprintf("%x", sum), nil
}

// computeHashLegacy is the version-0 scheme: only the chain fields are
// hashed; Metadata and Detail are not covered. Kept verbatim so logs
// written before the versioned scheme still verify.
func computeHashLegacy(e Entry) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%d|%s|%s:%s|%s|%s",
		e.PrevHash,
		e.Timestamp.Format(time.RFC3339Nano),
		e.SessionID,
		e.Sequence,
		e.EventType,
		e.Actor.Type, e.Actor.Name,
		e.Verdict,
		e.Command,
	)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ReadLog reads a JSONL audit log file and returns all entries.
func ReadLog(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var entries []Entry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("audit: parsing entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: reading log: %w", err)
	}

	return entries, nil
}

// ValidateChain verifies the hash chain integrity of a sequence of entries.
// Returns an error describing the first broken link, or nil if the chain is valid.
func ValidateChain(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}

	for i, entry := range entries {
		// Verify prevHash links.
		if i == 0 {
			if entry.PrevHash != zeroHash {
				return fmt.Errorf("audit: entry 0: expected prevHash %s, got %s", zeroHash, entry.PrevHash)
			}
		} else {
			if entry.PrevHash != entries[i-1].EntryHash {
				return fmt.Errorf("audit: entry %d: prevHash mismatch: expected %s, got %s", i, entries[i-1].EntryHash, entry.PrevHash)
			}
		}

		// Verify the entry's own hash.
		expected, err := computeHash(entry)
		if err != nil {
			return fmt.Errorf("audit: entry %d: %w", i, err)
		}
		if entry.EntryHash != expected {
			return fmt.Errorf("audit: entry %d: hash mismatch: expected %s, got %s", i, expected, entry.EntryHash)
		}

		// Verify sequence is correct.
		if entry.Sequence != uint64(i) {
			return fmt.Errorf("audit: entry %d: expected sequence %d, got %d", i, i, entry.Sequence)
		}
	}

	return nil
}

// SignatureVerifier verifies a raw signature by a DID over a message.
// internal/identity.DIDKeyResolver satisfies it.
type SignatureVerifier interface {
	Verify(did string, message, sig []byte) error
}

// VerifySignatures checks the cryptographic signature on every signed entry
// (G1). It is independent of, and complementary to, ValidateChain: the chain
// proves the entries are intact and ordered; the signatures prove who wrote
// them. An entry with neither DID nor Signature is treated as legacy/unsigned
// and skipped. An entry carrying only one of the two is malformed and fails.
// Verification fails closed on any decode error, hash mismatch, or bad
// signature. Returns the count of entries whose signatures were verified.
func VerifySignatures(entries []Entry, v SignatureVerifier) (int, error) {
	verified := 0
	for i, e := range entries {
		if e.DID == "" && e.Signature == "" {
			continue
		}
		if e.DID == "" || e.Signature == "" {
			return verified, fmt.Errorf("audit: entry %d: incomplete signature (did=%q, sig set=%v)", i, e.DID, e.Signature != "")
		}
		sig, err := base64.StdEncoding.DecodeString(e.Signature)
		if err != nil {
			return verified, fmt.Errorf("audit: entry %d: malformed signature: %w", i, err)
		}
		// Recompute the hash and confirm it matches the stored EntryHash, so
		// the signature is bound to the actual entry content, not a stale or
		// swapped hash value.
		expected, err := computeHash(e)
		if err != nil {
			return verified, fmt.Errorf("audit: entry %d: %w", i, err)
		}
		if e.EntryHash != expected {
			return verified, fmt.Errorf("audit: entry %d: hash mismatch under signature check: expected %s, got %s", i, expected, e.EntryHash)
		}
		if err := v.Verify(e.DID, []byte(e.EntryHash), sig); err != nil {
			return verified, fmt.Errorf("audit: entry %d: %w", i, err)
		}
		verified++
	}
	return verified, nil
}

// ListLogs returns all session audit log files in the audit directory.
// Each returned path is relative to the audit directory.
func ListLogs(dir string) ([]string, error) {
	if dir == "" {
		d, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = d
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: reading directory: %w", err)
	}

	var logs []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".jsonl" {
			logs = append(logs, e.Name())
		}
	}
	return logs, nil
}
