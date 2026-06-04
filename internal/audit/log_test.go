package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNewLogger(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("test-session", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close() //nolint:errcheck

	path := l.Path()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("log file not created at %s: %v", path, err)
	}

	if !strings.HasSuffix(path, "test-session.jsonl") {
		t.Errorf("expected path to end with test-session.jsonl, got %s", path)
	}
}

func TestLogEntry(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("log-entry-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "agent", Name: "claude"}
	err = l.Log(EventExec, actor,
		WithVerdict(VerdictAllow),
		WithCommand("ls -la"),
		WithResource("/home/user"),
		WithDetail("listing directory"),
		WithMetadata("cwd", "/home/user"),
	)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.SessionID != "log-entry-test" {
		t.Errorf("sessionID = %q, want %q", e.SessionID, "log-entry-test")
	}
	if e.Sequence != 0 {
		t.Errorf("sequence = %d, want 0", e.Sequence)
	}
	if e.EventType != EventExec {
		t.Errorf("eventType = %q, want %q", e.EventType, EventExec)
	}
	if e.Actor.Type != "agent" || e.Actor.Name != "claude" {
		t.Errorf("actor = %+v, want {Type:agent Name:claude}", e.Actor)
	}
	if e.Verdict != VerdictAllow {
		t.Errorf("verdict = %q, want %q", e.Verdict, VerdictAllow)
	}
	if e.Command != "ls -la" {
		t.Errorf("command = %q, want %q", e.Command, "ls -la")
	}
	if e.Resource != "/home/user" {
		t.Errorf("resource = %q, want %q", e.Resource, "/home/user")
	}
	if e.Detail != "listing directory" {
		t.Errorf("detail = %q, want %q", e.Detail, "listing directory")
	}
	if e.Metadata["cwd"] != "/home/user" {
		t.Errorf("metadata[cwd] = %q, want %q", e.Metadata["cwd"], "/home/user")
	}
	if e.PrevHash != zeroHash {
		t.Errorf("prevHash = %q, want zero hash", e.PrevHash)
	}
	if e.EntryHash == "" {
		t.Error("entryHash is empty")
	}
}

func TestLogMultipleEntries(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("multi-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "tool", Name: "bash"}
	for i := 0; i < 3; i++ {
		if err := l.Log(EventExec, actor, WithCommand("echo hello")); err != nil {
			t.Fatalf("Log entry %d: %v", i, err)
		}
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	for i, e := range entries {
		if e.Sequence != uint64(i) {
			t.Errorf("entry %d: sequence = %d, want %d", i, e.Sequence, i)
		}
	}
}

func TestHashChain(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("chain-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "system", Name: "enforcer"}
	for i := 0; i < 5; i++ {
		if err := l.Log(EventEnforcement, actor, WithVerdict(VerdictDeny)); err != nil {
			t.Fatalf("Log entry %d: %v", i, err)
		}
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}

	if err := ValidateChain(entries); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

func TestHashChainTampered(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("tamper-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "agent", Name: "codex"}
	for i := 0; i < 3; i++ {
		if err := l.Log(EventExec, actor, WithCommand("cmd")); err != nil {
			t.Fatalf("Log entry %d: %v", i, err)
		}
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}

	// Tamper with entry 1's command field.
	entries[1].Command = "rm -rf /"

	err = ValidateChain(entries)
	if err == nil {
		t.Fatal("expected ValidateChain to fail on tampered entry")
	}
	if !strings.Contains(err.Error(), "entry 1") {
		t.Errorf("expected error about entry 1, got: %v", err)
	}
}

func TestReadLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manual.jsonl")

	entry := Entry{
		SessionID: "manual",
		Sequence:  0,
		EventType: EventLifecycle,
		Actor:     Actor{Type: "system", Name: "init"},
		PrevHash:  zeroHash,
	}
	hash, err := computeHash(entry)
	if err != nil {
		t.Fatalf("computeHash: %v", err)
	}
	entry.EntryHash = hash

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	entries, err := ReadLog(path)
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].SessionID != "manual" {
		t.Errorf("sessionID = %q, want %q", entries[0].SessionID, "manual")
	}
	if entries[0].EventType != EventLifecycle {
		t.Errorf("eventType = %q, want %q", entries[0].EventType, EventLifecycle)
	}
}

func TestValidateChainEmpty(t *testing.T) {
	if err := ValidateChain(nil); err != nil {
		t.Errorf("ValidateChain(nil) = %v, want nil", err)
	}
	if err := ValidateChain([]Entry{}); err != nil {
		t.Errorf("ValidateChain([]) = %v, want nil", err)
	}
}

func TestLogConcurrent(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("concurrent-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	const numGoroutines = 10
	const entriesPerGoroutine = 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			actor := Actor{Type: "agent", Name: "worker"}
			for i := 0; i < entriesPerGoroutine; i++ {
				if err := l.Log(EventExec, actor, WithCommand("work")); err != nil {
					t.Errorf("Log: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}

	expectedCount := numGoroutines * entriesPerGoroutine
	if len(entries) != expectedCount {
		t.Fatalf("expected %d entries, got %d", expectedCount, len(entries))
	}

	// Chain should still be valid because the mutex serializes writes.
	if err := ValidateChain(entries); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

func TestLoggerClose(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("close-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Subsequent Log should return error.
	actor := Actor{Type: "agent", Name: "claude"}
	err = l.Log(EventExec, actor)
	if err == nil {
		t.Fatal("expected error after Close, got nil")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("expected error about closed logger, got: %v", err)
	}

	// Double close should not error.
	if err := l.Close(); err != nil {
		t.Errorf("double Close: %v", err)
	}
}

func TestListLogs(t *testing.T) {
	dir := t.TempDir()

	// Create a couple of log files.
	for _, name := range []string{"session-a.jsonl", "session-b.jsonl", "not-a-log.txt"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		_ = f.Close()
	}

	logs, err := ListLogs(dir)
	if err != nil {
		t.Fatalf("ListLogs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d: %v", len(logs), logs)
	}
}

func TestTypedMetadataRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("typed-meta-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "tool", Name: "sift-gateway"}
	err = l.Log(EventToolCall, actor,
		WithVerdict(VerdictAllow),
		WithCommand("run_command: find /evidence"),
		WithMetadataAny("reasons", []string{"a", "b"}),
		WithMetadataAny("policiesEvaluated", []string{"sift.denied_binaries"}),
		WithMetadataAny("latencyMs", 3),
		WithMetadataAny("approvalRequired", false),
	)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	reasons, ok := e.Metadata["reasons"].([]any)
	if !ok || len(reasons) != 2 || reasons[0] != "a" {
		t.Errorf("metadata[reasons] = %#v, want [a b]", e.Metadata["reasons"])
	}
	if lat, ok := e.Metadata["latencyMs"].(float64); !ok || lat != 3 {
		t.Errorf("metadata[latencyMs] = %#v, want 3", e.Metadata["latencyMs"])
	}
	if approval, ok := e.Metadata["approvalRequired"].(bool); !ok || approval {
		t.Errorf("metadata[approvalRequired] = %#v, want false", e.Metadata["approvalRequired"])
	}

	// The decoded entry (with JSON-generic metadata values) must still
	// validate: canonical hashing has to be representation-independent.
	if err := ValidateChain(entries); err != nil {
		t.Errorf("ValidateChain after round trip: %v", err)
	}
}

func TestHashCoversMetadataAndDetail(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLogger("meta-tamper-test", WithDir(dir))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	actor := Actor{Type: "tool", Name: "sift-gateway"}
	if err := l.Log(EventToolCall, actor,
		WithDetail("original detail"),
		WithMetadataAny("correlationId", "0192b3a4"),
	); err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()

	entries, err := ReadLog(l.Path())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}

	// Tamper with metadata: must now break the hash (it did not under v0).
	tampered := make([]Entry, len(entries))
	copy(tampered, entries)
	tampered[0].Metadata["correlationId"] = "ffffffff"
	if err := ValidateChain(tampered); err == nil {
		t.Error("expected ValidateChain to fail on tampered metadata")
	}

	// Restore and tamper with detail instead.
	entries[0].Metadata["correlationId"] = "0192b3a4"
	entries[0].Detail = "rewritten detail"
	if err := ValidateChain(entries); err == nil {
		t.Error("expected ValidateChain to fail on tampered detail")
	}
}

func TestCanonicalHashDeterministic(t *testing.T) {
	e := Entry{
		SessionID: "det-test",
		EventType: EventToolCall,
		Actor:     Actor{Type: "tool", Name: "x"},
		Version:   entryVersion,
		Metadata:  map[string]any{"b": 2, "a": []string{"x"}, "c": true},
		PrevHash:  zeroHash,
	}
	h1, err := computeHash(e)
	if err != nil {
		t.Fatalf("computeHash: %v", err)
	}
	h2, err := computeHash(e)
	if err != nil {
		t.Fatalf("computeHash: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic: %s != %s", h1, h2)
	}
}

func TestLegacyV0ChainStillValidates(t *testing.T) {
	// Build a v0-style chain by hand using the legacy hash, simulating a
	// log written before the versioned scheme.
	var entries []Entry
	prev := zeroHash
	for i := range 3 {
		e := Entry{
			SessionID: "legacy-test",
			Sequence:  uint64(i),
			EventType: EventExec,
			Actor:     Actor{Type: "agent", Name: "claude"},
			Command:   "ls",
			PrevHash:  prev,
		}
		e.EntryHash = computeHashLegacy(e)
		prev = e.EntryHash
		entries = append(entries, e)
	}

	if err := ValidateChain(entries); err != nil {
		t.Errorf("ValidateChain on legacy chain: %v", err)
	}

	// A tampered v1 entry must still fail.
	entries[1].Command = "rm -rf /"
	if err := ValidateChain(entries); err == nil {
		t.Error("expected ValidateChain to fail on tampered legacy entry")
	}
}

func TestAuditDirEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AC_AUDIT_DIR", dir)

	l, err := NewLogger("env-dir-test")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	_ = l.Close()

	if filepath.Dir(l.Path()) != dir {
		t.Errorf("log path %s not under AC_AUDIT_DIR %s", l.Path(), dir)
	}

	got, err := DefaultDir()
	if err != nil {
		t.Fatalf("DefaultDir: %v", err)
	}
	if got != dir {
		t.Errorf("DefaultDir() = %s, want %s", got, dir)
	}
}

func TestListLogsEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nonexistent")
	logs, err := ListLogs(dir)
	if err != nil {
		t.Fatalf("ListLogs: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}
