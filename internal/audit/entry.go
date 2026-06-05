package audit

import "time"

// EventType categorizes audit events.
type EventType string

const (
	EventExec        EventType = "exec"
	EventApproval    EventType = "approval"
	EventEscalation  EventType = "escalation"
	EventEnforcement EventType = "enforcement"
	EventSecret      EventType = "secret"
	EventLifecycle   EventType = "lifecycle"
	EventToolCall    EventType = "tool_call"
	// EventApprovalDecision records a human approve/deny verdict on a
	// proxied tools/call (the `<sessionId>-approval` chain, SPEC §7.3).
	EventApprovalDecision EventType = "approval_decision"
)

// Actor identifies who triggered an event.
type Actor struct {
	Type string `json:"type"` // "agent", "tool", "user", "system"
	Name string `json:"name"` // tool name, agent ID, "human", etc.
}

// Verdict is the outcome of a policy decision.
type Verdict string

const (
	VerdictAllow  Verdict = "allow"
	VerdictDeny   Verdict = "deny"
	VerdictPrompt Verdict = "prompt"
)

// Entry is a single audit log record.
//
// Version selects the hash scheme: 0 (legacy, absent from JSON) covers only
// the chain fields; 1 hashes the full canonicalized entry, making Metadata
// and Detail tamper-evident. New entries are always written at the current
// version; ValidateChain dispatches per entry so legacy logs still verify.
type Entry struct {
	Timestamp time.Time      `json:"timestamp"`
	SessionID string         `json:"sessionId"`
	Sequence  uint64         `json:"sequence"`
	EventType EventType      `json:"eventType"`
	Actor     Actor          `json:"actor"`
	Verdict   Verdict        `json:"verdict,omitempty"`
	Command   string         `json:"command,omitempty"`
	Resource  string         `json:"resource,omitempty"`
	Detail    string         `json:"detail,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Version   int            `json:"v,omitempty"`
	PrevHash  string         `json:"prevHash"`
	EntryHash string         `json:"entryHash"`
}
