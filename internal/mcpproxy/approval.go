package mcpproxy

import (
	"fmt"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
)

// ApprovalAuditSink writes the `<sessionId>-approval` audit chain — the
// authoritative record of human approve/deny decisions (SPEC §7.3).
// proxy.jsonl's approvalRequired field is a summary; this file is the
// record. Independent hash chain; cross-file correlation by correlationId.
type ApprovalAuditSink struct {
	logger *audit.Logger
}

// NewApprovalAuditSink creates the approval audit logger for a session. An
// empty dir uses audit.DefaultDir ($AC_AUDIT_DIR or ~/.ac/audit).
func NewApprovalAuditSink(sessionID, dir string) (*ApprovalAuditSink, error) {
	var opts []audit.LoggerOption
	if dir != "" {
		opts = append(opts, audit.WithDir(dir))
	}
	l, err := audit.NewLogger(sessionID+"-approval", opts...)
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: creating approval audit logger: %w", err)
	}
	return &ApprovalAuditSink{logger: l}, nil
}

// Path returns the approval.jsonl file path.
func (s *ApprovalAuditSink) Path() string { return s.logger.Path() }

// Close flushes and closes the audit log.
func (s *ApprovalAuditSink) Close() error { return s.logger.Close() }

// ApprovalRecord captures one human decision on a tool call.
type ApprovalRecord struct {
	CorrelationID    string
	Server           string
	Tool             string
	ArgsSummary      string
	Approved         bool
	Reason           string
	Decider          string // empty when the decision was synthesized (timeout/cancel)
	PromptDurationMs int64
}

// LogDecision appends an approval_decision entry per SPEC §7.3. Decisions a
// human made carry actor {user, <decider>}; synthesized denials (timeout,
// client disconnect) carry actor {system, approval-timeout} so the audit
// trail never attributes them to a person.
func (s *ApprovalAuditSink) LogDecision(rec ApprovalRecord) error {
	verdict := audit.VerdictDeny
	if rec.Approved {
		verdict = audit.VerdictAllow
	}
	actor := audit.Actor{Type: "user", Name: rec.Decider}
	if rec.Decider == "" {
		actor = audit.Actor{Type: "system", Name: "approval-timeout"}
	}

	return s.logger.Log(audit.EventApprovalDecision, actor,
		audit.WithVerdict(verdict),
		audit.WithCommand(rec.Tool+": "+rec.ArgsSummary),
		audit.WithMetadataAny("correlationId", rec.CorrelationID),
		audit.WithMetadataAny("server", rec.Server),
		audit.WithMetadataAny("tool", rec.Tool),
		audit.WithMetadataAny("argsSummary", rec.ArgsSummary),
		audit.WithMetadataAny("reason", rec.Reason),
		audit.WithMetadataAny("promptDurationMs", rec.PromptDurationMs),
	)
}
