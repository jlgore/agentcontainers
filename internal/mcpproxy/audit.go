package mcpproxy

import (
	"context"
	"fmt"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
)

// AuditSink writes the proxy's tool-call audit trail. It owns the
// `<sessionId>-proxy` logger: one JSONL file with an independent hash chain
// starting at sequence 0 (enforcer and approval streams are separate files
// with their own chains; cross-file correlation is by correlationId, not
// chain linkage).
type AuditSink struct {
	logger *audit.Logger
}

// EnforcerAuditSink writes the `<sessionId>-enforcer` audit chain from
// StreamEvents. It is intentionally separate from proxy.jsonl; correlation is
// by correlationId metadata, not hash-chain linkage.
type EnforcerAuditSink struct {
	logger *audit.Logger
}

func NewEnforcerAuditSink(sessionID, dir string) (*EnforcerAuditSink, error) {
	var opts []audit.LoggerOption
	if dir != "" {
		opts = append(opts, audit.WithDir(dir))
	}
	l, err := audit.NewLogger(sessionID+"-enforcer", opts...)
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: creating enforcer audit logger: %w", err)
	}
	return &EnforcerAuditSink{logger: l}, nil
}

func (s *EnforcerAuditSink) Path() string { return s.logger.Path() }

func (s *EnforcerAuditSink) Close() error { return s.logger.Close() }

func (s *EnforcerAuditSink) LogEvent(ev *enforcerapi.EnforcementEvent) error {
	if ev == nil {
		return nil
	}
	verdict := audit.VerdictAllow
	if ev.Verdict == "block" {
		verdict = audit.VerdictDeny
	}
	server := ev.ContainerId
	if server == "" {
		server = "enforcer"
	}
	opts := []audit.LogEntryOption{
		audit.WithVerdict(verdict),
		audit.WithCommand(enforcerCommand(ev)),
		audit.WithMetadataAny("containerId", ev.ContainerId),
		audit.WithMetadataAny("cgroupId", ev.CgroupId),
		audit.WithMetadataAny("correlationId", ev.CorrelationId),
		audit.WithMetadataAny("pid", ev.Pid),
		audit.WithMetadataAny("comm", ev.Comm),
	}
	for k, v := range ev.Details {
		opts = append(opts, audit.WithMetadataAny(k, v))
	}
	return s.logger.Log(audit.EventEnforcement, audit.Actor{Type: "tool", Name: server}, opts...)
}

func enforcerCommand(ev *enforcerapi.EnforcementEvent) string {
	switch ev.Domain {
	case "network":
		if dst := ev.Details["dst_ip"]; dst != "" {
			return fmt.Sprintf("connect %s:%s/%s", dst, ev.Details["dst_port"], ev.Details["protocol"])
		}
	case "filesystem":
		return "open inode " + ev.Details["inode"]
	case "process":
		if binary := ev.Details["binary"]; binary != "" {
			return binary
		}
	case "credential":
		return "credential inode " + ev.Details["inode"]
	}
	return ev.Domain
}

func StreamEnforcerAudit(ctx context.Context, client enforcerapi.EnforcerClient, sink *EnforcerAuditSink) error {
	stream, err := client.StreamEvents(ctx, &enforcerapi.StreamEventsRequest{})
	if err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := sink.LogEvent(ev); err != nil {
			return err
		}
	}
}

// NewAuditSink creates the proxy audit logger for a session. An empty dir
// uses audit.DefaultDir ($AC_AUDIT_DIR or ~/.ac/audit).
func NewAuditSink(sessionID, dir string) (*AuditSink, error) {
	var opts []audit.LoggerOption
	if dir != "" {
		opts = append(opts, audit.WithDir(dir))
	}
	l, err := audit.NewLogger(sessionID+"-proxy", opts...)
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: creating proxy audit logger: %w", err)
	}
	return &AuditSink{logger: l}, nil
}

// ToolCallRecord captures one proxied tools/call for the audit trail.
type ToolCallRecord struct {
	CorrelationID     string
	Server            string
	ContainerID       string
	Enforcement       string // "proxy-only" for remote backends, else empty
	Tool              string
	ArgsSummary       string
	Verdict           audit.Verdict
	Reasons           []string
	PoliciesEvaluated []string
	ApprovalRequired  bool
	LatencyMs         int64
}

// LogToolCall appends a tool_call entry per SPEC §7.1 (camelCase metadata
// keys, typed values covered by the entry hash).
func (s *AuditSink) LogToolCall(rec ToolCallRecord) error {
	// Arrays serialize as [] rather than null so DuckDB unnest() works.
	if rec.Reasons == nil {
		rec.Reasons = []string{}
	}
	if rec.PoliciesEvaluated == nil {
		rec.PoliciesEvaluated = []string{}
	}

	opts := []audit.LogEntryOption{
		audit.WithVerdict(rec.Verdict),
		audit.WithCommand(rec.Tool + ": " + rec.ArgsSummary),
		audit.WithMetadataAny("correlationId", rec.CorrelationID),
		audit.WithMetadataAny("tool", rec.Tool),
		audit.WithMetadataAny("argsSummary", rec.ArgsSummary),
		audit.WithMetadataAny("reasons", rec.Reasons),
		audit.WithMetadataAny("policiesEvaluated", rec.PoliciesEvaluated),
		audit.WithMetadataAny("approvalRequired", rec.ApprovalRequired),
		audit.WithMetadataAny("latencyMs", rec.LatencyMs),
	}
	if rec.ContainerID != "" {
		opts = append(opts, audit.WithMetadataAny("containerId", rec.ContainerID))
	}
	if rec.Enforcement != "" {
		opts = append(opts, audit.WithMetadataAny("enforcement", rec.Enforcement))
	}

	return s.logger.Log(audit.EventToolCall, audit.Actor{Type: "tool", Name: rec.Server}, opts...)
}

// Path returns the proxy.jsonl file path.
func (s *AuditSink) Path() string {
	return s.logger.Path()
}

// Close flushes and closes the audit log.
func (s *AuditSink) Close() error {
	return s.logger.Close()
}
