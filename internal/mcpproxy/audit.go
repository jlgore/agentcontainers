package mcpproxy

import (
	"context"
	"errors"
	"fmt"
	"time"

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
		// DNS observation: a tracked policy domain resolved inside the
		// container. The readable name is present when the enforcer could
		// reverse the digest; the digest alone is session-opaque.
		if ip := ev.Details["resolved_ip"]; ip != "" {
			name := ev.Details["domain"]
			if name == "" {
				name = "domain#" + ev.Details["domain_hash"]
			}
			return fmt.Sprintf("dns %s %s -> %s", ev.Details["record_type"], name, ip)
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

// Stream reconnect backoff bounds. Vars (not consts) so tests can shrink
// them.
var (
	streamReconnectBaseDelay = time.Second
	streamReconnectMaxDelay  = 30 * time.Second
)

// LogStreamGap records a drop ("dropped") or recovery ("resumed") of the
// kernel event stream. Kernel events emitted while the stream was down are
// lost; without these markers the loss would be indistinguishable from a
// quiet container, which a forensic audit cannot afford.
func (s *EnforcerAuditSink) LogStreamGap(phase, detail string, downtime time.Duration) error {
	opts := []audit.LogEntryOption{
		audit.WithMetadataAny("phase", phase),
	}
	if detail != "" {
		opts = append(opts, audit.WithDetail(detail))
	}
	if phase == "resumed" {
		opts = append(opts, audit.WithMetadataAny("downtimeMs", downtime.Milliseconds()))
	}
	return s.logger.Log(audit.EventStreamGap, audit.Actor{Type: "system", Name: "enforcer-stream"}, opts...)
}

// StreamEnforcerAudit consumes the enforcer's event stream into the
// enforcer audit chain, reconnecting with exponential backoff on stream
// errors — a transient gRPC drop (enforcer restart, network blip) must not
// silently end the kernel audit trail for the rest of the session. Each
// drop and subsequent resume is recorded as a stream_gap entry. Returns on
// ctx cancellation or when the audit sink itself fails (a broken chain
// cannot be papered over).
func StreamEnforcerAudit(ctx context.Context, client enforcerapi.EnforcerClient, sink *EnforcerAuditSink) error {
	delay := streamReconnectBaseDelay
	var droppedAt time.Time // zero while the stream is healthy

	for {
		stream, err := client.StreamEvents(ctx, &enforcerapi.StreamEventsRequest{})
		if err == nil {
			err = consumeEnforcerStream(stream, sink, &droppedAt, &delay)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, errAuditSink) {
			return err
		}
		if droppedAt.IsZero() {
			droppedAt = time.Now()
			detail := "stream error"
			if err != nil {
				detail = err.Error()
			}
			if gerr := sink.LogStreamGap("dropped", detail, 0); gerr != nil {
				return fmt.Errorf("%w: %w", errAuditSink, gerr)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, streamReconnectMaxDelay)
	}
}

// errAuditSink marks failures writing the audit chain itself — terminal,
// unlike stream errors.
var errAuditSink = errors.New("mcpproxy: enforcer audit sink write failed")

// consumeEnforcerStream drains one stream connection. The first successful
// Recv proves the (re)connection is real: it closes any open gap and resets
// the backoff. Always returns a non-nil error (the Recv that broke the
// stream, or errAuditSink).
func consumeEnforcerStream(stream enforcerapi.Enforcer_StreamEventsClient, sink *EnforcerAuditSink, droppedAt *time.Time, delay *time.Duration) error {
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		if !droppedAt.IsZero() {
			if gerr := sink.LogStreamGap("resumed", "", time.Since(*droppedAt)); gerr != nil {
				return fmt.Errorf("%w: %w", errAuditSink, gerr)
			}
			*droppedAt = time.Time{}
		}
		*delay = streamReconnectBaseDelay
		if err := sink.LogEvent(ev); err != nil {
			return fmt.Errorf("%w: %w", errAuditSink, err)
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
