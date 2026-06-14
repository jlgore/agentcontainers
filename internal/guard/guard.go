// Package guard evaluates an AI agent's own tool calls — Claude Code's Bash
// (shell commands) and its file-mutating tools (Write/Edit/MultiEdit/
// NotebookEdit) — against the same OPA policy that gates the MCP forensic
// tools, escalating policy denials to a human via the approval broker and
// recording every decision in the audit log.
//
// It is the out-of-band authority a Claude Code PreToolUse hook consults: the
// agent runs the thin `agentcontainer guard hook` client inside its container,
// but the decision is made here, in a process the agent cannot reach or
// tamper with. The eBPF enforcer remains the hard floor underneath; this is
// the semantic layer that reasons about whether a *command* is policy-allowed
// (interpreter escapes, protected-path removal, denied binaries) — things the
// kernel layer cannot express.
package guard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/mcpproxy"
)

// Decision values mirror the Claude Code PreToolUse permissionDecision field.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionAsk   = "ask"
)

// Request is the subset of a Claude Code PreToolUse hook payload the guard
// needs. The hook forwards its stdin verbatim; the service decodes this.
type Request struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	Cwd       string          `json:"cwd"`
	SessionID string          `json:"session_id"`
	// ToolUseID is Claude Code's stable per-call id, present on both the
	// PreToolUse and PostToolUse payloads — the inline ledger's join key.
	ToolUseID string `json:"tool_use_id"`
	// HookEventName routes the socket dispatch: "PreToolUse" (or "" for older
	// hooks) → Decide; "PostToolUse" → Report.
	HookEventName string `json:"hook_event_name"`
}

// Verdict is the guard's answer, which the hook maps onto permissionDecision.
type Verdict struct {
	Decision string `json:"decision"` // allow | deny | ask
	Reason   string `json:"reason,omitempty"`
	Decider  string `json:"decider,omitempty"` // who approved/denied, when a human did
}

// Service holds the compiled policy evaluator, the optional human-approval
// broker, and the audit logger. One Service serves many hook requests
// concurrently; the evaluator and broker are safe for concurrent use.
type Service struct {
	eval        *mcpproxy.Evaluator
	outputFlags []string
	broker      *approval.ToolCallBroker // nil → policy-only (no HITL escalation)
	audit       *audit.Logger            // nil → no audit
	log         *zap.Logger
	examiner    string
	inline      bool    // inline mode: escalations return "ask", host audits via ledger
	ledger      *ledger // non-nil iff inline
}

// Options configure a Service.
type Options struct {
	Evaluator   *mcpproxy.Evaluator
	OutputFlags []string
	Broker      *approval.ToolCallBroker
	Audit       *audit.Logger
	Logger      *zap.Logger
	Examiner    string
	// Inline turns on inline-approval mode: a policy denial returns DecisionAsk
	// (Claude Code renders its native prompt) instead of blocking on Broker,
	// and the host tracks the outcome in a ledger. Mutually exclusive with
	// Broker. LedgerGrace bounds how long an escalation waits for a PostToolUse
	// execution report before being reaped as denied-inferred (default 5m).
	Inline      bool
	LedgerGrace time.Duration
}

// New builds a Service. Evaluator is required; Broker, Audit, and Logger are
// optional (a nil Broker means a policy denial is final; a nil Logger uses a
// no-op).
func New(opts Options) *Service {
	log := opts.Logger
	if log == nil {
		log = zap.NewNop()
	}
	s := &Service{
		eval:        opts.Evaluator,
		outputFlags: opts.OutputFlags,
		broker:      opts.Broker,
		audit:       opts.Audit,
		log:         log,
		examiner:    opts.Examiner,
		inline:      opts.Inline,
	}
	if opts.Inline {
		s.ledger = newLedger(opts.LedgerGrace, log, s.recordDeniedInferred)
	}
	return s
}

// StartReconciler runs the inline ledger's reconcile loop until ctx is
// canceled (it then drains remaining escalations as denied-inferred). It is a
// no-op when not in inline mode. Call it in a goroutine.
func (s *Service) StartReconciler(ctx context.Context) {
	if s.ledger != nil {
		s.ledger.reconcileLoop(ctx)
	}
}

// Decide returns the guard's verdict for a single tool call. It never returns
// an error: an internal failure (policy engine error, broker unavailable)
// resolves to a deny — the guard fails closed.
func (s *Service) Decide(ctx context.Context, req Request) Verdict {
	act, ok := s.activity(req)
	if !ok {
		// No policy-evaluated action (a tool the guard doesn't model, or an
		// empty command/path). The semantic policy has no say here, so allow —
		// the eBPF floor still applies to anything the action would touch.
		v := Verdict{Decision: DecisionAllow, Reason: "no policy-evaluated action"}
		s.record(req, "", v, false)
		return v
	}
	line := act.subject

	allowed, reasons, err := s.evaluate(ctx, req, act.parsed)
	if err != nil {
		// Fail CLOSED: a broken policy engine never falls open.
		v := Verdict{Decision: DecisionDeny, Reason: "policy engine error: " + err.Error()}
		s.log.Error("guard policy evaluation failed", zap.String("tool", req.ToolName), zap.Error(err))
		s.record(req, line, v, false)
		return v
	}

	if allowed {
		v := Verdict{Decision: DecisionAllow}
		s.record(req, line, v, false)
		return v
	}

	// Policy denied. Escalate to a human when a broker is configured;
	// otherwise the denial is final.
	reason := strings.Join(reasons, "; ")

	// Inline mode: don't block on the broker — hand the decision to Claude
	// Code's own permission prompt by returning DecisionAsk, and track the
	// escalation in the ledger. The agent's PostToolUse hook reports execution
	// (= the human approved), resolving the entry; unresolved entries are
	// reaped as denied-inferred by the reconciler.
	if s.inline {
		escID := newID()
		s.ledger.add(&pendingEscalation{
			escalationID: escID,
			toolUseID:    req.ToolUseID,
			tool:         req.ToolName,
			subject:      line,
			sessionID:    req.SessionID,
			askedAt:      time.Now().UTC(),
		})
		s.recordAsked(req, line, reason, escID)
		return Verdict{Decision: DecisionAsk, Reason: reason}
	}

	if s.broker == nil {
		v := Verdict{Decision: DecisionDeny, Reason: reason}
		s.record(req, line, v, false)
		return v
	}

	dec := s.broker.Request(ctx, approval.ToolCallRequest{
		ID:          newID(),
		Server:      "agent",
		Tool:        req.ToolName,
		ArgsSummary: summarize(line),
	})
	v := Verdict{Decision: DecisionDeny, Reason: reason, Decider: dec.Decider}
	if dec.Approved {
		v.Decision = DecisionAllow
		v.Reason = dec.Reason
		if v.Reason == "" {
			v.Reason = "approved by " + decider(dec)
		}
	} else if dec.Reason != "" {
		v.Reason = dec.Reason
	}
	s.record(req, line, v, true)
	return v
}

// evaluate runs every decomposed sub-command/action against the policy. It
// denies if any denies; reasons are the deduplicated, human-facing union
// (sift.<pkg> prefixes stripped).
func (s *Service) evaluate(ctx context.Context, req Request, parsedList []mcpproxy.Parsed) (allowed bool, reasons []string, err error) {
	pctx := s.policyContext(req)
	if len(parsedList) == 0 {
		parsedList = []mcpproxy.Parsed{{}}
	}

	allowed = true
	seen := make(map[string]bool)
	for _, parsed := range parsedList {
		d, evErr := s.eval.EvaluateParsed(ctx, "agent", req.ToolName, nil, parsed, pctx)
		if evErr != nil {
			return false, nil, evErr
		}
		if !d.Allowed {
			allowed = false
		}
		for _, r := range d.Reasons {
			r = deprefix(r)
			if !seen[r] {
				seen[r] = true
				reasons = append(reasons, r)
			}
		}
	}
	return allowed, reasons, nil
}

// policyContext builds the runtime context document for policy evaluation.
//
// case_dir is set (mirroring the MCP proxy, which reads VHIR_CASE_DIR) so the
// output-path policy is well-defined: the rego rules key off case_dir == ""
// vs non-empty, and an *absent* field reads as undefined in Rego — which
// silently disables both the blocked-dir and the catch-all output denials.
// Empty (no active case) confines file writes to /tmp and the agent's cwd.
func (s *Service) policyContext(req Request) map[string]any {
	return map[string]any{
		"case_dir":  os.Getenv("VHIR_CASE_DIR"),
		"cwd":       req.Cwd,
		"examiner":  s.examiner,
		"sessionId": req.SessionID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}

// record appends the decision to the audit log. A human approval/denial is
// attributed to that user; everything else is attributed to the agent.
func (s *Service) record(req Request, line string, v Verdict, escalated bool) {
	if s.audit == nil {
		return
	}
	verdict := audit.VerdictAllow
	if v.Decision != DecisionAllow {
		verdict = audit.VerdictDeny
	}
	actor := audit.Actor{Type: "agent", Name: "claude"}
	if v.Decider != "" {
		actor = audit.Actor{Type: "user", Name: v.Decider}
	}
	if err := s.audit.Log(audit.EventExec, actor,
		audit.WithVerdict(verdict),
		audit.WithCommand(line),
		audit.WithMetadataAny("tool", req.ToolName),
		audit.WithMetadataAny("sessionId", req.SessionID),
		audit.WithMetadataAny("reason", v.Reason),
		audit.WithMetadataAny("escalated", escalated),
	); err != nil {
		s.log.Error("guard audit write failed", zap.Error(err))
	}
}

// Report handles a PostToolUse hook payload in inline mode: the tool ran,
// which means the human approved the inline prompt, so resolve the pending
// escalation to "executed". A report for a tool that was never escalated (a
// policy-allowed tool) is a no-op, as is any report reaching a non-inline
// guard. The returned verdict is trivial — PostToolUse cannot deny a tool that
// already ran — but it must be written so the client's read completes.
func (s *Service) Report(_ context.Context, req Request) Verdict {
	if s.ledger == nil {
		return Verdict{Decision: DecisionAllow}
	}
	if p, ok := s.ledger.resolve(req.ToolUseID); ok {
		s.recordExecuted(p)
	}
	return Verdict{Decision: DecisionAllow}
}

// recordAsked logs an inline escalation at the moment it is handed to Claude
// Code's prompt (verdict "prompt", status pending).
func (s *Service) recordAsked(req Request, line, reason, escID string) {
	s.auditInline(audit.EventEscalation, audit.Actor{Type: "agent", Name: "claude"},
		audit.VerdictPrompt, line, req.ToolName, req.SessionID, escID, req.ToolUseID,
		audit.WithMetadataAny("reason", reason),
		audit.WithMetadataAny("status", "pending"),
		audit.WithMetadataAny("inline", true),
	)
}

// recordExecuted logs that an inline escalation's tool ran — i.e. the human
// approved it. The decider is inferred from execution, not reported by the
// harness, so it is labeled as such.
func (s *Service) recordExecuted(p *pendingEscalation) {
	s.auditInline(audit.EventApprovalDecision, audit.Actor{Type: "user", Name: "inline-operator"},
		audit.VerdictAllow, p.subject, p.tool, p.sessionID, p.escalationID, p.toolUseID,
		audit.WithMetadataAny("status", "executed"),
		audit.WithMetadataAny("decider", "inline (inferred from execution)"),
	)
}

// recordDeniedInferred logs an inline escalation reaped without an execution
// report. This conflates a genuine human denial with an approved-but-failed
// tool (PostToolUse fires only on success), so it is explicitly soft-labeled
// inferred and must not be treated as an authoritative denial.
func (s *Service) recordDeniedInferred(p *pendingEscalation) {
	s.auditInline(audit.EventApprovalDecision, audit.Actor{Type: "system", Name: "reconciler"},
		audit.VerdictDeny, p.subject, p.tool, p.sessionID, p.escalationID, p.toolUseID,
		audit.WithMetadataAny("status", "denied-inferred"),
		audit.WithMetadataAny("inferred", true),
		audit.WithMetadataAny("grace_seconds", int(s.ledger.grace.Seconds())),
	)
}

// auditInline appends an inline-mode audit entry, threading the escalation_id
// and tool_use_id so the asked/executed/denied records for one escalation
// join. It is a no-op when no audit logger is configured.
func (s *Service) auditInline(ev audit.EventType, actor audit.Actor, verdict audit.Verdict, line, tool, sessionID, escID, toolUseID string, extra ...audit.LogEntryOption) {
	if s.audit == nil {
		return
	}
	opts := []audit.LogEntryOption{
		audit.WithVerdict(verdict),
		audit.WithCommand(line),
		audit.WithMetadataAny("tool", tool),
		audit.WithMetadataAny("sessionId", sessionID),
		audit.WithMetadataAny("escalation_id", escID),
		audit.WithMetadataAny("tool_use_id", toolUseID),
	}
	opts = append(opts, extra...)
	if err := s.audit.Log(ev, actor, opts...); err != nil {
		s.log.Error("guard inline audit write failed", zap.Error(err))
	}
}

// activity is a tool call decomposed into the policy input the evaluator
// consumes (parsed sub-commands/actions) plus a human-facing subject used for
// the audit record and the approval prompt.
type activity struct {
	parsed  []mcpproxy.Parsed
	subject string
}

// fileMutators are the Claude Code tools that write to the filesystem. Each
// carries a single target path under the field named here. Gating them closes
// the hole where an agent bypasses the shell policy by editing files directly
// (e.g. appending to ~/.bashrc or overwriting /etc/hosts) instead of shelling
// out. The target path is mapped to parsed.output_paths so the existing
// output-path policy governs it: without an active case, writes are confined
// to /tmp and the agent's cwd; anything else (system dirs, home dotfiles)
// denies and escalates to a human.
var fileMutators = map[string]string{
	"Write":        "file_path",
	"Edit":         "file_path",
	"MultiEdit":    "file_path",
	"NotebookEdit": "notebook_path",
}

// activity decomposes a tool call for policy evaluation. The bool is false when
// the tool is not one the guard models, or it carries no command/path — the
// caller treats that as allow (the eBPF floor still applies).
func (s *Service) activity(req Request) (activity, bool) {
	switch {
	case req.ToolName == "Bash":
		var in struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(req.ToolInput, &in); err != nil || in.Command == "" {
			return activity{}, false
		}
		parsed := mcpproxy.DecomposeShellLine(in.Command, s.outputFlags)
		if len(parsed) == 0 {
			parsed = []mcpproxy.Parsed{{}}
		}
		return activity{parsed: parsed, subject: in.Command}, true

	default:
		field, ok := fileMutators[req.ToolName]
		if !ok {
			return activity{}, false
		}
		path := toolPath(req.ToolInput, field)
		if path == "" {
			return activity{}, false
		}
		// Synthesize a parsed action whose output_paths is the write target.
		// The binary is the (lowercased) tool name — it matches no denied
		// binary, so only the path-oriented policies have a say.
		parsed := mcpproxy.Parsed{
			Binary:      strings.ToLower(req.ToolName),
			OutputPaths: []string{path},
			Args:        []string{path},
			Via:         "structured",
		}
		return activity{parsed: []mcpproxy.Parsed{parsed}, subject: req.ToolName + " " + path}, true
	}
}

// toolPath extracts and absolutizes a file path from a tool's input. Claude
// Code requires absolute paths for file tools, but we resolve lexically (no
// symlink following) as defense against a relative or "." path slipping
// through — the policy reasons about a clean absolute path either way.
func toolPath(raw json.RawMessage, field string) string {
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		return ""
	}
	p, _ := in[field].(string)
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// deprefix strips the "sift.<pkg>: " prefix from a policy reason for
// human-facing text (the audit keeps the raw reason via the engine).
func deprefix(r string) string {
	if strings.HasPrefix(r, "sift.") {
		if _, rest, ok := strings.Cut(r, ": "); ok {
			return rest
		}
	}
	return r
}

// summarize truncates a command for the approval prompt / audit summary.
func summarize(line string) string {
	const max = 160
	line = strings.TrimSpace(line)
	if len(line) > max {
		return line[:max-1] + "…"
	}
	return line
}

func decider(d approval.ToolCallDecision) string {
	if d.Decider != "" {
		return d.Decider
	}
	return "approver"
}

// newID returns a short random correlation ID for a broker request.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read failing is catastrophic; a time-derived fallback keeps
		// the broker correlation non-empty rather than panicking the guard.
		return "guard-" + time.Now().UTC().Format("150405.000000000")
	}
	return "guard-" + hex.EncodeToString(b[:])
}
