// Package guard evaluates an AI agent's own tool calls — Claude Code's Bash,
// and (later) Write/Edit/WebFetch — against the same OPA policy that gates the
// MCP forensic tools, escalating policy denials to a human via the approval
// broker and recording every decision in the audit log.
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
}

// Options configure a Service.
type Options struct {
	Evaluator   *mcpproxy.Evaluator
	OutputFlags []string
	Broker      *approval.ToolCallBroker
	Audit       *audit.Logger
	Logger      *zap.Logger
	Examiner    string
}

// New builds a Service. Evaluator is required; Broker, Audit, and Logger are
// optional (a nil Broker means a policy denial is final; a nil Logger uses a
// no-op).
func New(opts Options) *Service {
	log := opts.Logger
	if log == nil {
		log = zap.NewNop()
	}
	return &Service{
		eval:        opts.Evaluator,
		outputFlags: opts.OutputFlags,
		broker:      opts.Broker,
		audit:       opts.Audit,
		log:         log,
		examiner:    opts.Examiner,
	}
}

// Decide returns the guard's verdict for a single tool call. It never returns
// an error: an internal failure (policy engine error, broker unavailable)
// resolves to a deny — the guard fails closed.
func (s *Service) Decide(ctx context.Context, req Request) Verdict {
	line := commandLine(req)
	if line == "" {
		// No shell command to reason about (a non-Bash tool, or an empty
		// command). The shell policy has no say here yet, so allow — the
		// eBPF floor still applies to anything the command would touch.
		v := Verdict{Decision: DecisionAllow, Reason: "no shell command to evaluate"}
		s.record(req, line, v, false)
		return v
	}

	allowed, reasons, err := s.evaluate(ctx, req, line)
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

// evaluate decomposes the shell line and evaluates every sub-command against
// the policy. It denies if any sub-command denies; reasons are the
// deduplicated, human-facing union (sift.<pkg> prefixes stripped).
func (s *Service) evaluate(ctx context.Context, req Request, line string) (allowed bool, reasons []string, err error) {
	pctx := s.policyContext(req)
	parsedList := mcpproxy.DecomposeShellLine(line, s.outputFlags)
	if len(parsedList) == 0 {
		parsedList = []mcpproxy.Parsed{{}}
	}

	allowed = true
	seen := make(map[string]bool)
	for _, parsed := range parsedList {
		d, evErr := s.eval.EvaluateParsed(ctx, "agent", req.ToolName, line, parsed, pctx)
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
func (s *Service) policyContext(req Request) map[string]any {
	return map[string]any{
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

// commandLine extracts the shell command a tool call carries, or "" when the
// tool is not one the shell policy evaluates. Bash is the only shell-bearing
// Claude Code tool today; Write/Edit/WebFetch get path/network handling in a
// later stage.
func commandLine(req Request) string {
	switch req.ToolName {
	case "Bash":
		var in struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(req.ToolInput, &in); err != nil {
			return ""
		}
		return in.Command
	default:
		return ""
	}
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
