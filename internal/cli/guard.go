package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/guard"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/mcpproxy"
)

func newGuardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Policy-gate the agent's own tool calls (Claude Code hooks)",
		Long: `Gate an AI agent's native tools (Claude Code's Bash, …) with the same
OPA policy that gates the MCP forensic tools, escalating denials to a human.

  guard serve         run the host-side decision service (the authority)
  guard monitor       review pending approvals in a TUI
  guard hook          PreToolUse hook handler the agent runs in its container
  guard install-hook  emit the Claude Code settings that wire the hook

The agent runs the thin 'hook' client inside its container; the decision is
made by 'serve', a process the agent cannot reach. The eBPF enforcer remains
the hard floor underneath.`,
	}
	cmd.AddCommand(newGuardServeCmd(), newGuardMonitorCmd(), newGuardHookCmd(), newGuardInstallHookCmd())
	return cmd
}

func resolveGuardApprovalSocket(flag string) string {
	if flag != "" {
		return flag
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".ac", "guard-approve.sock")
	}
	return ""
}

// resolveGuardSocket picks the socket path: explicit flag, then
// $AC_GUARD_SOCKET, then ~/.ac/guard.sock.
func resolveGuardSocket(flag string) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv("AC_GUARD_SOCKET"); env != "" {
		return env
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".ac", "guard.sock")
	}
	return guard.DefaultSocket
}

func guardLogger() *zap.Logger {
	if logger != nil {
		return logger
	}
	return zap.NewNop()
}

// ---- guard serve ----------------------------------------------------------

func newGuardServeCmd() *cobra.Command {
	var (
		socket        string
		securityYAML  string
		noApproval    bool
		escalation    string
		timeout       time.Duration
		approveSocket string
		auditDir      string
		sessionID     string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the host-side guard decision service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGuardServe(cmd, guardServeOpts{
				socket: socket, securityYAML: securityYAML, noApproval: noApproval, escalation: escalation,
				timeout: timeout, approveSocket: approveSocket, auditDir: auditDir, sessionID: sessionID,
			})
		},
	}

	cmd.Flags().StringVar(&socket, "socket", "", "Guard socket path (default: $AC_GUARD_SOCKET or ~/.ac/guard.sock)")
	cmd.Flags().StringVar(&securityYAML, "security-yaml", "", "Policy file (default: sift-mcp built-in defaults)")
	cmd.Flags().BoolVar(&noApproval, "no-approval", false, "Policy-only: a denial is final, never escalated to a human (alias for --escalation deny)")
	cmd.Flags().StringVar(&escalation, "escalation", "prompt", "Escalation mode: 'prompt' (block for a human via the broker), 'inline' (return Claude Code 'ask' so it prompts in the agent's own TUI; host audits via a ledger), or 'deny' (policy-only)")
	cmd.Flags().DurationVar(&timeout, "approval-timeout", approval.DefaultToolCallTimeout, "prompt mode: how long a denial waits for a human; inline mode: ledger grace before an unconfirmed escalation is reaped as denied-inferred")
	cmd.Flags().StringVar(&approveSocket, "approval-socket", "", "Socket for 'agentcontainer approve' (default: ~/.ac/guard-approve.sock)")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Audit log directory (default: $AC_AUDIT_DIR or ~/.ac/audit)")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID (default: random)")

	return cmd
}

type guardServeOpts struct {
	socket, securityYAML, approveSocket, auditDir, sessionID string
	escalation                                               string
	noApproval                                               bool
	timeout                                                  time.Duration
}

func runGuardServe(cmd *cobra.Command, o guardServeOpts) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	log := guardLogger()

	if o.sessionID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("guard serve: generating session ID: %w", err)
		}
		o.sessionID = hex.EncodeToString(b)
	}

	// Compile the agent-tool policy: sift-mcp defaults (denied binaries,
	// dangerous flags, shell metacharacters, rm protection), or a custom
	// security.yaml.
	sec := mcpproxy.DefaultSecurityPolicy()
	policyDesc := "sift-mcp built-in defaults"
	if o.securityYAML != "" {
		loaded, err := mcpproxy.LoadSecurityYAML(o.securityYAML)
		if err != nil {
			return fmt.Errorf("guard serve: %w", err)
		}
		sec = loaded
		policyDesc = o.securityYAML
	}
	cp, err := mcpproxy.Compile(sec, nil)
	if err != nil {
		return fmt.Errorf("guard serve: compiling policy: %w", err)
	}
	ev, err := mcpproxy.NewEvaluator(ctx, "agent", cp)
	if err != nil {
		return fmt.Errorf("guard serve: %w", err)
	}

	// Audit log (shared hash-chained plane with the MCP tools).
	var auditOpts []audit.LoggerOption
	if o.auditDir != "" {
		auditOpts = append(auditOpts, audit.WithDir(o.auditDir))
	}
	alog, err := audit.NewLogger(o.sessionID, auditOpts...)
	if err != nil {
		return fmt.Errorf("guard serve: opening audit log: %w", err)
	}
	defer func() { _ = alog.Close() }()

	// Resolve the escalation mode. --no-approval is the legacy alias for "deny".
	mode := o.escalation
	if o.noApproval {
		mode = "deny"
	}
	switch mode {
	case "prompt", "inline", "deny":
	default:
		return fmt.Errorf("guard serve: invalid --escalation %q (want prompt, inline, or deny)", mode)
	}

	// Human-in-the-loop approval channels (prompt mode only).
	var (
		broker   *approval.ToolCallBroker
		chanDesc string
		cleanups []func()
	)
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()
	if mode == "prompt" {
		broker = approval.NewToolCallBroker(o.timeout)
		var channels []string
		if tty, terr := approval.OpenTTYChannel(broker); terr == nil {
			go tty.Run(ctx)
			cleanups = append(cleanups, func() { _ = tty.Close() })
			channels = append(channels, "interactive (this terminal)")
		}
		approveSock := resolveGuardApprovalSocket(o.approveSocket)
		if sock, serr := approval.ListenSocket(approveSock, broker); serr == nil {
			cleanups = append(cleanups, func() { _ = sock.Close() })
			channels = append(channels, "agentcontainer approve ("+sock.Path()+")")
		} else if len(channels) == 0 {
			return fmt.Errorf("guard serve: no approval channel available (no TTY, and %v); use --escalation deny to run policy-only", serr)
		}
		chanDesc = strings.Join(channels, ", ")
	}

	svc := guard.New(guard.Options{
		Evaluator:   ev,
		OutputFlags: cp.OutputFlags,
		Broker:      broker,
		Audit:       alog,
		Logger:      log,
		Examiner:    examinerIdentity(),
		Inline:      mode == "inline",
		LedgerGrace: o.timeout,
	})

	l, err := guard.Listen(resolveGuardSocket(o.socket), svc, log)
	if err != nil {
		return fmt.Errorf("guard serve: %w", err)
	}
	cleanups = append(cleanups, func() { _ = l.Close() })

	_, _ = fmt.Fprintf(out, "Guard serving on %s\n", l.Path())
	_, _ = fmt.Fprintf(out, "Session:  %s\n", o.sessionID)
	_, _ = fmt.Fprintf(out, "Policy:   %s\n", policyDesc)
	_, _ = fmt.Fprintf(out, "Audit:    %s\n", alog.Path())
	switch mode {
	case "prompt":
		_, _ = fmt.Fprintf(out, "Approval: %s\n", chanDesc)
	case "inline":
		_, _ = fmt.Fprintf(out, "Approval: inline (Claude Code prompts in the agent's TUI; host audits via ledger, grace %s)\n", o.timeout)
	default:
		_, _ = fmt.Fprintln(out, "Approval: disabled (policy-only — denials are final)")
	}
	_, _ = fmt.Fprintln(out, "Press Ctrl-C to stop.")

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Inline mode: reap unconfirmed escalations on a ticker, and drain on
	// shutdown, recording them as denied-inferred.
	go svc.StartReconciler(sigCtx)

	errCh := make(chan error, 1)
	go func() { errCh <- l.Serve(sigCtx) }()

	select {
	case <-sigCtx.Done():
		_, _ = fmt.Fprintln(out, "\nShutting down.")
		return nil
	case err := <-errCh:
		return err
	}
}

// examinerIdentity mirrors the proxy's examiner resolution for audit attribution.
func examinerIdentity() string {
	for _, env := range []string{"VHIR_EXAMINER", "VHIR_ANALYST", "USER"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return "agent"
}

// ---- guard hook -----------------------------------------------------------

func newGuardHookCmd() *cobra.Command {
	var (
		socket  string
		timeout time.Duration
	)

	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Claude Code PreToolUse hook handler (reads stdin, prints a permission decision)",
		Long: `Reads a Claude Code PreToolUse payload on stdin, asks the guard service
over its socket, and prints the hook's permission decision JSON on stdout.

Fails CLOSED: if the guard service is unreachable, it denies the tool call.
Wire it as a PreToolUse hook with 'agentcontainer guard install-hook'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGuardHook(cmd, socket, timeout)
		},
	}

	cmd.Flags().StringVar(&socket, "socket", "", "Guard socket path (default: $AC_GUARD_SOCKET or ~/.ac/guard.sock)")
	cmd.Flags().DurationVar(&timeout, "timeout", 6*time.Minute, "Max wait for a verdict (covers human approval)")

	return cmd
}

func runGuardHook(cmd *cobra.Command, socket string, timeout time.Duration) error {
	out := cmd.OutOrStdout()

	payload, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return emitDecision(out, guard.DecisionDeny, "guard: reading hook input failed (fail-closed): "+err.Error())
	}

	// PostToolUse reports an executed tool (inline mode resolves its ledger).
	// It carries no permission decision — it cannot block a tool that already
	// ran — so it fails OPEN: a lost report just leaves the escalation to be
	// reaped as denied-inferred. PreToolUse (or an older hook sending no event
	// name) is a policy decision and fails CLOSED.
	var probe struct {
		HookEventName string `json:"hook_event_name"`
	}
	_ = json.Unmarshal(payload, &probe)
	if probe.HookEventName == "PostToolUse" {
		if err := guard.Report(resolveGuardSocket(socket), payload, 5*time.Second, 5*time.Second); err != nil {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "guard: PostToolUse report failed (ignored):", err)
		}
		return nil
	}

	v, err := guard.Ask(resolveGuardSocket(socket), payload, 5*time.Second, timeout)
	if err != nil {
		// Fail CLOSED: a guard we cannot reach denies, it does not wave through.
		return emitDecision(out, guard.DecisionDeny, "guard service unreachable (fail-closed): "+err.Error())
	}
	return emitDecision(out, v.Decision, v.Reason)
}

// emitDecision writes the Claude Code PreToolUse hook output. It always
// returns nil after writing — the decision is carried in the JSON, not the
// exit code, so the hook exits 0 even on a deny.
func emitDecision(w io.Writer, decision, reason string) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       decision,
			"permissionDecisionReason": reason,
		},
	})
}

// ---- guard install-hook ---------------------------------------------------

func newGuardInstallHookCmd() *cobra.Command {
	var (
		matcher string
		command string
		write   string
		managed bool
	)

	cmd := &cobra.Command{
		Use:   "install-hook",
		Short: "Emit (or write) the Claude Code settings that wire the PreToolUse hook",
		Long: `Generates the Claude Code settings fragment that routes matching tool
calls through 'agentcontainer guard hook'.

By default it prints the fragment. With --write <path> it merges the hook into
an existing settings file. With --managed it targets the system
managed-settings.json (which user/project settings cannot override) — the
tamper-resistant placement for a containerized agent.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGuardInstallHook(cmd, matcher, command, write, managed)
		},
	}

	cmd.Flags().StringVar(&matcher, "matcher", "Bash|Write|Edit|MultiEdit|NotebookEdit", "Tool matcher (regex). Covers the guard-modeled tools by default: Bash plus the file mutators")
	cmd.Flags().StringVar(&command, "command", "agentcontainer guard hook", "Hook command to run")
	cmd.Flags().StringVar(&write, "write", "", "Merge into this settings file instead of printing")
	cmd.Flags().BoolVar(&managed, "managed", false, "Target the system managed-settings.json (implies --write that path)")

	return cmd
}

// managedSettingsPath is the Linux managed-settings location Claude Code reads
// with highest precedence (user/project settings cannot override it).
const managedSettingsPath = "/etc/claude-code/managed-settings.json"

func runGuardInstallHook(cmd *cobra.Command, matcher, command, write string, managed bool) error {
	out := cmd.OutOrStdout()

	entry := map[string]any{
		"matcher": matcher,
		"hooks": []any{
			map[string]any{"type": "command", "command": command},
		},
	}

	if managed && write == "" {
		write = managedSettingsPath
	}

	if write == "" {
		fragment := map[string]any{
			"hooks": map[string]any{"PreToolUse": []any{entry}},
		}
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(fragment)
	}

	return mergeHookIntoSettings(write, entry, command, matcher, out)
}

// mergeHookIntoSettings loads (or initializes) the settings file and appends
// the PreToolUse entry if an identical matcher+command isn't already present.
func mergeHookIntoSettings(path string, entry map[string]any, command, matcher string, out io.Writer) error {
	settings := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if len(data) > 0 {
			if err := json.Unmarshal(data, &settings); err != nil {
				return fmt.Errorf("guard install-hook: parsing %s: %w", path, err)
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("guard install-hook: reading %s: %w", path, err)
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		settings["hooks"] = hooks
	}
	pre, _ := hooks["PreToolUse"].([]any)

	for _, e := range pre {
		if em, ok := e.(map[string]any); ok {
			if em["matcher"] == matcher && hookHasCommand(em, command) {
				_, _ = fmt.Fprintf(out, "Hook already present in %s (matcher %q) — nothing to do.\n", path, matcher)
				return nil
			}
		}
	}

	hooks["PreToolUse"] = append(pre, entry)

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("guard install-hook: creating %s: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("guard install-hook: writing %s: %w", path, err)
	}
	_, _ = fmt.Fprintf(out, "Wrote PreToolUse hook (matcher %q) to %s\n", matcher, path)
	return nil
}

func hookHasCommand(entry map[string]any, command string) bool {
	hooks, _ := entry["hooks"].([]any)
	for _, h := range hooks {
		if hm, ok := h.(map[string]any); ok {
			if hm["command"] == command {
				return true
			}
		}
	}
	return false
}
