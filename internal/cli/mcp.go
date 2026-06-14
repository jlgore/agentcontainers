package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/mcpproxy"
)

const defaultMCPPort = 4508

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run and manage the MCP reverse proxy",
		Long: `The MCP proxy aggregates configured MCP servers behind one
Streamable HTTP endpoint. Tool calls are policy-gated and written to a
hash-chained audit log. Backend containers are launched on a private
per-session bridge network.`,
	}

	cmd.AddCommand(
		newMCPStartCmd(),
		newMCPStopCmd(),
		newMCPPsCmd(),
		newMCPLogsCmd(),
	)

	return cmd
}

func newMCPStartCmd() *cobra.Command {
	var (
		port            int
		sessionID       string
		auditDir        string
		approvalTimeout time.Duration
		approvalSocket  string
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the MCP proxy in the foreground",
		Long: `Loads agentcontainer.json from the working directory, connects all
configured MCP backends, and serves MCP Streamable HTTP until interrupted.
Point an MCP client at http://localhost:<port>/ to use the proxied tools.

Tools listed in policy.requireApproval pause for human confirmation:
interactively on this terminal when one is attached, and always via
'agentcontainer approve' over the approval socket. Unanswered requests are
denied after the approval timeout.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPStart(cmd, port, sessionID, auditDir, approvalTimeout, approvalSocket)
		},
	}

	cmd.Flags().IntVar(&port, "port", defaultMCPPort, "Listen port for MCP Streamable HTTP")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID (default: random)")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Audit log directory (default: $AC_AUDIT_DIR or ~/.ac/audit)")
	cmd.Flags().DurationVar(&approvalTimeout, "approval-timeout", approval.DefaultToolCallTimeout, "How long requireApproval tools wait for a decision before denying")
	cmd.Flags().StringVar(&approvalSocket, "approval-socket", "", "Approval socket path (default: ~/.agentcontainers/approval.sock)")

	return cmd
}

func runMCPStart(cmd *cobra.Command, port int, sessionID, auditDir string, approvalTimeout time.Duration, approvalSocket string) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("mcp start: %w", err)
	}
	cfg, cfgPath, err := config.Load(cwd)
	if err != nil {
		return fmt.Errorf("mcp start: loading config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("mcp start: invalid config %s: %w", cfgPath, err)
	}
	if cfg.Agent == nil || cfg.Agent.Tools == nil || len(cfg.Agent.Tools.MCP) == 0 {
		return errors.New("mcp start: no MCP servers configured under agent.tools.mcp")
	}

	if sessionID == "" {
		randBytes := make([]byte, 8)
		if _, err := rand.Read(randBytes); err != nil {
			return fmt.Errorf("mcp start: generating session ID: %w", err)
		}
		sessionID = hex.EncodeToString(randBytes)
	}

	deps, depCleanup, err := buildMCPDeps(cfg, logger)
	if err != nil {
		return fmt.Errorf("mcp start: %w", err)
	}
	defer depCleanup()

	// Human-in-the-loop approval channels (Phase 4): only stood up when a
	// server actually declares requireApproval tools. The socket always
	// serves (so `agentcontainer approve` works either way); the TTY
	// prompt is added when a controlling terminal is attached.
	broker, approvalCleanup, approvalDesc, err := buildApprovalChannels(ctx, cfg, approvalTimeout, approvalSocket)
	if err != nil {
		return fmt.Errorf("mcp start: %w", err)
	}
	defer approvalCleanup()

	proxy, err := mcpproxy.New(ctx, deps, cfg, sessionID, &mcpproxy.Options{
		AuditDir:  auditDir,
		ConfigDir: filepath.Dir(cfgPath),
		Approval:  broker,
	})
	if err != nil {
		return fmt.Errorf("mcp start: %w", err)
	}
	var enforcerAudit *mcpproxy.EnforcerAuditSink
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	if deps.Enforcer != nil {
		enforcerAudit, err = mcpproxy.NewEnforcerAuditSink(sessionID, auditDir)
		if err != nil {
			_ = proxy.Close(ctx)
			return fmt.Errorf("mcp start: %w", err)
		}
		go func() {
			// StreamEnforcerAudit reconnects on stream errors itself; it
			// only returns on shutdown or when the audit sink fails.
			if err := mcpproxy.StreamEnforcerAudit(streamCtx, deps.Enforcer, enforcerAudit); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("enforcer audit stream stopped", zap.Error(err))
			}
		}()
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           proxy.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	_, _ = fmt.Fprintf(out, "MCP proxy listening on http://localhost:%d\n", port)
	_, _ = fmt.Fprintf(out, "Session:  %s\n", sessionID)
	_, _ = fmt.Fprintf(out, "Backends: %s\n", strings.Join(proxy.Backends(), ", "))
	_, _ = fmt.Fprintf(out, "Audit:    %s\n", proxy.AuditPath())
	if enforcerAudit != nil {
		_, _ = fmt.Fprintf(out, "Enforcer: %s\n", enforcerAudit.Path())
	}
	if approvalDesc != "" {
		_, _ = fmt.Fprintf(out, "Approval: %s\n", approvalDesc)
		_, _ = fmt.Fprintf(out, "          %s\n", proxy.ApprovalAuditPath())
	}
	_, _ = fmt.Fprintln(out, "Press Ctrl-C to stop.")

	// Serve until interrupted, then tear down backends gracefully.
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-sigCtx.Done():
		_, _ = fmt.Fprintln(out, "\nShutting down...")
	case err := <-errCh:
		_ = proxy.Close(context.Background())
		return fmt.Errorf("mcp start: serving: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if err := proxy.Close(shutdownCtx); err != nil {
		return fmt.Errorf("mcp start: shutdown: %w", err)
	}
	cancelStream()
	if enforcerAudit != nil {
		_ = enforcerAudit.Close()
	}
	return nil
}

// buildMCPDeps creates the Docker and (when components are configured)
// enforcer clients the proxy needs.
func buildMCPDeps(cfg *config.AgentContainer, log *zap.Logger) (mcpproxy.Deps, func(), error) {
	deps := mcpproxy.Deps{Logger: log}
	var cleanups []func()
	cleanup := func() {
		for _, f := range cleanups {
			f()
		}
	}

	needsDocker, needsEnforcer := false, false
	for _, tool := range cfg.Agent.Tools.MCP {
		switch tool.Type {
		case "component":
			needsEnforcer = true
		case "", "container":
			needsDocker = true
			if !mcpEnforcerDisabled(cfg) {
				needsEnforcer = true
			}
		}
	}

	if needsDocker {
		dc, err := client.New(client.FromEnv)
		if err != nil {
			return deps, cleanup, fmt.Errorf("creating Docker client: %w", err)
		}
		deps.Docker = dc
		cleanups = append(cleanups, func() { _ = dc.Close() })
	}

	if needsEnforcer {
		// The MCP proxy runs as its own process; its enforcer endpoint and mTLS
		// material are supplied explicitly through the environment it is launched
		// with (AC_ENFORCER_ADDR + AC_ENFORCER_TLS_*). This is external
		// configuration, not the in-process AC_ENFORCER_ADDR mutation the
		// control-plane finding targets.
		addr := os.Getenv("AC_ENFORCER_ADDR")
		if addr == "" {
			addr = "127.0.0.1:50051"
		}
		profile := enforcement.ConnectionProfile{
			Addr:           addr,
			CACertPath:     os.Getenv("AC_ENFORCER_TLS_CA"),
			ClientCertPath: os.Getenv("AC_ENFORCER_TLS_CERT"),
			ClientKeyPath:  os.Getenv("AC_ENFORCER_TLS_KEY"),
			InsecureDev:    mcpEnforcerInsecureDev(cfg),
		}
		// grpc.NewClient is lazy — it never dials. Without an eager probe,
		// an unreachable enforcer surfaces only at the first backend
		// launch, after audit sinks and approval channels are already up.
		// Reaching this branch means enforcement is required (component
		// servers need the enforcer runtime; container servers only skip
		// it via enforcer.required: false), so fail `mcp start` here. The probe
		// uses the same TLS credentials a real client presents.
		if !enforcerProfileProbe(profile) {
			return deps, cleanup, fmt.Errorf("enforcer at %s failed its gRPC health check; the configured MCP servers require it (kernel enforcement, or the component runtime) — start the enforcer sidecar, point AC_ENFORCER_ADDR at it (with AC_ENFORCER_TLS_* for mTLS), or set agent.enforcer.required: false to run container servers without kernel enforcement", addr)
		}
		conn, err := enforcement.DialEnforcer(profile, func(msg string) { log.Warn(msg) })
		if err != nil {
			return deps, cleanup, fmt.Errorf("connecting to enforcer at %s: %w", addr, err)
		}
		deps.Enforcer = enforcerapi.NewEnforcerClient(conn)
		cleanups = append(cleanups, func() { _ = conn.Close() })
	}

	return deps, cleanup, nil
}

// enforcerHealthProbe is swappable for tests; the default asks the standard
// gRPC health service (grpc.health.v1, served by the enforcer sidecar) with
// a 2-second timeout over plaintext.
var enforcerHealthProbe = enforcement.ProbeEnforcerHealth

// enforcerProfileProbe is swappable for tests; the default probes the enforcer
// health service using the connection profile's TLS credentials, so an
// mTLS-only enforcer is checked exactly as a real client connects. For a
// plaintext (no-mTLS) profile it delegates to enforcerHealthProbe so both share
// one probe seam.
var enforcerProfileProbe = func(p enforcement.ConnectionProfile) bool {
	if p.HasMTLS() {
		return enforcement.ProbeEnforcerHealthProfile(p)
	}
	return enforcerHealthProbe(p.Addr)
}

// mcpEnforcerInsecureDev reports whether the agent config opted into a plaintext
// (no-mTLS) enforcer control plane.
func mcpEnforcerInsecureDev(cfg *config.AgentContainer) bool {
	if cfg == nil || cfg.Agent == nil || cfg.Agent.Enforcer == nil {
		return false
	}
	return cfg.Agent.Enforcer.InsecureDev
}

// buildApprovalChannels stands up the HITL broker and its channels when any
// configured server declares requireApproval tools. Returns a nil broker
// (and no-op cleanup) when nothing requires approval. At least one channel
// must come up — a session whose approvals can only ever time out is a
// startup error, not a degraded mode.
func buildApprovalChannels(ctx context.Context, cfg *config.AgentContainer, timeout time.Duration, socketPath string) (*approval.ToolCallBroker, func(), string, error) {
	required := false
	for _, tool := range cfg.Agent.Tools.MCP {
		if tool.Policy != nil && len(tool.Policy.RequireApproval) > 0 {
			required = true
			break
		}
	}
	if !required {
		return nil, func() {}, "", nil
	}

	broker := approval.NewToolCallBroker(timeout)
	var cleanups []func()
	cleanup := func() {
		for _, f := range cleanups {
			f()
		}
	}
	var channels []string

	if tty, err := approval.OpenTTYChannel(broker); err == nil {
		go tty.Run(ctx)
		cleanups = append(cleanups, func() { _ = tty.Close() })
		channels = append(channels, "interactive (this terminal)")
	}

	sock, err := approval.ListenSocket(socketPath, broker)
	if err == nil {
		cleanups = append(cleanups, func() { _ = sock.Close() })
		channels = append(channels, "agentcontainer approve ("+sock.Path()+")")
	} else if len(channels) == 0 {
		cleanup()
		return nil, func() {}, "", fmt.Errorf("no approval channel available (no TTY, and %v)", err)
	}

	return broker, cleanup, strings.Join(channels, ", "), nil
}

func mcpEnforcerDisabled(cfg *config.AgentContainer) bool {
	return cfg != nil && cfg.Agent != nil && cfg.Agent.Enforcer != nil && cfg.Agent.Enforcer.Required != nil && !*cfg.Agent.Enforcer.Required
}

func newMCPPsCmd() *cobra.Command {
	var session string

	cmd := &cobra.Command{
		Use:   "ps",
		Short: "List MCP backend containers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPPs(cmd, session)
		},
	}

	cmd.Flags().StringVar(&session, "session", "", "Filter by session ID")

	return cmd
}

func runMCPPs(cmd *cobra.Command, session string) error {
	dc, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("mcp ps: %w", err)
	}
	defer dc.Close() //nolint:errcheck

	items, err := listMCPContainers(cmd.Context(), dc, session)
	if err != nil {
		return fmt.Errorf("mcp ps: %w", err)
	}

	out := cmd.OutOrStdout()
	if len(items) == 0 {
		_, _ = fmt.Fprintln(out, "No MCP backend containers found.")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "SERVER\tSESSION\tCONTAINER\tIMAGE\tSTATUS")
	for _, c := range items {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%.12s\t%s\t%s\n",
			c.Labels[mcpproxy.LabelMCPName],
			c.Labels[mcpproxy.LabelSession],
			c.ID,
			c.Image,
			c.State,
		)
	}
	return w.Flush()
}

func newMCPLogsCmd() *cobra.Command {
	var (
		session string
		follow  bool
		tail    string
	)

	cmd := &cobra.Command{
		Use:   "logs <server>",
		Short: "Show logs from an MCP backend container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPLogs(cmd, args[0], session, follow, tail)
		},
	}

	cmd.Flags().StringVar(&session, "session", "", "Filter by session ID")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	cmd.Flags().StringVar(&tail, "tail", "", "Number of lines to show from the end")

	return cmd
}

func runMCPLogs(cmd *cobra.Command, server, session string, follow bool, tail string) error {
	ctx := cmd.Context()
	dc, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("mcp logs: %w", err)
	}
	defer dc.Close() //nolint:errcheck

	items, err := listMCPContainers(ctx, dc, session)
	if err != nil {
		return fmt.Errorf("mcp logs: %w", err)
	}
	var containerID string
	for _, c := range items {
		if c.Labels[mcpproxy.LabelMCPName] == server {
			containerID = c.ID
			break
		}
	}
	if containerID == "" {
		return fmt.Errorf("mcp logs: no backend container found for server %q", server)
	}

	reader, err := dc.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     follow,
		Tail:       tail,
	})
	if err != nil {
		return fmt.Errorf("mcp logs: %w", err)
	}
	defer reader.Close() //nolint:errcheck

	// Backend containers run without a TTY, so the log stream is
	// stdcopy-multiplexed.
	if _, err := stdcopy.StdCopy(cmd.OutOrStdout(), cmd.ErrOrStderr(), reader); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("mcp logs: %w", err)
	}
	return nil
}

func newMCPStopCmd() *cobra.Command {
	var session string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop and remove MCP backend containers and networks",
		Long: `Stops and removes all MCP backend containers (optionally filtered by
session) and removes their private bridge networks. Useful for cleaning up
after a crashed proxy; a healthy proxy cleans up on Ctrl-C.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPStop(cmd, session)
		},
	}

	cmd.Flags().StringVar(&session, "session", "", "Only stop backends for this session ID")

	return cmd
}

func runMCPStop(cmd *cobra.Command, session string) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	dc, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("mcp stop: %w", err)
	}
	defer dc.Close() //nolint:errcheck

	items, err := listMCPContainers(ctx, dc, session)
	if err != nil {
		return fmt.Errorf("mcp stop: %w", err)
	}

	sessions := make(map[string]struct{})
	for _, c := range items {
		timeout := 10
		_, _ = dc.ContainerStop(ctx, c.ID, client.ContainerStopOptions{Timeout: &timeout})
		if _, err := dc.ContainerRemove(ctx, c.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
			_, _ = fmt.Fprintf(out, "failed to remove %s: %v\n", c.ID[:12], err)
			continue
		}
		_, _ = fmt.Fprintf(out, "removed %s (%s)\n", c.Labels[mcpproxy.LabelMCPName], c.ID[:12])
		if sid := c.Labels[mcpproxy.LabelSession]; sid != "" {
			sessions[sid] = struct{}{}
		}
	}

	// Remove the per-session bridge networks once their containers are gone.
	for sid := range sessions {
		name := "ac-mcp-" + sid
		if len(sid) > 8 {
			name = "ac-mcp-" + sid[:8]
		}
		if _, err := dc.NetworkRemove(ctx, name, client.NetworkRemoveOptions{}); err == nil {
			_, _ = fmt.Fprintf(out, "removed network %s\n", name)
		}
	}

	if len(items) == 0 {
		_, _ = fmt.Fprintln(out, "No MCP backend containers found.")
	}
	return nil
}

// listMCPContainers returns containers labeled as MCP backends, optionally
// filtered by session.
func listMCPContainers(ctx context.Context, dc client.APIClient, session string) ([]containerSummary, error) {
	filters := client.Filters{}.Add("label", mcpproxy.LabelRole+"="+mcpproxy.RoleMCPBackend)
	if session != "" {
		filters = filters.Add("label", mcpproxy.LabelSession+"="+session)
	}
	result, err := dc.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: filters,
	})
	if err != nil {
		return nil, err
	}
	items := make([]containerSummary, 0, len(result.Items))
	for _, c := range result.Items {
		items = append(items, containerSummary{
			ID:     c.ID,
			Image:  c.Image,
			State:  string(c.State),
			Labels: c.Labels,
		})
	}
	return items, nil
}

// containerSummary is the subset of container metadata the mcp subcommands
// display.
type containerSummary struct {
	ID     string
	Image  string
	State  string
	Labels map[string]string
}
