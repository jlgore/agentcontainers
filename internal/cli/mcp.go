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
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
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
		port      int
		sessionID string
		auditDir  string
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the MCP proxy in the foreground",
		Long: `Loads agentcontainer.json from the working directory, connects all
configured MCP backends, and serves MCP Streamable HTTP until interrupted.
Point an MCP client at http://localhost:<port>/ to use the proxied tools.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPStart(cmd, port, sessionID, auditDir)
		},
	}

	cmd.Flags().IntVar(&port, "port", defaultMCPPort, "Listen port for MCP Streamable HTTP")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID (default: random)")
	cmd.Flags().StringVar(&auditDir, "audit-dir", "", "Audit log directory (default: $AC_AUDIT_DIR or ~/.ac/audit)")

	return cmd
}

func runMCPStart(cmd *cobra.Command, port int, sessionID, auditDir string) error {
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

	proxy, err := mcpproxy.New(ctx, deps, cfg, sessionID, &mcpproxy.Options{AuditDir: auditDir})
	if err != nil {
		return fmt.Errorf("mcp start: %w", err)
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
		addr := os.Getenv("AC_ENFORCER_ADDR")
		if addr == "" {
			addr = "127.0.0.1:50051"
		}
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return deps, cleanup, fmt.Errorf("connecting to enforcer at %s: %w", addr, err)
		}
		deps.Enforcer = enforcerapi.NewEnforcerClient(conn)
		cleanups = append(cleanups, func() { _ = conn.Close() })
	}

	return deps, cleanup, nil
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
