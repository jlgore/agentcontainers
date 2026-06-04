// Package mcpproxy implements an MCP reverse proxy: it accepts MCP
// Streamable HTTP connections from LLM clients, connects to backend MCP
// servers (stdio containers, remote URLs, WASM components hosted by the
// enforcer), and gates tools/call on host-side policy evaluation.
//
// Trust model: the proxy runs on the host, inside the TCB. Backend MCP
// servers are untrusted; a compromised server cannot tamper with its own
// policy or audit trail.
package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
)

// Container labels used to track MCP backend containers. Docker is the
// source of truth for `agentcontainer mcp ps|logs|stop` — no host-side
// state files.
const (
	labelPrefix  = "dev.agentcontainer"
	LabelRole    = labelPrefix + "/role"
	LabelSession = labelPrefix + "/session"
	LabelMCPName = labelPrefix + "/mcp"

	// RoleMCPBackend marks containers launched by the proxy as MCP backends.
	RoleMCPBackend = "mcp-backend"
)

// Backend kinds, selected by an explicit switch on the config type (and
// transport for containers) — never inferred from which fields are set.
const (
	KindStdio     = "stdio"
	KindHTTP      = "http"
	KindRemote    = "remote"
	KindComponent = "component"
)

// Deps holds the external clients a Proxy needs. Tests inject fakes.
type Deps struct {
	// Docker is required for container-type backends.
	Docker client.APIClient

	// Enforcer is required for component-type backends (WASM tools are
	// hosted by the enforcer; the proxy routes tools/call to its CallTool
	// gRPC endpoint).
	Enforcer enforcerapi.EnforcerClient

	// Logger defaults to zap.NewNop().
	Logger *zap.Logger
}

// Backend is a connected MCP backend server.
type Backend struct {
	Name        string
	Kind        string
	ContainerID string // empty for remote and component backends
	Policy      *config.MCPServerPolicy
	concurrency chan struct{}

	// session is the SDK client session (stdio/http/remote backends).
	session *mcp.ClientSession
	// component routes tool calls to the enforcer (component backends).
	component *componentClient

	// netPolicy is the enforcer network policy applied at registration,
	// kept for periodic hostname re-resolution (container backends with an
	// enforcer connection only).
	netPolicy *enforcerapi.NetworkPolicyRequest

	cleanup []func(context.Context) error
}

// Enforcement returns the audit-trail enforcement marker for this backend:
// "proxy-only" for remote servers (no cgroup to attach eBPF to), empty
// otherwise.
func (b *Backend) Enforcement() string {
	if b.Kind == KindRemote {
		return "proxy-only"
	}
	return ""
}

// supportsResources reports whether the backend advertises the resources
// capability.
func (b *Backend) supportsResources() bool {
	if b.session == nil {
		return false
	}
	res := b.session.InitializeResult()
	return res != nil && res.Capabilities != nil && res.Capabilities.Resources != nil
}

// supportsPrompts reports whether the backend advertises the prompts
// capability.
func (b *Backend) supportsPrompts() bool {
	if b.session == nil {
		return false
	}
	res := b.session.InitializeResult()
	return res != nil && res.Capabilities != nil && res.Capabilities.Prompts != nil
}

// ListTools returns the backend's tool list.
func (b *Backend) ListTools(ctx context.Context) ([]*mcp.Tool, error) {
	if b.component != nil {
		return b.component.listTools(ctx)
	}
	var tools []*mcp.Tool
	for tool, err := range b.session.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcpproxy: listing tools on %s: %w", b.Name, err)
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

// CallTool forwards a tool call to the backend.
func (b *Backend) CallTool(ctx context.Context, name string, args json.RawMessage, progressToken any) (*mcp.CallToolResult, error) {
	if b.component != nil {
		return b.component.callTool(ctx, name, args)
	}
	params := &mcp.CallToolParams{Name: name, Arguments: args}
	if progressToken != nil {
		params.SetProgressToken(progressToken)
	}
	return b.session.CallTool(ctx, params)
}

func (b *Backend) acquireToolSlot(ctx context.Context) error {
	if b.concurrency == nil {
		b.concurrency = make(chan struct{}, 1)
	}
	select {
	case b.concurrency <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *Backend) releaseToolSlot() {
	if b.concurrency == nil {
		return
	}
	<-b.concurrency
}

// Close tears down the backend connection and any owned container.
func (b *Backend) Close(ctx context.Context) error {
	var errs []string
	if b.session != nil {
		if err := b.session.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	// Cleanup functions run in reverse registration order.
	for i := len(b.cleanup) - 1; i >= 0; i-- {
		if err := b.cleanup[i](ctx); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("mcpproxy: closing backend %s: %s", b.Name, strings.Join(errs, "; "))
	}
	return nil
}

// newBackend connects a single backend per its declared type and transport.
// The mcp.Client is supplied by the proxy with relay handlers already wired.
func newBackend(ctx context.Context, deps Deps, mcpClient *mcp.Client, name string, tool config.MCPToolConfig, sessionID, networkName string, concurrency int) (*Backend, error) {
	b := &Backend{Name: name, Policy: tool.Policy, concurrency: make(chan struct{}, concurrency)}

	switch tool.Type {
	case "component":
		if deps.Enforcer == nil {
			return nil, fmt.Errorf("mcpproxy: backend %s: component type requires an enforcer connection", name)
		}
		b.Kind = KindComponent
		// Components are hosted by the enforcer keyed by (container_id,
		// component_name). The proxy addresses them under the session ID;
		// loading the component into the enforcer (LoadComponent) is the
		// session runtime's job, not the proxy's.
		b.component = &componentClient{
			ec:            deps.Enforcer,
			containerID:   sessionID,
			componentName: name,
		}
		return b, nil

	case "remote":
		b.Kind = KindRemote
		tr := &mcp.StreamableClientTransport{Endpoint: tool.URL}
		session, err := mcpClient.Connect(ctx, tr, nil)
		if err != nil {
			return nil, fmt.Errorf("mcpproxy: backend %s: connecting to remote %s: %w", name, tool.URL, err)
		}
		b.session = session
		return b, nil

	case "", "container":
		if tool.Transport == "http" {
			// Container HTTP transport rides the Compose lifecycle and is
			// deferred to Phase 3; type:"remote" exercises the same
			// StreamableClientTransport code path in the meantime.
			return nil, fmt.Errorf("mcpproxy: backend %s: transport %q is not yet implemented (use type \"remote\" for HTTP endpoints)", name, tool.Transport)
		}
		if deps.Docker == nil {
			return nil, fmt.Errorf("mcpproxy: backend %s: container type requires a Docker connection", name)
		}
		b.Kind = KindStdio
		tr, containerID, cleanup, err := dialStdioContainer(ctx, deps, name, tool, sessionID, networkName)
		if err != nil {
			return nil, err
		}
		b.ContainerID = containerID
		b.cleanup = append(b.cleanup, cleanup)

		// Register with the eBPF enforcer BEFORE the MCP handshake so
		// kernel policy is in place before the server handles anything.
		// Fail closed: with an enforcer connected, a backend that cannot
		// be brought under enforcement does not start.
		if deps.Enforcer != nil {
			unregister, err := registerBackendEnforcement(ctx, deps, b, tool)
			if err != nil {
				_ = b.Close(ctx)
				return nil, err
			}
			b.cleanup = append(b.cleanup, unregister)
		}

		session, err := mcpClient.Connect(ctx, tr, nil)
		if err != nil {
			_ = b.Close(ctx)
			return nil, fmt.Errorf("mcpproxy: backend %s: MCP initialize over stdio: %w", name, err)
		}
		b.session = session
		return b, nil

	default:
		return nil, fmt.Errorf("mcpproxy: backend %s: unknown type %q", name, tool.Type)
	}
}

// dialStdioContainer launches the backend container directly via the Docker
// API with attached stdin/stdout streams (NOT managed by Compose: Compose
// services are detached, so stdin pipes cannot be held cleanly), joined to
// the per-session MCP bridge network.
func dialStdioContainer(ctx context.Context, deps Deps, name string, tool config.MCPToolConfig, sessionID, networkName string) (mcp.Transport, string, func(context.Context) error, error) {
	dc := deps.Docker
	log := deps.Logger

	if err := ensureImage(ctx, dc, tool.Image); err != nil {
		return nil, "", nil, fmt.Errorf("mcpproxy: backend %s: pulling image %s: %w", name, tool.Image, err)
	}
	if err := ensureNetwork(ctx, dc, networkName, sessionID); err != nil {
		return nil, "", nil, fmt.Errorf("mcpproxy: backend %s: %w", name, err)
	}

	cfg := &container.Config{
		Image:        tool.Image,
		Cmd:          tool.Command,
		Env:          envList(tool.Env),
		OpenStdin:    true,
		StdinOnce:    false,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		// Tty must be false: a TTY merges stderr into stdout and would
		// corrupt MCP JSON-RPC framing. Non-TTY attach multiplexes the
		// streams with stdcopy headers, demuxed below.
		Tty: false,
		Labels: map[string]string{
			LabelRole:    RoleMCPBackend,
			LabelSession: sessionID,
			LabelMCPName: name,
		},
	}
	hostCfg := &container.HostConfig{
		Mounts: parseColonMounts(tool.Mounts),
		// Hardening mirrors the Compose MCP isolation path.
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
	}
	netCfg := &network.NetworkingConfig{
		EndpointsConfig: map[string]*network.EndpointSettings{
			networkName: {},
		},
	}

	created, err := dc.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:           cfg,
		HostConfig:       hostCfg,
		NetworkingConfig: netCfg,
		Name:             fmt.Sprintf("ac-mcp-%s-%s", name, shortID(sessionID)),
	})
	if err != nil {
		return nil, "", nil, fmt.Errorf("mcpproxy: backend %s: creating container: %w", name, err)
	}
	containerID := created.ID

	cleanup := func(cctx context.Context) error {
		timeout := 10
		_, _ = dc.ContainerStop(cctx, containerID, client.ContainerStopOptions{Timeout: &timeout})
		_, err := dc.ContainerRemove(cctx, containerID, client.ContainerRemoveOptions{Force: true})
		return err
	}

	// Attach before start so no early output is lost.
	attach, err := dc.ContainerAttach(ctx, containerID, client.ContainerAttachOptions{
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		_ = cleanup(ctx)
		return nil, "", nil, fmt.Errorf("mcpproxy: backend %s: attaching: %w", name, err)
	}

	if _, err := dc.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		attach.Close()
		_ = cleanup(ctx)
		return nil, "", nil, fmt.Errorf("mcpproxy: backend %s: starting container: %w", name, err)
	}

	log.Info("mcp backend container started",
		zap.String("backend", name),
		zap.String("containerId", containerID),
		zap.String("network", networkName),
	)

	// Demux the multiplexed attach stream: MCP needs a clean stdout byte
	// stream, but non-TTY attach interleaves stdout/stderr frames with
	// 8-byte stdcopy headers. Stderr is discarded here — diagnostics are
	// available via `agentcontainer mcp logs` (ContainerLogs).
	stdoutR, stdoutW := io.Pipe()
	go func() {
		_, err := stdcopy.StdCopy(stdoutW, io.Discard, attach.Reader)
		stdoutW.CloseWithError(err)
	}()

	tr := &mcp.IOTransport{
		Reader: stdoutR,
		Writer: &hijackWriter{attach: attach.HijackedResponse},
	}
	return tr, containerID, cleanup, nil
}

// hijackWriter adapts a hijacked attach connection into the WriteCloser
// half of an IOTransport. Close half-closes stdin so the backend sees EOF.
type hijackWriter struct {
	attach client.HijackedResponse
}

func (w *hijackWriter) Write(p []byte) (int, error) {
	return w.attach.Conn.Write(p)
}

func (w *hijackWriter) Close() error {
	return w.attach.CloseWrite()
}

// ensureImage pulls the image when it is not present locally.
func ensureImage(ctx context.Context, dc client.APIClient, ref string) error {
	if _, err := dc.ImageInspect(ctx, ref); err == nil {
		return nil
	}
	reader, err := dc.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close() //nolint:errcheck
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("reading pull response: %w", err)
	}
	return nil
}

// ensureNetwork creates the per-session MCP bridge network if absent.
func ensureNetwork(ctx context.Context, dc client.APIClient, name, sessionID string) error {
	if _, err := dc.NetworkInspect(ctx, name, client.NetworkInspectOptions{}); err == nil {
		return nil
	}
	_, err := dc.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge",
		Labels: map[string]string{
			LabelRole:    RoleMCPBackend,
			LabelSession: sessionID,
		},
	})
	if err != nil {
		return fmt.Errorf("creating network %s: %w", name, err)
	}
	return nil
}

// envList renders an env map as sorted KEY=VALUE pairs (deterministic for
// container config hashing and tests).
func envList(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// parseColonMounts parses docker-style "src:dst[:ro]" mount strings (the
// form used in agentcontainer.json MCP examples).
func parseColonMounts(raw []string) []mount.Mount {
	var mounts []mount.Mount
	for _, m := range raw {
		parts := strings.Split(m, ":")
		if len(parts) < 2 {
			continue
		}
		mt := mount.Mount{
			Type:        mount.TypeBind,
			Source:      parts[0],
			Target:      parts[1],
			BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate},
		}
		if len(parts) > 2 && parts[2] == "ro" {
			mt.ReadOnly = true
		}
		mounts = append(mounts, mt)
	}
	return mounts
}

// shortID truncates a session ID for container/network naming.
func shortID(sessionID string) string {
	if len(sessionID) > 8 {
		return sessionID[:8]
	}
	return sessionID
}

// componentClient routes tool listing and calls for WASM component
// backends to the enforcer's existing ListTools/CallTool gRPC endpoints.
type componentClient struct {
	ec            enforcerapi.EnforcerClient
	containerID   string
	componentName string
}

func (c *componentClient) listTools(ctx context.Context) ([]*mcp.Tool, error) {
	resp, err := c.ec.ListTools(ctx, &enforcerapi.ListToolsRequest{
		ContainerId:   c.containerID,
		ComponentName: c.componentName,
	})
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: enforcer ListTools for %s: %w", c.componentName, err)
	}
	tools := make([]*mcp.Tool, 0, len(resp.Tools))
	for _, td := range resp.Tools {
		t := &mcp.Tool{
			Name:        td.ToolName,
			Description: td.Description,
		}
		if td.InputSchemaJson != "" {
			t.InputSchema = json.RawMessage(td.InputSchemaJson)
		}
		tools = append(tools, t)
	}
	return tools, nil
}

func (c *componentClient) callTool(ctx context.Context, name string, args json.RawMessage) (*mcp.CallToolResult, error) {
	resp, err := c.ec.CallTool(ctx, &enforcerapi.CallToolRequest{
		ContainerId:   c.containerID,
		ComponentName: c.componentName,
		ToolName:      name,
		ArgumentsJson: string(args),
	})
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: enforcer CallTool %s/%s: %w", c.componentName, name, err)
	}
	if !resp.Success {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: resp.Error}},
		}, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: resp.ResultJson}},
	}, nil
}
