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
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

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
// "proxy-only" for remote servers (no cgroup to attach eBPF to);
// "fs-allowlists:proxy-only" for container backends whose policy declares
// filesystem read/write allowlists — the kernel LSM runs in deny-list mode
// (deny paths and secret ACLs are kernel-enforced), so allowlist confinement
// happens only at the proxy's filesystem.rego layer; empty otherwise.
func (b *Backend) Enforcement() string {
	if b.Kind == KindRemote {
		return "proxy-only"
	}
	if (b.Kind == KindStdio || b.Kind == KindHTTP) && b.Policy != nil && b.Policy.Filesystem != nil &&
		(len(b.Policy.Filesystem.Read) > 0 || len(b.Policy.Filesystem.Write) > 0) {
		return "fs-allowlists:proxy-only"
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
		params.SetProgressToken(normalizeProgressToken(progressToken))
	}
	return b.session.CallTool(ctx, params)
}

// normalizeProgressToken coerces a client-supplied progress token into a type
// the MCP SDK accepts (int/int32/int64/string). JSON numbers decode to float64,
// which mcp.CallToolParams.SetProgressToken panics on — and that panic, raised
// in the per-request goroutine, crashes the whole proxy (taking down every
// session's audited channel) on the first real tool call. Claude Code sends a
// numeric progressToken, so coerce an integral float to int64; stringify any
// other float defensively. int/int32/int64/string pass through unchanged.
func normalizeProgressToken(token any) any {
	switch t := token.(type) {
	case float64:
		if !math.IsInf(t, 0) && !math.IsNaN(t) && t == math.Trunc(t) {
			return int64(t)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		f := float64(t)
		if !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f) {
			return int64(f)
		}
		return strconv.FormatFloat(f, 'f', -1, 32)
	default:
		return token
	}
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

// freezeEnforceResume registers a freshly started, frozen backend container
// with the enforcer (when one is connected) and then unpauses it. It preserves
// the fail-closed invariant shared by the stdio and http container paths:
// kernel policy is applied while the container cannot execute, and a backend
// that cannot be brought under enforcement does not start. The unregister
// cleanup is appended to the backend so Close sweeps its BPF map entries.
func (b *Backend) freezeEnforceResume(ctx context.Context, deps Deps, tool config.MCPToolConfig, resume func(context.Context) error) error {
	if deps.Enforcer != nil {
		unregister, err := registerBackendEnforcement(ctx, deps, b, tool)
		if err != nil {
			return err
		}
		b.cleanup = append(b.cleanup, unregister)
	}
	// Unfreeze only after policy is in place. From here the container runs
	// fully enforced through the MCP handshake and every tool call.
	if err := resume(ctx); err != nil {
		return fmt.Errorf("resuming container after enforcement: %w", err)
	}
	return nil
}

// newBackend connects a single backend per its declared type and transport.
// The mcp.Client is supplied by the proxy with relay handlers already wired.
//
// The tool's hosting model is resolved up front via tool.Resolve, which
// yields a typed view exposing only the fields legal for the kind; the
// switch below dispatches on the resolved discriminator rather than reading
// raw config fields. Field-level validation is config.Validate's job (run
// before a proxy is ever constructed), so resolution errors other than an
// unknown type are not fatal here — the typed view is still populated and
// the proxy proceeds on the resolved kind.
func newBackend(ctx context.Context, deps Deps, mcpClient *mcp.Client, name string, tool config.MCPToolConfig, sessionID, networkName string, concurrency int) (*Backend, error) {
	resolved, _ := tool.Resolve(name)
	b := &Backend{Name: name, Policy: tool.Policy, concurrency: make(chan struct{}, concurrency)}

	switch resolved.Kind {
	case config.KindComponent:
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

	case config.KindRemote:
		b.Kind = KindRemote
		tr := &mcp.StreamableClientTransport{Endpoint: resolved.Remote.URL}
		session, err := mcpClient.Connect(ctx, tr, nil)
		if err != nil {
			return nil, fmt.Errorf("mcpproxy: backend %s: connecting to remote %s: %w", name, resolved.Remote.URL, err)
		}
		b.session = session
		return b, nil

	case config.KindContainer:
		ct := resolved.Container
		if deps.Docker == nil {
			return nil, fmt.Errorf("mcpproxy: backend %s: container type requires a Docker connection", name)
		}
		if ct.Transport == "http" {
			b.Kind = KindHTTP
			hc, err := dialHTTPContainer(ctx, deps, name, ct, sessionID, networkName)
			if err != nil {
				return nil, err
			}
			b.ContainerID = hc.containerID
			b.cleanup = append(b.cleanup, hc.cleanup)

			// Enforce while frozen, then resume — same fail-closed invariant
			// as the stdio path: kernel policy lands before the container runs.
			if err := b.freezeEnforceResume(ctx, deps, tool, hc.resume); err != nil {
				_ = b.Close(ctx)
				return nil, fmt.Errorf("mcpproxy: backend %s: %w", name, err)
			}

			// The HTTP server is not listening until it unfreezes and boots;
			// wait for the socket, then drive the MCP handshake over HTTP.
			if err := waitForListening(ctx, hc.address, httpBackendReadyTimeout); err != nil {
				_ = b.Close(ctx)
				return nil, fmt.Errorf("mcpproxy: backend %s: waiting for http server: %w", name, err)
			}
			tr := &mcp.StreamableClientTransport{Endpoint: hc.endpoint}
			session, err := mcpClient.Connect(ctx, tr, nil)
			if err != nil {
				_ = b.Close(ctx)
				return nil, fmt.Errorf("mcpproxy: backend %s: MCP initialize over http: %w", name, err)
			}
			b.session = session
			return b, nil
		}

		b.Kind = KindStdio
		sc, err := dialStdioContainer(ctx, deps, name, ct, sessionID, networkName)
		if err != nil {
			return nil, err
		}
		b.ContainerID = sc.containerID
		b.cleanup = append(b.cleanup, sc.cleanup)

		// Enforce while frozen, then resume — closes the window where the
		// container would otherwise run before its BPF maps are populated.
		if err := b.freezeEnforceResume(ctx, deps, tool, sc.resume); err != nil {
			_ = b.Close(ctx)
			return nil, fmt.Errorf("mcpproxy: backend %s: %w", name, err)
		}

		session, err := mcpClient.Connect(ctx, sc.transport, nil)
		if err != nil {
			_ = b.Close(ctx)
			return nil, fmt.Errorf("mcpproxy: backend %s: MCP initialize over stdio: %w", name, err)
		}
		b.session = session
		return b, nil

	default:
		return nil, fmt.Errorf("mcpproxy: backend %s: unknown kind %q", name, resolved.Kind)
	}
}

// stdioContainer is a launched, attached, and (best-effort) frozen backend
// container. The caller applies enforcement while it is frozen, then calls
// resume to unfreeze before driving the MCP handshake.
type stdioContainer struct {
	transport   mcp.Transport
	containerID string
	// resume unfreezes the container. No-op when the freeze could not be
	// applied (resume must still be called — it keeps the lifecycle linear).
	resume func(context.Context) error
	// cleanup stops and removes the container; safe whether or not the
	// container is still frozen.
	cleanup func(context.Context) error
}

// dialStdioContainer launches the backend container directly via the Docker
// API with attached stdin/stdout streams (NOT managed by Compose: Compose
// services are detached, so stdin pipes cannot be held cleanly), joined to
// the per-session MCP bridge network.
//
// The container is paused immediately after start so the caller can apply
// kernel enforcement before it executes anything meaningful. Docker has no
// atomic "start frozen", so the process runs unenforced for the brief
// Start→Pause interval — far smaller than the previous window (the entire
// startup, MCP handshake, and first tool call all ran unenforced). If the
// freezer is unavailable (e.g. some rootless setups) the pause is skipped
// with a warning and behaviour degrades to that prior window.
func dialStdioContainer(ctx context.Context, deps Deps, name string, tool *config.ContainerTool, sessionID, networkName string) (*stdioContainer, error) {
	dc := deps.Docker
	log := deps.Logger

	if err := ensureImage(ctx, dc, tool.Image); err != nil {
		return nil, fmt.Errorf("mcpproxy: backend %s: pulling image %s: %w", name, tool.Image, err)
	}
	if err := ensureNetwork(ctx, dc, networkName, sessionID); err != nil {
		return nil, fmt.Errorf("mcpproxy: backend %s: %w", name, err)
	}

	cfg := &container.Config{
		Image:        tool.Image,
		Cmd:          tool.Command,
		Env:          envList(tool.Env),
		User:         tool.User,
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
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		ReadonlyRootfs: true,
		Tmpfs: map[string]string{
			"/run/secrets": "rw,nosuid,nodev,noexec,size=256m,mode=1777",
		},
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
		return nil, fmt.Errorf("mcpproxy: backend %s: creating container: %w", name, err)
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
		return nil, fmt.Errorf("mcpproxy: backend %s: attaching: %w", name, err)
	}

	if _, err := dc.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		attach.Close()
		_ = cleanup(ctx)
		return nil, fmt.Errorf("mcpproxy: backend %s: starting container: %w", name, err)
	}

	// Freeze immediately: the caller applies kernel enforcement before the
	// container does anything meaningful. Best-effort — if the freezer is
	// unavailable, proceed unfrozen (the policy still lands, just with the
	// pre-fix startup race).
	paused := true
	if _, err := dc.ContainerPause(ctx, containerID, client.ContainerPauseOptions{}); err != nil {
		paused = false
		log.Warn("could not freeze backend container before enforcement; a brief startup window runs unenforced",
			zap.String("backend", name),
			zap.String("containerId", containerID),
			zap.Error(err),
		)
	}
	resume := func(rctx context.Context) error {
		if !paused {
			return nil
		}
		_, err := dc.ContainerUnpause(rctx, containerID, client.ContainerUnpauseOptions{})
		return err
	}

	log.Info("mcp backend container started",
		zap.String("backend", name),
		zap.String("containerId", containerID),
		zap.String("network", networkName),
		zap.Bool("frozen", paused),
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
	return &stdioContainer{
		transport:   tr,
		containerID: containerID,
		resume:      resume,
		cleanup:     cleanup,
	}, nil
}

// httpContainer is a launched, (best-effort) frozen backend container that
// serves MCP over Streamable HTTP on the per-session bridge network. Mirrors
// stdioContainer, but the proxy reaches it over the network (endpoint/address)
// rather than the Docker attach API.
type httpContainer struct {
	endpoint    string // full MCP URL, e.g. http://172.20.0.2:4508/mcp
	address     string // host:port for the readiness probe, e.g. 172.20.0.2:4508
	containerID string
	resume      func(context.Context) error
	cleanup     func(context.Context) error
}

const (
	// httpBackendReadyTimeout bounds the wait for the backend's HTTP server to
	// accept connections after the container unfreezes.
	httpBackendReadyTimeout = 30 * time.Second
	// httpBackendReadyInterval is the poll cadence for that wait.
	httpBackendReadyInterval = 250 * time.Millisecond
)

// dialHTTPContainer launches an HTTP MCP backend container on the per-session
// bridge network and returns the address to connect to. Like dialStdioContainer
// it freezes the container immediately after start so the caller can apply
// kernel enforcement before it serves anything; unlike stdio, there is no
// attached stream — the proxy connects to the container's bridge IP over the
// network once it resumes.
//
// The proxy reaches the container by its address on the bridge (host-routable
// for a standard Linux bridge network); no host port is published.
func dialHTTPContainer(ctx context.Context, deps Deps, name string, tool *config.ContainerTool, sessionID, networkName string) (*httpContainer, error) {
	dc := deps.Docker
	log := deps.Logger

	if tool.Port <= 0 {
		return nil, fmt.Errorf("mcpproxy: backend %s: container http transport requires port > 0", name)
	}
	if err := ensureImage(ctx, dc, tool.Image); err != nil {
		return nil, fmt.Errorf("mcpproxy: backend %s: pulling image %s: %w", name, tool.Image, err)
	}
	if err := ensureNetwork(ctx, dc, networkName, sessionID); err != nil {
		return nil, fmt.Errorf("mcpproxy: backend %s: %w", name, err)
	}

	cfg := &container.Config{
		Image: tool.Image,
		Cmd:   tool.Command,
		Env:   envList(tool.Env),
		User:  tool.User,
		Tty:   false,
		Labels: map[string]string{
			LabelRole:    RoleMCPBackend,
			LabelSession: sessionID,
			LabelMCPName: name,
		},
	}
	hostCfg := &container.HostConfig{
		Mounts: parseColonMounts(tool.Mounts),
		// Hardening mirrors the stdio and Compose MCP isolation paths.
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		ReadonlyRootfs: true,
		Tmpfs: map[string]string{
			"/run/secrets": "rw,nosuid,nodev,noexec,size=256m,mode=1777",
		},
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
		return nil, fmt.Errorf("mcpproxy: backend %s: creating container: %w", name, err)
	}
	containerID := created.ID

	cleanup := func(cctx context.Context) error {
		timeout := 10
		_, _ = dc.ContainerStop(cctx, containerID, client.ContainerStopOptions{Timeout: &timeout})
		_, err := dc.ContainerRemove(cctx, containerID, client.ContainerRemoveOptions{Force: true})
		return err
	}

	if _, err := dc.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		_ = cleanup(ctx)
		return nil, fmt.Errorf("mcpproxy: backend %s: starting container: %w", name, err)
	}

	// Freeze immediately (best-effort) so enforcement lands before the server
	// boots — same model and caveats as dialStdioContainer.
	paused := true
	if _, err := dc.ContainerPause(ctx, containerID, client.ContainerPauseOptions{}); err != nil {
		paused = false
		log.Warn("could not freeze backend container before enforcement; a brief startup window runs unenforced",
			zap.String("backend", name),
			zap.String("containerId", containerID),
			zap.Error(err),
		)
	}
	resume := func(rctx context.Context) error {
		if !paused {
			return nil
		}
		_, err := dc.ContainerUnpause(rctx, containerID, client.ContainerUnpauseOptions{})
		return err
	}

	// Resolve the container's address on the session bridge network. Inspect
	// works while frozen (the freezer stops processes, not the metadata).
	ip, err := containerBridgeIP(ctx, dc, containerID, networkName)
	if err != nil {
		_ = cleanup(ctx)
		return nil, fmt.Errorf("mcpproxy: backend %s: %w", name, err)
	}

	path := tool.Path
	if path == "" {
		path = "/"
	}
	address := net.JoinHostPort(ip, fmt.Sprintf("%d", tool.Port))

	log.Info("mcp backend container started (http)",
		zap.String("backend", name),
		zap.String("containerId", containerID),
		zap.String("network", networkName),
		zap.String("address", address),
		zap.Bool("frozen", paused),
	)

	return &httpContainer{
		endpoint:    fmt.Sprintf("http://%s%s", address, path),
		address:     address,
		containerID: containerID,
		resume:      resume,
		cleanup:     cleanup,
	}, nil
}

// containerBridgeIP returns the container's IPv4/IPv6 address on the named
// network, looked up via the Docker inspect API.
func containerBridgeIP(ctx context.Context, dc client.APIClient, containerID, networkName string) (string, error) {
	insp, err := dc.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspecting container for network address: %w", err)
	}
	ns := insp.Container.NetworkSettings
	if ns == nil {
		return "", fmt.Errorf("container %s has no network settings", containerID)
	}
	ep := ns.Networks[networkName]
	if ep == nil || !ep.IPAddress.IsValid() {
		return "", fmt.Errorf("container %s has no address on network %s", containerID, networkName)
	}
	return ep.IPAddress.String(), nil
}

// waitForListening blocks until a TCP connection to addr succeeds or the
// timeout elapses. Used to wait out the gap between a container unfreezing and
// its HTTP MCP server binding its port.
func waitForListening(ctx context.Context, addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	for {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("not listening at %s within %s: %w", addr, timeout, err)
		case <-time.After(httpBackendReadyInterval):
		}
	}
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
