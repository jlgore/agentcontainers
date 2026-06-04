package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// proxyImpl identifies the proxy in MCP initialize handshakes.
var proxyImpl = &mcp.Implementation{
	Name:    "agentcontainer-mcp-proxy",
	Version: "0.1.0",
}

// Options configures a Proxy.
type Options struct {
	// AuditDir overrides the audit directory (default: $AC_AUDIT_DIR or
	// ~/.ac/audit).
	AuditDir string
}

// Proxy is an MCP reverse proxy: one client-facing mcp.Server aggregating
// N backend MCP servers. tools/call is the policy gate (Phase 1:
// allow-passthrough with allowedTools filtering); everything else —
// resources, prompts, sampling, elicitation, progress, list_changed — is
// relayed.
type Proxy struct {
	deps      Deps
	cfg       *config.AgentContainer
	sessionID string

	server *mcp.Server
	audit  *AuditSink

	mu       sync.Mutex
	backends map[string]*Backend
	// toolRoutes maps an aggregated tool name to its owning backend. Tool
	// names must be unique across backends: collisions are a startup error
	// (never silently shadowed — this is a forensic audit boundary).
	toolRoutes map[string]*Backend
	// resourceRoutes maps concrete resource URIs to their backend, used to
	// route resources/subscribe.
	resourceRoutes map[string]*Backend
	// Per-backend registrations, so list_changed can re-aggregate one
	// backend without disturbing the others.
	backendTools     map[string][]string
	backendResources map[string][]string
	backendTemplates map[string][]string
	backendPrompts   map[string][]string
}

// New connects all configured MCP backends, aggregates their tools,
// resources, and prompts onto one server, and prepares the client-facing
// Streamable HTTP handler. On any backend failure the already-started
// backends are torn down.
func New(ctx context.Context, deps Deps, cfg *config.AgentContainer, sessionID string, opts *Options) (*Proxy, error) {
	if cfg == nil || cfg.Agent == nil || cfg.Agent.Tools == nil || len(cfg.Agent.Tools.MCP) == 0 {
		return nil, fmt.Errorf("mcpproxy: no MCP servers configured")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("mcpproxy: sessionID must not be empty")
	}
	if deps.Logger == nil {
		deps.Logger = zap.NewNop()
	}
	if opts == nil {
		opts = &Options{}
	}

	sink, err := NewAuditSink(sessionID, opts.AuditDir)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		deps:             deps,
		cfg:              cfg,
		sessionID:        sessionID,
		audit:            sink,
		backends:         make(map[string]*Backend),
		toolRoutes:       make(map[string]*Backend),
		resourceRoutes:   make(map[string]*Backend),
		backendTools:     make(map[string][]string),
		backendResources: make(map[string][]string),
		backendTemplates: make(map[string][]string),
		backendPrompts:   make(map[string][]string),
	}

	p.server = mcp.NewServer(proxyImpl, &mcp.ServerOptions{
		Instructions:       "MCP reverse proxy: tool calls are policy-gated and audited.",
		SubscribeHandler:   p.handleSubscribe,
		UnsubscribeHandler: p.handleUnsubscribe,
	})

	networkName := "ac-mcp-" + shortID(sessionID)

	// Connect backends in sorted order for deterministic startup and
	// deterministic collision reporting.
	names := make([]string, 0, len(cfg.Agent.Tools.MCP))
	for name := range cfg.Agent.Tools.MCP {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		tool := cfg.Agent.Tools.MCP[name]
		mcpClient := mcp.NewClient(proxyImpl, p.clientOptions(name))
		b, err := newBackend(ctx, deps, mcpClient, name, tool, sessionID, networkName, maxConcurrentTools(cfg, tool.Policy))
		if err != nil {
			_ = p.Close(ctx)
			return nil, err
		}
		p.mu.Lock()
		p.backends[name] = b
		p.mu.Unlock()

		if err := p.aggregateBackend(ctx, b, true); err != nil {
			_ = p.Close(ctx)
			return nil, err
		}
	}

	return p, nil
}

// Handler returns the client-facing MCP Streamable HTTP handler.
func (p *Proxy) Handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return p.server }, nil)
}

// AuditPath returns the proxy.jsonl audit file path.
func (p *Proxy) AuditPath() string {
	return p.audit.Path()
}

// Backends returns the connected backend names (sorted).
func (p *Proxy) Backends() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	names := make([]string, 0, len(p.backends))
	for name := range p.backends {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Close tears down all backends and the audit sink.
func (p *Proxy) Close(ctx context.Context) error {
	p.mu.Lock()
	backends := make([]*Backend, 0, len(p.backends))
	for _, b := range p.backends {
		backends = append(backends, b)
	}
	p.backends = make(map[string]*Backend)
	p.mu.Unlock()

	var errs []string
	for _, b := range backends {
		if err := b.Close(ctx); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if p.audit != nil {
		if err := p.audit.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("mcpproxy: close: %s", strings.Join(errs, "; "))
	}
	return nil
}

// upstreamSession returns the active client-facing session, used to relay
// backend-initiated sampling/elicitation/progress upstream. Phase 1 assumes
// a single analyst: the first connected session wins.
func (p *Proxy) upstreamSession() *mcp.ServerSession {
	for ss := range p.server.Sessions() {
		return ss
	}
	return nil
}

// clientOptions wires the per-backend relay handlers: backend-initiated
// traffic (sampling, elicitation, progress, logging) forwards to the
// upstream client session; list_changed notifications trigger
// re-aggregation of that backend.
func (p *Proxy) clientOptions(name string) *mcp.ClientOptions {
	log := p.deps.Logger
	return &mcp.ClientOptions{
		CreateMessageHandler: func(ctx context.Context, req *mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
			ss := p.upstreamSession()
			if ss == nil {
				return nil, fmt.Errorf("mcpproxy: no upstream client session to relay sampling request from %s", name)
			}
			return ss.CreateMessage(ctx, req.Params)
		},
		ElicitationHandler: func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			ss := p.upstreamSession()
			if ss == nil {
				return nil, fmt.Errorf("mcpproxy: no upstream client session to relay elicitation from %s", name)
			}
			return ss.Elicit(ctx, req.Params)
		},
		ProgressNotificationHandler: func(ctx context.Context, req *mcp.ProgressNotificationClientRequest) {
			if ss := p.upstreamSession(); ss != nil {
				if err := ss.NotifyProgress(ctx, req.Params); err != nil {
					log.Debug("relaying progress failed", zap.String("backend", name), zap.Error(err))
				}
			}
		},
		LoggingMessageHandler: func(ctx context.Context, req *mcp.LoggingMessageRequest) {
			if ss := p.upstreamSession(); ss != nil {
				if err := ss.Log(ctx, req.Params); err != nil {
					log.Debug("relaying log message failed", zap.String("backend", name), zap.Error(err))
				}
			}
		},
		ToolListChangedHandler: func(ctx context.Context, _ *mcp.ToolListChangedRequest) {
			p.reaggregate(ctx, name)
		},
		ResourceListChangedHandler: func(ctx context.Context, _ *mcp.ResourceListChangedRequest) {
			p.reaggregate(ctx, name)
		},
		PromptListChangedHandler: func(ctx context.Context, _ *mcp.PromptListChangedRequest) {
			p.reaggregate(ctx, name)
		},
		ResourceUpdatedHandler: func(ctx context.Context, req *mcp.ResourceUpdatedNotificationRequest) {
			if err := p.server.ResourceUpdated(ctx, req.Params); err != nil {
				log.Debug("relaying resource update failed", zap.String("backend", name), zap.Error(err))
			}
		},
	}
}

// reaggregate refreshes one backend's contributions after a list_changed
// notification. Server.RemoveX/AddX automatically emit list_changed to the
// upstream client. Collisions at this stage are logged and skipped (a
// running session must not crash on a misbehaving backend).
func (p *Proxy) reaggregate(ctx context.Context, name string) {
	p.mu.Lock()
	b := p.backends[name]
	p.mu.Unlock()
	if b == nil {
		return
	}
	if err := p.aggregateBackend(ctx, b, false); err != nil {
		p.deps.Logger.Warn("re-aggregation failed", zap.String("backend", name), zap.Error(err))
	}
}

// aggregateBackend (re)registers a backend's tools, resources, resource
// templates, and prompts on the client-facing server. With strict=true
// (startup) a tool-name collision across backends is an error; with
// strict=false (list_changed) collisions are skipped with a warning.
func (p *Proxy) aggregateBackend(ctx context.Context, b *Backend, strict bool) error {
	log := p.deps.Logger

	tools, err := b.ListTools(ctx)
	if err != nil {
		return fmt.Errorf("mcpproxy: backend %s: listing tools: %w", b.Name, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove this backend's previous registrations.
	if old := p.backendTools[b.Name]; len(old) > 0 {
		p.server.RemoveTools(old...)
		for _, t := range old {
			delete(p.toolRoutes, t)
		}
	}
	if old := p.backendResources[b.Name]; len(old) > 0 {
		p.server.RemoveResources(old...)
		for _, uri := range old {
			delete(p.resourceRoutes, uri)
		}
	}
	if old := p.backendTemplates[b.Name]; len(old) > 0 {
		p.server.RemoveResourceTemplates(old...)
	}
	if old := p.backendPrompts[b.Name]; len(old) > 0 {
		p.server.RemovePrompts(old...)
	}
	p.backendTools[b.Name] = nil
	p.backendResources[b.Name] = nil
	p.backendTemplates[b.Name] = nil
	p.backendPrompts[b.Name] = nil

	// Tools, filtered by the per-server allowedTools policy.
	for _, tool := range tools {
		if !toolAllowed(b.Policy, tool.Name) {
			continue
		}
		if owner, exists := p.toolRoutes[tool.Name]; exists {
			if strict {
				return fmt.Errorf("mcpproxy: tool name collision: %q exposed by both %s and %s (rename or restrict via policy.allowedTools)", tool.Name, owner.Name, b.Name)
			}
			log.Warn("skipping colliding tool",
				zap.String("tool", tool.Name),
				zap.String("backend", b.Name),
				zap.String("owner", owner.Name),
			)
			continue
		}
		p.server.AddTool(tool, p.handleToolCall(b, tool.Name))
		p.toolRoutes[tool.Name] = b
		p.backendTools[b.Name] = append(p.backendTools[b.Name], tool.Name)
	}

	// Resources and prompts: pure passthrough, no policy gating (the
	// policy boundary is tools/call).
	if b.supportsResources() {
		for res, err := range b.session.Resources(ctx, nil) {
			if err != nil {
				return fmt.Errorf("mcpproxy: backend %s: listing resources: %w", b.Name, err)
			}
			if _, exists := p.resourceRoutes[res.URI]; exists {
				log.Warn("skipping colliding resource", zap.String("uri", res.URI), zap.String("backend", b.Name))
				continue
			}
			p.server.AddResource(res, p.handleReadResource(b))
			p.resourceRoutes[res.URI] = b
			p.backendResources[b.Name] = append(p.backendResources[b.Name], res.URI)
		}
		for tmpl, err := range b.session.ResourceTemplates(ctx, nil) {
			if err != nil {
				return fmt.Errorf("mcpproxy: backend %s: listing resource templates: %w", b.Name, err)
			}
			p.server.AddResourceTemplate(tmpl, p.handleReadResource(b))
			p.backendTemplates[b.Name] = append(p.backendTemplates[b.Name], tmpl.URITemplate)
		}
	}
	if b.supportsPrompts() {
		for prompt, err := range b.session.Prompts(ctx, nil) {
			if err != nil {
				return fmt.Errorf("mcpproxy: backend %s: listing prompts: %w", b.Name, err)
			}
			p.server.AddPrompt(prompt, p.handleGetPrompt(b))
			p.backendPrompts[b.Name] = append(p.backendPrompts[b.Name], prompt.Name)
		}
	}

	return nil
}

// handleToolCall is the proxied tools/call hot path. Phase 1 is
// allow-passthrough: no policy engine yet, but every call gets a
// correlation ID and an audit entry. Phase 2 inserts policy evaluation
// before the forward; Phase 3 brackets it with PrepareToolCall /
// CompleteToolCall on the enforcer.
func (p *Proxy) handleToolCall(b *Backend, toolName string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		corrID := newCorrelationID()
		args := req.Params.Arguments
		summary := argsSummary(args)

		if err := b.acquireToolSlot(ctx); err != nil {
			return nil, err
		}
		defer b.releaseToolSlot()

		start := time.Now()
		res, callErr := b.CallTool(ctx, toolName, args, req.Params.GetProgressToken())
		latency := time.Since(start).Milliseconds()

		rec := ToolCallRecord{
			CorrelationID: corrID,
			Server:        b.Name,
			ContainerID:   b.ContainerID,
			Enforcement:   b.Enforcement(),
			Tool:          toolName,
			ArgsSummary:   summary,
			Verdict:       audit.VerdictAllow,
			LatencyMs:     latency,
		}
		if err := p.audit.LogToolCall(rec); err != nil {
			// The call already executed; an audit failure must be loud but
			// cannot retract the response.
			p.deps.Logger.Error("audit write failed",
				zap.String("correlationId", corrID),
				zap.String("backend", b.Name),
				zap.Error(err),
			)
		}

		return res, callErr
	}
}

// handleReadResource relays resources/read to the owning backend.
func (p *Proxy) handleReadResource(b *Backend) mcp.ResourceHandler {
	return func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return b.session.ReadResource(ctx, req.Params)
	}
}

// handleGetPrompt relays prompts/get to the owning backend.
func (p *Proxy) handleGetPrompt(b *Backend) mcp.PromptHandler {
	return func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return b.session.GetPrompt(ctx, req.Params)
	}
}

// handleSubscribe relays resources/subscribe to the backend owning the URI.
func (p *Proxy) handleSubscribe(ctx context.Context, req *mcp.SubscribeRequest) error {
	p.mu.Lock()
	b := p.resourceRoutes[req.Params.URI]
	p.mu.Unlock()
	if b == nil || b.session == nil {
		return fmt.Errorf("mcpproxy: no backend serves resource %q", req.Params.URI)
	}
	return b.session.Subscribe(ctx, &mcp.SubscribeParams{URI: req.Params.URI})
}

// handleUnsubscribe relays resources/unsubscribe.
func (p *Proxy) handleUnsubscribe(ctx context.Context, req *mcp.UnsubscribeRequest) error {
	p.mu.Lock()
	b := p.resourceRoutes[req.Params.URI]
	p.mu.Unlock()
	if b == nil || b.session == nil {
		return fmt.Errorf("mcpproxy: no backend serves resource %q", req.Params.URI)
	}
	return b.session.Unsubscribe(ctx, &mcp.UnsubscribeParams{URI: req.Params.URI})
}

// toolAllowed applies the per-server allowedTools filter; an empty list
// allows everything.
func toolAllowed(policy *config.MCPServerPolicy, name string) bool {
	if policy == nil || len(policy.AllowedTools) == 0 {
		return true
	}
	for _, t := range policy.AllowedTools {
		if t == name {
			return true
		}
	}
	return false
}

func maxConcurrentTools(cfg *config.AgentContainer, policy *config.MCPServerPolicy) int {
	if policy != nil && policy.MaxConcurrentTools > 0 {
		return policy.MaxConcurrentTools
	}
	if cfg != nil && cfg.Agent != nil && cfg.Agent.Policy != nil && cfg.Agent.Policy.MaxConcurrentTools > 0 {
		return cfg.Agent.Policy.MaxConcurrentTools
	}
	return 1
}

// newCorrelationID returns a UUIDv7 (monotonic within a millisecond, so
// audit entries sort by time).
func newCorrelationID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

// argsSummary renders raw tool arguments as a compact single-line string
// for the audit `command`/`argsSummary` fields, truncated to keep entries
// bounded.
func argsSummary(args json.RawMessage) string {
	const maxLen = 512
	s := strings.Join(strings.Fields(string(args)), " ")
	if len(s) > maxLen {
		s = s[:maxLen] + "…"
	}
	return s
}
