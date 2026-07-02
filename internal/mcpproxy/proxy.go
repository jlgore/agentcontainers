package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/identity"
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

	// ConfigDir anchors relative policy.securityYaml paths (the directory
	// containing agentcontainer.json).
	ConfigDir string

	// Approval resolves tools listed in policy.requireApproval. Required
	// when any configured server declares requireApproval — the HITL gate
	// is structural, so a missing broker is a startup error, not a
	// silent passthrough.
	Approval *approval.ToolCallBroker

	// PublisherName labels this deployment in the ARD catalog
	// (/.well-known/ai-catalog.json). Defaults to "agentcontainers" when
	// empty.
	PublisherName string

	// PublicEndpoint is the externally reachable MCP endpoint advertised in
	// the ARD catalog (e.g. "https://forensic-e2e.example.com/mcp"). When
	// empty the catalog omits per-capability endpoints; operators behind a
	// proxy should set their public URL.
	PublicEndpoint string

	// Identity is the instance's signing identity (G1). When set, every audit
	// entry across all three chains is signed with its did:key, the ARD
	// catalog publishes the issuer DID + an enforcement credential, and
	// operator-override VCs (G3) are verified against its resolver. Nil leaves
	// audit entries unsigned (back-compat) and the catalog's trust fields
	// empty.
	Identity identity.KeyStore
}

// serverPolicy is the per-server policy machinery compiled at startup:
// the OPA evaluator plus the decomposition settings it evaluates against.
// Servers that declare nothing the engine evaluates have no entry and
// skip Rego entirely (the Go-side allowedTools gate still applies).
type serverPolicy struct {
	eval        PolicyEngine
	outputFlags []string
	shellTools  map[string]config.ShellToolSpec
	// policyHash is sha256 of the compiled policy bundle (modules + data),
	// surfaced in the ARD catalog so external consumers can verify which
	// policy governs a capability.
	policyHash string
	// uriEgress enables URI-scoped transient egress (G4) for this server:
	// the proxy extracts user-supplied https URLs from tool arguments and
	// asks the policy to approve transient egress to their hosts.
	uriEgress bool
	// operatorDIDs are the did:key identities whose per-invocation override
	// VCs (G3) this server honors. Empty disables overrides (fail closed).
	// The override ceiling itself lives in the compiled policy data.
	operatorDIDs []string
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

	// approvals is the HITL broker for requireApproval tools; nil when no
	// server declares any. approvalAudit is the `<sessionId>-approval`
	// chain (SPEC §7.3), created alongside the broker.
	approvals     *approval.ToolCallBroker
	approvalAudit *ApprovalAuditSink

	// policies maps server name to its compiled policy machinery
	// (immutable after New).
	policies map[string]*serverPolicy

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
	// catalogTools holds the full tool descriptor for each aggregated
	// (allowed) tool name, so the ARD catalog can publish descriptions and
	// input schemas without re-listing backends on every request.
	catalogTools map[string]*mcp.Tool

	// refreshCancel stops the periodic network-policy hostname
	// re-resolution goroutine (nil when no enforcer is connected).
	refreshCancel context.CancelFunc

	// publisherName and publicEndpoint feed the ARD catalog
	// (/.well-known/ai-catalog.json); both come from Options.
	publisherName  string
	publicEndpoint string

	// identity signs the audit chains and issues the catalog publisher
	// credential (G1); nil when no identity is configured. publisherVC is the
	// pre-issued enforcement credential the catalog serves (empty when
	// identity is nil).
	identity    identity.KeyStore
	publisherVC string
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

	// The HITL gate is structural: a server declaring requireApproval
	// without a broker to resolve it is a startup error, never a silent
	// passthrough.
	needsApproval := anyRequireApproval(cfg)
	if needsApproval && opts.Approval == nil {
		return nil, fmt.Errorf("mcpproxy: policy.requireApproval is configured but no approval broker is available")
	}

	// A nil identity satisfies audit.Signer's nil contract (unsigned entries).
	var signer audit.Signer
	if opts.Identity != nil {
		signer = opts.Identity
	}

	sink, err := NewAuditSink(sessionID, opts.AuditDir, signer)
	if err != nil {
		return nil, err
	}

	var approvalSink *ApprovalAuditSink
	if needsApproval {
		approvalSink, err = NewApprovalAuditSink(sessionID, opts.AuditDir, signer)
		if err != nil {
			_ = sink.Close()
			return nil, err
		}
	}

	p := &Proxy{
		deps:             deps,
		cfg:              cfg,
		sessionID:        sessionID,
		audit:            sink,
		approvals:        opts.Approval,
		approvalAudit:    approvalSink,
		policies:         make(map[string]*serverPolicy),
		backends:         make(map[string]*Backend),
		toolRoutes:       make(map[string]*Backend),
		resourceRoutes:   make(map[string]*Backend),
		backendTools:     make(map[string][]string),
		backendResources: make(map[string][]string),
		backendTemplates: make(map[string][]string),
		backendPrompts:   make(map[string][]string),
		catalogTools:     make(map[string]*mcp.Tool),
		publisherName:    opts.PublisherName,
		publicEndpoint:   opts.PublicEndpoint,
		identity:         opts.Identity,
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

	// Compile per-server policies before launching anything: a broken
	// policy must fail startup, not fall open after containers exist.
	closeSinks := func() {
		_ = sink.Close()
		if approvalSink != nil {
			_ = approvalSink.Close()
		}
	}

	// Issue the deployment's enforcement credential (G1): a VC the ARD catalog
	// publishes so an external consumer can verify the enforcement posture
	// without trusting the agent. Re-issued each start (no expiry); the DID is
	// stable across restarts because the key is persisted. Enforcement layers
	// are known here (proxy is always active; kernel when an enforcer is wired).
	if p.identity != nil {
		enforcement := []string{"opa_proxy"}
		if p.deps.Enforcer != nil {
			enforcement = append(enforcement, "ebpf_kernel")
		}
		vc, err := identity.IssueVC(p.identity, identity.VCClaims{
			Sub:                  p.identity.DID(),
			EnforcementModel:     enforcement,
			EvidenceImmutability: "append_only_hash_chain",
			AuditChainType:       "independent_sha256_hash_chains",
		}, 0)
		if err != nil {
			closeSinks()
			return nil, fmt.Errorf("mcpproxy: issuing publisher credential: %w", err)
		}
		p.publisherVC = vc
	}

	for _, name := range names {
		tool := cfg.Agent.Tools.MCP[name]
		cp, err := CompileServerPolicy(tool, opts.ConfigDir)
		if err != nil {
			closeSinks()
			return nil, err
		}
		if cp == nil {
			continue
		}
		// The embedded Cedar engine evaluates the compiled policy. A bad
		// compiled policy fails closed here at startup rather than silently
		// degrading.
		engine, err := NewCedarEvaluator(ctx, name, cp)
		if err != nil {
			closeSinks()
			return nil, err
		}
		sp := &serverPolicy{eval: engine, outputFlags: cp.OutputFlags, policyHash: cp.Hash()}
		if tool.Policy != nil {
			sp.shellTools = tool.Policy.ShellTools
			sp.operatorDIDs = tool.Policy.OperatorDIDs
			if tool.Policy.Network != nil {
				sp.uriEgress = tool.Policy.Network.URIEgress
			}
		}
		p.policies[name] = sp
	}

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

	// Periodically re-resolve network policy hostnames so kernel egress
	// rules track CDN/cloud IP rotation across long forensic sessions.
	// Bound to the proxy lifetime (not the startup ctx).
	if deps.Enforcer != nil {
		refreshCtx, cancel := context.WithCancel(context.Background())
		p.refreshCancel = cancel
		go p.refreshNetworkPolicies(refreshCtx)
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

// ApprovalAuditPath returns the approval.jsonl audit file path, or "" when
// no server requires approval.
func (p *Proxy) ApprovalAuditPath() string {
	if p.approvalAudit == nil {
		return ""
	}
	return p.approvalAudit.Path()
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
	if p.refreshCancel != nil {
		p.refreshCancel()
	}
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
	if p.approvalAudit != nil {
		if err := p.approvalAudit.Close(); err != nil {
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
			delete(p.catalogTools, t)
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
		p.catalogTools[tool.Name] = tool
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

// handleToolCall is the proxied tools/call hot path: decompose the
// arguments, evaluate the server's compiled policy per sub-command (deny
// if ANY denies; an engine error fails CLOSED), then forward on allow.
// Every call gets a correlation ID and an audit entry. Phase 3 brackets
// the forward with PrepareToolCall / CompleteToolCall on the enforcer.
func (p *Proxy) handleToolCall(b *Backend, toolName string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		corrID := newCorrelationID()
		args := req.Params.Arguments
		start := time.Now()

		sp := p.policies[b.Name]
		decision, parsedList := p.evaluatePolicy(ctx, sp, b.Name, toolName, corrID, args, req.Params.Meta)
		summary := commandSummary(parsedList, args)

		rec := ToolCallRecord{
			CorrelationID:     corrID,
			Server:            b.Name,
			ContainerID:       b.ContainerID,
			Enforcement:       b.Enforcement(),
			Tool:              toolName,
			ArgsSummary:       summary,
			Reasons:           decision.Reasons,
			PoliciesEvaluated: decision.PoliciesEvaluated,
			OverrideApplied:   decision.OverrideActive,
			OverrideIssuer:    decision.OverrideIssuer,
			WaivedReasons:     decision.WaivedReasons,
			OverrideRejected:  decision.OverrideRejected,
		}

		if !decision.Allowed {
			rec.Verdict = audit.VerdictDeny
			rec.LatencyMs = time.Since(start).Milliseconds()
			p.logToolCall(rec)
			// Denials are in-band tool results, not protocol errors
			// (SPEC §6). The client-facing text drops the package
			// prefixes; the audit metadata keeps them.
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{
					Text: "Policy denial: " + strings.Join(deprefixReasons(decision.Reasons), "; "),
				}},
			}, nil
		}

		// Human-in-the-loop gate (Phase 4): tools in requireApproval pause
		// for a decision before the tool slot is acquired (a human wait
		// must not serialize other tool calls). approval.jsonl is the
		// authoritative record; the proxy entry only summarizes.
		if toolRequiresApproval(b.Policy, toolName) {
			rec.ApprovalRequired = true
			hd := p.awaitApproval(ctx, req, b.Name, toolName, corrID, summary)
			if !hd.Approved {
				rec.Verdict = audit.VerdictDeny
				rec.Reasons = append(rec.Reasons, "approval: "+hd.Reason)
				rec.LatencyMs = time.Since(start).Milliseconds()
				p.logToolCall(rec)
				return &mcp.CallToolResult{
					IsError: true,
					Content: []mcp.Content{&mcp.TextContent{
						Text: "Approval denied: " + hd.Reason,
					}},
				}, nil
			}
		}

		if err := b.acquireToolSlot(ctx); err != nil {
			return nil, err
		}
		defer b.releaseToolSlot()

		if err := p.prepareToolCall(ctx, b, corrID, decision.EgressTargets); err != nil {
			return nil, err
		}
		if shouldCorrelate(b) {
			defer p.completeToolCall(context.Background(), b, corrID)
		}

		res, callErr := b.CallTool(ctx, toolName, args, req.Params.GetProgressToken())
		rec.Verdict = audit.VerdictAllow
		rec.LatencyMs = time.Since(start).Milliseconds()
		p.logToolCall(rec)

		return res, callErr
	}
}

// awaitApproval blocks on the HITL broker for a requireApproval tool and
// logs the decision to the approval chain. While waiting it sends MCP
// progress notifications to the client (when the call carries a progress
// token) so long approval waits don't look like a hung connection. Timeout
// and client disconnect both deny — the gate fails closed.
func (p *Proxy) awaitApproval(ctx context.Context, req *mcp.CallToolRequest, server, toolName, corrID, summary string) approval.ToolCallDecision {
	if p.approvals == nil {
		// Unreachable when New validated the config, but never fall open.
		return approval.ToolCallDecision{Approved: false, Reason: "no approval broker configured"}
	}

	if token := req.Params.GetProgressToken(); token != nil && req.Session != nil {
		keepaliveCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			ticker := time.NewTicker(approvalProgressInterval)
			defer ticker.Stop()
			n := 0.0
			for {
				select {
				case <-keepaliveCtx.Done():
					return
				case <-ticker.C:
					n++
					if err := req.Session.NotifyProgress(keepaliveCtx, &mcp.ProgressNotificationParams{
						ProgressToken: token,
						Progress:      n,
						Message:       fmt.Sprintf("awaiting human approval for %s (deny after %s)", toolName, p.approvals.Timeout()),
					}); err != nil {
						p.deps.Logger.Debug("approval keepalive failed", zap.Error(err))
						return
					}
				}
			}
		}()
	}

	promptStart := time.Now()
	d := p.approvals.Request(ctx, approval.ToolCallRequest{
		ID:          corrID,
		Server:      server,
		Tool:        toolName,
		ArgsSummary: summary,
		RequestedAt: promptStart.UTC(),
	})

	if p.approvalAudit != nil {
		if err := p.approvalAudit.LogDecision(ApprovalRecord{
			CorrelationID:    corrID,
			Server:           server,
			Tool:             toolName,
			ArgsSummary:      summary,
			Approved:         d.Approved,
			Reason:           d.Reason,
			Decider:          d.Decider,
			PromptDurationMs: time.Since(promptStart).Milliseconds(),
		}); err != nil {
			p.deps.Logger.Error("approval audit write failed",
				zap.String("correlationId", corrID),
				zap.String("backend", server),
				zap.Error(err),
			)
		}
	}
	return d
}

// approvalProgressInterval is how often the proxy reassures a waiting
// client that the call is paused on a human, not hung.
const approvalProgressInterval = 10 * time.Second

// toolRequiresApproval reports whether the per-server policy pauses this
// tool for human confirmation.
func toolRequiresApproval(policy *config.MCPServerPolicy, name string) bool {
	if policy == nil {
		return false
	}
	for _, t := range policy.RequireApproval {
		if t == name {
			return true
		}
	}
	return false
}

// anyRequireApproval reports whether any configured server declares
// requireApproval tools.
func anyRequireApproval(cfg *config.AgentContainer) bool {
	for _, tool := range cfg.Agent.Tools.MCP {
		if tool.Policy != nil && len(tool.Policy.RequireApproval) > 0 {
			return true
		}
	}
	return false
}

func shouldCorrelate(b *Backend) bool {
	return b != nil && b.ContainerID != ""
}

func (p *Proxy) prepareToolCall(ctx context.Context, b *Backend, corrID string, egress []EgressTarget) error {
	if !shouldCorrelate(b) || p.deps.Enforcer == nil {
		return nil
	}
	// The per-tool secret restriction is keyed on the MCP *server* identity
	// (the tools.MCP entry name, b.Name), which is what policy resolution puts
	// in a secret's allowedTools. Sending the individual method name here would
	// never match the resolved ACL, so restricted secrets would be unreadable.
	req := &enforcerapi.PrepareToolCallRequest{
		CorrelationId: corrID,
		ContainerId:   b.ContainerID,
		ToolName:      b.Name,
	}
	// G4: attach URI-scoped transient egress targets. The enforcer opens
	// kernel egress to exactly these host:port pairs for this tool-call
	// window and closes them on CompleteToolCall (or at the timeout). Empty
	// leaves static egress policy unchanged.
	for _, t := range egress {
		req.TransientEgress = append(req.TransientEgress, &enforcerapi.EgressRule{
			Host:     t.Host,
			Port:     uint32(t.Port),
			Protocol: t.Protocol,
		})
	}
	if _, err := p.deps.Enforcer.PrepareToolCall(ctx, req); err != nil {
		return fmt.Errorf("mcpproxy: preparing tool-call correlation for %s: %w", b.Name, err)
	}
	return nil
}

// completeToolCallAttempts bounds the retries on CompleteToolCall: a lost
// Complete leaves the correlation window open until the enforcer's
// open-window horizon expires it, misattributing background events to this
// correlation ID in the meantime — worth a few hundred ms of retry.
const completeToolCallAttempts = 3

func (p *Proxy) completeToolCall(ctx context.Context, b *Backend, corrID string) {
	if !shouldCorrelate(b) || p.deps.Enforcer == nil {
		return
	}
	var err error
	for attempt := 0; attempt < completeToolCallAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
		if _, err = p.deps.Enforcer.CompleteToolCall(ctx, &enforcerapi.CompleteToolCallRequest{
			CorrelationId: corrID,
			ContainerId:   b.ContainerID,
		}); err == nil {
			return
		}
	}
	p.deps.Logger.Error("tool-call correlation completion failed — window stays open until the enforcer horizon expires it",
		zap.String("correlationId", corrID),
		zap.String("backend", b.Name),
		zap.Int("attempts", completeToolCallAttempts),
		zap.Error(err),
	)
}

// logToolCall writes the audit entry, loudly surfacing failures (the call
// outcome is already determined; an audit failure cannot retract it).
func (p *Proxy) logToolCall(rec ToolCallRecord) {
	if err := p.audit.LogToolCall(rec); err != nil {
		p.deps.Logger.Error("audit write failed",
			zap.String("correlationId", rec.CorrelationID),
			zap.String("backend", rec.Server),
			zap.Error(err),
		)
	}
}

// evaluatePolicy decomposes the tool arguments and evaluates each
// sub-command against the server's compiled policy. Servers without an
// evaluator allow by construction (nothing declared to evaluate). The
// overall decision denies if any sub-command denies; reasons are the
// deduplicated union. An evaluation error fails closed.
func (p *Proxy) evaluatePolicy(ctx context.Context, sp *serverPolicy, server, toolName, corrID string, args json.RawMessage, meta map[string]any) (Decision, []Parsed) {
	if sp == nil {
		return Decision{Allowed: true}, nil
	}

	parsedList := decomposeToolArgs(sp, toolName, args)
	if len(parsedList) == 0 {
		// Not a shell-like tool: evaluate once with an empty parsed
		// document. The security packages no-op on it, but the decision
		// (and policiesEvaluated) is still real and audited.
		parsedList = []Parsed{{}}
	}

	pctx := policyContext(corrID)
	argsVal := rawArgsValue(args)
	// G4: when the server opts into URI-scoped egress, surface user-supplied
	// https URLs to the policy as input.context.requested_uris. Two sources,
	// both tagged with provenance: Phase A from the tool's own arguments
	// (source "tool_args") and Phase B from the harness-attested _meta
	// (source "user_message"). The Rego rule prefers user_message when present;
	// the proxy only acts on the resulting egress_targets for an allowed call.
	if sp.uriEgress {
		uris := extractRequestedURIs(parsedList, argsVal)
		uris = append(uris, extractMetaURIs(meta)...)
		if len(uris) > 0 {
			pctx["requested_uris"] = uris
		}
	}

	// G3: a per-invocation operator override arrives as a signed VC in _meta.
	// Verify it here (crypto stays Go-side); on success inject the claims as
	// input.context.operator_override so the Rego ceiling can waive denies
	// within the operator's allowlist. A present-but-rejected override (bad
	// signature, expired, untrusted issuer) is dropped — the call proceeds
	// under static policy — and the reason is carried out for the audit trail.
	overrideClaims, overrideRejected := verifyOverride(meta, sp.operatorDIDs)
	if overrideClaims != nil {
		pctx["operator_override"] = map[string]any{
			"iss":          overrideClaims.Iss,
			"capabilities": stringsToAny(overrideClaims.Capabilities),
		}
	}

	agg := Decision{Allowed: true, PoliciesEvaluated: sp.eval.PoliciesEvaluated()}
	seen := make(map[string]bool)
	egressSeen := make(map[string]bool)

	for _, parsed := range parsedList {
		d, err := evaluateParsed(ctx, sp.eval, server, toolName, argsVal, parsed, pctx)
		if err != nil {
			// Fail CLOSED: a broken policy engine never falls open.
			p.deps.Logger.Error("policy evaluation failed",
				zap.String("backend", server),
				zap.String("tool", toolName),
				zap.Error(err),
			)
			return Decision{
				Allowed:           false,
				Reasons:           []string{"policy engine error: " + err.Error()},
				PoliciesEvaluated: agg.PoliciesEvaluated,
			}, parsedList
		}
		if !d.Allowed {
			agg.Allowed = false
		}
		for _, r := range d.Reasons {
			if !seen[r] {
				seen[r] = true
				agg.Reasons = append(agg.Reasons, r)
			}
		}
		for _, t := range d.EgressTargets {
			key := t.Host + ":" + strconv.Itoa(t.Port)
			if !egressSeen[key] {
				egressSeen[key] = true
				agg.EgressTargets = append(agg.EgressTargets, t)
			}
		}
		// Override provenance is the same across sub-commands (one pctx); OR
		// the active flag and union the waived reasons for the audit record.
		if d.OverrideActive {
			agg.OverrideActive = true
		}
		for _, r := range d.WaivedReasons {
			if !seen["waived:"+r] {
				seen["waived:"+r] = true
				agg.WaivedReasons = append(agg.WaivedReasons, r)
			}
		}
	}
	if overrideClaims != nil {
		agg.OverrideIssuer = overrideClaims.Iss
	}
	agg.OverrideRejected = overrideRejected
	return agg, parsedList
}

// extractRequestedURIs scans a tool call's decomposed arguments for https
// URLs and returns them as policy input objects {uri, scheme, host, port,
// source}. This is Phase A provenance: the URL is taken from the tool's own
// arguments (the link the agent is about to fetch), tagged source
// "tool_args". URL parsing is done here (Go net/url), not in Rego, so the
// policy only applies allow-logic over already-parsed fields. Phase B
// (harness-attested source "user_message" via request _meta) layers on top.
func extractRequestedURIs(parsedList []Parsed, args any) []map[string]any {
	seen := make(map[string]bool)
	var out []map[string]any
	consider := func(tok string) {
		if seen[tok] {
			return
		}
		u, ok := parseHTTPSURI(tok)
		if !ok {
			return
		}
		seen[tok] = true
		u["source"] = "tool_args"
		out = append(out, u)
	}
	for _, p := range parsedList {
		for _, a := range p.Args {
			consider(a)
		}
		for _, pth := range p.Paths {
			consider(pth)
		}
	}
	// Also scan raw string argument values (non-shell tools whose args carry
	// a URL directly, e.g. {"url": "https://..."}).
	scanArgStrings(args, consider)
	return out
}

// parseHTTPSURI parses an https URL into the policy-input fields
// {uri, scheme, host, port}, or reports false for anything that is not a
// well-formed https URL. The caller adds the "source" provenance tag. https
// only: http/file/ftp never qualify for transient egress.
func parseHTTPSURI(tok string) (map[string]any, bool) {
	if !strings.HasPrefix(tok, "https://") {
		return nil, false
	}
	u, err := url.Parse(tok)
	if err != nil || u.Host == "" {
		return nil, false
	}
	portNum := 443
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			portNum = n
		}
	}
	return map[string]any{
		"uri":    tok,
		"scheme": u.Scheme,
		"host":   u.Hostname(),
		"port":   portNum,
	}, true
}

// extractMetaURIs reads harness-attested URIs from a tool call's _meta field
// (Phase B provenance, G4). The harness — the Claude Code PreToolUse guard or
// the MCP client — attaches the URLs the *user* actually supplied under
// _meta.requested_uris, so the policy can grant egress to a user-named host
// without inferring intent from the tool's own arguments. Each entry may be a
// bare string ("https://x") or an object carrying a "uri" field; both are
// normalized and tagged source "user_message". This is the channel that
// delivers the PRD's "no implicit grants from tool output" guarantee: a URL
// the model merely echoed from prior output never arrives here.
func extractMetaURIs(meta map[string]any) []map[string]any {
	raw, ok := meta["requested_uris"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	seen := make(map[string]bool)
	var out []map[string]any
	for _, item := range list {
		var tok string
		switch v := item.(type) {
		case string:
			tok = v
		case map[string]any:
			tok, _ = v["uri"].(string)
		}
		if seen[tok] {
			continue
		}
		if u, ok := parseHTTPSURI(tok); ok {
			seen[tok] = true
			u["source"] = "user_message"
			out = append(out, u)
		}
	}
	return out
}

// verifyOverride validates an operator-override VC carried in a tool call's
// _meta (G3). It returns the verified claims to inject, or a non-empty
// rejection reason when an override was present but refused — the call then
// proceeds under static policy and the reason is audited. When no override is
// present it returns (nil, ""). Verification is layered and fails closed:
//
//  1. the override must be a string JWT,
//  2. its EdDSA signature and (if set) expiry must check out (VerifyVC),
//  3. its issuer DID must be in this server's trusted operator set.
//
// did:key verification is self-certifying, so step 2 only proves the token is
// internally consistent; step 3 is the actual authorization gate. With an
// empty trusted set, every override is rejected.
func verifyOverride(meta map[string]any, trusted []string) (*identity.VCClaims, string) {
	raw, ok := meta["operator_override"]
	if !ok {
		return nil, ""
	}
	token, ok := raw.(string)
	if !ok || token == "" {
		return nil, "operator override present but not a string token"
	}
	claims, err := identity.VerifyVC(token, identity.DIDKeyResolver{})
	if err != nil {
		return nil, "operator override rejected: " + err.Error()
	}
	if !containsString(trusted, claims.Iss) {
		return nil, "operator override issuer not trusted: " + claims.Iss
	}
	return claims, ""
}

// containsString reports whether s contains v.
func containsString(s []string, v string) bool {
	for _, e := range s {
		if e == v {
			return true
		}
	}
	return false
}

// stringsToAny widens a []string to []any for Rego input documents.
func stringsToAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// scanArgStrings walks a decoded JSON argument value, invoking fn on every
// string it finds (recursing through objects and arrays).
func scanArgStrings(v any, fn func(string)) {
	switch t := v.(type) {
	case string:
		fn(t)
	case []any:
		for _, e := range t {
			scanArgStrings(e, fn)
		}
	case map[string]any:
		for _, e := range t {
			scanArgStrings(e, fn)
		}
	}
}

// decomposeToolArgs maps an MCP tool's arguments onto shell commands for
// policy decomposition: an explicit policy.shellTools declaration wins;
// otherwise the default heuristic treats an argument object with a string
// "binary" field (plus optional "extra_args" array) as a shell command —
// the sift-mcp run_command contract. Non-matching tools return nil.
func decomposeToolArgs(sp *serverPolicy, toolName string, raw json.RawMessage) []Parsed {
	var argMap map[string]any
	if err := json.Unmarshal(raw, &argMap); err != nil || argMap == nil {
		return nil
	}

	if spec, ok := sp.shellTools[toolName]; ok {
		if spec.CommandArg != "" {
			line, _ := argMap[spec.CommandArg].(string)
			if line == "" {
				return nil
			}
			return DecomposeShellLine(line, sp.outputFlags)
		}
		binaryArg := spec.BinaryArg
		if binaryArg == "" {
			binaryArg = "binary"
		}
		argsArg := spec.ArgsArg
		if argsArg == "" {
			argsArg = "extra_args"
		}
		return decomposeStructuredArgs(argMap, binaryArg, argsArg, sp.outputFlags)
	}

	// Default heuristic: the sift-mcp run_command shape.
	return decomposeStructuredArgs(argMap, "binary", "extra_args", sp.outputFlags)
}

func decomposeStructuredArgs(argMap map[string]any, binaryArg, argsArg string, outputFlags []string) []Parsed {
	binary, _ := argMap[binaryArg].(string)
	if binary == "" {
		return nil
	}
	command := []string{binary}
	if extra, ok := argMap[argsArg].([]any); ok {
		for _, a := range extra {
			if s, ok := a.(string); ok {
				command = append(command, s)
			}
		}
	}
	// Normalize transparent wrappers / interpreters so a structured
	// run_command cannot launder a blocked effective executable behind e.g.
	// `timeout python3 -c ...`, matching the shell-line path.
	ps := decomposeWrapped(command, outputFlags, strings.Join(command, " "), 0)
	for i := range ps {
		ps[i].Via = "structured"
	}
	return ps
}

// policyContext builds the runtime context for the policy input document
// (SPEC §5): active case dir, cwd, examiner identity, correlation ID.
func policyContext(corrID string) map[string]any {
	cwd, _ := os.Getwd()
	examiner := os.Getenv("VHIR_EXAMINER")
	if examiner == "" {
		examiner = os.Getenv("VHIR_ANALYST")
	}
	if examiner == "" {
		examiner = os.Getenv("USER")
	}
	return map[string]any{
		"case_dir":      os.Getenv("VHIR_CASE_DIR"),
		"cwd":           cwd,
		"examiner":      examiner,
		"correlationId": corrID,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}
}

// rawArgsValue decodes the raw arguments for the policy input's `args`
// field (generic JSON; empty object when absent).
func rawArgsValue(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil || v == nil {
		return map[string]any{}
	}
	return v
}

// deprefixReasons strips the "sift.<pkg>: " prefixes for the
// client-facing denial text (SPEC §6 example); audit keeps the prefixed
// forms.
func deprefixReasons(reasons []string) []string {
	out := make([]string, len(reasons))
	for i, r := range reasons {
		if strings.HasPrefix(r, "sift.") {
			if _, rest, ok := strings.Cut(r, ": "); ok {
				out[i] = rest
				continue
			}
		}
		out[i] = r
	}
	return out
}

// commandSummary renders the audited command: the decomposed command line
// when the tool is shell-like (SPEC §7.1 shows "find /evidence -name
// *.evtx"), the compact raw JSON otherwise.
func commandSummary(parsedList []Parsed, raw json.RawMessage) string {
	const maxLen = 512
	if len(parsedList) > 0 && parsedList[0].Binary != "" {
		p := parsedList[0]
		var s string
		if p.Via == "structured" {
			s = strings.Join(append([]string{p.Binary}, p.Args...), " ")
		} else if len(p.Args) > 0 {
			// shell/fallback segments carry the original raw line last.
			s = p.Args[len(p.Args)-1]
		}
		if len(s) > maxLen {
			s = s[:maxLen] + "…"
		}
		if s != "" {
			return s
		}
	}
	return argsSummary(raw)
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
