package mcpproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
)

// newFixtureServer builds an in-process MCP server with one echo tool, one
// resource, and one prompt — the shared backend fixture for proxy tests.
func newFixtureServer(name string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: name, Version: "0.0.1"}, nil)

	srv.AddTool(&mcp.Tool{
		Name:        "echo",
		Description: "echoes its arguments",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "echo:" + string(req.Params.Arguments)}},
		}, nil
	})

	srv.AddResource(&mcp.Resource{
		URI:      "test://doc",
		Name:     "doc",
		MIMEType: "text/plain",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/plain", Text: "hello from " + name}},
		}, nil
	})

	srv.AddPrompt(&mcp.Prompt{Name: "greet"}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Messages: []*mcp.PromptMessage{{
				Role:    "user",
				Content: &mcp.TextContent{Text: "greetings from " + name},
			}},
		}, nil
	})

	return srv
}

// startBackendHTTP serves a fixture MCP server over Streamable HTTP and
// returns its URL (the test "remote" endpoint).
func startBackendHTTP(t *testing.T, srv *mcp.Server) string {
	t.Helper()
	hs := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	t.Cleanup(hs.Close)
	return hs.URL
}

// remoteCfg builds an agent config with remote-type MCP entries.
func remoteCfg(servers map[string]config.MCPToolConfig) *config.AgentContainer {
	return &config.AgentContainer{
		Name:  "test",
		Image: "alpine:3",
		Agent: &config.AgentConfig{
			Tools: &config.ToolsConfig{MCP: servers},
		},
	}
}

// newTestProxy builds a proxy over the given config with a temp audit dir.
func newTestProxy(t *testing.T, cfg *config.AgentContainer, deps Deps) *Proxy {
	t.Helper()
	if deps.Logger == nil {
		deps.Logger = zaptest.NewLogger(t)
	}
	p, err := New(t.Context(), deps, cfg, "testsess01", &Options{AuditDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(context.Background()) })
	return p
}

// connectClient connects an MCP client to the proxy's HTTP handler.
func connectClient(t *testing.T, p *Proxy) *mcp.ClientSession {
	t.Helper()
	hs := httptest.NewServer(p.Handler())
	t.Cleanup(hs.Close)
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := c.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: hs.URL}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func listToolNames(t *testing.T, session *mcp.ClientSession) []string {
	t.Helper()
	var names []string
	for tool, err := range session.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatalf("listing tools: %v", err)
		}
		names = append(names, tool.Name)
	}
	return names
}

func TestProxyEndToEnd_Remote(t *testing.T) {
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: url},
	})
	p := newTestProxy(t, cfg, Deps{})
	session := connectClient(t, p)

	// tools/list aggregates the backend's tools.
	names := listToolNames(t, session)
	if len(names) != 1 || names[0] != "echo" {
		t.Fatalf("tools = %v, want [echo]", names)
	}

	// tools/call round-trips through the proxy.
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"msg": "hi"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(res.Content))
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, `"msg":"hi"`) {
		t.Errorf("tool result = %q, want echoed args", text)
	}

	// The audit trail has one allow entry with proxy-only enforcement and
	// a valid hash chain.
	entries, err := audit.ReadLog(p.AuditPath())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.EventType != audit.EventToolCall {
		t.Errorf("eventType = %q, want tool_call", e.EventType)
	}
	if e.Verdict != audit.VerdictAllow {
		t.Errorf("verdict = %q, want allow", e.Verdict)
	}
	if e.Actor.Type != "tool" || e.Actor.Name != "backend-a" {
		t.Errorf("actor = %+v, want {tool backend-a}", e.Actor)
	}
	if cid, _ := e.Metadata["correlationId"].(string); cid == "" {
		t.Error("metadata.correlationId is empty")
	}
	if enf, _ := e.Metadata["enforcement"].(string); enf != "proxy-only" {
		t.Errorf("metadata.enforcement = %v, want proxy-only", e.Metadata["enforcement"])
	}
	if _, ok := e.Metadata["latencyMs"].(float64); !ok {
		t.Errorf("metadata.latencyMs = %#v, want number", e.Metadata["latencyMs"])
	}
	if reasons, ok := e.Metadata["reasons"].([]any); !ok || len(reasons) != 0 {
		t.Errorf("metadata.reasons = %#v, want []", e.Metadata["reasons"])
	}
	if err := audit.ValidateChain(entries); err != nil {
		t.Errorf("ValidateChain: %v", err)
	}
}

func TestProxyAllowedToolsFiltering(t *testing.T) {
	srv := newFixtureServer("backend-a")
	srv.AddTool(&mcp.Tool{
		Name:        "secret_tool",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "secret"}}}, nil
	})
	url := startBackendHTTP(t, srv)

	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {
			Type: "remote",
			URL:  url,
			Policy: &config.MCPServerPolicy{
				AllowedTools: []string{"echo"},
			},
		},
	})
	p := newTestProxy(t, cfg, Deps{})
	session := connectClient(t, p)

	names := listToolNames(t, session)
	if len(names) != 1 || names[0] != "echo" {
		t.Fatalf("tools = %v, want [echo] (secret_tool filtered)", names)
	}

	// A call to the filtered tool fails: it is not registered on the proxy.
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "secret_tool"})
	if err == nil && (res == nil || !res.IsError) {
		t.Error("expected calling filtered tool to fail")
	}
}

func TestProxyToolCollision(t *testing.T) {
	urlA := startBackendHTTP(t, newFixtureServer("backend-a"))
	urlB := startBackendHTTP(t, newFixtureServer("backend-b"))
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: urlA},
		"backend-b": {Type: "remote", URL: urlB},
	})

	_, err := New(t.Context(), Deps{Logger: zaptest.NewLogger(t)}, cfg, "collsess01", &Options{AuditDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected tool name collision error")
	}
	if !strings.Contains(err.Error(), "collision") || !strings.Contains(err.Error(), "echo") {
		t.Errorf("error = %v, want tool name collision mentioning echo", err)
	}
}

func TestProxyResourcesPassthrough(t *testing.T) {
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: url},
	})
	p := newTestProxy(t, cfg, Deps{})
	session := connectClient(t, p)

	// resources/list shows the backend's resource.
	var uris []string
	for res, err := range session.Resources(t.Context(), nil) {
		if err != nil {
			t.Fatalf("listing resources: %v", err)
		}
		uris = append(uris, res.URI)
	}
	if len(uris) != 1 || uris[0] != "test://doc" {
		t.Fatalf("resources = %v, want [test://doc]", uris)
	}

	// resources/read relays to the backend.
	rr, err := session.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "test://doc"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(rr.Contents) != 1 || rr.Contents[0].Text != "hello from backend-a" {
		t.Fatalf("resource contents = %+v, want hello from backend-a", rr.Contents)
	}
}

func TestProxyPromptsPassthrough(t *testing.T) {
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: url},
	})
	p := newTestProxy(t, cfg, Deps{})
	session := connectClient(t, p)

	var names []string
	for prompt, err := range session.Prompts(t.Context(), nil) {
		if err != nil {
			t.Fatalf("listing prompts: %v", err)
		}
		names = append(names, prompt.Name)
	}
	if len(names) != 1 || names[0] != "greet" {
		t.Fatalf("prompts = %v, want [greet]", names)
	}

	gp, err := session.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "greet"})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(gp.Messages) != 1 {
		t.Fatalf("expected 1 prompt message, got %d", len(gp.Messages))
	}
	if text := gp.Messages[0].Content.(*mcp.TextContent).Text; text != "greetings from backend-a" {
		t.Errorf("prompt text = %q", text)
	}
}

func TestProxyToolListChangedReaggregation(t *testing.T) {
	srv := newFixtureServer("backend-a")
	url := startBackendHTTP(t, srv)
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: url},
	})
	p := newTestProxy(t, cfg, Deps{})
	session := connectClient(t, p)

	// Adding a tool on the backend emits tools/list_changed; the proxy
	// re-aggregates and exposes it.
	srv.AddTool(&mcp.Tool{
		Name:        "late_tool",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "late"}}}, nil
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		names := listToolNames(t, session)
		if len(names) == 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tools = %v after list_changed, want [echo late_tool]", names)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestProxySerializesToolCallsPerBackendByDefault(t *testing.T) {
	var mu sync.Mutex
	active := 0
	maxActive := 0

	srv := mcp.NewServer(&mcp.Implementation{Name: "slow-backend", Version: "0.0.1"}, nil)
	srv.AddTool(&mcp.Tool{Name: "slow", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		time.Sleep(75 * time.Millisecond)

		mu.Lock()
		active--
		mu.Unlock()
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	})

	url := startBackendHTTP(t, srv)
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: url},
	})
	p := newTestProxy(t, cfg, Deps{})
	session := connectClient(t, p)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "slow"}); err != nil {
				t.Errorf("CallTool: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if maxActive != 1 {
		t.Fatalf("max concurrent backend calls = %d, want 1", maxActive)
	}
}

func TestMaxConcurrentToolsResolution(t *testing.T) {
	if got := maxConcurrentTools(nil, nil); got != 1 {
		t.Fatalf("default maxConcurrentTools = %d, want 1", got)
	}
	cfg := &config.AgentContainer{Agent: &config.AgentConfig{Policy: &config.PolicyConfig{MaxConcurrentTools: 3}}}
	if got := maxConcurrentTools(cfg, nil); got != 3 {
		t.Fatalf("agent maxConcurrentTools = %d, want 3", got)
	}
	if got := maxConcurrentTools(cfg, &config.MCPServerPolicy{MaxConcurrentTools: 2}); got != 2 {
		t.Fatalf("server maxConcurrentTools = %d, want 2", got)
	}
}

// fakeEnforcer implements the component-hosting RPCs over bufconn.
type fakeEnforcer struct {
	enforcerapi.UnimplementedEnforcerServer
}

func (f *fakeEnforcer) ListTools(ctx context.Context, req *enforcerapi.ListToolsRequest) (*enforcerapi.ListToolsResponse, error) {
	return &enforcerapi.ListToolsResponse{
		Tools: []*enforcerapi.ToolDefinition{{
			ComponentName:   req.ComponentName,
			ToolName:        "search_sigma",
			Description:     "search sigma rules",
			InputSchemaJson: `{"type":"object"}`,
		}},
	}, nil
}

func (f *fakeEnforcer) CallTool(ctx context.Context, req *enforcerapi.CallToolRequest) (*enforcerapi.CallToolResponse, error) {
	if req.ToolName != "search_sigma" {
		return &enforcerapi.CallToolResponse{Success: false, Error: "unknown tool"}, nil
	}
	return &enforcerapi.CallToolResponse{
		Success:    true,
		ResultJson: fmt.Sprintf(`{"component":%q,"args":%s}`, req.ComponentName, req.ArgumentsJson),
	}, nil
}

func newFakeEnforcerClient(t *testing.T) enforcerapi.EnforcerClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	enforcerapi.RegisterEnforcerServer(srv, &fakeEnforcer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("bufconn dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return enforcerapi.NewEnforcerClient(conn)
}

func TestProxyComponentBackend(t *testing.T) {
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"sigma-lookup": {Type: "component", Image: "ghcr.io/x/sigma:1"},
	})
	p := newTestProxy(t, cfg, Deps{Enforcer: newFakeEnforcerClient(t)})
	session := connectClient(t, p)

	names := listToolNames(t, session)
	if len(names) != 1 || names[0] != "search_sigma" {
		t.Fatalf("tools = %v, want [search_sigma]", names)
	}

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "search_sigma",
		Arguments: map[string]any{"q": "mimikatz"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, `"component":"sigma-lookup"`) || !strings.Contains(text, "mimikatz") {
		t.Errorf("component result = %q", text)
	}

	// Component tool calls are audited like any other.
	entries, err := audit.ReadLog(p.AuditPath())
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(entries) != 1 || entries[0].Actor.Name != "sigma-lookup" {
		t.Fatalf("expected 1 audit entry for sigma-lookup, got %+v", entries)
	}
}

func TestProxyJSONLShape(t *testing.T) {
	// The proxy.jsonl lines must parse as generic JSON with the SPEC §7.1
	// camelCase fields (what DuckDB read_json_auto sees).
	url := startBackendHTTP(t, newFixtureServer("backend-a"))
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: url},
	})
	p := newTestProxy(t, cfg, Deps{})
	session := connectClient(t, p)

	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	raw, err := readFirstLine(p.AuditPath())
	if err != nil {
		t.Fatalf("reading audit file: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("audit line is not valid JSON: %v", err)
	}
	for _, key := range []string{"timestamp", "sessionId", "sequence", "eventType", "actor", "verdict", "command", "metadata", "prevHash", "entryHash"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("audit line missing %q", key)
		}
	}
	meta, _ := doc["metadata"].(map[string]any)
	for _, key := range []string{"correlationId", "tool", "argsSummary", "reasons", "policiesEvaluated", "approvalRequired", "latencyMs"} {
		if _, ok := meta[key]; !ok {
			t.Errorf("metadata missing %q", key)
		}
	}
	if actor, _ := doc["actor"].(map[string]any); actor["type"] != "tool" {
		t.Errorf("actor.type = %v, want tool", actor["type"])
	}
}

func readFirstLine(path string) ([]byte, error) {
	entries, err := audit.ReadLog(path)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries in %s", path)
	}
	return json.Marshal(entries[0])
}

func TestToolAllowed(t *testing.T) {
	if !toolAllowed(nil, "anything") {
		t.Error("nil policy must allow")
	}
	if !toolAllowed(&config.MCPServerPolicy{}, "anything") {
		t.Error("empty allowedTools must allow")
	}
	p := &config.MCPServerPolicy{AllowedTools: []string{"a", "b"}}
	if !toolAllowed(p, "a") || toolAllowed(p, "c") {
		t.Error("allowedTools membership check failed")
	}
}

func TestArgsSummary(t *testing.T) {
	if got := argsSummary(json.RawMessage(`{"a": 1,
		"b": "two"}`)); got != `{"a": 1, "b": "two"}` {
		t.Errorf("argsSummary = %q", got)
	}
	long := json.RawMessage(`{"x":"` + strings.Repeat("y", 1000) + `"}`)
	if got := argsSummary(long); len(got) > 520 {
		t.Errorf("argsSummary not truncated: %d chars", len(got))
	}
}
