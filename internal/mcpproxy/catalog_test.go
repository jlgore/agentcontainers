package mcpproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.uber.org/zap/zaptest"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/identity"
)

// fetchCatalog GETs the proxy's ai-catalog.json through its HTTP handler and
// decodes it.
func fetchCatalog(t *testing.T, p *Proxy) Catalog {
	t.Helper()
	hs := httptest.NewServer(p.HTTPHandler())
	t.Cleanup(hs.Close)

	resp, err := http.Get(hs.URL + "/.well-known/ai-catalog.json")
	if err != nil {
		t.Fatalf("GET catalog: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("catalog status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var cat Catalog
	if err := json.NewDecoder(resp.Body).Decode(&cat); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	return cat
}

func capByName(cat Catalog, name string) (CatalogCapability, bool) {
	for _, c := range cat.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return CatalogCapability{}, false
}

// The catalog publishes exactly the policy-allowed tool surface: a tool
// filtered out by allowedTools must not appear.
func TestCatalogListsAllowedToolsOnly(t *testing.T) {
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
			Type:   "remote",
			URL:    url,
			Policy: &config.MCPServerPolicy{AllowedTools: []string{"echo"}},
		},
	})
	p := newTestProxy(t, cfg, Deps{})

	cat := fetchCatalog(t, p)

	if cat.CatalogVersion != catalogVersion {
		t.Errorf("catalog_version = %q, want %q", cat.CatalogVersion, catalogVersion)
	}
	if _, ok := capByName(cat, "backend-a/secret_tool"); ok {
		t.Error("secret_tool published despite allowedTools filter")
	}
	echo, ok := capByName(cat, "backend-a/echo")
	if !ok {
		t.Fatalf("echo capability missing; capabilities = %+v", cat.Capabilities)
	}
	if echo.Protocol != "mcp" {
		t.Errorf("protocol = %q, want mcp", echo.Protocol)
	}
	if echo.Description != "echoes its arguments" {
		t.Errorf("description = %q, want the backend's tool description", echo.Description)
	}
	if !strings.HasPrefix(echo.ID, "urn:agentcontainers:") {
		t.Errorf("id = %q, want urn:agentcontainers prefix", echo.ID)
	}
	// No enforcer in this test → cedar_proxy model only; a remote backend is
	// proxy-only at the capability level.
	if got := cat.Publisher.TrustManifest.EnforcementModel; len(got) != 1 || got[0] != "cedar_proxy" {
		t.Errorf("enforcement_model = %v, want [cedar_proxy]", got)
	}
	if echo.Trust.Enforcement != "proxy-only" {
		t.Errorf("capability enforcement = %q, want proxy-only (remote backend)", echo.Trust.Enforcement)
	}
}

// A server with a compiled security policy surfaces a stable, non-empty
// policy_hash in the catalog.
func TestCatalogPublishesPolicyHash(t *testing.T) {
	p, _ := policyTestProxy(t)
	cat := fetchCatalog(t, p)

	cap, ok := capByName(cat, "sift-gateway/run_command")
	if !ok {
		t.Fatalf("run_command capability missing; capabilities = %+v", cat.Capabilities)
	}
	if !strings.HasPrefix(cap.Trust.PolicyHash, "sha256:") {
		t.Errorf("policy_hash = %q, want sha256: prefix", cap.Trust.PolicyHash)
	}

	// Stable across a second fetch.
	if again, _ := capByName(fetchCatalog(t, p), "sift-gateway/run_command"); again.Trust.PolicyHash != cap.Trust.PolicyHash {
		t.Errorf("policy_hash unstable: %q != %q", again.Trust.PolicyHash, cap.Trust.PolicyHash)
	}
}

// With an identity configured, the catalog publishes the publisher DID and a
// verifiable enforcement credential that resolves and verifies against the
// self-certifying did:key (G1).
func TestCatalogPublishesPublisherCredential(t *testing.T) {
	ks, err := identity.LoadOrCreateKeyStore(filepath.Join(t.TempDir(), "id.pem"))
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: startBackendHTTP(t, newFixtureServer("backend-a"))},
	})
	p, err := New(t.Context(), Deps{Logger: zaptest.NewLogger(t)}, cfg, "idsess01",
		&Options{AuditDir: t.TempDir(), Identity: ks})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close(context.Background()) })

	cat := fetchCatalog(t, p)
	if cat.Publisher.DID != ks.DID() {
		t.Errorf("publisher.did = %q, want %q", cat.Publisher.DID, ks.DID())
	}
	cred := cat.Publisher.TrustManifest.Credential
	if cred == "" {
		t.Fatal("publisher credential is empty")
	}
	claims, err := identity.VerifyVC(cred, identity.DIDKeyResolver{})
	if err != nil {
		t.Fatalf("verify publisher VC: %v", err)
	}
	if claims.Iss != ks.DID() {
		t.Errorf("VC iss = %q, want %q", claims.Iss, ks.DID())
	}
	if len(claims.EnforcementModel) == 0 || claims.EnforcementModel[0] != "cedar_proxy" {
		t.Errorf("VC enforcement_model = %v, want [cedar_proxy ...]", claims.EnforcementModel)
	}
}

// Non-GET methods are rejected.
func TestCatalogRejectsNonGET(t *testing.T) {
	cfg := remoteCfg(map[string]config.MCPToolConfig{
		"backend-a": {Type: "remote", URL: startBackendHTTP(t, newFixtureServer("backend-a"))},
	})
	p := newTestProxy(t, cfg, Deps{})
	hs := httptest.NewServer(p.HTTPHandler())
	t.Cleanup(hs.Close)

	resp, err := http.Post(hs.URL+"/.well-known/ai-catalog.json", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", resp.StatusCode)
	}
}
