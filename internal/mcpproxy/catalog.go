package mcpproxy

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// catalogVersion tracks the ai-catalog.json shape this proxy emits. Bump on
// breaking changes to the document structure.
const catalogVersion = "0.2.0"

// Catalog is the ARD (Agentic Resource Discovery) capability document served
// at /.well-known/ai-catalog.json. It describes the proxy's *enforced* tool
// surface — only tools the policy admits are listed — with trust metadata an
// external consumer can use without trusting the agent.
type Catalog struct {
	CatalogVersion string              `json:"catalog_version"`
	Publisher      CatalogPublisher    `json:"publisher"`
	Capabilities   []CatalogCapability `json:"capabilities"`
}

// CatalogPublisher identifies the deployment and its trust posture.
type CatalogPublisher struct {
	Name string `json:"name"`
	// DID is the publisher's did:key (G1), self-certifying so a consumer can
	// verify the trust manifest's Credential with no truststore. Empty when
	// the instance runs without a configured identity.
	DID           string               `json:"did,omitempty"`
	TrustManifest CatalogTrustManifest `json:"trust_manifest"`
}

// CatalogTrustManifest carries deployment-wide enforcement claims.
type CatalogTrustManifest struct {
	// EnforcementModel lists the active enforcement layers, e.g.
	// ["cedar_proxy", "ebpf_kernel"].
	EnforcementModel []string `json:"enforcement_model"`
	// AuditChain names the audit mechanism (the proxy keeps independent
	// hash-chained trails).
	AuditChain string `json:"audit_chain"`
	// Credential is the publisher's enforcement verifiable credential (G1),
	// an EdDSA JWT signed by the publisher DID. Empty when no identity is
	// configured.
	Credential string `json:"credential,omitempty"`
}

// CatalogCapability is one published tool.
type CatalogCapability struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"` // "<backend>/<tool>"
	Description string          `json:"description,omitempty"`
	Protocol    string          `json:"protocol"`           // always "mcp"
	Endpoint    string          `json:"endpoint,omitempty"` // public MCP endpoint, if configured
	InputSchema any             `json:"input_schema,omitempty"`
	Trust       CatalogCapTrust `json:"trust"`
}

// CatalogCapTrust is the per-capability trust block.
type CatalogCapTrust struct {
	// Enforcement is the backend's enforcement posture (from
	// Backend.Enforcement()); "kernel" when an enforcer-correlated
	// container backs it, else the posture string or "proxy".
	Enforcement string `json:"enforcement"`
	// PolicyHash is the sha256 of the compiled policy governing this tool,
	// or "" when the server declares no evaluated policy.
	PolicyHash string `json:"policy_hash,omitempty"`
}

// buildCatalog snapshots the currently-aggregated tool surface into an ARD
// catalog. Only allowed tools are present (catalogTools holds the post
// allowedTools-filter set). Capabilities are sorted by name for a stable,
// diffable document.
func (p *Proxy) buildCatalog() Catalog {
	p.mu.Lock()
	defer p.mu.Unlock()

	enforcerActive := p.deps.Enforcer != nil
	publisher := p.publisherName
	if publisher == "" {
		publisher = "agentcontainers"
	}
	var publisherDID string
	if p.identity != nil {
		publisherDID = p.identity.DID()
	}
	enforcement := []string{"cedar_proxy"}
	if enforcerActive {
		enforcement = append(enforcement, "ebpf_kernel")
	}

	caps := make([]CatalogCapability, 0, len(p.catalogTools))
	for name, tool := range p.catalogTools {
		b := p.toolRoutes[name]
		if b == nil {
			continue
		}
		var policyHash string
		if sp := p.policies[b.Name]; sp != nil {
			policyHash = sp.policyHash
		}
		caps = append(caps, CatalogCapability{
			ID:          "urn:agentcontainers:" + p.sessionID + ":" + b.Name + ":" + name,
			Name:        b.Name + "/" + name,
			Description: toolDescription(tool),
			Protocol:    "mcp",
			Endpoint:    p.publicEndpoint,
			InputSchema: toolInputSchema(tool),
			Trust: CatalogCapTrust{
				Enforcement: capabilityEnforcement(b, enforcerActive),
				PolicyHash:  policyHash,
			},
		})
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i].Name < caps[j].Name })

	return Catalog{
		CatalogVersion: catalogVersion,
		Publisher: CatalogPublisher{
			Name: publisher,
			DID:  publisherDID,
			TrustManifest: CatalogTrustManifest{
				EnforcementModel: enforcement,
				AuditChain:       "independent_sha256_hash_chains",
				// Credential is the instance's enforcement VC (G1), signed by
				// publisherDID. A consumer verifies it with VerifyVC against
				// the self-certifying did:key — no truststore needed. Empty
				// when no identity is configured.
				Credential: p.publisherVC,
			},
		},
		Capabilities: caps,
	}
}

// capabilityEnforcement reports the per-capability enforcement posture. A
// container backend with an active enforcer is kernel-enforced; otherwise we
// surface the backend's own posture string, defaulting to "proxy".
func capabilityEnforcement(b *Backend, enforcerActive bool) string {
	if b.ContainerID != "" && enforcerActive {
		return "kernel"
	}
	if posture := b.Enforcement(); posture != "" {
		return posture
	}
	return "proxy"
}

func toolDescription(t *mcp.Tool) string {
	if t == nil {
		return ""
	}
	return t.Description
}

func toolInputSchema(t *mcp.Tool) any {
	if t == nil {
		return nil
	}
	return t.InputSchema
}

// CatalogHandler serves the ARD catalog as JSON. GET only.
func (p *Proxy) CatalogHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cat := p.buildCatalog()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(cat); err != nil {
			p.deps.Logger.Error("catalog: encoding ai-catalog.json failed")
		}
	})
}

// HTTPHandler returns the client-facing HTTP handler: the ARD catalog at
// /.well-known/ai-catalog.json, with the MCP Streamable HTTP handler serving
// everything else. Use this (not Handler) when standing up the listener so
// discovery and tool traffic share one port.
func (p *Proxy) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/.well-known/ai-catalog.json", p.CatalogHandler())
	mux.Handle("/", p.Handler())
	return mux
}
