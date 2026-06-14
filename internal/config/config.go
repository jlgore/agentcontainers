// Package config defines the agentcontainer.json schema types and configuration loader.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

// Resolution order for finding configuration files.
var configPaths = []string{
	"agentcontainer.json",
	".devcontainer/agentcontainer.json",
	".devcontainer/devcontainer.json",
}

// AgentContainer represents the agentcontainer.json configuration.
// It is a strict superset of devcontainer.json — any valid devcontainer.json
// is a valid agentcontainer.json with agent capabilities set to default-deny.
type AgentContainer struct {
	// Standard devcontainer fields.
	Name     string         `json:"name,omitempty"`
	Image    string         `json:"image,omitempty"`
	Build    *BuildConfig   `json:"build,omitempty"`
	Features map[string]any `json:"features,omitempty"`
	Mounts   []string       `json:"mounts,omitempty"`

	// Extends is the path to a base agentcontainer.json (relative to this
	// file's directory) that this config inherits from. The base is loaded
	// first, then this config is merged over it: scalars and slices in the
	// child replace those in the base; nested objects merge field by field.
	Extends string `json:"extends,omitempty"`

	// Agent-specific extensions.
	Agent *AgentConfig `json:"agent,omitempty"`

	// unknownFields holds dotted paths of keys present in the source document
	// that do not map to any schema field. Populated at parse time and
	// surfaced by Validate(). Not serialized.
	unknownFields []string
}

// BuildConfig holds container build settings.
type BuildConfig struct {
	Dockerfile string            `json:"dockerfile,omitempty"`
	Context    string            `json:"context,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
}

// AgentConfig holds all agent-specific configuration under the "agent" key.
type AgentConfig struct {
	// OrgPolicy is an OCI reference to a published org policy artifact. When
	// set (and no --org-policy flag overrides it), the policy is extracted and
	// merged into this config at runtime. Deny always wins.
	OrgPolicy    string                  `json:"orgPolicy,omitempty"`
	Capabilities *Capabilities           `json:"capabilities,omitempty"`
	Tools        *ToolsConfig            `json:"tools,omitempty"`
	Secrets      map[string]SecretConfig `json:"secrets,omitempty"`
	Policy       *PolicyConfig           `json:"policy,omitempty"`
	Provenance   *ProvenanceConfig       `json:"provenance,omitempty"`
	Enforcer     *EnforcerConfig         `json:"enforcer,omitempty"`
}

// EnforcerConfig controls sidecar discovery and lifecycle behavior.
type EnforcerConfig struct {
	// Image is the OCI reference for the agentcontainer-enforcer container.
	// Default: "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:latest"
	Image string `json:"image,omitempty"`

	// Required causes agentcontainer run to fail if the sidecar cannot start or is
	// unreachable. Default: true (fail-closed). Set to false only for
	// local development where enforcement is explicitly not needed.
	Required *bool `json:"required,omitempty"`

	// Addr is the gRPC address of a pre-existing sidecar. When set,
	// auto-start is skipped entirely. Overridden by AC_ENFORCER_ADDR env var.
	// Example: "127.0.0.1:50051" or "unix:///run/agentcontainer-enforcer.sock"
	Addr string `json:"addr,omitempty"`

	// InsecureDev disables mutual TLS on the enforcer control plane, allowing a
	// plaintext gRPC connection. It is a development-only opt-in: managed
	// sidecars otherwise run ephemeral mTLS, and a non-loopback plaintext
	// endpoint is rejected without this flag. A prominent warning is logged
	// whenever it takes effect. Default: false (mTLS required).
	InsecureDev bool `json:"insecureDev,omitempty"`
}

// Capabilities declares what the agent is allowed to do.
type Capabilities struct {
	Filesystem *FilesystemCaps `json:"filesystem,omitempty"`
	Network    *NetworkCaps    `json:"network,omitempty"`
	Shell      *ShellCaps      `json:"shell,omitempty"`
	Git        *GitCaps        `json:"git,omitempty"`
}

// FilesystemCaps controls file access.
type FilesystemCaps struct {
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// NetworkCaps controls network access.
type NetworkCaps struct {
	Egress []EgressRule `json:"egress,omitempty"`
	Deny   []string     `json:"deny,omitempty"`
}

// EgressRule defines an allowed outbound connection.
type EgressRule struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// ShellCaps controls which shell commands the agent can execute.
type ShellCaps struct {
	Commands []ShellCommand `json:"commands,omitempty"`
}

// ShellCommand defines a permitted binary with optional subcommand and argument restrictions.
//
// Supports a string shorthand for convenience:
//
//	"whoami"         → {"binary": "whoami"}
//	"npm test"       → {"binary": "npm", "subcommands": ["test"]}
//	"npm run build"  → {"binary": "npm", "subcommands": ["run", "build"]}
type ShellCommand struct {
	Binary           string   `json:"binary"`
	Subcommands      []string `json:"subcommands,omitempty"`
	Args             []string `json:"args,omitempty"`
	DenyArgs         []string `json:"denyArgs,omitempty"`
	DenyEnv          []string `json:"denyEnv,omitempty"`
	ScriptValidation string   `json:"scriptValidation,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling so that ShellCommand accepts
// either a JSON string (shorthand) or a full JSON object.
func (sc *ShellCommand) UnmarshalJSON(data []byte) error {
	// Try string first.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("shell command string must not be empty")
		}
		parts := strings.Fields(s)
		sc.Binary = parts[0]
		if len(parts) > 1 {
			sc.Subcommands = parts[1:]
		}
		return nil
	}

	// Fall back to object form. Use an alias to avoid infinite recursion.
	type shellCommandAlias ShellCommand
	var alias shellCommandAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*sc = ShellCommand(alias)
	return nil
}

// GitCaps controls git operations.
type GitCaps struct {
	Operations []string    `json:"operations,omitempty"`
	Branches   *BranchCaps `json:"branches,omitempty"`
}

// BranchCaps controls which branches the agent can push to.
type BranchCaps struct {
	Push []string `json:"push,omitempty"`
	Deny []string `json:"deny,omitempty"`
}

// ToolsConfig declares MCP servers and skills available to the agent.
type ToolsConfig struct {
	MCP    map[string]MCPToolConfig `json:"mcp,omitempty"`
	Skills map[string]SkillConfig   `json:"skills,omitempty"`
}

// MCPToolConfig is the JSON wire shape for an MCP server tool. It is a flat
// superset of every type's fields; which fields are legal depends on Type.
//
// Validation is type-driven and falls out of resolution: Resolve maps the
// wire struct onto a typed accessor view (ContainerTool, ComponentTool, or
// RemoteTool) that exposes only the fields legal for that type, returning an
// error for every field that is set but not permitted. Remote servers must
// not declare enforcement the runtime cannot deliver — kernel-class policy
// fields are validation errors on remote, not silent no-ops.
type MCPToolConfig struct {
	// Type is the tool hosting model: "container" (default), "component"
	// (WASM Component), or "remote" (URL endpoint, no container lifecycle,
	// proxy-only enforcement). When empty, "container" is assumed.
	Type string `json:"type,omitempty"`

	// Image is the OCI reference. For "container" type, this is a Docker image.
	// For "component" type, this is a WASM Component OCI artifact.
	// Unused (rejected) for "remote" type.
	Image        string   `json:"image,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Secrets      []string `json:"secrets,omitempty"`
	// Mounts is only valid for container-type tools. It is rejected on component-type tools.
	Mounts []string `json:"mounts,omitempty"`

	// Limits applies resource constraints to WASM Components.
	// Only valid when Type is "component"; rejected for container-type tools.
	Limits *ComponentLimits `json:"limits,omitempty"`

	// Transport is the MCP transport for container-type tools:
	// "stdio" (default) or "http".
	Transport string `json:"transport,omitempty"`

	// Port is the container port for HTTP transport. Required when
	// transport is "http". Container type only.
	Port int `json:"port,omitempty"`

	// Path is the HTTP path of the MCP Streamable HTTP endpoint for
	// container-type tools with transport "http" (e.g. "/mcp"). Defaults to
	// "/". Only valid for container + http.
	Path string `json:"path,omitempty"`

	// URL is the endpoint of a "remote" server. Remote type only.
	URL string `json:"url,omitempty"`

	// Command overrides the container entrypoint. Container type only.
	Command []string `json:"command,omitempty"`

	// Env sets environment variables. Container type only.
	Env map[string]string `json:"env,omitempty"`

	// Policy declares per-server enforcement rules. Valid on all types;
	// which sub-fields are valid depends on type (see Resolve).
	Policy *MCPServerPolicy `json:"policy,omitempty"`
}

// MCPKind is the resolved hosting model of an MCP tool. Type "" resolves to
// KindContainer.
type MCPKind string

const (
	KindContainer MCPKind = "container"
	KindComponent MCPKind = "component"
	KindRemote    MCPKind = "remote"
)

// ResolvedTool is a discriminated, type-checked view of an MCPToolConfig.
// Exactly one of Container/Component/Remote is non-nil, selected by Kind.
// Resolve is the only constructor; a ResolvedTool therefore witnesses that
// the underlying wire struct passed type-appropriate validation.
type ResolvedTool struct {
	Name      string
	Kind      MCPKind
	Container *ContainerTool
	Component *ComponentTool
	Remote    *RemoteTool
}

// ContainerTool exposes the fields legal for a container-type MCP tool.
type ContainerTool struct {
	Image        string
	Capabilities []string
	Secrets      []string
	Mounts       []string
	Transport    string
	Port         int
	Path         string
	Command      []string
	Env          map[string]string
	Policy       *MCPServerPolicy
}

// ComponentTool exposes the fields legal for a component-type MCP tool.
type ComponentTool struct {
	Image        string
	Capabilities []string
	Secrets      []string
	Limits       *ComponentLimits
	Policy       *MCPServerPolicy
}

// RemoteTool exposes the fields legal for a remote-type MCP tool.
type RemoteTool struct {
	URL          string
	Capabilities []string
	Policy       *MCPServerPolicy
}

// MCPServerPolicy declares per-MCP-server enforcement rules evaluated by
// the MCP proxy (allowedTools, requireApproval, maxConcurrentTools) and,
// for container-type servers, kernel-enforced capabilities
// (network/filesystem/shell) plus an optional security YAML policy file.
type MCPServerPolicy struct {
	// AllowedTools filters the server's tool list; empty means all tools.
	AllowedTools []string `json:"allowedTools,omitempty"`

	// RequireApproval lists tools that pause for human confirmation.
	RequireApproval []string `json:"requireApproval,omitempty"`

	// MaxConcurrentTools serializes tool calls per server. Defaults to 1.
	// Shadows the agent-level policy.maxConcurrentTools.
	MaxConcurrentTools int `json:"maxConcurrentTools,omitempty"`

	// Network/Filesystem/Shell are kernel-class capabilities, valid only
	// on container-type servers (there is no cgroup to enforce against on
	// component or remote servers).
	Network    *NetworkCaps    `json:"network,omitempty"`
	Filesystem *FilesystemCaps `json:"filesystem,omitempty"`
	Shell      *ShellCaps      `json:"shell,omitempty"`

	// SecurityYAML is a path to a security policy file, resolved relative
	// to the config file directory. Container type only.
	SecurityYAML string `json:"securityYaml,omitempty"`

	// ShellTools declares which of the server's MCP tools take shell
	// commands as arguments, and how to map the arguments for policy
	// decomposition. Tools not declared here fall back to a heuristic: an
	// argument object with a string "binary" field (plus optional
	// "extra_args" array) is treated as a shell command.
	ShellTools map[string]ShellToolSpec `json:"shellTools,omitempty"`
}

// ShellToolSpec maps an MCP tool's arguments onto a shell command for
// policy decomposition. Either CommandArg (a single free-form command
// string) or BinaryArg/ArgsArg (pre-tokenized) — not both.
type ShellToolSpec struct {
	// BinaryArg names the argument holding the binary (default "binary").
	BinaryArg string `json:"binaryArg,omitempty"`
	// ArgsArg names the argument holding the argument array
	// (default "extra_args").
	ArgsArg string `json:"argsArg,omitempty"`
	// CommandArg names an argument holding a free-form shell command
	// string, parsed with a real shell parser.
	CommandArg string `json:"commandArg,omitempty"`
}

// ComponentLimits constrains WASM Component resource usage per tool invocation.
type ComponentLimits struct {
	// MemoryMB is the maximum linear memory the component may allocate, in mebibytes.
	// Zero means no limit.
	MemoryMB int `json:"memory_mb,omitempty"`
	// TimeoutMs is the wall-clock timeout per tool call, in milliseconds.
	// Zero means no limit.
	TimeoutMs int `json:"timeout_ms,omitempty"`
	// Fuel is the Wasmtime instruction budget per tool call (fuel units).
	// Zero means unlimited.
	Fuel int `json:"fuel,omitempty"`
}

// SkillConfig declares an agent skill.
type SkillConfig struct {
	Artifact string   `json:"artifact"`
	Trust    string   `json:"trust,omitempty"`
	Requires []string `json:"requires,omitempty"`
}

// SecretConfig declares how a secret is obtained.
type SecretConfig struct {
	Provider     string   `json:"provider"`
	Audience     string   `json:"audience,omitempty"`
	TTL          string   `json:"ttl,omitempty"`
	Rotation     string   `json:"rotation,omitempty"`
	Role         string   `json:"role,omitempty"`
	Path         string   `json:"path,omitempty"`
	Key          string   `json:"key,omitempty"`
	Mount        string   `json:"mount,omitempty"`
	Vault        string   `json:"vault,omitempty"`
	Item         string   `json:"item,omitempty"`
	Field        string   `json:"field,omitempty"`
	Scope        []string `json:"scope,omitempty"`
	AllowedTools []string `json:"allowedTools,omitempty"`
}

// PolicyConfig controls runtime behavior and escalation handling.
type PolicyConfig struct {
	Escalation            string `json:"escalation,omitempty"`
	AuditLog              bool   `json:"auditLog,omitempty"`
	SessionTimeout        string `json:"sessionTimeout,omitempty"`
	MaxConcurrentTools    int    `json:"maxConcurrentTools,omitempty"`
	OnCapabilityViolation string `json:"onCapabilityViolation,omitempty"`
}

// ProvenanceConfig declares supply chain verification requirements.
type ProvenanceConfig struct {
	Require *ProvenanceRequirements `json:"require,omitempty"`
}

// ProvenanceRequirements specifies what must be verified before a session starts.
type ProvenanceRequirements struct {
	Signatures        bool     `json:"signatures,omitempty"`
	SBOM              bool     `json:"sbom,omitempty"`
	SLSALevel         int      `json:"slsaLevel,omitempty"`
	TrustedBuilders   []string `json:"trustedBuilders,omitempty"`
	TrustedRegistries []string `json:"trustedRegistries,omitempty"`
}

// Load finds and parses the agentcontainer configuration from the given
// working directory. It follows the resolution order:
//  1. agentcontainer.json in workspace root
//  2. .devcontainer/agentcontainer.json
//  3. .devcontainer/devcontainer.json (with default-deny agent caps)
func Load(workdir string) (*AgentContainer, string, error) {
	for _, rel := range configPaths {
		path := filepath.Join(workdir, rel)
		if _, err := os.Stat(path); err == nil {
			cfg, err := parseFile(path)
			if err != nil {
				return nil, path, fmt.Errorf("parsing %s: %w", rel, err)
			}
			return cfg, path, nil
		}
	}
	return nil, "", errors.New("no agentcontainer.json or devcontainer.json found")
}

// ParseFile parses the agentcontainer.json (or devcontainer.json) at the given
// path, handling JSONC comments and trailing commas. This is the exported
// variant used when a caller has a specific config file path (e.g. via --config).
func ParseFile(path string) (*AgentContainer, error) {
	return parseFile(path)
}

func parseFile(path string) (*AgentContainer, error) {
	return parseFileDepth(path, 0)
}

// maxExtendsDepth bounds the extends inheritance chain to guard against
// cycles and pathological nesting.
const maxExtendsDepth = 16

func parseFileDepth(path string, depth int) (*AgentContainer, error) {
	if depth > maxExtendsDepth {
		return nil, fmt.Errorf("extends chain too deep (>%d); possible cycle at %s", maxExtendsDepth, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	standardized, err := hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("standardizing JSONC: %w", err)
	}

	var rawChild map[string]any
	if err := json.Unmarshal(standardized, &rawChild); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Resolve extends: load the base (relative to this file's directory),
	// then overlay this config's keys on top. The merged map is what we
	// unmarshal and validate, so unknown-field detection sees the effective
	// document.
	if ext, ok := rawChild["extends"].(string); ok && ext != "" {
		basePath := ext
		if !filepath.IsAbs(basePath) {
			basePath = filepath.Join(filepath.Dir(path), ext)
		}
		baseData, err := os.ReadFile(basePath)
		if err != nil {
			return nil, fmt.Errorf("reading extends base %q: %w", ext, err)
		}
		baseStd, err := hujson.Standardize(baseData)
		if err != nil {
			return nil, fmt.Errorf("standardizing extends base %q: %w", ext, err)
		}
		var rawBase map[string]any
		if err := json.Unmarshal(baseStd, &rawBase); err != nil {
			return nil, fmt.Errorf("unmarshaling extends base %q: %w", ext, err)
		}
		// Recurse so the base may itself extend another file (depth-bounded).
		if _, err := parseFileDepth(basePath, depth+1); err != nil {
			return nil, err
		}
		delete(rawChild, "extends")
		delete(rawBase, "extends")
		rawChild = mergeMaps(rawBase, rawChild)
	}

	merged, err := json.Marshal(rawChild)
	if err != nil {
		return nil, fmt.Errorf("re-marshaling merged config: %w", err)
	}
	return parseBytes(merged)
}

// mergeMaps overlays child onto base. Nested objects merge field by field;
// every other value (scalars, arrays) in child replaces the base value.
func mergeMaps(base, child map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(child))
	for k, v := range base {
		out[k] = v
	}
	for k, cv := range child {
		if bv, ok := out[k]; ok {
			bm, bok := bv.(map[string]any)
			cm, cok := cv.(map[string]any)
			if bok && cok {
				out[k] = mergeMaps(bm, cm)
				continue
			}
		}
		out[k] = cv
	}
	return out
}

// parseBytes standardizes JSONC source bytes and unmarshals them into an
// AgentContainer, recording any unknown fields for Validate() to surface.
func parseBytes(data []byte) (*AgentContainer, error) {
	// Standardize JSONC to plain JSON by stripping comments and trailing commas.
	// This works for both .json and .jsonc files — valid JSON passes through unchanged.
	standardized, err := hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("standardizing JSONC: %w", err)
	}

	var cfg AgentContainer
	if err := json.Unmarshal(standardized, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Detect keys present in the source that map to no schema field so they
	// surface as validation errors instead of being silently dropped.
	cfg.unknownFields = detectUnknownFields(standardized)

	return &cfg, nil
}

// detectUnknownFields decodes the standardized JSON into a generic map and
// compares it against the AgentContainer schema, returning the dotted paths of
// any keys that do not map to a known field. Unlike json.Decoder's
// DisallowUnknownFields, this collects every unknown key in a single pass
// rather than failing on the first one.
func detectUnknownFields(data []byte) []string {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var unknown []string
	walkUnknownFields("", reflect.TypeOf(AgentContainer{}), raw, &unknown)
	return unknown
}

// walkUnknownFields recursively compares a decoded JSON object against a struct
// type, appending dotted paths for keys with no matching json tag.
func walkUnknownFields(prefix string, t reflect.Type, raw map[string]any, unknown *[]string) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}

	// Build a lookup of json key -> field for this struct.
	fields := make(map[string]reflect.StructField, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		fields[name] = f
	}

	for key, val := range raw {
		f, ok := fields[key]
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if !ok {
			*unknown = append(*unknown, path)
			continue
		}
		// Recurse into nested objects when the field is a struct/pointer.
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.Struct:
			if child, ok := val.(map[string]any); ok {
				// ShellCommand accepts a string shorthand or object; skip its
				// custom-unmarshaled internals to avoid false positives.
				if ft != reflect.TypeOf(ShellCommand{}) {
					walkUnknownFields(path, ft, child, unknown)
				}
			}
		case reflect.Map:
			// map[string]T — recurse into each value against the element type.
			elem := ft.Elem()
			if child, ok := val.(map[string]any); ok {
				for k, v := range child {
					if vm, ok := v.(map[string]any); ok {
						walkUnknownFields(path+"."+k, elem, vm, unknown)
					}
				}
			}
		}
	}
}

// Validate checks the AgentContainer configuration for structural correctness.
// It collects all validation errors and returns them joined via errors.Join.
func (c *AgentContainer) Validate() error {
	var errs []error

	// Surface keys that matched no schema field (e.g. typos, or fields used in
	// examples that the loader would otherwise silently drop).
	for _, path := range c.unknownFields {
		errs = append(errs, fmt.Errorf("unknown config field %q", path))
	}

	// Image or Build must be specified, but not both.
	hasImage := c.Image != ""
	hasBuild := c.Build != nil
	if !hasImage && !hasBuild {
		errs = append(errs, errors.New("either image or build must be specified"))
	}
	if hasImage && hasBuild {
		errs = append(errs, errors.New("image and build are mutually exclusive"))
	}

	// Reject unimplemented config sections to prevent misconfiguration.
	// Users must not assume security features are enforced when they are not.
	if c.Agent != nil {
		if c.Agent.Policy != nil {
			p := c.Agent.Policy
			switch p.Escalation {
			case "", "prompt", "deny", "allow":
				// Valid values.
			default:
				errs = append(errs, fmt.Errorf("agent.policy.escalation: invalid value %q (must be prompt, deny, or allow)", p.Escalation))
			}
			if p.SessionTimeout != "" {
				if _, err := time.ParseDuration(p.SessionTimeout); err != nil {
					errs = append(errs, fmt.Errorf("agent.policy.sessionTimeout: invalid duration %q: %w", p.SessionTimeout, err))
				}
			}
			if p.MaxConcurrentTools < 0 {
				errs = append(errs, fmt.Errorf("agent.policy.maxConcurrentTools: must be >= 0, got %d", p.MaxConcurrentTools))
			}
		}
		if c.Agent.Provenance != nil && c.Agent.Provenance.Require != nil {
			req := c.Agent.Provenance.Require
			if req.SLSALevel < 0 || req.SLSALevel > 4 {
				errs = append(errs, fmt.Errorf("agent.provenance.require.slsaLevel: must be 0-4, got %d", req.SLSALevel))
			}
		}
		// Note: c.Agent.Enforcer is validated at runtime — OCI image parse
		// validation is deferred to pull time, and Addr reachability is
		// checked when the sidecar is resolved.
	}

	// Validate agent capabilities if present.
	if c.Agent != nil && c.Agent.Capabilities != nil {
		caps := c.Agent.Capabilities

		// Validate shell commands: each must have a non-empty binary.
		if caps.Shell != nil {
			for i, cmd := range caps.Shell.Commands {
				if cmd.Binary == "" {
					errs = append(errs, fmt.Errorf("agent.capabilities.shell.commands[%d]: binary must not be empty", i))
				}
				if cmd.ScriptValidation != "" {
					errs = append(errs, fmt.Errorf("agent.capabilities.shell.commands[%d].scriptValidation is not yet implemented", i))
				}
				if len(cmd.DenyEnv) > 0 {
					errs = append(errs, fmt.Errorf("agent.capabilities.shell.commands[%d].denyEnv is not yet implemented", i))
				}
			}
		}

		// Validate network egress: each rule must have a non-empty host.
		if caps.Network != nil {
			for i, rule := range caps.Network.Egress {
				if rule.Host == "" {
					errs = append(errs, fmt.Errorf("agent.capabilities.network.egress[%d]: host must not be empty", i))
				}
			}
		}
	}

	// Validate secrets: Rotation must be a valid duration string if set.
	if c.Agent != nil {
		for name, sc := range c.Agent.Secrets {
			errs = append(errs, validateSecret(name, sc)...)
		}
	}

	// Validate MCP tool entries. Validation falls out of resolution: each
	// tool is resolved into its typed view, which rejects fields not legal
	// for the type.
	if c.Agent != nil && c.Agent.Tools != nil {
		for name, tool := range c.Agent.Tools.MCP {
			if _, errs2 := tool.Resolve(name); len(errs2) > 0 {
				errs = append(errs, errs2...)
			}
		}
	}

	errs = append(errs, c.validateRestrictedSecretConcurrency()...)

	return errors.Join(errs...)
}

// validateRestrictedSecretConcurrency rejects a configuration that combines a
// restricted secret (a secret with a non-empty allowedTools list) with MCP tool
// concurrency greater than one. Per-tool secret enforcement serializes tool
// calls per container — only one tool-call window may be active at a time — so a
// server permitted to run tool calls in parallel could not be gated correctly.
func (c *AgentContainer) validateRestrictedSecretConcurrency() []error {
	if c.Agent == nil {
		return nil
	}
	// A secret is restricted if it declares allowedTools explicitly OR is
	// referenced by an MCP server's secrets list — policy resolution restricts
	// both. Check the effective set, not just the explicit field, so an
	// implicitly-restricted secret cannot slip past with concurrency > 1.
	hasRestricted := false
	for _, sc := range c.Agent.Secrets {
		if len(sc.AllowedTools) > 0 {
			hasRestricted = true
			break
		}
	}
	if !hasRestricted && c.Agent.Tools != nil {
		for _, tool := range c.Agent.Tools.MCP {
			if len(tool.Secrets) > 0 {
				// Only counts if it references a declared secret.
				for _, key := range tool.Secrets {
					if _, ok := c.Agent.Secrets[key]; ok {
						hasRestricted = true
						break
					}
				}
			}
			if hasRestricted {
				break
			}
		}
	}
	if !hasRestricted {
		return nil
	}

	var errs []error
	if c.Agent.Policy != nil && c.Agent.Policy.MaxConcurrentTools > 1 {
		errs = append(errs, fmt.Errorf("agent.policy.maxConcurrentTools must be <= 1 when any secret declares allowedTools (per-tool secret enforcement serializes tool calls); got %d", c.Agent.Policy.MaxConcurrentTools))
	}
	if c.Agent.Tools != nil {
		for name, tool := range c.Agent.Tools.MCP {
			if tool.Policy != nil && tool.Policy.MaxConcurrentTools > 1 {
				errs = append(errs, fmt.Errorf("agent.tools.mcp[%q].policy.maxConcurrentTools must be <= 1 when any secret declares allowedTools (per-tool secret enforcement serializes tool calls); got %d", name, tool.Policy.MaxConcurrentTools))
			}
		}
	}
	return errs
}

// knownSecretProviders is the set of canonical provider identifiers accepted
// in SecretConfig.Provider. Provider-specific routing (e.g. the op:// CLI vs
// Connect Server) is selected at runtime via environment, not config.
var knownSecretProviders = map[string]bool{
	"env":       true,
	"oidc":      true,
	"vault":     true,
	"infisical": true,
	"1password": true,
}

// validateSecret checks a single secret declaration. Structured fields
// (provider, path, key, mount, role, ...) are canonical. The only URI
// shorthand still accepted in the provider field is env://NAME; every other
// scheme (op://, vault://, infisical://, oidc://) must be expressed with
// structured fields.
func validateSecret(name string, sc SecretConfig) []error {
	var errs []error
	field := func(f string) string { return fmt.Sprintf("agent.secrets[%q].%s", name, f) }

	if sc.Rotation != "" {
		if _, err := time.ParseDuration(sc.Rotation); err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid duration %q: %w", field("rotation"), sc.Rotation, err))
		}
	}

	switch {
	case sc.Provider == "":
		errs = append(errs, fmt.Errorf("%s: provider is required", field("provider")))
	case strings.HasPrefix(sc.Provider, "env://"):
		// Accepted shorthand: env://VAR_NAME.
	case strings.Contains(sc.Provider, "://"):
		scheme := sc.Provider[:strings.Index(sc.Provider, "://")+3]
		errs = append(errs, fmt.Errorf("%s: URI shorthand %q is no longer accepted; use structured fields instead (e.g. provider, path, key, mount)", field("provider"), scheme))
	case !knownSecretProviders[sc.Provider]:
		errs = append(errs, fmt.Errorf("%s: unknown provider %q (valid: env, oidc, vault, infisical, 1password)", field("provider"), sc.Provider))
	}

	if sc.Provider == "1password" {
		if sc.Vault == "" {
			errs = append(errs, fmt.Errorf("%s: vault is required for the 1password provider", field("vault")))
		}
		if sc.Item == "" {
			errs = append(errs, fmt.Errorf("%s: item is required for the 1password provider", field("item")))
		}
	}

	return errs
}

// Resolve maps the wire MCPToolConfig onto its typed accessor view,
// validating as it goes. It returns a ResolvedTool whose Kind selects the
// single non-nil typed view (Container/Component/Remote), plus every
// validation error encountered. Validation falls out of resolution: any
// field set on the wire struct but not legal for the resolved type yields an
// error. Type "" resolves to KindContainer.
//
// Per-type field allowlist (the matrix this enforces):
//
//	field                                  container  component  remote
//	image                                  required   required   rejected
//	url                                    rejected   rejected   required
//	transport, port, path                  ok         rejected   rejected
//	command, env, mounts                   ok         rejected   rejected
//	secrets                                ok         ok         rejected
//	limits                                 rejected   ok         rejected
//	policy.allowedTools/requireApproval/
//	  maxConcurrentTools                   ok         ok         ok
//	policy.network/filesystem/shell/
//	  securityYaml                         ok         rejected   rejected
//
// On a fatal type error (unknown Type) the returned ResolvedTool is zero and
// the only error describes the invalid type.
func (t MCPToolConfig) Resolve(name string) (ResolvedTool, []error) {
	field := func(f string) string { return fmt.Sprintf("agent.tools.mcp[%q].%s", name, f) }

	switch t.Type {
	case "", "container":
		return t.resolveContainer(name, field)
	case "component":
		return t.resolveComponent(name, field)
	case "remote":
		return t.resolveRemote(name, field)
	default:
		return ResolvedTool{}, []error{fmt.Errorf("%s: invalid value %q (must be \"container\", \"component\", or \"remote\")", field("type"), t.Type)}
	}
}

func (t MCPToolConfig) resolveContainer(name string, field func(string) string) (ResolvedTool, []error) {
	var errs []error

	if t.Image == "" {
		errs = append(errs, fmt.Errorf("%s: image must not be empty", field("image")))
	}

	switch t.Transport {
	case "", "stdio", "http":
		// Valid values.
	default:
		errs = append(errs, fmt.Errorf("%s: invalid value %q (must be \"stdio\" or \"http\")", field("transport"), t.Transport))
	}
	if t.Transport == "http" && t.Port <= 0 {
		errs = append(errs, fmt.Errorf("%s: port must be > 0 when transport is \"http\"", field("port")))
	}
	if t.Transport != "http" && t.Port != 0 {
		errs = append(errs, fmt.Errorf("%s: port is only valid when transport is \"http\"", field("port")))
	}
	if t.Transport != "http" && t.Path != "" {
		errs = append(errs, fmt.Errorf("%s: path is only valid when transport is \"http\"", field("path")))
	}

	if t.Limits != nil {
		errs = append(errs, fmt.Errorf("%s: limits are only valid for component-type tools", field("limits")))
		errs = append(errs, validateLimits(t.Limits, field)...)
	}

	errs = append(errs, validateSharedPolicy(t.Policy, field)...)
	errs = append(errs, validateContainerPolicy(t.Policy, field)...)

	view := &ContainerTool{
		Image:        t.Image,
		Capabilities: t.Capabilities,
		Secrets:      t.Secrets,
		Mounts:       t.Mounts,
		Transport:    t.Transport,
		Port:         t.Port,
		Path:         t.Path,
		Command:      t.Command,
		Env:          t.Env,
		Policy:       t.Policy,
	}
	return ResolvedTool{Name: name, Kind: KindContainer, Container: view}, errs
}

func (t MCPToolConfig) resolveComponent(name string, field func(string) string) (ResolvedTool, []error) {
	var errs []error

	if t.Image == "" {
		errs = append(errs, fmt.Errorf("%s: image must not be empty", field("image")))
	}
	if t.URL != "" {
		errs = append(errs, fmt.Errorf("%s: url is only valid for remote-type tools", field("url")))
	}
	if t.Transport != "" {
		errs = append(errs, fmt.Errorf("%s: transport is only valid for container-type tools", field("transport")))
	}
	if t.Port != 0 {
		errs = append(errs, fmt.Errorf("%s: port is only valid for container-type tools", field("port")))
	}
	if t.Path != "" {
		errs = append(errs, fmt.Errorf("%s: path is only valid for container-type tools", field("path")))
	}
	if len(t.Command) > 0 {
		errs = append(errs, fmt.Errorf("%s: command is only valid for container-type tools", field("command")))
	}
	if len(t.Env) > 0 {
		errs = append(errs, fmt.Errorf("%s: env is only valid for container-type tools", field("env")))
	}
	if len(t.Mounts) > 0 {
		errs = append(errs, fmt.Errorf("%s: mounts are not valid for component-type tools", field("mounts")))
	}
	if t.Limits != nil {
		errs = append(errs, validateLimits(t.Limits, field)...)
	}

	errs = append(errs, validateSharedPolicy(t.Policy, field)...)
	errs = append(errs, validateNonContainerPolicy(t.Policy, "component", field)...)

	view := &ComponentTool{
		Image:        t.Image,
		Capabilities: t.Capabilities,
		Secrets:      t.Secrets,
		Limits:       t.Limits,
		Policy:       t.Policy,
	}
	return ResolvedTool{Name: name, Kind: KindComponent, Component: view}, errs
}

func (t MCPToolConfig) resolveRemote(name string, field func(string) string) (ResolvedTool, []error) {
	var errs []error

	if t.Image != "" {
		errs = append(errs, fmt.Errorf("%s: image is not valid for remote-type tools", field("image")))
	}
	if t.URL == "" {
		errs = append(errs, fmt.Errorf("%s: url is required for remote-type tools", field("url")))
	} else if u, err := url.Parse(t.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, fmt.Errorf("%s: invalid URL %q (must be http or https)", field("url"), t.URL))
	}
	if t.Transport != "" {
		errs = append(errs, fmt.Errorf("%s: transport is only valid for container-type tools", field("transport")))
	}
	if t.Port != 0 {
		errs = append(errs, fmt.Errorf("%s: port is only valid for container-type tools", field("port")))
	}
	if t.Path != "" {
		errs = append(errs, fmt.Errorf("%s: path is only valid for container-type tools", field("path")))
	}
	if len(t.Command) > 0 {
		errs = append(errs, fmt.Errorf("%s: command is only valid for container-type tools", field("command")))
	}
	if len(t.Env) > 0 {
		errs = append(errs, fmt.Errorf("%s: env is only valid for container-type tools", field("env")))
	}
	if len(t.Mounts) > 0 {
		errs = append(errs, fmt.Errorf("%s: mounts are not valid for remote-type tools", field("mounts")))
	}
	if len(t.Secrets) > 0 {
		errs = append(errs, fmt.Errorf("%s: secrets are not valid for remote-type tools", field("secrets")))
	}
	if t.Limits != nil {
		errs = append(errs, fmt.Errorf("%s: limits are only valid for component-type tools", field("limits")))
		errs = append(errs, validateLimits(t.Limits, field)...)
	}

	errs = append(errs, validateSharedPolicy(t.Policy, field)...)
	errs = append(errs, validateNonContainerPolicy(t.Policy, "remote", field)...)

	view := &RemoteTool{
		URL:          t.URL,
		Capabilities: t.Capabilities,
		Policy:       t.Policy,
	}
	return ResolvedTool{Name: name, Kind: KindRemote, Remote: view}, errs
}

// validateLimits checks the non-negativity of component limit fields. The
// type-appropriateness of limits is checked by the caller.
func validateLimits(l *ComponentLimits, field func(string) string) []error {
	var errs []error
	if l.MemoryMB < 0 {
		errs = append(errs, fmt.Errorf("%s: must be >= 0", field("limits.memory_mb")))
	}
	if l.TimeoutMs < 0 {
		errs = append(errs, fmt.Errorf("%s: must be >= 0", field("limits.timeout_ms")))
	}
	if l.Fuel < 0 {
		errs = append(errs, fmt.Errorf("%s: must be >= 0", field("limits.fuel")))
	}
	return errs
}

// validateSharedPolicy checks policy fields legal on every tool type:
// maxConcurrentTools (>= 0), shell command binaries, shellTools arg shape,
// and network egress hosts.
func validateSharedPolicy(p *MCPServerPolicy, field func(string) string) []error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.MaxConcurrentTools < 0 {
		errs = append(errs, fmt.Errorf("%s: must be >= 0, got %d", field("policy.maxConcurrentTools"), p.MaxConcurrentTools))
	}
	if p.Shell != nil {
		for i, cmd := range p.Shell.Commands {
			if cmd.Binary == "" {
				errs = append(errs, fmt.Errorf("%s: binary must not be empty", field(fmt.Sprintf("policy.shell.commands[%d]", i))))
			}
		}
	}
	for toolName, spec := range p.ShellTools {
		if spec.CommandArg != "" && (spec.BinaryArg != "" || spec.ArgsArg != "") {
			errs = append(errs, fmt.Errorf("%s: commandArg and binaryArg/argsArg are mutually exclusive", field(fmt.Sprintf("policy.shellTools[%q]", toolName))))
		}
	}
	if p.Network != nil {
		for i, rule := range p.Network.Egress {
			if rule.Host == "" {
				errs = append(errs, fmt.Errorf("%s: host must not be empty", field(fmt.Sprintf("policy.network.egress[%d]", i))))
			}
		}
	}
	return errs
}

// validateContainerPolicy is a no-op placeholder: kernel-class policy fields
// (network/filesystem/shell/securityYaml) are all legal on container-type
// tools. Kept symmetric with validateNonContainerPolicy for clarity.
func validateContainerPolicy(_ *MCPServerPolicy, _ func(string) string) []error {
	return nil
}

// validateNonContainerPolicy rejects kernel-class policy fields that cannot
// be enforced without a cgroup (component and remote tools). kind is the
// tool type label used in the error message.
func validateNonContainerPolicy(p *MCPServerPolicy, kind string, field func(string) string) []error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.Network != nil {
		errs = append(errs, fmt.Errorf("%s: network policy is not enforceable for %s-type tools", field("policy.network"), kind))
	}
	if p.Filesystem != nil {
		errs = append(errs, fmt.Errorf("%s: filesystem policy is not enforceable for %s-type tools", field("policy.filesystem"), kind))
	}
	if p.Shell != nil {
		errs = append(errs, fmt.Errorf("%s: shell policy is not enforceable for %s-type tools", field("policy.shell"), kind))
	}
	if p.SecurityYAML != "" {
		errs = append(errs, fmt.Errorf("%s: securityYaml is not enforceable for %s-type tools", field("policy.securityYaml"), kind))
	}
	return errs
}
