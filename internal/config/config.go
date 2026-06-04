// Package config defines the agentcontainer.json schema types and configuration loader.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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

	// Agent-specific extensions.
	Agent *AgentConfig `json:"agent,omitempty"`
}

// BuildConfig holds container build settings.
type BuildConfig struct {
	Dockerfile string            `json:"dockerfile,omitempty"`
	Context    string            `json:"context,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
}

// AgentConfig holds all agent-specific configuration under the "agent" key.
type AgentConfig struct {
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

// MCPToolConfig declares an MCP server tool.
//
// Validation is type-driven: each type has an allowlist of valid fields
// (see validateMCPTool). Remote servers must not declare enforcement the
// runtime cannot deliver — kernel-class policy fields are validation
// errors on remote, not silent no-ops.
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

	// URL is the endpoint of a "remote" server. Remote type only.
	URL string `json:"url,omitempty"`

	// Command overrides the container entrypoint. Container type only.
	Command []string `json:"command,omitempty"`

	// Env sets environment variables. Container type only.
	Env map[string]string `json:"env,omitempty"`

	// Policy declares per-server enforcement rules. Valid on all types;
	// which sub-fields are valid depends on type (see validateMCPTool).
	Policy *MCPServerPolicy `json:"policy,omitempty"`
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

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

	return &cfg, nil
}

// Validate checks the AgentContainer configuration for structural correctness.
// It collects all validation errors and returns them joined via errors.Join.
func (c *AgentContainer) Validate() error {
	var errs []error

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
			if sc.Rotation != "" {
				if _, err := time.ParseDuration(sc.Rotation); err != nil {
					errs = append(errs, fmt.Errorf("agent.secrets[%q].rotation: invalid duration %q: %w", name, sc.Rotation, err))
				}
			}
		}
	}

	// Validate MCP tool entries.
	if c.Agent != nil && c.Agent.Tools != nil {
		for name, tool := range c.Agent.Tools.MCP {
			errs = append(errs, validateMCPTool(name, tool)...)
		}
	}

	return errors.Join(errs...)
}

// validateMCPTool enforces the per-type field allowlist for an MCP tool
// entry. Each type permits a distinct field set:
//
//	field                                  container  component  remote
//	image                                  required   required   rejected
//	url                                    rejected   rejected   required
//	transport, port                        ok         rejected   rejected
//	command, env, mounts                   ok         rejected   rejected
//	secrets                                ok         ok         rejected
//	limits                                 rejected   ok         rejected
//	policy.allowedTools/requireApproval/
//	  maxConcurrentTools                   ok         ok         ok
//	policy.network/filesystem/shell/
//	  securityYaml                         ok         rejected   rejected
func validateMCPTool(name string, tool MCPToolConfig) []error {
	var errs []error
	field := func(f string) string { return fmt.Sprintf("agent.tools.mcp[%q].%s", name, f) }

	switch tool.Type {
	case "", "container", "component", "remote":
		// Valid values.
	default:
		errs = append(errs, fmt.Errorf("%s: invalid value %q (must be \"container\", \"component\", or \"remote\")", field("type"), tool.Type))
		return errs
	}
	isComponent := tool.Type == "component"
	isRemote := tool.Type == "remote"
	isContainer := !isComponent && !isRemote

	// Image: required for container/component, rejected for remote.
	if isRemote {
		if tool.Image != "" {
			errs = append(errs, fmt.Errorf("%s: image is not valid for remote-type tools", field("image")))
		}
	} else if tool.Image == "" {
		errs = append(errs, fmt.Errorf("%s: image must not be empty", field("image")))
	}

	// URL: required for remote, rejected otherwise.
	if isRemote {
		if tool.URL == "" {
			errs = append(errs, fmt.Errorf("%s: url is required for remote-type tools", field("url")))
		} else if u, err := url.Parse(tool.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("%s: invalid URL %q (must be http or https)", field("url"), tool.URL))
		}
	} else if tool.URL != "" {
		errs = append(errs, fmt.Errorf("%s: url is only valid for remote-type tools", field("url")))
	}

	// Transport/port: container only.
	if isContainer {
		switch tool.Transport {
		case "", "stdio", "http":
			// Valid values.
		default:
			errs = append(errs, fmt.Errorf("%s: invalid value %q (must be \"stdio\" or \"http\")", field("transport"), tool.Transport))
		}
		if tool.Transport == "http" && tool.Port <= 0 {
			errs = append(errs, fmt.Errorf("%s: port must be > 0 when transport is \"http\"", field("port")))
		}
		if tool.Transport != "http" && tool.Port != 0 {
			errs = append(errs, fmt.Errorf("%s: port is only valid when transport is \"http\"", field("port")))
		}
	} else {
		if tool.Transport != "" {
			errs = append(errs, fmt.Errorf("%s: transport is only valid for container-type tools", field("transport")))
		}
		if tool.Port != 0 {
			errs = append(errs, fmt.Errorf("%s: port is only valid for container-type tools", field("port")))
		}
	}

	// Command/env/mounts: container only.
	if !isContainer {
		if len(tool.Command) > 0 {
			errs = append(errs, fmt.Errorf("%s: command is only valid for container-type tools", field("command")))
		}
		if len(tool.Env) > 0 {
			errs = append(errs, fmt.Errorf("%s: env is only valid for container-type tools", field("env")))
		}
	}
	if isComponent && len(tool.Mounts) > 0 {
		errs = append(errs, fmt.Errorf("%s: mounts are not valid for component-type tools", field("mounts")))
	}
	if isRemote && len(tool.Mounts) > 0 {
		errs = append(errs, fmt.Errorf("%s: mounts are not valid for remote-type tools", field("mounts")))
	}

	// Secrets: rejected on remote (nothing to inject into).
	if isRemote && len(tool.Secrets) > 0 {
		errs = append(errs, fmt.Errorf("%s: secrets are not valid for remote-type tools", field("secrets")))
	}

	// Limits: component only.
	if !isComponent && tool.Limits != nil {
		errs = append(errs, fmt.Errorf("%s: limits are only valid for component-type tools", field("limits")))
	}
	if tool.Limits != nil {
		if tool.Limits.MemoryMB < 0 {
			errs = append(errs, fmt.Errorf("%s: must be >= 0", field("limits.memory_mb")))
		}
		if tool.Limits.TimeoutMs < 0 {
			errs = append(errs, fmt.Errorf("%s: must be >= 0", field("limits.timeout_ms")))
		}
		if tool.Limits.Fuel < 0 {
			errs = append(errs, fmt.Errorf("%s: must be >= 0", field("limits.fuel")))
		}
	}

	// Policy: allowedTools/requireApproval/maxConcurrentTools are valid on
	// all types; kernel-class fields only on container.
	if p := tool.Policy; p != nil {
		if p.MaxConcurrentTools < 0 {
			errs = append(errs, fmt.Errorf("%s: must be >= 0, got %d", field("policy.maxConcurrentTools"), p.MaxConcurrentTools))
		}
		if !isContainer {
			kind := tool.Type
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
	}

	return errs
}
