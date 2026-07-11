package toolpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// securityPolicyPackages are the category packages rendered from the
// embedded sift-mcp template ports, in evaluation order. The decision
// aggregator references whichever packages a server's compile produced.
var securityPolicyPackages = []string{
	"denied_binaries",
	"dangerous_flags",
	"tool_blocked_flags",
	"shell_metacharacters",
	"awk_scanning",
	"rm_protection",
	"path_policy",
	"output_path_policy",
}

// Defaults ported verbatim from sift-mcp policy/schema.py. A stock (or
// absent) security.yaml still produces full-parity data; any field can be
// overridden in YAML.
var (
	defaultShellMetacharacters = []string{";", "&&", "||", "`", "$(", "${"}
	defaultAwkProgramTools     = []string{"awk", "gawk", "mawk", "nawk"}

	// RE2-safe form of sift-mcp's awk danger regex: system(), getline,
	// and pipe/redirect-into-string operators.
	defaultAwkDangerRegex = `system\s*\(|getline|".*\||\|.*"|>\s*"|>>\s*"`

	defaultBlockedInputDirsBase = []string{"/etc", "/proc", "/sys", "/dev", "/boot"}
	defaultOutputOnlyDirs       = []string{"/usr", "/bin", "/sbin", "/lib", "/var", "/home"}
)

// SecurityPolicy is the validated representation of a security.yaml file,
// ready to emit as OPA data. Mirrors sift-mcp policy/schema.py.
type SecurityPolicy struct {
	// Fields a security.yaml declares directly.
	DangerousFlags   []string            `yaml:"dangerous_flags"`
	ToolAllowedFlags map[string][]string `yaml:"tool_allowed_flags"`
	ToolBlockedFlags map[string][]string `yaml:"tool_blocked_flags"`
	OutputFlags      []string            `yaml:"output_flags"`
	DeniedBinaries   []string            `yaml:"denied_binaries"`

	// Fields with sift-mcp defaults, overridable in YAML.
	ShellMetacharacters    []string `yaml:"shell_metacharacters"`
	AwkProgramTools        []string `yaml:"awk_program_tools"`
	AwkDangerRegex         string   `yaml:"awk_danger_regex"`
	BlockedInputDirs       []string `yaml:"blocked_input_dirs"`
	BlockedInputExceptions []string `yaml:"blocked_input_exceptions"`
	BlockedOutputDirs      []string `yaml:"blocked_output_dirs"`
	ProtectedRmDirs        []string `yaml:"protected_rm_dirs"`
}

// DefaultSecurityPolicy returns the policy produced by an empty
// security.yaml: all sift-mcp defaults, no declared flags or binaries.
func DefaultSecurityPolicy() *SecurityPolicy {
	p := &SecurityPolicy{}
	p.applyDefaults()
	return p
}

func (p *SecurityPolicy) applyDefaults() {
	if p.ShellMetacharacters == nil {
		p.ShellMetacharacters = append([]string(nil), defaultShellMetacharacters...)
	}
	if p.AwkProgramTools == nil {
		p.AwkProgramTools = append([]string(nil), defaultAwkProgramTools...)
	}
	if p.AwkDangerRegex == "" {
		p.AwkDangerRegex = defaultAwkDangerRegex
	}
}

// LoadSecurityYAML reads and validates a security.yaml file.
func LoadSecurityYAML(path string) (*SecurityPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: reading security.yaml %s: %w", path, err)
	}
	var p SecurityPolicy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // fail loudly on unknown fields, like pydantic extra="forbid"
	if err := dec.Decode(&p); err != nil {
		// An empty file decodes to EOF; treat as defaults-only.
		if strings.Contains(err.Error(), "EOF") {
			return DefaultSecurityPolicy(), nil
		}
		return nil, fmt.Errorf("mcpproxy: invalid security.yaml %s: %w", path, err)
	}
	p.applyDefaults()
	return &p, nil
}

// GuardPolicyFile is the agent-tool policy the guard compiles: a security.yaml
// (SecurityPolicy, inlined) optionally extended with a `shell:` allowlist. It
// is a strict superset of the security.yaml schema — a file with no `shell:`
// block parses identically to LoadSecurityYAML — so the guard can additionally
// enforce a default-deny binary allowlist (and per-binary denyArgs) over the
// agent's native shell, which a plain SecurityPolicy cannot express. The yaml
// tags mirror the capability-matrix fixture's `policy` block so that block can
// drive the guard verbatim (single source of truth with the Layer-1 oracle).
type GuardPolicyFile struct {
	SecurityPolicy `yaml:",inline"`
	Shell          []struct {
		Binary   string   `yaml:"binary"`
		DenyArgs []string `yaml:"denyArgs"`
	} `yaml:"shell"`
}

// LoadGuardPolicyYAML reads a guard policy file (a security.yaml optionally
// extended with a `shell:` allowlist) and returns the SecurityPolicy plus the
// shell caps wrapped as an MCPServerPolicy, ready for Compile. When the file
// declares no `shell:` block the returned cfg is nil and the result matches
// LoadSecurityYAML.
func LoadGuardPolicyYAML(path string) (*SecurityPolicy, *config.MCPServerPolicy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("mcpproxy: reading guard policy %s: %w", path, err)
	}
	var gp GuardPolicyFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // fail loudly on unknown fields, like security.yaml
	if err := dec.Decode(&gp); err != nil {
		// An empty file decodes to EOF; treat as defaults-only.
		if strings.Contains(err.Error(), "EOF") {
			return DefaultSecurityPolicy(), nil, nil
		}
		return nil, nil, fmt.Errorf("mcpproxy: invalid guard policy %s: %w", path, err)
	}
	sec := &gp.SecurityPolicy
	sec.applyDefaults()

	var cfg *config.MCPServerPolicy
	if len(gp.Shell) > 0 {
		cmds := make([]config.ShellCommand, len(gp.Shell))
		for i, s := range gp.Shell {
			cmds[i] = config.ShellCommand{Binary: s.Binary, DenyArgs: s.DenyArgs}
		}
		cfg = &config.MCPServerPolicy{Shell: &config.ShellCaps{Commands: cmds}}
	}
	return sec, cfg, nil
}

// expandPath expands ~ and makes the path absolute (lexically — host
// symlinks are deliberately not resolved; see decompose.go).
func expandPath(path string) string {
	if path == "" {
		return path
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return abs
}

// ToData produces the OPA data document: policy lists resolved, absolute,
// and lowercased where sift-mcp lowercases. Ports schema.py to_data().
func (p *SecurityPolicy) ToData() map[string]any {
	homeVhir := expandPath("~/.vhir")
	casesDir := os.Getenv("VHIR_CASES_DIR")
	if casesDir == "" {
		casesDir = "~/cases"
	}
	casesDir = expandPath(casesDir)

	blockedInput := p.BlockedInputDirs
	if blockedInput == nil {
		blockedInput = append(append([]string(nil), defaultBlockedInputDirsBase...), homeVhir)
	}
	blockedInputExceptions := p.BlockedInputExceptions
	if blockedInputExceptions == nil {
		blockedInputExceptions = []string{
			expandPath("~/.vhir/cases"),
			expandPath("~/.vhir/hayabusa-output"),
		}
	}
	blockedOutput := p.BlockedOutputDirs
	if blockedOutput == nil {
		blockedOutput = append(append([]string(nil), blockedInput...), defaultOutputOnlyDirs...)
	}
	protectedRm := p.ProtectedRmDirs
	if protectedRm == nil {
		protectedRm = []string{casesDir, "/cases", "/evidence"}
	}

	// denied_binaries lowercased and deduplicated, sorted (is_denied()
	// compares binary.lower()).
	deniedSet := make(map[string]struct{}, len(p.DeniedBinaries))
	for _, b := range p.DeniedBinaries {
		deniedSet[strings.ToLower(b)] = struct{}{}
	}
	denied := make([]string, 0, len(deniedSet))
	for b := range deniedSet {
		denied = append(denied, b)
	}
	sort.Strings(denied)

	return map[string]any{
		"denied_binaries":          denied,
		"dangerous_flags":          sliceAny(p.DangerousFlags),
		"tool_allowed_flags":       mapSliceAny(p.ToolAllowedFlags),
		"tool_blocked_flags":       mapSliceAny(p.ToolBlockedFlags),
		"output_flags":             sliceAny(p.OutputFlags),
		"shell_metacharacters":     sliceAny(p.ShellMetacharacters),
		"awk_program_tools":        sliceAny(p.AwkProgramTools),
		"blocked_input_dirs":       sliceAny(blockedInput),
		"blocked_input_exceptions": sliceAny(blockedInputExceptions),
		"blocked_output_dirs":      sliceAny(blockedOutput),
		"protected_rm_dirs":        sliceAny(protectedRm),
	}
}

// CompiledPolicy is a server's policy compiled to the neutral data document
// plus the emitted Cedar policy set the embedded engine evaluates (no temp
// files, unlike sift-mcp's compiler).
type CompiledPolicy struct {
	// Data is the neutral policy document: allow/deny sets and structured
	// categories the Cedar emitter and the native-Go evaluators consume.
	Data map[string]any
	// PolicyPackages drives policies_evaluated, in evaluation order (reported
	// to audit fully qualified as "sift.<pkg>").
	PolicyPackages []string
	// OutputFlags classify output paths during decomposition (from the
	// security.yaml, falling back to the sift-mcp catalog defaults).
	OutputFlags []string

	// CedarPolicies and CedarSchema are the Cedar emission of the
	// structured-membership categories, baked from the Data above. They are the
	// policy artifact the engine actually evaluates, so they are part of Hash().
	CedarPolicies string
	CedarSchema   string

	// AwkDangerRegex is the RE2 pattern the native-Go content evaluator
	// compiles for the awk_scanning category (the one category Cedar cannot
	// express, as its `\s*` has no `like` equivalent). Carried alongside the
	// Data document — which already holds shell_metacharacters/awk_program_tools
	// — because the regex is compiled Go-side, not carried in Data.
	AwkDangerRegex string
}

// Hash returns a stable "sha256:<hex>" digest of the compiled policy bundle
// (data document + package order + emitted Cedar policies). It is published in
// the ARD catalog so external consumers can verify which policy governs a
// capability and detect when it changes. json.Marshal sorts map keys, so the
// digest is deterministic for equal policies.
func (cp *CompiledPolicy) Hash() string {
	if cp == nil {
		return ""
	}
	payload := struct {
		Data           map[string]any `json:"data"`
		PolicyPackages []string       `json:"policyPackages"`
		CedarPolicies  string         `json:"cedarPolicies"`
	}{cp.Data, cp.PolicyPackages, cp.CedarPolicies}
	b, err := json.Marshal(payload)
	if err != nil {
		// A compiled policy that cannot marshal is a programming error, not
		// a runtime condition; surface an empty hash rather than panic.
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Compile renders a server's policy: the security.yaml-derived templates
// plus the agentcontainers-native packages (capabilities from
// policy.shell, network from policy.network). sec may be nil when the
// server declares no securityYaml — sift-mcp defaults still apply
// (defense in depth: an empty YAML produces full-parity data).
func Compile(sec *SecurityPolicy, cfgPolicy *config.MCPServerPolicy) (*CompiledPolicy, error) {
	if sec == nil {
		sec = DefaultSecurityPolicy()
	}

	pkgs := append([]string(nil), securityPolicyPackages...)
	if cfgPolicy != nil && cfgPolicy.Filesystem != nil {
		pkgs = append(pkgs, "filesystem")
	}
	if cfgPolicy != nil && cfgPolicy.Shell != nil {
		pkgs = append(pkgs, "capabilities")
	}
	if cfgPolicy != nil && cfgPolicy.Network != nil {
		pkgs = append(pkgs, "network")
	}

	// Data is the neutral policy document the Cedar emitter consumes; the
	// security.yaml-derived defaults are merged with the config-derived
	// allow/deny sets below. uri_egress and override categories live in the
	// data (context_eval.go evaluates them natively) rather than as separate
	// modules; they no-op unless the proxy populates the matching context.
	data := sec.ToData()

	fsRead, fsWrite, fsDeny := []any{}, []any{}, []any{}
	if cfgPolicy != nil && cfgPolicy.Filesystem != nil {
		fsRead = sliceAny(cfgPolicy.Filesystem.Read)
		fsWrite = sliceAny(cfgPolicy.Filesystem.Write)
		fsDeny = sliceAny(cfgPolicy.Filesystem.Deny)
	}
	data["fs_read"] = fsRead
	data["fs_write"] = fsWrite
	data["fs_deny"] = fsDeny

	allowedBinaries := []any{}
	shellCommands := map[string]any{}
	if cfgPolicy != nil && cfgPolicy.Shell != nil {
		for _, cmd := range cfgPolicy.Shell.Commands {
			allowedBinaries = append(allowedBinaries, cmd.Binary)
			entry := map[string]any{}
			if len(cmd.DenyArgs) > 0 {
				entry["denyArgs"] = sliceAny(cmd.DenyArgs)
			}
			shellCommands[cmd.Binary] = entry
		}
	}
	data["allowed_binaries"] = allowedBinaries
	data["shell_commands"] = shellCommands

	egress := []any{}
	denyCIDRs := []any{}
	uriEgressDeny := []any{}
	if cfgPolicy != nil && cfgPolicy.Network != nil {
		for _, rule := range cfgPolicy.Network.Egress {
			egress = append(egress, map[string]any{
				"host":     rule.Host,
				"port":     rule.Port,
				"protocol": rule.Protocol,
			})
		}
		denyCIDRs = sliceAny(cfgPolicy.Network.Deny)
		uriEgressDeny = sliceAny(cfgPolicy.Network.URIEgressDeny)
	}
	data["network_egress"] = egress
	data["network_deny"] = denyCIDRs

	// uri_egress_denylist: hosts never eligible for URI-scoped transient
	// egress, regardless of user request (G4). From policy.network.uriEgressDeny;
	// empty when unset.
	data["uri_egress_denylist"] = uriEgressDeny

	// override_ceiling: the policy categories an operator override may waive
	// (G3). Fail-closed default is empty — no override can widen anything
	// unless the operator explicitly opts categories in via
	// policy.overrideCeiling. Structural decomposition denials (parsed.Deny)
	// short-circuit before Rego and are never reachable by an override.
	overrideCeiling := []any{}
	if cfgPolicy != nil {
		overrideCeiling = sliceAny(cfgPolicy.OverrideCeiling)
	}
	data["override_ceiling"] = overrideCeiling

	outputFlags := sec.OutputFlags
	if len(outputFlags) == 0 {
		outputFlags = append([]string(nil), defaultOutputFlags...)
	}

	// Cedar emission of the structured-membership categories, baked from the
	// same data the OPA modules consume (so both engines decide identically).
	// Always emitted for inspection; only consumed when engine == "cedar".
	cedarPolicies, cedarSchema, err := EmitCedar(data)
	if err != nil {
		return nil, err
	}

	return &CompiledPolicy{
		Data:           data,
		PolicyPackages: pkgs,
		OutputFlags:    outputFlags,
		CedarPolicies:  cedarPolicies,
		CedarSchema:    cedarSchema,
		AwkDangerRegex: sec.AwkDangerRegex,
	}, nil
}

// CompileServerPolicy resolves and compiles the policy for one MCP server
// config entry. configDir anchors the relative securityYaml path. Returns
// nil (no error) when the server declares nothing the policy engine
// evaluates — the caller skips Rego evaluation entirely for such servers.
func CompileServerPolicy(tool config.MCPToolConfig, configDir string) (*CompiledPolicy, error) {
	p := tool.Policy
	if p == nil || (p.SecurityYAML == "" && p.Shell == nil && p.Network == nil && p.Filesystem == nil) {
		return nil, nil
	}

	var sec *SecurityPolicy
	if p.SecurityYAML != "" {
		path := p.SecurityYAML
		if !filepath.IsAbs(path) {
			path = filepath.Join(configDir, path)
		}
		loaded, err := LoadSecurityYAML(path)
		if err != nil {
			return nil, err
		}
		sec = loaded
	}

	return Compile(sec, p)
}

func sliceAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func mapSliceAny(in map[string][]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = sliceAny(v)
	}
	return out
}
