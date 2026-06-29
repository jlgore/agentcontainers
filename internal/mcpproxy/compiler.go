package mcpproxy

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

//go:embed templates/*.rego.tmpl
var templateFS embed.FS

const regoHeader = "# Generated from security policy by mcpproxy — do not edit directly."

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

// CompiledPolicy is a server's policy compiled to in-memory Rego module
// sources plus the data document, ready for the OPA library (no temp
// files, unlike sift-mcp's compiler).
type CompiledPolicy struct {
	// Modules maps a synthetic filename to Rego source.
	Modules map[string]string
	// Data is the OPA data document.
	Data map[string]any
	// PolicyPackages drives decision.rego and policies_evaluated, in
	// evaluation order (fully qualified as "sift.<pkg>" by the template).
	PolicyPackages []string
	// OutputFlags classify output paths during decomposition (from the
	// security.yaml, falling back to the sift-mcp catalog defaults).
	OutputFlags []string

	// CedarPolicies and CedarSchema are the Cedar emission of the
	// structured-membership categories, baked from the same Data above. They
	// are always populated (so `ac policy translate` works regardless of the
	// configured engine) but only consumed when policy.engine == "cedar". They
	// are NOT part of Hash() — adding them leaves the OPA bundle digest, and
	// therefore the ARD catalog entry, byte-for-byte unchanged.
	CedarPolicies string
	CedarSchema   string

	// AwkDangerRegex is the RE2 pattern the native-Go content evaluator
	// compiles for the awk_scanning category (the one category Cedar cannot
	// express, as its `\s*` has no `like` equivalent). Carried alongside the
	// Data document — which already holds shell_metacharacters/awk_program_tools
	// — because the regex itself is baked into the OPA module text, not Data.
	// NOT part of Hash() (Hash marshals only Modules/Data/PolicyPackages), so
	// the OPA bundle digest and ARD catalog entry stay byte-for-byte unchanged.
	AwkDangerRegex string
}

// Hash returns a stable "sha256:<hex>" digest of the compiled policy
// bundle (Rego modules + data document + package order). It is published in
// the ARD catalog so external consumers can verify which policy governs a
// capability and detect when it changes. json.Marshal sorts map keys, so
// the digest is deterministic for equal policies.
func (cp *CompiledPolicy) Hash() string {
	if cp == nil {
		return ""
	}
	payload := struct {
		Modules        map[string]string `json:"modules"`
		Data           map[string]any    `json:"data"`
		PolicyPackages []string          `json:"policyPackages"`
	}{cp.Modules, cp.Data, cp.PolicyPackages}
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

	tmpl, err := template.ParseFS(templateFS, "templates/*.rego.tmpl")
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: parsing policy templates: %w", err)
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

	render := func(name string, data any) (string, error) {
		var sb strings.Builder
		if err := tmpl.ExecuteTemplate(&sb, name+".rego.tmpl", data); err != nil {
			return "", fmt.Errorf("mcpproxy: rendering %s: %w", name, err)
		}
		return sb.String(), nil
	}

	type templateInput struct {
		Header         string
		AwkDangerRegex string
		PolicyPackages []string
	}
	in := templateInput{
		Header:         regoHeader,
		AwkDangerRegex: sec.AwkDangerRegex,
		PolicyPackages: pkgs,
	}

	modules := make(map[string]string, len(pkgs)+1)
	for _, pkg := range pkgs {
		src, err := render(pkg, in)
		if err != nil {
			return nil, err
		}
		modules[pkg+".rego"] = src
	}
	decision, err := render("decision", in)
	if err != nil {
		return nil, err
	}
	modules["decision.rego"] = decision

	// uri_egress is always compiled (so data.sift.uri_egress is defined for
	// the decision aggregator) but is NOT a PolicyPackages member: it
	// contributes egress_targets, never a deny, and must not perturb
	// policies_evaluated. It no-ops unless the proxy populates
	// input.context.requested_uris (server opted into policy.network.uriEgress).
	uriEgress, err := render("uri_egress", in)
	if err != nil {
		return nil, err
	}
	modules["uri_egress.rego"] = uriEgress

	// override is always compiled (so data.sift.override is defined for the
	// decision aggregator) but is NOT a PolicyPackages member: it never
	// contributes a deny, only waives existing ones within the operator
	// ceiling (G3). It no-ops unless the proxy injects a verified
	// input.context.operator_override.
	override, err := render("override", in)
	if err != nil {
		return nil, err
	}
	modules["override.rego"] = override

	// Merge config-derived data on top of the security.yaml data.
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
		Modules:        modules,
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
