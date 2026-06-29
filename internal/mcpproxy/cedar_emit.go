package mcpproxy

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"text/template"
)

//go:embed templates/cedar/*.cedar.tmpl templates/cedar/command.cedarschema
var cedarTemplateFS embed.FS

// cedarMembershipCategories are the policy categories the Cedar backend
// evaluates natively (everything else — paths and regex/substring content —
// is delegated to the in-process OPA engine; see cedar.go). The order is the
// emission order in the generated .cedar file.
var cedarMembershipCategories = []string{
	"denied_binaries",
	"dangerous_flags",
	"tool_blocked_flags",
	"capabilities",
	"network",
}

// cedarPerTool is one binary-scoped forbid policy: a Cedar string literal for
// the binary plus a pre-rendered Cedar set literal of the flags it forbids.
type cedarPerTool struct {
	Binary       string // raw binary, used in the @id annotation
	BinaryLit    string // Cedar string literal of the binary
	FlagsLiteral string // Cedar set literal of the forbidden flags
}

// cedarTemplateInput carries pre-rendered Cedar literals into the per-category
// templates. Rendering the set/string literals in Go (rather than in the
// templates) keeps the templates declarative and the Cedar syntax in one place.
type cedarTemplateInput struct {
	// denied_binaries
	HasDenied      bool
	DeniedBinaries string

	// dangerous_flags
	HasDangerous         bool
	DangerousDefault     string         // full dangerous set (applied to non-excepted binaries)
	DangerousExcludeBins string         // binaries handled by a per-tool policy
	DangerousPerTool     []cedarPerTool // reduced (dangerous \ exceptions) sets

	// tool_blocked_flags
	ToolBlocked []cedarPerTool

	// capabilities
	HasAllowlist    bool
	AllowedBinaries string
	DenyArgsPerTool []cedarPerTool
}

// EmitCedar renders the Cedar policy text and schema for a compiled policy's
// structured-membership categories, baking the resolved policy data into the
// forbid rules. It consumes the same CompiledPolicy.Data the OPA engine uses,
// so the two backends decide identically. Path and content categories are not
// emitted here (they are OPA-evaluated under the Cedar engine — fail-closed,
// never weaker; see cedar.go). Returns (policies, schema).
func EmitCedar(data map[string]any) (string, string, error) {
	tmpl, err := template.ParseFS(cedarTemplateFS, "templates/cedar/*.cedar.tmpl")
	if err != nil {
		return "", "", fmt.Errorf("mcpproxy: parsing cedar templates: %w", err)
	}
	schema, err := cedarTemplateFS.ReadFile("templates/cedar/command.cedarschema")
	if err != nil {
		return "", "", fmt.Errorf("mcpproxy: reading cedar schema: %w", err)
	}

	in := buildCedarInput(data)

	var sb strings.Builder
	sb.WriteString("// Generated from security policy by mcpproxy — do not edit directly.\n")
	sb.WriteString("// Structured-membership categories only; paths and content are native-Go evaluated.\n")
	// Cedar is deny-by-default: with only forbid policies, every request is
	// denied. The baseline permit makes the default ALLOW; the forbid policies
	// below carve out the denials (forbid overrides permit). This mirrors the
	// membership semantics — a command is allowed unless a category forbids it.
	sb.WriteString("\n@id(\"baseline_allow\")\npermit(principal, action == Action::\"Invoke\", resource);\n")
	for _, cat := range cedarMembershipCategories {
		var seg strings.Builder
		if err := tmpl.ExecuteTemplate(&seg, cat+".cedar.tmpl", in); err != nil {
			return "", "", fmt.Errorf("mcpproxy: rendering cedar %s: %w", cat, err)
		}
		if s := strings.TrimSpace(seg.String()); s != "" {
			sb.WriteString("\n")
			sb.WriteString(s)
			sb.WriteString("\n")
		}
	}
	return sb.String(), string(schema), nil
}

// buildCedarInput resolves CompiledPolicy.Data into the pre-rendered Cedar
// literals each template needs. Binary keys stay exact-case (map-keyed Rego
// categories look them up case-sensitively); membership comparisons that Rego
// lowercases are baked lowercased here and matched against resource.*_lc.
func buildCedarInput(data map[string]any) cedarTemplateInput {
	var in cedarTemplateInput

	// denied_binaries: already lowercased + sorted in ToData.
	denied := dataStrings(data["denied_binaries"])
	if len(denied) > 0 {
		in.HasDenied = true
		in.DeniedBinaries = cedarSetLiteral(denied)
	}

	// dangerous_flags with per-tool exceptions.
	dangerousLC := lowerAll(dataStrings(data["dangerous_flags"]))
	if len(dangerousLC) > 0 {
		in.HasDangerous = true
		in.DangerousDefault = cedarSetLiteral(dangerousLC)
		dangerousSet := toSet(dangerousLC)

		exceptions := dataStringMap(data["tool_allowed_flags"])
		var excludeBins []string
		for _, bin := range sortedKeys(exceptions) {
			excLC := toSet(lowerAll(exceptions[bin]))
			// Effective set is the dangerous flags this tool does NOT except.
			var effective []string
			for _, f := range dangerousLC {
				if _, excepted := excLC[f]; !excepted {
					effective = append(effective, f)
				}
			}
			// Only worth a dedicated policy when the exception actually removes
			// something; otherwise the default policy already covers this binary.
			if len(effective) == len(dangerousSet) {
				continue
			}
			excludeBins = append(excludeBins, bin)
			in.DangerousPerTool = append(in.DangerousPerTool, cedarPerTool{
				Binary:       bin,
				BinaryLit:    cedarString(bin),
				FlagsLiteral: cedarSetLiteral(effective),
			})
		}
		if len(excludeBins) > 0 {
			in.DangerousExcludeBins = cedarSetLiteral(excludeBins)
		}
	}

	// tool_blocked_flags: per binary (key exact-case, flags lowercased).
	blocked := dataStringMap(data["tool_blocked_flags"])
	for _, bin := range sortedKeys(blocked) {
		flags := lowerAll(blocked[bin])
		if len(flags) == 0 {
			continue
		}
		in.ToolBlocked = append(in.ToolBlocked, cedarPerTool{
			Binary:       bin,
			BinaryLit:    cedarString(bin),
			FlagsLiteral: cedarSetLiteral(flags),
		})
	}

	// capabilities: allowlist (lowercased) + per-binary denyArgs.
	allowed := lowerAll(dataStrings(data["allowed_binaries"]))
	if len(allowed) > 0 {
		in.HasAllowlist = true
		in.AllowedBinaries = cedarSetLiteral(allowed)
	}
	shellCommands := dataStringSetMap(data["shell_commands"], "denyArgs")
	for _, bin := range sortedKeys(shellCommands) {
		flags := lowerAll(shellCommands[bin])
		if len(flags) == 0 {
			continue
		}
		in.DenyArgsPerTool = append(in.DenyArgsPerTool, cedarPerTool{
			Binary:       bin,
			BinaryLit:    cedarString(bin),
			FlagsLiteral: cedarSetLiteral(flags),
		})
	}

	return in
}

// cedarString renders a Cedar string literal (double-quoted, escaped).
func cedarString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// cedarSetLiteral renders a Cedar set literal of strings, sorted+deduplicated
// for deterministic output (so the emitted policy — and ac policy translate —
// is stable for equal inputs).
func cedarSetLiteral(items []string) string {
	seen := make(map[string]struct{}, len(items))
	uniq := make([]string, 0, len(items))
	for _, it := range items {
		if _, ok := seen[it]; ok {
			continue
		}
		seen[it] = struct{}{}
		uniq = append(uniq, it)
	}
	sort.Strings(uniq)
	parts := make([]string, len(uniq))
	for i, it := range uniq {
		parts[i] = cedarString(it)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// --- CompiledPolicy.Data coercion helpers (Data values are []any / []string
// / map[string]any depending on which builder produced them). ---

func dataStrings(v any) []string {
	switch xs := v.(type) {
	case []string:
		return append([]string(nil), xs...)
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func dataStringMap(v any) map[string][]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, val := range m {
		out[k] = dataStrings(val)
	}
	return out
}

// dataStringSetMap reads map[binary] -> { key: []string } (e.g. shell_commands
// where each entry holds a "denyArgs" list), returning map[binary][]string.
func dataStringSetMap(v any, key string) map[string][]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, val := range m {
		entry, ok := val.(map[string]any)
		if !ok {
			continue
		}
		out[k] = dataStrings(entry[key])
	}
	return out
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func toSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[s] = struct{}{}
	}
	return out
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
