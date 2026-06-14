package mcpproxy

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// devPathTools are tools whose positional args may legitimately be /dev/
// device specifiers (disk forensics), where a /dev path must NOT be
// treated as a blocked input. Ported from sift-mcp security.DEV_PATH_TOOLS.
var devPathTools = map[string]bool{
	"mount": true, "umount": true, "mmls": true, "fls": true,
	"icat": true, "img_stat": true, "blkid": true, "fdisk": true,
	"losetup": true, "fsstat": true, "ifind": true, "istat": true,
	"mmcat": true, "sigfind": true, "tsk_recover": true, "sorter": true,
	"dd": true,
}

// defaultOutputFlags classify which flag's value (or following positional)
// is an output path. Matches the sift-mcp catalog security.yaml.
var defaultOutputFlags = []string{"--csv", "--csvf", "-o", "--output", "--json", "--jsonl"}

// Parsed is the decomposed view of one command, evaluated as
// input.parsed by the Rego policies (SPEC §5).
type Parsed struct {
	Binary      string   `json:"binary"`
	Flags       []string `json:"flags"`        // normalized: "--output=/x" -> "--output"
	Paths       []string `json:"paths"`        // input paths, resolved absolute (lexically)
	OutputPaths []string `json:"output_paths"` // from output flags and > / >> redirects
	DevicePaths []string `json:"device_paths"` // /dev/* for devPathTools
	Args        []string `json:"args"`         // raw args (scanned by shell_metacharacters)
	Via         string   `json:"via"`          // "structured" | "shell" | "fallback"

	// Deny marks a decomposition-level structural denial that the Rego policies
	// cannot express: a malformed or excessively nested wrapper chain, a blocked
	// interpreter eval flag (python -c, perl -e), or an unmodeled exec mechanism
	// (xargs). EvaluateParsed denies any Parsed with Deny set, regardless of the
	// Rego decision. Not serialized into the policy input.
	Deny        bool     `json:"-"`
	DenyReasons []string `json:"-"`
}

func (p Parsed) toInput() map[string]any {
	return map[string]any{
		"binary":       p.Binary,
		"flags":        sliceAny(p.Flags),
		"paths":        sliceAny(p.Paths),
		"output_paths": sliceAny(p.OutputPaths),
		"device_paths": sliceAny(p.DevicePaths),
		"args":         sliceAny(p.Args),
	}
}

// looksLikePath matches sift-mcp generic.py's heuristic for "this argument
// is a filesystem path".
func looksLikePath(arg string) bool {
	return strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "..") || strings.Contains(arg, "/")
}

// resolveLexical makes a path absolute WITHOUT following symlinks. The
// paths refer to the backend container's filesystem, not the host's, so
// host symlink resolution would be wrong (and a host-information leak).
// Deliberate divergence from sift-mcp's Path.resolve(); the container
// boundary plus eBPF (Phase 3) is the real control for symlink games.
func resolveLexical(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

// DecomposeCommand ports sift-mcp parser.build_input_doc: classify a
// tokenized [binary, args...] command into flags / input paths / output
// paths / device paths.
func DecomposeCommand(command []string, outputFlags []string) Parsed {
	if len(command) == 0 {
		return Parsed{Via: "structured"}
	}
	if outputFlags == nil {
		outputFlags = defaultOutputFlags
	}
	outFlag := make(map[string]bool, len(outputFlags))
	for _, f := range outputFlags {
		outFlag[f] = true
	}

	// Strip any path prefix from the binary, as run_command does.
	binary := command[0]
	if i := strings.LastIndex(binary, "/"); i >= 0 {
		binary = binary[i+1:]
	}
	args := command[1:]

	p := Parsed{Binary: binary, Args: append([]string(nil), args...), Via: "structured"}

	// Normalized flag tokens: "--output=/x" -> "--output".
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flag, _, _ := strings.Cut(a, "=")
			p.Flags = append(p.Flags, flag)
		}
	}

	// Path-classification loop, mirroring security.validate_command.
	prevWasOutputFlag := false
	for _, arg := range args {
		// flag=value: classify the value portion as a path.
		if strings.Contains(arg, "=") && strings.HasPrefix(arg, "-") {
			flagPart, value, _ := strings.Cut(arg, "=")
			if value != "" && looksLikePath(value) {
				switch {
				case strings.HasPrefix(value, "/dev/") && devPathTools[binary]:
					p.DevicePaths = append(p.DevicePaths, value)
				case outFlag[flagPart]:
					p.OutputPaths = append(p.OutputPaths, resolveLexical(value))
				default:
					p.Paths = append(p.Paths, resolveLexical(value))
				}
			}
			prevWasOutputFlag = false
			continue
		}
		// bare flag: remember whether it expects an output path next.
		if strings.HasPrefix(arg, "-") {
			prevWasOutputFlag = outFlag[arg]
			continue
		}
		// positional: classify as device / output / input path.
		if looksLikePath(arg) {
			switch {
			case strings.HasPrefix(arg, "/dev/") && devPathTools[binary]:
				p.DevicePaths = append(p.DevicePaths, arg)
			case prevWasOutputFlag:
				p.OutputPaths = append(p.OutputPaths, resolveLexical(arg))
			default:
				p.Paths = append(p.Paths, resolveLexical(arg))
			}
		}
		prevWasOutputFlag = false
	}

	if binary == "rm" {
		// rm ALSO validates every non-flag arg as a deletion target, on
		// top of the path loop above — including no-slash relative ones.
		existing := make(map[string]bool, len(p.Paths))
		for _, path := range p.Paths {
			existing[path] = true
		}
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				rp := resolveLexical(arg)
				if !existing[rp] {
					p.Paths = append(p.Paths, rp)
					existing[rp] = true
				}
			}
		}
	}

	return p
}

// DecomposeShellLine parses a free-form shell command line into one Parsed
// per sub-command (pipes, &&, ||, ;, subshells, command substitutions all
// recurse). Each segment's Args additionally carries the original raw
// line, so the shell_metacharacters policy always sees the operators —
// compound free-form commands are deny-by-construction in this forensic
// profile, matching SPEC §6.
//
// On a parse failure (forensic one-liners can be unparseable), falls back
// to a literal operator split; the raw-line metachar scan means the
// fallback never weakens the deny, only path/flag extraction precision.
func DecomposeShellLine(line string, outputFlags []string) []Parsed {
	return decomposeShellLineDepth(line, outputFlags, 0)
}

// decomposeShellLineDepth is the depth-bounded core of DecomposeShellLine.
// depth increases through interpreter `-c` payloads and nested
// substitutions/subshells, so a pathological or hostile nesting is denied
// rather than parsed without limit.
func decomposeShellLineDepth(line string, outputFlags []string, depth int) []Parsed {
	if depth > maxWrapperDepth {
		return []Parsed{denyParsed("", "shell nesting exceeds limit", line)}
	}
	if len(line) > maxPayloadBytes {
		return []Parsed{denyParsed("", "shell line exceeds size limit", line)}
	}

	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(line), "command")
	if err != nil {
		return fallbackSplit(line, outputFlags, depth)
	}

	printer := syntax.NewPrinter()
	wordText := func(w *syntax.Word) string {
		var sb strings.Builder
		_ = printer.Print(&sb, w)
		return sb.String()
	}

	var out []Parsed
	substitutions := 0
	var walkStmt func(stmt *syntax.Stmt, depth int)
	walkStmt = func(stmt *syntax.Stmt, depth int) {
		if depth > maxWrapperDepth {
			out = append(out, denyParsed("", "shell nesting exceeds limit", line))
			return
		}
		// Redirect targets: > and >> are output paths attached to the
		// segment produced by this statement's command.
		var redirOutputs []string
		for _, r := range stmt.Redirs {
			op := r.Op.String()
			if (op == ">" || op == ">>") && r.Word != nil {
				redirOutputs = append(redirOutputs, resolveLexical(wordText(r.Word)))
			}
		}

		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Args) == 0 {
				return
			}
			tokens := make([]string, 0, len(cmd.Args))
			for _, w := range cmd.Args {
				tokens = append(tokens, wordText(w))
				// Command substitutions nest a full command — decompose
				// and evaluate the inner command too.
				for _, part := range w.Parts {
					if cs, ok := part.(*syntax.CmdSubst); ok {
						substitutions++
						if substitutions > maxSubstitutions {
							out = append(out, denyParsed("", "too many command substitutions", line))
							return
						}
						for _, inner := range cs.Stmts {
							walkStmt(inner, depth+1)
						}
					}
				}
			}
			// Normalize transparent wrappers / interpreter -c payloads, then
			// attach this statement's redirect outputs to the leading segment.
			ps := decomposeWrapped(tokens, outputFlags, line, depth)
			if len(ps) > 0 {
				ps[0].OutputPaths = append(ps[0].OutputPaths, redirOutputs...)
			}
			out = append(out, ps...)
		case *syntax.BinaryCmd: // |, &&, ||
			walkStmt(cmd.X, depth)
			walkStmt(cmd.Y, depth)
		case *syntax.Subshell:
			for _, inner := range cmd.Stmts {
				walkStmt(inner, depth+1)
			}
		case *syntax.Block:
			for _, inner := range cmd.Stmts {
				walkStmt(inner, depth+1)
			}
		}
	}
	for _, stmt := range file.Stmts {
		walkStmt(stmt, depth)
	}

	if len(out) == 0 {
		return fallbackSplit(line, outputFlags, depth)
	}
	return out
}

// shellOperators split a raw line in the fallback path.
var shellOperators = []string{"&&", "||", ";", "|", "\n", "&"}

// fallbackSplit is the sift-mcp-style degradation: split on shell
// operators literally (not quote-aware), tokenize each segment by fields.
// Transparent wrappers are still normalized so the fallback never weakens the
// deny relative to the AST path.
func fallbackSplit(line string, outputFlags []string, depth int) []Parsed {
	segments := []string{line}
	for _, op := range shellOperators {
		var next []string
		for _, seg := range segments {
			next = append(next, strings.Split(seg, op)...)
		}
		segments = next
	}

	var out []Parsed
	for _, seg := range segments {
		tokens := strings.Fields(seg)
		if len(tokens) == 0 {
			continue
		}
		ps := decomposeWrapped(tokens, outputFlags, line, depth)
		for i := range ps {
			ps[i].Via = "fallback"
		}
		out = append(out, ps...)
	}
	return out
}
