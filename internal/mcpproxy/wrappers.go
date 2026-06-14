package mcpproxy

import "strings"

// Resource limits for command decomposition. Wrapper/interpreter nesting,
// per-command token counts, and -c payload sizes are bounded so a hostile or
// pathological command cannot exhaust CPU or stack during policy evaluation.
const (
	maxWrapperDepth  = 12
	maxCommandTokens = 4096
	maxPayloadBytes  = 1 << 16 // 64 KiB
	maxSubstitutions = 64      // command substitutions / subshells per line
)

// wrapperSpec describes how to skip a transparent wrapper's own options and
// arguments to reach the effective command it ultimately executes.
type wrapperSpec struct {
	// argFlags consume the following token as their value (e.g. env -u NAME).
	argFlags map[string]bool
	// splitFlags carry a whole command as their value, which env splits on
	// whitespace and executes (env -S 'python3 -c ...'). The value is the
	// effective command, not an ignored option argument.
	splitFlags map[string]bool
	// allowAssignments permits leading VAR=val assignments (env).
	allowAssignments bool
	// numericPositional consumes one leading numeric/duration positional as a
	// wrapper argument rather than the command (timeout DURATION).
	numericPositional bool
	// numericOption treats a leading "-<number>" as a wrapper option (nice -5).
	numericOption bool
}

func flagSet(flags ...string) map[string]bool {
	m := make(map[string]bool, len(flags))
	for _, f := range flags {
		m[f] = true
	}
	return m
}

// transparentWrappers run another command with the same effect as running it
// directly; the effective executable must be evaluated, not just the wrapper.
var transparentWrappers = map[string]*wrapperSpec{
	"env":     {allowAssignments: true, argFlags: flagSet("-u", "--unset", "-C", "--chdir"), splitFlags: flagSet("-S", "--split-string")},
	"nohup":   {},
	"setsid":  {}, // -w/-f/-c are no-arg flags
	"command": {}, // -p/-v/-V are no-arg flags
	"builtin": {},
	"exec":    {argFlags: flagSet("-a")}, // -c/-l are no-arg flags
	"nice":    {argFlags: flagSet("-n", "--adjustment"), numericOption: true},
	"timeout": {argFlags: flagSet("-s", "--signal", "-k", "--kill-after"), numericPositional: true},
	"stdbuf":  {argFlags: flagSet("-i", "--input", "-o", "--output", "-e", "--error")},
}

// shellInterpreters take a -c string payload that is itself a shell program and
// must be parsed recursively.
var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "ash": true, "ksh": true, "zsh": true,
}

// interpreterEvalFlags map a language evaluator to the flags that execute
// inline source. We do not parse the language source — we deny the eval flag.
var interpreterEvalFlags = map[string]map[string]bool{
	"python":  flagSet("-c"),
	"python2": flagSet("-c"),
	"python3": flagSet("-c"),
	"perl":    flagSet("-e", "-E"),
	"ruby":    flagSet("-e"),
	"node":    flagSet("-e", "--eval", "-p", "--print"),
	"nodejs":  flagSet("-e", "--eval", "-p", "--print"),
	"php":     flagSet("-r"),
}

// unmodeledExecMechanisms run other programs in ways this decomposer does not
// model (argument templating, -exec, etc.). They are denied by default until
// explicitly modeled, so they cannot be used to launder a blocked command.
var unmodeledExecMechanisms = map[string]bool{
	"xargs": true, "parallel": true,
}

// isAssignment reports whether tok is a shell VAR=value assignment.
func isAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	if eq <= 0 {
		return false
	}
	name := tok[:eq]
	for i, r := range name {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// isDashNumber reports whether tok is "-<digits>" (a nice priority option).
func isDashNumber(tok string) bool {
	if len(tok) < 2 || tok[0] != '-' {
		return false
	}
	for _, r := range tok[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isDurationish reports whether tok looks like a timeout DURATION (a number,
// optionally fractional, optionally with an s/m/h/d suffix) or "infinity".
func isDurationish(tok string) bool {
	if tok == "infinity" {
		return true
	}
	s := strings.TrimRight(tok, "smhd")
	seenDigit := false
	seenDot := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			seenDigit = true
		case r == '.' && !seenDot:
			seenDot = true
		default:
			return false
		}
	}
	return seenDigit
}

// unwrapTransparent skips a transparent wrapper's own options/arguments and
// returns the effective command tokens. ok is false only when the wrapper usage
// is malformed (e.g. an arg-taking option with no argument). An empty effective
// slice with ok=true means the wrapper had no following command (e.g. bare
// `env`), which is harmless.
func unwrapTransparent(bin string, args []string) (effective []string, ok bool) {
	spec := transparentWrappers[bin]
	numericPositionalLeft := spec.numericPositional
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--":
			i++
			return args[i:], true
		case spec.allowAssignments && isAssignment(a):
			i++
		case spec.numericOption && isDashNumber(a):
			i++
		case strings.HasPrefix(a, "--") && strings.Contains(a, "="):
			i++ // attached long option --flag=value
		case strings.HasPrefix(a, "-") && a != "-":
			flag := a
			i++
			if spec.argFlags[flag] {
				if i >= len(args) {
					return nil, false // option expects an argument that is absent
				}
				i++
			}
		case numericPositionalLeft && isDurationish(a):
			numericPositionalLeft = false
			i++
		default:
			return args[i:], true // first token that is not wrapper machinery
		}
	}
	return nil, true // wrapper with no following command
}

// extractDashC finds an interpreter -c payload (including short-option clusters
// like -lc) and returns the following token. ok is false when there is no -c or
// it has no payload.
func extractDashC(args []string) (payload string, ok bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		isC := a == "-c" ||
			(strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") &&
				len(a) > 1 && strings.HasSuffix(a, "c") && !strings.Contains(a, "="))
		if isC {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if !strings.HasPrefix(a, "-") {
			return "", false // first positional (e.g. a script path) — not -c
		}
	}
	return "", false
}

// unquoteCArg removes one layer of shell quoting from an interpreter -c payload
// so it can be re-parsed as a shell program. Handles the common single-quoted
// and double-quoted forms; anything else is returned unchanged (the recursive
// parse and the raw-line metacharacter scan still apply).
func unquoteCArg(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	switch s[0] {
	case '\'':
		if s[len(s)-1] == '\'' {
			inner := s[1 : len(s)-1]
			return strings.ReplaceAll(inner, `'\''`, "'")
		}
	case '"':
		if s[len(s)-1] == '"' {
			inner := s[1 : len(s)-1]
			inner = strings.ReplaceAll(inner, `\"`, `"`)
			inner = strings.ReplaceAll(inner, "\\`", "`")
			inner = strings.ReplaceAll(inner, "\\$", "$")
			inner = strings.ReplaceAll(inner, `\\`, `\`)
			return inner
		}
	}
	return s
}

// blockedEvalFlag reports whether any raw argument is a blocked interpreter
// eval flag, matching exact (`-c`, `--eval`), attached short (`-c'print(1)'` →
// token `-cprint(1)`), and attached long (`--eval=...`) forms. Operating on the
// raw args (not normalized Parsed.Flags) is what catches the attached forms.
func blockedEvalFlag(args []string, blocked map[string]bool) (string, bool) {
	for _, a := range args {
		if blocked[a] {
			return a, true
		}
		if strings.HasPrefix(a, "--") {
			if name, _, found := strings.Cut(a, "="); found && blocked[name] {
				return name, true
			}
			continue
		}
		// Attached short form: "-c<payload>" → blocked if "-c" is blocked.
		if len(a) > 2 && a[0] == '-' {
			if short := a[:2]; blocked[short] {
				return short, true
			}
		}
	}
	return "", false
}

// extractSplitString finds a split-string flag (env -S / --split-string) and
// returns its still-quoted value, which is a whole command. ok is false when
// the wrapper declares no split flags or none is present.
func extractSplitString(bin string, args []string) (value string, ok bool) {
	spec := transparentWrappers[bin]
	if spec == nil || len(spec.splitFlags) == 0 {
		return "", false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--") && strings.Contains(a, "="):
			if name, val, _ := strings.Cut(a, "="); spec.splitFlags[name] {
				return val, true
			}
		case spec.splitFlags[a]: // "-S value" (separate token)
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case len(a) > 2 && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && spec.splitFlags[a[:2]]:
			return a[2:], true // attached "-Svalue"
		}
	}
	return "", false
}

// denyParsed builds a decomposition-level structural deny for a command segment
// that cannot be safely evaluated (malformed/over-nested wrapper chain, blocked
// interpreter eval flag, unmodeled exec mechanism).
func denyParsed(binary, reason, rawLine string) Parsed {
	return Parsed{
		Binary:      binary,
		Via:         "shell",
		Args:        []string{rawLine},
		Deny:        true,
		DenyReasons: []string{reason},
	}
}

// decomposeWrapped decomposes a tokenized command and normalizes transparent
// wrappers and interpreters: it always evaluates the command as written, and
// additionally evaluates the effective executable behind a wrapper, the shell
// program behind an interpreter `-c`, blocked interpreter eval flags, and
// unmodeled exec mechanisms. rawLine is carried in Args for the metacharacter
// scan; depth bounds wrapper/interpreter recursion.
func decomposeWrapped(command []string, outputFlags []string, rawLine string, depth int) []Parsed {
	if depth > maxWrapperDepth {
		return []Parsed{denyParsed("", "wrapper/interpreter nesting exceeds limit", rawLine)}
	}
	if len(command) == 0 {
		return nil
	}
	if len(command) > maxCommandTokens {
		return []Parsed{denyParsed(command[0], "command token count exceeds limit", rawLine)}
	}

	p := DecomposeCommand(command, outputFlags)
	p.Via = "shell"
	p.Args = append(p.Args, rawLine)
	bin := p.Binary
	out := []Parsed{p}

	switch {
	case transparentWrappers[bin] != nil:
		// env -S 'cmd ...' carries the command in the split-string value; parse
		// it as a shell program so the effective executable is evaluated.
		if val, ok := extractSplitString(bin, command[1:]); ok {
			payload := unquoteCArg(val)
			if len(payload) > maxPayloadBytes {
				out = append(out, denyParsed(bin, "split-string payload exceeds size limit", rawLine))
			} else {
				out = append(out, decomposeShellLineDepth(payload, outputFlags, depth+1)...)
			}
			return out
		}
		effective, ok := unwrapTransparent(bin, command[1:])
		if !ok {
			out[0].Deny = true
			out[0].DenyReasons = append(out[0].DenyReasons, "malformed "+bin+" wrapper command")
			return out
		}
		if len(effective) > 0 {
			out = append(out, decomposeWrapped(effective, outputFlags, rawLine, depth+1)...)
		}
	case shellInterpreters[bin]:
		if payload, ok := extractDashC(command[1:]); ok {
			payload = unquoteCArg(payload)
			if len(payload) > maxPayloadBytes {
				out = append(out, denyParsed(bin, "shell -c payload exceeds size limit", rawLine))
			} else {
				out = append(out, decomposeShellLineDepth(payload, outputFlags, depth+1)...)
			}
		}
	case interpreterEvalFlags[bin] != nil:
		if f, ok := blockedEvalFlag(command[1:], interpreterEvalFlags[bin]); ok {
			out[0].Deny = true
			out[0].DenyReasons = append(out[0].DenyReasons,
				"blocked eval flag "+f+" on interpreter "+bin)
		}
	case unmodeledExecMechanisms[bin]:
		out[0].Deny = true
		out[0].DenyReasons = append(out[0].DenyReasons,
			"execution mechanism "+bin+" is not modeled and is denied by default")
	}
	return out
}
