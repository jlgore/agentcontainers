package mcpproxy

import (
	"slices"
	"strings"
	"testing"
)

func TestDecomposeCommand_Structured(t *testing.T) {
	p := DecomposeCommand([]string{"find", "/evidence/disk1", "-name", "*.evtx"}, defaultOutputFlags)
	if p.Binary != "find" || p.Via != "structured" {
		t.Errorf("binary=%q via=%q", p.Binary, p.Via)
	}
	if !slices.Equal(p.Flags, []string{"-name"}) {
		t.Errorf("flags = %v", p.Flags)
	}
	if !slices.Equal(p.Paths, []string{"/evidence/disk1"}) {
		t.Errorf("paths = %v", p.Paths)
	}
}

func TestDecomposeCommand_FlagValueOutput(t *testing.T) {
	p := DecomposeCommand([]string{"tool", "--output=/etc/passwd"}, defaultOutputFlags)
	if !slices.Equal(p.Flags, []string{"--output"}) {
		t.Errorf("flags = %v, want normalized --output", p.Flags)
	}
	if !slices.Equal(p.OutputPaths, []string{"/etc/passwd"}) {
		t.Errorf("output_paths = %v", p.OutputPaths)
	}
	if len(p.Paths) != 0 {
		t.Errorf("paths = %v, want empty", p.Paths)
	}
}

func TestDecomposeCommand_DevPathTools(t *testing.T) {
	// fls is a device tool: /dev specifier goes to device_paths.
	p := DecomposeCommand([]string{"fls", "/dev/sda1"}, defaultOutputFlags)
	if !slices.Equal(p.DevicePaths, []string{"/dev/sda1"}) || len(p.Paths) != 0 {
		t.Errorf("fls: device=%v paths=%v", p.DevicePaths, p.Paths)
	}
	// strings is not: /dev path is a (blocked) input path.
	p = DecomposeCommand([]string{"strings", "/dev/sda"}, defaultOutputFlags)
	if len(p.DevicePaths) != 0 || !slices.Equal(p.Paths, []string{"/dev/sda"}) {
		t.Errorf("strings: device=%v paths=%v", p.DevicePaths, p.Paths)
	}
}

func TestDecomposeCommand_RmTargets(t *testing.T) {
	// rm collects ALL non-flag args as deletion targets, including
	// no-slash relative names the path heuristic would miss.
	p := DecomposeCommand([]string{"rm", "-f", "report.bin", "/cases/c/x"}, defaultOutputFlags)
	if len(p.Paths) != 2 {
		t.Fatalf("paths = %v, want 2 targets", p.Paths)
	}
	if !strings.HasSuffix(p.Paths[1], "/report.bin") && !strings.HasSuffix(p.Paths[0], "/report.bin") {
		t.Errorf("paths = %v, want resolved report.bin", p.Paths)
	}
}

func TestDecomposeCommand_BinaryPathPrefix(t *testing.T) {
	p := DecomposeCommand([]string{"/usr/sbin/mkfs", "/dev/sda1"}, defaultOutputFlags)
	if p.Binary != "mkfs" {
		t.Errorf("binary = %q, want mkfs", p.Binary)
	}
}

func TestDecomposeShellLine_PipeAndRedirect(t *testing.T) {
	line := `fls /cases/c/img.dd | grep evtx > /etc/out`
	parsed := DecomposeShellLine(line, defaultOutputFlags)
	if len(parsed) != 2 {
		t.Fatalf("got %d segments, want 2: %+v", len(parsed), parsed)
	}
	if parsed[0].Binary != "fls" || parsed[1].Binary != "grep" {
		t.Errorf("binaries = %q, %q", parsed[0].Binary, parsed[1].Binary)
	}
	if parsed[0].Via != "shell" {
		t.Errorf("via = %q", parsed[0].Via)
	}
	// The redirect target lands on the grep segment as an output path.
	if !slices.Contains(parsed[1].OutputPaths, "/etc/out") {
		t.Errorf("grep output_paths = %v, want /etc/out", parsed[1].OutputPaths)
	}
	// Both segments carry the raw line so the metachar scan sees the pipe.
	for i, p := range parsed {
		if !slices.Contains(p.Args, line) {
			t.Errorf("segment %d args missing raw line: %v", i, p.Args)
		}
	}
}

func TestDecomposeShellLine_Operators(t *testing.T) {
	parsed := DecomposeShellLine("ls /cases && rm -rf /evidence; cat /etc/shadow", defaultOutputFlags)
	if len(parsed) != 3 {
		t.Fatalf("got %d segments, want 3", len(parsed))
	}
	bins := []string{parsed[0].Binary, parsed[1].Binary, parsed[2].Binary}
	if !slices.Equal(bins, []string{"ls", "rm", "cat"}) {
		t.Errorf("binaries = %v", bins)
	}
	// rm segment must carry its deletion target.
	if !slices.Contains(parsed[1].Paths, "/evidence") {
		t.Errorf("rm paths = %v", parsed[1].Paths)
	}
}

func TestDecomposeShellLine_CommandSubstitution(t *testing.T) {
	parsed := DecomposeShellLine(`cat $(whoami)`, defaultOutputFlags)
	// Two segments: the inner whoami and the outer cat.
	var bins []string
	for _, p := range parsed {
		bins = append(bins, p.Binary)
	}
	if !slices.Contains(bins, "whoami") || !slices.Contains(bins, "cat") {
		t.Errorf("binaries = %v, want inner whoami + outer cat", bins)
	}
	// The raw line carries "$(" so shell_metacharacters fires.
	var hasRaw bool
	for _, p := range parsed {
		for _, a := range p.Args {
			if strings.Contains(a, "$(") {
				hasRaw = true
			}
		}
	}
	if !hasRaw {
		t.Error("no segment carries the $( marker")
	}
}

func TestDecomposeShellLine_QuotedMetachar(t *testing.T) {
	// A quoted ";" is one literal arg — no spurious second command — but
	// the raw line still trips the metachar scan.
	parsed := DecomposeShellLine(`sometool "--flag; rm -rf /"`, defaultOutputFlags)
	if len(parsed) != 1 {
		t.Fatalf("got %d segments, want 1 (quoted ; must not split)", len(parsed))
	}
	if parsed[0].Binary != "sometool" {
		t.Errorf("binary = %q", parsed[0].Binary)
	}
	var hasSemicolonArg bool
	for _, a := range parsed[0].Args {
		if strings.Contains(a, ";") {
			hasSemicolonArg = true
		}
	}
	if !hasSemicolonArg {
		t.Error("quoted metachar lost from args")
	}
}

func TestDecomposeShellLine_FallbackOnParseError(t *testing.T) {
	// Unbalanced quote: sh/v3 fails, the operator split takes over.
	line := `vol3 -f /cases/mem.raw "windows.pslist ; rm -rf /evidence`
	parsed := DecomposeShellLine(line, defaultOutputFlags)
	if len(parsed) == 0 {
		t.Fatal("fallback produced no segments")
	}
	for _, p := range parsed {
		if p.Via != "fallback" {
			t.Errorf("via = %q, want fallback", p.Via)
		}
		if !slices.Contains(p.Args, line) {
			t.Error("fallback segment missing raw line in args")
		}
	}
	if parsed[0].Binary != "vol3" {
		t.Errorf("binary = %q", parsed[0].Binary)
	}
}

func TestDecomposeShellLine_Subshell(t *testing.T) {
	parsed := DecomposeShellLine(`(cat /etc/shadow)`, defaultOutputFlags)
	if len(parsed) != 1 || parsed[0].Binary != "cat" {
		t.Fatalf("parsed = %+v, want inner cat", parsed)
	}
	if !slices.Contains(parsed[0].Paths, "/etc/shadow") {
		t.Errorf("paths = %v", parsed[0].Paths)
	}
}

func TestDecomposeCommand_Empty(t *testing.T) {
	p := DecomposeCommand(nil, nil)
	if p.Binary != "" || len(p.Args) != 0 {
		t.Errorf("empty command parsed = %+v", p)
	}
}
