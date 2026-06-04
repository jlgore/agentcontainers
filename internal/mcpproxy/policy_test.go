package mcpproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// compileCanonical compiles testdata/security.yaml (a copy of the sift-mcp
// catalog policy) the way a container server with securityYaml would.
func compileCanonical(t *testing.T, cfgPolicy *config.MCPServerPolicy) *CompiledPolicy {
	t.Helper()
	sec, err := LoadSecurityYAML("testdata/security.yaml")
	if err != nil {
		t.Fatalf("LoadSecurityYAML: %v", err)
	}
	cp, err := Compile(sec, cfgPolicy)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return cp
}

func newCanonicalEvaluator(t *testing.T) *Evaluator {
	t.Helper()
	cp := compileCanonical(t, nil)
	ev, err := NewEvaluator(t.Context(), "test-server", cp)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return ev
}

// buildTestInput assembles the SPEC §5 input document for one decomposed
// command.
func buildTestInput(p Parsed, caseDir, cwd string) map[string]any {
	return map[string]any{
		"server": "test-server",
		"tool":   "run_command",
		"args":   map[string]any{},
		"parsed": p.toInput(),
		"context": map[string]any{
			"case_dir": caseDir,
			"cwd":      cwd,
		},
	}
}

func TestCompile_PackageSelection(t *testing.T) {
	// security.yaml only: the 8 security packages.
	cp := compileCanonical(t, nil)
	if len(cp.PolicyPackages) != 8 {
		t.Errorf("packages = %v, want 8 security packages", cp.PolicyPackages)
	}
	if _, ok := cp.Modules["decision.rego"]; !ok {
		t.Error("decision.rego missing")
	}

	// shell + network policy adds the two native packages.
	cp = compileCanonical(t, &config.MCPServerPolicy{
		Shell:   &config.ShellCaps{Commands: []config.ShellCommand{{Binary: "fls"}}},
		Network: &config.NetworkCaps{Deny: []string{"0.0.0.0/0"}},
	})
	joined := strings.Join(cp.PolicyPackages, ",")
	if !strings.Contains(joined, "capabilities") || !strings.Contains(joined, "network") {
		t.Errorf("packages = %v, want capabilities and network included", cp.PolicyPackages)
	}
}

func TestCompile_Data(t *testing.T) {
	cp := compileCanonical(t, nil)

	denied, _ := cp.Data["denied_binaries"].([]string)
	if len(denied) == 0 {
		t.Fatalf("denied_binaries = %#v", cp.Data["denied_binaries"])
	}
	// Lowercased and sorted.
	for i, b := range denied {
		if b != strings.ToLower(b) {
			t.Errorf("denied_binaries[%d] = %q not lowercase", i, b)
		}
		if i > 0 && denied[i-1] > b {
			t.Errorf("denied_binaries not sorted at %d: %q > %q", i, denied[i-1], b)
		}
	}

	// Defaults applied: blocked input dirs include the base set + ~/.vhir.
	blocked := cp.Data["blocked_input_dirs"].([]any)
	var hasEtc, hasVhir bool
	for _, d := range blocked {
		s := d.(string)
		if s == "/etc" {
			hasEtc = true
		}
		if strings.HasSuffix(s, "/.vhir") {
			hasVhir = true
		}
	}
	if !hasEtc || !hasVhir {
		t.Errorf("blocked_input_dirs = %v, want /etc and ~/.vhir", blocked)
	}

	if len(cp.OutputFlags) == 0 {
		t.Error("OutputFlags empty")
	}
}

func TestCompileServerPolicy_NoPolicy(t *testing.T) {
	cp, err := CompileServerPolicy(config.MCPToolConfig{Type: "remote", URL: "http://h:1/mcp"}, t.TempDir())
	if err != nil {
		t.Fatalf("CompileServerPolicy: %v", err)
	}
	if cp != nil {
		t.Error("expected nil CompiledPolicy for a server with no evaluable policy")
	}

	// allowedTools alone is a Go-side gate, not a Rego compile.
	cp, err = CompileServerPolicy(config.MCPToolConfig{
		Type: "remote", URL: "http://h:1/mcp",
		Policy: &config.MCPServerPolicy{AllowedTools: []string{"x"}},
	}, t.TempDir())
	if err != nil || cp != nil {
		t.Errorf("allowedTools-only server: cp=%v err=%v, want nil/nil", cp, err)
	}
}

func TestCompileServerPolicy_ResolvesRelativeYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sec.yaml"), []byte("denied_binaries: [badbin]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cp, err := CompileServerPolicy(config.MCPToolConfig{
		Image:  "x:1",
		Policy: &config.MCPServerPolicy{SecurityYAML: "sec.yaml"},
	}, dir)
	if err != nil {
		t.Fatalf("CompileServerPolicy: %v", err)
	}
	denied := cp.Data["denied_binaries"].([]string)
	if len(denied) != 1 || denied[0] != "badbin" {
		t.Errorf("denied_binaries = %v", denied)
	}
}

func TestLoadSecurityYAML_UnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sec.yaml")
	if err := os.WriteFile(path, []byte("not_a_field: [x]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecurityYAML(path); err == nil {
		t.Error("expected unknown-field error")
	}
}

// parityCase ports one entry of the sift-mcp parity.py CURATED corpus.
type parityCase struct {
	command      []string
	category     string
	note         string
	requiresCase bool
}

// expectAllowed mirrors the corpus convention: notes containing "allowed"
// mark the cases security.py permits; everything else is a deny.
func (c parityCase) expectAllowed() bool {
	return strings.Contains(c.note, "allowed")
}

func parityCorpus(t *testing.T) []parityCase {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	vhir := filepath.Join(home, ".vhir")

	return []parityCase{
		// denied binaries (+ near-misses that must stay allowed)
		{command: []string{"mkfs", "/dev/sda1"}, category: "denied_binary"},
		{command: []string{"mkfs.ext4", "/dev/sda1"}, category: "denied_binary"},
		{command: []string{"/usr/sbin/mkfs", "/dev/sda1"}, category: "denied_binary", note: "path-prefixed"},
		{command: []string{"SHUTDOWN", "-h", "now"}, category: "denied_binary", note: "case-insensitive"},
		{command: []string{"kill", "-9", "1234"}, category: "denied_binary"},
		{command: []string{"nc", "-l", "4444"}, category: "denied_binary"},
		{command: []string{"env"}, category: "denied_binary"},
		{command: []string{"dd", "if=/cases/c/disk.img", "of=/tmp/out.img"}, category: "denied_binary", note: "dd allowed"},
		{command: []string{"fdisk", "-l"}, category: "denied_binary", note: "fdisk allowed"},
		{command: []string{"mount"}, category: "denied_binary", note: "mount allowed"},
		{command: []string{"strings", "/cases/c/file.bin"}, category: "denied_binary", note: "allowed"},
		// per-tool blocked flags
		{command: []string{"find", "/cases", "-name", "*.log", "-exec", "rm", "{}", "+"}, category: "tool_blocked_flags"},
		{command: []string{"find", "/cases", "-execdir", "cat", "{}", ";"}, category: "tool_blocked_flags"},
		{command: []string{"find", "/cases", "-name", "*.tmp", "-delete"}, category: "tool_blocked_flags"},
		{command: []string{"find", "/cases", "-fls", "/tmp/o"}, category: "tool_blocked_flags"},
		{command: []string{"find", "/cases", "-fprintf", "/tmp/o", "%p"}, category: "tool_blocked_flags"},
		{command: []string{"sed", "-i", "s/a/b/", "/cases/c/f.txt"}, category: "tool_blocked_flags"},
		{command: []string{"sed", "--in-place", "s/a/b/", "/cases/c/f.txt"}, category: "tool_blocked_flags"},
		{command: []string{"tar", "-x", "-f", "/cases/c/a.tar"}, category: "tool_blocked_flags"},
		{command: []string{"tar", "--delete", "-f", "/cases/c/a.tar"}, category: "tool_blocked_flags"},
		{command: []string{"unzip", "-o", "/cases/c/a.zip"}, category: "tool_blocked_flags"},
		{command: []string{"find", "/cases", "-name", "*.evtx", "-type", "f"}, category: "tool_blocked_flags", note: "allowed"},
		{command: []string{"sed", "s/a/b/", "/cases/c/f.txt"}, category: "tool_blocked_flags", note: "read-only allowed"},
		{command: []string{"tar", "-t", "-f", "/cases/c/a.tar"}, category: "tool_blocked_flags", note: "list allowed"},
		// global dangerous flags (+ exception that is dead in the live path)
		{command: []string{"sometool", "-e", "payload"}, category: "dangerous_flags"},
		{command: []string{"sometool", "--exec", "x"}, category: "dangerous_flags"},
		{command: []string{"sometool", "--command", "x"}, category: "dangerous_flags"},
		{command: []string{"pwsh", "-enc", "AAAA"}, category: "dangerous_flags"},
		{command: []string{"sometool", "--script", "x"}, category: "dangerous_flags"},
		{command: []string{"bulk_extractor", "-e", "email", "-o", "/tmp/o"}, category: "dangerous_flags", note: "dead exception → both deny"},
		{command: []string{"grep", "-r", "pattern", "/cases/c"}, category: "dangerous_flags", note: "benign allowed"},
		// shell metacharacters
		{command: []string{"sometool", "--flag; rm -rf /"}, category: "shell_metacharacters"},
		{command: []string{"sometool", "$(whoami)"}, category: "shell_metacharacters"},
		{command: []string{"sometool", "a&&b"}, category: "shell_metacharacters"},
		{command: []string{"sometool", "a||b"}, category: "shell_metacharacters"},
		{command: []string{"sometool", "`id`"}, category: "shell_metacharacters"},
		{command: []string{"sometool", "${HOME}"}, category: "shell_metacharacters"},
		{command: []string{"grep", "foo", "/cases/c/f"}, category: "shell_metacharacters", note: "clean allowed"},
		// awk program text
		{command: []string{"awk", `{system("id")}`, "/cases/c/f"}, category: "awk_scanning"},
		{command: []string{"gawk", "/x/{getline}", "/cases/c/f"}, category: "awk_scanning"},
		{command: []string{"awk", `{print > "/tmp/x"}`, "/cases/c/f"}, category: "awk_scanning", note: "redirect"},
		{command: []string{"awk", `{print $1 | "sort"}`, "/cases/c/f"}, category: "awk_scanning", note: "pipe"},
		{command: []string{"awk", "{print $1}", "/cases/c/f"}, category: "awk_scanning", note: "benign allowed"},
		{command: []string{"awk", "BEGIN{x=1}", "/cases/c/f"}, category: "awk_scanning", note: "benign allowed"},
		// input path validation
		{command: []string{"strings", "/etc/shadow"}, category: "input_path"},
		{command: []string{"cat", "/proc/1/cmdline"}, category: "input_path"},
		{command: []string{"cat", "/sys/class/net"}, category: "input_path"},
		{command: []string{"strings", "/dev/sda"}, category: "input_path", note: "non-dev tool → blocked"},
		{command: []string{"cat", "/boot/vmlinuz"}, category: "input_path"},
		{command: []string{"cat", vhir + "/config"}, category: "input_path", note: "~/.vhir blocked"},
		{command: []string{"cat", vhir + "/cases/c/f"}, category: "input_path", note: "~/.vhir/cases exception → allowed"},
		{command: []string{"cat", vhir + "/hayabusa-output/r.json"}, category: "input_path", note: "exception → allowed"},
		{command: []string{"strings", "/cases/c/image.E01"}, category: "input_path", note: "allowed"},
		{command: []string{"strings", "/opt/tools/x"}, category: "input_path", note: "allowed"},
		{command: []string{"strings", "/home/u/evidence/d.dd"}, category: "input_path", note: "allowed"},
		{command: []string{"strings", "/var/log/syslog"}, category: "input_path", note: "allowed"},
		{command: []string{"strings", "/usr/bin/ls"}, category: "input_path", note: "allowed"},
		// /dev device tools
		{command: []string{"fls", "/dev/sda1"}, category: "dev_tool", note: "allowed"},
		{command: []string{"mmls", "/dev/nvme0n1"}, category: "dev_tool", note: "allowed"},
		{command: []string{"icat", "/dev/sda1", "5"}, category: "dev_tool", note: "allowed"},
		// flag=value forms
		{command: []string{"tool", "--input=/etc/shadow"}, category: "flag_value"},
		{command: []string{"tool", "--input=/cases/c/e.img"}, category: "flag_value", note: "allowed"},
		{command: []string{"tool", "--output=/etc/passwd"}, category: "flag_value", note: "output blocked"},
		{command: []string{"tool", "--csv=/tmp/o.csv"}, category: "flag_value", note: "output to /tmp allowed"},
		// output path (no active case)
		{command: []string{"tool", "-o", "/etc/passwd"}, category: "output_path"},
		{command: []string{"tool", "-o", "/usr/local/bin/x"}, category: "output_path"},
		{command: []string{"tool", "--csv", "/var/spool/x"}, category: "output_path"},
		{command: []string{"tool", "-o", "/opt/sneaky/o.csv"}, category: "output_path", note: "no case → blocked"},
		{command: []string{"tool", "-o", "/tmp/o.csv"}, category: "output_path", note: "/tmp allowed"},
		// rm protection (static dirs)
		{command: []string{"rm", "-rf", "/cases"}, category: "rm_protection"},
		{command: []string{"rm", "/cases/c/file.txt"}, category: "rm_protection"},
		{command: []string{"rm", "/evidence/disk.dd"}, category: "rm_protection"},
		{command: []string{"rm", "-rf", "/"}, category: "rm_protection", note: "root"},
		{command: []string{"rm", "/tmp/output.csv"}, category: "rm_protection", note: "/tmp allowed"},
		{command: []string{"rm", "-f", "/opt/work/temp.txt"}, category: "rm_protection", note: "allowed"},
		// output path / rm with an active case
		{command: []string{"tool", "-o", "OUTPUT_INSIDE"}, category: "output_path_case", note: "inside case → allowed", requiresCase: true},
		{command: []string{"tool", "-o", "/tmp/out.csv"}, category: "output_path_case", note: "outside case → blocked", requiresCase: true},
		{command: []string{"rm", "RM_INSIDE_CASE"}, category: "rm_case", note: "rm in case dir → blocked", requiresCase: true},
	}
}

// TestParityCorpus runs the curated sift-mcp parity corpus against the
// compiled policies: decompose → evaluate → compare the boolean verdict
// with security.py's documented behavior.
func TestParityCorpus(t *testing.T) {
	ev := newCanonicalEvaluator(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	caseDir := t.TempDir()

	for _, tc := range parityCorpus(t) {
		name := tc.category + "/" + strings.Join(tc.command, "_")
		t.Run(name, func(t *testing.T) {
			cmd := make([]string, len(tc.command))
			for i, tok := range tc.command {
				switch tok {
				case "OUTPUT_INSIDE":
					cmd[i] = filepath.Join(caseDir, "out", "o.csv")
				case "RM_INSIDE_CASE":
					cmd[i] = filepath.Join(caseDir, "f.txt")
				default:
					cmd[i] = tok
				}
			}
			activeCase := ""
			if tc.requiresCase {
				activeCase = caseDir
			}

			parsed := DecomposeCommand(cmd, defaultOutputFlags)
			d, err := ev.Evaluate(t.Context(), buildTestInput(parsed, activeCase, cwd))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if d.Allowed != tc.expectAllowed() {
				t.Errorf("command %q: allowed=%v want %v (reasons: %v)",
					strings.Join(cmd, " "), d.Allowed, tc.expectAllowed(), d.Reasons)
			}
		})
	}
}

// TestSpecDenialExample asserts the SPEC §6 example: find -exec with a
// shell metacharacter denies with both prefixed reasons.
func TestSpecDenialExample(t *testing.T) {
	ev := newCanonicalEvaluator(t)
	cwd, _ := os.Getwd()

	parsed := DecomposeCommand([]string{"find", "/evidence", "-exec", "rm", "{}", ";"}, defaultOutputFlags)
	d, err := ev.Evaluate(t.Context(), buildTestInput(parsed, "", cwd))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Allowed {
		t.Fatal("expected deny")
	}
	var hasFlagReason, hasMetaReason bool
	for _, r := range d.Reasons {
		if strings.HasPrefix(r, "sift.tool_blocked_flags:") && strings.Contains(r, "-exec") {
			hasFlagReason = true
		}
		if strings.HasPrefix(r, "sift.shell_metacharacters:") && strings.Contains(r, "';'") {
			hasMetaReason = true
		}
	}
	if !hasFlagReason || !hasMetaReason {
		t.Errorf("reasons = %v, want tool_blocked_flags(-exec) and shell_metacharacters(;)", d.Reasons)
	}
	if len(d.PoliciesEvaluated) != 8 {
		t.Errorf("policiesEvaluated = %v", d.PoliciesEvaluated)
	}
	for _, p := range d.PoliciesEvaluated {
		if !strings.HasPrefix(p, "sift.") {
			t.Errorf("package %q missing sift. prefix", p)
		}
	}
}

// TestCapabilitiesPackage exercises the agentcontainers-native allowlist +
// denyArgs package sourced from agentcontainer.json.
func TestCapabilitiesPackage(t *testing.T) {
	cp := compileCanonical(t, &config.MCPServerPolicy{
		Shell: &config.ShellCaps{Commands: []config.ShellCommand{
			{Binary: "fls"},
			{Binary: "find", DenyArgs: []string{"-exec", "-delete"}},
		}},
	})
	ev, err := NewEvaluator(t.Context(), "test-server", cp)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	cwd, _ := os.Getwd()

	// Binary not in the allowlist denies.
	parsed := DecomposeCommand([]string{"strings", "/cases/c/x"}, defaultOutputFlags)
	d, err := ev.Evaluate(t.Context(), buildTestInput(parsed, "", cwd))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Error("expected deny: strings not in allowlist")
	}
	var found bool
	for _, r := range d.Reasons {
		if strings.HasPrefix(r, "sift.capabilities:") && strings.Contains(r, "allowlist") {
			found = true
		}
	}
	if !found {
		t.Errorf("reasons = %v, want sift.capabilities allowlist reason", d.Reasons)
	}

	// Allowlisted binary with a denied arg denies via capabilities too.
	parsed = DecomposeCommand([]string{"find", "/cases", "-delete"}, defaultOutputFlags)
	d, err = ev.Evaluate(t.Context(), buildTestInput(parsed, "", cwd))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Error("expected deny: -delete in denyArgs")
	}

	// Allowlisted binary, clean args: allowed.
	parsed = DecomposeCommand([]string{"fls", "/cases/c/img.dd"}, defaultOutputFlags)
	d, err = ev.Evaluate(t.Context(), buildTestInput(parsed, "", cwd))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Errorf("expected allow, reasons: %v", d.Reasons)
	}
}

// TestFilesystemPackage exercises the agentcontainers-native filesystem
// policy (SPEC §4 example shapes: plain prefixes and globs).
func TestFilesystemPackage(t *testing.T) {
	cp := compileCanonical(t, &config.MCPServerPolicy{
		Filesystem: &config.FilesystemCaps{
			Read:  []string{"/evidence", "/opt", "/usr"},
			Write: []string{"/cases/*/extractions", "/tmp"},
			Deny:  []string{"/etc/shadow", "/proc/*/mem"},
		},
	})
	if !slicesContains(cp.PolicyPackages, "filesystem") {
		t.Fatalf("packages = %v, want filesystem included", cp.PolicyPackages)
	}
	ev, err := NewEvaluator(t.Context(), "test-server", cp)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	cwd, _ := os.Getwd()

	eval := func(t *testing.T, cmd []string) Decision {
		t.Helper()
		parsed := DecomposeCommand(cmd, defaultOutputFlags)
		d, err := ev.Evaluate(t.Context(), buildTestInput(parsed, "", cwd))
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		return d
	}
	wantFsReason := func(t *testing.T, d Decision, fragment string) {
		t.Helper()
		if d.Allowed {
			t.Fatalf("expected deny, reasons: %v", d.Reasons)
		}
		for _, r := range d.Reasons {
			if strings.HasPrefix(r, "sift.filesystem:") && strings.Contains(r, fragment) {
				return
			}
		}
		t.Errorf("reasons = %v, want sift.filesystem reason containing %q", d.Reasons, fragment)
	}

	// Deny pattern, plain path. (path_policy would also block /etc — the
	// filesystem reason must be independently present.)
	wantFsReason(t, eval(t, []string{"strings", "/etc/shadow"}), "denied by filesystem policy")

	// Deny pattern with glob: /proc/*/mem.
	wantFsReason(t, eval(t, []string{"strings", "/proc/1234/mem"}), "'/proc/*/mem'")

	// Read allowlist: a read outside the allowlist denies.
	wantFsReason(t, eval(t, []string{"strings", "/cases/c/file.bin"}), "outside the filesystem read allowlist")

	// Read inside the allowlist: allowed.
	if d := eval(t, []string{"strings", "/evidence/disk1/img.E01"}); !d.Allowed {
		t.Errorf("read inside allowlist denied: %v", d.Reasons)
	}

	// Write allowlist: a glob descendant passes the FILESYSTEM package
	// (the sift-level output_path_policy still denies it without an
	// active case — layered policies stay independent).
	d := eval(t, []string{"tool", "-o", "/cases/INC-42/extractions/out.csv"})
	for _, r := range d.Reasons {
		if strings.HasPrefix(r, "sift.filesystem:") {
			t.Errorf("write inside glob allowlist denied by filesystem package: %v", r)
		}
	}
	wantFsReason(t, eval(t, []string{"tool", "-o", "/evidence/out.csv"}), "outside the filesystem write allowlist")

	// Device paths are exempt from the read allowlist.
	if d := eval(t, []string{"fls", "/dev/sda1"}); !d.Allowed {
		t.Errorf("device path denied by read allowlist: %v", d.Reasons)
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestEmptyParsedIsNoOp: a non-shell tool (e.g. record_finding) evaluates
// with an empty parsed document — no security package fires.
func TestEmptyParsedIsNoOp(t *testing.T) {
	ev := newCanonicalEvaluator(t)
	d, err := ev.Evaluate(t.Context(), buildTestInput(Parsed{}, "", "/work"))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Errorf("empty parsed must allow, reasons: %v", d.Reasons)
	}
}
