package mcpproxy

import (
	"strings"
	"testing"
)

// binariesOf returns the binary of every decomposed segment.
func binariesOf(ps []Parsed) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Binary)
	}
	return out
}

// anyDenied reports whether any segment carries a decomposition-level deny.
func anyDenied(ps []Parsed) bool {
	for _, p := range ps {
		if p.Deny {
			return true
		}
	}
	return false
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestUnwrapTransparent(t *testing.T) {
	cases := []struct {
		name string
		bin  string
		args []string
		want []string
	}{
		{"env assignments", "env", []string{"FOO=bar", "BAZ=1", "bash", "-c", "x"}, []string{"bash", "-c", "x"}},
		{"env unset opt", "env", []string{"-u", "PATH", "python3", "-c", "x"}, []string{"python3", "-c", "x"}},
		{"env double dash", "env", []string{"--", "bash"}, []string{"bash"}},
		{"timeout duration", "timeout", []string{"5", "python3", "-c", "x"}, []string{"python3", "-c", "x"}},
		{"timeout signal+dur", "timeout", []string{"-s", "TERM", "5s", "bash", "-c", "x"}, []string{"bash", "-c", "x"}},
		{"timeout long signal", "timeout", []string{"--signal=TERM", "1.5h", "sh"}, []string{"sh"}},
		{"nice -n", "nice", []string{"-n", "10", "bash", "-c", "x"}, []string{"bash", "-c", "x"}},
		{"nice -N", "nice", []string{"-5", "bash"}, []string{"bash"}},
		{"nohup", "nohup", []string{"bash", "-c", "x"}, []string{"bash", "-c", "x"}},
		{"setsid", "setsid", []string{"-f", "bash"}, []string{"bash"}},
		{"exec -a", "exec", []string{"-a", "fake", "bash", "-c", "x"}, []string{"bash", "-c", "x"}},
		{"stdbuf -o sep", "stdbuf", []string{"-o", "0", "bash"}, []string{"bash"}},
		{"stdbuf attached", "stdbuf", []string{"-oL", "bash"}, []string{"bash"}},
		{"command", "command", []string{"-p", "bash", "-c", "x"}, []string{"bash", "-c", "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := unwrapTransparent(tc.bin, tc.args)
			if !ok {
				t.Fatalf("unwrapTransparent(%s, %v) returned not-ok", tc.bin, tc.args)
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("unwrapTransparent(%s, %v) = %v, want %v", tc.bin, tc.args, got, tc.want)
			}
		})
	}
}

func TestUnwrapTransparent_MalformedDenied(t *testing.T) {
	// -u expects an argument; none present.
	if _, ok := unwrapTransparent("env", []string{"-u"}); ok {
		t.Error("env -u with no argument should be malformed (not ok)")
	}
}

// TestWrapperBypassesAreDecomposed asserts the effective executable behind a
// transparent wrapper is surfaced and the interpreter eval flag is denied.
func TestWrapperBypassesAreDecomposed(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantBinary string // effective binary that must appear
		wantDeny   bool
	}{
		{"timeout python -c", "timeout 5 python3 -c 'import os'", "python3", true},
		{"env python -c", "env FOO=1 python3 -c 'x'", "python3", true},
		{"nohup nice perl -e", "nohup nice -n 5 perl -e 'system(1)'", "perl", true},
		{"env bash -c recurses", "env bash -c 'rm -rf /'", "rm", false},
		{"setsid node -e", "setsid node -e 'process.exit()'", "node", true},
		{"plain python no eval flag", "python3 script.py", "python3", false},
		{"xargs unmodeled", "xargs rm", "xargs", true},
		{"nested wrappers reach python", "timeout 5 nohup env stdbuf -oL python3 -c 'x'", "python3", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := DecomposeShellLine(tc.line, nil)
			if !contains(binariesOf(ps), tc.wantBinary) {
				t.Errorf("line %q: effective binary %q not surfaced; got %v", tc.line, tc.wantBinary, binariesOf(ps))
			}
			if anyDenied(ps) != tc.wantDeny {
				t.Errorf("line %q: deny = %v, want %v (segments %v)", tc.line, anyDenied(ps), tc.wantDeny, binariesOf(ps))
			}
		})
	}
}

// TestShellDashCRecursion confirms bash -c payloads are parsed recursively, so
// a blocked command inside the payload is surfaced.
func TestShellDashCRecursion(t *testing.T) {
	ps := DecomposeShellLine("bash -c 'timeout 5 python3 -c \"evil\"'", nil)
	bins := binariesOf(ps)
	if !contains(bins, "python3") {
		t.Errorf("nested -c payload not recursed; got %v", bins)
	}
	if !anyDenied(ps) {
		t.Errorf("python3 -c inside bash -c should be denied; got %v", bins)
	}
}

func TestDecompositionLimits(t *testing.T) {
	t.Run("deep wrapper nesting denied", func(t *testing.T) {
		// Build sh -c 'sh -c '...'' nested well past maxWrapperDepth.
		line := "echo ok"
		for i := 0; i < maxWrapperDepth+3; i++ {
			line = "sh -c " + shellQuote(line)
		}
		ps := DecomposeShellLine(line, nil)
		if !anyDenied(ps) {
			t.Errorf("deeply nested -c chain should be denied")
		}
	})

	t.Run("oversized payload denied", func(t *testing.T) {
		payload := strings.Repeat("a", maxPayloadBytes+1)
		ps := DecomposeShellLine("bash -c "+shellQuote(payload), nil)
		if !anyDenied(ps) {
			t.Errorf("oversized -c payload should be denied")
		}
	})
}

// TestBenignCommandsUnaffected guards against over-blocking ordinary commands.
func TestBenignCommandsUnaffected(t *testing.T) {
	for _, line := range []string{
		"ls -la /tmp",
		"git status",
		"grep -c foo file.txt", // -c is a count flag here, not a python eval flag
		"timeout 30 git fetch", // wrapper around a benign command
		"env FOO=bar ls",
	} {
		ps := DecomposeShellLine(line, nil)
		if anyDenied(ps) {
			t.Errorf("benign command %q was denied; segments %v", line, binariesOf(ps))
		}
	}
}

func TestHelperPredicates(t *testing.T) {
	if !isAssignment("FOO=bar") || isAssignment("=bar") || isAssignment("foo") || isAssignment("/a=b") {
		t.Error("isAssignment misclassified")
	}
	if !isDashNumber("-5") || isDashNumber("-n") || isDashNumber("5") {
		t.Error("isDashNumber misclassified")
	}
	if !isDurationish("5") || !isDurationish("1.5h") || !isDurationish("infinity") || isDurationish("python3") {
		t.Error("isDurationish misclassified")
	}
	if p, ok := extractDashC([]string{"-lc", "payload"}); !ok || p != "payload" {
		t.Errorf("extractDashC(-lc) = %q,%v", p, ok)
	}
	if _, ok := extractDashC([]string{"script.sh"}); ok {
		t.Error("extractDashC should not treat a script path as -c")
	}
}

// shellQuote single-quotes a string for embedding in a shell -c argument.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// FuzzDecomposeShellLine ensures decomposition terminates and never panics on
// arbitrary input, and that nested wrappers/substitutions stay within limits.
func FuzzDecomposeShellLine(f *testing.F) {
	seeds := []string{
		"ls -la",
		"env bash -c 'rm -rf /'",
		"timeout 5 python3 -c 'x'",
		"a $(b $(c $(d)))",
		"sh -c 'sh -c \"sh -c uname\"'",
		"nice -n 5 nohup setsid env FOO=1 perl -e 'x' | xargs rm",
		"'unbalanced",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		ps := DecomposeShellLine(line, nil)
		// Decomposition must not explode the segment count unboundedly.
		if len(ps) > maxCommandTokens {
			t.Fatalf("segment count %d exceeds bound for input %q", len(ps), line)
		}
	})
}
