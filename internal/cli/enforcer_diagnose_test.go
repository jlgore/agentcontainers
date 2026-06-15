package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestDiagnoseCommandStructure(t *testing.T) {
	cmd := newEnforcerDiagnoseCmd()

	if cmd.Use != "diagnose" {
		t.Errorf("expected Use %q, got %q", "diagnose", cmd.Use)
	}
}

func TestDiagnoseRegisteredInEnforcer(t *testing.T) {
	cmd := newEnforcerCmd()

	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Use == "diagnose" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'diagnose' subcommand registered on enforcer command")
	}
}

func TestDiagnoseOutputFormat(t *testing.T) {
	// The diagnose command should produce structured output with check names.
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"enforcer", "diagnose", "--skip-docker"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Should contain diagnostic check headers.
	checks := []string{
		"Kernel Version",
		"Cgroup Version",
		"BPF Support",
		"BPF LSM",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing check %q\noutput: %s", check, output)
		}
	}
}

func TestLsmListHasBPF(t *testing.T) {
	cases := []struct {
		list string
		want bool
	}{
		{"capability,landlock,lockdown,yama,bpf", true},
		{"bpf", true},
		{"capability, bpf", true}, // tolerates whitespace
		{"capability,landlock,lockdown,yama,apparmor", false},
		{"", false},
		{"bpffs", false}, // must be exact token, not a prefix match
	}
	for _, c := range cases {
		if got := lsmListHasBPF(c.list); got != c.want {
			t.Errorf("lsmListHasBPF(%q) = %v, want %v", c.list, got, c.want)
		}
	}
}

func TestCheckBPFLSMReportsValidStatus(t *testing.T) {
	// checkBPFLSM reads the host's real LSM list; assert it produces a
	// well-formed check (name + a recognized status) rather than a fixed value,
	// since the host kernel config varies.
	c := checkBPFLSM()
	if c.Name != "BPF LSM" {
		t.Errorf("Name = %q, want %q", c.Name, "BPF LSM")
	}
	switch c.Status {
	case "PASS", "FAIL", "WARN":
	default:
		t.Errorf("unexpected Status %q (detail: %q)", c.Status, c.Detail)
	}
}

func TestDiagnoseSkipDockerFlag(t *testing.T) {
	cmd := newEnforcerDiagnoseCmd()
	if err := cmd.ParseFlags([]string{"--skip-docker"}); err != nil {
		t.Fatalf("unexpected error parsing --skip-docker: %v", err)
	}

	skipVal, err := cmd.Flags().GetBool("skip-docker")
	if err != nil {
		t.Fatalf("unexpected error getting skip-docker flag: %v", err)
	}
	if !skipVal {
		t.Error("expected --skip-docker to be true")
	}
}

func TestDiagnoseDefaultFlags(t *testing.T) {
	cmd := newEnforcerDiagnoseCmd()
	if err := cmd.ParseFlags([]string{}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	skipVal, err := cmd.Flags().GetBool("skip-docker")
	if err != nil {
		t.Fatalf("unexpected error getting skip-docker flag: %v", err)
	}
	if skipVal {
		t.Error("expected --skip-docker to default to false")
	}
}

func TestDiagnoseContainsPlatformInfo(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"enforcer", "diagnose", "--skip-docker"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Platform") {
		t.Errorf("output missing Platform check\noutput: %s", output)
	}
	if !strings.Contains(output, "Nested Container") {
		t.Errorf("output missing Nested Container check\noutput: %s", output)
	}
}

func TestDiagnoseContainsSummary(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"enforcer", "diagnose", "--skip-docker"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Result:") {
		t.Errorf("output missing summary Result line\noutput: %s", output)
	}
}

func TestDiagnoseEnforcerHealthSkipped(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"enforcer", "diagnose", "--skip-docker"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Enforcer Health") {
		t.Errorf("output missing Enforcer Health check\noutput: %s", output)
	}
	if !strings.Contains(output, "SKIP") {
		t.Errorf("expected Enforcer Health to show SKIP when --skip-docker is set\noutput: %s", output)
	}
}
