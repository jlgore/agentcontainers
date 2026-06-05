//go:build linux

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
)

// startApprovalSession stands up a broker + socket with one pending request
// and returns the socket path plus the decision channel.
func startApprovalSession(t *testing.T) (string, *approval.ToolCallBroker, <-chan approval.ToolCallDecision) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ac-approve-cli-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	broker := approval.NewToolCallBroker(time.Minute)
	sock, err := approval.ListenSocket(filepath.Join(dir, "approval.sock"), broker)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	t.Cleanup(func() { _ = sock.Close() })

	done := make(chan approval.ToolCallDecision, 1)
	go func() {
		done <- broker.Request(context.Background(), approval.ToolCallRequest{
			ID: "req-1", Server: "sift-gateway", Tool: "run_privileged_command", ArgsSummary: "vol3 --write",
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(broker.Pending()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("request never became pending")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return sock.Path(), broker, done
}

func TestApproveList(t *testing.T) {
	path, _, _ := startApprovalSession(t)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--socket", path, "--list"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("approve --list: %v", err)
	}
	for _, want := range []string{"req-1", "sift-gateway", "run_privileged_command", "vol3 --write"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("list output missing %q:\n%s", want, out.String())
		}
	}
}

func TestApproveByID(t *testing.T) {
	path, _, done := startApprovalSession(t)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--socket", path, "req-1"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("approve req-1: %v", err)
	}
	d := <-done
	if !d.Approved {
		t.Fatalf("decision = %+v, want approved", d)
	}
}

func TestApproveDenyByID(t *testing.T) {
	path, _, done := startApprovalSession(t)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--socket", path, "req-1", "--deny", "--reason", "not during business hours"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("approve --deny: %v", err)
	}
	d := <-done
	if d.Approved || d.Reason != "not during business hours" {
		t.Fatalf("decision = %+v, want denial with reason", d)
	}
}

func TestApproveInteractive(t *testing.T) {
	path, _, done := startApprovalSession(t)

	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader("a\n"))
	cmd.SetArgs([]string{"--socket", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("approve interactive: %v", err)
	}
	d := <-done
	if !d.Approved {
		t.Fatalf("decision = %+v, want approved", d)
	}
}

func TestApproveNoSession(t *testing.T) {
	cmd := newApproveCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--socket", "/tmp/ac-approve-cli-nonexistent.sock", "--list"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected connection error with no running session")
	}
}
