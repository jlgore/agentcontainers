package container

import (
	"context"
	"testing"

	"github.com/moby/moby/client"
	"go.uber.org/zap/zaptest"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
)

func TestAppleVMRuntime_InterfaceCompliance(t *testing.T) {
	var _ Runtime = (*SandboxRuntime)(nil)
	rt, err := NewAppleVMRuntime(WithAppleVMClient(&mockSandboxAPI{}))
	if err != nil {
		t.Fatalf("NewAppleVMRuntime: %v", err)
	}
	var _ Runtime = rt
}

// TestAppleVMRuntime_StartIdentity verifies the applevm runtime overrides the
// sandbox identity: acvm- VM name prefix, docker-in-docker default image, and
// the RuntimeAppleVM session tag.
func TestAppleVMRuntime_StartIdentity(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, req *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			if req.VMName != "acvm-test-agent" {
				t.Errorf("expected VM name acvm-test-agent, got %s", req.VMName)
			}
			return &sandbox.VMCreateResponse{
				VMID:     "avm-abc123",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/applevm/avm-abc123/docker.sock"},
				Started:  true,
			}, nil
		},
	}

	// Capture the image used to create the agent container.
	var createdImage string
	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{
			containerCreateFn: func(_ context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
				if opts.Config != nil {
					createdImage = opts.Config.Image
				}
				return client.ContainerCreateResult{ID: "ctr-1"}, nil
			},
		}, nil
	}

	rt, err := NewAppleVMRuntime(
		WithAppleVMLogger(logger),
		WithAppleVMClient(mock),
		WithAppleVMSandboxOptions(WithDockerClientFactory(factory)),
	)
	if err != nil {
		t.Fatalf("NewAppleVMRuntime: %v", err)
	}

	cfg := &config.AgentContainer{Name: "test-agent"} // no Image -> default
	session, err := rt.Start(context.Background(), cfg, StartOptions{WorkspacePath: "/home/user/project"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if session.RuntimeType != RuntimeAppleVM {
		t.Errorf("expected RuntimeType %q, got %q", RuntimeAppleVM, session.RuntimeType)
	}
	if session.Name != "acvm-test-agent" {
		t.Errorf("expected Name acvm-test-agent, got %s", session.Name)
	}
	if createdImage != defaultAppleVMImage {
		t.Errorf("expected default image %q, got %q", defaultAppleVMImage, createdImage)
	}
}

// TestAppleVMRuntime_ListFilters verifies List only returns VMs with the acvm-
// prefix, so it never cross-lists Docker Sandbox ("ac-") VMs on a shared host.
func TestAppleVMRuntime_ListFilters(t *testing.T) {
	mock := &mockSandboxAPI{
		listVMsFn: func(_ context.Context) ([]sandbox.VMListEntry, error) {
			return []sandbox.VMListEntry{
				{VMID: "avm-1", VMName: "acvm-agent-1", Status: "running", Active: true},
				{VMID: "vm-2", VMName: "ac-sandbox-agent", Status: "running", Active: true},
				{VMID: "x-3", VMName: "unrelated", Status: "running", Active: true},
			}, nil
		},
	}

	rt, err := NewAppleVMRuntime(WithAppleVMClient(mock))
	if err != nil {
		t.Fatalf("NewAppleVMRuntime: %v", err)
	}

	sessions, err := rt.List(context.Background(), true)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session (acvm- prefixed only), got %d", len(sessions))
	}
	if sessions[0].Name != "acvm-agent-1" {
		t.Errorf("expected acvm-agent-1, got %s", sessions[0].Name)
	}
	if sessions[0].RuntimeType != RuntimeAppleVM {
		t.Errorf("expected RuntimeType %q, got %q", RuntimeAppleVM, sessions[0].RuntimeType)
	}
}
