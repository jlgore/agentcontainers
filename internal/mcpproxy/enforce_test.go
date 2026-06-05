package mcpproxy

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
)

func TestTranslateNetworkCaps(t *testing.T) {
	tests := []struct {
		name        string
		policy      *config.MCPServerPolicy
		wantHosts   []string
		wantEgress  int
		wantDefProt string
	}{
		{
			name:   "nil policy is default-deny (empty request)",
			policy: nil,
		},
		{
			name:   "nil network is default-deny",
			policy: &config.MCPServerPolicy{},
		},
		{
			name: "port rules become egress tuples, default tcp",
			policy: &config.MCPServerPolicy{Network: &config.NetworkCaps{
				Egress: []config.EgressRule{
					{Host: "intel.example.com", Port: 443},
					{Host: "10.0.0.5", Port: 53, Protocol: "udp"},
				},
			}},
			wantEgress:  2,
			wantDefProt: "tcp",
		},
		{
			name: "port-less rules become host allows",
			policy: &config.MCPServerPolicy{Network: &config.NetworkCaps{
				Egress: []config.EgressRule{{Host: "ghcr.io"}},
			}},
			wantHosts: []string{"ghcr.io"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := translateNetworkCaps("ctr-1", tt.policy)
			if req.ContainerId != "ctr-1" {
				t.Errorf("ContainerId = %q", req.ContainerId)
			}
			if len(req.AllowedHosts) != len(tt.wantHosts) {
				t.Errorf("AllowedHosts = %v, want %v", req.AllowedHosts, tt.wantHosts)
			}
			for i, h := range tt.wantHosts {
				if req.AllowedHosts[i] != h {
					t.Errorf("AllowedHosts[%d] = %q, want %q", i, req.AllowedHosts[i], h)
				}
			}
			if len(req.EgressRules) != tt.wantEgress {
				t.Fatalf("EgressRules = %d, want %d", len(req.EgressRules), tt.wantEgress)
			}
			if tt.wantDefProt != "" && req.EgressRules[0].Protocol != tt.wantDefProt {
				t.Errorf("default protocol = %q, want %q", req.EgressRules[0].Protocol, tt.wantDefProt)
			}
		})
	}
}

func TestHasHostnames(t *testing.T) {
	tests := []struct {
		name string
		req  *enforcerapi.NetworkPolicyRequest
		want bool
	}{
		{"empty", &enforcerapi.NetworkPolicyRequest{}, false},
		{"ip literals only", &enforcerapi.NetworkPolicyRequest{
			AllowedHosts: []string{"10.0.0.5", "2001:db8::1"},
			EgressRules:  []*enforcerapi.EgressRule{{Host: "192.168.1.20", Port: 4624}},
		}, false},
		{"hostname in allowed hosts", &enforcerapi.NetworkPolicyRequest{
			AllowedHosts: []string{"ghcr.io"},
		}, true},
		{"hostname in egress rule", &enforcerapi.NetworkPolicyRequest{
			EgressRules: []*enforcerapi.EgressRule{{Host: "intel.example.com", Port: 443}},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasHostnames(tt.req); got != tt.want {
				t.Errorf("hasHostnames() = %v, want %v", got, tt.want)
			}
		})
	}
}

// recordingEnforcer is an EnforcerClient fake for registration-lifecycle
// tests. Unset RPCs panic via the embedded nil interface — these tests only
// exercise register/apply/unregister.
type recordingEnforcer struct {
	enforcerapi.EnforcerClient

	netPolicyErr error
	fsPolicyErr  error

	registered   []string
	unregistered []string
}

func (f *recordingEnforcer) RegisterContainer(ctx context.Context, req *enforcerapi.RegisterContainerRequest, opts ...grpc.CallOption) (*enforcerapi.RegisterContainerResponse, error) {
	f.registered = append(f.registered, req.ContainerId)
	return &enforcerapi.RegisterContainerResponse{CgroupId: 42}, nil
}

func (f *recordingEnforcer) UnregisterContainer(ctx context.Context, req *enforcerapi.UnregisterContainerRequest, opts ...grpc.CallOption) (*enforcerapi.UnregisterContainerResponse, error) {
	f.unregistered = append(f.unregistered, req.ContainerId)
	return &enforcerapi.UnregisterContainerResponse{}, nil
}

func (f *recordingEnforcer) ApplyNetworkPolicy(ctx context.Context, req *enforcerapi.NetworkPolicyRequest, opts ...grpc.CallOption) (*enforcerapi.PolicyResponse, error) {
	if f.netPolicyErr != nil {
		return nil, f.netPolicyErr
	}
	return &enforcerapi.PolicyResponse{Success: true}, nil
}

func (f *recordingEnforcer) ApplyFilesystemPolicy(ctx context.Context, req *enforcerapi.FilesystemPolicyRequest, opts ...grpc.CallOption) (*enforcerapi.PolicyResponse, error) {
	if f.fsPolicyErr != nil {
		return nil, f.fsPolicyErr
	}
	return &enforcerapi.PolicyResponse{Success: true}, nil
}

func enforcementTestTool() config.MCPToolConfig {
	return config.MCPToolConfig{
		Policy: &config.MCPServerPolicy{
			Filesystem: &config.FilesystemCaps{Deny: []string{"/etc/shadow"}},
		},
	}
}

func TestApplyBackendEnforcementSuccess(t *testing.T) {
	ec := &recordingEnforcer{}
	b := &Backend{Name: "sift", ContainerID: "ctr-1"}

	unregister, err := applyBackendEnforcement(context.Background(), ec, zaptest.NewLogger(t), b, enforcementTestTool(), "/sys/fs/cgroup/test", 123)
	if err != nil {
		t.Fatalf("applyBackendEnforcement: %v", err)
	}
	if len(ec.unregistered) != 0 {
		t.Fatalf("unexpected unregister during successful registration: %v", ec.unregistered)
	}
	if err := unregister(context.Background()); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if len(ec.unregistered) != 1 || ec.unregistered[0] != "ctr-1" {
		t.Errorf("unregistered = %v, want [ctr-1]", ec.unregistered)
	}
}

// A failure after RegisterContainer must roll the registration back: a
// leaked cgroup in ENFORCED_CGROUPS outlives the container, and cgroup IDs
// recycle (issue: partial-registration leak).
func TestApplyBackendEnforcementRollsBackOnNetworkPolicyFailure(t *testing.T) {
	ec := &recordingEnforcer{netPolicyErr: fmt.Errorf("boom")}
	b := &Backend{Name: "sift", ContainerID: "ctr-1"}

	_, err := applyBackendEnforcement(context.Background(), ec, zaptest.NewLogger(t), b, enforcementTestTool(), "/sys/fs/cgroup/test", 123)
	if err == nil {
		t.Fatal("expected network policy failure")
	}
	if len(ec.registered) != 1 {
		t.Fatalf("registered = %v, want one registration", ec.registered)
	}
	if len(ec.unregistered) != 1 || ec.unregistered[0] != "ctr-1" {
		t.Errorf("unregistered = %v, want rollback of ctr-1", ec.unregistered)
	}
}

func TestApplyBackendEnforcementRollsBackOnFilesystemPolicyFailure(t *testing.T) {
	ec := &recordingEnforcer{fsPolicyErr: fmt.Errorf("boom")}
	b := &Backend{Name: "sift", ContainerID: "ctr-1"}

	_, err := applyBackendEnforcement(context.Background(), ec, zaptest.NewLogger(t), b, enforcementTestTool(), "/sys/fs/cgroup/test", 123)
	if err == nil {
		t.Fatal("expected filesystem policy failure")
	}
	if len(ec.unregistered) != 1 || ec.unregistered[0] != "ctr-1" {
		t.Errorf("unregistered = %v, want rollback of ctr-1", ec.unregistered)
	}
}

// Rollback must work even when the caller's context is already cancelled
// (registration aborts mid-startup) — it uses a fresh context internally.
func TestApplyBackendEnforcementRollsBackWithCancelledContext(t *testing.T) {
	ec := &recordingEnforcer{fsPolicyErr: fmt.Errorf("boom")}
	b := &Backend{Name: "sift", ContainerID: "ctr-1"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := applyBackendEnforcement(ctx, ec, zaptest.NewLogger(t), b, enforcementTestTool(), "/sys/fs/cgroup/test", 123)
	if err == nil {
		t.Fatal("expected filesystem policy failure")
	}
	if len(ec.unregistered) != 1 {
		t.Errorf("unregistered = %v, want rollback despite cancelled caller context", ec.unregistered)
	}
}

// completingEnforcer counts CompleteToolCall attempts, failing the first n.
type completingEnforcer struct {
	enforcerapi.EnforcerClient
	failFirst int
	calls     int
}

func (f *completingEnforcer) CompleteToolCall(ctx context.Context, req *enforcerapi.CompleteToolCallRequest, opts ...grpc.CallOption) (*enforcerapi.CompleteToolCallResponse, error) {
	f.calls++
	if f.calls <= f.failFirst {
		return nil, fmt.Errorf("transient rpc failure")
	}
	return &enforcerapi.CompleteToolCallResponse{}, nil
}

// A transient CompleteToolCall failure must be retried: a lost Complete
// leaves the correlation window open at the enforcer.
func TestCompleteToolCallRetriesTransientFailure(t *testing.T) {
	ec := &completingEnforcer{failFirst: 2}
	p := &Proxy{deps: Deps{Enforcer: ec, Logger: zaptest.NewLogger(t)}}
	b := &Backend{Name: "sift", ContainerID: "ctr-1"}

	p.completeToolCall(context.Background(), b, "corr-1")
	if ec.calls != 3 {
		t.Errorf("CompleteToolCall attempts = %d, want 3 (two failures then success)", ec.calls)
	}
}

func TestCompleteToolCallNoRetryOnSuccess(t *testing.T) {
	ec := &completingEnforcer{}
	p := &Proxy{deps: Deps{Enforcer: ec, Logger: zaptest.NewLogger(t)}}
	b := &Backend{Name: "sift", ContainerID: "ctr-1"}

	p.completeToolCall(context.Background(), b, "corr-1")
	if ec.calls != 1 {
		t.Errorf("CompleteToolCall attempts = %d, want 1", ec.calls)
	}
}

func TestCompleteToolCallGivesUpAfterBoundedAttempts(t *testing.T) {
	ec := &completingEnforcer{failFirst: 100}
	p := &Proxy{deps: Deps{Enforcer: ec, Logger: zaptest.NewLogger(t)}}
	b := &Backend{Name: "sift", ContainerID: "ctr-1"}

	p.completeToolCall(context.Background(), b, "corr-1")
	if ec.calls != completeToolCallAttempts {
		t.Errorf("CompleteToolCall attempts = %d, want %d", ec.calls, completeToolCallAttempts)
	}
}
