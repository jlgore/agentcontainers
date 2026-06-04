package mcpproxy

import (
	"testing"

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
