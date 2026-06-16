package applevm

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
)

func newTestClient(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	c, err := NewClient(WithSocketPath(sockPath))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestHealth(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sandbox.HealthResponse{ //nolint:errcheck
			Status:  "healthy",
			Version: "v0.1.0",
			VMs:     1,
		})
	})

	c := newTestClient(t, mux)
	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if h.Status != "healthy" {
		t.Errorf("Status = %q, want %q", h.Status, "healthy")
	}
	if h.VMs != 1 {
		t.Errorf("VMs = %d, want %d", h.VMs, 1)
	}
}

func TestCreateVM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req sandbox.VMCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.WorkspaceDir == "" {
			http.Error(w, "workspace_dir required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sandbox.VMCreateResponse{ //nolint:errcheck
			VMID: "avm-abc123",
			VMConfig: sandbox.VMConfig{
				SocketPath: "/run/applevm/avm-abc123.sock",
			},
			Started: true,
		})
	})

	c := newTestClient(t, mux)
	resp, err := c.CreateVM(context.Background(), &sandbox.VMCreateRequest{
		AgentName:    "shell",
		WorkspaceDir: "/workspace",
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if resp.VMID != "avm-abc123" {
		t.Errorf("VMID = %q, want %q", resp.VMID, "avm-abc123")
	}
	if resp.VMConfig.SocketPath != "/run/applevm/avm-abc123.sock" {
		t.Errorf("SocketPath = %q, want %q", resp.VMConfig.SocketPath, "/run/applevm/avm-abc123.sock")
	}
	if !resp.Started {
		t.Error("Started = false, want true")
	}
}

func TestCreateVM_ServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal failure", http.StatusInternalServerError)
	})

	c := newTestClient(t, mux)
	_, err := c.CreateVM(context.Background(), &sandbox.VMCreateRequest{
		AgentName:    "shell",
		WorkspaceDir: "/workspace",
	})
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "500")
	}
}

func TestListVMs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]sandbox.VMListEntry{ //nolint:errcheck
			{VMID: "avm-1", VMName: "acvm-agent-1", Status: "running", Active: true},
			{VMID: "avm-2", VMName: "acvm-agent-2", Status: "stopped"},
		})
	})

	c := newTestClient(t, mux)
	vms, err := c.ListVMs(context.Background())
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(vms) != 2 {
		t.Fatalf("len(vms) = %d, want 2", len(vms))
	}
	if vms[0].VMName != "acvm-agent-1" {
		t.Errorf("vms[0].VMName = %q, want %q", vms[0].VMName, "acvm-agent-1")
	}
}

func TestInspectVM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm/test-vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sandbox.VMInspectResponse{ //nolint:errcheck
			VMID:        "avm-abc123",
			VMName:      "test-vm",
			IPAddresses: []string{"192.168.64.2"},
		})
	})

	c := newTestClient(t, mux)
	v, err := c.InspectVM(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if len(v.IPAddresses) != 1 || v.IPAddresses[0] != "192.168.64.2" {
		t.Errorf("IPAddresses = %v, want [192.168.64.2]", v.IPAddresses)
	}
}

func TestStopDeleteKeepalive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vm/test-vm/stop", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/vm/test-vm/keepalive", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/vm/test-vm", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	c := newTestClient(t, mux)
	if err := c.StopVM(context.Background(), "test-vm"); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	if err := c.Keepalive(context.Background(), "test-vm"); err != nil {
		t.Fatalf("Keepalive: %v", err)
	}
	if err := c.DeleteVM(context.Background(), "test-vm"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
}

func TestUpdateProxyConfig(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/network/proxyconfig", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req sandbox.ProxyConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.VMName == "" {
			http.Error(w, "vm_name required", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	c := newTestClient(t, mux)
	err := c.UpdateProxyConfig(context.Background(), &sandbox.ProxyConfigRequest{
		VMName:     "test-vm",
		AllowHosts: []string{"api.github.com"},
		Policy:     "DENY",
	})
	if err != nil {
		t.Fatalf("UpdateProxyConfig: %v", err)
	}
}

func TestSocketPath_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	customPath := filepath.Join(dir, "custom.sock")
	t.Setenv(EnvSocketPath, customPath)

	c, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient with env override: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}
