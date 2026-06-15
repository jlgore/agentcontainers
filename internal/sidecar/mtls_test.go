package sidecar

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

// namesInTar returns the regular-file entry names in a tar stream.
func namesInTar(t *testing.T, r io.Reader) []string {
	t.Helper()
	var names []string
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			names = append(names, hdr.Name)
		}
	}
	return names
}

// TestStartSidecar_MTLS_LoopbackAndCreds asserts that a managed mTLS sidecar
// publishes only on 127.0.0.1, runs with host-provided --tls-* certs, has the
// server material pushed into its creds dir, and returns a connection profile
// pointing at the stable host client material.
func TestStartSidecar_MTLS_LoopbackAndCreds(t *testing.T) {
	// Redirect the stable creds dir to a throwaway location for the test.
	t.Setenv(credsHostDirEnv, t.TempDir())

	// The profile prober would otherwise make a real network call.
	origProber := defaultProfileProber
	defaultProfileProber = func(enforcement.ConnectionProfile) bool { return true }
	defer func() { defaultProfileProber = origProber }()

	var gotCmd []string
	var gotBindings map[string][]string // port -> []hostIP
	var pushedNames []string

	m := &mockDockerClient{
		imageInspectFn: func(_ context.Context, _ string, _ ...client.ImageInspectOption) (client.ImageInspectResult, error) {
			return client.ImageInspectResult{}, nil // image present
		},
		containerCreateFn: func(_ context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
			gotCmd = opts.Config.Cmd
			gotBindings = map[string][]string{}
			for p, binds := range opts.HostConfig.PortBindings {
				for _, b := range binds {
					hostIP := ""
					if b.HostIP.IsValid() {
						hostIP = b.HostIP.String()
					}
					gotBindings[p.String()] = append(gotBindings[p.String()], hostIP)
				}
			}
			return client.ContainerCreateResult{ID: "cid"}, nil
		},
		copyToContainerFn: func(_ context.Context, _ string, opts client.CopyToContainerOptions) (client.CopyToContainerResult, error) {
			pushedNames = namesInTar(t, opts.Content)
			return client.CopyToContainerResult{}, nil
		},
	}

	handle, err := StartSidecar(context.Background(), m, StartOptions{
		Image:          "enforcer:test",
		Port:           50051,
		HostBindIP:     "127.0.0.1",
		MTLS:           true,
		Required:       true,
		HealthTimeout:  2 * time.Second,
		HealthInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("StartSidecar: %v", err)
	}

	// Loopback-only publication.
	for port, ips := range gotBindings {
		for _, ip := range ips {
			if ip != "127.0.0.1" {
				t.Errorf("port %s published on %q, want 127.0.0.1 only", port, ip)
			}
		}
	}

	// Host-provided TLS flags present (and the old --creds-dir gone).
	for _, want := range []string{"--tls-cert", "--tls-key", "--tls-ca"} {
		if !containsArg(gotCmd, want) {
			t.Errorf("Cmd %v missing %s", gotCmd, want)
		}
	}
	if containsArg(gotCmd, "--creds-dir") {
		t.Errorf("Cmd %v should not pass --creds-dir under host-gen creds", gotCmd)
	}

	// Server material pushed into the container's creds dir.
	wantPushed := map[string]bool{
		"creds/" + serverCertFile: false,
		"creds/" + serverKeyFile:  false,
		"creds/" + clientCAFile:   false,
	}
	for _, n := range pushedNames {
		if _, ok := wantPushed[n]; ok {
			wantPushed[n] = true
		}
	}
	for name, seen := range wantPushed {
		if !seen {
			t.Errorf("expected %s pushed into container, got %v", name, pushedNames)
		}
	}
	// Client private key must never be pushed into the container.
	for _, n := range pushedNames {
		if n == "creds/"+clientKeyFile || n == "creds/"+clientCertFile {
			t.Errorf("client material %s must not be pushed into the container", n)
		}
	}

	// Profile carries the stable host client material, present on disk.
	profile := handle.Profile()
	if !profile.HasMTLS() {
		t.Fatalf("handle profile is not mTLS: %+v", profile)
	}
	for _, p := range []string{profile.CACertPath, profile.ClientCertPath, profile.ClientKeyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected cred file %s on disk: %v", p, err)
		}
	}

	// Stopping leaves the creds in place (they are reusable).
	credsDir := handle.credsDir
	if err := StopSidecar(context.Background(), m, handle); err != nil {
		t.Fatalf("StopSidecar: %v", err)
	}
	if _, err := os.Stat(credsDir); err != nil {
		t.Errorf("creds dir %s should persist after StopSidecar: %v", credsDir, err)
	}

	// Purge explicitly removes them.
	if err := PurgeCreds(); err != nil {
		t.Fatalf("PurgeCreds: %v", err)
	}
	if _, err := os.Stat(credsDir); !os.IsNotExist(err) {
		t.Errorf("creds dir %s should be removed after PurgeCreds", credsDir)
	}
}

// TestEnsureHostCreds_ReuseAndRegenerate asserts that valid creds are reused
// across calls and that removing material forces regeneration.
func TestEnsureHostCreds_ReuseAndRegenerate(t *testing.T) {
	t.Setenv(credsHostDirEnv, t.TempDir())

	first, err := ensureHostCreds()
	if err != nil {
		t.Fatalf("ensureHostCreds (first): %v", err)
	}
	before, err := os.ReadFile(first.clientCert)
	if err != nil {
		t.Fatalf("read client cert: %v", err)
	}

	// Second call reuses the same material untouched.
	if _, err := ensureHostCreds(); err != nil {
		t.Fatalf("ensureHostCreds (reuse): %v", err)
	}
	after, err := os.ReadFile(first.clientCert)
	if err != nil {
		t.Fatalf("re-read client cert: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("valid creds should be reused, but client cert changed")
	}

	// Removing a file forces regeneration of the whole set.
	if err := os.Remove(first.clientKey); err != nil {
		t.Fatalf("remove client key: %v", err)
	}
	if _, err := ensureHostCreds(); err != nil {
		t.Fatalf("ensureHostCreds (regen): %v", err)
	}
	regen, err := os.ReadFile(first.clientCert)
	if err != nil {
		t.Fatalf("read regenerated client cert: %v", err)
	}
	if bytes.Equal(before, regen) {
		t.Error("missing material should force regeneration, but client cert was unchanged")
	}
}

// TestStartSidecar_DefaultBindingUnrestricted confirms the in-VM path (no
// HostBindIP) leaves the published port reachable on all interfaces.
func TestStartSidecar_DefaultBindingUnrestricted(t *testing.T) {
	origProber := defaultHealthProber
	defaultHealthProber = alwaysHealthy
	defer func() { defaultHealthProber = origProber }()

	var gotHostIPValid bool
	m := &mockDockerClient{
		imageInspectFn: func(_ context.Context, _ string, _ ...client.ImageInspectOption) (client.ImageInspectResult, error) {
			return client.ImageInspectResult{}, nil
		},
		containerCreateFn: func(_ context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
			for _, binds := range opts.HostConfig.PortBindings {
				for _, b := range binds {
					if b.HostIP.IsValid() {
						gotHostIPValid = true
					}
				}
			}
			return client.ContainerCreateResult{ID: "cid"}, nil
		},
	}

	_, err := StartSidecar(context.Background(), m, StartOptions{
		Image:          "enforcer:test",
		Port:           50051,
		Required:       true,
		HealthTimeout:  2 * time.Second,
		HealthInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("StartSidecar: %v", err)
	}
	if gotHostIPValid {
		t.Error("expected no HostIP restriction when HostBindIP is empty")
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
