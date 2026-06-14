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

// credsTar builds a tar stream mimicking `docker cp <container>:/creds`, with
// the five PEM files the enforcer writes under a "creds/" prefix.
func credsTar(t *testing.T) io.ReadCloser {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files := map[string]string{
		"creds/server.crt":        "server-cert",
		"creds/server.key":        "server-key",
		"creds/" + clientCAFile:   "ca-pem",
		"creds/" + clientCertFile: "client-cert-pem",
		"creds/" + clientKeyFile:  "client-key-pem",
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o600,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return io.NopCloser(&buf)
}

// TestStartSidecar_MTLS_LoopbackAndCreds asserts that a managed mTLS sidecar
// publishes only on 127.0.0.1, runs with --creds-dir, and returns a connection
// profile populated with the retrieved client credentials.
func TestStartSidecar_MTLS_LoopbackAndCreds(t *testing.T) {
	// The profile prober would otherwise make a real network call.
	origProber := defaultProfileProber
	defaultProfileProber = func(enforcement.ConnectionProfile) bool { return true }
	defer func() { defaultProfileProber = origProber }()

	var gotCmd []string
	var gotBindings map[string][]string // port -> []hostIP

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
		copyFromContainerFn: func(_ context.Context, _ string, _ client.CopyFromContainerOptions) (client.CopyFromContainerResult, error) {
			return client.CopyFromContainerResult{Content: credsTar(t)}, nil
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
	t.Cleanup(func() { cleanupCreds(handle) })

	// Loopback-only publication.
	for port, ips := range gotBindings {
		for _, ip := range ips {
			if ip != "127.0.0.1" {
				t.Errorf("port %s published on %q, want 127.0.0.1 only", port, ip)
			}
		}
	}

	// --creds-dir present in the command.
	if !containsArg(gotCmd, "--creds-dir") {
		t.Errorf("Cmd %v missing --creds-dir", gotCmd)
	}

	// Profile carries retrieved mTLS material that exists on disk.
	profile := handle.Profile()
	if !profile.HasMTLS() {
		t.Fatalf("handle profile is not mTLS: %+v", profile)
	}
	for _, p := range []string{profile.CACertPath, profile.ClientCertPath, profile.ClientKeyPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected cred file %s on disk: %v", p, err)
		}
	}

	// Stopping removes the creds dir.
	credsDir := handle.credsDir
	if err := StopSidecar(context.Background(), m, handle); err != nil {
		t.Fatalf("StopSidecar: %v", err)
	}
	if _, err := os.Stat(credsDir); !os.IsNotExist(err) {
		t.Errorf("creds dir %s should be removed after StopSidecar", credsDir)
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
