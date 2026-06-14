package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

// writeSelfSignedCerts writes a self-signed cert (reused as both CA and client
// material) plus its key to a temp dir, returning the three file paths.
func writeSelfSignedCerts(t *testing.T) (caFile, certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	caFile = filepath.Join(dir, "ca.crt")
	certFile = filepath.Join(dir, "client.crt")
	keyFile = filepath.Join(dir, "client.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	for path, data := range map[string][]byte{caFile: certPEM, certFile: certPEM, keyFile: keyPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return caFile, certFile, keyFile
}

// withEnforcerProbe swaps the eager health probe for the test's duration.
func withEnforcerProbe(t *testing.T, probe func(string) bool) *int {
	t.Helper()
	calls := new(int)
	orig := enforcerHealthProbe
	enforcerHealthProbe = func(addr string) bool {
		*calls++
		return probe(addr)
	}
	t.Cleanup(func() { enforcerHealthProbe = orig })
	return calls
}

// TestBuildMCPDepsUsesMTLSProfileFromEnv verifies that AC_ENFORCER_TLS_* in the
// environment produces an mTLS connection profile (probed with credentials),
// rather than a hardcoded plaintext dial.
func TestBuildMCPDepsUsesMTLSProfileFromEnv(t *testing.T) {
	caFile, certFile, keyFile := writeSelfSignedCerts(t)
	t.Setenv("AC_ENFORCER_ADDR", "10.0.0.9:50051")
	t.Setenv("AC_ENFORCER_TLS_CA", caFile)
	t.Setenv("AC_ENFORCER_TLS_CERT", certFile)
	t.Setenv("AC_ENFORCER_TLS_KEY", keyFile)

	var gotProfile enforcement.ConnectionProfile
	orig := enforcerProfileProbe
	enforcerProfileProbe = func(p enforcement.ConnectionProfile) bool {
		gotProfile = p
		return true
	}
	t.Cleanup(func() { enforcerProfileProbe = orig })

	_, cleanup, err := buildMCPDeps(mcpDepsConfig(nil), zap.NewNop())
	defer cleanup()
	if err != nil {
		t.Fatalf("buildMCPDeps: %v", err)
	}
	if !gotProfile.HasMTLS() {
		t.Errorf("expected an mTLS profile from env, got %+v", gotProfile)
	}
	if gotProfile.Addr != "10.0.0.9:50051" {
		t.Errorf("addr = %q, want 10.0.0.9:50051", gotProfile.Addr)
	}
}

func mcpDepsConfig(enforcerRequired *bool) *config.AgentContainer {
	return &config.AgentContainer{
		Agent: &config.AgentConfig{
			Enforcer: &config.EnforcerConfig{Required: enforcerRequired},
			Tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"sift": {Type: "container", Image: "example/mcp:latest"},
				},
			},
		},
	}
}

// An unreachable enforcer with enforcement required must fail at mcp start
// (buildMCPDeps), not at first backend launch — grpc.NewClient is lazy and
// would otherwise defer the failure past audit/approval setup.
func TestBuildMCPDepsFailsEagerlyWhenEnforcerUnreachable(t *testing.T) {
	calls := withEnforcerProbe(t, func(string) bool { return false })

	_, cleanup, err := buildMCPDeps(mcpDepsConfig(nil), zap.NewNop())
	defer cleanup()

	if err == nil {
		t.Fatal("expected buildMCPDeps to fail with an unreachable enforcer")
	}
	if !strings.Contains(err.Error(), "health check") {
		t.Errorf("error should name the failed health check, got: %v", err)
	}
	if *calls != 1 {
		t.Errorf("health probe calls = %d, want 1", *calls)
	}
}

func TestBuildMCPDepsConnectsWhenEnforcerHealthy(t *testing.T) {
	calls := withEnforcerProbe(t, func(string) bool { return true })

	deps, cleanup, err := buildMCPDeps(mcpDepsConfig(nil), zap.NewNop())
	defer cleanup()

	if err != nil {
		t.Fatalf("buildMCPDeps: %v", err)
	}
	if deps.Enforcer == nil {
		t.Error("expected an enforcer client when the health probe passes")
	}
	if *calls != 1 {
		t.Errorf("health probe calls = %d, want 1", *calls)
	}
}

// enforcer.required: false opts out of kernel enforcement entirely — no
// probe, no client, no startup failure.
func TestBuildMCPDepsSkipsProbeWhenEnforcerDisabled(t *testing.T) {
	calls := withEnforcerProbe(t, func(string) bool { return false })

	disabled := false
	deps, cleanup, err := buildMCPDeps(mcpDepsConfig(&disabled), zap.NewNop())
	defer cleanup()

	if err != nil {
		t.Fatalf("buildMCPDeps: %v", err)
	}
	if deps.Enforcer != nil {
		t.Error("no enforcer client expected when enforcer.required is false")
	}
	if *calls != 0 {
		t.Errorf("health probe calls = %d, want 0", *calls)
	}
}
