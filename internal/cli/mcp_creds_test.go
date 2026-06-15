package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveEnforcerClientCreds locks down the fix for the SIFT-demo failure:
// `mcp start` / `enforcer status` (separate, credential-less processes) probed
// the mTLS enforcer with no client cert and were rejected. The resolver now
// falls back to the stable host creds dir when AC_ENFORCER_TLS_* is unset.
func TestResolveEnforcerClientCreds(t *testing.T) {
	// credsHostDirEnv on the sidecar package; the resolver reads the stable dir
	// through sidecar.DefaultClientCredsPaths.
	const credsHostDirEnv = "AC_ENFORCER_CREDS_HOST_DIR"

	writeStable := func(t *testing.T, dir string) (ca, cert, key string) {
		t.Helper()
		ca = filepath.Join(dir, "client-ca.crt")
		cert = filepath.Join(dir, "client.crt")
		key = filepath.Join(dir, "client.key")
		for _, f := range []string{ca, cert, key} {
			if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
				t.Fatalf("write %s: %v", f, err)
			}
		}
		return
	}

	t.Run("env wins over the stable-dir fallback", func(t *testing.T) {
		t.Setenv(credsHostDirEnv, t.TempDir())
		writeStable(t, os.Getenv(credsHostDirEnv))
		t.Setenv("AC_ENFORCER_TLS_CA", "/env/ca")
		t.Setenv("AC_ENFORCER_TLS_CERT", "/env/cert")
		t.Setenv("AC_ENFORCER_TLS_KEY", "/env/key")
		ca, cert, key := resolveEnforcerClientCreds(false)
		if ca != "/env/ca" || cert != "/env/cert" || key != "/env/key" {
			t.Errorf("expected env creds, got %q %q %q", ca, cert, key)
		}
	})

	t.Run("falls back to the stable dir when env is unset", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv(credsHostDirEnv, dir)
		t.Setenv("AC_ENFORCER_TLS_CA", "")
		t.Setenv("AC_ENFORCER_TLS_CERT", "")
		t.Setenv("AC_ENFORCER_TLS_KEY", "")
		wantCA, wantCert, wantKey := writeStable(t, dir)
		ca, cert, key := resolveEnforcerClientCreds(false)
		if ca != wantCA || cert != wantCert || key != wantKey {
			t.Errorf("expected stable creds, got %q %q %q", ca, cert, key)
		}
	})

	t.Run("empty when neither env nor stable dir has creds", func(t *testing.T) {
		t.Setenv(credsHostDirEnv, t.TempDir()) // empty dir
		t.Setenv("AC_ENFORCER_TLS_CA", "")
		t.Setenv("AC_ENFORCER_TLS_CERT", "")
		t.Setenv("AC_ENFORCER_TLS_KEY", "")
		if ca, cert, key := resolveEnforcerClientCreds(false); ca != "" || cert != "" || key != "" {
			t.Errorf("expected empty creds, got %q %q %q", ca, cert, key)
		}
	})

	t.Run("no fallback under insecureDev", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv(credsHostDirEnv, dir)
		writeStable(t, dir)
		t.Setenv("AC_ENFORCER_TLS_CA", "")
		t.Setenv("AC_ENFORCER_TLS_CERT", "")
		t.Setenv("AC_ENFORCER_TLS_KEY", "")
		if ca, cert, key := resolveEnforcerClientCreds(true); ca != "" || cert != "" || key != "" {
			t.Errorf("expected no creds under insecureDev, got %q %q %q", ca, cert, key)
		}
	})
}
