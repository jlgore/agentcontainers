package sidecar

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestHostCreds_MTLSHandshake proves the host-generated material forms a working
// mTLS pair using the exact file roles the system relies on:
//
//   - enforcer (server): --tls-cert=server.crt, --tls-key=server.key,
//     --tls-ca=client-ca.crt  →  tonic identity(server) + client_ca_root(ca)
//   - ac (client): CACertPath=client-ca.crt, ClientCertPath=client.crt,
//     ClientKeyPath=client.key, ServerName=localhost
//
// Replicating that with crypto/tls verifies the CA signing, SANs and EKUs are
// correct end-to-end — and confirms the enforcer needs no change, since its TLS
// config is exactly this server side.
func TestHostCreds_MTLSHandshake(t *testing.T) {
	t.Setenv(credsHostDirEnv, t.TempDir())

	p, err := ensureHostCreds()
	if err != nil {
		t.Fatalf("ensureHostCreds: %v", err)
	}

	// Server side (mirrors the enforcer's --tls-cert/--tls-key/--tls-ca).
	serverCert, err := tls.LoadX509KeyPair(p.serverCert, p.serverKey)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	clientCAs := mustPool(t, p.clientCA)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	srvErr := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			srvErr <- aerr
			return
		}
		defer conn.Close() //nolint:errcheck
		// Force the handshake and echo one byte.
		buf := make([]byte, 1)
		if _, rerr := conn.Read(buf); rerr != nil && !errors.Is(rerr, io.EOF) {
			srvErr <- rerr
			return
		}
		_, werr := conn.Write([]byte("ok"))
		srvErr <- werr
	}()

	// Client side (mirrors ac's connection profile).
	clientCert, err := tls.LoadX509KeyPair(p.clientCert, p.clientKey)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      mustPool(t, p.clientCA),
		ServerName:   EnforcerCertServerName, // "localhost"
		MinVersion:   tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("mTLS dial failed (handshake did not complete): %v", err)
	}
	defer conn.Close() //nolint:errcheck

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(resp) != "ok" {
		t.Errorf("got %q, want %q", resp, "ok")
	}

	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// TestDefaultClientCredsPaths covers the discovery primitive that lets a
// credential-less caller (mcp start / enforcer status) find a managed enforcer's
// client material: false before any enforcer ran, true (with real paths) after.
func TestDefaultClientCredsPaths(t *testing.T) {
	t.Setenv(credsHostDirEnv, t.TempDir())

	if _, _, _, ok := DefaultClientCredsPaths(); ok {
		t.Fatal("expected ok=false before any creds exist")
	}
	if _, err := ensureHostCreds(); err != nil {
		t.Fatalf("ensureHostCreds: %v", err)
	}
	ca, cert, key, ok := DefaultClientCredsPaths()
	if !ok {
		t.Fatal("expected ok=true after creds generated")
	}
	for _, p := range []string{ca, cert, key} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("discovered path %s should exist: %v", p, err)
		}
	}
}

func mustPool(t *testing.T, caPath string) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA %s: %v", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("no CA certs parsed from %s", caPath)
	}
	return pool
}
