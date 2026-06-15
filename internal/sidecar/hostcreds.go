package sidecar

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/moby/moby/client"
)

// Host-side mTLS credential lifecycle.
//
// Earlier versions let the enforcer generate ephemeral session certs inside the
// container and copied the client material out to a random /tmp directory on
// every start. That left stale cred dirs accumulating in /tmp and made the
// AC_ENFORCER_TLS_* export paths move on every restart (so a shell glob over
// them could silently concatenate several dirs and break the handshake).
//
// Instead the host owns the credentials: it generates a CA + server + client
// cert once into a single stable directory, reuses them across restarts (until
// they expire), and pushes only the server material into the enforcer container
// over the Docker API (CopyToContainer — the symmetric inverse of the old
// copy-out). CopyToContainer works identically for host Docker and for the
// per-VM Docker socket used by the sandbox runtime, where no host directory is
// shared with the container, so this preserves the constraint that originally
// ruled out a host bind mount. The enforcer consumes the pushed files via its
// --tls-cert/--tls-key/--tls-ca flags; it no longer generates anything.

const (
	// serverCertFile and serverKeyFile are the server-side mTLS material the
	// enforcer presents. They are pushed into the container and never needed by
	// clients. (The client-side filenames clientCertFile/clientKeyFile/
	// clientCAFile are declared in sidecar.go.)
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"

	// credValidity is how long a freshly generated cert is valid. The creds are
	// reusable across restarts, so this is a rotation interval, not a session
	// lifetime; rotate early with `enforcer stop --purge`.
	credValidity = 90 * 24 * time.Hour

	// credRenewBefore triggers regeneration once a cert is within this window of
	// expiry, so a long-running host never hands a client a cert that expires
	// mid-session.
	credRenewBefore = 24 * time.Hour

	// credsHostDirEnv overrides the stable host credential directory. Named
	// distinctly from the enforcer binary's AC_ENFORCER_CREDS_DIR (which selects
	// in-container generation) to avoid any collision.
	credsHostDirEnv = "AC_ENFORCER_CREDS_HOST_DIR"
)

// credPaths is the set of host file paths under a credential directory.
type credPaths struct {
	dir        string
	serverCert string
	serverKey  string
	clientCA   string
	clientCert string
	clientKey  string
}

func credPathsIn(dir string) credPaths {
	return credPaths{
		dir:        dir,
		serverCert: filepath.Join(dir, serverCertFile),
		serverKey:  filepath.Join(dir, serverKeyFile),
		clientCA:   filepath.Join(dir, clientCAFile),
		clientCert: filepath.Join(dir, clientCertFile),
		clientKey:  filepath.Join(dir, clientKeyFile),
	}
}

// stableCredsDir returns the single, stable host directory holding the
// enforcer's mTLS material: ~/.ac/enforcer-creds, overridable via
// AC_ENFORCER_CREDS_HOST_DIR.
func stableCredsDir() (string, error) {
	if override := os.Getenv(credsHostDirEnv); override != "" {
		return override, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory for enforcer creds: %w", err)
	}
	return filepath.Join(home, ".ac", "enforcer-creds"), nil
}

// ensureHostCreds returns valid mTLS material in the stable directory,
// generating a fresh CA + server + client cert only if the directory is missing
// material or the server cert is expired (or close to it). Existing valid creds
// are reused untouched so that a running enforcer's pushed server cert keeps
// matching the client material on disk.
func ensureHostCreds() (credPaths, error) {
	dir, err := stableCredsDir()
	if err != nil {
		return credPaths{}, err
	}
	p := credPathsIn(dir)
	if hostCredsValid(p) {
		return p, nil
	}
	if err := generateHostCreds(p); err != nil {
		return credPaths{}, fmt.Errorf("generating enforcer creds in %s: %w", dir, err)
	}
	return p, nil
}

// hostCredsValid reports whether all five PEM files exist and the server leaf
// certificate is currently valid with comfortable headroom before expiry.
func hostCredsValid(p credPaths) bool {
	for _, f := range []string{p.serverCert, p.serverKey, p.clientCA, p.clientCert, p.clientKey} {
		if _, err := os.Stat(f); err != nil {
			return false
		}
	}
	pemBytes, err := os.ReadFile(p.serverCert)
	if err != nil {
		return false
	}
	cert, err := parseLeafCert(pemBytes)
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false
	}
	return now.Add(credRenewBefore).Before(cert.NotAfter)
}

func parseLeafCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no PEM certificate block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// generateHostCreds writes a fresh self-signed CA, a server cert (SANs
// localhost / 127.0.0.1, serverAuth) and a client cert (clientAuth) into the
// directory, replacing whatever was there. The on-wire structure mirrors the
// enforcer's former generate_session_certs exactly: one CA signs both leaves,
// and client-ca.crt is that CA (used by the server to verify clients and by the
// client to verify the server).
func generateHostCreds(p credPaths) error {
	caCert, caKey, err := generateCA()
	if err != nil {
		return err
	}
	serverPEM, serverKeyPEM, err := generateLeaf(caCert, caKey, leafServer)
	if err != nil {
		return err
	}
	clientPEM, clientKeyPEM, err := generateLeaf(caCert, caKey, leafClient)
	if err != nil {
		return err
	}
	caPEM := encodeCertPEM(caCert.Raw)

	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(p.dir, 0o700); err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
	}{
		{p.serverCert, serverPEM},
		{p.serverKey, serverKeyPEM},
		{p.clientCA, caPEM},
		{p.clientCert, clientPEM},
		{p.clientKey, clientKeyPEM},
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", filepath.Base(f.path), err)
		}
	}
	return nil
}

type leafKind int

const (
	leafServer leafKind = iota
	leafClient
)

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "agentcontainer-enforcer ephemeral CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(credValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func generateLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, kind leafKind) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(credValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	switch kind {
	case leafServer:
		// SANs match the enforcer's former server cert so an in-VM enforcer
		// reached at the VM IP keeps working via the ServerName=localhost override.
		tmpl.Subject = pkix.Name{CommonName: "localhost"}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case leafClient:
		tmpl.Subject = pkix.Name{CommonName: "ac client"}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return encodeCertPEM(der), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// pushServerCreds copies the server-side mTLS material into the enforcer
// container's creds directory over the Docker API. It is called between
// ContainerCreate and ContainerStart (docker cp works on a created-but-not-yet
// running container), so the files are present when the enforcer reads its
// --tls-* paths at startup.
func pushServerCreds(ctx context.Context, cli client.APIClient, containerID string, p credPaths) error {
	base := path.Base(credsContainerDir) // "creds"

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Directory entry first so extraction creates /creds with 0700.
	if err := tw.WriteHeader(&tar.Header{
		Name:     base + "/",
		Mode:     0o700,
		Typeflag: tar.TypeDir,
	}); err != nil {
		return fmt.Errorf("tar creds dir header: %w", err)
	}

	files := []struct{ name, src string }{
		{serverCertFile, p.serverCert},
		{serverKeyFile, p.serverKey},
		{clientCAFile, p.clientCA},
	}
	for _, f := range files {
		data, err := os.ReadFile(f.src)
		if err != nil {
			return fmt.Errorf("reading %s: %w", f.src, err)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     path.Join(base, f.name),
			Mode:     0o600,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			return fmt.Errorf("tar header %s: %w", f.name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("tar write %s: %w", f.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing creds tar: %w", err)
	}

	// Extract relative to the parent of credsContainerDir (i.e. "/"), so the
	// "creds/..." entries land at /creds/...
	dest := path.Dir(credsContainerDir)
	if _, err := cli.CopyToContainer(ctx, containerID, client.CopyToContainerOptions{
		DestinationPath: dest,
		Content:         &buf,
	}); err != nil {
		return fmt.Errorf("copying creds into container: %w", err)
	}
	return nil
}

// PurgeCreds deletes the stable host credential directory, forcing fresh
// material to be generated on the next enforcer start. Used by
// `enforcer stop --purge` to rotate credentials.
func PurgeCreds() error {
	dir, err := stableCredsDir()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing enforcer creds %s: %w", dir, err)
	}
	return nil
}
