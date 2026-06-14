package sidecar

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/moby/moby/client"
)

// maxCredFileSize bounds how much of any single credential file is read out of
// the container, guarding against a hostile or corrupt archive entry.
const maxCredFileSize = 1 << 20 // 1 MiB

// retrieveCredsWithRetry polls retrieveCreds until the enforcer has written its
// ephemeral credentials or the timeout expires. The enforcer writes the creds
// directory at startup, so this normally succeeds on the first attempt; the
// retry tolerates the brief window before the files appear.
func retrieveCredsWithRetry(ctx context.Context, cli client.APIClient, containerID string, handle *SidecarHandle, timeout, interval time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Try immediately, then on each tick.
	var lastErr error
	for {
		if err := retrieveCreds(ctx, cli, containerID, handle); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timed out retrieving enforcer credentials: %w", lastErr)
		case <-ticker.C:
		}
	}
}

// retrieveCreds copies the client mTLS material out of the enforcer container's
// --creds-dir over the Docker API and writes it to a fresh 0700 host temp
// directory, populating the handle's credential paths. Using CopyFromContainer
// (rather than a host bind mount) means this works identically for host Docker
// and for the per-VM Docker socket used by the sandbox runtime, where no host
// directory is shared with the container.
func retrieveCreds(ctx context.Context, cli client.APIClient, containerID string, handle *SidecarHandle) error {
	res, err := cli.CopyFromContainer(ctx, containerID, client.CopyFromContainerOptions{
		SourcePath: credsContainerDir,
	})
	if err != nil {
		return fmt.Errorf("copy %s from container: %w", credsContainerDir, err)
	}
	defer res.Content.Close() //nolint:errcheck

	// Extract the three client files from the tar stream. Entries are named
	// relative to the parent of SourcePath, e.g. "creds/client.crt".
	wanted := map[string]bool{
		clientCertFile: true,
		clientKeyFile:  true,
		clientCAFile:   true,
	}
	found := map[string][]byte{}

	tr := tar.NewReader(res.Content)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read creds archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := path.Base(hdr.Name)
		if !wanted[base] {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxCredFileSize+1))
		if err != nil {
			return fmt.Errorf("read creds entry %s: %w", base, err)
		}
		if len(data) > maxCredFileSize {
			return fmt.Errorf("creds entry %s exceeds %d bytes", base, maxCredFileSize)
		}
		found[base] = data
	}

	for name := range wanted {
		if _, ok := found[name]; !ok {
			return fmt.Errorf("creds archive missing %s", name)
		}
	}

	// Write to a fresh 0700 host temp dir. Reuse the handle's dir if a prior
	// attempt already created one.
	dir := handle.credsDir
	if dir == "" {
		dir, err = os.MkdirTemp("", "ac-enforcer-creds-")
		if err != nil {
			return fmt.Errorf("create creds temp dir: %w", err)
		}
	}
	for name, data := range found {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return fmt.Errorf("write cred %s: %w", name, err)
		}
	}

	handle.credsDir = dir
	handle.ClientCertPath = filepath.Join(dir, clientCertFile)
	handle.ClientKeyPath = filepath.Join(dir, clientKeyFile)
	handle.CACertPath = filepath.Join(dir, clientCAFile)
	return nil
}

// cleanupCreds removes the host temp directory holding a handle's retrieved
// credentials, if any. Safe to call with a nil handle or empty credsDir.
func cleanupCreds(handle *SidecarHandle) {
	if handle == nil || handle.credsDir == "" {
		return
	}
	_ = os.RemoveAll(handle.credsDir)
	handle.credsDir = ""
}
