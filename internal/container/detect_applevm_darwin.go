//go:build darwin

package container

import (
	"os"
	"path/filepath"
)

func probeAppleVMSocket() bool {
	// Allow an explicit override via the same env var the client honours.
	if p := os.Getenv("AC_APPLEVM_API"); p != "" {
		_, err := os.Stat(p)
		return err == nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	// ac-applevmd creates its control socket at this path.
	socketPath := filepath.Join(home, ".agentcontainers", "applevm", "applevmd.sock")
	_, err = os.Stat(socketPath)
	return err == nil
}
