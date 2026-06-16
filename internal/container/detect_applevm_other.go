//go:build !darwin

package container

func probeAppleVMSocket() bool {
	return false
}
