package container

// SandboxProber checks if Docker Sandbox is available on the current system.
// Returns true if the Sandbox runtime can be used.
type SandboxProber func() bool

// DetectRuntime determines the best available runtime.
// If a SandboxProber is provided and returns true, RuntimeSandbox is selected.
// Otherwise, falls back to RuntimeDocker.
func DetectRuntime(prober SandboxProber) RuntimeType {
	if prober != nil && prober() {
		return RuntimeSandbox
	}
	return RuntimeDocker
}

// DefaultSandboxProber checks for the sandboxd socket on macOS.
// Returns false on non-macOS platforms or when Docker Desktop is not installed.
func DefaultSandboxProber() bool {
	return probeSandboxSocket()
}

// DefaultAppleVMProber checks for the ac-applevmd control socket on macOS.
// Returns false on non-macOS platforms or when ac-applevmd is not running.
// Apple containerization is opt-in via --runtime=applevm; this prober is exposed
// for callers that want to detect availability (it is not used by auto-detect,
// which prefers the Docker-based backends to avoid surprising existing users).
func DefaultAppleVMProber() bool {
	return probeAppleVMSocket()
}
