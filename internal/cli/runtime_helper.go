package cli

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

// newRuntime creates the appropriate container runtime based on the runtime
// flag value, for management commands (exec, logs, ps, stop, gc) that operate
// on existing containers without (re)applying enforcement. For the enforcing
// start path, use newEnforcingRuntime.
func newRuntime(runtimeFlag string, log *zap.Logger, enfLevel enforcement.Level) (container.Runtime, error) {
	return newEnforcingRuntime(runtimeFlag, log, enfLevel, nil, false, false)
}

// newEnforcingRuntime creates a container runtime wired for enforcement. When a
// pre-built enforcement strategy is provided (host-local Docker/Compose), it is
// injected directly so the runtime never reads AC_ENFORCER_* from the
// environment. The Sandbox runtime starts its own per-VM enforcer, so it
// receives the enforcement level and the insecure-dev opt-in instead and builds
// the strategy from the in-VM sidecar's connection profile.
// cgroupnsHost runs Docker containers in the host cgroup namespace
// (--cgroupns=host) for the kernel-primary posture; see config.EnforcerConfig.
// KernelPrimary. It applies only to the Docker runtime — the Sandbox runtime's
// cgroups live inside its VM, and the Compose runtime is driven by a compose
// file rather than direct create flags.
func newEnforcingRuntime(runtimeFlag string, log *zap.Logger, enfLevel enforcement.Level, strategy enforcement.Strategy, insecureDev bool, cgroupnsHost bool) (container.Runtime, error) {
	runtimeType := container.RuntimeType(runtimeFlag)

	// Auto-detect: probe for Sandbox, fall back to Docker.
	if runtimeType == "auto" {
		runtimeType = container.DetectRuntime(container.DefaultSandboxProber)
		log.Info("runtime auto-detected", zap.String("runtime", string(runtimeType)))
	}

	switch runtimeType {
	case container.RuntimeDocker:
		rt, err := container.NewDockerRuntime(
			container.WithDockerLogger(log),
			container.WithEnforcementLevel(enfLevel),
			container.WithEnforcementStrategy(strategy),
			container.WithCgroupnsHost(cgroupnsHost),
		)
		if err != nil {
			return nil, fmt.Errorf("creating docker runtime: %w", err)
		}
		return rt, nil
	case container.RuntimeCompose:
		rt, err := container.NewComposeRuntime(
			container.WithComposeLogger(log),
			container.WithComposeEnforcementLevel(enfLevel),
			container.WithComposeEnforcementStrategy(strategy),
		)
		if err != nil {
			return nil, fmt.Errorf("creating compose runtime: %w", err)
		}
		return rt, nil
	case container.RuntimeSandbox:
		rt, err := container.NewSandboxRuntime(
			container.WithSandboxLogger(log),
			container.WithSandboxEnforcementLevel(enfLevel),
			container.WithSandboxInsecureDev(insecureDev),
		)
		if err != nil {
			return nil, fmt.Errorf("creating sandbox runtime: %w", err)
		}
		return rt, nil
	default:
		return nil, fmt.Errorf("unknown runtime %q (valid: auto, docker, compose, sandbox)", runtimeFlag)
	}
}
