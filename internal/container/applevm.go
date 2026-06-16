package container

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/applevm"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

// appleVMNamePrefix is prepended to the agent config name to form the Apple
// containerization VM name. It is distinct from the Docker Sandbox prefix
// ("ac-") so a machine running both backends never cross-lists VMs in List().
const appleVMNamePrefix = "acvm-"

// defaultAppleVMImage is the default agent image used when the config does not
// specify one. Unlike the Docker Sandbox template, the Apple backend boots a
// microVM whose workload is a private Docker daemon, so the agent image must be
// docker-in-docker capable.
const defaultAppleVMImage = "docker:dind"

// AppleVMOption configures an Apple containerization runtime.
type AppleVMOption func(*appleVMOptions)

type appleVMOptions struct {
	logger      *zap.Logger
	client      SandboxAPI
	enfLevel    enforcement.Level
	extraSbOpts []SandboxOption
}

// WithAppleVMLogger sets the logger for the Apple VM runtime.
func WithAppleVMLogger(l *zap.Logger) AppleVMOption {
	return func(o *appleVMOptions) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithAppleVMClient injects a SandboxAPI client (for testing or custom config).
// When nil, a default applevm.Client connected to the ac-applevmd socket is used.
func WithAppleVMClient(c SandboxAPI) AppleVMOption {
	return func(o *appleVMOptions) {
		if c != nil {
			o.client = c
		}
	}
}

// WithAppleVMEnforcementLevel sets the enforcement level for the Apple VM runtime.
func WithAppleVMEnforcementLevel(l enforcement.Level) AppleVMOption {
	return func(o *appleVMOptions) {
		o.enfLevel = l
	}
}

// WithAppleVMSandboxOptions passes additional SandboxOptions straight through to
// the underlying SandboxRuntime. Primarily useful for testing (e.g. injecting a
// fake docker client factory or sidecar funcs).
func WithAppleVMSandboxOptions(opts ...SandboxOption) AppleVMOption {
	return func(o *appleVMOptions) {
		o.extraSbOpts = append(o.extraSbOpts, opts...)
	}
}

// NewAppleVMRuntime creates a Runtime backed by Apple's containerization library
// via the ac-applevmd helper daemon. Because ac-applevmd speaks sandboxd's wire
// contract, this is a thin wrapper over SandboxRuntime: it injects an
// applevm.Client and overrides the runtime identity (RuntimeAppleVM, the "acvm-"
// VM name prefix, and a docker-in-docker default image). All VM-over-Docker
// lifecycle behaviour — image pull, container create/exec/logs, CA injection,
// the in-VM enforcer sidecar, and MCP sidecars — is inherited unchanged.
func NewAppleVMRuntime(opts ...AppleVMOption) (*SandboxRuntime, error) {
	o := &appleVMOptions{
		logger: zap.NewNop(),
	}
	for _, opt := range opts {
		opt(o)
	}

	client := o.client
	if client == nil {
		c, err := applevm.NewClient(applevm.WithLogger(o.logger))
		if err != nil {
			return nil, fmt.Errorf("applevm runtime: creating client: %w", err)
		}
		client = c
	}

	sbOpts := []SandboxOption{
		WithSandboxLogger(o.logger),
		WithSandboxClient(client),
		WithSandboxEnforcementLevel(o.enfLevel),
		WithRuntimeIdentity(RuntimeAppleVM, appleVMNamePrefix, defaultAppleVMImage),
	}
	sbOpts = append(sbOpts, o.extraSbOpts...)

	rt, err := NewSandboxRuntime(sbOpts...)
	if err != nil {
		return nil, fmt.Errorf("applevm runtime: %w", err)
	}
	return rt, nil
}
