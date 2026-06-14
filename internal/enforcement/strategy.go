// Package enforcement provides a strategy-based enforcement layer that selects
// the best available mechanism (gRPC sidecar) and applies container
// security policy through it. If no mechanism is available, enforcement fails closed.
package enforcement

import (
	"context"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// Strategy applies and manages enforcement for a container.
//
// Bootstrap ordering is explicit. A caller that injects secrets must interleave
// the steps so credential ACLs are installed only after the secret files exist:
//
//	ApplyBasePolicy → InjectSecrets → ApplyCredentialACLs
//
// Apply is a convenience that performs ApplyBasePolicy followed by
// ApplyCredentialACLs in one call, for runtimes that do not inject secrets
// through the enforcer.
type Strategy interface {
	// Apply attaches full enforcement (base policy + credential ACLs) to a
	// container in one call. The initPID is the container's PID 1 as seen from
	// the host, used by the enforcer to access /proc/<pid>/root/. Prefer the
	// split ApplyBasePolicy / ApplyCredentialACLs when secrets are injected, so
	// ACLs are installed after the secret files exist.
	Apply(ctx context.Context, containerID string, initPID uint32, p *policy.ContainerPolicy) error

	// ApplyBasePolicy registers the container and applies network, filesystem,
	// and process policy — everything except credential ACLs.
	ApplyBasePolicy(ctx context.Context, containerID string, initPID uint32, p *policy.ContainerPolicy) error

	// ApplyCredentialACLs installs the secret credential ACLs. It must run after
	// the secret files have been injected so the enforcer can resolve each
	// secret's inode; an unresolvable path is a fatal error, never a silent skip.
	ApplyCredentialACLs(ctx context.Context, containerID string, p *policy.ContainerPolicy) error

	// Update modifies the enforcement policy for a running container.
	Update(ctx context.Context, containerID string, p *policy.ContainerPolicy) error

	// Remove detaches enforcement from a container.
	Remove(ctx context.Context, containerID string) error

	// InjectSecrets writes secret values into the container via the enforcer
	// sidecar. It must run after ApplyBasePolicy and before ApplyCredentialACLs:
	// the secret files must exist on disk before their ACLs are installed. The
	// enforcer writes each value to /run/secrets/<name>.
	InjectSecrets(ctx context.Context, containerID string, resolved map[string]*secrets.Secret) error

	// Events returns an audit event channel, or nil if the strategy
	// doesn't support event streaming.
	Events(containerID string) <-chan Event

	// Level returns the enforcement level this strategy provides.
	Level() Level
}
