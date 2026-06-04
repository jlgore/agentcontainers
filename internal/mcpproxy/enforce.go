// Kernel enforcement wiring for container backends: registers each stdio
// backend container with the eBPF enforcer and applies its kernel-enforceable
// policy (network egress + filesystem deny list). Shell policy is NOT applied
// at the kernel — it is an argument-level policy enforced by the in-process
// OPA evaluator on tools/call.
package mcpproxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/moby/moby/client"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
)

// networkPolicyRefreshInterval is how often hostname-based network policies
// are re-applied so the enforcer re-resolves DNS (CDN/cloud IPs rotate
// during long forensic sessions). Stale IPs are not removed until the
// container unregisters — a documented limitation (SPEC §14).
const networkPolicyRefreshInterval = 5 * time.Minute

// registerBackendEnforcement registers a freshly started container backend
// with the eBPF enforcer and applies its policy. Returns a cleanup function
// that unregisters the container (sweeping its per-cgroup map entries).
//
// Every container backend is registered when an enforcer is connected —
// kernel containment (default-deny egress) is the point of running one. A
// backend that needs egress declares it in policy.network. Operators who
// want no kernel enforcement set enforcer.required: false.
func registerBackendEnforcement(ctx context.Context, deps Deps, b *Backend, tool config.MCPToolConfig) (func(context.Context) error, error) {
	ec := deps.Enforcer
	log := deps.Logger

	inspect, err := deps.Docker.ContainerInspect(ctx, b.ContainerID, client.ContainerInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: backend %s: inspecting container for enforcement: %w", b.Name, err)
	}
	initPid := uint32(0)
	if st := inspect.Container.State; st != nil && st.Pid > 0 {
		initPid = uint32(st.Pid)
	}

	cgroupPath, err := enforcement.ResolveCgroupPath(b.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: backend %s: resolving cgroup path: %w", b.Name, err)
	}

	resp, err := ec.RegisterContainer(ctx, &enforcerapi.RegisterContainerRequest{
		ContainerId: b.ContainerID,
		CgroupPath:  cgroupPath,
		InitPid:     initPid,
	})
	if err != nil {
		return nil, fmt.Errorf("mcpproxy: backend %s: registering with enforcer: %w", b.Name, err)
	}
	log.Info("registered backend container with enforcer",
		zap.String("backend", b.Name),
		zap.String("containerID", b.ContainerID),
		zap.Uint64("cgroupID", resp.GetCgroupId()))

	// Network policy is applied unconditionally: an absent or empty
	// policy.network means default-deny egress (loopback excepted) — the
	// spec's intent for forensic MCP servers.
	netReq := translateNetworkCaps(b.ContainerID, tool.Policy)
	b.netPolicy = netReq
	if _, err := ec.ApplyNetworkPolicy(ctx, netReq); err != nil {
		return nil, fmt.Errorf("mcpproxy: backend %s: applying network policy: %w", b.Name, err)
	}

	// Filesystem policy: deny_paths are kernel-enforced (DENIED_INODES);
	// read/write paths populate ALLOWED_INODES (write-protection applies to
	// listed read-only inodes; full allowlist enforcement is deferred —
	// the LSM runs in deny-list mode).
	if tool.Policy != nil && tool.Policy.Filesystem != nil {
		fs := tool.Policy.Filesystem
		if _, err := ec.ApplyFilesystemPolicy(ctx, &enforcerapi.FilesystemPolicyRequest{
			ContainerId: b.ContainerID,
			ReadPaths:   fs.Read,
			WritePaths:  fs.Write,
			DenyPaths:   fs.Deny,
		}); err != nil {
			return nil, fmt.Errorf("mcpproxy: backend %s: applying filesystem policy: %w", b.Name, err)
		}
	}

	unregister := func(cctx context.Context) error {
		if _, err := ec.UnregisterContainer(cctx, &enforcerapi.UnregisterContainerRequest{
			ContainerId: b.ContainerID,
		}); err != nil {
			return fmt.Errorf("mcpproxy: backend %s: unregistering from enforcer: %w", b.Name, err)
		}
		return nil
	}
	return unregister, nil
}

// translateNetworkCaps converts config.NetworkCaps to the enforcer request.
// Egress rules with a port become precise (host, port, protocol) tuples;
// port-less rules become host-wide allows. The deny list is not forwarded:
// the kernel layer is default-deny, so an explicit deny adds nothing today
// (BLOCKED_CIDRS population is reserved for always-deny overrides).
func translateNetworkCaps(containerID string, p *config.MCPServerPolicy) *enforcerapi.NetworkPolicyRequest {
	req := &enforcerapi.NetworkPolicyRequest{ContainerId: containerID}
	if p == nil || p.Network == nil {
		return req
	}
	for _, rule := range p.Network.Egress {
		if rule.Port > 0 {
			proto := rule.Protocol
			if proto == "" {
				proto = "tcp"
			}
			req.EgressRules = append(req.EgressRules, &enforcerapi.EgressRule{
				Host:     rule.Host,
				Port:     uint32(rule.Port),
				Protocol: proto,
			})
		} else {
			req.AllowedHosts = append(req.AllowedHosts, rule.Host)
		}
	}
	return req
}

// refreshNetworkPolicies re-applies each container backend's network policy
// on a fixed interval so the enforcer re-resolves policy hostnames. Runs
// until ctx is cancelled (proxy shutdown).
func (p *Proxy) refreshNetworkPolicies(ctx context.Context) {
	ticker := time.NewTicker(networkPolicyRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		p.mu.Lock()
		backends := make([]*Backend, 0, len(p.backends))
		for _, b := range p.backends {
			if b.netPolicy != nil && hasHostnames(b.netPolicy) {
				backends = append(backends, b)
			}
		}
		p.mu.Unlock()
		for _, b := range backends {
			if _, err := p.deps.Enforcer.ApplyNetworkPolicy(ctx, b.netPolicy); err != nil {
				p.deps.Logger.Warn("network policy refresh failed",
					zap.String("backend", b.Name), zap.Error(err))
			} else {
				p.deps.Logger.Debug("re-resolved network policy hostnames",
					zap.String("backend", b.Name))
			}
		}
	}
}

// hasHostnames reports whether the request references any hostname (as
// opposed to IP literals only) — only those need periodic re-resolution.
func hasHostnames(req *enforcerapi.NetworkPolicyRequest) bool {
	for _, h := range req.AllowedHosts {
		if !isIPLiteral(h) {
			return true
		}
	}
	for _, r := range req.EgressRules {
		if !isIPLiteral(r.Host) {
			return true
		}
	}
	return false
}

func isIPLiteral(host string) bool {
	return net.ParseIP(host) != nil
}
