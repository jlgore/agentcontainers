// Package sidecar provides lifecycle management for the agentcontainer-enforcer sidecar
// container. It handles pulling, starting, health-checking, discovering, and
// stopping the enforcer container that provides BPF-based enforcement via gRPC.
package sidecar

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

const (
	// DefaultEnforcerImage is the default OCI image for the agentcontainer-enforcer sidecar.
	DefaultEnforcerImage = "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:latest"

	// DefaultPort is the default gRPC port for the agentcontainer-enforcer sidecar.
	DefaultPort = 50051

	// DefaultHealthTimeout is how long to wait for the enforcer to become healthy.
	DefaultHealthTimeout = 15 * time.Second

	// DefaultHealthInterval is how often to poll health during startup.
	DefaultHealthInterval = 500 * time.Millisecond

	// ContainerName is the well-known container name for the agentcontainer-enforcer sidecar.
	ContainerName = "agentcontainer-enforcer"

	// LabelComponent identifies the container as an enforcer component.
	LabelComponent = "dev.agentcontainer/component"

	// LabelManaged indicates the container was started by ac (not pre-existing).
	LabelManaged = "dev.agentcontainer/managed"

	// credsContainerDir is the in-container directory the enforcer writes its
	// ephemeral mTLS material to (passed via --creds-dir).
	credsContainerDir = "/creds"

	// Client-side credential filenames written by the enforcer into credsContainerDir.
	clientCertFile = "client.crt"
	clientKeyFile  = "client.key"
	clientCAFile   = "client-ca.crt"
)

// SidecarHandle represents a running or pre-existing sidecar instance, together
// with the complete connection profile (address + mTLS material) needed to
// reach it. The profile is threaded explicitly into every enforcer client so no
// caller has to consult process-global AC_ENFORCER_* environment variables.
type SidecarHandle struct {
	// ContainerID is the Docker container ID. Empty for external sidecars.
	ContainerID string

	// Addr is the gRPC endpoint address (e.g., "127.0.0.1:50051").
	Addr string

	// Managed is true if this sidecar was started by ac (not pre-existing).
	// Only managed sidecars are stopped during teardown.
	Managed bool

	// CACertPath, ClientCertPath, and ClientKeyPath are host paths to the
	// ephemeral mTLS material retrieved from the managed enforcer's --creds-dir.
	// They are empty for plaintext (insecure-dev) or external sidecars whose
	// credentials are supplied out of band.
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string

	// InsecureDev records that this endpoint was permitted to run plaintext
	// without mTLS via an explicit development-only opt-in.
	InsecureDev bool

	// credsDir is the host temp directory holding the retrieved credentials.
	// It is removed when a managed sidecar is stopped.
	credsDir string
}

// Profile returns the enforcement connection profile for this sidecar, suitable
// for NewStrategyFromProfile / ProbeEnforcerHealthProfile.
func (h *SidecarHandle) Profile() enforcement.ConnectionProfile {
	return enforcement.ConnectionProfile{
		Addr:           h.Addr,
		CACertPath:     h.CACertPath,
		ClientCertPath: h.ClientCertPath,
		ClientKeyPath:  h.ClientKeyPath,
		InsecureDev:    h.InsecureDev,
	}
}

// StartOptions configures sidecar startup behavior.
type StartOptions struct {
	// Image is the OCI reference to pull and run.
	// Default: DefaultEnforcerImage
	Image string

	// Port is the host TCP port to bind (default: 50051).
	Port int

	// HealthTimeout is how long to wait for SERVING (default: 15s).
	HealthTimeout time.Duration

	// HealthInterval is the polling interval (default: 500ms).
	HealthInterval time.Duration

	// Required: if true (default), return an error when health check fails
	// or image cannot be pulled. If false, return (nil, nil) and log a warning.
	Required bool

	// HealthCheckAddr overrides the default health check target address.
	// If empty, defaults to "127.0.0.1:<Port>" (suitable for host-local sidecars).
	// For in-VM sidecars, set this to "<vm_ip>:<port>" so the host can reach
	// the enforcer inside the VM.
	HealthCheckAddr string

	// HostBindIP restricts the published gRPC port to a single host interface.
	// Host-local managed sidecars set this to "127.0.0.1" so the control plane
	// is never exposed on all interfaces. Leave empty for in-VM sidecars, which
	// must be reachable from the host at the VM's IP.
	HostBindIP string

	// Mutual TLS. When true (the default for managed sidecars), the enforcer is
	// started with --creds-dir, generating ephemeral mTLS material that is
	// retrieved over the Docker API and returned in the SidecarHandle. When
	// false, the enforcer runs plaintext — permitted only as an explicit
	// development opt-in (see InsecureDev).
	MTLS bool

	// InsecureDev records that plaintext operation was explicitly requested.
	// It is propagated to the returned handle's connection profile so a
	// non-loopback plaintext endpoint is permitted rather than rejected.
	InsecureDev bool
}

func (o *StartOptions) applyDefaults() {
	if o.Image == "" {
		o.Image = DefaultEnforcerImage
	}
	if o.Port == 0 {
		o.Port = DefaultPort
	}
	if o.HealthTimeout == 0 {
		o.HealthTimeout = DefaultHealthTimeout
	}
	if o.HealthInterval == 0 {
		o.HealthInterval = DefaultHealthInterval
	}
}

// DiscoverOptions configures external sidecar discovery.
type DiscoverOptions struct {
	// ConfigAddr is from agent.enforcer.addr in agentcontainer.json.
	// Empty string means not configured.
	ConfigAddr string
}

// DiscoverResult describes how the sidecar was found.
type DiscoverResult struct {
	// Addr is the gRPC endpoint to use. Empty if no sidecar found.
	Addr string

	// Source is "env", "config", or "" (not found).
	Source string
}

// HealthProber is a function that checks if a gRPC endpoint is healthy.
// This allows injection of a mock for testing.
type HealthProber func(target string) bool

// ProfileProber checks if an enforcer endpoint is healthy using a full
// connection profile (so an mTLS-only endpoint is probed with its credentials).
type ProfileProber func(p enforcement.ConnectionProfile) bool

// defaultHealthProber uses the enforcement package's plaintext health probe.
var defaultHealthProber HealthProber = enforcement.ProbeEnforcerHealth

// defaultProfileProber probes with the profile's mTLS credentials when present,
// and otherwise delegates to defaultHealthProber so a plaintext endpoint shares
// the same (test-swappable) probe seam.
var defaultProfileProber ProfileProber = func(p enforcement.ConnectionProfile) bool {
	if p.HasMTLS() {
		return enforcement.ProbeEnforcerHealthProfile(p)
	}
	return defaultHealthProber(p.Addr)
}

// StartSidecar pulls (if necessary) and starts the agentcontainer-enforcer container,
// then polls the gRPC health endpoint until SERVING or timeout.
// Returns a SidecarHandle with Managed: true.
//
// Error behavior:
//   - If Required is true (default): any failure returns a non-nil error.
//   - If Required is false (explicit opt-out): failures return (nil, nil).
func StartSidecar(ctx context.Context, dockerClient client.APIClient, opts StartOptions) (*SidecarHandle, error) {
	opts.applyDefaults()

	// 1. Ensure image is available locally.
	if err := EnsureImage(ctx, dockerClient, opts.Image); err != nil {
		if opts.Required {
			return nil, fmt.Errorf("pulling image %s: %w", opts.Image, err)
		}
		return nil, nil
	}

	// 2. Create the container.
	portStr := fmt.Sprintf("%d", opts.Port)
	exposedPort := network.MustParsePort(portStr + "/tcp")

	// Command: bind to all interfaces *inside* the container netns (host port
	// publication is what restricts external reach — see PortBindings below).
	// In mTLS mode, --creds-dir makes the enforcer generate ephemeral session
	// credentials and require client certificates on every RPC.
	cmd := []string{"--listen", "0.0.0.0:" + portStr}
	if opts.MTLS {
		cmd = append(cmd, "--creds-dir", credsContainerDir)
	}

	containerCfg := &container.Config{
		Image: opts.Image,
		Cmd:   cmd,
		ExposedPorts: network.PortSet{
			exposedPort: {},
		},
		Labels: map[string]string{
			LabelComponent: "enforcer",
			LabelManaged:   "true",
		},
	}

	// Publish the gRPC port to a single host interface when requested. Managed
	// host-local sidecars bind 127.0.0.1 so the control plane is never exposed
	// on all host interfaces; in-VM sidecars leave HostIP empty so the host can
	// reach them at the VM's address.
	portBinding := network.PortBinding{HostPort: portStr}
	if opts.HostBindIP != "" {
		hostIP, err := netip.ParseAddr(opts.HostBindIP)
		if err != nil {
			return nil, fmt.Errorf("invalid HostBindIP %q: %w", opts.HostBindIP, err)
		}
		portBinding.HostIP = hostIP
	}

	hostCfg := &container.HostConfig{
		CapAdd: []string{
			"BPF",
			"NET_ADMIN",
			"SYS_ADMIN",
			"SYS_RESOURCE",
			// SYS_PTRACE is required to inject secrets: the enforcer writes them
			// through the agent's /proc/<init_pid>/root magic symlink (see
			// grpc.rs InjectSecrets). Dereferencing another process's
			// /proc/<pid>/root triggers ptrace_may_access(), which the yama LSM
			// at ptrace_scope>=1 (the distro default) denies for non-descendant
			// processes unless the caller holds CAP_SYS_PTRACE. Without it,
			// injection fails with EACCES the moment it steps into the agent root.
			"SYS_PTRACE",
		},
		PidMode: container.PidMode("host"),
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   "/sys/fs/cgroup",
				Target:   "/sys/fs/cgroup",
				ReadOnly: true,
			},
			{
				Type:   mount.TypeBind,
				Source: "/sys/fs/bpf",
				Target: "/sys/fs/bpf",
			},
			// UDS mount deferred to Phase 6 (PRD-015 non-goal).
			// {Type: mount.TypeBind, Source: "/run/agentcontainer-enforcer", Target: "/run/agentcontainer-enforcer"},
		},
		PortBindings: network.PortMap{
			exposedPort: {portBinding},
		},
		RestartPolicy: container.RestartPolicy{
			Name: container.RestartPolicyUnlessStopped,
		},
	}

	resp, err := dockerClient.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     containerCfg,
		HostConfig: hostCfg,
		Name:       ContainerName,
	})
	addr := opts.HealthCheckAddr
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", opts.Port)
	}

	if err != nil {
		// Handle name conflict: a container named "agentcontainer-enforcer" already exists
		// (e.g., from a previous crash or concurrent agentcontainer run). Try to adopt it.
		if isNameConflict(err) {
			// Retrieve the existing container's credentials so the adoption
			// health probe authenticates exactly as a real client would. A
			// plaintext probe of an mTLS enforcer would always fail and wrongly
			// destroy a healthy sidecar.
			adoptHandle := &SidecarHandle{Addr: addr, Managed: false, InsecureDev: opts.InsecureDev}
			if opts.MTLS {
				if credErr := retrieveCreds(ctx, dockerClient, ContainerName, adoptHandle); credErr != nil {
					adoptHandle = nil // can't authenticate — treat as unhealthy
				}
			}
			if adoptHandle != nil && defaultProfileProber(adoptHandle.Profile()) {
				// Existing container is healthy — adopt it as unmanaged.
				return adoptHandle, nil
			}
			if adoptHandle != nil {
				cleanupCreds(adoptHandle)
			}
			// Existing container is unhealthy — remove it and retry once.
			_ = removeByName(ctx, dockerClient, ContainerName)
			resp, err = dockerClient.ContainerCreate(ctx, client.ContainerCreateOptions{
				Config:     containerCfg,
				HostConfig: hostCfg,
				Name:       ContainerName,
			})
			if err != nil {
				if opts.Required {
					return nil, fmt.Errorf("creating container (retry after conflict): %w", err)
				}
				return nil, nil
			}
			// Fall through to start the freshly created container.
		} else {
			if opts.Required {
				return nil, fmt.Errorf("creating container: %w", err)
			}
			return nil, nil
		}
	}

	// 3. Start the container.
	if _, err := dockerClient.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		// Best-effort cleanup on start failure.
		_, _ = dockerClient.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
		if opts.Required {
			return nil, fmt.Errorf("starting container: %w", err)
		}
		return nil, nil
	}

	handle := &SidecarHandle{
		ContainerID: resp.ID,
		Addr:        addr,
		Managed:     true,
		InsecureDev: opts.InsecureDev,
	}

	// 4. Retrieve ephemeral mTLS credentials before the health gate. The
	// enforcer writes them to --creds-dir at startup, before binding the gRPC
	// server; because the server requires mTLS, the health probe must present
	// these client credentials. Failure here is fatal: an mTLS sidecar we can't
	// authenticate to is unusable.
	if opts.MTLS {
		if err := retrieveCredsWithRetry(ctx, dockerClient, resp.ID, handle, opts.HealthTimeout, opts.HealthInterval); err != nil {
			cleanupContainer(ctx, dockerClient, resp.ID)
			if opts.Required {
				return nil, fmt.Errorf("retrieving enforcer credentials: %w", err)
			}
			return nil, nil
		}
	}

	// 5. Wait for health check, presenting the same credentials a real client uses.
	if err := WaitHealthyProfile(ctx, handle.Profile(), opts.HealthTimeout, opts.HealthInterval); err != nil {
		// Health check failed — clean up the container and credentials.
		cleanupContainer(ctx, dockerClient, resp.ID)
		cleanupCreds(handle)
		if opts.Required {
			return nil, fmt.Errorf("enforcer failed to reach SERVING: %w", err)
		}
		return nil, nil
	}

	return handle, nil
}

// StopSidecar gracefully stops and removes the managed sidecar container.
// If handle.Managed is false (external sidecar), it returns immediately.
func StopSidecar(ctx context.Context, dockerClient client.APIClient, handle *SidecarHandle) error {
	if handle == nil || !handle.Managed {
		return nil
	}

	if _, err := dockerClient.ContainerStop(ctx, handle.ContainerID, client.ContainerStopOptions{}); err != nil {
		// Best-effort: try to force remove even if stop failed.
		_, _ = dockerClient.ContainerRemove(ctx, handle.ContainerID, client.ContainerRemoveOptions{
			Force:         true,
			RemoveVolumes: true,
		})
		return fmt.Errorf("stopping sidecar: %w", err)
	}

	if _, err := dockerClient.ContainerRemove(ctx, handle.ContainerID, client.ContainerRemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	}); err != nil {
		return fmt.Errorf("removing sidecar: %w", err)
	}

	// Remove the retrieved ephemeral credentials from the host.
	cleanupCreds(handle)

	return nil
}

// WaitHealthy polls the gRPC health endpoint at target until the service
// reports SERVING or the timeout expires.
func WaitHealthy(ctx context.Context, target string, timeout, interval time.Duration) error {
	return WaitHealthyWithProber(ctx, target, timeout, interval, defaultHealthProber)
}

// WaitHealthyProfile polls the gRPC health endpoint using the connection
// profile (so an mTLS endpoint is probed with its client credentials) until the
// service reports SERVING or the timeout expires.
func WaitHealthyProfile(ctx context.Context, profile enforcement.ConnectionProfile, timeout, interval time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timed out waiting for agentcontainer-enforcer health on %s", profile.Addr)
		case <-ticker.C:
			if defaultProfileProber(profile) {
				return nil
			}
		}
	}
}

// WaitHealthyWithProber polls the gRPC health endpoint using the provided
// prober function. This is useful for testing with mock probers.
func WaitHealthyWithProber(ctx context.Context, target string, timeout, interval time.Duration, prober HealthProber) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timed out waiting for agentcontainer-enforcer health on %s", target)
		case <-ticker.C:
			if prober(target) {
				return nil
			}
		}
	}
}

// DiscoverExternalSidecar checks whether a pre-existing sidecar is reachable.
// Priority order: AC_ENFORCER_ADDR env var > config addr.
// Returns a result with empty Addr if no sidecar is found.
func DiscoverExternalSidecar(opts DiscoverOptions) DiscoverResult {
	return DiscoverExternalSidecarWithProber(opts, defaultHealthProber)
}

// DiscoverExternalSidecarWithProber checks for a pre-existing sidecar using
// the provided health prober. This is useful for testing.
func DiscoverExternalSidecarWithProber(opts DiscoverOptions, prober HealthProber) DiscoverResult {
	// 1. Check AC_ENFORCER_ADDR env var.
	if envAddr := os.Getenv("AC_ENFORCER_ADDR"); envAddr != "" {
		if prober(envAddr) {
			return DiscoverResult{Addr: envAddr, Source: "env"}
		}
	}

	// 2. Check config addr.
	if opts.ConfigAddr != "" {
		if prober(opts.ConfigAddr) {
			return DiscoverResult{Addr: opts.ConfigAddr, Source: "config"}
		}
	}

	// 3. Not found.
	return DiscoverResult{}
}

// EnsureImage pulls the image if it is not already present locally.
func EnsureImage(ctx context.Context, dockerClient client.APIClient, ref string) error {
	if _, err := dockerClient.ImageInspect(ctx, ref); err == nil {
		return nil
	}

	reader, err := dockerClient.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pulling image %s: %w", ref, err)
	}
	defer reader.Close() //nolint:errcheck

	// Drain the pull output to ensure the pull completes.
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("reading pull response for %s: %w", ref, err)
	}
	return nil
}

// isNameConflict returns true if the error indicates a container name conflict.
func isNameConflict(err error) bool {
	return strings.Contains(err.Error(), "is already in use")
}

// removeByName force-removes a container by name, best-effort.
func removeByName(ctx context.Context, dockerClient client.APIClient, name string) error {
	_, err := dockerClient.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true})
	return err
}

// cleanupContainer stops and removes a container, best-effort.
func cleanupContainer(ctx context.Context, dockerClient client.APIClient, containerID string) {
	_, _ = dockerClient.ContainerStop(ctx, containerID, client.ContainerStopOptions{})
	_, _ = dockerClient.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	})
}
