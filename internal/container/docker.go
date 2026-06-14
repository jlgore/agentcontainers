package container

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
)

const (
	// defaultStopTimeout is the graceful shutdown period before SIGKILL.
	defaultStopTimeout = 10 * time.Second

	// defaultWorkspaceTarget is the in-container mount point for the workspace.
	defaultWorkspaceTarget = "/workspace"

	// labelPrefix is used for container labels to identify agentcontainer sessions.
	labelPrefix = "dev.agentcontainer"
)

// Compile-time check that DockerRuntime satisfies the Runtime interface.
var _ Runtime = (*DockerRuntime)(nil)

// Compile-time check that DockerRuntime supports interactive (TTY) exec.
var _ InteractiveExecer = (*DockerRuntime)(nil)

// DockerRuntime implements the Runtime interface using the Docker Engine API.
type DockerRuntime struct {
	client      client.APIClient
	logger      *zap.Logger
	stopTimeout time.Duration
	strategy    enforcement.Strategy
}

// DockerOption configures a DockerRuntime.
type DockerOption func(*dockerOptions)

// dockerOptions holds the configuration for a DockerRuntime.
type dockerOptions struct {
	client           client.APIClient
	logger           *zap.Logger
	stopTimeout      time.Duration
	enforcementLevel *enforcement.Level
	strategy         enforcement.Strategy
}

// defaultDockerOptions returns sensible defaults for the Docker runtime.
func defaultDockerOptions() *dockerOptions {
	return &dockerOptions{
		logger:      zap.NewNop(),
		stopTimeout: defaultStopTimeout,
	}
}

// WithDockerClient sets a pre-configured Docker API client. This is useful for
// testing or when the caller needs to customise TLS, API version, or host.
func WithDockerClient(c client.APIClient) DockerOption {
	return func(o *dockerOptions) {
		if c != nil {
			o.client = c
		}
	}
}

// WithDockerLogger sets the logger for the Docker runtime.
func WithDockerLogger(l *zap.Logger) DockerOption {
	return func(o *dockerOptions) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithStopTimeout sets the graceful shutdown timeout before force-killing
// a container.
func WithStopTimeout(d time.Duration) DockerOption {
	return func(o *dockerOptions) {
		if d > 0 {
			o.stopTimeout = d
		}
	}
}

// WithEnforcementLevel sets the enforcement level for the Docker runtime.
// When set to a level other than LevelNone, a Strategy is created during
// NewDockerRuntime from process environment (AC_ENFORCER_*). Prefer
// WithEnforcementStrategy, which threads an explicit connection profile and
// does not depend on process-global environment variables.
func WithEnforcementLevel(level enforcement.Level) DockerOption {
	return func(o *dockerOptions) {
		o.enforcementLevel = &level
	}
}

// WithEnforcementStrategy injects a pre-built enforcement strategy (e.g. one
// constructed from a sidecar's connection profile via
// enforcement.NewStrategyFromProfile). When set it takes precedence over
// WithEnforcementLevel, so the runtime never has to read AC_ENFORCER_* itself.
func WithEnforcementStrategy(s enforcement.Strategy) DockerOption {
	return func(o *dockerOptions) {
		if s != nil {
			o.strategy = s
		}
	}
}

// NewDockerRuntime creates a new Docker-backed Runtime. If no client is provided
// via WithDockerClient, it creates one from the default environment variables
// (DOCKER_HOST, DOCKER_TLS_VERIFY, etc.).
func NewDockerRuntime(opts ...DockerOption) (*DockerRuntime, error) {
	o := defaultDockerOptions()
	for _, opt := range opts {
		opt(o)
	}

	if o.client == nil {
		c, err := client.New(client.FromEnv)
		if err != nil {
			return nil, fmt.Errorf("docker runtime: creating client: %w", err)
		}
		o.client = c
	}

	d := &DockerRuntime{
		client:      o.client,
		logger:      o.logger,
		stopTimeout: o.stopTimeout,
	}

	// Prefer an explicitly injected strategy (built from a connection profile).
	// Fall back to deriving one from the enforcement level via the environment.
	switch {
	case o.strategy != nil:
		d.strategy = o.strategy
		d.logger.Info("enforcement strategy configured",
			zap.String("level", d.strategy.Level().String()),
			zap.String("source", "profile"),
		)
	case o.enforcementLevel != nil && *o.enforcementLevel != enforcement.LevelNone:
		level := *o.enforcementLevel
		d.strategy = enforcement.NewStrategy(level)
		d.logger.Info("enforcement strategy configured",
			zap.String("level", level.String()),
			zap.String("source", "env"),
		)
	}

	return d, nil
}

// Start pulls the image (if not already present), creates a container from the
// AgentContainer configuration, and starts it.
func (d *DockerRuntime) Start(ctx context.Context, cfg *config.AgentContainer, opts StartOptions) (*Session, error) {
	if cfg.Image == "" {
		return nil, fmt.Errorf("docker runtime: image is required")
	}

	// Use the lockfile-pinned digest reference when available (F-4
	// dual-resolution fix): both policy extraction and image pull must use the
	// same content-addressed manifest, preventing a tag swap between the two
	// operations. When PinnedImageRef is set it overrides cfg.Image for the
	// pull and container create; cfg.Image is used only as a display name.
	imageRef := cfg.Image
	if opts.PinnedImageRef != "" {
		imageRef = opts.PinnedImageRef
	}

	// Pull image if not present locally.
	if err := d.ensureImage(ctx, imageRef); err != nil {
		return nil, fmt.Errorf("docker runtime: pulling image: %w", err)
	}

	containerCfg, hostCfg, networkCfg := d.buildContainerConfig(cfg, opts)

	// When the policy enables egress ("bridge"), the container attaches to a
	// per-agent user-defined bridge for embedded DNS (see buildContainerConfig).
	// Create it before ContainerCreate so the attachment resolves.
	netPolicy := opts.Policy
	if netPolicy == nil {
		netPolicy = defaultContainerPolicy()
	}
	if netPolicy.NetworkMode == "bridge" {
		if err := d.ensureAgentNetwork(ctx, agentNetworkName(cfg.Name)); err != nil {
			return nil, fmt.Errorf("docker runtime: ensuring agent network: %w", err)
		}
	}

	d.logger.Info("creating container",
		zap.String("image", imageRef),
		zap.String("name", cfg.Name),
	)

	resp, err := d.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:           containerCfg,
		HostConfig:       hostCfg,
		NetworkingConfig: networkCfg,
		Name:             cfg.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("docker runtime: creating container: %w", err)
	}

	// Resolve policy for enforcement.
	p := opts.Policy
	if p == nil {
		p = defaultContainerPolicy()
	}

	if _, err := d.client.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		_, _ = d.client.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
		return nil, fmt.Errorf("docker runtime: starting container: %w", err)
	}

	d.logger.Info("container started", zap.String("id", resp.ID))

	// teardownUnenforced force-removes the container without unpausing it, so a
	// container can never be left running with incomplete enforcement. Best-effort
	// enforcement removal first cleans up any partially-installed BPF state.
	teardownUnenforced := func() {
		if d.strategy != nil {
			_ = d.strategy.Remove(ctx, resp.ID)
		}
		_, _ = d.client.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
	}

	// When enforcement is active, bootstrap atomically: pause the container
	// immediately so it cannot execute a single instruction before policy and
	// secrets are fully installed, then apply enforcement in a strict order:
	//
	//   pause → base policy → inject secrets → credential ACLs → unpause
	//
	// Credential ACLs are installed only after the secret files exist, so the
	// enforcer can resolve each secret's inode. Any failure tears the container
	// down without ever unpausing it.
	if d.strategy != nil {
		if _, err := d.client.ContainerPause(ctx, resp.ID, client.ContainerPauseOptions{}); err != nil {
			teardownUnenforced()
			return nil, fmt.Errorf("docker runtime: pausing container for enforcement bootstrap: %w", err)
		}

		// Inspect (while paused) to get the init PID for enforcer access to
		// /proc/<pid>/root/. Fatal on failure: without the PID the enforcer
		// cannot inject secrets, and initPID=0 would target /proc/0/root.
		inspectResult, err := d.client.ContainerInspect(ctx, resp.ID, client.ContainerInspectOptions{})
		if err != nil {
			teardownUnenforced()
			return nil, fmt.Errorf("docker runtime: inspecting container for init PID: %w", err)
		}
		initPID := uint32(inspectResult.Container.State.Pid)

		// 1. Base policy: register + network/filesystem/process (no ACLs yet).
		if err := d.strategy.ApplyBasePolicy(ctx, resp.ID, initPID, p); err != nil {
			teardownUnenforced()
			return nil, fmt.Errorf("docker runtime: applying base policy: %w", err)
		}

		// 2. Inject secrets while paused, so the files exist before their ACLs.
		if len(opts.ResolvedSecrets) > 0 {
			if err := d.strategy.InjectSecrets(ctx, resp.ID, opts.ResolvedSecrets); err != nil {
				teardownUnenforced()
				return nil, fmt.Errorf("docker runtime: injecting secrets: %w", err)
			}
			d.logger.Info("secrets injected via enforcer",
				zap.String("id", resp.ID),
				zap.Int("count", len(opts.ResolvedSecrets)),
			)
		}

		// 3. Credential ACLs, now that the secret files exist. A path that
		// cannot be resolved is fatal in the enforcer (no silent skip).
		if err := d.strategy.ApplyCredentialACLs(ctx, resp.ID, p); err != nil {
			teardownUnenforced()
			return nil, fmt.Errorf("docker runtime: installing credential ACLs: %w", err)
		}

		// 4. Resume only after every step succeeded.
		if _, err := d.client.ContainerUnpause(ctx, resp.ID, client.ContainerUnpauseOptions{}); err != nil {
			teardownUnenforced()
			return nil, fmt.Errorf("docker runtime: unpausing container after enforcement bootstrap: %w", err)
		}

		d.logger.Info("enforcement applied",
			zap.String("id", resp.ID),
			zap.String("level", d.strategy.Level().String()),
		)
	}

	return &Session{
		ContainerID: resp.ID,
		RuntimeType: RuntimeDocker,
		Status:      "running",
		CreatedAt:   time.Now(),
	}, nil
}

// Stop gracefully stops the container, waits for the stop timeout, then removes it.
func (d *DockerRuntime) Stop(ctx context.Context, session *Session) error {
	if session == nil {
		return fmt.Errorf("docker runtime: nil session")
	}

	d.logger.Info("stopping container", zap.String("id", session.ContainerID))

	// Remove enforcement before stopping the container.
	if d.strategy != nil {
		if err := d.strategy.Remove(ctx, session.ContainerID); err != nil {
			d.logger.Warn("failed to remove enforcement, continuing with stop",
				zap.String("id", session.ContainerID),
				zap.Error(err),
			)
		}
	}

	timeout := int(d.stopTimeout.Seconds())
	if _, err := d.client.ContainerStop(ctx, session.ContainerID, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		d.logger.Warn("failed to stop container gracefully, forcing removal",
			zap.String("id", session.ContainerID),
			zap.Error(err),
		)
	}

	if _, err := d.client.ContainerRemove(ctx, session.ContainerID, client.ContainerRemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	}); err != nil {
		return fmt.Errorf("docker runtime: removing container %s: %w", session.ContainerID, err)
	}

	session.Status = "stopped"
	d.logger.Info("container removed", zap.String("id", session.ContainerID))
	return nil
}

// Exec executes a command inside the running container and returns the result.
func (d *DockerRuntime) Exec(ctx context.Context, session *Session, cmd []string) (*ExecResult, error) {
	if session == nil {
		return nil, fmt.Errorf("docker runtime: nil session")
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("docker runtime: empty command")
	}

	execResp, err := d.client.ExecCreate(ctx, session.ContainerID, client.ExecCreateOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("docker runtime: creating exec: %w", err)
	}

	attach, err := d.client.ExecAttach(ctx, execResp.ID, client.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker runtime: attaching exec: %w", err)
	}
	defer attach.Close()

	var stdout, stderr bytes.Buffer
	// Docker multiplexes stdout/stderr over a single connection using an
	// 8-byte header per frame. StdCopy demuxes the stream so that stdout
	// and stderr are captured separately.
	if _, err := stdcopy.StdCopy(&stdout, &stderr, attach.Reader); err != nil {
		return nil, fmt.Errorf("docker runtime: reading exec output: %w", err)
	}

	inspect, err := d.client.ExecInspect(ctx, execResp.ID, client.ExecInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker runtime: inspecting exec: %w", err)
	}

	return &ExecResult{
		ExitCode: inspect.ExitCode,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
	}, nil
}

// ExecInteractive runs cmd inside the session container with streamed stdio and
// an optional TTY, for human-driven sessions. It returns the command's exit
// code. The caller owns the terminal; this method owns the docker exec and
// applies resize events delivered on opts.Resize.
//
// Enforcement is unaffected: the exec process is created in the container's
// cgroup, so the eBPF egress hooks apply, and an interactive `claude` reads the
// same managed-settings PreToolUse hook as the main process.
func (d *DockerRuntime) ExecInteractive(ctx context.Context, session *Session, cmd []string, opts InteractiveExecOptions) (int, error) {
	if session == nil {
		return 0, fmt.Errorf("docker runtime: nil session")
	}
	if len(cmd) == 0 {
		return 0, fmt.Errorf("docker runtime: empty command")
	}

	execResp, err := d.client.ExecCreate(ctx, session.ContainerID, client.ExecCreateOptions{
		Cmd:          cmd,
		User:         opts.User,
		WorkingDir:   opts.WorkingDir,
		Env:          opts.Env,
		TTY:          opts.TTY,
		AttachStdin:  opts.Stdin != nil,
		AttachStdout: opts.Stdout != nil,
		AttachStderr: opts.Stderr != nil,
		ConsoleSize:  client.ConsoleSize{Height: opts.InitialSize.Rows, Width: opts.InitialSize.Cols},
	})
	if err != nil {
		return 0, fmt.Errorf("docker runtime: creating exec: %w", err)
	}

	attach, err := d.client.ExecAttach(ctx, execResp.ID, client.ExecAttachOptions{TTY: opts.TTY})
	if err != nil {
		return 0, fmt.Errorf("docker runtime: attaching exec: %w", err)
	}
	defer attach.Close()

	// Pump TTY resize events to the exec for the lifetime of this call.
	if opts.Resize != nil {
		resizeCtx, cancelResize := context.WithCancel(ctx)
		defer cancelResize()
		go func() {
			for {
				select {
				case <-resizeCtx.Done():
					return
				case sz, ok := <-opts.Resize:
					if !ok {
						return
					}
					_, _ = d.client.ExecResize(resizeCtx, execResp.ID, client.ExecResizeOptions{
						Height: sz.Rows,
						Width:  sz.Cols,
					})
				}
			}
		}()
	}

	// Stream stdin to the exec, then half-close so the process sees EOF.
	if opts.Stdin != nil {
		go func() {
			_, _ = io.Copy(attach.Conn, opts.Stdin)
			_ = attach.CloseWrite()
		}()
	}

	// Stream output back. A TTY merges stdout and stderr onto one stream, so
	// copy it directly; otherwise demux the multiplexed frames.
	if opts.TTY {
		if opts.Stdout != nil {
			_, _ = io.Copy(opts.Stdout, attach.Reader)
		}
	} else {
		out := opts.Stdout
		errOut := opts.Stderr
		if out == nil {
			out = io.Discard
		}
		if errOut == nil {
			errOut = io.Discard
		}
		if _, err := stdcopy.StdCopy(out, errOut, attach.Reader); err != nil {
			return 0, fmt.Errorf("docker runtime: streaming exec output: %w", err)
		}
	}

	inspect, err := d.client.ExecInspect(ctx, execResp.ID, client.ExecInspectOptions{})
	if err != nil {
		return 0, fmt.Errorf("docker runtime: inspecting exec: %w", err)
	}
	return inspect.ExitCode, nil
}

// Logs returns a ReadCloser that streams the container's combined stdout/stderr.
func (d *DockerRuntime) Logs(ctx context.Context, session *Session) (io.ReadCloser, error) {
	if session == nil {
		return nil, fmt.Errorf("docker runtime: nil session")
	}

	reader, err := d.client.ContainerLogs(ctx, session.ContainerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("docker runtime: streaming logs: %w", err)
	}

	return reader, nil
}

// EnforcementEvents returns the enforcement event channel for the given
// container, or nil if enforcement is not active or no events are available.
// This enables callers to consume BPF block/allow events for user feedback.
func (d *DockerRuntime) EnforcementEvents(containerID string) <-chan enforcement.Event {
	if d.strategy == nil {
		return nil
	}
	return d.strategy.Events(containerID)
}

// List returns all agentcontainer-managed sessions by filtering Docker
// containers with the dev.agentcontainer/managed=true label.
func (d *DockerRuntime) List(ctx context.Context, all bool) ([]*Session, error) {
	filters := client.Filters{}.Add("label", labelPrefix+"/managed=true")

	result, err := d.client.ContainerList(ctx, client.ContainerListOptions{
		All:     all,
		Filters: filters,
	})
	if err != nil {
		return nil, fmt.Errorf("docker runtime: listing containers: %w", err)
	}

	sessions := make([]*Session, 0, len(result.Items))
	for _, c := range result.Items {
		name := ""
		if len(c.Names) > 0 {
			// Docker prefixes container names with "/".
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		sessions = append(sessions, &Session{
			ContainerID: c.ID,
			Name:        name,
			Image:       c.Image,
			RuntimeType: RuntimeDocker,
			Status:      string(c.State),
			CreatedAt:   time.Unix(c.Created, 0),
		})
	}

	return sessions, nil
}

// ensureImage pulls the image if it is not already present locally.
func (d *DockerRuntime) ensureImage(ctx context.Context, ref string) error {
	if _, err := d.client.ImageInspect(ctx, ref); err == nil {
		d.logger.Debug("image already present", zap.String("image", ref))
		return nil
	}

	d.logger.Info("pulling image", zap.String("image", ref))
	reader, err := d.client.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close() //nolint:errcheck

	// Drain the pull output to ensure the pull completes.
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("reading pull response: %w", err)
	}
	return nil
}

// buildContainerConfig translates the AgentContainer configuration into Docker
// API types. This is an exported-via-test helper: the logic is exercised in
// unit tests without needing a live Docker daemon.
func (d *DockerRuntime) buildContainerConfig(
	cfg *config.AgentContainer,
	opts StartOptions,
) (*container.Config, *container.HostConfig, *network.NetworkingConfig) {
	// Use the pinned digest ref when available so the container starts from
	// the same manifest that was used for policy extraction (F-4).
	imageRef := cfg.Image
	if opts.PinnedImageRef != "" {
		imageRef = opts.PinnedImageRef
	}
	containerCfg := &container.Config{
		Image: imageRef,
		Labels: map[string]string{
			labelPrefix + "/managed": "true",
			labelPrefix + "/name":    cfg.Name,
		},
	}

	// When running in detached mode, override the entrypoint to keep the
	// container alive indefinitely. Without this, images whose default CMD
	// is a shell (e.g. devcontainer base images) exit immediately because
	// there is no TTY attached. This matches devcontainer CLI behavior.
	if opts.Detach {
		containerCfg.Entrypoint = []string{"sleep", "infinity"}
		containerCfg.Cmd = nil
	}

	// Apply security settings from policy, falling back to default-deny if nil.
	p := opts.Policy
	if p == nil {
		p = defaultContainerPolicy()
	}

	hostCfg := &container.HostConfig{
		CapDrop:        p.CapDrop,
		CapAdd:         p.CapAdd,
		SecurityOpt:    p.SecurityOpt,
		ReadonlyRootfs: p.ReadonlyRootfs,
	}

	networkCfg := &network.NetworkingConfig{}

	// Network attachment. "bridge" (set by policy resolution when egress rules
	// are present) must NOT use Docker's default bridge: that bridge has no
	// embedded DNS resolver, so the container's resolv.conf points at an
	// external nameserver on :53, and the egress default-deny blocks that —
	// breaking all name resolution. Attach to a per-agent user-defined bridge
	// instead, which runs Docker's embedded resolver at 127.0.0.11 (loopback,
	// which the enforcer always allows). This mirrors how the MCP proxy
	// attaches its backends. "none" and any explicit mode pass through.
	if p.NetworkMode == "bridge" {
		networkCfg.EndpointsConfig = map[string]*network.EndpointSettings{
			agentNetworkName(cfg.Name): {},
		}
	} else if p.NetworkMode != "" {
		hostCfg.NetworkMode = container.NetworkMode(p.NetworkMode)
	}

	// Map config mounts from devcontainer.json.
	hostCfg.Mounts = parseMounts(cfg.Mounts)

	// Apply policy-defined mounts from agent capabilities.
	// Skip entries with glob characters — those are BPF enforcement rules,
	// not bind mount requests. Concrete paths are mounted as bind mounts.
	for _, mp := range p.AllowedMounts {
		if strings.ContainsAny(mp.Source, "*?[") {
			continue
		}
		hostCfg.Mounts = append(hostCfg.Mounts, mount.Mount{
			Type:        mount.TypeBind,
			Source:      mp.Source,
			Target:      mp.Target,
			ReadOnly:    mp.ReadOnly,
			BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate},
		})
	}

	// Bind-mount workspace if provided.
	if opts.WorkspacePath != "" {
		hostCfg.Mounts = append(hostCfg.Mounts, mount.Mount{
			Type:        mount.TypeBind,
			Source:      opts.WorkspacePath,
			Target:      defaultWorkspaceTarget,
			ReadOnly:    false,
			BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate},
		})
	}

	// Mount a writable tmpfs at /run/secrets when secrets are configured.
	// The rootfs is read-only by default, so the enforcer needs a writable
	// target for InjectSecrets via /proc/<pid>/root/run/secrets/.
	// Access control is handled by BPF LSM SECRET_ACLS, not mount permissions.
	if len(opts.ResolvedSecrets) > 0 {
		hostCfg.Mounts = append(hostCfg.Mounts, mount.Mount{
			Type:   mount.TypeTmpfs,
			Target: "/run/secrets",
			TmpfsOptions: &mount.TmpfsOptions{
				SizeBytes: 1024 * 1024,
				Mode:      0o700,
			},
		})
	}

	// P0-4 Security Fix: Reject Docker/containerd socket mounts (ESC-2 finding).
	// If these sockets are mounted, the agent has full control of the host.
	if err := validateMounts(hostCfg.Mounts); err != nil {
		d.logger.Error("mount validation failed", zap.Error(err))
		// This is a programming error, not a runtime error — panic is appropriate.
		panic(fmt.Sprintf("docker runtime: %v", err))
	}

	return containerCfg, hostCfg, networkCfg
}

// agentNetworkName is the deterministic name of the per-agent user-defined
// bridge network. Keyed by the agent name so repeated runs of the same config
// reuse one network rather than accumulating per-run networks.
func agentNetworkName(name string) string {
	return "ac-net-" + name
}

// ensureAgentNetwork creates the per-agent user-defined bridge network if it
// does not already exist. A user-defined bridge — unlike Docker's default
// bridge — runs the embedded DNS resolver at 127.0.0.11, loopback traffic the
// enforcer always allows, so name resolution works under default-deny egress.
// Idempotent: an existing network is reused.
func (d *DockerRuntime) ensureAgentNetwork(ctx context.Context, name string) error {
	if _, err := d.client.NetworkInspect(ctx, name, client.NetworkInspectOptions{}); err == nil {
		return nil
	}
	if _, err := d.client.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge",
		Labels: map[string]string{
			labelPrefix + "/managed": "true",
		},
	}); err != nil {
		return fmt.Errorf("creating network %s: %w", name, err)
	}
	return nil
}

// defaultContainerPolicy returns a default-deny security policy when no
// policy is provided. This ensures containers start with the strictest
// possible security settings.
func defaultContainerPolicy() *policy.ContainerPolicy {
	return &policy.ContainerPolicy{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		ReadonlyRootfs: true,
		NetworkMode:    "none",
	}
}

// parseMounts converts devcontainer-style mount strings into Docker mount
// structs. Each mount string has the form:
//
//	type=bind,source=/host/path,target=/container/path[,readonly]
//
// Unrecognised fields are silently ignored for forward compatibility.
func parseMounts(raw []string) []mount.Mount {
	var mounts []mount.Mount

	for _, m := range raw {
		parsed := parseMount(m)
		if parsed != nil {
			mounts = append(mounts, *parsed)
		}
	}

	return mounts
}

// parseMount parses a single devcontainer-style mount string.
func parseMount(raw string) *mount.Mount {
	fields := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			fields[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		} else if len(kv) == 1 {
			// Handle bare flags like "readonly".
			fields[strings.TrimSpace(kv[0])] = ""
		}
	}

	source := fields["source"]
	if source == "" {
		source = fields["src"]
	}
	target := fields["target"]
	if target == "" {
		target = fields["dst"]
	}
	if target == "" {
		target = fields["destination"]
	}

	if source == "" || target == "" {
		return nil
	}

	mt := mount.TypeBind
	if t, ok := fields["type"]; ok {
		switch t {
		case "bind":
			mt = mount.TypeBind
		case "volume":
			mt = mount.TypeVolume
		case "tmpfs":
			mt = mount.TypeTmpfs
		}
	}

	_, readOnly := fields["readonly"]
	if ro, ok := fields["readonly"]; ok && ro == "true" {
		readOnly = true
	}

	m := &mount.Mount{
		Type:     mt,
		Source:   source,
		Target:   target,
		ReadOnly: readOnly,
	}

	// Parse propagation for bind mounts.
	if mt == mount.TypeBind {
		if prop, ok := fields["propagation"]; ok {
			if p := parsePropagation(prop); p != "" {
				m.BindOptions = &mount.BindOptions{Propagation: p}
			}
		}
	}

	return m
}

// parsePropagation maps a propagation string to a mount.Propagation constant.
// Returns empty string for unrecognised values.
func parsePropagation(s string) mount.Propagation {
	switch s {
	case "rprivate":
		return mount.PropagationRPrivate
	case "private":
		return mount.PropagationPrivate
	case "rshared":
		return mount.PropagationRShared
	case "shared":
		return mount.PropagationShared
	case "rslave":
		return mount.PropagationRSlave
	case "slave":
		return mount.PropagationSlave
	default:
		return ""
	}
}

// validateMounts enforces security invariants on container mounts.
// P0-4: Rejects Docker/containerd socket mounts that would grant host control.
// MEDIUM-4 fix: expanded socket list to cover CRI-O, Podman, and Docker Desktop;
// added symlink resolution and basename matching for non-standard paths.
func validateMounts(mounts []mount.Mount) error {
	// ESC-2: Forbidden socket paths that grant container escape.
	forbiddenSockets := []string{
		// Docker
		"/var/run/docker.sock",
		"/run/docker.sock",
		// containerd
		"/var/run/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		// CRI-O
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
		// Podman
		"/var/run/podman/podman.sock",
		"/run/podman/podman.sock",
		// Docker Desktop (macOS)
		"/var/run/docker.raw.sock",
	}

	// Runtime socket basenames — catches non-standard paths.
	forbiddenBasenames := map[string]bool{
		"docker.sock":     true,
		"containerd.sock": true,
		"crio.sock":       true,
		"podman.sock":     true,
		"dockershim.sock": true,
	}

	for _, m := range mounts {
		// Only check bind mounts; volumes and tmpfs don't expose host sockets.
		if m.Type != mount.TypeBind {
			continue
		}

		// Resolve symlinks to prevent bypass via indirect paths.
		source := m.Source
		if resolved, err := filepath.EvalSymlinks(source); err == nil {
			source = resolved
		}

		// Check against known forbidden paths.
		for _, forbidden := range forbiddenSockets {
			if source == forbidden {
				return fmt.Errorf("forbidden mount: %s (grants host control via container runtime socket)", m.Source)
			}
		}

		// Check basename for runtime socket names in non-standard locations.
		if forbiddenBasenames[filepath.Base(source)] {
			return fmt.Errorf("forbidden mount: %s (grants host control via container runtime socket)", m.Source)
		}
	}

	return nil
}
