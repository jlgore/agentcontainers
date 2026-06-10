package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oidc"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

func newExecCmd() *cobra.Command {
	var (
		runtime     string
		configPath  string
		envVars     []string
		interactive bool
		tty         bool
	)

	cmd := &cobra.Command{
		Use:   "exec [-it] <container-id> -- <command...>",
		Short: "Execute a command inside a running agent container",
		Long: `Run a command inside the primary container identified by <container-id>.
Everything after "--" is treated as the command and its arguments.

Without -i/-t the command runs to completion and its buffered output is checked
against the agent capability policy before execution.

With -i/-t the command runs interactively with streamed stdio and (with -t) a
pseudo-TTY — use this to drive Claude Code as a human would:

  agentcontainer exec -it claude-agent -- claude

The interactive process joins the container cgroup, so the eBPF egress
allowlist and the PreToolUse guard hook gate it exactly as they gate the main
process; enforcement does not depend on this command.

Environment variables can be injected with -e KEY=VALUE. Secret URI schemes
(e.g. op://vault/item/field) are resolved on demand before execution.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			containerID := args[0]
			cmdArgs := args[1:]

			if len(cmdArgs) == 0 {
				return fmt.Errorf("exec: no command specified (usage: ac exec [-it] <container-id> -- <command> [args...])")
			}

			if interactive || tty {
				return runExecInteractive(cmd, containerID, cmdArgs, runtime, envVars, tty)
			}
			return runExec(cmd, containerID, cmdArgs, runtime, configPath, envVars)
		},
	}

	cmd.Flags().StringVar(&runtime, "runtime", "docker", "Container runtime backend (auto|docker|compose|sandbox)")
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json")
	cmd.Flags().StringArrayVarP(&envVars, "env", "e", nil, "Set environment variables (KEY=VALUE or KEY=op://...)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Keep stdin attached to the command")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "Allocate a pseudo-TTY (implies --interactive)")

	return cmd
}

func runExec(cmd *cobra.Command, containerID string, execCmd []string, runtimeFlag string, configPath string, envVars []string) error {
	// BPF enforcement is already active on the container's cgroup from agentcontainer run.
	// The runtime here only needs LevelNone because we are not re-applying
	// policy — the approval broker provides the Go-side defense-in-depth.
	rt, err := newRuntime(runtimeFlag, logger, enforcement.LevelNone)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	// Load config to wire the approval broker.
	cfg, cfgPath, err := loadConfig(configPath)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	var caps *config.Capabilities
	var escalation string
	if cfg.Agent != nil {
		caps = cfg.Agent.Capabilities
		if cfg.Agent.Policy != nil {
			escalation = cfg.Agent.Policy.Escalation
		}
	}

	approvalMgr := approval.NewManager(
		approval.NewTerminalApprover(approval.WithOutput(cmd.OutOrStdout())),
		cfgPath,
		caps,
		approval.WithEscalation(escalation),
	)
	defer func() {
		if persistErr := approvalMgr.Persist(); persistErr != nil {
			logger.Warn("failed to persist capabilities")
		}
	}()

	brokerRT := approval.NewBroker(rt, approvalMgr)

	// Resolve any secret URI schemes in the --env flag values before executing.
	resolvedEnv, err := resolveEnvVars(cmd.Context(), envVars)
	if err != nil {
		return err
	}

	// The Runtime.Exec interface only accepts a command slice. When env vars
	// have been resolved, prepend them to the command via POSIX `env` so that
	// the container process sees the correct environment without requiring an
	// interface change.
	finalCmd := execCmd
	if len(resolvedEnv) > 0 {
		envArgs := append([]string{"env"}, resolvedEnv...)
		finalCmd = append(envArgs, execCmd...)
	}

	session := &container.Session{
		ContainerID: containerID,
		RuntimeType: container.RuntimeType(runtimeFlag),
	}

	result, err := brokerRT.Exec(cmd.Context(), session, finalCmd)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	if len(result.Stdout) > 0 {
		_, _ = fmt.Fprint(cmd.OutOrStdout(), string(result.Stdout))
	}
	if len(result.Stderr) > 0 {
		_, _ = fmt.Fprint(cmd.ErrOrStderr(), string(result.Stderr))
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("exec: command exited with code %d", result.ExitCode)
	}

	return nil
}

// resolveEnvVars resolves secret URI schemes in --env flag values. Values like
// KEY=op://vault/item/field are resolved on demand via a temporary
// single-provider Manager; plain values pass through unchanged.
func resolveEnvVars(ctx context.Context, envVars []string) ([]string, error) {
	var resolved []string
	for _, envStr := range envVars {
		parts := strings.SplitN(envStr, "=", 2)
		if len(parts) != 2 {
			resolved = append(resolved, envStr)
			continue
		}
		ref, ok := secrets.ParseSecretURI(parts[1])
		if !ok {
			resolved = append(resolved, envStr)
			continue
		}
		ref.Name = parts[0]
		secret, err := resolveSecretOnDemand(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("exec: resolving secret for env %q: %w", parts[0], err)
		}
		resolved = append(resolved, parts[0]+"="+string(secret.Value))
	}
	return resolved, nil
}

// runExecInteractive runs a command inside the container with streamed stdio and
// (when tty is set and stdin is a terminal) a raw pseudo-TTY, for human-driven
// sessions such as an interactive `claude`. Unlike runExec it does not route the
// command through the approval broker: the human is at the keyboard and the real
// gate is the in-container PreToolUse hook plus the kernel egress enforcement,
// both of which apply to this exec because it joins the container cgroup.
func runExecInteractive(cmd *cobra.Command, containerID string, execCmd []string, runtimeFlag string, envVars []string, tty bool) error {
	rt, err := newRuntime(runtimeFlag, logger, enforcement.LevelNone)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	ie, ok := rt.(container.InteractiveExecer)
	if !ok {
		return fmt.Errorf("exec: interactive mode is not supported by the %q runtime", runtimeFlag)
	}

	resolvedEnv, err := resolveEnvVars(cmd.Context(), envVars)
	if err != nil {
		return err
	}

	opts := container.InteractiveExecOptions{
		TTY:    tty,
		Env:    resolvedEnv,
		Stdin:  cmd.InOrStdin(),
		Stdout: cmd.OutOrStdout(),
		Stderr: cmd.ErrOrStderr(),
	}

	// When a TTY is requested and stdin is a real terminal, put it in raw mode
	// and forward window-resize events so the in-container REPL behaves.
	var restore func()
	if tty {
		if f, isFile := cmd.InOrStdin().(*os.File); isFile && term.IsTerminal(int(f.Fd())) {
			fd := int(f.Fd())
			oldState, rawErr := term.MakeRaw(fd)
			if rawErr != nil {
				return fmt.Errorf("exec: setting raw terminal: %w", rawErr)
			}
			var once sync.Once
			restore = func() { once.Do(func() { _ = term.Restore(fd, oldState) }) }

			if w, h, sizeErr := term.GetSize(fd); sizeErr == nil {
				opts.InitialSize = container.TerminalSize{Rows: uint(h), Cols: uint(w)}
			}

			resize := make(chan container.TerminalSize, 1)
			opts.Resize = resize
			winch := make(chan os.Signal, 1)
			signal.Notify(winch, syscall.SIGWINCH)
			go func() {
				for range winch {
					if w, h, sizeErr := term.GetSize(fd); sizeErr == nil {
						select {
						case resize <- container.TerminalSize{Rows: uint(h), Cols: uint(w)}:
						default:
						}
					}
				}
			}()
			defer func() {
				signal.Stop(winch)
				close(winch)
			}()
		}
	}
	if restore != nil {
		defer restore()
	}

	session := &container.Session{
		ContainerID: containerID,
		RuntimeType: container.RuntimeType(runtimeFlag),
	}

	code, execErr := ie.ExecInteractive(cmd.Context(), session, execCmd, opts)

	// Restore the terminal before printing any error so the message renders
	// with normal line discipline.
	if restore != nil {
		restore()
	}
	if execErr != nil {
		return fmt.Errorf("exec: %w", execErr)
	}
	if code != 0 {
		return fmt.Errorf("exec: command exited with code %d", code)
	}
	return nil
}

// resolveSecretOnDemand creates a temporary Manager, registers the single
// required provider, resolves the secret, and tears everything down.
// It is used to resolve URI-scheme secret references passed via --env.
// Provider options mirror the env-var plumbing in buildSecretsManager (run.go)
// so that VAULT_ADDR, VAULT_TOKEN, INFISICAL_*, OP_CONNECT_* etc. are honoured.
func resolveSecretOnDemand(ctx context.Context, ref secrets.SecretRef) (*secrets.Secret, error) {
	var provider secrets.Provider
	switch ref.Provider {
	case "env":
		provider = secrets.NewEnvProvider()
	case "vault":
		var vaultOpts []secrets.VaultProviderOption
		if sock := os.Getenv("VAULT_AGENT_SOCKET"); sock != "" {
			vaultOpts = append(vaultOpts, secrets.WithVaultSocket(sock))
		}
		if addr := os.Getenv("VAULT_ADDR"); addr != "" {
			vaultOpts = append(vaultOpts, secrets.WithVaultAddr(addr))
		}
		if token := os.Getenv("VAULT_TOKEN"); token != "" {
			vaultOpts = append(vaultOpts, secrets.WithVaultToken(token))
		}
		provider = secrets.NewVaultProvider(vaultOpts...)
	case "1password":
		var opOpts []secrets.OnePasswordProviderOption
		if host := os.Getenv("OP_CONNECT_HOST"); host != "" {
			opOpts = append(opOpts, secrets.WithOnePasswordAddr(host))
		}
		if token := os.Getenv("OP_CONNECT_TOKEN"); token != "" {
			opOpts = append(opOpts, secrets.WithOnePasswordToken(token))
		}
		provider = secrets.NewOnePasswordProvider(opOpts...)
	case "infisical":
		var infisicalOpts []secrets.InfisicalProviderOption
		if sock := os.Getenv("INFISICAL_SOCKET"); sock != "" {
			infisicalOpts = append(infisicalOpts, secrets.WithInfisicalSocket(sock))
		}
		if apiURL := os.Getenv("INFISICAL_API_URL"); apiURL != "" {
			infisicalOpts = append(infisicalOpts, secrets.WithInfisicalAddr(apiURL))
		}
		clientID := os.Getenv("INFISICAL_CLIENT_ID")
		clientSecret := os.Getenv("INFISICAL_CLIENT_SECRET")
		if (clientID == "") != (clientSecret == "") {
			return nil, fmt.Errorf("INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET must both be set or both be unset")
		}
		if clientID != "" {
			infisicalOpts = append(infisicalOpts, secrets.WithInfisicalAuth(clientID, clientSecret))
		}
		provider = secrets.NewInfisicalProvider(infisicalOpts...)
	case "oidc":
		issuer, err := oidc.NewIssuer()
		if err != nil {
			return nil, fmt.Errorf("creating OIDC issuer: %w", err)
		}
		if err := issuer.Start(); err != nil {
			return nil, fmt.Errorf("starting OIDC issuer: %w", err)
		}
		defer issuer.Stop(context.Background()) //nolint:errcheck
		provider = secrets.NewOIDCProvider(issuer)
	default:
		return nil, fmt.Errorf("unsupported provider %q for on-demand resolution", ref.Provider)
	}
	defer provider.Close() //nolint:errcheck

	mgr := secrets.NewManager(secrets.WithProvider(provider))
	defer mgr.Close() //nolint:errcheck

	return mgr.Resolve(ctx, ref)
}
