package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.temporal.io/sdk/activity"
	"golang.org/x/crypto/ssh"
)

// guestFatal wraps an error that means the guest itself is unreachable/broken
// (SSH dial failed, connection dropped) — as opposed to a command that ran and
// returned a non-zero status. The workflow treats guestFatal as the trigger for
// a VM reset before retrying the cell.
type guestFatal struct{ err error }

func (g guestFatal) Error() string { return "guest-fatal: " + g.err.Error() }
func (g guestFatal) Unwrap() error { return g.err }

func newGuestFatal(format string, a ...any) error {
	return guestFatal{fmt.Errorf(format, a...)}
}

// dial opens an SSH client to the guest as SSHUser using the private key at
// SSHKeyPath. Host key checking is disabled to mirror the existing breakout.sh
// (StrictHostKeyChecking=no) — the guest is a disposable lab VM.
func dial(cfg Config, host string) (*ssh.Client, error) {
	keyBytes, err := os.ReadFile(cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %s: %w", cfg.SSHKeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key: %w", err)
	}
	clientCfg := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	if !strings.Contains(host, ":") {
		host += ":22"
	}
	client, err := ssh.Dial("tcp", host, clientCfg)
	if err != nil {
		return nil, newGuestFatal("ssh dial %s: %v", host, err)
	}
	return client, nil
}

// runCmd runs a single command to completion, returning combined stdout and the
// exit error (nil on exit 0). stdin, if non-empty, is fed to the command.
func runCmd(client *ssh.Client, cmd, stdin string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", newGuestFatal("new session: %v", err)
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
	err = sess.Run(cmd)
	return out.String(), err
}

// runCmdHeartbeat runs a long command, recording a Temporal heartbeat every
// `every` while it runs so a hung LLM call is detected inside HeartbeatTimeout.
// If the activity context is cancelled (heartbeat timeout / workflow cancel) the
// session is torn down and the guest connection is closed so nothing lingers.
func runCmdHeartbeat(ctx context.Context, client *ssh.Client, cmd string, every time.Duration) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", newGuestFatal("new session: %v", err)
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	if err := sess.Start(cmd); err != nil {
		return "", newGuestFatal("start command: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return out.String(), err
		case <-ticker.C:
			activity.RecordHeartbeat(ctx, lastLines(out.String(), 3))
		case <-ctx.Done():
			// Heartbeat timeout or cancellation: kill the remote command and
			// drop the connection. Report guest-fatal so the workflow resets.
			_ = sess.Signal(ssh.SIGKILL)
			_ = sess.Close()
			_ = client.Close()
			return out.String(), newGuestFatal("activity context done: %v", ctx.Err())
		}
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// shquote single-quotes a value for safe interpolation into a remote shell
// command line (wraps in '...', escaping embedded single quotes).
func shquote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
