package cli

import (
	"bufio"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
)

func newApproveCmd() *cobra.Command {
	var (
		socketPath string
		list       bool
		deny       bool
		reason     string
	)

	cmd := &cobra.Command{
		Use:   "approve [request-id]",
		Short: "Review pending tool-call approvals for a running MCP proxy",
		Long: `Connects to a running 'agentcontainer mcp start' session over its
approval socket and decides pending requireApproval tool calls.

With no arguments, shows each pending request and prompts approve/deny/skip.
With a request ID, approves it (or denies with --deny). --list only lists.

The socket is restricted to the owning user (mode 0600 + kernel peer
credential check). Decisions are recorded in the session's approval audit
chain.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""
			if len(args) == 1 {
				id = args[0]
			}
			return runApprove(cmd, socketPath, id, list, deny, reason)
		},
	}

	cmd.Flags().StringVar(&socketPath, "socket", "", "Approval socket path (default: ~/.agentcontainers/approval.sock)")
	cmd.Flags().BoolVar(&list, "list", false, "List pending requests and exit")
	cmd.Flags().BoolVar(&deny, "deny", false, "Deny the given request instead of approving it")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason recorded with a denial")

	return cmd
}

func runApprove(cmd *cobra.Command, socketPath, id string, list, deny bool, reason string) error {
	out := cmd.OutOrStdout()

	client, err := approval.DialSocket(socketPath)
	if err != nil {
		return fmt.Errorf("approve: %w", err)
	}
	defer client.Close() //nolint:errcheck

	if id != "" {
		if err := client.Resolve(id, !deny, reason); err != nil {
			return fmt.Errorf("approve: %w", err)
		}
		verdict := "approved"
		if deny {
			verdict = "denied"
		}
		_, _ = fmt.Fprintf(out, "%s %s\n", verdict, id)
		return nil
	}

	pending, err := client.List()
	if err != nil {
		return fmt.Errorf("approve: %w", err)
	}
	if len(pending) == 0 {
		_, _ = fmt.Fprintln(out, "No pending approval requests.")
		return nil
	}

	if list {
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintln(w, "ID\tSERVER\tTOOL\tAGE\tCOMMAND")
		for _, r := range pending {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				r.ID, r.Server, r.Tool, time.Since(r.RequestedAt).Round(time.Second), r.ArgsSummary)
		}
		return w.Flush()
	}

	scanner := bufio.NewScanner(cmd.InOrStdin())
	for _, r := range pending {
		_, _ = fmt.Fprintf(out, "\nServer:  %s\nTool:    %s\nCommand: %s\nWaiting: %s\nID:      %s\n",
			r.Server, r.Tool, r.ArgsSummary, time.Since(r.RequestedAt).Round(time.Second), r.ID)

		decided := false
		for !decided {
			_, _ = fmt.Fprint(out, "Choice [a]pprove / [d]eny / [s]kip: ")
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("approve: reading input: %w", err)
				}
				_, _ = fmt.Fprintln(out, "\nInput closed; remaining requests left pending.")
				return nil
			}
			switch strings.TrimSpace(strings.ToLower(scanner.Text())) {
			case "a", "approve":
				if err := client.Resolve(r.ID, true, ""); err != nil {
					_, _ = fmt.Fprintf(out, "%v\n", err)
				} else {
					_, _ = fmt.Fprintf(out, "approved %s\n", r.ID)
				}
				decided = true
			case "d", "deny":
				_, _ = fmt.Fprint(out, "Reason (optional): ")
				denyReason := ""
				if scanner.Scan() {
					denyReason = strings.TrimSpace(scanner.Text())
				}
				if err := client.Resolve(r.ID, false, denyReason); err != nil {
					_, _ = fmt.Fprintf(out, "%v\n", err)
				} else {
					_, _ = fmt.Fprintf(out, "denied %s\n", r.ID)
				}
				decided = true
			case "s", "skip":
				decided = true
			default:
				_, _ = fmt.Fprintf(out, "Invalid choice %q. Please enter a, d, or s.\n", scanner.Text())
			}
		}
	}
	return nil
}
