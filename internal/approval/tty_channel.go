package approval

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
)

// TTYChannel prompts for pending tool-call approvals on the controlling
// terminal. It is the interactive channel from SPEC §9 Phase 4; daemonized
// sessions use the Unix socket channel instead.
type TTYChannel struct {
	broker  *ToolCallBroker
	sub     <-chan ToolCallRequest
	in      io.Reader
	out     io.Writer
	closer  io.Closer
	decider string
}

// OpenTTYChannel opens /dev/tty for interactive approval. It fails when no
// controlling terminal is available (daemonized) — callers fall back to the
// socket channel.
func OpenTTYChannel(broker *ToolCallBroker) (*TTYChannel, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("approval: no controlling terminal: %w", err)
	}
	c := NewTTYChannelWith(broker, tty, tty, currentUsername())
	c.closer = tty
	return c, nil
}

// NewTTYChannelWith builds a TTY channel over explicit reader/writer —
// used by tests and callers that manage the terminal themselves. The
// channel subscribes immediately so requests submitted before Run starts
// are not missed.
func NewTTYChannelWith(broker *ToolCallBroker, in io.Reader, out io.Writer, decider string) *TTYChannel {
	return &TTYChannel{broker: broker, sub: broker.Subscribe(), in: in, out: out, decider: decider}
}

// Run consumes pending requests and prompts for each, serially, until ctx
// is canceled. Prompt outcomes resolve through the broker; a request that
// expired while the prompt was open is reported and skipped.
func (c *TTYChannel) Run(ctx context.Context) {
	scanner := bufio.NewScanner(c.in)
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-c.sub:
			d, err := c.prompt(scanner, req)
			if err != nil {
				_, _ = fmt.Fprintf(c.out, "approval input closed: %v\n", err)
				return
			}
			if err := c.broker.Resolve(req.ID, d); err != nil {
				_, _ = fmt.Fprintf(c.out, "%v\n", err)
			}
		}
	}
}

// Close releases the /dev/tty handle, if this channel owns one.
func (c *TTYChannel) Close() error {
	if c.closer != nil {
		return c.closer.Close()
	}
	return nil
}

// prompt displays one request and reads an approve/deny decision. Deny asks
// for an optional reason (it lands in approval.jsonl).
func (c *TTYChannel) prompt(scanner *bufio.Scanner, req ToolCallRequest) (ToolCallDecision, error) {
	_, _ = fmt.Fprintf(c.out, "\n")
	_, _ = fmt.Fprintf(c.out, "========================================\n")
	_, _ = fmt.Fprintf(c.out, "        Tool Call Approval\n")
	_, _ = fmt.Fprintf(c.out, "========================================\n")
	_, _ = fmt.Fprintf(c.out, "Server:  %s\n", req.Server)
	_, _ = fmt.Fprintf(c.out, "Tool:    %s\n", req.Tool)
	_, _ = fmt.Fprintf(c.out, "Command: %s\n", req.ArgsSummary)
	_, _ = fmt.Fprintf(c.out, "ID:      %s\n", req.ID)
	_, _ = fmt.Fprintf(c.out, "\n[a] Approve\n[d] Deny\n")

	for {
		_, _ = fmt.Fprintf(c.out, "Choice [a/d]: ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return ToolCallDecision{}, err
			}
			return ToolCallDecision{}, io.EOF
		}
		switch strings.TrimSpace(strings.ToLower(scanner.Text())) {
		case "a", "approve":
			return ToolCallDecision{Approved: true, Decider: c.decider}, nil
		case "d", "deny":
			_, _ = fmt.Fprintf(c.out, "Reason (optional): ")
			reason := ""
			if scanner.Scan() {
				reason = strings.TrimSpace(scanner.Text())
			}
			if reason == "" {
				reason = "denied by examiner"
			}
			return ToolCallDecision{Approved: false, Reason: reason, Decider: c.decider}, nil
		default:
			_, _ = fmt.Fprintf(c.out, "Invalid choice %q. Please enter a or d.\n", scanner.Text())
		}
	}
}

// currentUsername resolves the examiner identity for audit actor fields,
// matching the VHIR_EXAMINER → VHIR_ANALYST → OS user convention.
func currentUsername() string {
	if v := os.Getenv("VHIR_EXAMINER"); v != "" {
		return v
	}
	if v := os.Getenv("VHIR_ANALYST"); v != "" {
		return v
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return os.Getenv("USER")
}
