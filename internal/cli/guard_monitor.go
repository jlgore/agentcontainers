package cli

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
)

func newGuardMonitorCmd() *cobra.Command {
	var approvalSocket string

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Review guard approvals in a terminal UI",
		Long: `Connects to a running 'guard serve' approval socket and shows pending
tool-call approvals in a terminal UI. Approvals and denials made here are
recorded by the running guard service's audit log.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGuardMonitor(cmd, approvalSocket)
		},
	}

	cmd.Flags().StringVar(&approvalSocket, "approval-socket", "", "Approval socket path (default: ~/.ac/guard-approve.sock)")
	return cmd
}

func runGuardMonitor(cmd *cobra.Command, approvalSocket string) error {
	socketPath := resolveGuardApprovalSocket(approvalSocket)
	if socketPath == "" {
		return fmt.Errorf("guard monitor: resolving approval socket")
	}

	model := newGuardMonitorModel(socketPath)
	program := tea.NewProgram(model, tea.WithContext(cmd.Context()))
	_, err := program.Run()
	return err
}

type monitorMode int

const (
	monitorNormal monitorMode = iota
	monitorDenyReason
)

type monitorDecision struct {
	req       approval.ToolCallRequest
	approved  bool
	reason    string
	decidedAt time.Time
	err       error
}

type guardMonitorModel struct {
	socketPath string
	pending    []approval.ToolCallRequest
	selected   int
	history    []monitorDecision
	mode       monitorMode
	reason     string
	denying    *approval.ToolCallRequest
	status     string
	lastErr    string
}

type monitorPendingMsg struct {
	pending []approval.ToolCallRequest
	err     error
}

type monitorResolvedMsg struct {
	decision monitorDecision
}

type monitorTickMsg time.Time

func newGuardMonitorModel(socketPath string) guardMonitorModel {
	return guardMonitorModel{socketPath: socketPath, status: "connecting"}
}

func (m guardMonitorModel) Init() tea.Cmd {
	return tea.Batch(monitorPollCmd(m.socketPath), monitorTickCmd())
}

func (m guardMonitorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	case monitorPendingMsg:
		if msg.err != nil {
			m.lastErr = msg.err.Error()
			m.status = "disconnected"
			return m, nil
		}
		m.lastErr = ""
		m.status = "connected"
		m.pending = msg.pending
		if m.selected >= len(m.pending) {
			m.selected = len(m.pending) - 1
		}
		if m.selected < 0 {
			m.selected = 0
		}
		return m, nil
	case monitorResolvedMsg:
		m.history = append([]monitorDecision{msg.decision}, m.history...)
		if len(m.history) > 20 {
			m.history = m.history[:20]
		}
		if msg.decision.err != nil {
			m.lastErr = msg.decision.err.Error()
		} else {
			m.lastErr = ""
		}
		m.mode = monitorNormal
		m.reason = ""
		m.denying = nil
		return m, monitorPollCmd(m.socketPath)
	case monitorTickMsg:
		return m, tea.Batch(monitorPollCmd(m.socketPath), monitorTickCmd())
	}
	return m, nil
}

func (m guardMonitorModel) View() tea.View {
	var b strings.Builder
	b.WriteString("Guard Monitor\n")
	b.WriteString(fmt.Sprintf("Socket: %s\n", m.socketPath))
	b.WriteString(fmt.Sprintf("Status: %s", m.status))
	if m.lastErr != "" {
		b.WriteString(" - ")
		b.WriteString(m.lastErr)
	}
	b.WriteString("\n\n")

	if m.mode == monitorDenyReason && m.denying != nil {
		b.WriteString("Deny request\n")
		b.WriteString(fmt.Sprintf("Tool:    %s\n", m.denying.Tool))
		b.WriteString(fmt.Sprintf("Command: %s\n", m.denying.ArgsSummary))
		b.WriteString(fmt.Sprintf("Reason:  %s\n\n", m.reason))
		b.WriteString("enter deny  esc cancel  ctrl+c quit\n")
		return tea.NewView(b.String())
	}

	b.WriteString("Pending Approvals\n")
	if len(m.pending) == 0 {
		b.WriteString("  No pending approval requests.\n")
	} else {
		for i, req := range m.pending {
			cursor := " "
			if i == m.selected {
				cursor = ">"
			}
			b.WriteString(fmt.Sprintf("%s %s  %s/%s  waiting %s\n", cursor, req.ID, req.Server, req.Tool, time.Since(req.RequestedAt).Round(time.Second)))
			if i == m.selected {
				b.WriteString(fmt.Sprintf("    %s\n", req.ArgsSummary))
			}
		}
	}

	b.WriteString("\nRecent Decisions\n")
	if len(m.history) == 0 {
		b.WriteString("  No decisions made in this monitor session.\n")
	} else {
		for _, h := range m.history {
			verdict := "denied"
			if h.approved {
				verdict = "approved"
			}
			if h.err != nil {
				verdict = "failed"
			}
			b.WriteString(fmt.Sprintf("  %s  %s  %s  %s\n", h.decidedAt.Format("15:04:05"), verdict, h.req.ID, h.req.ArgsSummary))
			if h.reason != "" {
				b.WriteString(fmt.Sprintf("    reason: %s\n", h.reason))
			}
			if h.err != nil {
				b.WriteString(fmt.Sprintf("    error: %v\n", h.err))
			}
		}
	}

	b.WriteString("\nup/down or j/k select  a approve  d deny  r refresh  q quit\n")
	return tea.NewView(b.String())
}

func (m guardMonitorModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.mode == monitorDenyReason {
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			m.mode = monitorNormal
			m.reason = ""
			m.denying = nil
			return m, nil
		case "enter":
			if m.denying == nil {
				m.mode = monitorNormal
				return m, nil
			}
			req := *m.denying
			return m, monitorResolveCmd(m.socketPath, req, false, strings.TrimSpace(m.reason))
		case "backspace", "ctrl+h":
			if len(m.reason) > 0 {
				runes := []rune(m.reason)
				m.reason = string(runes[:len(runes)-1])
			}
			return m, nil
		default:
			key := msg.Key()
			if key.Text != "" {
				m.reason += key.Text
			}
			return m, nil
		}
	}

	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
	case "down", "j":
		if m.selected < len(m.pending)-1 {
			m.selected++
		}
	case "r":
		return m, monitorPollCmd(m.socketPath)
	case "a":
		if len(m.pending) > 0 {
			req := m.pending[m.selected]
			return m, monitorResolveCmd(m.socketPath, req, true, "")
		}
	case "d":
		if len(m.pending) > 0 {
			req := m.pending[m.selected]
			m.denying = &req
			m.reason = ""
			m.mode = monitorDenyReason
		}
	}
	return m, nil
}

func monitorTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return monitorTickMsg(t) })
}

func monitorPollCmd(socketPath string) tea.Cmd {
	return func() tea.Msg {
		client, err := approval.DialSocket(socketPath)
		if err != nil {
			return monitorPendingMsg{err: err}
		}
		defer client.Close() //nolint:errcheck
		pending, err := client.List()
		return monitorPendingMsg{pending: pending, err: err}
	}
}

func monitorResolveCmd(socketPath string, req approval.ToolCallRequest, approve bool, reason string) tea.Cmd {
	return func() tea.Msg {
		client, err := approval.DialSocket(socketPath)
		if err == nil {
			defer client.Close() //nolint:errcheck
			err = client.Resolve(req.ID, approve, reason)
		}
		return monitorResolvedMsg{decision: monitorDecision{
			req:       req,
			approved:  approve && err == nil,
			reason:    reason,
			decidedAt: time.Now(),
			err:       err,
		}}
	}
}
