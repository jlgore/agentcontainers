package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/harness"
)

func newHarnessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "harness",
		Short: "Discover and protect agent execution-config (guard hooks, cron, shell rc)",
		Long: `Find and freeze the on-disk configuration that can cause an AI agent's
own tools to be gated differently, or code to run out-of-band: the harness's
tool-gating hook/plugin/extension config, OS schedulers (cron/at/systemd
timers), and shell startup files. An agent that can rewrite these can disable
its own guard, or schedule code that runs in an unenforced cgroup.`,
	}
	cmd.AddCommand(newHarnessScanCmd())
	return cmd
}

func newHarnessScanCmd() *cobra.Command {
	var (
		root         string
		home         string
		agentUID     int
		agentGID     int
		include      []string
		writableOnly bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Report execution-triggering config surfaces and whether the agent can write them",
		Long: `Walk the catalog of execution-triggering config (harness hooks, cron/at/
systemd, shell rc) against a filesystem root and report every surface that
exists, with a writability verdict for the agent.

Scan a running container by pointing --root at its mount namespace and passing
the agent's uid:

  agentcontainer harness scan --root /proc/<pid>/root --home /workspace --agent-uid 1000

A WRITABLE row is a surface the agent could rewrite — the blindspot
'agentcontainer harness protect' closes by making it immutable.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cats, err := parseCategories(include)
			if err != nil {
				return err
			}
			findings, err := harness.Scan(harness.Options{
				Root:     root,
				Home:     home,
				AgentUID: agentUID,
				AgentGID: agentGID,
				Include:  cats,
			})
			if err != nil {
				return err
			}
			return printHarnessFindings(cmd.OutOrStdout(), findings, writableOnly)
		},
	}
	cmd.Flags().StringVar(&root, "root", "/", "Filesystem root to scan (a container is /proc/<pid>/root)")
	cmd.Flags().StringVar(&home, "home", defaultAgentHome(), "Agent home directory, for ~ expansion")
	cmd.Flags().IntVar(&agentUID, "agent-uid", os.Getuid(), "Agent uid for the writability verdict")
	cmd.Flags().IntVar(&agentGID, "agent-gid", os.Getgid(), "Agent gid for the writability verdict")
	cmd.Flags().StringSliceVar(&include, "include", nil, "Categories to scan: harness,scheduler,shell-rc (default all)")
	cmd.Flags().BoolVar(&writableOnly, "writable-only", false, "Only show agent-writable surfaces (the risks)")
	return cmd
}

func defaultAgentHome() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}

func parseCategories(in []string) ([]harness.Category, error) {
	var out []harness.Category
	for _, s := range in {
		switch c := harness.Category(strings.TrimSpace(s)); c {
		case harness.CategoryHarness, harness.CategoryScheduler, harness.CategoryShellRC:
			out = append(out, c)
		default:
			return nil, fmt.Errorf("harness: unknown category %q (want harness|scheduler|shell-rc)", s)
		}
	}
	return out, nil
}

func printHarnessFindings(out io.Writer, findings []harness.Finding, writableOnly bool) error {
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "WRITABLE\tCATEGORY\tHARNESS\tPATH\tMECHANISM")
	writable := 0
	for _, f := range findings {
		if f.Writable {
			writable++
		}
		if writableOnly && !f.Writable {
			continue
		}
		mark := "-"
		if f.Writable {
			mark = "yes"
		}
		harnessName := f.Harness
		if harnessName == "" {
			harnessName = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", mark, f.Category, harnessName, f.Path, f.Why)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintf(out, "\n%d surface(s) found, %d agent-writable.\n", len(findings), writable)
	if writable > 0 {
		_, _ = fmt.Fprintln(out, "Freeze the writable ones with: agentcontainer harness protect")
	}
	return nil
}
