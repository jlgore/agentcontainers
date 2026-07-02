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
	cmd.AddCommand(newHarnessScanCmd(), newHarnessProtectCmd(), newHarnessUnprotectCmd())
	return cmd
}

// scanOpts carries the flags shared by scan/protect/unprotect.
type scanOpts struct {
	root     string
	home     string
	agentUID int
	agentGID int
	include  []string
}

func addScanFlags(cmd *cobra.Command, o *scanOpts) {
	cmd.Flags().StringVar(&o.root, "root", "/", "Filesystem root (a container is /proc/<pid>/root)")
	cmd.Flags().StringVar(&o.home, "home", defaultAgentHome(), "Agent home directory, for ~ expansion")
	cmd.Flags().IntVar(&o.agentUID, "agent-uid", os.Getuid(), "Agent uid for the writability verdict")
	cmd.Flags().IntVar(&o.agentGID, "agent-gid", os.Getgid(), "Agent gid for the writability verdict")
	cmd.Flags().StringSliceVar(&o.include, "include", nil, "Categories: harness,scheduler,shell-rc (default all)")
}

func (o *scanOpts) scan() ([]harness.Finding, error) {
	cats, err := parseCategories(o.include)
	if err != nil {
		return nil, err
	}
	return harness.Scan(harness.Options{
		Root:     o.root,
		Home:     o.home,
		AgentUID: o.agentUID,
		AgentGID: o.agentGID,
		Include:  cats,
	})
}

func newHarnessScanCmd() *cobra.Command {
	var so scanOpts
	var writableOnly bool
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
			findings, err := so.scan()
			if err != nil {
				return err
			}
			return printHarnessFindings(cmd.OutOrStdout(), findings, writableOnly)
		},
	}
	addScanFlags(cmd, &so)
	cmd.Flags().BoolVar(&writableOnly, "writable-only", false, "Only show agent-writable surfaces (the risks)")
	return cmd
}

func newHarnessProtectCmd() *cobra.Command {
	var so scanOpts
	var all, dryRun bool
	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Freeze execution-config surfaces immutable (chattr +i)",
		Long: `Freeze the execution-triggering config found by scan by setting the
immutable bit (chattr +i): the agent can no longer write, rename, unlink, or
replace them — so it cannot disable its own guard or plant a cron/systemd job —
and, lacking CAP_LINUX_IMMUTABLE, it cannot clear the bit itself.

By default only agent-WRITABLE surfaces are frozen (the actual risks); --all
freezes every discovered surface (defense in depth). Requires
CAP_LINUX_IMMUTABLE (run as root, or via the enforcer sidecar in the agent
namespace).

WARNING: this modifies the target root. Scope it with --root — freezing a live
host's /etc/systemd/system or /etc/cron.d will block legitimate administration
too. Use --dry-run first.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			findings, err := so.scan()
			if err != nil {
				return err
			}
			return applyHarnessProtect(cmd.OutOrStdout(), findings, true, all, dryRun)
		},
	}
	addScanFlags(cmd, &so)
	cmd.Flags().BoolVar(&all, "all", false, "Also freeze surfaces the agent can't currently write")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would change without modifying anything")
	return cmd
}

func newHarnessUnprotectCmd() *cobra.Command {
	var so scanOpts
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "unprotect",
		Short: "Clear the immutable bit from execution-config surfaces",
		Long: `Clear the immutable bit (chattr -i) from the execution-config surfaces
found by scan, reversing 'harness protect'. Requires CAP_LINUX_IMMUTABLE.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			findings, err := so.scan()
			if err != nil {
				return err
			}
			// Unprotect clears everything discovered, not just writable ones.
			return applyHarnessProtect(cmd.OutOrStdout(), findings, false, true, dryRun)
		},
	}
	addScanFlags(cmd, &so)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would change without modifying anything")
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
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", mark, f.Category, harnessName(f.Harness), f.Path, f.Why)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintf(out, "\n%d surface(s) found, %d agent-writable.\n", len(findings), writable)
	if writable > 0 {
		_, _ = fmt.Fprintln(out, "Freeze the writable ones with: agentcontainer harness protect")
	}
	return nil
}

func applyHarnessProtect(out io.Writer, findings []harness.Finding, on, all, dryRun bool) error {
	var paths []string
	for _, f := range findings {
		if on && !all && !f.Writable {
			continue // protect: only the actual risks unless --all
		}
		paths = append(paths, f.Path)
	}
	verb := "protect"
	if !on {
		verb = "unprotect"
	}
	if len(paths) == 0 {
		_, _ = fmt.Fprintf(out, "No surfaces to %s.\n", verb)
		return nil
	}
	if dryRun {
		_, _ = fmt.Fprintf(out, "Would %s %d surface(s):\n", verb, len(paths))
		for _, p := range paths {
			_, _ = fmt.Fprintf(out, "  %s\n", p)
		}
		return nil
	}

	results := harness.Protect(paths, on)
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	changed, errs := 0, 0
	for _, r := range results {
		detail := ""
		switch r.Action {
		case "error":
			errs++
			detail = r.Err.Error()
		case "protected", "unprotected":
			changed++
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Action, r.Path, detail)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintf(out, "\n%d changed, %d error(s).\n", changed, errs)
	if errs > 0 {
		return fmt.Errorf("harness %s: %d path(s) failed (need CAP_LINUX_IMMUTABLE / root?)", verb, errs)
	}
	return nil
}

func harnessName(h string) string {
	if h == "" {
		return "-"
	}
	return h
}
