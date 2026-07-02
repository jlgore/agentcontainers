// Package harness discovers and protects the on-disk configuration that can
// cause deferred or out-of-band code execution for an AI agent: the harness's
// own tool-gating hook/plugin/extension config, OS schedulers (cron, at,
// systemd timers/units), and shell startup files. An agent that can rewrite
// these can disable its own guard (harness config) or run code in an
// unenforced context (a cron job or systemd unit runs in the scheduler
// daemon's cgroup, not the agent's). `ac harness scan` reports them with a
// writability verdict; `ac harness protect` freezes them (chattr +i).
package harness

// Category classifies an execution-triggering configuration surface.
type Category string

const (
	// CategoryHarness is the agent-harness config that installs the tool-gating
	// hook/plugin/extension; rewriting it lets the agent disable its own guard.
	CategoryHarness Category = "harness"
	// CategoryScheduler is OS scheduler config (cron, at, systemd timers/units);
	// writing it runs code later, typically in a different (unenforced) cgroup.
	CategoryScheduler Category = "scheduler"
	// CategoryShellRC is shell startup files sourced when the agent next spawns
	// a shell — a deferred-execution and persistence surface.
	CategoryShellRC Category = "shell-rc"
)

// AllCategories is the default scan/protect scope.
var AllCategories = []Category{CategoryHarness, CategoryScheduler, CategoryShellRC}

// Entry is one catalog item: a path whose contents (a config file) or
// membership (a directory) trigger deferred/out-of-band execution.
type Entry struct {
	// Path is absolute in the target root's namespace. A leading "~/" expands to
	// the agent's home; a "*" is matched with filepath.Glob.
	Path string
	// Category and Harness classify the entry (Harness "" = OS-level).
	Category Category
	Harness  string
	// Dir marks a directory whose *membership* matters — freezing it (chattr +i
	// on the dir) blocks the agent creating/removing entries in it. Otherwise
	// Path is a config file whose contents matter.
	Dir bool
	// Why documents the execution mechanism, shown in scan output.
	Why string
}

// Catalog is the full set of execution-triggering config surfaces. It targets
// specific files and scheduler directories — never a harness *state* directory
// (e.g. all of ~/.claude, which holds session history the harness must write).
func Catalog() []Entry {
	return []Entry{
		// ── harness: Claude Code ── (freeze settings*.json, NOT the ~/.claude state dir)
		{Path: "/etc/claude-code/managed-settings.json", Category: CategoryHarness, Harness: "claude-code", Why: "locked root-owned PreToolUse guard hook"},
		{Path: "~/.claude/settings.json", Category: CategoryHarness, Harness: "claude-code", Why: "user PreToolUse hooks"},
		{Path: "~/.claude/settings.local.json", Category: CategoryHarness, Harness: "claude-code", Why: "user-local PreToolUse hooks"},
		{Path: "~/.config/claude/settings.json", Category: CategoryHarness, Harness: "claude-code", Why: "CLAUDE_CONFIG_DIR PreToolUse hooks"},

		// ── harness: opencode ── (plugins auto-load from writable dirs)
		{Path: "/etc/opencode/opencode.json", Category: CategoryHarness, Harness: "opencode", Why: "managed permission/plugin config"},
		{Path: "~/.config/opencode/opencode.json", Category: CategoryHarness, Harness: "opencode", Why: "user permission/plugin config"},
		{Path: "~/.config/opencode/plugin/*", Category: CategoryHarness, Harness: "opencode", Why: "auto-loaded guard-adapter plugins"},

		// ── harness: pi ── (no managed lock — agent can rewrite its own config)
		{Path: "~/.config/pi/config.json", Category: CategoryHarness, Harness: "pi", Why: "pi config (no managed lock)"},
		{Path: "~/.config/pi/mcp.json", Category: CategoryHarness, Harness: "pi", Why: "pi-mcp-adapter config"},

		// ── scheduler: cron / at ──
		{Path: "/etc/crontab", Category: CategoryScheduler, Why: "system crontab"},
		{Path: "/etc/anacrontab", Category: CategoryScheduler, Why: "anacron schedule"},
		{Path: "/etc/cron.d", Category: CategoryScheduler, Dir: true, Why: "drop-in cron jobs"},
		{Path: "/etc/cron.hourly", Category: CategoryScheduler, Dir: true, Why: "hourly cron scripts"},
		{Path: "/etc/cron.daily", Category: CategoryScheduler, Dir: true, Why: "daily cron scripts"},
		{Path: "/etc/cron.weekly", Category: CategoryScheduler, Dir: true, Why: "weekly cron scripts"},
		{Path: "/etc/cron.monthly", Category: CategoryScheduler, Dir: true, Why: "monthly cron scripts"},
		{Path: "/var/spool/cron/crontabs", Category: CategoryScheduler, Dir: true, Why: "per-user crontabs (Debian)"},
		{Path: "/var/spool/cron", Category: CategoryScheduler, Dir: true, Why: "per-user crontabs (RHEL)"},
		{Path: "/var/spool/cron/atjobs", Category: CategoryScheduler, Dir: true, Why: "at/batch jobs (Debian)"},
		{Path: "/var/spool/at", Category: CategoryScheduler, Dir: true, Why: "at/batch jobs"},

		// ── scheduler: systemd ──
		{Path: "/etc/systemd/system", Category: CategoryScheduler, Dir: true, Why: "systemd units + timers"},
		{Path: "/etc/systemd/user", Category: CategoryScheduler, Dir: true, Why: "systemd user units"},
		{Path: "~/.config/systemd/user", Category: CategoryScheduler, Dir: true, Why: "per-user systemd units + timers"},

		// ── shell-rc ── (sourced on the agent's next shell)
		{Path: "~/.bashrc", Category: CategoryShellRC, Why: "sourced by interactive bash"},
		{Path: "~/.bash_profile", Category: CategoryShellRC, Why: "bash login shell"},
		{Path: "~/.bash_login", Category: CategoryShellRC, Why: "bash login shell"},
		{Path: "~/.bash_aliases", Category: CategoryShellRC, Why: "sourced from ~/.bashrc"},
		{Path: "~/.profile", Category: CategoryShellRC, Why: "POSIX login shell"},
		{Path: "~/.zshrc", Category: CategoryShellRC, Why: "interactive zsh"},
		{Path: "~/.zshenv", Category: CategoryShellRC, Why: "every zsh invocation"},
		{Path: "~/.zprofile", Category: CategoryShellRC, Why: "zsh login shell"},
		{Path: "~/.zlogin", Category: CategoryShellRC, Why: "zsh login shell"},
		{Path: "~/.config/fish/config.fish", Category: CategoryShellRC, Why: "fish startup"},
		{Path: "~/.config/fish/conf.d/*", Category: CategoryShellRC, Why: "fish drop-in startup"},
		{Path: "/etc/profile", Category: CategoryShellRC, Why: "system login shell"},
		{Path: "/etc/bash.bashrc", Category: CategoryShellRC, Why: "system interactive bash"},
		{Path: "/etc/profile.d", Category: CategoryShellRC, Dir: true, Why: "system login drop-ins"},
	}
}
