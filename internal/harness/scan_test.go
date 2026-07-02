package harness

import (
	"os"
	"path/filepath"
	"testing"
)

// mkfile creates a file (and parents) with the given mode.
func mkfile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile respects umask; force the exact mode.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func find(fs []Finding, suffix string) *Finding {
	for i := range fs {
		if filepath.Base(fs[i].Path) == suffix {
			return &fs[i]
		}
	}
	return nil
}

func TestScan_FindsCatalogSurfacesByCategory(t *testing.T) {
	root := t.TempDir()
	home := "/home/agent"
	uid := os.Getuid()

	// Plant one surface per category (+ a glob and a dir).
	mkfile(t, filepath.Join(root, "etc/crontab"), 0o644)
	if err := os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	mkfile(t, filepath.Join(root, home, ".bashrc"), 0o644)
	mkfile(t, filepath.Join(root, home, ".claude/settings.json"), 0o600)
	mkfile(t, filepath.Join(root, home, ".config/opencode/plugin/guard.js"), 0o644)

	got, err := Scan(Options{Root: root, Home: home, AgentUID: uid, AgentGID: os.Getgid()})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	crontab := find(got, "crontab")
	if crontab == nil || crontab.Category != CategoryScheduler {
		t.Errorf("crontab not found as scheduler: %+v", crontab)
	}
	crond := find(got, "cron.d")
	if crond == nil || !crond.IsDir {
		t.Errorf("cron.d dir not found: %+v", crond)
	}
	bashrc := find(got, ".bashrc")
	if bashrc == nil || bashrc.Category != CategoryShellRC {
		t.Errorf(".bashrc not found as shell-rc: %+v", bashrc)
	}
	settings := find(got, "settings.json")
	if settings == nil || settings.Category != CategoryHarness || settings.Harness != "claude-code" {
		t.Errorf("claude settings.json not found: %+v", settings)
	}
	// Glob expansion of the opencode plugin dir.
	if plugin := find(got, "guard.js"); plugin == nil || plugin.Harness != "opencode" {
		t.Errorf("opencode plugin (glob) not found: %+v", plugin)
	}
}

func TestScan_SkipsNonExistentAndFiltersCategory(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "etc/crontab"), 0o644)
	mkfile(t, filepath.Join(root, "etc/profile"), 0o644)

	// Only shell-rc requested → crontab (scheduler) excluded, profile included.
	got, err := Scan(Options{Root: root, Include: []Category{CategoryShellRC}})
	if err != nil {
		t.Fatal(err)
	}
	if find(got, "crontab") != nil {
		t.Error("scheduler entry returned when only shell-rc requested")
	}
	if find(got, "profile") == nil {
		t.Error("shell-rc /etc/profile not found")
	}
}

func TestScan_WritabilityVerdict(t *testing.T) {
	root := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()

	mkfile(t, filepath.Join(root, "etc/crontab"), 0o600)   // owner-write, owned by test uid
	mkfile(t, filepath.Join(root, "etc/anacrontab"), 0o644) // owner rw, others r
	mkfile(t, filepath.Join(root, "etc/profile"), 0o666)    // world-writable

	// Agent == the owning uid: the 0600 file is writable.
	asOwner, err := Scan(Options{Root: root, AgentUID: uid, AgentGID: gid})
	if err != nil {
		t.Fatal(err)
	}
	if f := find(asOwner, "crontab"); f == nil || !f.Writable {
		t.Errorf("0600 file owned by agent should be writable: %+v", f)
	}
	if f := find(asOwner, "profile"); f == nil || !f.Writable {
		t.Errorf("world-writable file should be writable: %+v", f)
	}

	// Agent is a DIFFERENT uid (and gid): the owner-only files are not writable,
	// but the world-writable one still is.
	other := uid + 12345
	asOther, err := Scan(Options{Root: root, AgentUID: other, AgentGID: other})
	if err != nil {
		t.Fatal(err)
	}
	if f := find(asOther, "crontab"); f == nil || f.Writable {
		t.Errorf("0600 file not owned by agent should be read-only: %+v", f)
	}
	if f := find(asOther, "anacrontab"); f == nil || f.Writable {
		t.Errorf("0644 file not owned by agent should be read-only: %+v", f)
	}
	if f := find(asOther, "profile"); f == nil || !f.Writable {
		t.Errorf("world-writable file should be writable regardless of owner: %+v", f)
	}
}
