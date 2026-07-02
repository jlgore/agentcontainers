package harness

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Options configure a scan (and, later, protect).
type Options struct {
	// Root is the filesystem root to inspect. "/" scans the host; a container's
	// mount namespace is "/proc/<init_pid>/root".
	Root string
	// Home is the agent's home directory (for "~/" expansion), in the target
	// root's namespace (e.g. "/home/node", "/workspace", "/root").
	Home string
	// AgentUID/AgentGID identify the agent process, for the writability verdict.
	AgentUID int
	AgentGID int
	// Include limits the scan to these categories (empty = AllCategories).
	Include []Category
}

// Finding is a discovered, existing catalog entry with a risk verdict.
type Finding struct {
	// Path is the resolved absolute path inside Root.
	Path     string
	Category Category
	Harness  string
	IsDir    bool
	// Writable reports whether the agent (AgentUID/GID) could modify this path
	// given its mode and ownership. A writable execution-config surface is the
	// blindspot ac harness protect closes.
	Writable bool
	Why      string
}

// Scan walks the catalog against opts.Root and returns the entries that exist,
// each with a writability verdict. Non-existent entries are skipped.
func Scan(opts Options) ([]Finding, error) {
	if opts.Root == "" {
		opts.Root = "/"
	}
	include := opts.Include
	if len(include) == 0 {
		include = AllCategories
	}
	want := make(map[Category]bool, len(include))
	for _, c := range include {
		want[c] = true
	}

	var findings []Finding
	seen := make(map[string]bool)
	for _, e := range Catalog() {
		if !want[e.Category] {
			continue
		}
		matches, err := resolve(e.Path, opts.Root, opts.Home)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			fi, err := os.Lstat(m)
			if err != nil {
				continue // does not exist in this root — skip
			}
			if seen[m] {
				continue
			}
			seen[m] = true
			findings = append(findings, Finding{
				Path:     m,
				Category: e.Category,
				Harness:  e.Harness,
				IsDir:    fi.IsDir(),
				Writable: writableBy(fi, opts.AgentUID, opts.AgentGID),
				Why:      e.Why,
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Path < findings[j].Path
	})
	return findings, nil
}

// resolve expands a catalog path ("~/" and "*") against a root, returning the
// absolute paths to test for existence.
func resolve(p, root, home string) ([]string, error) {
	if strings.HasPrefix(p, "~/") {
		if home == "" {
			return nil, nil // no home known — skip user-scoped entries
		}
		p = filepath.Join(home, p[2:])
	}
	full := filepath.Join(root, p)
	if strings.ContainsAny(full, "*?[") {
		matches, err := filepath.Glob(full)
		if err != nil {
			return nil, fmt.Errorf("harness: bad glob %q: %w", full, err)
		}
		return matches, nil
	}
	return []string{full}, nil
}

// writableBy reports whether a process with the given uid/gid could write the
// file: world-writable, or owner/group-writable and owned by the agent. When
// ownership can't be determined (non-Linux), it falls back to the mode bits and
// conservatively treats owner-writable as writable.
func writableBy(fi fs.FileInfo, uid, gid int) bool {
	mode := fi.Mode().Perm()
	if mode&0o002 != 0 {
		return true // world-writable
	}
	fuid, fgid, ok := statOwner(fi)
	if !ok {
		return mode&0o200 != 0 // unknown owner — assume the agent may own it
	}
	if fuid == uid && mode&0o200 != 0 {
		return true
	}
	if fgid == gid && mode&0o020 != 0 {
		return true
	}
	return false
}
