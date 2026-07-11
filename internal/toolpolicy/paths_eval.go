package toolpolicy

import (
	"fmt"
	"path"
	"strings"
)

// pathEvaluator decides the four path categories the Cedar engine delegates to
// native Go: path_policy, output_path_policy (stateful on the active case dir),
// rm_protection (stateful), and filesystem (glob allowlists/denylist). Cedar's
// `like` wildcard crosses `/`, so it cannot reproduce the `/`-bounded glob
// semantics of filesystem.rego without being weaker than OPA — these stay a
// faithful native port. Reason strings reproduce the rego `sprintf` output
// verbatim for audit parity.
type pathEvaluator struct {
	blockedInputDirs       []string
	blockedInputExceptions []string
	blockedOutputDirs      []string
	protectedRmDirs        []string
	fsRead                 []string
	fsWrite                []string
	fsDeny                 []string
}

func newPathEvaluator(cp *CompiledPolicy) *pathEvaluator {
	return &pathEvaluator{
		blockedInputDirs:       dataStrings(cp.Data["blocked_input_dirs"]),
		blockedInputExceptions: dataStrings(cp.Data["blocked_input_exceptions"]),
		blockedOutputDirs:      dataStrings(cp.Data["blocked_output_dirs"]),
		protectedRmDirs:        dataStrings(cp.Data["protected_rm_dirs"]),
		fsRead:                 dataStrings(cp.Data["fs_read"]),
		fsWrite:                dataStrings(cp.Data["fs_write"]),
		fsDeny:                 dataStrings(cp.Data["fs_deny"]),
	}
}

// evaluate returns the prefixed deny reasons for all path categories. caseDir
// and cwd come from input.context (runtime state); an empty caseDir means no
// active case.
func (e *pathEvaluator) evaluate(p parsedFields, caseDir, cwd string) []string {
	var out denyset
	e.pathPolicy(&out, p)
	e.outputPathPolicy(&out, p, caseDir, cwd)
	e.rmProtection(&out, p, caseDir)
	e.filesystem(&out, p)
	return out.list
}

// pathPolicy ports path_policy.rego: input paths inside a blocked system dir
// deny, unless covered by an evidence-data exception.
func (e *pathEvaluator) pathPolicy(out *denyset, p parsedFields) {
	for _, pth := range p.paths {
		for _, blocked := range e.blockedInputDirs {
			if !inside(pth, blocked) || e.inputException(pth) {
				continue
			}
			out.add(fmt.Sprintf("sift.path_policy: input path '%s' is inside blocked system directory '%s'", pth, blocked))
		}
	}
}

func (e *pathEvaluator) inputException(pth string) bool {
	for _, exc := range e.blockedInputExceptions {
		if inside(pth, exc) {
			return true
		}
	}
	return false
}

// outputPathPolicy ports output_path_policy.rego (stateful). With an active
// case dir, output must stay inside it; without one, only /tmp and cwd are
// permitted, with a specific message for known-blocked dirs.
func (e *pathEvaluator) outputPathPolicy(out *denyset, p parsedFields, caseDir, cwd string) {
	if caseDir != "" {
		for _, pth := range p.outputPaths {
			if !inside(pth, caseDir) {
				out.add(fmt.Sprintf("sift.output_path_policy: output path '%s' is outside the case directory '%s'", pth, caseDir))
			}
		}
		return
	}
	for _, pth := range p.outputPaths {
		if e.tmpOrCwd(pth, cwd) {
			continue
		}
		blockedHit := false
		for _, blocked := range e.blockedOutputDirs {
			if inside(pth, blocked) {
				blockedHit = true
				out.add(fmt.Sprintf("sift.output_path_policy: output denied: '%s' is inside blocked directory '%s'", pth, blocked))
			}
		}
		if !blockedHit {
			out.add(fmt.Sprintf("sift.output_path_policy: output denied: '%s' — without an active case, output is only allowed in /tmp or the current working directory", pth))
		}
	}
}

func (e *pathEvaluator) tmpOrCwd(pth, cwd string) bool {
	if inside(pth, "/tmp") {
		return true
	}
	return cwd != "" && inside(pth, cwd)
}

// rmProtection ports rm_protection.rego: rm is blocked inside evidence/case
// storage, at filesystem root, and inside the active case dir.
func (e *pathEvaluator) rmProtection(out *denyset, p parsedFields, caseDir string) {
	if p.binary != "rm" {
		return
	}
	for _, pth := range p.paths {
		for _, protected := range e.protectedRmDirs {
			if inside(pth, protected) {
				out.add(fmt.Sprintf("sift.rm_protection: rm in protected directory '%s'. File deletion in case/evidence directories requires human action outside the AI session.", protected))
			}
		}
		if pth == "/" {
			out.add("sift.rm_protection: rm targeting filesystem root")
		}
		if caseDir != "" && inside(pth, caseDir) {
			out.add(fmt.Sprintf("sift.rm_protection: rm in case directory '%s'. File deletion in case/evidence directories requires human action outside the AI session.", caseDir))
		}
	}
}

// filesystem ports filesystem.rego: a deny-pattern match on any referenced
// path denies; non-empty read/write allowlists confine input/output paths.
func (e *pathEvaluator) filesystem(out *denyset, p parsedFields) {
	for _, pth := range append(append([]string(nil), p.paths...), p.outputPaths...) {
		for _, pattern := range e.fsDeny {
			if fsMatches(pth, pattern) {
				out.add(fmt.Sprintf("sift.filesystem: path '%s' is denied by filesystem policy ('%s')", pth, pattern))
			}
		}
	}
	if len(e.fsRead) > 0 {
		for _, pth := range p.paths {
			if !fsMatchesAny(pth, e.fsRead) {
				out.add(fmt.Sprintf("sift.filesystem: read path '%s' is outside the filesystem read allowlist", pth))
			}
		}
	}
	if len(e.fsWrite) > 0 {
		for _, pth := range p.outputPaths {
			if !fsMatchesAny(pth, e.fsWrite) {
				out.add(fmt.Sprintf("sift.filesystem: write path '%s' is outside the filesystem write allowlist", pth))
			}
		}
	}
}

// inside mirrors the rego `_inside`: path is the directory itself or lives
// beneath it (a "/"-boundary prefix, so "/ab" is not inside "/a").
func inside(pth, dir string) bool {
	return pth == dir || strings.HasPrefix(pth, dir+"/")
}

func fsMatchesAny(pth string, patterns []string) bool {
	for _, pattern := range patterns {
		if fsMatches(pth, pattern) {
			return true
		}
	}
	return false
}

// fsMatches mirrors filesystem.rego `_matches`. A plain pattern (no "*") is a
// prefix-containment check; a glob matches the path exactly or as a descendant,
// with "*" bounded by "/" (the rego uses glob.match with the "/" delimiter, so
// "*" never crosses a path segment — unlike Cedar `like`, which is why this
// stays native Go).
func fsMatches(pth, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return inside(pth, pattern)
	}
	pseg := splitSegments(pattern)
	fseg := splitSegments(pth)
	// Exact: same segment count, every segment matches.
	if len(fseg) == len(pseg) && segmentsMatch(pseg, fseg) {
		return true
	}
	// Descendant (pattern + "/**"): path has more segments, the prefix matches.
	if len(fseg) > len(pseg) && segmentsMatch(pseg, fseg[:len(pseg)]) {
		return true
	}
	return false
}

func splitSegments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// segmentsMatch matches each pattern segment against the corresponding path
// segment with shell-glob semantics (path.Match: "*" matches within a segment).
func segmentsMatch(pat, seg []string) bool {
	for i := range pat {
		ok, err := path.Match(pat[i], seg[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// denyset accumulates deny reasons preserving first-seen order and deduping
// identical messages, mirroring the set semantics of the rego `deny` rules.
type denyset struct {
	list []string
	seen map[string]struct{}
}

func (d *denyset) add(msg string) {
	if d.seen == nil {
		d.seen = make(map[string]struct{})
	}
	if _, dup := d.seen[msg]; dup {
		return
	}
	d.seen[msg] = struct{}{}
	d.list = append(d.list, msg)
}
