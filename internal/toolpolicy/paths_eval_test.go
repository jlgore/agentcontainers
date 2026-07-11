package toolpolicy

import "testing"

func TestFsMatches(t *testing.T) {
	cases := []struct {
		path, pattern string
		want          bool
	}{
		// Plain prefix (no "*"): the dir itself or inside it, "/"-bounded.
		{"/evidence", "/evidence", true},
		{"/evidence/disk.img", "/evidence", true},
		{"/evidenceX", "/evidence", false},
		// Glob bounded by "/": "*" does not cross a segment.
		{"/cases/c1/extractions", "/cases/*/extractions", true},
		{"/cases/c1/extractions/file.bin", "/cases/*/extractions", true}, // descendant
		{"/cases/c1/other", "/cases/*/extractions", false},
		{"/cases/c1/x/extractions", "/cases/*/extractions", false}, // "*" must not span "/"
		{"/proc/123/mem", "/proc/*/mem", true},
		{"/proc/123/maps", "/proc/*/mem", false},
	}
	for _, c := range cases {
		if got := fsMatches(c.path, c.pattern); got != c.want {
			t.Errorf("fsMatches(%q, %q) = %v, want %v", c.path, c.pattern, got, c.want)
		}
	}
}

func TestPathEvaluator_FilesystemAllowlist(t *testing.T) {
	e := newPathEvaluator(&CompiledPolicy{Data: map[string]any{
		"fs_read":  sliceAny([]string{"/cases/*/extractions"}),
		"fs_write": sliceAny([]string{"/tmp"}),
		"fs_deny":  sliceAny([]string{"/etc/shadow"}),
	}})

	// Read inside the allowlist: allowed.
	if r := e.evaluate(parsedFields{paths: []string{"/cases/c1/extractions/f.bin"}}, "", ""); len(r) != 0 {
		t.Errorf("read inside allowlist should pass, got %v", r)
	}
	// Read outside the allowlist: denied.
	r := e.evaluate(parsedFields{paths: []string{"/home/user/secret"}}, "", "")
	if !containsStr(r, "sift.filesystem: read path '/home/user/secret' is outside the filesystem read allowlist") {
		t.Errorf("read outside allowlist should deny, got %v", r)
	}
	// Deny pattern hit on any referenced path.
	r = e.evaluate(parsedFields{paths: []string{"/etc/shadow"}}, "", "")
	if !containsStr(r, "sift.filesystem: path '/etc/shadow' is denied by filesystem policy ('/etc/shadow')") {
		t.Errorf("deny pattern should fire, got %v", r)
	}
}

func TestPathEvaluator_OutputCaseDirStateful(t *testing.T) {
	e := newPathEvaluator(&CompiledPolicy{Data: map[string]any{
		"blocked_output_dirs": sliceAny([]string{"/etc"}),
	}})
	// Active case: output outside it is denied.
	r := e.evaluate(parsedFields{outputPaths: []string{"/tmp/o.csv"}}, "/cases/c1", "")
	if !containsStr(r, "sift.output_path_policy: output path '/tmp/o.csv' is outside the case directory '/cases/c1'") {
		t.Errorf("output outside active case should deny, got %v", r)
	}
	// Active case: output inside it is allowed.
	if r := e.evaluate(parsedFields{outputPaths: []string{"/cases/c1/out.csv"}}, "/cases/c1", ""); len(r) != 0 {
		t.Errorf("output inside active case should pass, got %v", r)
	}
}
