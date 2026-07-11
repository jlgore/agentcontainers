package toolpolicy

import (
	"fmt"
	"regexp"
	"strings"
)

// contentEvaluator decides the two content categories the Cedar engine cannot
// express in policy language: shell_metacharacters (literal substring scan) and
// awk_scanning (an RE2 regex with variable-length `\s*`). It is a faithful
// native-Go port of shell_metacharacters.rego and awk_scanning.rego, owned by
// the Cedar engine. The reason strings reproduce the rego `sprintf` output
// verbatim so audit records are byte-identical across engines.
type contentEvaluator struct {
	shellMetacharacters []string
	awkProgramTools     map[string]struct{} // lowercased set
	awkRegex            *regexp.Regexp      // nil when the pattern is empty
}

// newContentEvaluator builds the content evaluator from a compiled policy. The
// awk regex is compiled once; a malformed pattern is a hard error (fail closed
// at construction rather than silently skipping the awk_scanning category).
func newContentEvaluator(cp *CompiledPolicy) (*contentEvaluator, error) {
	c := &contentEvaluator{
		shellMetacharacters: dataStrings(cp.Data["shell_metacharacters"]),
		awkProgramTools:     toSet(lowerAll(dataStrings(cp.Data["awk_program_tools"]))),
	}
	if re := strings.TrimSpace(cp.AwkDangerRegex); re != "" {
		compiled, err := regexp.Compile(re)
		if err != nil {
			return nil, fmt.Errorf("mcpproxy: compiling awk_danger_regex: %w", err)
		}
		c.awkRegex = compiled
	}
	return c, nil
}

// evaluate returns the prefixed deny reasons for the content categories.
func (c *contentEvaluator) evaluate(p parsedFields) []string {
	var reasons []string
	reasons = append(reasons, c.shellMetacharacterReasons(p)...)
	reasons = append(reasons, c.awkReasons(p)...)
	return reasons
}

// shellMetacharacterReasons mirrors shell_metacharacters.rego: any declared
// metacharacter appearing as a substring of any argument denies. The rego
// `deny` is a set, so a metacharacter that matches multiple args yields one
// reason — we dedupe by the (pattern-only) message accordingly.
func (c *contentEvaluator) shellMetacharacterReasons(p parsedFields) []string {
	seen := make(map[string]struct{})
	var reasons []string
	for _, arg := range p.args {
		for _, pattern := range c.shellMetacharacters {
			if pattern == "" || !strings.Contains(arg, pattern) {
				continue
			}
			msg := fmt.Sprintf("sift.shell_metacharacters: shell metacharacter '%s' detected in argument", pattern)
			if _, dup := seen[msg]; dup {
				continue
			}
			seen[msg] = struct{}{}
			reasons = append(reasons, msg)
		}
	}
	return reasons
}

// awkReasons mirrors awk_scanning.rego: for an awk-family binary, any positional
// (non-flag) argument whose program text matches the danger regex denies. The
// message names only the binary, so all matching args collapse to one reason.
func (c *contentEvaluator) awkReasons(p parsedFields) []string {
	if c.awkRegex == nil {
		return nil
	}
	if _, ok := c.awkProgramTools[strings.ToLower(p.binary)]; !ok {
		return nil
	}
	for _, arg := range p.args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if c.awkRegex.MatchString(arg) {
			return []string{fmt.Sprintf(
				"sift.awk_scanning: dangerous construct in %s program text (system(), getline, or pipe operators)",
				p.binary)}
		}
	}
	return nil
}
