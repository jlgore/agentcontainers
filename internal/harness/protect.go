package harness

// ProtectResult records the outcome of a protect/unprotect for one path.
type ProtectResult struct {
	Path   string
	Action string // protected | unprotected | already-immutable | already-clear | error
	Err    error
}

// Protect sets (on=true) or clears (on=false) the immutable bit on each path.
// It requires CAP_LINUX_IMMUTABLE and is idempotent: a path already in the
// desired state is reported without a change. Errors are captured per-path, not
// fatal, so a single unreachable file doesn't abort the batch.
func Protect(paths []string, on bool) []ProtectResult {
	results := make([]ProtectResult, 0, len(paths))
	for _, p := range paths {
		cur, err := isImmutable(p)
		if err != nil {
			results = append(results, ProtectResult{Path: p, Action: "error", Err: err})
			continue
		}
		if cur == on {
			act := "already-clear"
			if on {
				act = "already-immutable"
			}
			results = append(results, ProtectResult{Path: p, Action: act})
			continue
		}
		if err := setImmutable(p, on); err != nil {
			results = append(results, ProtectResult{Path: p, Action: "error", Err: err})
			continue
		}
		act := "unprotected"
		if on {
			act = "protected"
		}
		results = append(results, ProtectResult{Path: p, Action: act})
	}
	return results
}
