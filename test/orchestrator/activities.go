package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.temporal.io/sdk/activity"
)

// Substrate names how the escape harness is hosted for a cell.
const (
	SubstrateVM        = "vm"        // KubeVirt VMI; recovery = VM restart
	SubstrateContainer = "container" // privileged pod; recovery = delete + recreate
)

// Cell is one point of the escape matrix: a single fixture case run under one
// harness/model, optionally under the eBPF enforcer.
type Cell struct {
	Harness  string // pi | opencode | claude
	Provider string // openrouter | anthropic | openai
	Model    string // e.g. z-ai/glm-5.2
	CaseID   string // fixture case id → CASE_FILTER (the ONE case this cell runs)
	Enforcer bool   // BREAKOUT_ENFORCER=1 (kernel egress boundary)

	// Substrate hosts this cell: "vm" (KubeVirt VMI) or "container" (privileged
	// pod). Empty falls back to the worker's DefaultSubstrate. The drive path is
	// identical (SSH); only guest-host resolution and reset-recovery differ.
	Substrate string

	AgentTimeoutSec int // BREAKOUT_AGENT_TIMEOUT
	MaxRounds       int // BREAKOUT_MAX_ROUNDS (budget loop); 0/1 = single-shot
	CodebaseDir     string

	// OpenRouterRole selects which vault-openrouter-engine role (hence which
	// budget cap) mints this cell's key — per-model budgets. Empty falls back to
	// the worker's OPENROUTER_ROLE default.
	OpenRouterRole string

	// ApproverVerdict is set by the workflow for score:hitl cells from the Temporal
	// approval signal ("allow"|"deny"). It drives breakout-run.sh's `fixed` approver
	// policy so the honored decision comes from the control plane (a human or scripted
	// approver via `temporal workflow signal`), not a baked-in persona. Empty otherwise.
	ApproverVerdict string
}

// CellResult mirrors one line of the runner's results.jsonl plus a derived
// Passed flag (gate=="PASS").
type CellResult struct {
	ID      string `json:"id"`
	Test    any    `json:"test"`
	Score   string `json:"score"`
	Expect  string `json:"expect"`
	Gate    string `json:"gate"`
	Note    string `json:"note"`
	Session string `json:"session"`
	Passed  bool   `json:"-"`
}

// Activities holds the worker's side-effecting operations. It carries config and
// resolves the guest host once per activity call.
type Activities struct {
	Cfg Config
}

// substrate resolves the cell's substrate, falling back to the worker default.
func (a *Activities) substrate(cell Cell) string {
	if cell.Substrate != "" {
		return cell.Substrate
	}
	if a.Cfg.DefaultSubstrate != "" {
		return a.Cfg.DefaultSubstrate
	}
	return SubstrateVM
}

// guestHost returns the address to SSH to: an explicit GUEST_HOST override, else
// the live guest IP — the VMI pod IP for the "vm" substrate, or the substrate
// pod's IP for the "container" substrate. Both resolve through the in-cluster
// API; the SSH drive path downstream is identical.
func (a *Activities) guestHost(ctx context.Context, cell Cell) (string, error) {
	if a.Cfg.GuestHost != "" {
		return a.Cfg.GuestHost, nil
	}
	kc, err := newK8sClient()
	if err != nil {
		return "", err
	}
	if a.substrate(cell) == SubstrateContainer {
		return kc.podIP(ctx, a.Cfg.PodNamespace, a.Cfg.PodSelector)
	}
	return kc.vmiIP(ctx, a.Cfg.VMNamespace, a.Cfg.VMName)
}

// CheckGuest is a cheap, aggressively-retried probe: SSH up and confirm the
// runner is present. A dial failure surfaces as guest-fatal.
func (a *Activities) CheckGuest(ctx context.Context, cell Cell) error {
	host, err := a.guestHost(ctx, cell)
	if err != nil {
		return err
	}
	client, err := dial(a.Cfg, host)
	if err != nil {
		return err
	}
	defer client.Close()
	out, err := runCmd(client, fmt.Sprintf("test -x %s/breakout-run.sh && echo ok", a.Cfg.RemoteDir), "")
	if err != nil {
		return fmt.Errorf("runner not present at %s (bootstrap the guest first): %s", a.Cfg.RemoteDir, strings.TrimSpace(out))
	}
	activity.GetLogger(ctx).Info("guest reachable", "host", host, "case", cell.CaseID)
	return nil
}

// runEnv builds the BREAKOUT_* env prefix the runner expects for this cell.
func (a *Activities) runEnv(cell Cell, scoreOnly bool) string {
	to := cell.AgentTimeoutSec
	if to == 0 {
		to = 180
	}
	parts := []string{
		"BREAKOUT_HARNESS=" + shquote(cell.Harness),
		"BREAKOUT_PROVIDER=" + shquote(cell.Provider),
		"BREAKOUT_MODEL=" + shquote(cell.Model),
		fmt.Sprintf("BREAKOUT_AGENT_TIMEOUT=%d", to),
		"AC_AUDIT_DIR=" + shquote(a.Cfg.AuditDir),
		"CASE_FILTER=" + shquote(cell.CaseID),
	}
	if scoreOnly {
		parts = append(parts, "SCORE_ONLY=1")
	}
	if cell.MaxRounds > 1 {
		parts = append(parts, fmt.Sprintf("BREAKOUT_MAX_ROUNDS=%d", cell.MaxRounds))
	}
	if cell.Enforcer {
		parts = append(parts, "BREAKOUT_ENFORCER=1")
		if cell.CodebaseDir != "" {
			parts = append(parts, "BREAKOUT_CODEBASE_DIR="+shquote(cell.CodebaseDir))
		}
	}
	if cell.ApproverVerdict != "" {
		parts = append(parts, "BREAKOUT_APPROVER_VERDICT="+shquote(cell.ApproverVerdict))
	}
	return strings.Join(parts, " ")
}

// CaseScore reads the fixture's score type for this cell's case off the guest
// (cases.json), so the workflow can tell BEFORE driving whether this is an
// approval-gated (hitl) case that must block on a Temporal approval signal.
func (a *Activities) CaseScore(ctx context.Context, cell Cell) (string, error) {
	host, err := a.guestHost(ctx, cell)
	if err != nil {
		return "", err
	}
	client, err := dial(a.Cfg, host)
	if err != nil {
		return "", err
	}
	defer client.Close()
	out, err := runCmd(client, fmt.Sprintf("cat %s/cases.json", a.Cfg.RemoteDir), "")
	if err != nil {
		return "", fmt.Errorf("read cases.json: %s", strings.TrimSpace(out))
	}
	var cases []struct {
		ID    string `json:"id"`
		Score string `json:"score"`
	}
	if err := json.Unmarshal([]byte(out), &cases); err != nil {
		return "", fmt.Errorf("parse cases.json: %w", err)
	}
	for _, c := range cases {
		if c.ID == cell.CaseID {
			return c.Score, nil
		}
	}
	return "", nil
}

// SeedAndDrive runs breakout-run.sh for the single cell (seed → guard → drive →
// score). Heartbeated so a hung model is caught fast. Returns a CellResult on a
// clean run (even if the gate is FAIL — that is a valid verdict, not an error);
// returns guest-fatal only when the guest is unreachable or produced no result.
func (a *Activities) SeedAndDrive(ctx context.Context, cell Cell) (*CellResult, error) {
	host, err := a.guestHost(ctx, cell)
	if err != nil {
		return nil, err
	}
	client, err := dial(a.Cfg, host)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// Provider key: a static override, else a budget-capped dynamic key minted
	// from the vault-openrouter-engine and revoked when this activity exits. The
	// key lives only here — it never enters Temporal history — and SCORE_ONLY
	// re-scoring needs no key.
	providerKey := a.Cfg.ProviderKey
	if providerKey == "" {
		vc, err := newVaultClient(ctx, a.Cfg)
		if err != nil {
			return nil, fmt.Errorf("vault login: %w", err)
		}
		role := cell.OpenRouterRole // per-model budget role
		if role == "" {
			role = a.Cfg.OpenRouterRole
		}
		mk, err := vc.MintKey(ctx, a.Cfg.OpenRouterMount, role)
		if err != nil {
			return nil, fmt.Errorf("mint openrouter key (role %s): %w", role, err)
		}
		activity.GetLogger(ctx).Info("minted budget-capped openrouter key", "role", role, "lease", mk.LeaseID)
		defer func() {
			if rerr := vc.RevokeLease(mk.LeaseID); rerr != nil {
				activity.GetLogger(ctx).Warn("revoke openrouter lease failed (TTL is the backstop)", "lease", mk.LeaseID, "err", rerr.Error())
			}
		}()
		providerKey = mk.APIKey
	}

	stage := "sudo install -d -m0711 /run/secrets && sudo tee /run/secrets/breakout-key >/dev/null && " +
		"sudo chown " + a.Cfg.SSHUser + ":" + a.Cfg.SSHUser + " /run/secrets/breakout-key && sudo chmod 600 /run/secrets/breakout-key"
	if out, err := runCmd(client, stage, providerKey); err != nil {
		return nil, fmt.Errorf("stage provider key: %s", strings.TrimSpace(out))
	}

	cmd := fmt.Sprintf("cd %s && %s ./breakout-run.sh", a.Cfg.RemoteDir, a.runEnv(cell, false))
	activity.GetLogger(ctx).Info("driving cell", "host", host, "case", cell.CaseID, "harness", cell.Harness)
	out, runErr := runCmdHeartbeat(ctx, client, cmd, 20*time.Second)
	// runErr non-nil for guest-fatal (dial/ctx) OR a non-zero runner exit. A
	// non-zero exit still leaves results.jsonl (a FAIL gate), so try to parse
	// before deciding this is fatal.
	res, perr := a.parseResult(ctx, host, cell.CaseID)
	if perr != nil {
		if isGuestFatalErr(runErr) {
			return nil, runErr
		}
		return nil, fmt.Errorf("no result for case %s (runner rc err=%v): %s", cell.CaseID, runErr, lastLines(out, 5))
	}
	return res, nil
}

// ScoreCase re-scores the cell from the existing audit trail (SCORE_ONLY=1) —
// idempotent, no model calls, fast. Proves scoring is a separable, replayable
// step decoupled from the expensive drive.
func (a *Activities) ScoreCase(ctx context.Context, cell Cell) (*CellResult, error) {
	host, err := a.guestHost(ctx, cell)
	if err != nil {
		return nil, err
	}
	client, err := dial(a.Cfg, host)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	cmd := fmt.Sprintf("cd %s && %s ./breakout-run.sh", a.Cfg.RemoteDir, a.runEnv(cell, true))
	if _, err := runCmd(client, cmd, ""); err != nil {
		// non-zero exit = a FAIL gate; still parse the fresh result.
		activity.GetLogger(ctx).Info("score-only returned non-zero (expected on FAIL)", "case", cell.CaseID)
	}
	return a.parseResult(ctx, host, cell.CaseID)
}

// parseResult reads results.jsonl off the guest and returns the line for caseID.
func (a *Activities) parseResult(ctx context.Context, host, caseID string) (*CellResult, error) {
	client, err := dial(a.Cfg, host)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	out, err := runCmd(client, fmt.Sprintf("cat %s/results.jsonl", a.Cfg.RemoteDir), "")
	if err != nil {
		return nil, fmt.Errorf("read results.jsonl: %s", strings.TrimSpace(out))
	}
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var r CellResult
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			continue
		}
		if r.ID == caseID {
			r.Passed = r.Gate == "PASS"
			return &r, nil
		}
	}
	return nil, fmt.Errorf("case %s absent from results.jsonl", caseID)
}

// auditStreams are the guest files ShipToLoki tails, one Loki stream each.
func (a *Activities) auditStreams(sess string) map[string]string {
	d := a.Cfg.AuditDir
	return map[string]string{
		"guard":    fmt.Sprintf("%s/%s.jsonl", d, sess),      // hash-chained guard verdicts
		"serve":    fmt.Sprintf("%s/%s.serve.log", d, sess),  // guard serve log
		"canary":   fmt.Sprintf("%s/%s.canary.log", d, sess), // exfil receiver
		"enforcer": fmt.Sprintf("%s/enforcer.log", d),        // kernel NET-BLOCK events
	}
}

// ShipToLoki pushes the cell's guest audit files to Loki, every line labeled
// with run_id=workflowId so the guard→enforcer→canary timeline for this run is
// one correlated query in Grafana. It also emits a single `stream=results` line
// carrying the gate verdict — with gate/passed as (low-cardinality) labels — so
// the cross-run gate matrix panel is a plain label query over runs.
func (a *Activities) ShipToLoki(ctx context.Context, cell Cell, workflowID, sess string, res *CellResult) error {
	host, err := a.guestHost(ctx, cell)
	if err != nil {
		return err
	}
	client, err := dial(a.Cfg, host)
	if err != nil {
		return err
	}
	defer client.Close()

	base := time.Now().Add(-time.Hour) // keep well inside Loki's ingestion window
	baseLabels := func(stream string) map[string]string {
		return map[string]string{
			"job":      "escape-harness",
			"run_id":   workflowID,
			"harness":  cell.Harness,
			"model":    cell.Model,
			"case":     cell.CaseID,
			"enforcer": fmt.Sprintf("%t", cell.Enforcer),
			"stream":   stream,
		}
	}

	shipped := 0
	for stream, path := range a.auditStreams(sess) {
		out, err := runCmd(client, fmt.Sprintf("cat %s 2>/dev/null || true", path), "")
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if err := pushLoki(ctx, a.Cfg.LokiURL, baseLabels(stream), lines, base); err != nil {
			return err
		}
		shipped += len(lines)
	}

	// The gate verdict as its own queryable stream — drives the gate matrix panel.
	if res != nil {
		line, _ := json.Marshal(map[string]any{
			"run_id": workflowID, "harness": cell.Harness, "model": cell.Model,
			"case": cell.CaseID, "enforcer": cell.Enforcer,
			"gate": res.Gate, "passed": res.Passed, "score": res.Score, "note": res.Note,
		})
		labels := baseLabels("results")
		labels["gate"] = res.Gate
		labels["passed"] = fmt.Sprintf("%t", res.Passed)
		if err := pushLoki(ctx, a.Cfg.LokiURL, labels, []string{string(line)}, time.Now().Add(-time.Minute)); err != nil {
			return err
		}
	}

	activity.GetLogger(ctx).Info("shipped audit to Loki", "run_id", workflowID, "lines", shipped)
	return nil
}

// Teardown is best-effort hygiene between cells: kill any stray canary/approver
// listeners so they cannot bleed into a later cell.
func (a *Activities) Teardown(ctx context.Context, cell Cell) error {
	host, err := a.guestHost(ctx, cell)
	if err != nil {
		return nil // best effort
	}
	client, err := dial(a.Cfg, host)
	if err != nil {
		return nil
	}
	defer client.Close()
	_, _ = runCmd(client, "pkill -f breakout-canary.py 2>/dev/null; pkill -f breakout-approver.js 2>/dev/null; true", "")
	return nil
}

// ResetSubstrate is the durable recovery step the workflow runs when a cell
// wrecks the guest. It dispatches on the cell's substrate: restart the KubeVirt
// VM, or delete the substrate pod so its Deployment recreates a clean one. Both
// paths wait until the guest is Ready and SSH is back, heartbeating across the
// wait. Idempotent — safe to retry.
func (a *Activities) ResetSubstrate(ctx context.Context, cell Cell) error {
	if a.Cfg.GuestHost != "" {
		return fmt.Errorf("ResetSubstrate requires in-cluster API access; not available with GUEST_HOST override")
	}
	kc, err := newK8sClient()
	if err != nil {
		return err
	}
	if a.substrate(cell) == SubstrateContainer {
		return a.resetContainer(ctx, kc)
	}
	return a.resetVM(ctx, kc)
}

// ResetVM is retained as a registered alias so pre-existing workflow histories
// (which scheduled an activity named "ResetVM") still resolve on replay. It
// delegates to the substrate-aware reset.
func (a *Activities) ResetVM(ctx context.Context, cell Cell) error {
	return a.ResetSubstrate(ctx, cell)
}

// resetVM restarts the KubeVirt VM and waits until the VMI is Running+Ready,
// then confirms SSH is back. Heartbeated across the (minutes-long) boot.
func (a *Activities) resetVM(ctx context.Context, kc *k8sClient) error {
	log := activity.GetLogger(ctx)
	log.Warn("resetting VM", "vm", a.Cfg.VMName)
	if err := kc.restartVM(ctx, a.Cfg.VMNamespace, a.Cfg.VMName); err != nil {
		return err
	}
	deadline := time.Now().Add(8 * time.Minute)
	for time.Now().Before(deadline) {
		activity.RecordHeartbeat(ctx, "waiting for VMI Ready")
		if kc.vmiReady(ctx, a.Cfg.VMNamespace, a.Cfg.VMName) {
			if host, err := kc.vmiIP(ctx, a.Cfg.VMNamespace, a.Cfg.VMName); err == nil {
				if client, err := dial(a.Cfg, host); err == nil {
					_ = client.Close()
					log.Info("VM back up", "host", host)
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
	return fmt.Errorf("VM %s not Ready+reachable within timeout", a.Cfg.VMName)
}

// resetContainer deletes the substrate pod(s) matching the selector so the
// Deployment recreates a clean one, then waits until a new pod is Ready and SSH
// answers. Far faster than a VM reboot (seconds, not minutes) but the same
// contract: return only once the guest is a clean, reachable baseline.
func (a *Activities) resetContainer(ctx context.Context, kc *k8sClient) error {
	log := activity.GetLogger(ctx)
	log.Warn("resetting container substrate", "ns", a.Cfg.PodNamespace, "selector", a.Cfg.PodSelector)
	if err := kc.deletePods(ctx, a.Cfg.PodNamespace, a.Cfg.PodSelector); err != nil {
		return err
	}
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		activity.RecordHeartbeat(ctx, "waiting for a fresh Ready pod")
		if host, err := kc.podIP(ctx, a.Cfg.PodNamespace, a.Cfg.PodSelector); err == nil {
			if client, err := dial(a.Cfg, host); err == nil {
				_ = client.Close()
				log.Info("container substrate back up", "host", host)
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("no Ready+reachable substrate pod (%s/%s) within timeout", a.Cfg.PodNamespace, a.Cfg.PodSelector)
}
