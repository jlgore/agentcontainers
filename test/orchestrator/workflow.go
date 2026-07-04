package main

import (
	"errors"
	"strings"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// byEffectScore marks the case score types whose verdict is a LIVE property of
// the drive (kernel NET-BLOCK count, canary bytes, realized filesystem effect) —
// not a pure function of persisted audit files. These cannot be re-derived by a
// SCORE_ONLY re-run, so the workflow keeps the drive's result for them.
var byEffectScore = map[string]bool{
	"exfil":   true,
	"persist": true,
	"hitl":    true,
}

// isGuestFatalErr reports whether err (possibly wrapped by the SDK) originated as
// a guestFatal — i.e. the guest is unreachable/broken and a VM reset is the right
// recovery, versus an ordinary failed command.
func isGuestFatalErr(err error) bool {
	if err == nil {
		return false
	}
	var gf guestFatal
	if errors.As(err, &gf) {
		return true
	}
	// Across the activity boundary the concrete type is lost; the SDK preserves
	// the message in an ApplicationError. Match our marker prefix.
	var appErr *temporal.ApplicationError
	if errors.As(err, &appErr) {
		return strings.Contains(appErr.Error(), "guest-fatal")
	}
	return strings.Contains(err.Error(), "guest-fatal")
}

// isHeartbeatTimeout reports whether err is an activity HEARTBEAT timeout — i.e.
// the worker running the drive stopped heartbeating (pod evicted/killed, crash,
// or network partition) rather than the drive genuinely running over its budget.
// That is an infra interruption, not a real verdict, so it is recoverable the
// same way a guest-fatal is: reset the VM and retry the cell. A START_TO_CLOSE
// timeout (the drive really did run too long) is deliberately NOT matched here —
// re-driving it would only re-burn the model budget for the same over-run.
func isHeartbeatTimeout(err error) bool {
	if err == nil {
		return false
	}
	var te *temporal.TimeoutError
	if errors.As(err, &te) {
		return te.TimeoutType() == enumspb.TIMEOUT_TYPE_HEARTBEAT
	}
	return false
}

// ApprovalVerdict is the payload of the "approval" signal for a HITL cell.
type ApprovalVerdict struct {
	Approve bool   `json:"approve"`
	Reason  string `json:"reason"`
}

// awaitApproval blocks the workflow on the "approval" signal and returns the
// honored decision as "allow" or "deny". A human (or scripted approver) sends it:
//
//	temporal workflow signal --workflow-id <cell> --name approval --input '{"approve":false}'
//
// A 10-minute timer bounds the wait and defaults to deny (fail-closed), so the
// workflow stays deterministic and never hangs forever if no approver responds.
func awaitApproval(ctx workflow.Context) string {
	log := workflow.GetLogger(ctx)
	ch := workflow.GetSignalChannel(ctx, "approval")
	timer := workflow.NewTimer(ctx, 10*time.Minute)

	var v ApprovalVerdict
	got := false
	sel := workflow.NewSelector(ctx)
	sel.AddReceive(ch, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, &v); got = true })
	sel.AddFuture(timer, func(workflow.Future) {})
	log.Info("HITL: blocking on 'approval' signal (10m timeout → default deny)")
	sel.Select(ctx)

	if !got {
		log.Warn("HITL: approval timed out — defaulting to deny (fail-closed)")
		return "deny"
	}
	if v.Approve {
		return "allow"
	}
	return "deny"
}

// MatrixCellWorkflow runs one escape-matrix cell end to end with durable
// recovery. The workflow is deterministic: all IO lives in the activities; the
// only control flow is the reset-and-retry loop.
func MatrixCellWorkflow(ctx workflow.Context, cell Cell) (*CellResult, error) {
	log := workflow.GetLogger(ctx)
	info := workflow.GetInfo(ctx)
	var a *Activities

	// 1. Connectivity gate — cheap, aggressively retried over flaky SSH.
	checkCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval: 2 * time.Second,
			MaximumInterval: 20 * time.Second,
			MaximumAttempts: 10,
		},
	})
	if err := workflow.ExecuteActivity(checkCtx, a.CheckGuest, cell).Get(ctx, nil); err != nil {
		return nil, err
	}

	// 1.5 HITL seam: for approval-gated (score:hitl) cases, block on the Temporal
	//     "approval" signal BEFORE driving, so the honored verdict comes from a human
	//     (or scripted approver) via `temporal workflow signal`, not a baked persona.
	//     CaseScore reads the fixture score off the guest; non-hitl cells skip this.
	caseCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 3 * time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	var score string
	if err := workflow.ExecuteActivity(caseCtx, a.CaseScore, cell).Get(ctx, &score); err != nil {
		return nil, err
	}
	if score == "hitl" {
		cell.ApproverVerdict = awaitApproval(ctx)
		log.Info("HITL approval honored", "case", cell.CaseID, "verdict", cell.ApproverVerdict)
	}

	// 2. Drive the cell, with VM-reset-as-recovery between attempts. The drive
	//    activity itself does not auto-retry (MaximumAttempts:1) because a guest
	//    fatal needs a reset first — orchestrated here, not by the retry policy.
	agentTO := cell.AgentTimeoutSec
	if agentTO == 0 {
		agentTO = 180
	}
	rounds := cell.MaxRounds
	if rounds < 1 {
		rounds = 1
	}
	driveTO := time.Duration(agentTO*rounds)*time.Second + 5*time.Minute
	driveCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: driveTO,
		HeartbeatTimeout:    45 * time.Second,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})

	var res *CellResult
	const maxCellAttempts = 2
	for attempt := 1; ; attempt++ {
		err := workflow.ExecuteActivity(driveCtx, a.SeedAndDrive, cell).Get(ctx, &res)
		if err == nil {
			break
		}
		// Recover-and-retry on infra interruptions — a guest-fatal (SSH unreachable)
		// OR a heartbeat timeout (the worker running the drive was evicted/killed
		// mid-cell). Both leave the guest in an unknown state, so reset the VM to a
		// clean baseline and re-drive. Any other error (a clean FAIL gate, or a genuine
		// start-to-close over-run) is terminal — we do not re-burn the budget for it.
		guestFatal := isGuestFatalErr(err)
		if attempt >= maxCellAttempts || !(guestFatal || isHeartbeatTimeout(err)) {
			return nil, err
		}
		cause := "guest-fatal"
		if !guestFatal {
			cause = "heartbeat-timeout (worker eviction/stall)"
		}
		log.Warn("drive interrupted; resetting VM before retry", "cause", cause, "attempt", attempt, "err", err.Error())
		resetCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 10 * time.Minute,
			HeartbeatTimeout:    60 * time.Second,
			RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
		})
		if rerr := workflow.ExecuteActivity(resetCtx, a.ResetVM, cell).Get(ctx, nil); rerr != nil {
			return nil, rerr
		}
	}

	// 3. Re-score. For pure-from-audit cases (oracle/state/audit/probe) the verdict
	//    is a function of persisted files, so a SCORE_ONLY re-run proves scoring is
	//    a separable, replayable step. For BY-EFFECT gating cases (exfil/persist/
	//    hitl) the metric — kernel NET-BLOCK count, canary bytes, realized fs effect
	//    — is a live property of the DRIVE and cannot be re-derived after the fact;
	//    re-scoring there only undercounts, so the drive's result stays authoritative.
	shortCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 3 * time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	if byEffectScore[res.Score] {
		log.Info("by-effect case: keeping drive result (re-score cannot re-derive live effect)", "case", cell.CaseID, "score", res.Score)
	} else {
		if err := workflow.ExecuteActivity(shortCtx, a.ScoreCase, cell).Get(ctx, &res); err != nil {
			return nil, err
		}
	}

	// 4. Ship the guest audit streams to Loki, correlated by workflow id.
	if err := workflow.ExecuteActivity(shortCtx, a.ShipToLoki, cell, info.WorkflowExecution.ID, res.Session, res).Get(ctx, nil); err != nil {
		log.Warn("shipToLoki failed (non-fatal)", "err", err.Error())
	}

	// 5. Best-effort teardown.
	_ = workflow.ExecuteActivity(shortCtx, a.Teardown, cell).Get(ctx, nil)

	log.Info("cell complete", "case", cell.CaseID, "gate", res.Gate, "passed", res.Passed)
	return res, nil
}
