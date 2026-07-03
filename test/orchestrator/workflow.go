package main

import (
	"errors"
	"strings"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

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
		if attempt >= maxCellAttempts || !isGuestFatalErr(err) {
			return nil, err
		}
		log.Warn("drive guest-fatal; resetting VM before retry", "attempt", attempt, "err", err.Error())
		resetCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 10 * time.Minute,
			HeartbeatTimeout:    60 * time.Second,
			RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 2},
		})
		if rerr := workflow.ExecuteActivity(resetCtx, a.ResetVM, cell).Get(ctx, nil); rerr != nil {
			return nil, rerr
		}
	}

	// 3. Idempotent re-score from the audit trail (decoupled from the drive).
	shortCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 3 * time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	if err := workflow.ExecuteActivity(shortCtx, a.ScoreCase, cell).Get(ctx, &res); err != nil {
		return nil, err
	}

	// 4. Ship the guest audit streams to Loki, correlated by workflow id.
	if err := workflow.ExecuteActivity(shortCtx, a.ShipToLoki, cell, info.WorkflowExecution.ID, res.Session).Get(ctx, nil); err != nil {
		log.Warn("shipToLoki failed (non-fatal)", "err", err.Error())
	}

	// 5. Best-effort teardown.
	_ = workflow.ExecuteActivity(shortCtx, a.Teardown, cell).Get(ctx, nil)

	log.Info("cell complete", "case", cell.CaseID, "gate", res.Gate, "passed", res.Passed)
	return res, nil
}
