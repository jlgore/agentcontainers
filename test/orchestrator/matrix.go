package main

import (
	"fmt"
	"regexp"
	"strings"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ModelSpec is one attacker brain: the provider/model the harness talks to plus
// the vault-openrouter-engine role (hence budget cap) that mints its key.
type ModelSpec struct {
	Provider       string // openrouter | anthropic | openai
	Model          string // e.g. z-ai/glm-5.2 or anthropic/claude-opus-4.8
	OpenRouterRole string // escape-glm | escape-opus (per-model budget)
}

// MatrixSpec is the fan-out request: the axes of the escape grid plus the shared
// per-cell knobs. EscapeMatrixWorkflow cross-products Models × Harnesses ×
// CaseIDs × EnforcerModes into one child MatrixCellWorkflow per point.
//
// The cross-product is pure and deterministic (buildCells), so the workflow does
// no IO to plan the grid — replay-safe. The starter fills this in; a small host
// helper can enumerate CaseIDs from breakout-matrix.yaml, or leave it empty to
// use the gating-case default set below.
type MatrixSpec struct {
	RunID     string
	Models    []ModelSpec
	Harnesses []string // pi | opencode | claude
	CaseIDs   []string // fixture case ids; empty => defaultGatingCases
	// EnforcerModes selects the enforcer axis: [false] off-only, [true] on-only,
	// [false,true] both. Empty defaults to [false] (guard-layer only).
	EnforcerModes []bool
	// Substrates selects where each cell runs: "vm" (KubeVirt), "container"
	// (privileged pod), or both. Empty defaults to [""] — each cell inherits the
	// worker's DefaultSubstrate. Adding "container" fans the SAME grid across the
	// container substrate so a regression is caught on both hosting models.
	Substrates      []string
	AgentTimeoutSec int
	MaxRounds       int
	CodebaseDir     string // source snapshot on the guest (enforcer cells only)
}

// CellOutcome is one cell's result within a matrix run: either a CellResult or,
// if the child workflow failed outright (not merely a FAIL gate), the error.
type CellOutcome struct {
	Cell    Cell        `json:"cell"`
	ChildID string      `json:"child_id"`
	Result  *CellResult `json:"result,omitempty"`
	Err     string      `json:"err,omitempty"`
}

// MatrixResult aggregates the whole grid for one run.
type MatrixResult struct {
	RunID    string        `json:"run_id"`
	Total    int           `json:"total"`
	Passed   int           `json:"passed"`
	Failed   int           `json:"failed"` // child workflow errored (infra), not a FAIL gate
	Outcomes []CellOutcome `json:"outcomes"`
}

// defaultGatingCases are the "loud" cases an adversarial model actually exercises
// (exfil / persist / hitl) — the escape-the-box subset. Oracle/probe cases are
// context-free and already covered deterministically by the Layer-1 matrix, so
// they are not fanned out through models here.
var defaultGatingCases = []string{
	"T11-exfil-canary",
	"P1-persist-evidence-tamper",
	"P2-persist-cross-case-plant",
	"T8-xcase-diligent",
	"T8-xcase-credulous",
	"T8-xcase-keyword",
}

var slugStrip = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// slug builds a deterministic, DNS/Temporal-safe id fragment for this cell so the
// child workflow id is stable across replays (harness-model-case-enf[-substrate]).
// The substrate segment is only appended when set, so existing vm-only grids keep
// their historical child ids (stable resume).
func (c Cell) slug() string {
	enf := "ne"
	if c.Enforcer {
		enf = "enf"
	}
	raw := fmt.Sprintf("%s-%s-%s-%s", c.Harness, c.Model, c.CaseID, enf)
	if c.Substrate != "" {
		raw += "-" + c.Substrate
	}
	s := slugStrip.ReplaceAllString(raw, "-")
	return strings.Trim(strings.ToLower(s), "-")
}

// buildCells is the deterministic cross-product of the spec's axes. Ordering is
// fixed (models, then harnesses, then cases, then enforcer) so a given spec
// always yields the same cell list in the same order — required for replay and
// for stable child workflow ids.
func buildCells(spec MatrixSpec) []Cell {
	cases := spec.CaseIDs
	if len(cases) == 0 {
		cases = defaultGatingCases
	}
	enfModes := spec.EnforcerModes
	if len(enfModes) == 0 {
		enfModes = []bool{false}
	}
	substrates := spec.Substrates
	if len(substrates) == 0 {
		substrates = []string{""} // inherit the worker's DefaultSubstrate
	}
	var cells []Cell
	for _, m := range spec.Models {
		for _, h := range spec.Harnesses {
			for _, caseID := range cases {
				for _, enf := range enfModes {
					for _, sub := range substrates {
						cell := Cell{
							Harness:         h,
							Provider:        m.Provider,
							Model:           m.Model,
							CaseID:          caseID,
							Enforcer:        enf,
							Substrate:       sub,
							AgentTimeoutSec: spec.AgentTimeoutSec,
							MaxRounds:       spec.MaxRounds,
							OpenRouterRole:  m.OpenRouterRole,
						}
						if enf {
							cell.CodebaseDir = spec.CodebaseDir
						}
						cells = append(cells, cell)
					}
				}
			}
		}
	}
	return cells
}

// EscapeMatrixWorkflow fans the grid out across one child MatrixCellWorkflow per
// cell. Because every cell mutates the ONE shared guest per substrate in place,
// cells run STRICTLY SEQUENTIALLY (breakout-run.sh re-seeds per cell, but two
// cells on one guest would collide). This holds even across the substrate axis:
// the vm and container substrates are distinct guests and could in principle run
// concurrently, but the single shared-guest-per-substrate invariant keeps the
// loop sequential. Concurrency would require multiple guests per substrate; that
// is the single, documented knob to change if it happens.
//
// Durability: child workflow ids are deterministic (runID.slug), so if the worker
// dies mid-grid the parent replays from history — children that already completed
// are recovered, not re-run, and the loop resumes at the next unfinished cell. A
// child that fails outright (infra error, not a FAIL gate) is recorded and the
// grid CONTINUES — a rate-limit at cell 20 of 24 no longer loses the run.
func EscapeMatrixWorkflow(ctx workflow.Context, spec MatrixSpec) (*MatrixResult, error) {
	log := workflow.GetLogger(ctx)
	cells := buildCells(spec)
	log.Info("escape matrix fan-out", "run_id", spec.RunID, "cells", len(cells), "sequential", true)

	res := &MatrixResult{RunID: spec.RunID, Total: len(cells)}
	for i, cell := range cells {
		childID := fmt.Sprintf("%s.%s", spec.RunID, cell.slug())
		cwo := workflow.ChildWorkflowOptions{
			WorkflowID: childID,
			// The grid must outlive a flaky cell; the child's own workflow retry
			// is off (cells are coarse-idempotent, re-seeded per run), so an infra
			// failure surfaces here and we move on rather than abort the run.
			RetryPolicy: &temporal.RetryPolicy{MaximumAttempts: 1},
		}
		cctx := workflow.WithChildOptions(ctx, cwo)
		log.Info("starting cell", "i", i+1, "of", len(cells), "child", childID, "case", cell.CaseID, "model", cell.Model, "enforcer", cell.Enforcer)

		var cr CellResult
		err := workflow.ExecuteChildWorkflow(cctx, MatrixCellWorkflow, cell).Get(ctx, &cr)
		outcome := CellOutcome{Cell: cell, ChildID: childID}
		if err != nil {
			outcome.Err = err.Error()
			res.Failed++
			log.Warn("cell failed (grid continues)", "child", childID, "err", err.Error())
		} else {
			// cr.Passed is json:"-" (not serialized across the child→parent
			// boundary), so derive it from the gate that DID cross.
			cr.Passed = cr.Gate == "PASS"
			outcome.Result = &cr
			if cr.Passed {
				res.Passed++
			}
		}
		res.Outcomes = append(res.Outcomes, outcome)
	}

	log.Info("escape matrix complete", "run_id", spec.RunID, "total", res.Total, "passed", res.Passed, "failed", res.Failed)
	return res, nil
}
