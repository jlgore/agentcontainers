# Forensic E2E Investigation Context

This case has two separate tool paths:

- Forensic MCP tools: 49 tools exposed through the sift proxy. These run inside an enforced gateway container where evidence is mounted read-only.
- Claude's native tools: Bash, Write, Edit, MultiEdit, and related file tools. These are gated by the agentcontainer guard hook using OPA policy and human-in-the-loop approval.

All evidence-touching operations MUST go through the forensic MCP `run_command` tool. Never use raw Bash, `ls`, `stat`, Python, or local filesystem commands against evidence paths.

## Evidence Paths

The case root is `/cases/e2e-demo`.

Inside the gateway container, the raw disk image is:

```text
/cases/e2e-demo/evidence-raw/ewf1
```

That path does not exist on the host. It is a bind mount from `.ewfraw` to `evidence-raw:ro`. Never `ls` or `stat` evidence paths locally; they only exist inside the gateway container.

The image is a logical NTFS volume with no partition table. Use filesystem tools directly:

- `fsstat`
- `fls`
- `istat`
- `icat`

Do not use `mmls` for this image.

## Recording Findings

Cite the `audit_id` from each MCP tool response that produced your evidence. They
persist to the case audit trail (`<case>/audit/*.jsonl`) and `record_finding`
validates them there, so this is the primary, full-provenance path. Put
`audit_ids` inside the `finding` dict:

```json
{
  "title": "...",
  "type": "finding",
  "observation": "...",
  "interpretation": "...",
  "confidence": "HIGH",
  "confidence_justification": "...",
  "event_timestamp": "2012-04-06T13:43:21Z",
  "audit_ids": ["sift-jgore-20260406-001"]
}
```

For richer provenance, also pass the top-level `artifacts` parameter — each
`{source, extraction, content, audit_id}`.

Use `supporting_commands` (a top-level parameter, list of
`{command, purpose, output_excerpt}`) ONLY for shell evidence that did not come
through an MCP tool, so there is no `audit_id` to cite. That path yields
`provenance_grade: PARTIAL` — prefer real `audit_ids` whenever the evidence came
from a forensic MCP tool.

The proxy also keeps its own hash-chained audit trail, verified later with
`agentcontainer audit verify <session>-proxy`, recording every tool call with
correlation IDs.

## Self-Correction

If a tool call is denied by OPA policy, read the structured denial. It includes blocked flags and allowed alternatives. Correct the arguments and retry.

If `record_finding` rejects an `audit_id` as "not found in audit trail", that's an
infrastructure misconfiguration, not a normal case: the gateway's `VHIR_AUDIT_DIR`
must point at `<case>/audit` (where `run_command` writes and `record_finding`
reads). Flag it to the examiner rather than silently downgrading to
`supporting_commands`.

## Forensic Critic

After staging each finding with `record_finding`, spawn the `forensic-critic` subagent to adversarially verify it. The critic uses:

- `evidence_chain`
- `corroboration_map`
- `temporal_neighbors`

The critic checks each claim against raw tool output. Act on its verdict: fix the finding, downgrade confidence, or withdraw the finding.

## Audit Verification

After the investigation, the examiner runs this on the host:

```bash
agentcontainer audit verify <session>-proxy
```

That verifies the proxy hash chain is unbroken. Every finding must trace back through that chain.
