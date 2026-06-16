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

When staging findings with `record_finding`, use `supporting_commands` for provenance:

```json
{
  "audit_ids": [],
  "supporting_commands": [
    {
      "command": "fls -r /cases/e2e-demo/evidence-raw/ewf1",
      "purpose": "Explain why this command supports the finding",
      "output_excerpt": "Paste the relevant raw output excerpt"
    }
  ]
}
```

The proxy returns `audit_ids` in tool responses, but the gateway backend lifecycle does not persist those IDs into the case audit directory. `record_finding` cross-validates audit IDs against that directory and will reject them. Use `audit_ids: []` with `supporting_commands`; this produces `provenance_grade: PARTIAL`.

This is expected. It is not an evidence gap. The proxy's own hash-chained audit trail, verified later with `agentcontainer audit verify <session>-proxy`, independently records every tool call with correlation IDs.

## Self-Correction

If a tool call is denied by OPA policy, read the structured denial. It includes blocked flags and allowed alternatives. Correct the arguments and retry.

If `record_finding` rejects an `audit_id`, switch to the `supporting_commands` path with `audit_ids: []`.

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
