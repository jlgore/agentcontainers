# 1Password Secrets Provider

Demonstrates secret injection using 1Password via the `1password` provider. Secrets are referenced with structured `vault` / `item` / `field` fields, read from 1Password vaults on the host, and injected into the container at `/run/secrets/`.

## Prerequisites

- [1Password desktop app](https://1password.com/downloads) (v8+) with CLI integration enabled
- `op` CLI ([install guide](https://developer.1password.com/docs/cli/get-started/))
- `ac` CLI

## Quick Start

```bash
# 1. Verify 1Password CLI is working
op whoami

# 2. Create the referenced items in 1Password (if they don't exist)
#    See "Setting Up Vault Items" below

# 3. Run the agent container
ac run --config agentcontainer.json .
```

## Secrets in This Example

| Secret | Vault | Item | Field | TTL | Description |
|--------|-------|------|-------|-----|-------------|
| `GITHUB_TOKEN` | `Development` | `GitHub PAT` | `credential` | 1h | GitHub personal access token |
| `NPM_TOKEN` | `Development` | `npm Registry` | `token` | 4h | npm publish token |
| `DATABASE_URL` | `Development` | `Staging DB` | `connection-string` | 1h | Database connection string |

## Setting Up Vault Items

Create the referenced items in your 1Password vault:

```bash
# Create a vault for development secrets (if needed)
op vault create "Development"

# Create GitHub PAT item
op item create \
  --vault "Development" \
  --category login \
  --title "GitHub PAT" \
  'credential=ghp_your_token_here'

# Create npm registry item
op item create \
  --vault "Development" \
  --category login \
  --title "npm Registry" \
  'token=npm_your_token_here'

# Create database item
op item create \
  --vault "Development" \
  --category "Database" \
  --title "Staging DB" \
  'connection-string=postgresql://user:pass@host:5432/dbname'
```

## How It Works

1. `agentcontainer run` reads the `secrets` block from `agentcontainer.json`
2. The Secrets Manager invokes `op read` on the **host** for each secret, using the configured `vault`/`item`/`field`
3. 1Password desktop app prompts for biometric/2FA approval
4. Resolved values are written to `/run/secrets/<NAME>` (tmpfs, mode 0400)
5. The `op` CLI never runs inside the container
6. On session end, tmpfs is unmounted and secrets are zeroed

## Per-Tool Scoping

The `allowedTools` field restricts which MCP servers can read a secret:

- `GITHUB_TOKEN` is only visible to the `mcp-github` MCP server
- `DATABASE_URL` is only visible to the `mcp-postgres` MCP server
- `NPM_TOKEN` has no restriction (available to all tools)

## Production Notes

- Use 1Password Connect Server for headless/CI environments (no biometric prompt)
- Rotate tokens in 1Password regularly — the agent always reads the latest value
- Enable 1Password's audit log for compliance visibility
