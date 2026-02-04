# GuardSkills

Security framework for AI agents. Provides code scanning, runtime action evaluation, and trust management.

## Skill

This project provides a unified Claude Code skill: `/guardskills`

```
/guardskills scan <path>          — Scan code for security risks (20 detection rules)
/guardskills action <description> — Evaluate runtime action safety (allow/deny/confirm)
/guardskills trust <subcommand>   — Manage skill trust levels (lookup/attest/revoke/list)
```

## Project Structure

- `skills/guardskills/` — Claude Code skill definition and supporting files
- `src/` — TypeScript source (scanner rules, registry, action detectors, MCP server)
- `data/` — Registry storage (`registry.json`)
- `dist/` — Compiled JavaScript output

## Setup for Trust & Action CLI

The `trust` and `action` subcommands use CLI scripts that require the guardskills package:

```bash
cd skills/guardskills/scripts && npm install
```

For GoPlus API (optional Web3 enhancement for action evaluation):

```bash
export GOPLUS_API_KEY=your_key
export GOPLUS_API_SECRET=your_secret
```
