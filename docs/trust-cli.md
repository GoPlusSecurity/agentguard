# Trust Management

GoPlus AgentGuard includes a trust registry for managing skill permissions.

## Commands

### Attest (Register a Skill)

```
/agentguard trust attest --id my-bot --source github.com/org/bot --version v1.0.0 --hash abc --trust-level restricted --preset trading_bot --reviewed-by admin
```

### Lookup

```
/agentguard trust lookup --source github.com/org/bot
```

### Revoke

```
/agentguard trust revoke --source github.com/org/bot --reason "security concern"
```

### List

```
/agentguard trust list --trust-level trusted
```

## Trust Levels

| Level | Description |
|-------|-------------|
| `trusted` | Full access per its capability model |
| `restricted` | Limited access, some actions require confirmation |
| `untrusted` | Minimal access, most actions blocked or require confirmation |

## Capability Presets

| Preset | Network | Filesystem | Exec | Secrets | Web3 |
|--------|---------|------------|------|---------|------|
| `none` | No | No | No | No | No |
| `read_only` | No | Read `./**` | No | No | No |
| `trading_bot` | Binance, Bybit, OKX, Coinbase, Dextools, CoinGecko | `./config/**`, `./logs/**` | No | `*_API_KEY`, `*_API_SECRET` | Chains 1, 56, 137, 42161 |
| `defi` | All | No | No | No | Chains 1, 56, 137, 42161, 10, 8453, 43114 |

## Auto-Scan on Session Start

When installed as a Claude Code plugin, AgentGuard automatically scans new skills on session start:

- Discovers skills in `~/.claude/skills/`
- Calculates artifact hash and checks the registry
- Runs `quickScan` on new or updated skills
- Auto-registers with trust level based on scan results:
  - Low risk → `trusted`
  - Medium risk → `restricted`
  - High/Critical risk → `untrusted`
