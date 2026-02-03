# GuardSkills

Security skill for AI agents - scan, registry, and action control.

## Overview

GuardSkills provides three core security modules for AI agents:

1. **Skill Scanner** - Static analysis of skill code to detect security risks
2. **Skill Registry** - Trust level and capability management for skills
3. **Action Scanner** - Runtime action decision engine with Web3 support

## Installation

```bash
npm install guardskills
```

Or install globally to use as MCP server:

```bash
npm install -g guardskills
```

## Quick Start

### As MCP Server

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "guardskills": {
      "command": "npx",
      "args": ["-y", "guardskills"]
    }
  }
}
```

With GoPlus API for Web3 security (recommended):

```json
{
  "mcpServers": {
    "guardskills": {
      "command": "npx",
      "args": ["-y", "guardskills"],
      "env": {
        "GOPLUS_API_KEY": "your_api_key",
        "GOPLUS_API_SECRET": "your_api_secret"
      }
    }
  }
}
```

### As SDK

```typescript
import { createGuardSkills } from 'guardskills';

const { scanner, registry, actionScanner } = createGuardSkills();

// Scan a skill
const scanResult = await scanner.scan({
  skill: {
    id: 'my-skill',
    source: 'github.com/org/my-skill',
    version_ref: 'v1.0.0',
    artifact_hash: 'sha256:abc...',
  },
  payload: { type: 'dir', ref: '/path/to/skill' },
});

console.log(scanResult.risk_level); // 'low' | 'medium' | 'high' | 'critical'
console.log(scanResult.risk_tags);  // ['SHELL_EXEC', 'READ_ENV_SECRETS', ...]
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `skill_scanner_scan` | Scan skill code for security risks |
| `registry_lookup` | Look up skill trust record |
| `registry_attest` | Add/update skill trust record |
| `registry_revoke` | Revoke skill trust |
| `registry_list` | List trust records |
| `action_scanner_decide` | Evaluate runtime action |
| `action_scanner_simulate_web3` | Simulate Web3 transaction |

## Security Rules

### Detection Categories

- **Execution Risks**: SHELL_EXEC, REMOTE_LOADER, AUTO_UPDATE
- **Secret Access**: READ_ENV_SECRETS, READ_SSH_KEYS, READ_KEYCHAIN
- **Data Exfiltration**: NET_EXFIL_UNRESTRICTED, WEBHOOK_EXFIL
- **Code Obfuscation**: OBFUSCATION
- **Prompt Injection**: PROMPT_INJECTION
- **Web3 Specific**: PRIVATE_KEY_PATTERN, MNEMONIC_PATTERN, WALLET_DRAINING, UNLIMITED_APPROVAL

### Trust Levels

| Level | Description |
|-------|-------------|
| `untrusted` | Default, requires full review |
| `restricted` | Trusted with capability limits |
| `trusted` | Full trust (still subject to global policies) |

### Capability Model

```typescript
interface CapabilityModel {
  network_allowlist: string[];     // Allowed domains
  filesystem_allowlist: string[];  // Allowed file paths
  exec: 'allow' | 'deny';          // Command execution
  secrets_allowlist: string[];     // Allowed secrets
  web3?: {
    chains_allowlist: number[];    // Allowed chain IDs
    rpc_allowlist: string[];       // Allowed RPC endpoints
    tx_policy: 'allow' | 'confirm_high_risk' | 'deny';
  };
}
```

## External Scanner Integration

GuardSkills can use [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) for enhanced detection when installed:

```bash
pip install cisco-ai-skill-scanner
```

The skill-scanner provides:
- YAML + YARA pattern matching
- Python AST dataflow analysis
- LLM-powered semantic analysis
- VirusTotal integration

## GoPlus Integration

For Web3 security features, configure GoPlus API:

```bash
export GOPLUS_API_KEY=your_key
export GOPLUS_API_SECRET=your_secret
```

Features enabled:
- Token security analysis
- Malicious address detection
- Transaction simulation
- Phishing site detection
- Approval risk analysis

Get API keys at: https://gopluslabs.io/security-api

## API Reference

### SkillScanner

```typescript
class SkillScanner {
  async scan(payload: ScanPayload): Promise<ScanResult>;
  async quickScan(dirPath: string): Promise<QuickScanResult>;
  async calculateArtifactHash(dirPath: string): Promise<string>;
}
```

### SkillRegistry

```typescript
class SkillRegistry {
  async lookup(skill: SkillIdentity): Promise<LookupResult>;
  async attest(request: AttestRequest): Promise<AttestResult>;
  async forceAttest(request: AttestRequest): Promise<AttestResult>;
  async revoke(match: RevokeMatch, reason: string): Promise<number>;
  async list(filters?: ListFilters): Promise<TrustRecord[]>;
}
```

### ActionScanner

```typescript
class ActionScanner {
  async decide(envelope: ActionEnvelope): Promise<PolicyDecision>;
  async simulateWeb3(intent: Web3Intent): Promise<Web3SimulationResult>;
}
```

## Default Policies

```typescript
const DEFAULT_POLICIES = {
  secret_exfil: {
    private_key: 'deny',    // Always block
    mnemonic: 'deny',       // Always block
    api_secret: 'confirm',  // Require confirmation
  },
  exec_command: 'deny',     // Default deny
  web3: {
    unlimited_approval: 'confirm',
    unknown_spender: 'confirm',
    user_not_present: 'confirm',
  },
  network: {
    untrusted_domain: 'confirm',
    body_contains_secret: 'deny',
  },
};
```

## License

MIT

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
