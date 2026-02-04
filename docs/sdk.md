# SDK Usage

Use GoPlus AgentGuard as a library in your own project.

## Installation

```bash
npm install @goplus/agentguard
```

## Quick Start

```typescript
import { createAgentGuard } from '@goplus/agentguard';

const { scanner, registry, actionScanner } = createAgentGuard();
```

## Scan Code

```typescript
const result = await scanner.scan({
  skill: {
    id: 'my-skill',
    source: 'github.com/org/skill',
    version_ref: 'v1.0.0',
    artifact_hash: '',
  },
  payload: { type: 'dir', ref: '/path/to/skill' },
});

console.log(result.risk_level); // 'low' | 'medium' | 'high' | 'critical'
console.log(result.hits);       // Array of detection rule matches
```

## Evaluate Actions

```typescript
const decision = await actionScanner.decide({
  actor: {
    skill: { id: 'my-skill', source: 'cli', version_ref: '1.0.0', artifact_hash: '' },
  },
  action: {
    type: 'exec_command',
    data: { command: 'rm -rf /' },
  },
  context: {
    session_id: 's1',
    user_present: true,
    env: 'prod',
    time: new Date().toISOString(),
  },
});

console.log(decision.decision); // 'allow' | 'deny' | 'confirm'
```

## Trust Registry

```typescript
// Register a skill
await registry.attest({
  skill: { id: 'bot', source: 'github.com/org/bot', version_ref: 'v1.0.0', artifact_hash: 'sha256:abc' },
  trust_level: 'trusted',
  capabilities: { network_allowlist: ['api.example.com'], filesystem_allowlist: [], exec: 'deny', secrets_allowlist: [] },
  review: { reviewed_by: 'admin', evidence_refs: [], notes: 'Verified safe' },
});

// Look up
const result = await registry.lookup({
  id: 'bot', source: 'github.com/org/bot', version_ref: 'v1.0.0', artifact_hash: 'sha256:abc',
});
console.log(result.effective_trust_level); // 'trusted'
```

## API Reference

See the TypeScript types exported from `@goplus/agentguard` for full API details:

- `SkillScanner` — Static analysis engine
- `SkillRegistry` — Trust level management
- `ActionScanner` — Runtime action evaluator
- `CAPABILITY_PRESETS` — Predefined capability sets (none, read_only, trading_bot, defi)
