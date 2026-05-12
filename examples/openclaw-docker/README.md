# OpenClaw Docker Demo

This demo shows the minimal AgentGuard runtime wiring for OpenClaw.

```bash
docker compose build
docker compose run --rm agentguard-openclaw-demo
```

In a real OpenClaw workspace, register `plugin.ts` as a plugin. It uses `registerOpenClawPlugin` to scan loaded skills/plugins and evaluate runtime tool calls before execution.

For Cloud policy and audit sync:

```bash
AGENTGUARD_API_KEY=ag_live_xxxxx agentguard connect --url https://agentguard.gopluslabs.io
```
