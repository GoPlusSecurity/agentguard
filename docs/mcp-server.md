# MCP Server Setup

GoPlus AgentGuard can run as an MCP (Model Context Protocol) server, providing security tools to any MCP-compatible AI agent.

## Configuration

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "npx",
      "args": ["-y", "@goplus/agentguard"],
      "env": {
        "GOPLUS_API_KEY": "your_key",
        "GOPLUS_API_SECRET": "your_secret"
      }
    }
  }
}
```

GoPlus API keys are optional — the scanner and registry work without them. They enable enhanced Web3 security features.

## Available Tools

| Tool | Description |
|------|-------------|
| `skill_scanner_scan` | Scan a directory for security risks |
| `registry_lookup` | Look up a skill's trust level |
| `registry_attest` | Register a skill with a trust level |
| `registry_revoke` | Revoke a skill's trust |
| `registry_list` | List all registered skills |
| `action_scanner_decide` | Evaluate an action's safety |
| `action_scanner_simulate_web3` | Simulate a Web3 transaction |
