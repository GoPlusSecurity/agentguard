# MCP Server

AgentGuard still ships an MCP server for hosts that prefer MCP tools over hooks.

## Run

```bash
npx -y --package @goplus/agentguard agentguard-mcp
```

If installed globally:

```bash
agentguard-mcp
```

## Configure

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "agentguard-mcp"
    }
  }
}
```

## Tools

- `skill_scanner_scan`
- `registry_lookup`
- `registry_attest`
- `registry_revoke`
- `registry_list`
- `action_scanner_decide`
- `action_scanner_simulate_web3`

For live action blocking, prefer `agentguard protect` hooks. MCP is best for agent-invoked scans, trust registry operations, and Web3 simulation.
