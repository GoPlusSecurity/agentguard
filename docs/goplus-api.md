# GoPlus API Integration

GoPlus AgentGuard optionally integrates with the [GoPlus Security API](https://gopluslabs.io/security-api) for enhanced Web3 security.

## Setup

```bash
export GOPLUS_API_KEY=your_key
export GOPLUS_API_SECRET=your_secret
```

Get keys at: https://gopluslabs.io/security-api

## What It Adds

Without GoPlus API, AgentGuard uses local pattern matching for Web3 security (unlimited approvals, reentrancy, selfdestruct, etc.).

With GoPlus API, you get additional capabilities:

- **Token Security**: Check if a token is a honeypot, has a tax, or has other risks
- **Address Security**: Check if an address is associated with phishing, scams, or malicious activity
- **Transaction Simulation**: Simulate a transaction to see its effects before execution
- **Approval Security**: Check for risky token approvals
- **dApp Security**: Verify the safety of decentralized applications

## Graceful Degradation

If the GoPlus API is unavailable or keys are not configured, AgentGuard falls back to local-only analysis. No functionality is lost — you just get fewer Web3-specific insights.

## External Scanner

GoPlus AgentGuard also integrates with [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) for additional scanning capabilities:

```bash
pip install cisco-ai-skill-scanner
```

This adds YAML/YARA pattern scanning, Python AST analysis, and VirusTotal integration.
