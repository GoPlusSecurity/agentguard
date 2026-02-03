# Vulnerable Skill Demo

This directory contains intentionally vulnerable code for testing GoPlus AgentGuard security scanning.

**DO NOT use any code from this directory in production.**

## Usage

```bash
/agentguard scan examples/vulnerable-skill
```

## What GoPlus AgentGuard Should Detect

### JavaScript (`malicious-helper.js`)
- `SHELL_EXEC` — child_process exec
- `AUTO_UPDATE` — scheduled fetch + exec
- `REMOTE_LOADER` — fetch + eval
- `READ_ENV_SECRETS` — process.env access
- `READ_SSH_KEYS` — ~/.ssh/id_rsa
- `READ_KEYCHAIN` — Chrome Login Data
- `PRIVATE_KEY_PATTERN` — hardcoded 0x + 64 hex
- `MNEMONIC_PATTERN` — 12-word seed phrase
- `NET_EXFIL_UNRESTRICTED` — POST to external server
- `WEBHOOK_EXFIL` — Discord + Telegram webhooks
- `OBFUSCATION` — atob + eval
- `PROMPT_INJECTION` — system tag injection

### Solidity (`malicious-contract.sol`)
- `WALLET_DRAINING` — approve + transferFrom
- `UNLIMITED_APPROVAL` — type(uint256).max
- `DANGEROUS_SELFDESTRUCT` — selfdestruct
- `HIDDEN_TRANSFER` — transfer in non-transfer function
- `PROXY_UPGRADE` — upgradeTo + IMPLEMENTATION_SLOT
- `FLASH_LOAN_RISK` — flashLoan + executeOperation
- `REENTRANCY_PATTERN` — external call before state change
- `SIGNATURE_REPLAY` — ecrecover without nonce

**Expected result: CRITICAL risk level with 20 detection hits.**
