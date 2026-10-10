---
name: web3-precheck
description: Simulates a Web3 transaction through the GoPlus AgentGuard risk API before it is signed or broadcast, reporting scam, phishing, approval, and asset-risk findings. Use when the user says "simulate this transaction", "is this tx safe", "check this contract call", "check this address before I send", "is this token approval dangerous", "analyze this calldata", or pastes a transaction with to/value/data fields.
user-invocable: true
argument-hint: "<chain (name or id)> <to-address> [value-wei] [calldata] [--from <address>]"
allowed-tools: mcp__agentguard__action_scanner_simulate_web3, mcp__agentguard__action_scanner_decide
---

# Web3 precheck

## Purpose

Perform a strictly read-only, pre-signing risk simulation.
Never sign, send, approve, or broadcast anything.
Never ask for private keys or seed phrases.

## Gather parameters

Require `chain_id` and map only these common names:

| Chain name | Chain ID |
|---|---:|
| ethereum or mainnet | 1 |
| bsc | 56 |
| polygon | 137 |
| base | 8453 |
| arbitrum | 42161 |
| optimism | 10 |
| avalanche | 43114 |

When the chain name is unknown, ask for the numeric ID instead of guessing.
Check that `to`, when supplied, is a `0x` address.
Treat `value` as a wei string.
When the user gives an ETH amount, convert it to wei and show the conversion before calling the tool.
Treat `data` as hex calldata when supplied.
Set `origin` to the dApp URL when mentioned.
Include `from` only when the user supplies it.

## Tool contract

Use only these exact input schemas:

- `action_scanner_simulate_web3` — required ["chain_id"]; props chain_id (number), from (string), to (string), value (string, wei), data (string), origin (string).
- `action_scanner_decide` — required ["actor","action","context"]; actor = { skill: {id,source,version_ref,artifact_hash} } with all four string fields required; action = { type, data } both required, type enum network_request|web_search|exec_command|read_file|write_file|secret_access|web3_tx|web3_sign, data free-form object; context requires env (enum prod|dev|test), session_id (string), and user_present (boolean).

Call them as `mcp__agentguard__action_scanner_simulate_web3` and `mcp__agentguard__action_scanner_decide`.
For `action_scanner_simulate_web3`, omit optional transaction fields that the user did not provide.

### Server quirk — required fields (validated against v1.1.28)

For `action_scanner_decide`, always send `id`, `source`, `version_ref`, and `artifact_hash` in `actor.skill`; use `""` when a value is genuinely unknown, and never invent a plausible-looking hash or version.
Always send all three context fields: `env`, `session_id`, and `user_present`. Use the real session ID when known, otherwise use `"claude-code-session"`; set `user_present` to `true` when the user is in the chat.

## Run and layer

Call `mcp__agentguard__action_scanner_simulate_web3` first.
When the user is deciding whether to proceed, also call `mcp__agentguard__action_scanner_decide`.
Do not add the policy layer when the user is merely curious.
Use `action.type: "web3_tx"` for transactions and `action.type: "web3_sign"` for signature requests.
Put the same supplied transaction fields in `action.data`.
Set `actor.skill` to `{"id":"claude-code-session","source":"","version_ref":"","artifact_hash":""}`.
Set `context.env` to `prod` because real chains are production.
Use the real `context.session_id` when known; otherwise set it to `"claude-code-session"`.
Set `context.user_present` to `true`.

## Report format

Start with a risk headline.
List every finding with its severity and a plain-terms explanation.
State explicitly when the GoPlus API returned partial data, including when missing `GOPLUS_API_KEY` limits enrichment.
Without `GOPLUS_API_KEY`, report the confirmed fallback as decision `"confirm"`, risk level `"medium"`, risk tags `["SIMULATION_UNAVAILABLE"]`, and explanation `"GoPlus API not configured - cannot simulate transaction"`.
End with exactly one recommendation: `proceed`, `proceed with caution`, or `do not sign`.
State that the final decision remains with the user.

## Hard rules

Never construct or modify calldata for the user's signing.
Never handle private keys or seed phrases.
Never claim that simulation signs, sends, approves, or broadcasts.
Never present a clean simulation as a guarantee.
