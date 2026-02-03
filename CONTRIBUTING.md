# Contributing to GoPlus AgentGuard

Thanks for your interest in contributing to GoPlus AgentGuard! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cd agentguard
npm install
npm run build
npm test
```

## Project Structure

- `src/` — TypeScript source code
  - `scanner/` — Static analysis engine (20 detection rules)
  - `action/` — Runtime action evaluator (exec, network, file, web3 detectors)
  - `registry/` — Trust level management
  - `policy/` — Default policies and capability presets
  - `tests/` — Test suite (Node.js built-in test runner)
- `skills/agentguard/` — Claude Code skill definition (SKILL.md + reference docs)
- `hooks/` — Plugin hooks configuration for auto-guard
- `examples/` — Demo projects for testing

## Making Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Make your changes
4. Run `npm run build && npm test` to verify
5. Submit a pull request

## Adding Detection Rules

New scan rules go in `src/scanner/rules/`. Each rule needs:
- A unique `id` (e.g., `MY_NEW_RULE`)
- `severity`: `low` | `medium` | `high` | `critical`
- `pattern`: regex to match against file content
- `fileTypes`: array of extensions to scan (e.g., `['.js', '.ts']`)

Export the rule from the appropriate category file and add it to the `ALL_RULES` array in `src/scanner/rules/index.ts`.

## Adding Action Detectors

Action detectors go in `src/action/detectors/`. They evaluate runtime actions and return risk assessments with tags.

## Code Style

- TypeScript strict mode
- Zod for runtime validation
- Minimal dependencies (currently 5 production deps)
- Node.js built-in test runner (no test framework needed)

## Reporting Issues

Please open an issue at https://github.com/GoPlusSecurity/agentguard/issues with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Your Node.js version and OS
