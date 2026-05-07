# iFlytek Skillhub Review Fixes

This note records the iFlytek Skillhub review feedback for the AgentGuard skill package and the channel-specific fixes made on this branch. Keep it as a merge-conflict reference when bringing new work from `main`.

## Review Feedback

iFlytek rejected the submitted `agentguard` skill package because the published skill bundle still contained platform entry points and external resources that should not appear in this channel package:

- `skills/agentguard/README.md`: described publishing the report to X, Telegram, and WhatsApp.
- `skills/agentguard/scripts/checkup-report.js`: included X, Telegram, and WhatsApp share buttons and outbound jump links.
- `skills/agentguard/scripts/checkup-report.js`: loaded Google Fonts from `fonts.googleapis.com`.
- `skills/agentguard/SKILL.md`: retained Claude and Telegram related paths, delivery wording, and platform-specific instructions.
- `skills/agentguard/scripts/guard-hook.js`: retained Claude platform naming and adapter references in the packaged hook script.

The requested remediation was to remove X, Telegram, and WhatsApp share/notification entries and jump links, replace or localize Google font resources, and clean up Claude/Telegram platform naming, paths, and adaptation notes before resubmission.

## Scope Decision

Only files explicitly mentioned by the review are changed for this iFlytek channel branch:

- `skills/agentguard/README.md`
- `skills/agentguard/SKILL.md`
- `skills/agentguard/scripts/checkup-report.js`
- `skills/agentguard/scripts/guard-hook.js`

Do not expand the channel cleanup to unrelated rule/reference docs unless iFlytek specifically asks for them. For example, `scan-rules.md`, `action-policies.md`, and `patrol-checks.md` may still mention suspicious webhook domains as security detection content in the general product.

## Concrete Changes

### `skills/agentguard/README.md`

- Replaced the X/Telegram/WhatsApp sharing sentence with local export wording.
- The report is now described as providing a downloadable summary image.

### `skills/agentguard/SKILL.md`

- Removed the `~/.claude/` filesystem access entry.
- Removed Claude-specific skill discovery and credential scan paths from the checkup workflow.
- Reworded runtime protection checks to use OpenClaw/QClaw paths.
- Replaced Telegram/Discord/WhatsApp delivery wording with generic supported-platform file delivery wording.
- Replaced Claude-specific channel names with generic local desktop / web artifact / API-headless wording.
- Removed the Claude Code auto-scan enablement instruction.

### `skills/agentguard/scripts/checkup-report.js`

- Removed X, Telegram, and WhatsApp share buttons.
- Removed outbound share links to `x.com`, `t.me`, and `wa.me`.
- Removed social share copy generation that existed only for those platform buttons.
- Removed Twitter meta tags.
- Removed Google Fonts and Material Symbols imports from `fonts.googleapis.com`.
- Switched report typography to system font stacks.
- Kept local report image actions: download and copy to clipboard.
- Cleaned comments that included the reviewed platform naming.

### `skills/agentguard/scripts/guard-hook.js`

- Reworded comments and helper labels from Claude-specific naming to host/platform-neutral wording.
- Avoided direct Claude adapter symbol text in the packaged script while preserving runtime behavior through dynamic property lookup.

## Merge Guidance

When merging new work from `main`, preserve these iFlytek-channel constraints in the four scoped files:

- Do not reintroduce X, Telegram, or WhatsApp report sharing UI.
- Do not reintroduce outbound share URLs for `x.com`, `t.me`, or `wa.me`.
- Do not load fonts from `fonts.googleapis.com` in the skill report HTML.
- Do not reintroduce Claude or `.claude` paths/instructions in `skills/agentguard/SKILL.md`.
- Do not reintroduce Telegram/WhatsApp delivery wording or `sendDocument` instructions.
- Keep `scripts/guard-hook.js` comments/platform wording neutral for this channel package.

Recommended post-merge checks:

```bash
rg -n "Telegram|telegram|WhatsApp|whatsapp|https://x\\.com|https://t\\.me|https://wa\\.me|fonts\\.googleapis|Claude|claude|\\.claude|sendDocument|twitter" \
  skills/agentguard/README.md \
  skills/agentguard/SKILL.md \
  skills/agentguard/scripts/checkup-report.js \
  skills/agentguard/scripts/guard-hook.js

node --check skills/agentguard/scripts/checkup-report.js
node --check skills/agentguard/scripts/guard-hook.js
```

The `rg` command should return no matches for the four scoped files.
