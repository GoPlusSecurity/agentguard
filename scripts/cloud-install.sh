#!/usr/bin/env bash
set -euo pipefail

# AgentGuard Cloud bootstrap template.
#
# The hosting endpoint may render the defaults below from validated query
# parameters, or callers may provide the same values as environment variables.
# AGENTGUARD_AGENT is optional: when absent, `agentguard init` discovers every
# supported local agent. Keep credentials out of this script and its URL.

PACKAGE_SPEC="${AGENTGUARD_PACKAGE_SPEC:-@goplus/agentguard}"
CLOUD_URL="${AGENTGUARD_CLOUD_URL:-https://agentguard.gopluslabs.io}"
AGENT="${AGENTGUARD_AGENT:-}"

case "$AGENT" in
  ''|auto|openclaw|hermes|dsh) ;;
  *)
    echo 'ERROR: activation-link bootstrap supports auto, openclaw, hermes, or dsh.' >&2
    echo 'Use the AgentGuard CLI with an API key for other agent hosts.' >&2
    exit 2
    ;;
esac

if ! command -v node >/dev/null 2>&1; then
  echo 'ERROR: Node.js is required to install AgentGuard.' >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo 'ERROR: npm is required to install AgentGuard.' >&2
  exit 1
fi

echo "Installing ${PACKAGE_SPEC}..."
npm install -g "$PACKAGE_SPEC"

if ! command -v agentguard >/dev/null 2>&1; then
  echo 'ERROR: npm completed, but the agentguard command is not on PATH.' >&2
  exit 1
fi

if [ -n "$AGENT" ] && [ "$AGENT" != 'auto' ]; then
  agentguard init --agent "$AGENT" --cloud "$CLOUD_URL"
else
  agentguard init --cloud "$CLOUD_URL"
fi

CONNECT_OUTPUT="$(agentguard connect --cloud "$CLOUD_URL")"
printf '%s\n' "$CONNECT_OUTPUT"

if [ "${DSH_SHELL:-}" = '1' ] || [ "$AGENT" = 'dsh' ]; then
  echo 'Restart DSH after account binding to activate AgentGuard in the web profile.'
fi

ACTIVATION_URL="$(printf '%s\n' "$CONNECT_OUTPUT" | awk '/^https:\/\/[^[:space:]]+$/ { url=$0 } END { print url }')"
if [ -n "$ACTIVATION_URL" ]; then
  printf 'AGENTGUARD_ACTIVATION_URL=%s\n' "$ACTIVATION_URL"
fi
