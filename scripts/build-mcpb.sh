#!/usr/bin/env bash
#
# build-mcpb.sh — reproducibly build the AgentGuard .mcpb (MCP Bundle / Desktop Extension).
#
# Output: dist-mcpb/agentguard-<version>.mcpb
#
# Bundle layout produced (matches what the MCP Directory expects):
#   manifest.json          <- from mcpb/manifest.json, version stamped from package.json
#   icon.png               <- from mcpb/icon.png (256x256)
#   server/
#     dist/                <- compiled TypeScript (tsc output)
#     node_modules/        <- production dependencies only
#     package.json
#     package-lock.json
#     README.md
#     LICENSE
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(node -p "require('./package.json').version")"
STAGE="$ROOT/build/mcpb"
OUT_DIR="$ROOT/dist-mcpb"
OUT="$OUT_DIR/agentguard-$VERSION.mcpb"

echo "==> Building AgentGuard .mcpb v$VERSION"

# 1. Clean install + compile
npm ci
npm run build

# 2. Fresh staging tree
rm -rf "$STAGE"
mkdir -p "$STAGE/server" "$OUT_DIR"

# 3. Bundle root: manifest (version-stamped) + icon
jq --arg v "$VERSION" '.version = $v' mcpb/manifest.json > "$STAGE/manifest.json"
cp mcpb/icon.png "$STAGE/icon.png"

# 4. server/ payload
cp -R dist "$STAGE/server/dist"
cp README.md LICENSE package.json package-lock.json "$STAGE/server/"

# 5. Production dependencies only
( cd "$STAGE/server" && npm ci --omit=dev --ignore-scripts )

# 6. Pack with the official mcpb CLI (pinned latest so manifest_version 0.3 is supported)
npx --yes @anthropic-ai/mcpb@latest pack "$STAGE" "$OUT"

echo "==> Built $OUT"
