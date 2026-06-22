#!/usr/bin/env bash
#
# build-mcpb.sh — reproducibly build the AgentGuard .mcpb (MCP Bundle / Desktop Extension).
#
# Output: dist-mcpb/agentguard.mcpb
#
# Bundle layout produced (matches what the MCP Directory expects):
#   manifest.json          <- from mcpb/manifest.json, version stamped from package.json
#   icon.png               <- from mcpb/icon.png (512x512)
#   server/
#     dist/                <- compiled TypeScript runtime output
#     node_modules/        <- production dependencies only
#     package.json
#     package-lock.json
#     README.md
#     LICENSE
#
# Optional env:
#   EXPECTED_VERSION  When set (e.g. from a release tag), the build fails unless it
#                     matches package.json — guards against publishing a .mcpb under
#                     the wrong version. The release workflow passes the git tag here.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(node -p "require('./package.json').version")"
MANIFEST_VERSION="$(jq -r '.version' mcpb/manifest.json)"
STAGE="$ROOT/build/mcpb"
OUT_DIR="$ROOT/dist-mcpb"
OUT="$OUT_DIR/agentguard.mcpb"
MCPB="$ROOT/node_modules/.bin/mcpb"

echo "==> Building AgentGuard .mcpb v$VERSION"

# 0. Version consistency — package.json, source manifest, and (if given) the release tag
#    must all agree before we publish anything.
if [ "$MANIFEST_VERSION" != "$VERSION" ]; then
  echo "ERROR: mcpb/manifest.json version ($MANIFEST_VERSION) != package.json version ($VERSION)." >&2
  echo "       Update mcpb/manifest.json to match before building." >&2
  exit 1
fi
if [ -n "${EXPECTED_VERSION:-}" ] && [ "${EXPECTED_VERSION#v}" != "$VERSION" ]; then
  echo "ERROR: release tag version (${EXPECTED_VERSION#v}) != package.json version ($VERSION)." >&2
  echo "       Tag, package.json, and manifest must all match before releasing." >&2
  exit 1
fi

# 1. Clean install + compile. Ignore lifecycle scripts here so release builds
#    cannot mutate user/runner AgentGuard config via postinstall.
npm ci --ignore-scripts
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

# Keep the desktop extension runtime-only: tests, type declarations, and source
# maps are useful in npm/source builds but should not ship in the installed MCPB.
rm -rf "$STAGE/server/dist/tests"
find "$STAGE/server/dist" -type f \( -name '*.map' -o -name '*.d.ts' \) -delete

# 5. Production dependencies only
( cd "$STAGE/server" && npm ci --omit=dev --ignore-scripts )

# 6. Pack with the pinned mcpb CLI (exact version in devDependencies — reproducible,
#    no @latest drift). npm ci above installed it into node_modules/.bin.
"$MCPB" pack "$STAGE" "$OUT"

# 7. Integrity check — fail if the archive contains anything outside the allowlist,
#    so stray build artifacts or unexpected files can never ship in a release.
ALLOWED='^(manifest\.json|icon\.png|server/dist/|server/node_modules/|server/package\.json|server/package-lock\.json|server/README\.md|server/LICENSE)'
UNEXPECTED="$(unzip -Z1 "$OUT" | grep -v '/$' | grep -vE "$ALLOWED" || true)"
if [ -n "$UNEXPECTED" ]; then
  echo "ERROR: unexpected files in bundle (not on allowlist):" >&2
  echo "$UNEXPECTED" >&2
  exit 1
fi

DISALLOWED='^server/dist/tests/|^server/dist/.*(\.map|\.d\.ts)$'
DISALLOWED_FILES="$(unzip -Z1 "$OUT" | grep -v '/$' | grep -E "$DISALLOWED" || true)"
if [ -n "$DISALLOWED_FILES" ]; then
  echo "ERROR: non-runtime TypeScript artifacts in bundle:" >&2
  echo "$DISALLOWED_FILES" >&2
  exit 1
fi

echo "==> Built $OUT (contents verified against allowlist)"
