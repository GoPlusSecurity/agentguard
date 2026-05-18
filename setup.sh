#!/usr/bin/env bash
set -euo pipefail

# GoPlus AgentGuard — One-click setup
# Supports: Claude Code, OpenClaw, ClawHub
# Detects the platform and installs to the correct location.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_SRC="$SCRIPT_DIR/skills/agentguard"
AGENTGUARD_DIR="$HOME/.agentguard"
MIN_NODE_VERSION=18
OPENCLAW_ROOT="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
OPENCLAW_PLUGIN_DIR="$OPENCLAW_ROOT/plugins/agentguard"
OPENCLAW_CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$OPENCLAW_ROOT/openclaw.json}"

echo ""
echo "  GoPlus AgentGuard — AI Agent Security Guard"
echo "  ============================================="
echo ""

# ---- Pre-check: Node.js ----
if ! command -v node &>/dev/null; then
  echo "  ERROR: Node.js is not installed."
  echo "  GoPlus AgentGuard requires Node.js >= $MIN_NODE_VERSION."
  echo "  Install from: https://nodejs.org"
  exit 1
fi

NODE_MAJOR=$(node -e "console.log(process.versions.node.split('.')[0])")
if [ "$NODE_MAJOR" -lt "$MIN_NODE_VERSION" ]; then
  echo "  ERROR: Node.js v$(node -v) is too old."
  echo "  GoPlus AgentGuard requires Node.js >= $MIN_NODE_VERSION."
  echo "  Install from: https://nodejs.org"
  exit 1
fi

if ! command -v npm &>/dev/null; then
  echo "  ERROR: npm is not installed."
  exit 1
fi

# ---- Detect platform ----
detect_platform() {
  # Check OpenClaw first (workspace skills or managed skills)
  if [ -d "$HOME/.openclaw" ]; then
    # Prefer workspace skills if workspace exists
    if [ -d "$HOME/.openclaw/workspace" ]; then
      SKILLS_DIR="$HOME/.openclaw/workspace/skills/agentguard"
      PLATFORM="openclaw-workspace"
    else
      SKILLS_DIR="$HOME/.openclaw/skills/agentguard"
      PLATFORM="openclaw-managed"
    fi
    return
  fi

  # Check Claude Code
  if [ -d "$HOME/.claude" ]; then
    SKILLS_DIR="$HOME/.claude/skills/agentguard"
    PLATFORM="claude-code"
    return
  fi

  # Fallback: create Claude Code dir (most common)
  SKILLS_DIR="$HOME/.claude/skills/agentguard"
  PLATFORM="claude-code"
}

detect_platform
echo "  Platform detected: $PLATFORM"
echo "  Install target:    $SKILLS_DIR"
echo ""

# ---- Uninstall mode ----
if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "uninstall" ]; then
  echo "  Uninstalling GoPlus AgentGuard..."
  rm -rf "$SKILLS_DIR" 2>/dev/null && echo "  Removed skill from $SKILLS_DIR" || true
  # Also clean up other possible locations
  rm -rf "$HOME/.claude/skills/agentguard" 2>/dev/null || true
  rm -rf "$HOME/.openclaw/skills/agentguard" 2>/dev/null || true
  rm -rf "$HOME/.openclaw/workspace/skills/agentguard" 2>/dev/null || true
  rm -rf "$OPENCLAW_PLUGIN_DIR" 2>/dev/null || true
  rm -rf "$AGENTGUARD_DIR" 2>/dev/null && echo "  Removed config from $AGENTGUARD_DIR" || true
  echo ""
  echo "  GoPlus AgentGuard has been uninstalled."
  echo ""
  exit 0
fi

# ---- Step 1: Build the project ----
echo "[1/5] Building GoPlus AgentGuard..."
if [ -f "$SCRIPT_DIR/package.json" ]; then
  cd "$SCRIPT_DIR"
  npm install --ignore-scripts 2>/dev/null
  npm run build 2>/dev/null
  echo "  OK: Build complete"
else
  echo "  ERROR: package.json not found. Run this script from the agentguard root."
  exit 1
fi

# ---- Step 2: Install CLI dependencies ----
echo "[2/5] Installing CLI dependencies..."
if [ -d "$SKILL_SRC/scripts" ]; then
  cd "$SKILL_SRC/scripts"
  npm install 2>/dev/null
  echo "  OK: CLI dependencies installed"
fi

# ---- Step 3: Copy skill files ----
echo "[3/5] Installing skill files..."
mkdir -p "$SKILLS_DIR"
for f in SKILL.md README.md scan-rules.md action-policies.md web3-patterns.md evals.md patrol-checks.md .clawignore; do
  [ -f "$SKILL_SRC/$f" ] && cp "$SKILL_SRC/$f" "$SKILLS_DIR/" 2>/dev/null || true
done
echo "  OK: Skill files installed"

# ---- Step 4: Copy scripts + node_modules ----
echo "[4/5] Installing scripts and dependencies..."
mkdir -p "$SKILLS_DIR/scripts"

# Copy script files
for f in checkup-report.js guard-hook.js auto-scan.js trust-cli.ts action-cli.ts package.json package-lock.json; do
  [ -f "$SKILL_SRC/scripts/$f" ] && cp "$SKILL_SRC/scripts/$f" "$SKILLS_DIR/scripts/" 2>/dev/null || true
done

# Copy data directory
if [ -d "$SKILL_SRC/scripts/data" ]; then
  mkdir -p "$SKILLS_DIR/scripts/data"
  cp -r "$SKILL_SRC/scripts/data/"* "$SKILLS_DIR/scripts/data/" 2>/dev/null || true
fi

# Install node_modules in the target (avoids symlink issues in containers)
cd "$SKILLS_DIR/scripts"
if [ -f "package.json" ]; then
  npm install 2>/dev/null
  echo "  OK: Scripts and dependencies installed"
else
  echo "  WARN: No package.json found in scripts directory"
fi

# ---- Step 5: Create config directory ----
echo "[5/5] Setting up configuration..."
mkdir -p "$AGENTGUARD_DIR"
if [ ! -f "$AGENTGUARD_DIR/config.json" ]; then
  echo '{"level":"balanced"}' > "$AGENTGUARD_DIR/config.json"
  echo "  OK: Config created (protection level: balanced)"
else
  echo "  OK: Config already exists (keeping current settings)"
fi

if [ "$PLATFORM" = "openclaw-workspace" ] || [ "$PLATFORM" = "openclaw-managed" ]; then
  echo "  Enabling OpenClaw plugin..."
  mkdir -p "$OPENCLAW_PLUGIN_DIR"
  AGENTGUARD_DIST_INDEX="$SCRIPT_DIR/dist/index.js" node - "$OPENCLAW_PLUGIN_DIR/index.js" <<'NODE'
const { writeFileSync } = require('node:fs');
const pluginPath = process.argv[2];
const distIndex = process.env.AGENTGUARD_DIST_INDEX;
writeFileSync(pluginPath, `const { registerOpenClawPlugin } = require(${JSON.stringify(distIndex)});

module.exports = function setup(api) {
  registerOpenClawPlugin(api, {
    skipAutoScan: false,
  });
};
module.exports.default = module.exports;
`);
NODE
  cat > "$OPENCLAW_PLUGIN_DIR/openclaw.plugin.json" <<'JSON'
{
  "id": "agentguard",
  "name": "GoPlus AgentGuard",
  "description": "AI agent security framework — blocks dangerous commands, prevents data leaks, and protects secrets",
  "configSchema": {
    "type": "object",
    "properties": {
      "level": {
        "type": "string",
        "enum": ["strict", "balanced", "permissive"],
        "default": "balanced",
        "description": "Protection level: strict (block all risky), balanced (block dangerous, confirm risky), permissive (only block critical)"
      }
    }
  }
}
JSON
  node - "$OPENCLAW_CONFIG_PATH" "$OPENCLAW_PLUGIN_DIR" <<'NODE'
const { existsSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { dirname } = require('node:path');
const [configPath, pluginDir] = process.argv.slice(2);
const ensureRecord = (parent, key) => {
  const existing = parent[key];
  if (existing && typeof existing === 'object' && !Array.isArray(existing)) return existing;
  const next = {};
  parent[key] = next;
  return next;
};
let config = {};
if (existsSync(configPath)) {
  const raw = readFileSync(configPath, 'utf8').trim();
  config = raw ? JSON.parse(raw) : {};
}
const plugins = ensureRecord(config, 'plugins');
const load = ensureRecord(plugins, 'load');
const entries = ensureRecord(plugins, 'entries');
const agentguard = ensureRecord(entries, 'agentguard');
agentguard.enabled = true;
const paths = Array.isArray(load.paths) ? load.paths.filter((p) => typeof p === 'string') : [];
if (!paths.includes(pluginDir)) paths.push(pluginDir);
load.paths = paths;
if (Array.isArray(plugins.allow)) {
  const allow = plugins.allow.filter((id) => typeof id === 'string');
  if (!allow.includes('agentguard')) allow.push('agentguard');
  plugins.allow = allow;
}
mkdirSync(dirname(configPath), { recursive: true });
writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
NODE
  echo "  OK: OpenClaw plugin enabled in $OPENCLAW_CONFIG_PATH"
fi

# ---- Done ----
echo ""
echo "  ✅ GoPlus AgentGuard is installed!"
echo ""
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🦞 NEXT STEP: Run your first security checkup"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
if [ "$PLATFORM" = "claude-code" ]; then
  echo "  Open Claude Code and type:"
else
  echo "  Send your OpenClaw bot:"
fi
echo ""
echo "    /agentguard checkup"
echo ""
echo "  This will:"
echo "    • Scan all your installed skills for threats"
echo "    • Check credentials, permissions & network exposure"
echo "    • Generate a full HTML security report"
echo "    • Deliver the report directly to you"
echo ""
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Installed to: $SKILLS_DIR"
echo "  Platform:     $PLATFORM"
echo ""
echo "  Other commands:"
echo "    /agentguard scan <path>    Scan code for security risks"
echo "    /agentguard trust list     View trusted skills"
echo "    /agentguard report         View security event log"
echo ""
echo "  To uninstall: ./setup.sh --uninstall"
echo ""
