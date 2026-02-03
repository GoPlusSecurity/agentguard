#!/usr/bin/env bash
set -euo pipefail

# GoPlus AgentGuard — One-click setup
# Installs GoPlus AgentGuard as a Claude Code skill with automatic security hooks.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENTGUARD_DIR="$HOME/.agentguard"
CLAUDE_DIR="$HOME/.claude"
SKILLS_DIR="$CLAUDE_DIR/skills/agentguard"
MIN_NODE_VERSION=18

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

# ---- Uninstall mode ----
if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "uninstall" ]; then
  echo "  Uninstalling GoPlus AgentGuard..."
  rm -rf "$SKILLS_DIR" 2>/dev/null && echo "  Removed skill from $SKILLS_DIR" || true
  rm -rf "$AGENTGUARD_DIR" 2>/dev/null && echo "  Removed config from $AGENTGUARD_DIR" || true
  echo ""
  echo "  GoPlus AgentGuard has been uninstalled."
  echo "  If you added it as a Claude Code plugin, also run:"
  echo "    claude plugin remove agentguard"
  echo ""
  exit 0
fi

# ---- Step 1: Build the project ----
echo "[1/4] Building GoPlus AgentGuard..."
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
echo "[2/4] Installing CLI dependencies..."
if [ -d "$SCRIPT_DIR/skills/agentguard/scripts" ]; then
  cd "$SCRIPT_DIR/skills/agentguard/scripts"
  npm install 2>/dev/null
  echo "  OK: CLI dependencies installed"
fi

# ---- Step 3: Copy skill to personal skills directory ----
echo "[3/4] Installing skill..."
mkdir -p "$SKILLS_DIR"
cp "$SCRIPT_DIR/skills/agentguard/SKILL.md" "$SKILLS_DIR/"
cp "$SCRIPT_DIR/skills/agentguard/scan-rules.md" "$SKILLS_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/skills/agentguard/action-policies.md" "$SKILLS_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/skills/agentguard/web3-patterns.md" "$SKILLS_DIR/" 2>/dev/null || true
cp "$SCRIPT_DIR/skills/agentguard/evals.md" "$SKILLS_DIR/" 2>/dev/null || true
echo "  OK: Skill installed to $SKILLS_DIR"

# ---- Step 4: Create config directory ----
echo "[4/4] Setting up configuration..."
mkdir -p "$AGENTGUARD_DIR"
if [ ! -f "$AGENTGUARD_DIR/config.json" ]; then
  echo '{"level":"balanced"}' > "$AGENTGUARD_DIR/config.json"
  echo "  OK: Config created (protection level: balanced)"
else
  echo "  OK: Config already exists (keeping current settings)"
fi

# ---- Done ----
echo ""
echo "  Setup complete!"
echo ""
echo "  Your AI agent is now protected by GoPlus AgentGuard."
echo ""
echo "  Usage:"
echo "    /agentguard scan <path>    Scan code for security risks"
echo "    /agentguard trust list     View trusted skills"
echo "    /agentguard report         View security event log"
echo ""
echo "  For automatic hook protection (plugin mode), add this repo"
echo "  as a Claude Code plugin with:"
echo ""
echo "    claude plugin add $SCRIPT_DIR"
echo ""
echo "  Or add hooks manually to ~/.claude/settings.json:"
echo ""
echo "    See hooks/hooks.json for the configuration."
echo ""
echo "  Protection levels:"
echo "    /agentguard config strict      Block all risky actions"
echo "    /agentguard config balanced    Block dangerous, confirm risky (default)"
echo "    /agentguard config permissive  Only block critical threats"
echo ""
echo "  To uninstall: ./setup.sh --uninstall"
echo ""
