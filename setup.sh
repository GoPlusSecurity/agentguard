#!/usr/bin/env bash
set -euo pipefail

# GoPlus AgentGuard — One-click setup
# Supports: Claude Code, OpenClaw, ClawHub
# Detects the platform and installs to the correct location.
#
# Flags:
#   --shared              Use shared node_modules to reduce disk usage in
#                         multi-agent environments. node_modules is installed
#                         once at AGENTGUARD_SHARED_DIR (default:
#                         ~/.agentguard/shared/scripts) and each agent's
#                         scripts/node_modules becomes a symlink to it.
#   --shared-dir <path>   Override the shared node_modules location.
#                         Equivalent to setting AGENTGUARD_SHARED_DIR.
#   --uninstall           Remove the installed skill and config directory.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_SRC="$SCRIPT_DIR/skills/agentguard"
AGENTGUARD_DIR="$HOME/.agentguard"
MIN_NODE_VERSION=18

# ---- Parse flags ----
SHARED_MODE=false
# Allow env var override; --shared-dir flag takes precedence below
SHARED_DIR="${AGENTGUARD_SHARED_DIR:-$HOME/.agentguard/shared/scripts}"

_args=("$@")
for ((i=0; i<${#_args[@]}; i++)); do
  case "${_args[$i]}" in
    --shared) SHARED_MODE=true ;;
    --shared-dir)
      SHARED_MODE=true
      SHARED_DIR="${_args[$((i+1))]:-$SHARED_DIR}"
      ;;
  esac
done

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
# ---- Uninstall mode ----
if [ "${1:-}" = "--uninstall" ] || [ "${1:-}" = "uninstall" ]; then
  echo "  Uninstalling GoPlus AgentGuard..."
  rm -rf "$SKILLS_DIR" 2>/dev/null && echo "  Removed skill from $SKILLS_DIR" || true
  # Also clean up other possible locations
  rm -rf "$HOME/.claude/skills/agentguard" 2>/dev/null || true
  rm -rf "$HOME/.openclaw/skills/agentguard" 2>/dev/null || true
  rm -rf "$HOME/.openclaw/workspace/skills/agentguard" 2>/dev/null || true
  rm -rf "$AGENTGUARD_DIR" 2>/dev/null && echo "  Removed config from $AGENTGUARD_DIR" || true
  # Remove shared node_modules only if explicitly requested
  if [ "$SHARED_MODE" = "true" ]; then
    rm -rf "$SHARED_DIR" 2>/dev/null && echo "  Removed shared deps from $SHARED_DIR" || true
  fi
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

if [ "$SHARED_MODE" = "true" ]; then
  # Shared mode: install node_modules once to the shared dir, then symlink
  echo "  Shared mode: node_modules -> $SHARED_DIR/node_modules"
  mkdir -p "$SHARED_DIR"

  # Copy package files to shared dir if not already present or outdated
  cp "$SKILL_SRC/scripts/package.json" "$SHARED_DIR/package.json" 2>/dev/null || true
  cp "$SKILL_SRC/scripts/package-lock.json" "$SHARED_DIR/package-lock.json" 2>/dev/null || true

  # Install once in the shared dir
  cd "$SHARED_DIR"
  if [ -f "package.json" ]; then
    npm install 2>/dev/null
    echo "  OK: Shared node_modules installed at $SHARED_DIR"
  fi

  # Replace any existing node_modules in the skill dir with a symlink
  rm -rf "$SKILLS_DIR/scripts/node_modules"
  ln -s "$SHARED_DIR/node_modules" "$SKILLS_DIR/scripts/node_modules"
  echo "  OK: Symlinked scripts/node_modules -> $SHARED_DIR/node_modules"
else
  # Default mode: install node_modules directly in the target (container-safe)
  cd "$SKILLS_DIR/scripts"
  if [ -f "package.json" ]; then
    npm install 2>/dev/null
    echo "  OK: Scripts and dependencies installed"
  else
    echo "  WARN: No package.json found in scripts directory"
  fi
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
if [ "$SHARED_MODE" = "true" ]; then
  echo "  Shared deps:  $SHARED_DIR/node_modules"
fi
echo ""
echo "  Other commands:"
echo "    /agentguard scan <path>    Scan code for security risks"
echo "    /agentguard trust list     View trusted skills"
echo "    /agentguard report         View security event log"
echo ""
echo "  To uninstall: ./setup.sh --uninstall"
echo "  Shared mode:  ./setup.sh --shared  (saves ~67MB per extra agent)"
echo ""
