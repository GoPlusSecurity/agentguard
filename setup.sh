#!/usr/bin/env bash
set -euo pipefail

# GoPlus AgentGuard — One-click setup
# Supports: Claude Code, OpenClaw, ClawHub
# Auto-detects the agent platform; use --target or --scope for custom paths.
#
# Usage:
#   ./setup.sh                              Auto-detect platform
#   ./setup.sh --target <path>              Install to <path>/agentguard
#   ./setup.sh --scope user                 Install to ~/.openclaw/skills/agentguard
#   ./setup.sh --scope project <name>       Install to ~/.openclaw-<name>/skills/agentguard
#   ./setup.sh --scope agent <name>         Install to ~/.openclaw-<name>/skills/agentguard
#   ./setup.sh --uninstall                  Remove installed skill

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_SRC="$SCRIPT_DIR/skills/agentguard"
AGENTGUARD_DIR="$HOME/.agentguard"
MIN_NODE_VERSION=18

# ---- Parse arguments ----
TARGET_DIR=""
SCOPE_TYPE=""
SCOPE_NAME=""
UNINSTALL=false
POSITIONAL=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET_DIR="${2:-}"
      [ -z "$TARGET_DIR" ] && { echo "  ERROR: --target requires a path argument."; exit 1; }
      shift 2
      ;;
    --scope)
      SCOPE_TYPE="${2:-}"
      case "$SCOPE_TYPE" in
        user) shift 2 ;;
        project|agent)
          SCOPE_NAME="${3:-}"
          [ -z "$SCOPE_NAME" ] && { echo "  ERROR: --scope $SCOPE_TYPE requires a name argument."; exit 1; }
          shift 3
          ;;
        *) echo "  ERROR: --scope must be one of: user, project, agent"; exit 1 ;;
      esac
      ;;
    --uninstall|uninstall) UNINSTALL=true; shift ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

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
  # --target overrides all detection
  if [ -n "$TARGET_DIR" ]; then
    # Expand leading ~ manually (eval is unsafe with user input)
    case "$TARGET_DIR" in
      "~/"*) TARGET_DIR="$HOME/${TARGET_DIR#~/}" ;;
      "~")   TARGET_DIR="$HOME" ;;
    esac
    SKILLS_DIR="$TARGET_DIR/agentguard"
    PLATFORM="custom"
    return
  fi

  # --scope selects a specific user/project/agent directory
  if [ -n "$SCOPE_TYPE" ]; then
    case "$SCOPE_TYPE" in
      user)
        SKILLS_DIR="$HOME/.openclaw/skills/agentguard"
        PLATFORM="openclaw-user"
        ;;
      project)
        SKILLS_DIR="$HOME/.openclaw-${SCOPE_NAME}/skills/agentguard"
        PLATFORM="openclaw-project:$SCOPE_NAME"
        ;;
      agent)
        SKILLS_DIR="$HOME/.openclaw-${SCOPE_NAME}/skills/agentguard"
        PLATFORM="openclaw-agent:$SCOPE_NAME"
        ;;
    esac
    return
  fi

  # $OPENCLAW_STATE_DIR: per-agent state directory set by the platform at runtime
  if [ -n "${OPENCLAW_STATE_DIR:-}" ] && [ -d "$OPENCLAW_STATE_DIR" ] && [ -w "$OPENCLAW_STATE_DIR" ]; then
    SKILLS_DIR="$OPENCLAW_STATE_DIR/skills/agentguard"
    PLATFORM="openclaw-agent"
    return
  fi

  # Auto-detect: collect all writable ~/.openclaw* directories
  local candidates=()
  for dir in "$HOME"/.openclaw*/; do
    [ -d "$dir" ] || continue
    [ -w "$dir" ] || continue
    candidates+=("$dir")
  done

  if [ "${#candidates[@]}" -eq 1 ]; then
    local oc_dir="${candidates[0]%/}"
    if [ -d "$oc_dir/workspace" ] && [ -w "$oc_dir/workspace" ]; then
      SKILLS_DIR="$oc_dir/workspace/skills/agentguard"
      PLATFORM="openclaw-workspace"
    else
      SKILLS_DIR="$oc_dir/skills/agentguard"
      PLATFORM="openclaw-managed"
    fi
    return
  fi

  if [ "${#candidates[@]}" -gt 1 ]; then
    echo "  Multiple writable OpenClaw directories found:"
    local i=1
    for dir in "${candidates[@]}"; do
      echo "    [$i] ${dir%/}"
      i=$((i + 1))
    done
    echo ""
    printf "  Select target [1-%d]: " "${#candidates[@]}"
    read -r choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#candidates[@]}" ]; then
      local selected="${candidates[$((choice - 1))]%/}"
      if [ -d "$selected/workspace" ] && [ -w "$selected/workspace" ]; then
        SKILLS_DIR="$selected/workspace/skills/agentguard"
        PLATFORM="openclaw-workspace"
      else
        SKILLS_DIR="$selected/skills/agentguard"
        PLATFORM="openclaw-managed"
      fi
      return
    else
      echo "  ERROR: Invalid selection. Use --target <path> or --scope agent <name> to specify explicitly."
      exit 1
    fi
  fi

  # Check Claude Code
  if [ -d "$HOME/.claude" ]; then
    SKILLS_DIR="$HOME/.claude/skills/agentguard"
    PLATFORM="claude-code"
    return
  fi

  # Nothing detected — require explicit --target
  echo "  ERROR: Could not detect a supported agent platform."
  echo "  Set \$OPENCLAW_STATE_DIR, or use --target <path> to specify the skills directory."
  echo "  Example: ./setup.sh --target ~/minax/agents/cto-owen/skills"
  exit 1
}

detect_platform
echo "  Platform detected: $PLATFORM"
echo "  Install target:    $SKILLS_DIR"
echo ""

# ---- Uninstall mode ----
if [ "$UNINSTALL" = true ]; then
  echo "  Uninstalling GoPlus AgentGuard..."
  rm -rf "$SKILLS_DIR" 2>/dev/null && echo "  Removed skill from $SKILLS_DIR" || true
  # Also clean up other possible locations
  rm -rf "$HOME/.claude/skills/agentguard" 2>/dev/null || true
  rm -rf "$HOME/.openclaw/skills/agentguard" 2>/dev/null || true
  rm -rf "$HOME/.openclaw/workspace/skills/agentguard" 2>/dev/null || true
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

# ---- Step 2: Copy skill files ----
echo "[2/5] Installing skill files..."
mkdir -p "$SKILLS_DIR"
for f in SKILL.md README.md scan-rules.md action-policies.md web3-patterns.md evals.md patrol-checks.md suppress.example.yaml .clawignore; do
  [ -f "$SKILL_SRC/$f" ] && cp "$SKILL_SRC/$f" "$SKILLS_DIR/" 2>/dev/null || true
done
echo "  OK: Skill files installed"

# ---- Step 3: Copy scripts ----
echo "[3/5] Installing scripts..."
mkdir -p "$SKILLS_DIR/scripts"

# Copy script files
for f in checkup-report.js checkup-score.js scan-to-sarif.js guard-hook.js auto-scan.js trust-cli.js action-cli.js; do
  [ -f "$SKILL_SRC/scripts/$f" ] && cp "$SKILL_SRC/scripts/$f" "$SKILLS_DIR/scripts/" 2>/dev/null || true
done

if [ -d "$SKILL_SRC/scripts/data" ]; then
  mkdir -p "$SKILLS_DIR/scripts/data"
  cp -r "$SKILL_SRC/scripts/data/"* "$SKILLS_DIR/scripts/data/" 2>/dev/null || true
fi
echo "  OK: Scripts installed"

# ---- Step 4: Install dependencies ----
echo "[4/5] Installing dependencies..."
# Scripts run as: cd $SKILLS_DIR && node scripts/<script>
# so node_modules must live at $SKILLS_DIR root for Node resolution.
cp "$SKILL_SRC/package.json" "$SKILLS_DIR/package.json"
[ -f "$SKILL_SRC/package-lock.json" ] && cp "$SKILL_SRC/package-lock.json" "$SKILLS_DIR/package-lock.json" || true
cd "$SKILLS_DIR"
npm install 2>/dev/null
echo "  OK: Dependencies installed"

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
echo ""
echo "  Other commands:"
echo "    /agentguard scan <path>    Scan code for security risks"
echo "    /agentguard trust list     View trusted skills"
echo "    /agentguard report         View security event log"
echo ""
echo "  To uninstall: ./setup.sh --uninstall"
echo ""
