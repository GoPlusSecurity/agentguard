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
OPENCLAW_ROOT="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
OPENCLAW_PLUGIN_DIR="$OPENCLAW_ROOT/plugins/agentguard"
OPENCLAW_CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-$OPENCLAW_ROOT/openclaw.json}"
QCLAW_ROOT="${QCLAW_STATE_DIR:-$HOME/.qclaw}"
QCLAW_PLUGIN_DIR="$QCLAW_ROOT/plugins/agentguard"
QCLAW_CONFIG_PATH="${QCLAW_CONFIG_PATH:-$QCLAW_ROOT/qclaw.json}"

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

  if [ -d "$HOME/.hermes" ]; then
    SKILLS_DIR="$HOME/.hermes/skills/agentguard"
    PLATFORM="hermes"
    return
  fi

  if [ -d "$HOME/.qclaw" ]; then
    SKILLS_DIR="$HOME/.qclaw/skills/agentguard"
    PLATFORM="qclaw"
    return
  fi

  if [ -d "$HOME/.codex" ]; then
    SKILLS_DIR="$HOME/.codex/skills/agentguard"
    PLATFORM="codex"
    return
  fi

  # Fallback: create Claude Code dir (most common legacy install path).
  # Use --target for custom layouts when this default is not desired.
  SKILLS_DIR="$HOME/.claude/skills/agentguard"
  PLATFORM="claude-code"
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
for f in checkup-report.js checkup-score.js scan-to-sarif.js guard-hook.js hermes-hook.js auto-scan.js trust-cli.js action-cli.js; do
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

if [ "$PLATFORM" = "qclaw" ]; then
  echo "  Enabling QClaw plugin..."
  mkdir -p "$QCLAW_PLUGIN_DIR"
  AGENTGUARD_DIST_INDEX="$SCRIPT_DIR/dist/index.js" node - "$QCLAW_PLUGIN_DIR/index.js" <<'NODE'
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
  cat > "$QCLAW_PLUGIN_DIR/package.json" <<'JSON'
{
  "name": "agentguard-qclaw-local",
  "private": true,
  "type": "commonjs",
  "openclaw": {
    "extensions": ["./index.js"],
    "runtimeExtensions": ["./index.js"]
  },
  "qclaw": {
    "extensions": ["./index.js"],
    "runtimeExtensions": ["./index.js"]
  }
}
JSON
  cat > "$QCLAW_PLUGIN_DIR/openclaw.plugin.json" <<'JSON'
{
  "id": "agentguard",
  "name": "GoPlus AgentGuard",
  "description": "AI agent security framework — blocks dangerous commands, prevents data leaks, and protects secrets"
}
JSON
  node - "$QCLAW_CONFIG_PATH" "$QCLAW_PLUGIN_DIR" <<'NODE'
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
  echo "  OK: QClaw plugin enabled in $QCLAW_CONFIG_PATH"
fi

if [ "$PLATFORM" = "hermes" ]; then
  echo "  Configuring Hermes hooks..."
  HERMES_CONFIG_PATH="$HOME/.hermes/config.yaml" AGENTGUARD_SKILL_DIR="$SKILLS_DIR" node <<'NODE'
const { existsSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { dirname } = require('node:path');
const configPath = process.env.HERMES_CONFIG_PATH;
const skillDir = process.env.AGENTGUARD_SKILL_DIR;
const block = `  on_session_start:
    - command: "env AGENTGUARD_AUTO_SCAN=1 node \\"${skillDir}/scripts/auto-scan.js\\""
      timeout: 30

  pre_tool_call:
    - matcher: "terminal|execute_code"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "write_file|patch|skill_manage"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "read_file"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "web_search"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "web_extract|browser_navigate"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10

  post_tool_call:
    - matcher: "terminal|execute_code|write_file|patch|skill_manage|read_file|web_search|web_extract|browser_navigate"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 5`;
const findNextTopLevel = (lines, start) => {
  for (let i = start; i < lines.length; i += 1) {
    if (/^\S/.test(lines[i]) && !/^#/.test(lines[i])) return i;
  }
  return lines.length;
};
const removeManaged = (lines) => {
  const events = new Set(['on_session_start', 'pre_tool_call', 'post_tool_call']);
  const kept = [];
  for (let i = 0; i < lines.length;) {
    const match = /^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$/.exec(lines[i]);
    if (match && events.has(match[1])) {
      i += 1;
      while (i < lines.length && !/^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(lines[i]) && !/^\S/.test(lines[i])) i += 1;
      continue;
    }
    kept.push(lines[i]);
    i += 1;
  }
  return kept;
};
const existing = existsSync(configPath) ? readFileSync(configPath, 'utf8') : '';
const lines = existing.replace(/\s+$/g, '').split(/\r?\n/).filter((line, index, arr) => !(arr.length === 1 && index === 0 && line === ''));
const hooksIndex = lines.findIndex((line) => /^hooks:\s*(?:#.*)?$/.test(line));
let merged;
if (hooksIndex === -1) {
  merged = `${lines.length ? `${lines.join('\n')}\n\n` : ''}hooks:\n${block}\n`;
} else {
  const hooksEnd = findNextTopLevel(lines, hooksIndex + 1);
  merged = [...lines.slice(0, hooksIndex + 1), ...removeManaged(lines.slice(hooksIndex + 1, hooksEnd)), ...block.split('\n'), ...lines.slice(hooksEnd)].join('\n');
}
if (!/^hooks_auto_accept:\s*/m.test(merged)) merged += '\n\nhooks_auto_accept: false';
mkdirSync(dirname(configPath), { recursive: true });
writeFileSync(configPath, `${merged.replace(/\s+$/g, '')}\n`);
NODE
  echo "  OK: Hermes hooks configured in $HOME/.hermes/config.yaml"
fi

if [ "$PLATFORM" = "codex" ]; then
  echo "  Writing Codex AgentGuard hook config..."
  mkdir -p "$HOME/.codex"
  cat > "$HOME/.codex/agentguard-hook.json" <<'JSON'
{
  "agentHost": "codex",
  "command": "AGENTGUARD_AGENT_HOST=codex agentguard protect",
  "actionTypes": {
    "shell": "shell",
    "fileRead": "file_read",
    "fileWrite": "file_write",
    "network": "network",
    "mcpTool": "mcp_tool"
  }
}
JSON
  echo "  OK: Codex AgentGuard config written to $HOME/.codex/agentguard-hook.json"
fi

# ---- Done ----
echo ""
echo "  ✅ GoPlus AgentGuard is installed!"
echo ""
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  NEXT STEPS"
echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
AGENT_HOST="$PLATFORM"
if [ "$PLATFORM" = "openclaw-workspace" ] || [ "$PLATFORM" = "openclaw-managed" ]; then
  AGENT_HOST="openclaw"
fi
echo "    agentguard init --agent $AGENT_HOST"
echo "    agentguard checkup"
echo ""
echo "  Optional Cloud connect:"
if [ "$AGENT_HOST" = "openclaw" ]; then
  echo "    agentguard connect        # uses OpenClaw Agent JWT; no API key required"
else
  echo "    agentguard connect        # optional; use AGENTGUARD_API_KEY for API-key auth"
fi
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
