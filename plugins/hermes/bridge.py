"""Subprocess bridge from the Hermes plugin to the AgentGuard decision engine.

The plugin does **not** re-implement detection. It forwards each tool call to the
existing AgentGuard Node engine — the same ``protectAction`` path used by the
Hermes shell hook — so all detection rules live in one place.

Invocation is resolved at call time, in priority order:

1. ``AGENTGUARD_HERMES_HOOK`` env -> ``node <hermes-hook.js>`` (emits Hermes-format
   ``{"action":"block",...}`` / ``{}``).
2. ``AGENTGUARD_BIN`` env or ``agentguard`` on PATH -> ``agentguard protect --json``.
3. Bundled skill hook at ``~/.hermes/skills/agentguard/scripts/hermes-hook.js``.
4. ``npx -y @goplus/agentguard protect --json`` as a last resort.

Fail policy mirrors the shell hook: pre-tool engine failures fail **closed**
(block) for mapped, security-sensitive tools; post-tool failures never block.
Set ``AGENTGUARD_HERMES_FAIL_OPEN=1`` to fail open instead.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Hermes tool name -> AgentGuard runtime action type.
# Mirrors runtimeActionTypeFrom() in skills/agentguard/scripts/hermes-hook.js and
# the TOOL_ACTION_MAP keys in src/adapters/hermes.ts. Passing the action type
# explicitly is required because `agentguard protect`'s generic heuristic would
# otherwise classify e.g. "terminal" as "other".
TOOL_ACTION_TYPE: Dict[str, str] = {
    "terminal": "shell",
    "execute_code": "shell",
    "write_file": "file_write",
    "patch": "file_write",
    "skill_manage": "file_write",
    "read_file": "file_read",
    "web_search": "web_search",
    "web_extract": "network",
    "browser_navigate": "network",
    "browser_open": "network",
    "web_open": "network",
    "open_url": "network",
    "visit_url": "network",
    "open": "network",
}

# Tools outside this set are out of scope and allowed without invoking the engine
# (mirrors the shell-hook matchers and avoids the unknown-tool fail-closed path).
MAPPED_TOOLS = frozenset(TOOL_ACTION_TYPE)

# Required tool_input fields per mapped tool. A mapped, security-sensitive event
# missing its required field is malformed and is blocked (fail-closed), mirroring
# validatePreToolPayload() in skills/agentguard/scripts/hermes-hook.js.
_REQUIRED_FIELDS: Dict[str, tuple] = {
    "terminal": ("command",),
    "execute_code": ("code", "command"),
    "write_file": ("path", "file_path"),
    "patch": ("path", "file_path"),
    "read_file": ("path", "file_path"),
    "skill_manage": ("path", "file_path", "target", "skill_path"),
    "web_search": ("query", "url"),
    "web_extract": ("url", "href", "target"),
    "browser_navigate": ("url", "href", "target"),
    "browser_open": ("url", "href", "target"),
    "web_open": ("url", "href", "target"),
    "open_url": ("url", "href", "target"),
    "visit_url": ("url", "href", "target"),
    "open": ("url", "href", "target"),
}

# Hermes pre_tool_call has no native "ask"; AgentGuard's confirm maps to a block.
_BLOCK_DECISIONS = frozenset({"block", "confirm"})

_DEFAULT_BLOCK_MESSAGE = "GoPlus AgentGuard blocked this action"


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"", "0", "false", "no", "off"}


class AgentGuardBridge:
    """Evaluates Hermes tool calls through the AgentGuard engine."""

    def __init__(
        self,
        runner: Optional[Callable[[list, str], Any]] = None,
        mode: str = "protect",
        timeout: Optional[float] = None,
    ) -> None:
        # ``runner`` lets tests inject a deterministic engine without spawning a
        # subprocess. When set, invocation resolution is bypassed and ``mode``
        # selects how the runner's stdout is interpreted ("protect" or "hook").
        self._runner = runner
        self._test_mode = mode
        if timeout is None:
            try:
                timeout = float(os.environ.get("AGENTGUARD_HERMES_TIMEOUT", "10"))
            except ValueError:
                timeout = 10.0
        self.timeout = timeout

    # -- public API --------------------------------------------------------

    def evaluate(
        self,
        event: str,
        tool_name: str,
        args: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        cwd: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """Return a Hermes block dict, or ``None`` to allow.

        ``{"action": "block", "message": ...}`` vetoes the tool call.
        """
        phase = "post" if event.startswith("post") else "pre"
        if tool_name not in TOOL_ACTION_TYPE:
            return None  # out of scope -> allow without invoking the engine

        if phase == "pre":
            # A malformed mapped-tool payload is blocked unconditionally (even
            # under fail-open): we can't evaluate what we can't read.
            missing = _validate_mapped_payload(tool_name, args or {})
            if missing:
                return _block("GoPlus AgentGuard: %s" % missing)

        argv, mode = self._invocation()
        if argv is None:
            return self._fail(
                phase,
                "AgentGuard engine not found; install @goplus/agentguard or set "
                "AGENTGUARD_BIN / AGENTGUARD_HERMES_HOOK",
            )

        payload = _build_payload(event, tool_name, args, session_id, cwd, task_id)
        cmd = list(argv)
        if mode == "protect":
            cmd += [
                "--agent", "hermes",
                "--action-type", TOOL_ACTION_TYPE[tool_name],
                "--tool-name", tool_name,
                "--json",
            ]
            if session_id:
                cmd += ["--session-id", session_id]

        try:
            proc = self._run(cmd, json.dumps(payload))
        except subprocess.TimeoutExpired:
            return self._fail(phase, "AgentGuard evaluation timed out")
        except (OSError, ValueError) as exc:
            return self._fail(phase, "AgentGuard evaluation failed to start: %s" % exc)

        if phase == "post":
            return None  # post hooks are audit-only; never block
        return self._interpret(mode, proc)

    def run_cli(self, args: list) -> str:
        """Run an ``agentguard`` subcommand and return stdout (for /agentguard)."""
        bin_path = os.environ.get("AGENTGUARD_BIN") or shutil.which("agentguard")
        if not bin_path:
            if _env_truthy("AGENTGUARD_HERMES_ALLOW_NPX") and shutil.which("npx"):
                cmd = ["npx", "-y", "@goplus/agentguard", *args]
            else:
                return "AgentGuard CLI not found. Install @goplus/agentguard (or set AGENTGUARD_BIN)."
        else:
            cmd = [bin_path, *args]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, encoding="utf-8"
            )
        except subprocess.SubprocessError as exc:
            return "AgentGuard CLI failed: %s" % exc
        return (proc.stdout or proc.stderr or "").strip()

    # -- internals ---------------------------------------------------------

    def _run(self, cmd: list, input_text: str) -> Any:
        if self._runner is not None:
            return self._runner(cmd, input_text)
        return subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            encoding="utf-8",
        )

    def _invocation(self):
        if self._runner is not None:
            return (["<test-engine>"], self._test_mode)
        return self._resolve_invocation()

    @staticmethod
    def _resolve_invocation():
        hook = os.environ.get("AGENTGUARD_HERMES_HOOK")
        if hook and Path(hook).is_file():
            node = shutil.which("node")
            if node:
                return ([node, hook], "hook")

        bin_path = os.environ.get("AGENTGUARD_BIN") or shutil.which("agentguard")
        if bin_path:
            return ([bin_path, "protect"], "protect")

        skill_hook = Path.home() / ".hermes" / "skills" / "agentguard" / "scripts" / "hermes-hook.js"
        node = shutil.which("node")
        if node and skill_hook.is_file():
            return ([node, str(skill_hook)], "hook")

        # npx fetches an unpinned package over the network — unsafe for a
        # security gate, so it is opt-in only.
        if _env_truthy("AGENTGUARD_HERMES_ALLOW_NPX") and shutil.which("npx"):
            return (["npx", "-y", "@goplus/agentguard", "protect"], "protect")

        return (None, None)

    def _interpret(self, mode: str, proc: Any) -> Optional[Dict[str, str]]:
        out = (getattr(proc, "stdout", "") or "").strip()

        if mode == "hook":
            data = _safe_json(out)
            if isinstance(data, dict) and (data.get("action") == "block" or data.get("block") is True):
                return _block(data.get("message") or data.get("reason"))
            return None

        # protect mode: empty stdout means a null (low-risk / safe) result -> allow.
        if not out:
            return None
        data = _safe_json(out)
        if not isinstance(data, dict):
            return _block(None) if getattr(proc, "returncode", 0) == 2 else None
        if data.get("decision") in _BLOCK_DECISIONS:
            return _block(_format_reason(data))
        return None

    @staticmethod
    def _fail(phase: str, reason: str) -> Optional[Dict[str, str]]:
        if phase == "post":
            return None
        if _env_truthy("AGENTGUARD_HERMES_FAIL_OPEN"):
            return None
        return _block("GoPlus AgentGuard: %s; blocking fail-closed" % reason)


def _validate_mapped_payload(tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    """Return an error string if a mapped tool's required field is missing."""
    fields = _REQUIRED_FIELDS.get(tool_name)
    if not fields:
        return None
    for field in fields:
        value = args.get(field)
        if isinstance(value, str) and value:
            return None
    return "Hermes %s payload is missing %s" % (tool_name, " / ".join(fields))


def _build_payload(event, tool_name, args, session_id, cwd, task_id) -> Dict[str, Any]:
    return {
        "hook_event_name": event,
        "tool_name": tool_name,
        "tool_input": args or {},
        "session_id": session_id,
        "cwd": cwd,
        "extra": {"task_id": task_id} if task_id else {},
    }


def _safe_json(text: str) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _block(message: Optional[str]) -> Dict[str, str]:
    return {"action": "block", "message": message or _DEFAULT_BLOCK_MESSAGE}


def _format_reason(data: Dict[str, Any]) -> str:
    titles = []
    for reason in data.get("reasons") or []:
        if isinstance(reason, dict) and reason.get("title"):
            titles.append(str(reason["title"]))
    titles = titles[:3]
    risk = data.get("riskScore")
    level = data.get("riskLevel")
    verb = "requires confirmation for" if data.get("decision") == "confirm" else "blocked"
    base = "GoPlus AgentGuard %s this Hermes tool call (risk: %s/100, level: %s)." % (
        verb, risk, level,
    )
    if titles:
        base += " Reasons: %s." % ", ".join(titles)
    return base
