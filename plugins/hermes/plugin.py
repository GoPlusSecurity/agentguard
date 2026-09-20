"""GoPlus AgentGuard — native Hermes Agent plugin.

Registers Hermes lifecycle hooks that route tool calls through the AgentGuard
decision engine (see :mod:`bridge`), plus a ``/agentguard`` slash command.

Hermes loads this package and calls :func:`register` at plugin-load time.
"""

from __future__ import annotations

import os
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

try:  # loaded as a package by Hermes (~/.hermes/plugins/agentguard/)
    from .bridge import AgentGuardBridge
except ImportError:  # loaded as a top-level module (tests / ad-hoc)
    from bridge import AgentGuardBridge


logger = logging.getLogger(__name__)


def register(ctx: Any, bridge: Optional[AgentGuardBridge] = None) -> None:
    """Entry point invoked by Hermes. ``bridge`` is injectable for tests."""
    guard = bridge or AgentGuardBridge()

    ctx.register_hook("pre_llm_call", _make_pre_llm_call(guard))
    ctx.register_hook("pre_api_request", _make_pre_api_request(guard))
    ctx.register_hook("post_api_request", _make_post_api_request(guard))
    ctx.register_hook("pre_tool_call", _make_pre_tool_call(guard))
    ctx.register_hook("post_tool_call", _make_post_tool_call(guard))
    ctx.register_hook("on_session_start", _make_session_start(guard))

    register_command = getattr(ctx, "register_command", None)
    if callable(register_command):
        register_command(
            "agentguard",
            _make_status_command(guard),
            description="Show GoPlus AgentGuard status, recent audit report, or run a checkup.",
        )


def _make_pre_llm_call(_guard: AgentGuardBridge):
    def pre_llm_call(*_args: Any, **_kwargs: Any):
        # Hermes invokes this once per user turn and interprets a return value
        # as context injection. It is not a per-request security gate, so
        # AgentGuard deliberately observes the lower pre_api_request hook.
        return None

    return pre_llm_call


def _make_pre_api_request(guard: AgentGuardBridge):
    def pre_api_request(**kwargs: Any):
        request_id = kwargs.get("api_request_id")
        try:
            result = guard.observe_llm_request(**kwargs)
            _warn_observer_decision("request", request_id, result)
        except Exception as exc:
            logger.warning(
                "GoPlus AgentGuard Hermes request observer failed; model request remains observe_only: %s",
                exc,
            )
        return None

    return pre_api_request


def _make_post_api_request(guard: AgentGuardBridge):
    def post_api_request(**kwargs: Any):
        request_id = kwargs.get("api_request_id")
        try:
            result = guard.observe_llm_response(**kwargs)
            _warn_observer_decision("response", request_id, result)
        except Exception as exc:
            logger.warning(
                "GoPlus AgentGuard Hermes response observer failed; response remains observe_only: %s",
                exc,
            )
        return None

    return post_api_request


def _warn_observer_decision(kind: str, request_id: Any, result: Optional[Dict[str, Any]]) -> None:
    if not result or result.get("policyDecision") not in {"block", "require_approval"}:
        return
    logger.warning(
        "GoPlus AgentGuard observed a Hermes model %s policy violation "
        "(request_id=%s, enforcement=would_block); the Hermes API hook is observe_only",
        kind,
        request_id or "unknown",
    )


def _make_pre_tool_call(guard: AgentGuardBridge):
    def pre_tool_call(tool_name: str, args: Optional[Dict[str, Any]] = None, **kwargs: Any):
        try:
            return guard.evaluate(
                event="pre_tool_call",
                tool_name=tool_name,
                args=args or {},
                session_id=kwargs.get("session_id"),
                cwd=kwargs.get("cwd"),
                task_id=kwargs.get("task_id"),
            )
        except Exception:
            # Hooks must never crash the agent. Expected failures already fail
            # closed inside the bridge; an unexpected error here allows the call.
            return None

    return pre_tool_call


def _make_post_tool_call(guard: AgentGuardBridge):
    def post_tool_call(tool_name: str, args: Optional[Dict[str, Any]] = None, **kwargs: Any):
        try:
            guard.evaluate(
                event="post_tool_call",
                tool_name=tool_name,
                args=args or {},
                session_id=kwargs.get("session_id"),
                cwd=kwargs.get("cwd"),
                task_id=kwargs.get("task_id"),
            )
        except Exception:
            pass  # audit-only
        return None

    return post_tool_call


def _make_session_start(guard: AgentGuardBridge):
    def on_session_start(*_args: Any, **_kwargs: Any):
        # Best-effort background scan of installed skills, mirroring the shell
        # hook's on_session_start. Opt out with AGENTGUARD_HERMES_AUTOSCAN=0.
        if os.environ.get("AGENTGUARD_HERMES_AUTOSCAN", "1").strip().lower() in {"0", "false", "no", "off"}:
            return None
        script = Path.home() / ".hermes" / "skills" / "agentguard" / "scripts" / "auto-scan.js"
        node = shutil.which("node")
        if not (node and script.is_file()):
            return None
        try:
            env = dict(os.environ, AGENTGUARD_AUTO_SCAN="1")
            subprocess.Popen(  # detached; never blocks session start
                [node, str(script)],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
        except OSError:
            pass
        return None

    return on_session_start


_ALLOWED_SUBCOMMANDS = {"status", "report", "checkup"}


def _make_status_command(guard: AgentGuardBridge):
    def agentguard_command(raw_args: str = "") -> str:
        parts = (raw_args or "").split()
        sub = parts[0] if parts else "report"
        if sub not in _ALLOWED_SUBCOMMANDS:
            return "Usage: /agentguard [%s] [args...]" % " | ".join(sorted(_ALLOWED_SUBCOMMANDS))
        # Forward any remaining args to the subcommand (e.g. `report --json`)
        # rather than silently dropping them.
        return guard.run_cli([sub, *parts[1:]]) or "(no output)"

    return agentguard_command
