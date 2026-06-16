"""Shared test helpers: a fake Hermes PluginContext and stub engine runners."""

import json
from types import SimpleNamespace

import plugin
from bridge import AgentGuardBridge


class FakeCtx:
    """Minimal stand-in for Hermes' PluginContext."""

    def __init__(self):
        self.hooks = {}
        self.commands = {}

    def register_hook(self, event_name, handler):
        self.hooks[event_name] = handler

    def register_command(self, name, handler, description=""):
        self.commands[name] = (handler, description)


def make_protect_runner(decision=None, *, returncode=0, stdout=None, raises=None, calls=None):
    """Stub for ``agentguard protect --json`` (mode="protect")."""

    def run(cmd, input_text):
        if calls is not None:
            calls.append((cmd, input_text))
        if raises is not None:
            raise raises
        if stdout is not None:
            return SimpleNamespace(stdout=stdout, returncode=returncode)
        if decision is None:
            # Null / low-risk result: protect prints nothing, exits 0.
            return SimpleNamespace(stdout="", returncode=0)
        body = {
            "decision": decision,
            "riskScore": 90,
            "riskLevel": "high",
            "reasons": [{"title": "Credential exfiltration"}],
        }
        rc = 2 if decision in ("block", "confirm") else 0
        return SimpleNamespace(stdout=json.dumps(body), returncode=rc)

    return run


def make_hook_runner(block=False, *, message="blocked by test", calls=None):
    """Stub for ``node hermes-hook.js`` (mode="hook")."""

    def run(cmd, input_text):
        if calls is not None:
            calls.append((cmd, input_text))
        if block:
            return SimpleNamespace(
                stdout=json.dumps({"action": "block", "message": message}),
                returncode=0,
            )
        return SimpleNamespace(stdout="{}", returncode=0)

    return run


def register_with(runner, mode="protect"):
    """Register the plugin against a stub engine; return (ctx, bridge)."""
    ctx = FakeCtx()
    guard = AgentGuardBridge(runner=runner, mode=mode)
    plugin.register(ctx, bridge=guard)
    return ctx, guard
