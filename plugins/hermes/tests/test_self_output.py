"""Native Hermes leaves AgentGuard command results untouched."""

from helpers import make_protect_runner, register_with


def test_no_result_transform_hook_is_registered():
    ctx, _ = register_with(make_protect_runner())
    assert "transform_tool_result" not in ctx.hooks


def test_slash_command_returns_raw_cli_output(monkeypatch):
    ctx, guard = register_with(make_protect_runner())
    monkeypatch.setattr(guard, "run_cli", lambda args: "api_key=sk-hermes-secret-1234567890")
    output = ctx.commands["agentguard"][0]("status")
    assert output == "api_key=sk-hermes-secret-1234567890"
