"""Benign and out-of-scope calls are allowed."""

from helpers import make_protect_runner, register_with


def test_benign_exec_is_allowed():
    ctx, _ = register_with(make_protect_runner(decision=None))
    result = ctx.hooks["pre_tool_call"]("terminal", {"command": "git status"})
    assert result is None


def test_register_wires_all_hooks_and_command():
    ctx, _ = register_with(make_protect_runner(decision=None))
    assert set(ctx.hooks) == {"pre_tool_call", "post_tool_call", "on_session_start"}
    assert "agentguard" in ctx.commands


def test_unmapped_tool_skips_engine():
    calls = []
    ctx, _ = register_with(make_protect_runner(decision="block", calls=calls))
    # An out-of-scope tool must pass through without invoking the engine.
    result = ctx.hooks["pre_tool_call"]("attempt_completion", {"result": "done"})
    assert result is None
    assert calls == []


def test_allow_decision_with_json_passes():
    ctx, _ = register_with(make_protect_runner(decision="allow"))
    result = ctx.hooks["pre_tool_call"]("read_file", {"path": "/tmp/notes.txt"})
    assert result is None
