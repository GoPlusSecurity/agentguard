"""post_tool_call is audit-only and never blocks."""

from helpers import make_protect_runner, register_with


def test_post_tool_call_never_blocks_even_on_block_decision():
    ctx, _ = register_with(make_protect_runner(decision="block"))
    result = ctx.hooks["post_tool_call"]("terminal", {"command": "rm -rf /"})
    assert result is None


def test_bridge_post_phase_returns_none():
    _, guard = register_with(make_protect_runner(decision="block"))
    decision = guard.evaluate(
        event="post_tool_call",
        tool_name="terminal",
        args={"command": "rm -rf /"},
    )
    assert decision is None
