"""post_tool_call is audit-only and never blocks."""

from helpers import make_ipc_transport, make_protect_runner, register_with, register_with_transport


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


def test_post_search_forwards_host_result_without_treating_query_as_output():
    calls = []
    ctx, _ = register_with_transport(make_ipc_transport(calls=calls))
    args = {"query": "bitcoin price"}
    result = {"content": '{"id":"2026101215253008"}'}
    assert ctx.hooks["post_tool_call"]("web_search", args, result=result) is None
    assert calls[0]["action"]["rawInput"]["tool_response"] == result
    assert calls[0]["action"]["rawInput"]["tool_input"] == args

    assert ctx.hooks["post_tool_call"]("web_search", args) is None
    assert "tool_response" not in calls[1]["action"]["rawInput"]
