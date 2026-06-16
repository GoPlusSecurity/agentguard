"""Malformed mapped-tool payloads fail closed before the engine is invoked."""

from helpers import make_protect_runner, register_with


def test_terminal_without_command_blocks_without_engine():
    calls = []
    ctx, _ = register_with(make_protect_runner(decision="allow", calls=calls))
    result = ctx.hooks["pre_tool_call"]("terminal", {})
    assert isinstance(result, dict) and result["action"] == "block"
    assert "missing" in result["message"]
    assert calls == []  # engine never invoked on a malformed payload


def test_write_file_without_path_blocks():
    ctx, _ = register_with(make_protect_runner(decision="allow"))
    result = ctx.hooks["pre_tool_call"]("write_file", {"content": "x"})
    assert isinstance(result, dict) and result["action"] == "block"


def test_web_extract_without_url_blocks():
    ctx, _ = register_with(make_protect_runner(decision="allow"))
    result = ctx.hooks["pre_tool_call"]("web_extract", {})
    assert isinstance(result, dict) and result["action"] == "block"


def test_malformed_blocks_even_under_fail_open(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_HERMES_FAIL_OPEN", "1")
    ctx, _ = register_with(make_protect_runner(decision="allow"))
    result = ctx.hooks["pre_tool_call"]("terminal", {})
    assert isinstance(result, dict) and result["action"] == "block"


def test_post_phase_does_not_validate():
    ctx, _ = register_with(make_protect_runner(decision="block"))
    result = ctx.hooks["post_tool_call"]("terminal", {})
    assert result is None


def test_wellformed_payload_passes_validation():
    ctx, _ = register_with(make_protect_runner(decision="allow"))
    result = ctx.hooks["pre_tool_call"]("terminal", {"command": "ls"})
    assert result is None
