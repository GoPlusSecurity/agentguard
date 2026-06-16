"""Engine failures fail closed (pre) unless fail-open is requested."""

import subprocess

import pytest

from helpers import make_protect_runner, register_with


def test_timeout_fails_closed_for_mapped_tool(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_HERMES_FAIL_OPEN", raising=False)
    runner = make_protect_runner(raises=subprocess.TimeoutExpired(cmd="agentguard", timeout=10))
    ctx, _ = register_with(runner)
    result = ctx.hooks["pre_tool_call"]("terminal", {"command": "git status"})
    assert isinstance(result, dict)
    assert result["action"] == "block"
    assert "fail-closed" in result["message"]


def test_os_error_fails_closed(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_HERMES_FAIL_OPEN", raising=False)
    runner = make_protect_runner(raises=OSError("boom"))
    ctx, _ = register_with(runner)
    result = ctx.hooks["pre_tool_call"]("write_file", {"path": "/etc/hosts"})
    assert isinstance(result, dict)
    assert result["action"] == "block"


def test_fail_open_env_allows_on_engine_error(monkeypatch):
    monkeypatch.setenv("AGENTGUARD_HERMES_FAIL_OPEN", "1")
    runner = make_protect_runner(raises=OSError("boom"))
    ctx, _ = register_with(runner)
    result = ctx.hooks["pre_tool_call"]("terminal", {"command": "git status"})
    assert result is None


def test_post_phase_never_blocks_on_engine_error(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_HERMES_FAIL_OPEN", raising=False)
    runner = make_protect_runner(raises=subprocess.TimeoutExpired(cmd="agentguard", timeout=10))
    ctx, _ = register_with(runner)
    result = ctx.hooks["post_tool_call"]("terminal", {"command": "rm -rf /"})
    assert result is None


def test_malformed_output_with_block_exit_code_blocks():
    runner = make_protect_runner(stdout="not-json", returncode=2)
    ctx, _ = register_with(runner)
    result = ctx.hooks["pre_tool_call"]("terminal", {"command": "rm -rf /"})
    assert isinstance(result, dict)
    assert result["action"] == "block"


def test_malformed_output_with_ok_exit_code_allows():
    runner = make_protect_runner(stdout="not-json", returncode=0)
    ctx, _ = register_with(runner)
    result = ctx.hooks["pre_tool_call"]("terminal", {"command": "echo hi"})
    assert result is None
