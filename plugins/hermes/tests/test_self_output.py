"""Native Hermes own-command results are rewritten before model context."""

import json
import shlex
import shutil
from pathlib import Path

from helpers import make_protect_runner, register_with


def test_transform_hook_scopes_standalone_commands_and_fails_safe(monkeypatch):
    ctx, guard = register_with(make_protect_runner())
    guard.redact_self_output = lambda text: text.replace("sk-test-secret-1234567890", "[REDACTED]")
    transform = ctx.hooks["transform_tool_result"]
    own = '{"output":"api_key=sk-test-secret-1234567890"}'
    assert transform("terminal", {"command": "agentguard scan ./skill"}, result=own) == '{"output":"api_key=[REDACTED]"}'
    assert transform("execute_code", {"code": "agentguard status"}, result=own) == '{"output":"api_key=[REDACTED]"}'
    assert transform("terminal", {"command": "agentguard status; cat .env"}, result=own) is None
    assert transform("terminal", {"command": "cat .env"}, result=own) is None
    assert transform("read_file", {"path": "x"}, result=own) is None
    assert transform("terminal", {"command": "agentguard status"}, result="public") is None
    guard.redact_self_output = lambda _text: (_ for _ in ()).throw(RuntimeError("sk-private-value"))
    failed = transform("terminal", {"command": "agentguard status"}, result=own)
    assert "safely redacted" in failed
    assert "sk-test-secret" not in failed


def test_bridge_uses_shared_redactor_and_preserves_only_the_saved_link(monkeypatch, tmp_path):
    node = shutil.which("node")
    assert node
    cli = Path(__file__).resolve().parents[3] / "dist" / "cli.js"
    shim = tmp_path / "agentguard"
    shim.write_text("#!/bin/sh\nexec " + shlex.quote(node) + " " + shlex.quote(str(cli)) + ' "$@"\n')
    shim.chmod(0o755)
    monkeypatch.setenv("AGENTGUARD_BIN", str(shim))
    monkeypatch.setenv("AGENTGUARD_HOME", str(tmp_path))
    link = "https://agentguard.example/activate?token=hermes-self-link-123456"
    (tmp_path / "config.json").write_text(json.dumps({
        "version": 1, "level": "balanced", "agentJwt": "agent.jwt.test", "agentRegisterUrl": link,
        "cloudUrl": "http://127.0.0.1:9",
    }))
    ctx, guard = register_with(make_protect_runner())
    output = f"{link}\napi_key=sk-hermes-secret-1234567890"
    rewritten = ctx.hooks["transform_tool_result"]("terminal", {"command": "agentguard connect"}, result=output)
    assert link in rewritten
    assert "hermes-secret" not in rewritten
    assert "api_key=[REDACTED]" in rewritten
    assert ctx.hooks["transform_tool_result"]("terminal", {"command": "agentguard status"}, result=link) is None
    forged = guard.redact_self_output(output.replace(link, link + "-forged"))
    assert "hermes-self-link-123456-forged" not in forged
    assert "sk-hermes-secret" not in forged
    slash_status = ctx.commands["agentguard"][0]("status")
    assert link in slash_status
    assert "TYPESAFE_API_KEY=[REDACTED]" in slash_status
