"""The /agentguard slash command forwards args and rejects unknown subcommands."""

from helpers import make_protect_runner, register_with


def test_command_forwards_extra_args():
    ctx, guard = register_with(make_protect_runner())
    seen = []
    guard.run_cli = lambda args: (seen.append(args) or "ok")
    handler, _desc = ctx.commands["agentguard"]
    out = handler("report --json")
    assert seen == [["report", "--json"]]
    assert out == "ok"


def test_command_defaults_to_report():
    ctx, guard = register_with(make_protect_runner())
    seen = []
    guard.run_cli = lambda args: (seen.append(args) or "ok")
    handler, _desc = ctx.commands["agentguard"]
    handler("")
    assert seen == [["report"]]


def test_command_rejects_unknown_subcommand():
    ctx, _ = register_with(make_protect_runner())
    handler, _desc = ctx.commands["agentguard"]
    out = handler("rm -rf")
    assert "Usage" in out
