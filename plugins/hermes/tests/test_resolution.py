"""Engine resolution: npx is opt-in; explicit binary is preferred."""

import bridge


def _only_npx(name):
    return "/usr/bin/npx" if name == "npx" else None


def test_npx_not_used_without_optin(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENTGUARD_BIN", raising=False)
    monkeypatch.delenv("AGENTGUARD_HERMES_HOOK", raising=False)
    monkeypatch.delenv("AGENTGUARD_HERMES_ALLOW_NPX", raising=False)
    monkeypatch.setattr(bridge.shutil, "which", _only_npx)
    monkeypatch.setattr(bridge.Path, "home", classmethod(lambda cls: tmp_path))
    argv, mode = bridge.AgentGuardBridge._resolve_invocation()
    assert argv is None and mode is None


def test_npx_used_with_optin(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENTGUARD_BIN", raising=False)
    monkeypatch.delenv("AGENTGUARD_HERMES_HOOK", raising=False)
    monkeypatch.setenv("AGENTGUARD_HERMES_ALLOW_NPX", "1")
    monkeypatch.setattr(bridge.shutil, "which", _only_npx)
    monkeypatch.setattr(bridge.Path, "home", classmethod(lambda cls: tmp_path))
    argv, mode = bridge.AgentGuardBridge._resolve_invocation()
    assert mode == "protect" and argv[0] == "npx"


def test_agentguard_bin_is_preferred(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_BIN", "/opt/agentguard")
    monkeypatch.delenv("AGENTGUARD_HERMES_HOOK", raising=False)
    monkeypatch.setattr(bridge.Path, "home", classmethod(lambda cls: tmp_path))
    argv, mode = bridge.AgentGuardBridge._resolve_invocation()
    assert mode == "protect" and argv == ["/opt/agentguard", "protect"]
