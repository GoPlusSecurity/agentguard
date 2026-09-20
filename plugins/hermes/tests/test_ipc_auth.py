"""Windows loopback IPC authenticates the daemon before sharing private data."""

import json
import shutil
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from bridge import AgentGuardBridge, _default_windows_port


def test_tcp_server_must_authenticate_before_client_sends_action_content():
    frames = []
    ready = threading.Event()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        ready.set()
        connection, _ = server.accept()
        with connection:
            line = _read_line(connection)
            frames.append(json.loads(line.decode("utf-8")))
            connection.sendall(
                json.dumps(
                    {
                        "version": 1,
                        "id": "request-1",
                        "kind": "challenge",
                        "serverNonce": "0" * 64,
                        "serverProof": "invalid",
                    }
                ).encode("utf-8")
                + b"\n"
            )

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(timeout=1)
    bridge = AgentGuardBridge(timeout=0.5)
    try:
        bridge._ipc_endpoint = lambda: {
            "kind": "tcp",
            "port": port,
            "token": "test-token-that-is-at-least-32-bytes",
        }
        result = bridge.evaluate(
            event="pre_tool_call",
            tool_name="terminal",
            args={"command": "echo private.person@example.invalid"},
            session_id="session-1",
        )
    finally:
        server.close()
        thread.join(timeout=1)

    assert result["action"] == "block"
    assert "authentication" in result["message"]
    assert len(frames) == 1
    assert frames[0]["kind"] == "hello"
    assert len(frames[0]["clientNonce"]) == 64
    assert "private.person" not in json.dumps(frames[0])
    assert "test-token" not in json.dumps(frames[0])


def test_python_client_deadline_is_absolute_during_drip_response():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        connection, _ = server.accept()
        with connection:
            _read_line(connection)
            deadline = time.monotonic() + 0.2
            while time.monotonic() < deadline:
                try:
                    connection.sendall(b" ")
                except OSError:
                    break
                time.sleep(0.015)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    bridge = AgentGuardBridge(timeout=0.05)
    bridge._ipc_endpoint = lambda: {
        "kind": "tcp",
        "port": port,
        "token": "test-token-that-is-at-least-32-bytes",
    }
    started_at = time.monotonic()
    try:
        result = bridge.evaluate(
            event="pre_tool_call",
            tool_name="terminal",
            args={"command": "echo safe"},
        )
    finally:
        server.close()
        thread.join(timeout=1)

    assert result["action"] == "block"
    assert "timed out" in result["message"]
    assert time.monotonic() - started_at < 0.13


def test_windows_token_first_use_is_atomic(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_HOME", str(tmp_path))
    monkeypatch.delenv("AGENTGUARD_HERMES_IPC_TOKEN", raising=False)
    workers = 12
    barrier = threading.Barrier(workers)

    def load_token(_index):
        barrier.wait(timeout=2)
        return AgentGuardBridge()._windows_ipc_token()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        tokens = list(pool.map(load_token, range(workers)))

    assert len(set(tokens)) == 1
    assert (tmp_path / "run" / "hermes-evaluator.token").read_text().strip() == tokens[0]


def test_default_windows_port_is_stable_and_user_scoped(tmp_path):
    alice = tmp_path / "alice" / ".agentguard"
    bob = tmp_path / "bob" / ".agentguard"

    assert _default_windows_port(alice) == _default_windows_port(alice)
    assert _default_windows_port(alice) != _default_windows_port(bob)


def test_python_client_interoperates_with_node_authenticated_daemon(tmp_path):
    root = Path(__file__).resolve().parents[3]
    daemon_module = root / "dist" / "hermes" / "evaluator-daemon.js"
    node = shutil.which("node")
    if node is None or not daemon_module.is_file():
        pytest.skip("build the Node daemon before running the cross-language integration test")

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    token = "cross-language-token-that-is-at-least-32-bytes"
    script = """
      import { startHermesEvaluatorDaemon } from './dist/hermes/evaluator-daemon.js';
      const daemon = await startHermesEvaluatorDaemon({
        endpoint: { kind: 'tcp', host: '127.0.0.1', port: Number(process.argv[1]), token: process.argv[2] },
        loadConfig: () => ({
          version: 1,
          level: 'balanced',
          policyCachePath: process.argv[3] + '/policy.json',
          auditPath: process.argv[3] + '/audit.jsonl',
          eventSpoolPath: process.argv[3] + '/spool.jsonl',
        }),
        protect: async () => null,
      });
      const stop = async () => { await daemon.close(); process.exit(0); };
      process.once('SIGTERM', stop);
      process.once('SIGINT', stop);
      setInterval(() => {}, 1000);
    """
    process = subprocess.Popen(
        [node, "--input-type=module", "-e", script, str(port), token, str(tmp_path)],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("Node daemon exited early: %s" % (process.stderr.read() or ""))
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                break
        except OSError:
            time.sleep(0.02)
    else:
        process.kill()
        raise AssertionError("Node daemon did not listen in time")

    try:
        response = AgentGuardBridge(timeout=0.5)._socket_exchange(
            {"kind": "tcp", "port": port, "token": token},
            {
                "version": 1,
                "id": "python-node-integration",
                "action": {
                    "rawInput": {"input": "safe integration request"},
                    "actionType": "llm_request",
                    "sessionId": "session-1",
                    "phase": "pre",
                },
            },
        )
        assert response == {
            "version": 1,
            "id": "python-node-integration",
            "ok": True,
            "result": None,
        }
    finally:
        process.terminate()
        process.wait(timeout=2)


def _read_line(connection):
    chunks = []
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("connection ended before newline")
        chunks.append(chunk)
        buffered = b"".join(chunks)
        newline = buffered.find(b"\n")
        if newline >= 0:
            return buffered[:newline]
