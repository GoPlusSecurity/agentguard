"""Persistent local IPC bridge from Hermes to the AgentGuard Node evaluator.

Native plugin events use one current-user daemon rather than starting Node for
every prompt or tool call. The daemon still runs the shared ``protectAction``
path, so detection and redacted audit logic remain centralized. Injected legacy
runners are retained only as a deterministic compatibility seam for tests.

Blocking pre-tool IPC failures fail closed unless
``AGENTGUARD_HERMES_FAIL_OPEN=1``. Model request/response hooks are observers;
their failures and block-class policy results can warn but cannot stop Hermes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

# Hermes tool name -> AgentGuard runtime action type.
# Mirrors runtimeActionTypeFrom() in skills/agentguard/scripts/hermes-hook.js and
# the TOOL_ACTION_MAP keys in src/adapters/hermes.ts. Passing the action type
# explicitly is required because `agentguard protect`'s generic heuristic would
# otherwise classify e.g. "terminal" as "other".
TOOL_ACTION_TYPE: Dict[str, str] = {
    "terminal": "shell",
    "execute_code": "shell",
    "write_file": "file_write",
    "patch": "file_write",
    "skill_manage": "file_write",
    "read_file": "file_read",
    "web_search": "web_search",
    "web_extract": "network",
    "browser_navigate": "network",
    "browser_open": "network",
    "web_open": "network",
    "open_url": "network",
    "visit_url": "network",
    "open": "network",
}

# Tools outside this set are out of scope and allowed without invoking the engine
# (mirrors the shell-hook matchers and avoids the unknown-tool fail-closed path).
MAPPED_TOOLS = frozenset(TOOL_ACTION_TYPE)

# Required tool_input fields per mapped tool. A mapped, security-sensitive event
# missing its required field is malformed and is blocked (fail-closed), mirroring
# validatePreToolPayload() in skills/agentguard/scripts/hermes-hook.js.
_REQUIRED_FIELDS: Dict[str, tuple] = {
    "terminal": ("command",),
    "execute_code": ("code", "command"),
    "write_file": ("path", "file_path"),
    "patch": ("path", "file_path"),
    "read_file": ("path", "file_path"),
    "skill_manage": ("path", "file_path", "target", "skill_path"),
    "web_search": ("query", "url"),
    "web_extract": ("url", "href", "target"),
    "browser_navigate": ("url", "href", "target"),
    "browser_open": ("url", "href", "target"),
    "web_open": ("url", "href", "target"),
    "open_url": ("url", "href", "target"),
    "visit_url": ("url", "href", "target"),
    "open": ("url", "href", "target"),
}

# Hermes pre_tool_call has no native "ask"; AgentGuard's confirm maps to a block.
_BLOCK_DECISIONS = frozenset({"block", "confirm"})

_DEFAULT_BLOCK_MESSAGE = "GoPlus AgentGuard blocked this action"
_IPC_VERSION = 1
_DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024
_DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
_WINDOWS_PORT_BASE = 40000
_WINDOWS_PORT_SPAN = 20000

_LLM_REQUEST_MISSING_FACTS = [
    "complete_payload",
    "final_destination",
    "credential_kind",
    "credential_presence",
    "exact_payload_bytes",
    "attachment_bytes",
    "file_path_count",
    "retry_and_fallback",
    "auxiliary_model_calls",
]
_LLM_RESPONSE_MISSING_FACTS = [
    "complete_response",
    "final_destination",
    "credential_kind",
    "credential_presence",
    "retry_and_fallback",
    "auxiliary_model_calls",
    "response_source",
]


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"", "0", "false", "no", "off"}


class AgentGuardBridge:
    """Evaluates Hermes tool calls through the AgentGuard engine."""

    def __init__(
        self,
        runner: Optional[Callable[[list, str], Any]] = None,
        mode: str = "protect",
        timeout: Optional[float] = None,
        transport: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> None:
        # ``runner`` lets tests inject a deterministic engine without spawning a
        # subprocess. When set, invocation resolution is bypassed and ``mode``
        # selects how the runner's stdout is interpreted ("protect" or "hook").
        self._runner = runner
        self._test_mode = mode
        self._transport = transport
        self._daemon_lock = threading.Lock()
        self._daemon_process: Optional[subprocess.Popen] = None
        if timeout is None:
            try:
                timeout = float(os.environ.get("AGENTGUARD_HERMES_TIMEOUT", "10"))
            except ValueError:
                timeout = 10.0
        self.timeout = timeout

    # -- public API --------------------------------------------------------

    def evaluate(
        self,
        event: str,
        tool_name: str,
        args: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        cwd: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """Return a Hermes block dict, or ``None`` to allow.

        ``{"action": "block", "message": ...}`` vetoes the tool call.
        """
        phase = "post" if event.startswith("post") else "pre"
        if tool_name not in TOOL_ACTION_TYPE:
            return None  # out of scope -> allow without invoking the engine

        if phase == "pre":
            # A malformed mapped-tool payload is blocked unconditionally (even
            # under fail-open): we can't evaluate what we can't read.
            missing = _validate_mapped_payload(tool_name, args or {})
            if missing:
                return _block("GoPlus AgentGuard: %s" % missing)

        if self._runner is None:
            try:
                result = self._evaluate_daemon(
                    action_type=TOOL_ACTION_TYPE[tool_name],
                    tool_name=tool_name,
                    raw_input=_build_payload(event, tool_name, args, session_id, cwd, task_id),
                    session_id=session_id,
                    phase=phase,
                )
            except Exception as exc:
                return self._fail(phase, "AgentGuard evaluator IPC failed: %s" % exc)
            if phase == "post" or not result:
                return None
            if result.get("decision") in {"block", "require_approval"}:
                return _block(None)
            return None

        argv, mode = self._invocation()
        if argv is None:
            return self._fail(
                phase,
                "AgentGuard engine not found; install @goplus/agentguard or set "
                "AGENTGUARD_BIN / AGENTGUARD_HERMES_HOOK",
            )

        payload = _build_payload(event, tool_name, args, session_id, cwd, task_id)
        cmd = list(argv)
        if mode == "protect":
            cmd += [
                "--agent", "hermes",
                "--action-type", TOOL_ACTION_TYPE[tool_name],
                "--tool-name", tool_name,
                "--json",
            ]
            if session_id:
                cmd += ["--session-id", session_id]

        try:
            proc = self._run(cmd, json.dumps(payload))
        except subprocess.TimeoutExpired:
            return self._fail(phase, "AgentGuard evaluation timed out")
        except (OSError, ValueError) as exc:
            return self._fail(phase, "AgentGuard evaluation failed to start: %s" % exc)

        if phase == "post":
            return None  # post hooks are audit-only; never block
        return self._interpret(mode, proc)

    def observe_llm_request(self, **kwargs: Any) -> Optional[Dict[str, Any]]:
        """Evaluate the visible per-API-call request as an observer-only event."""
        return self._observe_llm("llm_request", "model_request", "pre", kwargs)

    def observe_llm_response(self, **kwargs: Any) -> Optional[Dict[str, Any]]:
        """Evaluate the visible per-API-call response as an observer-only event."""
        return self._observe_llm("llm_response", "model_response", "post", kwargs)

    def _observe_llm(
        self,
        action_type: str,
        lifecycle_stage: str,
        phase: str,
        fields: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        request_id, session_id = _llm_correlation(fields)
        if action_type == "llm_request":
            visible = fields.get("request_messages")
            if visible is None:
                visible = fields.get("request")
            missing_facts = list(_LLM_REQUEST_MISSING_FACTS)
        else:
            visible = fields.get("assistant_message")
            if visible is None:
                visible = fields.get("response")
            missing_facts = list(_LLM_RESPONSE_MISSING_FACTS)

        raw_input = _build_llm_payload(
            visible=visible,
            fields=fields,
            request_id=request_id,
            session_id=session_id,
            lifecycle_stage=lifecycle_stage,
            missing_facts=missing_facts,
        )
        return self._evaluate_daemon(
            action_type=action_type,
            tool_name="hermes.%s" % ("pre_api_request" if phase == "pre" else "post_api_request"),
            raw_input=raw_input,
            session_id=session_id,
            phase=phase,
            request_id=request_id,
        )

    def run_cli(self, args: list) -> str:
        """Run an ``agentguard`` subcommand and return stdout (for /agentguard)."""
        bin_path = os.environ.get("AGENTGUARD_BIN") or shutil.which("agentguard")
        if not bin_path:
            if _env_truthy("AGENTGUARD_HERMES_ALLOW_NPX") and shutil.which("npx"):
                cmd = ["npx", "-y", "@goplus/agentguard", *args]
            else:
                return "AgentGuard CLI not found. Install @goplus/agentguard (or set AGENTGUARD_BIN)."
        else:
            cmd = [bin_path, *args]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, encoding="utf-8"
            )
        except subprocess.SubprocessError as exc:
            return "AgentGuard CLI failed: %s" % exc
        return (proc.stdout or proc.stderr or "").strip()

    # -- internals ---------------------------------------------------------

    def _evaluate_daemon(
        self,
        action_type: str,
        tool_name: str,
        raw_input: Dict[str, Any],
        session_id: Optional[str],
        phase: str,
        request_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        wire = {
            "version": _IPC_VERSION,
            "id": request_id or str(uuid.uuid4()),
            "action": {
                "rawInput": raw_input,
                "actionType": action_type,
                "toolName": tool_name,
                "sessionId": session_id,
                "phase": phase,
            },
        }
        response = self._send_wire_request(wire)
        if not isinstance(response, dict):
            raise ValueError("evaluator returned a non-object response")
        if response.get("version") != _IPC_VERSION or response.get("id") != wire["id"]:
            raise ValueError("evaluator returned a mismatched response")
        if response.get("ok") is not True:
            error = response.get("error")
            if isinstance(error, dict):
                raise RuntimeError(str(error.get("code") or error.get("message") or "evaluation failed"))
            raise RuntimeError("evaluation failed")
        result = response.get("result")
        if result is None:
            return None
        if not isinstance(result, dict):
            raise ValueError("evaluator returned an invalid result")
        return result

    def _send_wire_request(self, wire: Dict[str, Any]) -> Dict[str, Any]:
        if self._transport is not None:
            return self._transport(wire)

        endpoint = self._ipc_endpoint()
        try:
            return self._socket_exchange(endpoint, wire)
        except OSError as exc:
            if not _daemon_unavailable(exc):
                raise

        with self._daemon_lock:
            try:
                return self._socket_exchange(endpoint, wire)
            except OSError as exc:
                if not _daemon_unavailable(exc):
                    raise
            self._launch_daemon(endpoint)

        deadline = time.monotonic() + min(max(self.timeout, 0.1), 10.0)
        last_error: Optional[OSError] = None
        while time.monotonic() < deadline:
            try:
                return self._socket_exchange(endpoint, wire)
            except OSError as exc:
                if not _daemon_unavailable(exc):
                    raise
                last_error = exc
                time.sleep(0.05)
        raise last_error or TimeoutError("Hermes evaluator daemon did not become ready")

    def _socket_exchange(self, endpoint: Dict[str, Any], wire: Dict[str, Any]) -> Dict[str, Any]:
        request = dict(wire)
        if endpoint["kind"] == "tcp":
            request["authProof"] = "0" * 64
        payload = (json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(payload) > _DEFAULT_MAX_REQUEST_BYTES:
            raise ValueError("Hermes evaluator request exceeded the byte limit")

        if endpoint["kind"] == "unix":
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            address: Any = endpoint["path"]
        else:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            address = ("127.0.0.1", endpoint["port"])

        deadline = time.monotonic() + self.timeout
        with client:
            client.settimeout(_remaining_timeout(deadline))
            client.connect(address)
            if endpoint["kind"] == "tcp":
                client_nonce = secrets.token_hex(32)
                hello = {
                    "version": _IPC_VERSION,
                    "id": wire["id"],
                    "kind": "hello",
                    "clientNonce": client_nonce,
                }
                client.settimeout(_remaining_timeout(deadline))
                client.sendall(
                    (json.dumps(hello, separators=(",", ":")) + "\n").encode("utf-8")
                )
                challenge = _receive_json_frame(client, deadline)
                server_nonce = challenge.get("serverNonce")
                expected = _authentication_proof(
                    endpoint["token"], "server", wire["id"], client_nonce, server_nonce
                ) if isinstance(server_nonce, str) else ""
                if (
                    challenge.get("version") != _IPC_VERSION
                    or challenge.get("id") != wire["id"]
                    or challenge.get("kind") != "challenge"
                    or not _valid_nonce(server_nonce)
                    or not isinstance(challenge.get("serverProof"), str)
                    or not hmac.compare_digest(challenge["serverProof"], expected)
                ):
                    raise ValueError("Hermes evaluator server authentication failed")
                request["authProof"] = _authentication_proof(
                    endpoint["token"], "client", wire["id"], client_nonce, server_nonce
                )
                payload = (
                    json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n"
                ).encode("utf-8")
            client.settimeout(_remaining_timeout(deadline))
            client.sendall(payload)
            return _receive_json_frame(client, deadline)

    def _ipc_endpoint(self) -> Dict[str, Any]:
        if os.name != "nt":
            home = Path(os.environ.get("AGENTGUARD_HOME") or (Path.home() / ".agentguard"))
            return {"kind": "unix", "path": str(home / "run" / "hermes-evaluator.sock")}
        home = Path(os.environ.get("AGENTGUARD_HOME") or (Path.home() / ".agentguard"))
        raw_port = os.environ.get(
            "AGENTGUARD_HERMES_IPC_PORT", str(_default_windows_port(home))
        )
        try:
            port = int(raw_port)
        except ValueError as exc:
            raise ValueError("AGENTGUARD_HERMES_IPC_PORT must be an integer") from exc
        if port < 1 or port > 65535:
            raise ValueError("AGENTGUARD_HERMES_IPC_PORT must be between 1 and 65535")
        return {"kind": "tcp", "port": port, "token": self._windows_ipc_token()}

    def _windows_ipc_token(self) -> str:
        configured = os.environ.get("AGENTGUARD_HERMES_IPC_TOKEN", "").strip()
        if len(configured.encode("utf-8")) >= 32:
            return configured
        home = Path(os.environ.get("AGENTGUARD_HOME") or (Path.home() / ".agentguard"))
        run_dir = home / "run"
        run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(run_dir, 0o700)
        except OSError:
            pass
        token_path = run_dir / "hermes-evaluator.token"
        try:
            token = token_path.read_text(encoding="utf-8").strip()
        except OSError:
            token = ""
        if len(token.encode("utf-8")) < 32:
            candidate = secrets.token_urlsafe(32)
            candidate_path = run_dir / (
                ".hermes-evaluator.token.%s.%s" % (os.getpid(), secrets.token_hex(16))
            )
            try:
                candidate_path.write_text(candidate, encoding="utf-8")
                try:
                    os.chmod(candidate_path, 0o600)
                except OSError:
                    pass
                try:
                    os.link(candidate_path, token_path)
                except FileExistsError:
                    pass
            finally:
                try:
                    candidate_path.unlink()
                except FileNotFoundError:
                    pass
            try:
                token = token_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise RuntimeError("Unable to create the Hermes IPC token") from exc
            if len(token.encode("utf-8")) < 32:
                raise RuntimeError("The Hermes IPC token file is invalid")
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            pass
        return token

    def _launch_daemon(self, endpoint: Dict[str, Any]) -> None:
        bin_path = os.environ.get("AGENTGUARD_BIN") or shutil.which("agentguard")
        if not bin_path:
            raise FileNotFoundError("AgentGuard CLI not found; set AGENTGUARD_BIN")
        env = dict(os.environ)
        env["AGENTGUARD_HERMES_PYTHON"] = sys.executable
        if endpoint["kind"] == "tcp":
            env["AGENTGUARD_HERMES_IPC_PORT"] = str(endpoint["port"])
            env["AGENTGUARD_HERMES_IPC_TOKEN"] = endpoint["token"]
        popen_kwargs: Dict[str, Any] = {
            "env": env,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_kwargs["start_new_session"] = True
        self._daemon_process = subprocess.Popen([bin_path, "hermes-daemon"], **popen_kwargs)

    def _run(self, cmd: list, input_text: str) -> Any:
        if self._runner is not None:
            return self._runner(cmd, input_text)
        return subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            encoding="utf-8",
        )

    def _invocation(self):
        if self._runner is not None:
            return (["<test-engine>"], self._test_mode)
        return self._resolve_invocation()

    @staticmethod
    def _resolve_invocation():
        hook = os.environ.get("AGENTGUARD_HERMES_HOOK")
        if hook and Path(hook).is_file():
            node = shutil.which("node")
            if node:
                return ([node, hook], "hook")

        bin_path = os.environ.get("AGENTGUARD_BIN") or shutil.which("agentguard")
        if bin_path:
            return ([bin_path, "protect"], "protect")

        skill_hook = Path.home() / ".hermes" / "skills" / "agentguard" / "scripts" / "hermes-hook.js"
        node = shutil.which("node")
        if node and skill_hook.is_file():
            return ([node, str(skill_hook)], "hook")

        # npx fetches an unpinned package over the network — unsafe for a
        # security gate, so it is opt-in only.
        if _env_truthy("AGENTGUARD_HERMES_ALLOW_NPX") and shutil.which("npx"):
            return (["npx", "-y", "@goplus/agentguard", "protect"], "protect")

        return (None, None)

    def _interpret(self, mode: str, proc: Any) -> Optional[Dict[str, str]]:
        out = (getattr(proc, "stdout", "") or "").strip()

        if mode == "hook":
            data = _safe_json(out)
            if isinstance(data, dict) and (data.get("action") == "block" or data.get("block") is True):
                return _block(data.get("message") or data.get("reason"))
            return None

        # protect mode: empty stdout means a null (low-risk / safe) result -> allow.
        if not out:
            return None
        data = _safe_json(out)
        if not isinstance(data, dict):
            return _block(None) if getattr(proc, "returncode", 0) == 2 else None
        if data.get("decision") in _BLOCK_DECISIONS:
            return _block(_format_reason(data))
        return None

    @staticmethod
    def _fail(phase: str, reason: str) -> Optional[Dict[str, str]]:
        if phase == "post":
            return None
        if _env_truthy("AGENTGUARD_HERMES_FAIL_OPEN"):
            return None
        return _block("GoPlus AgentGuard: %s; blocking fail-closed" % reason)


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Hermes evaluator IPC timed out")
    return remaining


def _default_windows_port(home: Path) -> int:
    digest = hashlib.sha256(os.path.abspath(str(home)).encode("utf-8")).digest()
    return _WINDOWS_PORT_BASE + (int.from_bytes(digest[:4], "big") % _WINDOWS_PORT_SPAN)


def _receive_json_frame(client: socket.socket, deadline: float) -> Dict[str, Any]:
    chunks = []
    total = 0
    while True:
        client.settimeout(_remaining_timeout(deadline))
        chunk = client.recv(65536)
        if not chunk:
            raise ValueError("Hermes evaluator response ended before a newline frame")
        total += len(chunk)
        if total > _DEFAULT_MAX_RESPONSE_BYTES:
            raise ValueError("Hermes evaluator response exceeded the byte limit")
        chunks.append(chunk)
        buffered = b"".join(chunks)
        newline = buffered.find(b"\n")
        if newline < 0:
            continue
        if buffered[newline + 1:].strip():
            raise ValueError("Hermes evaluator returned multiple response frames")
        value = json.loads(buffered[:newline].decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Hermes evaluator returned a non-object response")
        return value


def _valid_nonce(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _authentication_proof(
    token: str,
    role: str,
    request_id: str,
    client_nonce: str,
    server_nonce: str,
) -> str:
    message = "\0".join(
        [role, str(_IPC_VERSION), request_id, client_nonce, server_nonce]
    ).encode("utf-8")
    return hmac.new(token.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _validate_mapped_payload(tool_name: str, args: Dict[str, Any]) -> Optional[str]:
    """Return an error string if a mapped tool's required field is missing."""
    fields = _REQUIRED_FIELDS.get(tool_name)
    if not fields:
        return None
    for field in fields:
        value = args.get(field)
        if isinstance(value, str) and value:
            return None
    return "Hermes %s payload is missing %s" % (tool_name, " / ".join(fields))


def _build_payload(event, tool_name, args, session_id, cwd, task_id) -> Dict[str, Any]:
    return {
        "hook_event_name": event,
        "tool_name": tool_name,
        "tool_input": args or {},
        "session_id": session_id,
        "cwd": cwd,
        "extra": {"task_id": task_id} if task_id else {},
    }


def _build_llm_payload(
    visible: Any,
    fields: Dict[str, Any],
    request_id: str,
    session_id: str,
    lifecycle_stage: str,
    missing_facts: list,
) -> Dict[str, Any]:
    try:
        content = json.dumps(visible if visible is not None else {}, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        content = json.dumps(str(visible), ensure_ascii=False)
    llm: Dict[str, Any] = {
        "schemaVersion": 1,
        "requestId": request_id,
        "sessionId": session_id,
        "purpose": "conversation",
        "lifecycleStage": lifecycle_stage,
        "canBlockCurrentAction": False,
        "credentialKind": "unknown",
        "credentialPresent": "unknown",
    }
    for source, target in (("provider", "provider"), ("model", "model"), ("api_mode", "apiMode")):
        value = _first_string(fields.get(source))
        if value:
            llm[target] = value
    message_count = fields.get("message_count")
    if isinstance(message_count, int) and not isinstance(message_count, bool) and message_count >= 0:
        llm["messageCount"] = message_count
    elif isinstance(visible, list):
        llm["messageCount"] = len(visible)
    destination = _visible_destination(fields.get("base_url"))
    if destination:
        llm["destination"] = destination
    return {
        "input": content,
        "lifecycleStage": lifecycle_stage,
        "canBlockCurrentAction": False,
        "coverageLevel": "observe_only",
        "missingFacts": missing_facts,
        "llm": llm,
    }


def _llm_correlation(fields: Dict[str, Any]) -> tuple[str, str]:
    """Derive stable request/response IDs from facts shared by both Hermes hooks."""
    explicit_request_id = _first_string(fields.get("api_request_id"))
    explicit_session_id = _first_string(fields.get("session_id"))
    task_id = _first_string(fields.get("task_id"))
    turn_id = _first_string(fields.get("turn_id"))
    session_id = explicit_session_id or task_id or turn_id or "hermes-%s" % uuid.uuid4()
    if explicit_request_id:
        return explicit_request_id, session_id

    api_call_count = fields.get("api_call_count")
    if isinstance(api_call_count, bool) or not isinstance(api_call_count, (int, str)):
        api_call_count = ""
    per_call_facts = [task_id, turn_id, str(api_call_count)]
    if any(per_call_facts):
        correlation_facts = [session_id, *per_call_facts]
        digest = hashlib.sha256(
            json.dumps(correlation_facts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return "hermes-%s" % digest[:32], session_id
    return str(uuid.uuid4()), session_id


def _visible_destination(value: Any) -> Optional[Dict[str, Any]]:
    raw = _first_string(value)
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
        if not parsed.hostname:
            return None
        destination: Dict[str, Any] = {"host": parsed.hostname}
        if parsed.scheme:
            destination["scheme"] = parsed.scheme
        try:
            if parsed.port is not None:
                destination["port"] = parsed.port
        except ValueError:
            return None
        if parsed.path:
            destination["path"] = parsed.path
        return destination
    except (TypeError, ValueError):
        return None


def _first_string(value: Any) -> str:
    return value if isinstance(value, str) and value else ""


def _daemon_unavailable(error: OSError) -> bool:
    return getattr(error, "errno", None) in {
        getattr(os, "ENOENT", 2),
        getattr(os, "ECONNREFUSED", 61),
        2,
        61,
        111,
        10061,
    }


def _safe_json(text: str) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _block(message: Optional[str]) -> Dict[str, str]:
    return {"action": "block", "message": message or _DEFAULT_BLOCK_MESSAGE}


def _format_reason(data: Dict[str, Any]) -> str:
    titles = []
    for reason in data.get("reasons") or []:
        if isinstance(reason, dict) and reason.get("title"):
            titles.append(str(reason["title"]))
    titles = titles[:3]
    risk = data.get("riskScore")
    level = data.get("riskLevel")
    verb = "requires confirmation for" if data.get("decision") == "confirm" else "blocked"
    base = "GoPlus AgentGuard %s this Hermes tool call (risk: %s/100, level: %s)." % (
        verb, risk, level,
    )
    if titles:
        base += " Reasons: %s." % ", ".join(titles)
    return base
