"""Hermes model-request hooks are local observers, never request gates."""

import logging

from helpers import make_ipc_transport, register_with_transport


def _would_block_result():
    return {
        "decision": "warn",
        "policyDecision": "block",
        "actionId": "action-request-1",
        "riskScore": 95,
        "riskLevel": "critical",
        "reasons": [{"title": "Personal data in visible LLM payload"}],
        "policyVersion": "test",
        "policySource": "default",
        "coverageLevel": "observe_only",
        "enforcementStatus": "would_block",
        "canBlockCurrentAction": False,
        "missingFacts": ["complete_payload", "final_destination"],
    }


def test_registers_supported_llm_hooks_without_inventing_a_gate():
    ctx, _ = register_with_transport(make_ipc_transport())

    assert {"pre_llm_call", "pre_api_request", "post_api_request", "pre_tool_call"} <= set(ctx.hooks)
    assert "before_model_request" not in ctx.hooks
    assert "after_model_response" not in ctx.hooks


def test_pre_llm_call_is_a_non_mutating_turn_observer():
    calls = []
    ctx, _ = register_with_transport(make_ipc_transport(calls=calls))

    result = ctx.hooks["pre_llm_call"](
        session_id="session-1",
        turn_id="turn-1",
        user_message="hello",
        conversation_history=[],
        model="gpt-test",
        platform="cli",
    )

    assert result is None
    assert calls == []


def test_pre_api_request_maps_visible_facts_but_never_blocks(caplog):
    calls = []
    ctx, _ = register_with_transport(make_ipc_transport(_would_block_result(), calls=calls))

    with caplog.at_level(logging.WARNING):
        result = ctx.hooks["pre_api_request"](
            session_id="session-1",
            turn_id="turn-1",
            api_request_id="api-request-1",
            request_messages=[{"role": "user", "content": "email private.person@example.invalid"}],
            provider="openai-compatible",
            model="model-1",
            base_url="https://relay.example/v1",
            api_mode="chat.completions",
            message_count=1,
            tool_count=3,
        )

    assert result is None
    assert len(calls) == 1
    wire = calls[0]
    assert wire["id"] == "api-request-1"
    assert wire["action"]["actionType"] == "llm_request"
    assert wire["action"]["phase"] == "pre"
    raw = wire["action"]["rawInput"]
    assert "private.person@example.invalid" in raw["input"]
    assert raw["lifecycleStage"] == "model_request"
    assert raw["canBlockCurrentAction"] is False
    assert raw["coverageLevel"] == "observe_only"
    assert "enforcementStatus" not in raw
    assert raw["llm"]["requestId"] == "api-request-1"
    assert raw["llm"]["provider"] == "openai-compatible"
    assert raw["llm"]["model"] == "model-1"
    assert raw["llm"]["apiMode"] == "chat.completions"
    assert raw["llm"]["messageCount"] == 1
    assert raw["llm"]["destination"] == {
        "scheme": "https",
        "host": "relay.example",
        "path": "/v1",
    }
    assert "complete_payload" in raw["missingFacts"]
    assert "final_destination" in raw["missingFacts"]
    assert "credential_presence" in raw["missingFacts"]
    assert "auxiliary_model_calls" in raw["missingFacts"]
    assert "would_block" in caplog.text
    assert "api-request-1" in caplog.text


def test_pre_api_request_accepts_sanitized_request_on_newer_hermes():
    calls = []
    ctx, _ = register_with_transport(make_ipc_transport(calls=calls))

    ctx.hooks["pre_api_request"](
        session_id="session-2",
        api_request_id="api-request-2",
        request={"messages": [{"role": "user", "content": "sanitized view"}], "tools": ["bounded"]},
        provider="anthropic",
        model="claude-test",
        base_url="https://api.anthropic.com",
    )

    assert "sanitized view" in calls[0]["action"]["rawInput"]["input"]
    assert "complete_payload" in calls[0]["action"]["rawInput"]["missingFacts"]


def test_request_and_response_share_fallback_correlation_ids():
    calls = []
    ctx, _ = register_with_transport(make_ipc_transport(calls=calls))

    common = {
        "turn_id": "turn-without-api-id",
        "api_call_count": 2,
        "task_id": "task-1",
        "provider": "openai-compatible",
    }
    ctx.hooks["pre_api_request"](
        **common,
        request_messages=[{"role": "user", "content": "hello"}],
    )
    ctx.hooks["post_api_request"](
        **common,
        assistant_message={"role": "assistant", "content": "hi"},
    )

    assert calls[0]["id"] == calls[1]["id"]
    assert calls[0]["action"]["sessionId"] == calls[1]["action"]["sessionId"]

    ctx.hooks["pre_api_request"](
        **common,
        session_id="different-session",
        request_messages=[{"role": "user", "content": "hello again"}],
    )
    assert calls[2]["id"] != calls[0]["id"]


def test_session_id_alone_does_not_claim_per_call_correlation():
    calls = []
    ctx, _ = register_with_transport(make_ipc_transport(calls=calls))

    ctx.hooks["pre_api_request"](
        session_id="session-only",
        request_messages=[{"role": "user", "content": "hello"}],
    )
    ctx.hooks["post_api_request"](
        session_id="session-only",
        assistant_message={"role": "assistant", "content": "hi"},
    )

    assert calls[0]["id"] != calls[1]["id"]
