"""A failed Oracle adjudication says what failed (soc_ai.oracle.failures).

Production filed 23 gateway HTTP 500 answers as ``no_parseable_verdict`` from
2026-09-10 to 2026-09-14. Each 500 carried the message that the subscription
behind the Oracle route had hit its weekly limit. The failure event had no
status and no text. Now the event carries the HTTP status, the error class and
the gateway's message, secret-scrubbed, and ``no_parseable_verdict`` means
one thing only: a 200 whose body held no verdict.

These tests drive the REAL ``_call_oracle_raw`` over an ``httpx.MockTransport``
fake gateway, so the status, the body and the header travel the real path.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import SecretStr
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import investigate
from soc_ai.config import Settings
from soc_ai.oracle import failures
from soc_ai.oracle.client import adjudicate
from soc_ai.triage_models import TriageReport
from soc_ai.webui.timeline_labels import title_for

from tests.test_agent import _make_ctx, _malware_signal_enriched

GATEWAY_KEY = "sk-planted-gateway-key-0123456789"

WEEKLY_LIMIT_BODY = json.dumps(
    {
        "error": {
            "message": (
                "litellm.InternalServerError: AnthropicException - api_error: Claude Code "
                "returned an error result: You've hit your weekly limit · resets Sep 14, "
                f"5am (UTC). Received Authorization: Bearer {GATEWAY_KEY}. "
                "password=hunter2-planted"
            ),
            "type": None,
            "param": None,
            "code": "500",
        }
    }
)


def _settings() -> Settings:
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://gateway.example.test:4000",
        litellm_api_key=SecretStr(GATEWAY_KEY),
        oracle_enabled=True,
        oracle_model="claude-sonnet-4-6",
        oracle_timeout_s=30.0,
    )


def _ctx(settings: Settings) -> Any:
    ctx = MagicMock()
    ctx.settings = settings
    return ctx


def _report() -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="Local summary.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )


def _enriched() -> Any:
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(id="alert-001", severity_label="low"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _completion(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


async def _adjudicate_against(
    handler: Callable[[httpx.Request], httpx.Response],
) -> tuple[Any, dict[str, Any], list[httpx.Request]]:
    """Run the single-shot adjudication against a fake gateway; return the calls."""
    seen: list[httpx.Request] = []
    real_client = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    def _client(**kw: Any) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(_handler), **kw)

    failure: dict[str, Any] = {}
    with (
        patch("httpx.AsyncClient", _client),
        patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()),
    ):
        result = await adjudicate(
            _ctx(_settings()),
            enriched=_enriched(),
            local_report=_report(),
            transcript_text="",
            failure_out=failure,
        )
    return result, failure, seen


async def test_a_weekly_limit_500_is_a_quota_gateway_error_with_its_message() -> None:
    result, failure, calls = await _adjudicate_against(
        lambda _r: httpx.Response(500, text=WEEKLY_LIMIT_BODY)
    )
    assert result is None
    assert calls, "the fake gateway was never called"
    # The 09-10 to 09-14 label: a 500 is never an unparseable answer.
    assert failure["reason"] == "gateway_error"
    assert failure["error_class"] == "quota"
    assert failure["http_status"] == 500
    assert "You've hit your weekly limit" in failure["message"]
    assert "resets Sep 14, 5am (UTC)" in failure["message"]
    # Secret-scrubbed: the configured key, the bearer token and a credential value.
    assert GATEWAY_KEY not in failure["message"]
    assert "hunter2-planted" not in failure["message"]
    assert len(failure["message"]) <= failures.MESSAGE_LIMIT


async def test_a_200_with_prose_is_the_only_unparseable_answer() -> None:
    result, failure, calls = await _adjudicate_against(
        lambda _r: _completion("I think this is probably fine, but I cannot be sure.")
    )
    assert result is None
    assert len(calls) == 3
    assert failure["reason"] == "no_parseable_verdict"
    assert failure["error_class"] == "unparseable"
    assert failure["http_status"] == 200
    assert failure["message"].startswith("The answer held no JSON verdict. It began: I think")


async def test_a_plain_500_is_a_5xx_gateway_error() -> None:
    result, failure, _calls = await _adjudicate_against(
        lambda _r: httpx.Response(502, json={"error": {"message": "upstream connect error"}})
    )
    assert result is None
    assert (failure["reason"], failure["error_class"], failure["http_status"]) == (
        "gateway_error",
        "5xx",
        502,
    )
    assert failure["message"] == "upstream connect error"


async def test_the_last_attempt_decides_the_class() -> None:
    """Two 500s then a 200 with prose: the answer that ended the loop was unparseable.

    Negative control on the other order: two prose answers then a 500 is a
    gateway error. A label that kept the first class would pass one of these.
    """
    answers = iter(
        [
            httpx.Response(500, text="boom"),
            httpx.Response(500, text="boom"),
            _completion("no json here"),
        ]
    )
    _r, failure, _c = await _adjudicate_against(lambda _r: next(answers))
    assert (failure["reason"], failure["error_class"]) == ("no_parseable_verdict", "unparseable")

    answers2 = iter(
        [
            _completion("no json here"),
            _completion("no json here"),
            httpx.Response(503, text="overloaded"),
        ]
    )
    _r, failure2, _c = await _adjudicate_against(lambda _r: next(answers2))
    assert (failure2["reason"], failure2["error_class"], failure2["http_status"]) == (
        "gateway_error",
        "5xx",
        503,
    )


async def test_a_401_fails_fast_as_a_4xx() -> None:
    result, failure, calls = await _adjudicate_against(
        lambda _r: httpx.Response(401, json={"error": {"message": "Authentication Error"}})
    )
    assert result is None
    assert len(calls) == 1
    assert (failure["reason"], failure["error_class"], failure["http_status"]) == (
        "gateway_error",
        "4xx",
        401,
    )


async def test_a_429_is_quota() -> None:
    _r, failure, _c = await _adjudicate_against(
        lambda _r: httpx.Response(429, json={"error": {"message": "slow down"}})
    )
    assert (failure["error_class"], failure["http_status"]) == ("quota", 429)


async def test_a_timeout_is_a_timeout() -> None:
    def _raise(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    _r, failure, calls = await _adjudicate_against(_raise)
    assert len(calls) == 3
    assert (failure["reason"], failure["error_class"]) == ("gateway_error", "timeout")
    assert "http_status" not in failure


def test_the_classifier_and_the_scrubber() -> None:
    assert failures.classify_http_failure(500, "You've hit your weekly limit") == "quota"
    assert failures.classify_http_failure(500, "Internal error") == "5xx"
    assert failures.classify_http_failure(400, "rate_limit_error") == "quota"
    assert failures.classify_http_failure(404, "model not found") == "4xx"
    scrubbed = failures.scrub_message(
        f"key {GATEWAY_KEY} api_key=abc123def", secrets=(GATEWAY_KEY,)
    )
    assert GATEWAY_KEY not in scrubbed and "abc123def" not in scrubbed


def test_the_timeline_title_names_the_class() -> None:
    title = title_for("oracle_adjudication_failed", {"error_class": "quota", "http_status": 500})
    assert title == (
        "Oracle second opinion failed: the Oracle route hit a usage limit, HTTP 500. "
        "The local verdict stands"
    )
    # An event from before the class existed keeps the old title.
    assert title_for("oracle_adjudication_failed", {"reason": "no_parseable_verdict"}) == (
        "Oracle second opinion failed. The local verdict stands"
    )


async def test_the_failure_event_carries_the_truth(settings_kratos: Settings) -> None:
    """The orchestrator copies the status, the class and the message onto the event."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.oracle_enabled = True
    ctx = _make_ctx(settings_kratos)
    local_fp = TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="Local verdict: benign.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)

    async def _failing(*_a: Any, **kw: Any) -> None:
        kw["failure_out"].update(
            {
                "reason": "gateway_error",
                "error_class": "quota",
                "http_status": 500,
                "message": "You've hit your weekly limit",
            }
        )

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=local_fp),
        ),
        patch("soc_ai.oracle.client.adjudicate", new=AsyncMock(side_effect=_failing)),
    ):
        events = [ev async for ev in investigate("beacon-001", ctx=ctx)]
    fail_ev = next(e for e in events if e.kind == "oracle_adjudication_failed")
    assert fail_ev.payload["reason"] == "gateway_error"
    assert fail_ev.payload["error_class"] == "quota"
    assert fail_ev.payload["http_status"] == 500
    assert fail_ev.payload["message"] == "You've hit your weekly limit"


@pytest.mark.parametrize("cls", ["refused", "unparseable", "timeout"])
def test_a_200_class_title_carries_no_status(cls: str) -> None:
    title = title_for("oracle_adjudication_failed", {"error_class": cls, "http_status": 200})
    assert "HTTP" not in title
