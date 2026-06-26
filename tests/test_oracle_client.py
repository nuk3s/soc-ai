"""Tests for :mod:`soc_ai.oracle.client` — Oracle adjudication client.

All tests are hermetic: no LiteLLM, no gateway, no real network traffic.
The raw ``_call_oracle_raw`` coroutine is patched rather than a pydantic-ai
Agent, matching the new robust httpx-based implementation.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.oracle.client import OracleResult, adjudicate

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_settings(**kwargs: Any) -> Settings:
    """Build a minimal Settings instance with the Oracle enabled."""
    base: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "synth_first_pipeline": False,
        "oracle_enabled": True,
        "oracle_model": "claude-sonnet-4-6",
        "oracle_timeout_s": 30.0,
    }
    base.update(kwargs)
    return Settings(**base)


def _make_ctx(settings: Settings) -> Any:
    """Minimal InvestigationContext-like object (duck-typed)."""
    ctx = MagicMock()
    ctx.settings = settings
    return ctx


def _stub_report(verdict: str = "false_positive", confidence: float = 0.85) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        summary="Test summary.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )


def _stub_enriched(alert_id: str = "alert-001") -> Any:
    """Minimal EnrichedAlertContext (duck-typed for the case dict builder)."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(id=alert_id, severity_label="low"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _valid_verdict_json(
    verdict: str = "true_positive",
    confidence: float = 0.92,
    summary: str = "Traffic from IP_01 matched C2 beacon pattern.",
    reasoning: str = "ET MALWARE rule fired on repeated 4-second beacons.",
) -> str:
    """Return a well-formed OracleVerdict JSON string."""
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "reasoning": reasoning,
        }
    )


# ---------------------------------------------------------------------------
# Test: GUARDRAIL — residue detected → refuse, do NOT call the model
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_refuses_on_residue() -> None:
    """When unsafe_residue fires, adjudicate must return None without calling
    the oracle model."""
    settings = _make_settings()
    ctx = _make_ctx(settings)

    # Inject a private IP into the case dict so sanitize *misses* it.
    raw_case = {
        "alert_summary": {"source_ip": "192.168.1.100"},
        "loop_evidence": "",
        "local_verdict": "false_positive",
        "local_confidence": 0.85,
        "local_summary": "Some summary",
        "local_citations": [],
    }

    raw_call = AsyncMock()

    with (
        patch("soc_ai.oracle.client.sanitize_case", return_value=raw_case),
        patch("soc_ai.oracle.client._call_oracle_raw", raw_call),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
        )

    # Must refuse — model must NOT be called.
    assert result is None
    raw_call.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test: success — clean payload → Oracle returns minimal verdict JSON →
#       adjudicate returns desanitized OracleResult with oracle verdict
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_success_desanitizes_response() -> None:
    """Clean payload → oracle returns valid OracleVerdict JSON with opaque labels →
    adjudicate desanitizes summary/reasoning back to real identifiers."""
    settings = _make_settings()
    ctx = _make_ctx(settings)

    # Oracle response references opaque label IP_01; after desanitization it
    # should appear as 10.0.0.1 (the real address from the enriched context).
    oracle_response = _valid_verdict_json(
        verdict="true_positive",
        confidence=0.92,
        summary="Traffic from IP_01 matched Cobalt Strike C2 beacon pattern.",
        reasoning="ET MALWARE rule on IP_01:443.",
    )

    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    enriched_with_ip = EnrichedAlertContext(
        alert=SoAlert(id="alert-001", severity_label="high", source_ip="10.0.0.1"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )

    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(return_value=oracle_response),
    ):
        result = await adjudicate(
            ctx,
            enriched=enriched_with_ip,
            local_report=_stub_report(),
            transcript_text="Evidence: 10.0.0.1 pinged gateway.",
        )

    assert result is not None
    assert isinstance(result, OracleResult)
    assert result.report.verdict == "true_positive"
    assert result.oracle_model == "claude-sonnet-4-6"

    # The summary/reasoning contained "IP_01"; desanitization must restore "10.0.0.1".
    assert "10.0.0.1" in result.report.summary
    assert "IP_01" not in result.report.summary

    # Redaction summary must be present (safe audit metadata).
    assert isinstance(result.redaction_summary, dict)
    assert result.redaction_summary.get("IP", 0) >= 1


# ---------------------------------------------------------------------------
# Test: gateway resilience — 5xx retries with backoff, 4xx fails fast (#5)
# ---------------------------------------------------------------------------


def _enriched_min() -> Any:
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(id="alert-001", severity_label="high", source_ip="10.0.0.1"),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


@pytest.mark.asyncio
async def test_adjudicate_retries_on_5xx_then_succeeds() -> None:
    """A transient 5xx is retried (with backoff) and the next attempt's verdict
    is used — the Oracle isn't abandoned on a momentary gateway blip."""
    from soc_ai.oracle.client import _OracleGatewayError

    ctx = _make_ctx(_make_settings())
    good = _valid_verdict_json(
        verdict="true_positive",
        confidence=0.9,
        summary="IP_01 beaconed.",
        reasoning="ET MALWARE on IP_01.",
    )
    raw_call = AsyncMock(
        side_effect=[_OracleGatewayError("LiteLLM returned 503", retryable=True), good]
    )

    with (
        patch("soc_ai.oracle.client._call_oracle_raw", raw_call),
        patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()) as sleep,
    ):
        result = await adjudicate(
            ctx,
            enriched=_enriched_min(),
            local_report=_stub_report(),
            transcript_text="Evidence: 10.0.0.1 pinged gateway.",
        )

    assert result is not None
    assert result.report.verdict == "true_positive"
    assert raw_call.await_count == 2  # failed once, succeeded on retry
    sleep.assert_awaited()  # backed off before retrying


@pytest.mark.asyncio
async def test_adjudicate_fails_fast_on_4xx() -> None:
    """A 4xx (auth/bad-request) is terminal — adjudicate returns None WITHOUT
    burning the retry budget (no point retrying a 401)."""
    from soc_ai.oracle.client import _OracleGatewayError

    ctx = _make_ctx(_make_settings())
    raw_call = AsyncMock(side_effect=_OracleGatewayError("LiteLLM returned 401", retryable=False))

    with (
        patch("soc_ai.oracle.client._call_oracle_raw", raw_call),
        patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()) as sleep,
    ):
        result = await adjudicate(
            ctx,
            enriched=_enriched_min(),
            local_report=_stub_report(),
            transcript_text="Evidence.",
        )

    assert result is None  # local verdict retained
    assert raw_call.await_count == 1  # no retry on a client error
    sleep.assert_not_awaited()


# ---------------------------------------------------------------------------
# Test: robustness — JSON wrapped in a ```json fence → still parses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_parses_fenced_json() -> None:
    """When the oracle wraps its JSON in a ```json ... ``` fence, adjudicate must
    still extract and parse the verdict correctly."""
    settings = _make_settings()
    ctx = _make_ctx(settings)

    inner = _valid_verdict_json(verdict="false_positive", confidence=0.80)
    fenced_response = (
        f"Here is my assessment:\n```json\n{inner}\n```\nLet me know if you need anything else."
    )

    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(return_value=fenced_response),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
        )

    assert result is not None
    assert result.report.verdict == "false_positive"


# ---------------------------------------------------------------------------
# Test: robustness — <think> preamble wrapping the JSON → still parses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_parses_think_preamble() -> None:
    """When a reasoning model emits <think>...</think> before the JSON,
    adjudicate must strip it and still extract the verdict."""
    settings = _make_settings()
    ctx = _make_ctx(settings)

    inner = _valid_verdict_json(verdict="needs_more_info", confidence=0.50)
    think_response = "<think>Let me reason through the evidence carefully...</think>\n" + inner

    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(return_value=think_response),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
        )

    assert result is not None
    assert result.report.verdict == "needs_more_info"


# ---------------------------------------------------------------------------
# Test: robustness — JSON embedded in prose (no fence, no think) → parses
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_parses_json_in_prose() -> None:
    """When JSON is embedded in prose (no fence), brace-balanced extraction
    must still recover a valid verdict."""
    settings = _make_settings()
    ctx = _make_ctx(settings)

    inner = _valid_verdict_json(verdict="true_positive", confidence=0.95)
    prose_response = (
        "Based on my analysis of the sanitized payload, I conclude that "
        f"the alert is a true positive. My structured verdict: {inner} "
        "Please escalate this case immediately."
    )

    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(return_value=prose_response),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
        )

    assert result is not None
    assert result.report.verdict == "true_positive"


# ---------------------------------------------------------------------------
# Test: truly unparseable → returns None (triage not broken)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_returns_none_on_unparseable_response() -> None:
    """When the oracle returns text that cannot be parsed into an OracleVerdict
    after all retries, adjudicate must return None."""
    settings = _make_settings()
    ctx = _make_ctx(settings)

    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(return_value="I cannot determine a verdict at this time."),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
        )

    assert result is None


# ---------------------------------------------------------------------------
# Test: gateway exception → returns None (triage not broken)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_returns_none_on_model_exception() -> None:
    """When _call_oracle_raw raises on every attempt, adjudicate must
    return None and not propagate the exception."""
    settings = _make_settings()
    ctx = _make_ctx(settings)

    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(side_effect=RuntimeError("gateway timeout")),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
        )

    assert result is None


# ---------------------------------------------------------------------------
# Test: non-JSON-serialisable type in case dict → serialization failure → None
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_returns_none_on_serialization_error() -> None:
    """If the case dict contains a non-JSON-serialisable value after sanitize,
    adjudicate refuses (fails closed) and returns None."""
    settings = _make_settings()
    ctx = _make_ctx(settings)

    bad_case: dict[str, Any] = {"unserializable": {1, 2, 3}}
    raw_call = AsyncMock()

    with (
        patch("soc_ai.oracle.client.sanitize_case", return_value=bad_case),
        patch("soc_ai.oracle.client._call_oracle_raw", raw_call),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
        )

    assert result is None
    raw_call.assert_not_awaited()


# ---------------------------------------------------------------------------
# Fix 3: oracle_extra_hosts is threaded into both sanitize and unsafe_residue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_extra_hosts_redacts_bare_hostname() -> None:
    """Fix M1: with oracle_extra_hosts=["appserver"], a case payload containing
    the bare hostname 'appserver' must be sanitized (not egress), and the
    sanitized payload must pass the residue check.

    Verifies the threading invariant: both sanitize() and unsafe_residue()
    receive the same extra_hosts tuple derived from settings.oracle_extra_hosts.
    """
    settings = _make_settings(oracle_extra_hosts=["appserver"])
    ctx = _make_ctx(settings)

    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    enriched_with_hostname = EnrichedAlertContext(
        alert=SoAlert(
            id="alert-555",
            severity_label="medium",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            rule_name="Connection to appserver registry",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )

    captured_payload: list[str] = []

    async def _capture_and_respond(payload: str, *, settings: Any) -> str:
        captured_payload.append(payload)
        return _valid_verdict_json(verdict="false_positive", confidence=0.75)

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture_and_respond):
        result = await adjudicate(
            ctx,
            enriched=enriched_with_hostname,
            local_report=_stub_report(),
            transcript_text="Alert: target is appserver on 10.0.0.1",
        )

    assert result is not None, (
        "adjudicate should succeed — 'appserver' is an extra_host, so it gets redacted "
        "and residue check passes"
    )
    assert len(captured_payload) == 1
    assert "appserver" not in captured_payload[0], (
        "bare 'appserver' hostname must be redacted by sanitize(extra_hosts=['appserver'])"
    )
    assert "HOST_" in captured_payload[0], (
        "sanitized payload must contain a HOST_NN token for 'appserver'"
    )


@pytest.mark.asyncio
async def test_adjudicate_bare_hostname_without_extra_hosts_passes_through() -> None:
    """Control test: without oracle_extra_hosts, 'appserver' egresses verbatim.

    This documents current behavior: bare single-label names are NOT caught by
    the default suffix list.  The residue check also does not flag them.
    The operator MUST list them in ORACLE_EXTRA_HOSTS to protect them.
    """
    settings = _make_settings()  # oracle_extra_hosts=[] (default)
    ctx = _make_ctx(settings)

    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    enriched_no_extra = EnrichedAlertContext(
        alert=SoAlert(
            id="appserver-002",
            severity_label="low",
            source_ip="10.0.0.1",
            rule_name="Connection to appserver",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )

    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return _valid_verdict_json()

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=enriched_no_extra,
            local_report=_stub_report(),
            transcript_text="Appserver registry contacted.",
        )

    # Without extra_hosts, 'appserver' passes through verbatim — not a private-IP.
    assert result is not None
    assert len(captured) == 1
    assert "appserver" in captured[0]


# ---------------------------------------------------------------------------
# Test: _call_oracle_raw — HTTP egress, response extraction, error mapping
# (exercises the REAL coroutine with a mocked httpx.AsyncClient; the other
# tests patch _call_oracle_raw wholesale, so its internals are tested here)
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, data: Any = None, status: int = 200, text: str = "ok") -> None:
        self._data = data if data is not None else {}
        self.status_code = status
        self.text = text

    def raise_for_status(self) -> None:
        import httpx

        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "err",
                request=httpx.Request("POST", "http://x"),
                response=self,  # type: ignore[arg-type]
            )

    def json(self) -> Any:
        return self._data


class _FakeClient:
    def __init__(self, *, result: Any = None, exc: Exception | None = None) -> None:
        self._result = result
        self._exc = exc

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *a: Any) -> bool:
        return False

    async def post(self, *a: Any, **k: Any) -> Any:
        if self._exc is not None:
            raise self._exc
        return self._result


def _patch_client(client: _FakeClient) -> Any:
    return patch("httpx.AsyncClient", MagicMock(return_value=client))


def _msg(content: Any) -> dict[str, Any]:
    return {"choices": [{"message": {"content": content}}]}


async def _raw(client: _FakeClient, **settings_kw: Any) -> str:
    """Run the REAL _call_oracle_raw against a mocked httpx client."""
    from soc_ai.oracle.client import _call_oracle_raw

    with _patch_client(client):
        return await _call_oracle_raw("payload", settings=_make_settings(**settings_kw))


@pytest.mark.asyncio
async def test_call_oracle_raw_str_content() -> None:
    # litellm_api_key set → exercises the get_secret_value() branch.
    out = await _raw(
        _FakeClient(result=_FakeResp(_msg("the verdict"))),
        litellm_api_key=SecretStr("sk-test"),
    )
    assert out == "the verdict"


@pytest.mark.asyncio
async def test_call_oracle_raw_list_content_joins_text_parts() -> None:
    content = [
        {"type": "text", "text": "Hello "},
        {"type": "text", "text": "world"},
        {"type": "image", "url": "x"},  # non-text part ignored
    ]
    out = await _raw(_FakeClient(result=_FakeResp(_msg(content))))
    assert out == "Hello world"


@pytest.mark.asyncio
async def test_call_oracle_raw_none_content_returns_empty() -> None:
    out = await _raw(_FakeClient(result=_FakeResp({"choices": [{"message": {}}]})))
    assert out == ""


@pytest.mark.asyncio
async def test_call_oracle_raw_empty_choices_raises() -> None:
    with pytest.raises(RuntimeError):
        await _raw(_FakeClient(result=_FakeResp({"choices": []})))


@pytest.mark.asyncio
async def test_call_oracle_raw_transport_error_is_retryable() -> None:
    import httpx
    from soc_ai.oracle.client import _OracleGatewayError

    with pytest.raises(_OracleGatewayError) as ei:
        await _raw(_FakeClient(exc=httpx.ConnectError("refused")))
    assert ei.value.retryable is True


@pytest.mark.asyncio
async def test_call_oracle_raw_5xx_retryable() -> None:
    from soc_ai.oracle.client import _OracleGatewayError

    with pytest.raises(_OracleGatewayError) as ei:
        await _raw(_FakeClient(result=_FakeResp({}, status=503, text="overloaded")))
    assert ei.value.retryable is True


@pytest.mark.asyncio
async def test_call_oracle_raw_4xx_terminal() -> None:
    from soc_ai.oracle.client import _OracleGatewayError

    with pytest.raises(_OracleGatewayError) as ei:
        await _raw(_FakeClient(result=_FakeResp({}, status=401, text="nope")))
    assert ei.value.retryable is False
