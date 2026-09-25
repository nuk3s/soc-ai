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
from soc_ai.oracle.client import OracleResult, _parse_oracle_verdict, adjudicate

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
# Test: NaN / out-of-range confidence → rejected as unparseable, never clamped
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_confidence",
    ["NaN", "Infinity", "-Infinity", "85", "1.5", "-0.1"],
)
def test_parse_oracle_verdict_rejects_nan_and_out_of_range_confidence(
    raw_confidence: str,
) -> None:
    """A confidence outside 0.0-1.0 (or NaN/inf, which json.loads accepts) must
    fail OracleVerdict validation rather than survive to the report mapper,
    where a clamp would turn it into a fabricated 1.0."""
    raw = (
        '{"verdict": "false_positive", "confidence": '
        + raw_confidence
        + ', "summary": "Benign scanner.", "reasoning": "Known vuln scanner."}'
    )
    assert _parse_oracle_verdict(raw) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("raw_confidence", ["NaN", "85"])
async def test_adjudicate_rejects_nan_and_out_of_range_confidence(
    raw_confidence: str,
) -> None:
    """A verdict whose confidence is NaN or percent-style must not become a
    1.0-confidence report (which would clear the auto-ack threshold); it is
    treated like any other unparseable answer and the local verdict is kept."""
    settings = _make_settings()
    ctx = _make_ctx(settings)
    raw = (
        '{"verdict": "false_positive", "confidence": '
        + raw_confidence
        + ', "summary": "Benign scanner.", "reasoning": "Known vuln scanner."}'
    )
    failure: dict[str, str] = {}

    with (
        patch("soc_ai.oracle.client._call_oracle_raw", AsyncMock(return_value=raw)),
        patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
            failure_out=failure,
        )

    assert result is None
    assert failure.get("reason") == "no_parseable_verdict"


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


@pytest.mark.asyncio
async def test_adjudicate_refusal_increments_metric() -> None:
    """A residue-gate refusal bumps socai_oracle_refusals_total so a silently-
    disabled Oracle (refusing every transcript) becomes visible."""
    from soc_ai import metrics

    fresh = metrics._Metrics()
    metrics._GLOBAL = fresh

    ctx = _make_ctx(_make_settings())
    # sanitize_case is stubbed to MISS a private IP, so the residue gate fires.
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

    assert result is None
    raw_call.assert_not_awaited()
    assert fresh.oracle_refusals_total == 1


# ---------------------------------------------------------------------------
# Fix: oracle-refuse-by-design — the gate must not refuse a payload the
# sanitizer intentionally left partly un-propagated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adjudicate_does_not_refuse_two_occurrence_credential() -> None:
    """Class 1: a credential value learned in Pass 2 (in-place-only) that re-occurs
    bare in another case field must egress FULLY LABELLED — adjudicate returns a
    result rather than refusing by construction, and the username is off the wire."""
    ctx = _make_ctx(_make_settings())
    local = TriageReport(
        verdict="false_positive",
        confidence=0.6,
        summary="jdoe touched the share",  # bare re-occurrence of the credential value
        citations=[],
        recommended_actions=[],
    )
    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return _valid_verdict_json(verdict="false_positive", confidence=0.7)

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=local,
            transcript_text="Failed logon for user=jdoe from gateway",
        )

    assert result is not None  # NOT refused
    assert len(captured) == 1
    assert "jdoe" not in captured[0]  # fully labelled on the wire


@pytest.mark.asyncio
async def test_adjudicate_does_not_refuse_short_domain_like_label() -> None:
    """Class 2: a short (<=3 char) DOMAIN_LIKE value the sanitizer intentionally did
    not propagate (to protect public FQDNs) must be excluded from known_values, so
    the gate does not refuse when the same substring appears in a public FQDN."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    enriched = EnrichedAlertContext(
        alert=SoAlert(id="alert-dc", severity_label="low", zeek_dns_query="dc"),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )
    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return _valid_verdict_json(verdict="false_positive", confidence=0.7)

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx=_make_ctx(_make_settings()),
            enriched=enriched,
            local_report=_stub_report(),
            transcript_text="lookup dc.example.com in passive dns",
        )

    assert result is not None  # NOT refused
    assert len(captured) == 1
    # The public FQDN survived verbatim (short-token propagation would corrupt it).
    assert "dc.example.com" in captured[0]


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


# ===========================================================================
# The read-only tool loop (oracle_tools_enabled=True, 2026-08-27 design).
#
# These drive _adjudicate_with_tools. Tests (b)/(c)/(d) substitute a pydantic-ai
# FunctionModel for the gateway (production still registers the REAL oracle
# tools on the agent); the wire-gate test (a) exercises the real httpx client's
# request hook over an httpx.MockTransport, so the residue choke point is tested
# where it actually sits — on the outbound request body.
# ===========================================================================


def _tools_settings(**kwargs: Any) -> Settings:
    return _make_settings(oracle_tools_enabled=True, **kwargs)


def _real_ctx(settings: Settings, *, elastic: Any = None, include_synth: Any = False) -> Any:
    """A REAL InvestigationContext (the tool loop calls dataclasses.replace on it)."""
    from soc_ai.agent.orchestrator import InvestigationContext

    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=elastic if elastic is not None else AsyncMock(),
        include_synth=include_synth,
    )


def _es_result(total: int = 1, hits: list[dict[str, Any]] | None = None) -> Any:
    from soc_ai.so_client.elastic import EsSearchResult

    return EsSearchResult(
        total=total,
        took_ms=1,
        hits=hits if hits is not None else [{"event": {"dataset": "zeek.conn"}}],
    )


def _script_model(
    actions: list[tuple[str, Any]], *, tool_return_sink: list[Any] | None = None
) -> Any:
    """A FunctionModel that plays a fixed script of tool calls / final verdicts.

    ``actions`` items: ``("tool", (name, args))`` or ``("verdict", json_str)``.
    ``tool_return_sink`` (optional) collects every tool-return content the model
    is shown, so a test can assert on what a tool handed back.
    """
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
    from pydantic_ai.models.function import AgentInfo, FunctionModel

    state = {"i": 0}

    def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        if tool_return_sink is not None:
            for m in messages:
                for p in getattr(m, "parts", []) or []:
                    if getattr(p, "part_kind", None) == "tool-return":
                        tool_return_sink.append(getattr(p, "content", None))
        i = state["i"]
        state["i"] += 1
        if i < len(actions):
            kind, payload = actions[i]
            if kind == "tool":
                name, args = payload
                return ModelResponse(parts=[ToolCallPart(tool_name=name, args=args)])
            return ModelResponse(parts=[TextPart(content=payload)])
        return ModelResponse(parts=[TextPart(content=_valid_verdict_json())])

    return FunctionModel(_fn)


class _NoopHTTPClient:
    async def aclose(self) -> None:
        return None


def _patch_oracle_model(model: Any) -> Any:
    """Substitute the gateway model with ``model`` (the wire hook is unused)."""

    def _fake(settings: Any, hook: Any, *, transport: Any = None) -> Any:
        return model, _NoopHTTPClient()

    return patch("soc_ai.oracle.client._build_oracle_model", _fake)


# ---------------------------------------------------------------------------
# (a) SECURITY: an internal identifier that reaches an outbound body is caught
#     at the wire and refuses the adjudication.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oracle_wire_hook_refuses_leaked_known_value() -> None:
    """The wire hook sweeps the ACTUAL outbound body with live known_values from
    the mapping: a harvested internal hostname that leaked verbatim (a sanitize
    miss on a tool result) is caught and raises OracleResidueError; a fully
    labelled body passes."""
    import httpx
    from soc_ai.oracle.client import OracleResidueError, _make_residue_hook
    from soc_ai.oracle.redact import Mapping

    mapping = Mapping()
    mapping.label_for("filesrv01", "HOST")  # reverse now maps HOST_01 -> filesrv01
    hook = _make_residue_hook(
        mapping, allowlist=(), extra_hosts=(), extra_suffixes=(), no_propagate=set()
    )

    leaked = httpx.Request(
        "POST",
        "http://x/v1/chat/completions",
        content=b'{"role":"tool","content":"peer filesrv01 was contacted"}',
    )
    with pytest.raises(OracleResidueError):
        await hook(leaked)

    clean = httpx.Request("POST", "http://x", content=b'{"content":"peer HOST_01 was contacted"}')
    await hook(clean)  # fully labelled — must not raise


@pytest.mark.asyncio
async def test_oracle_tools_wire_gate_aborts_adjudication_on_residue() -> None:
    """(a) end-to-end: a residue in the actual outbound body aborts the whole
    adjudication — adjudicate returns None with reason residue_refusal, the
    refusal metric bumps, and the gateway is NEVER reached."""
    import httpx
    from soc_ai import metrics

    fresh = metrics._Metrics()
    metrics._GLOBAL = fresh

    ctx = _real_ctx(_tools_settings())

    def _handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("the model must not be reached when residue is detected")

    transport = httpx.MockTransport(_handler)

    # sanitize_case stubbed to MISS a private IP → the first outbound body leaks.
    leaking = {
        "alert_summary": {"source_ip": "192.168.1.100"},
        "loop_evidence": "",
        "loop_tool_results": [],
        "loop_evidence_bullets": [],
        "local_verdict": "false_positive",
        "local_confidence": 0.85,
        "local_summary": "s",
        "local_citations": [],
    }
    failure: dict[str, str] = {}
    with patch("soc_ai.oracle.client.sanitize_case", return_value=leaking):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
            failure_out=failure,
            _http_transport=transport,
        )

    assert result is None
    assert failure.get("reason") == "residue_refusal"
    assert fresh.oracle_refusals_total == 1


# ---------------------------------------------------------------------------
# (b) SECURITY: a hallucinated label is refused, not silently-empty-queried.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oracle_tools_hallucinated_label_refused_not_silent_empty() -> None:
    """The model asks for IP_99, a label no case allocated. The desanitize guard
    returns a structured unknown_label error INSTEAD of running the query against
    the literal placeholder — the grid is never queried (no silent empty result),
    and the model sees a corrective error it can self-correct from."""
    elastic = AsyncMock()
    elastic.search = AsyncMock(return_value=_es_result(total=0, hits=[]))
    ctx = _real_ctx(_tools_settings(), elastic=elastic)

    seen: list[Any] = []
    model = _script_model(
        [
            ("tool", ("t_query_events_oql", {"query": "source.ip:IP_99"})),
            ("verdict", _valid_verdict_json(verdict="false_positive", confidence=0.6)),
        ],
        tool_return_sink=seen,
    )
    with _patch_oracle_model(model):
        result = await adjudicate(
            ctx,
            enriched=_enriched_min(),
            local_report=_stub_report(),
            transcript_text="",
        )

    # The literal placeholder was NEVER queried against the grid.
    elastic.search.assert_not_called()
    # The model was handed a structured, self-correcting refusal naming the label.
    assert any(isinstance(c, dict) and c.get("reason") == "unknown_label" for c in seen), seen
    assert result is not None  # the loop still concludes on the local verdict


# ---------------------------------------------------------------------------
# (c) SECURITY: the override gate blocks a zero-tool flip.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oracle_tools_override_gate_blocks_zero_tool_flip() -> None:
    """A class-CHANGING Oracle verdict with NO supporting tool call does not
    override — the local verdict stands, and the dissent is recorded."""
    ctx = _real_ctx(_tools_settings())
    local = _stub_report(verdict="false_positive", confidence=0.6)
    model = _script_model(
        [("verdict", _valid_verdict_json(verdict="true_positive", confidence=0.95))]
    )
    with _patch_oracle_model(model):
        result = await adjudicate(
            ctx, enriched=_enriched_min(), local_report=local, transcript_text=""
        )

    assert result is not None
    assert result.oracle_tool_calls == 0
    assert result.override_withheld is True
    assert result.raw_oracle_verdict == "true_positive"  # what the Oracle ruled
    assert result.report.verdict == "false_positive"  # but the LOCAL verdict stands


@pytest.mark.asyncio
async def test_oracle_tools_backed_flip_overrides() -> None:
    """A class-changing verdict BACKED by a successful tool call DOES override —
    the gate blocks only unbacked flips."""
    elastic = AsyncMock()
    elastic.search = AsyncMock(return_value=_es_result(total=3))
    ctx = _real_ctx(_tools_settings(), elastic=elastic)
    local = _stub_report(verdict="false_positive", confidence=0.6)
    model = _script_model(
        [
            ("tool", ("t_query_events_oql", {"query": "event.dataset:zeek.conn"})),
            ("verdict", _valid_verdict_json(verdict="true_positive", confidence=0.95)),
        ]
    )
    with _patch_oracle_model(model):
        result = await adjudicate(
            ctx, enriched=_enriched_min(), local_report=local, transcript_text=""
        )

    assert result is not None
    assert result.oracle_tool_calls >= 1
    assert result.override_withheld is False
    assert result.report.verdict == "true_positive"  # the flip lands


@pytest.mark.asyncio
async def test_oracle_tools_zero_tool_agreement_still_lands() -> None:
    """A zero-tool AGREEMENT is not a flip — it lands, adding confidence."""
    ctx = _real_ctx(_tools_settings())
    local = _stub_report(verdict="false_positive", confidence=0.55)
    model = _script_model(
        [("verdict", _valid_verdict_json(verdict="false_positive", confidence=0.9))]
    )
    with _patch_oracle_model(model):
        result = await adjudicate(
            ctx, enriched=_enriched_min(), local_report=local, transcript_text=""
        )

    assert result is not None
    assert result.override_withheld is False
    assert result.report.verdict == "false_positive"
    assert result.report.confidence == pytest.approx(0.9)


# ---------------------------------------------------------------------------
# (d) SECURITY / PARITY: prod scope keeps planted docs unreachable — asserted on
#     the EMITTED ES query body, never on a mock return.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oracle_tools_prod_scope_excludes_planted_docs() -> None:
    """include_synth=False (prod) → every oracle OQL query carries the synth
    must_not exclusion, so planted eval docs are unreachable."""
    captured: dict[str, Any] = {}

    async def _search(index: str, query: dict[str, Any], **_kw: Any) -> Any:
        captured["query"] = query
        return _es_result(total=0, hits=[])

    elastic = AsyncMock()
    elastic.search = AsyncMock(side_effect=_search)
    ctx = _real_ctx(_tools_settings(), elastic=elastic, include_synth=False)
    model = _script_model(
        [
            ("tool", ("t_query_events_oql", {"query": "event.dataset:zeek.conn"})),
            ("verdict", _valid_verdict_json()),
        ]
    )
    with _patch_oracle_model(model):
        await adjudicate(
            ctx, enriched=_enriched_min(), local_report=_stub_report(), transcript_text=""
        )

    must_not = captured["query"]["bool"]["must_not"]
    assert {"exists": {"field": "synth.scenario_id"}} in must_not


@pytest.mark.asyncio
async def test_oracle_tools_eval_scope_is_scenario_scoped_not_blanket() -> None:
    """include_synth=<scenario id> (batch eval) → the query sees THAT scenario's
    plants and excludes siblings' — a scenario-scoped bool, not the blanket
    exists-exclude that prod uses."""
    captured: dict[str, Any] = {}

    async def _search(index: str, query: dict[str, Any], **_kw: Any) -> Any:
        captured["query"] = query
        return _es_result(total=0, hits=[])

    elastic = AsyncMock()
    elastic.search = AsyncMock(side_effect=_search)
    ctx = _real_ctx(_tools_settings(), elastic=elastic, include_synth="scenario-x")
    model = _script_model(
        [
            ("tool", ("t_query_events_oql", {"query": "event.dataset:zeek.conn"})),
            ("verdict", _valid_verdict_json()),
        ]
    )
    with _patch_oracle_model(model):
        await adjudicate(
            ctx, enriched=_enriched_min(), local_report=_stub_report(), transcript_text=""
        )

    must_not = captured["query"]["bool"]["must_not"]
    assert {"exists": {"field": "synth.scenario_id"}} not in must_not
    # A bare "a bool clause exists" check would pass even if the scope named the
    # WRONG scenario. Assert THIS scenario id is actually in the term clause, so a
    # mis-scoped query cannot slip through green.
    scoped = [c for c in must_not if isinstance(c, dict) and "bool" in c]
    assert scoped, must_not
    inner_must_not = scoped[0]["bool"]["must_not"]
    assert {"term": {"synth.scenario_id": "scenario-x"}} in inner_must_not
    assert {"term": {"synth.scenario_id.keyword": "scenario-x"}} in inner_must_not


@pytest.mark.asyncio
async def test_oracle_tools_disabled_keeps_single_shot(monkeypatch: pytest.MonkeyPatch) -> None:
    """With oracle_tools_enabled=False (the default) the tool loop is never
    entered — the single-shot _call_oracle_raw path runs unchanged."""
    import soc_ai.oracle.client as client_mod

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("tool loop must not run when oracle_tools_enabled is False")

    monkeypatch.setattr(client_mod, "_adjudicate_with_tools", _boom)
    ctx = _make_ctx(_make_settings())  # oracle_tools_enabled defaults False
    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(return_value=_valid_verdict_json(verdict="false_positive", confidence=0.8)),
    ):
        result = await adjudicate(
            ctx, enriched=_stub_enriched(), local_report=_stub_report(), transcript_text=""
        )
    assert result is not None
    assert result.report.verdict == "false_positive"
    assert result.oracle_tool_calls == 0
    assert result.override_withheld is False


# ===========================================================================
# F1 — the test whose ABSENCE let the tool-result leak hide.
#
# The existing e2e wire tests STUB sanitize_case, so no test ever exercised a
# HARVESTED value on the real wire, nor an UNHARVESTED generic-key value. These
# run REAL sanitize_case with a REAL httpx.MockTransport on the adjudication
# client (the _http_transport seam), so the residue choke point and the
# field-aware harvest are exercised exactly where they sit — on the outbound body.
# ===========================================================================


def _openai_tool_call_response(name: str, arguments: str) -> dict[str, Any]:
    """A minimal OpenAI chat-completion response asking to call one tool."""
    return {
        "id": "chatcmpl-tool",
        "object": "chat.completion",
        "created": 0,
        "model": "oracle",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_0",
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def _openai_text_response(content: str) -> dict[str, Any]:
    """A minimal OpenAI chat-completion response with a final text message."""
    return {
        "id": "chatcmpl-final",
        "object": "chat.completion",
        "created": 0,
        "model": "oracle",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def _enriched_with_host(host_name: str) -> Any:
    """Enriched context carrying a bare internal host_name on the alert — a
    field-aware-HARVEST value (host_name ∈ _HOST_FIELDS), the control that must
    stay tokenized on the real wire."""
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(
            id="alert-001", severity_label="high", source_ip="10.0.0.1", host_name=host_name
        ),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


@pytest.mark.asyncio
async def test_oracle_generic_key_identifier_never_reaches_the_real_wire() -> None:
    """F1 (RED before the fix): a tool that returns an internal hostname under a
    GENERIC key — t_field_values(host.name) → 'filesrv' in values[].value — is
    tokenized to a HOST_ label BEFORE the continuation body is sent, so the bare
    name never rides the wire. The wire residue gate structurally cannot catch a
    shapeless bare name (it has no regex shape and is not yet a known_value), so
    the field-aware harvest MUST — this asserts it does, on the real transport."""
    import httpx
    from soc_ai.so_client.elastic import EsSearchResult

    # A REAL field-aware value on the alert (the control) AND a generic-key value
    # from the tool (the regression) — both must be absent-raw from the wire.
    elastic = AsyncMock()
    elastic.search = AsyncMock(
        return_value=EsSearchResult(
            total=0,
            took_ms=1,
            hits=[],
            aggregations={"vals": {"buckets": [{"key": "filesrv", "doc_count": 5}]}},
        )
    )
    ctx = _real_ctx(_tools_settings(), elastic=elastic)

    bodies: list[str] = []
    state = {"i": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content.decode("utf-8", "replace"))
        i = state["i"]
        state["i"] += 1
        if i == 0:
            return httpx.Response(
                200,
                json=_openai_tool_call_response("t_field_values", '{"field": "host.name"}'),
            )
        return httpx.Response(200, json=_openai_text_response(_valid_verdict_json()))

    transport = httpx.MockTransport(_handler)
    result = await adjudicate(
        ctx,
        enriched=_enriched_with_host("corp-dc01"),
        local_report=_stub_report(),
        transcript_text="",
        _http_transport=transport,
    )

    wire = "\n".join(bodies)
    # The tool ran and its result rode a continuation body back to the gateway.
    assert len(bodies) >= 2, bodies
    # The one unacceptable outcome: a bare internal name reaching the cloud. The
    # generic-key value (regression) AND the field-aware-harvest value (control)
    # are both absent-raw; both were tokenized to stable labels the model saw.
    assert "filesrv" not in wire, "generic-key internal hostname leaked to the wire"
    assert "corp-dc01" not in wire, "field-aware-harvest hostname leaked to the wire"
    assert "HOST_" in wire
    assert result is not None


@pytest.mark.asyncio
async def test_oracle_harvested_value_is_tokenized_on_the_real_wire() -> None:
    """The harvested-value control on the real wire: an internal host_name carried
    on the alert is tokenized by the initial payload's field-aware harvest and
    never appears raw in the first outbound body. Green before and after the F1
    fix — it proves the real-wire harness itself, so the regression test above is
    trustworthy."""
    import httpx

    ctx = _real_ctx(_tools_settings())
    bodies: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content.decode("utf-8", "replace"))
        return httpx.Response(200, json=_openai_text_response(_valid_verdict_json()))

    transport = httpx.MockTransport(_handler)
    result = await adjudicate(
        ctx,
        enriched=_enriched_with_host("filesrv-primary"),
        local_report=_stub_report(),
        transcript_text="",
        _http_transport=transport,
    )

    wire = "\n".join(bodies)
    assert bodies, "the gateway was never reached"
    assert "filesrv-primary" not in wire
    assert "HOST_" in wire
    assert result is not None


# ===========================================================================
# F1b — the RESIDUAL of the tool-result leak (found by re-verifying the F1 fix).
#
# The DOMAIN category (dns.question.name / dns.query.name / domain / host.domain,
# + the unrecognised source/destination.domain) is SUFFIX-gated by the harvest,
# but the oracle re-key routes tool-result values onto the LITERAL field path. A
# bare single-label internal name (``filesrv``, NetBIOS ``ACMECORP``) ends in no
# suffix, so it is neither harvested (no suffix) NOR wire-catchable (no regex
# shape) — it egresses raw. These run REAL sanitize_case over a REAL
# httpx.MockTransport (the _http_transport seam, nothing stubbed): each is RED
# before the reroute fix (the bare name in the outbound body) and GREEN after
# (tokenized to a HOST_ label). The existing F1 test only covered host.name, an
# UNCONDITIONAL-harvest field — which is exactly why this residual hid.
# ===========================================================================


async def _drive_single_tool_call_wire(
    *,
    tool_name: str,
    tool_args: str,
    elastic: Any,
) -> str:
    """Run one adjudication whose model calls exactly ``tool_name`` once over a
    real MockTransport, and return the concatenation of every outbound body so a
    test can assert what did (not) ride the wire."""
    import httpx

    ctx = _real_ctx(_tools_settings(), elastic=elastic)
    bodies: list[str] = []
    state = {"i": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content.decode("utf-8", "replace"))
        i = state["i"]
        state["i"] += 1
        if i == 0:
            return httpx.Response(200, json=_openai_tool_call_response(tool_name, tool_args))
        return httpx.Response(200, json=_openai_text_response(_valid_verdict_json()))

    transport = httpx.MockTransport(_handler)
    result = await adjudicate(
        ctx,
        enriched=_enriched_with_host("corp-sensor"),
        local_report=_stub_report(),
        transcript_text="",
        _http_transport=transport,
    )
    assert result is not None
    assert len(bodies) >= 2, bodies
    return "\n".join(bodies)


@pytest.mark.asyncio
async def test_oracle_single_label_dns_question_name_never_reaches_the_real_wire() -> None:
    """F1b (RED before the reroute fix): t_field_values(dns.question.name) → a
    bare single-label internal name 'filesrv' in values[].value. DOMAIN is
    suffix-gated, so the harvest skips a suffix-less name and the wire gate cannot
    shape-catch it — it egresses raw. The reroute must route the single-label
    value onto HOST so it is tokenized before the continuation body is sent."""
    from soc_ai.so_client.elastic import EsSearchResult

    elastic = AsyncMock()
    elastic.search = AsyncMock(
        return_value=EsSearchResult(
            total=0,
            took_ms=1,
            hits=[],
            aggregations={"vals": {"buckets": [{"key": "filesrv", "doc_count": 5}]}},
        )
    )
    wire = await _drive_single_tool_call_wire(
        tool_name="t_field_values",
        tool_args='{"field": "dns.question.name"}',
        elastic=elastic,
    )
    assert "filesrv" not in wire, "single-label internal DNS name leaked to the wire"
    assert "HOST_" in wire


@pytest.mark.asyncio
async def test_oracle_single_label_host_domain_never_reaches_the_real_wire() -> None:
    """F1b (RED before the reroute fix): t_field_values(host.domain) → a NetBIOS
    short domain 'ACMECORP' (single label). Same suffix-gating gap as the DNS
    case; the reroute must tokenize it before it rides the wire."""
    from soc_ai.so_client.elastic import EsSearchResult

    elastic = AsyncMock()
    elastic.search = AsyncMock(
        return_value=EsSearchResult(
            total=0,
            took_ms=1,
            hits=[],
            aggregations={"vals": {"buckets": [{"key": "ACMECORP", "doc_count": 5}]}},
        )
    )
    wire = await _drive_single_tool_call_wire(
        tool_name="t_field_values",
        tool_args='{"field": "host.domain"}',
        elastic=elastic,
    )
    assert "ACMECORP" not in wire, "single-label NetBIOS domain leaked to the wire"
    assert "HOST_" in wire


@pytest.mark.asyncio
async def test_oracle_oql_groupby_single_label_domain_key_never_reaches_the_real_wire() -> None:
    """F1b (RED before the reroute fix): `… | groupby dns.question.name` returns
    the grouped internal name under aggregations.by_dns_question_name.buckets[].key.
    _rekey_oql_aggregations routes that key onto the DOMAIN field dns.question.name,
    where a single-label 'filesrv' would be suffix-gated out of the harvest — the
    reroute must tokenize it before the wire."""
    from soc_ai.so_client.elastic import EsSearchResult

    elastic = AsyncMock()
    elastic.search = AsyncMock(
        return_value=EsSearchResult(
            total=0,
            took_ms=1,
            hits=[],
            aggregations={
                "by_dns_question_name": {"buckets": [{"key": "filesrv", "doc_count": 5}]}
            },
        )
    )
    wire = await _drive_single_tool_call_wire(
        tool_name="t_query_events_oql",
        tool_args='{"query": "* | groupby dns.question.name"}',
        elastic=elastic,
    )
    assert "filesrv" not in wire, "single-label groupby key on a DOMAIN field leaked to the wire"
    assert "HOST_" in wire


@pytest.mark.asyncio
async def test_oracle_get_event_raw_winlog_hostname_never_reaches_the_real_wire() -> None:
    """The last winlog egress residual: t_get_event_raw returns an arbitrary nested
    _source with NO field→value envelope, so it is neither re-keyed (unknown
    envelope) nor wire-catchable (a single-label NetBIOS name has no regex shape).
    A bare hostname under a winlog host leaf key — ``TargetServerName: FILESRV`` —
    egressed raw. The shared harvest add (``_WINLOG_HOST_LEAF_KEYS``) must tokenise
    it before the continuation body rides the wire. RED before, GREEN after."""
    from soc_ai.so_client.elastic import EsSearchResult

    elastic = AsyncMock()
    elastic.search = AsyncMock(
        return_value=EsSearchResult(
            total=1,
            took_ms=1,
            hits=[
                {
                    "_id": "ev-4648",
                    "_source": {
                        "event.dataset": "windows.security",
                        "winlog": {"event_data": {"TargetServerName": "FILESRV"}},
                    },
                }
            ],
            aggregations=None,
        )
    )
    wire = await _drive_single_tool_call_wire(
        tool_name="t_get_event_raw",
        tool_args='{"event_id": "ev-4648"}',
        elastic=elastic,
    )
    assert "FILESRV" not in wire, "winlog host leaf value leaked to the wire via t_get_event_raw"
    assert "HOST_" in wire


# ===========================================================================
# F1c — the allow-known-safe egress backstop: the STRUCTURAL fix for the whole
# whack-a-mole. The harvest is a blocklist keyed on field paths, so a bare name
# on a field NOBODY enumerated egresses raw (no harvest rule, no regex shape the
# wire gate can catch). The backstop converts the oracle result path to
# allow-known-safe: mask any residual free-form scalar on an unrecognised field.
# These run REAL sanitize_case over a REAL httpx.MockTransport / the real
# mask pass — nothing stubbed.
# ===========================================================================


@pytest.mark.asyncio
async def test_oracle_unrecognised_field_bare_name_masked_before_the_real_wire() -> None:
    """F1c (RED before the backstop): t_get_event_raw returns a _source carrying a
    bare internal hostname on a COMPLETELY UNRECOGNISED field —
    ``some.vendor.custom_asset: 'filesrv'``. No harvest rule classifies it, it is
    not a winlog leaf, and a single-label bare name has no regex shape the wire
    gate can catch, so it egressed RAW. The allow-known-safe backstop masks it
    before the continuation body rides the wire — this proves an un-enumerated
    field can no longer leak a bare name. RED before, GREEN after."""
    from soc_ai.oracle.backstop import MASK_PLACEHOLDER
    from soc_ai.so_client.elastic import EsSearchResult

    elastic = AsyncMock()
    elastic.search = AsyncMock(
        return_value=EsSearchResult(
            total=1,
            took_ms=1,
            hits=[
                {
                    "_id": "ev-1",
                    "_source": {
                        "event.dataset": "corelight.conn",
                        # A vendor envelope the harvest has NO rule for.
                        "some": {"vendor": {"custom_asset": "filesrv"}},
                    },
                }
            ],
            aggregations=None,
        )
    )
    wire = await _drive_single_tool_call_wire(
        tool_name="t_get_event_raw",
        tool_args='{"event_id": "ev-1"}',
        elastic=elastic,
    )
    assert "filesrv" not in wire, "bare name on an UNRECOGNISED field leaked to the wire"
    assert MASK_PLACEHOLDER in wire, "the backstop did not mask the unclassified scalar"


def test_backstop_allows_known_safe_values_and_masks_unrecognised_free_form() -> None:
    """F1c control: the allow-known-safe policy preserves utility for provably-safe
    value shapes and known-safe fields (a minted label, a port, an enum, a public
    FQDN, a timestamp, a hash all pass through UNmasked) while masking a bare
    internal name / free-text prose on an unrecognised field — so the backstop is
    not a blanket nuke of utility."""
    from soc_ai.oracle.backstop import MASK_PLACEHOLDER, mask_unclassified_scalars

    suffixes = (".lan", ".local", ".internal", ".corp")
    result = {
        "event": {"category": "network", "action": "connection", "kind": "alert"},
        "destination": {"port": 443},  # int scalar — never masked
        "network": {"protocol": "tls"},  # enum field → allowed
        "server_name": "www.example.com",  # public FQDN → allowed by shape
        "who": "HOST_01",  # already-minted label → allowed by shape
        "first_seen": "2026-08-27T14:00:00Z",  # timestamp → allowed by shape
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        # The leak surface: a bare name and prose embedding one on unknown fields.
        "some": {"vendor": {"custom_asset": "filesrv"}},
        "note": "call filesrv about this ticket",
    }
    masked, n = mask_unclassified_scalars(result, suffixes=suffixes)

    # Utility preserved for every provably-safe / allowlisted value.
    assert masked["event"]["category"] == "network"
    assert masked["event"]["action"] == "connection"
    assert masked["event"]["kind"] == "alert"
    assert masked["destination"]["port"] == 443
    assert masked["network"]["protocol"] == "tls"
    assert masked["server_name"] == "www.example.com"
    assert masked["who"] == "HOST_01"
    assert masked["first_seen"] == "2026-08-27T14:00:00Z"
    assert masked["sha256"].startswith("e3b0")

    # The bare internal name and the prose that embeds it are masked.
    assert masked["some"]["vendor"]["custom_asset"] == MASK_PLACEHOLDER
    assert masked["note"] == MASK_PLACEHOLDER
    assert "filesrv" not in json.dumps(masked)
    assert n == 2


# ===========================================================================
# F1d — the completeness gap: the backstop now also covers the INITIAL payload.
#
# The INITIAL adjudication body ALWAYS egresses (it is the first outbound
# request), yet before this change only the TOOL-RESULT sanitize ran the
# allow-known-safe backstop — the initial payload's own sanitize did not. So a
# bare internal name on a field neither the field-aware harvest nor the wire
# residue gate can catch (shapeless, not yet a known_value) rode the first body
# raw. These run REAL sanitize_case over a REAL httpx.MockTransport (the
# _http_transport seam, nothing stubbed): the leak is placed in the INITIAL
# payload via the local loop's tool results, and the model returns its verdict on
# the FIRST turn so the only outbound body IS the initial payload.
# ===========================================================================


def _loop_messages_with_tool_result(tool_name: str, content: dict[str, Any]) -> list[Any]:
    """A minimal pydantic-ai-shaped message history carrying ONE local-loop tool
    result, duck-typed exactly as ``_extract_tool_results`` reads it
    (``msg.parts`` / ``part.part_kind`` / ``part.content`` / ``part.tool_name``).
    Lets a test place a value on a chosen field INSIDE the initial payload's
    ``loop_tool_results`` without standing up the whole investigation loop."""
    from types import SimpleNamespace

    part = SimpleNamespace(part_kind="tool-return", tool_name=tool_name, content=content)
    return [SimpleNamespace(parts=[part])]


@pytest.mark.asyncio
async def test_oracle_initial_payload_bare_name_masked_before_the_first_body() -> None:
    """F1d (RED before extending the backstop to the initial payload): a bare
    internal hostname on a COMPLETELY UNRECOGNISED field carried in the INITIAL
    payload's loop_tool_results — ``some.vendor.custom_asset: 'filesrv'`` — has no
    harvest rule and no regex shape the wire gate can catch, so it rode the FIRST
    outbound body raw. The initial-payload backstop masks it before that body is
    sent. RED before, GREEN after."""
    import httpx
    from soc_ai.oracle.backstop import MASK_PLACEHOLDER

    ctx = _real_ctx(_tools_settings())
    loop_messages = _loop_messages_with_tool_result(
        "t_get_event_raw",
        {"event.dataset": "corelight.conn", "some": {"vendor": {"custom_asset": "filesrv"}}},
    )
    bodies: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content.decode("utf-8", "replace"))
        # Final verdict on the FIRST turn (no tool call) → the only outbound body
        # is the initial payload.
        return httpx.Response(200, json=_openai_text_response(_valid_verdict_json()))

    transport = httpx.MockTransport(_handler)
    result = await adjudicate(
        ctx,
        enriched=_enriched_min(),
        local_report=_stub_report(),
        transcript_text="",
        loop_messages=loop_messages,
        _http_transport=transport,
    )

    assert result is not None
    assert bodies, "the gateway was never reached"
    first = bodies[0]
    assert "filesrv" not in first, "bare name on an UNRECOGNISED initial-payload field leaked"
    assert MASK_PLACEHOLDER in first, "the initial-payload backstop did not mask the scalar"
    # The mask is counted, so the owner sees the initial-payload cost too.
    assert result.oracle_masked_values >= 1


@pytest.mark.asyncio
async def test_oracle_initial_payload_known_safe_values_pass_unmasked() -> None:
    """F1d utility side: known-safe values pass UNmasked in the first outbound
    body — an ECS enum and an opaque id in a loop_tool_results entry, plus the app
    envelope the backstop must never mask (local_verdict / local_summary / a
    minted label). No MASK_PLACEHOLDER appears because nothing unclassified is
    present; masking any of these would blind the Oracle to the local case."""
    import httpx
    from soc_ai.oracle.backstop import MASK_PLACEHOLDER

    ctx = _real_ctx(_tools_settings())
    loop_messages = _loop_messages_with_tool_result(
        "t_query_events_oql",
        {"event": {"category": "network"}, "agent": {"id": "AbC123xyz789"}},
    )
    bodies: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content.decode("utf-8", "replace"))
        return httpx.Response(200, json=_openai_text_response(_valid_verdict_json()))

    transport = httpx.MockTransport(_handler)
    result = await adjudicate(
        ctx,
        enriched=_enriched_min(),
        local_report=_stub_report(verdict="false_positive"),
        transcript_text="",
        loop_messages=loop_messages,
        _http_transport=transport,
    )

    assert result is not None
    assert result.oracle_masked_values == 0
    # Inspect the ACTUAL adjudication payload (the user message), not the escaped
    # wire bytes, so the assertions are exact rather than quote-escaping-sensitive.
    payload = next(m["content"] for m in json.loads(bodies[0])["messages"] if m["role"] == "user")
    assert MASK_PLACEHOLDER not in payload, "a known-safe initial-payload value was wrongly masked"
    # ECS enum (safe field) and opaque id (safe id field) survive verbatim.
    assert '"category": "network"' in payload
    assert "AbC123xyz789" in payload
    # The app envelope survives — else the Oracle is blind to the local case.
    assert "false_positive" in payload  # local_verdict
    assert "Test summary." in payload  # local_summary
    assert "IP_01" in payload  # minted label for the alert's source_ip


@pytest.mark.asyncio
async def test_single_shot_oracle_path_applies_no_backstop() -> None:
    """The single-shot production Oracle path (oracle_enabled, tools OFF) is
    byte-identical to before — the backstop is NOT applied there. A bare internal
    name on an UNRECOGNISED field egresses VERBATIM (the pre-existing, operator-
    mitigated behaviour) and MASK_PLACEHOLDER never appears, pinning that the
    extension is scoped to the tool-loop path only."""
    from soc_ai.oracle.backstop import MASK_PLACEHOLDER

    ctx = _make_ctx(_make_settings())  # oracle_tools_enabled defaults False
    loop_messages = _loop_messages_with_tool_result(
        "t_get_event_raw",
        {"event.dataset": "corelight.conn", "some": {"vendor": {"custom_asset": "filesrv"}}},
    )
    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return _valid_verdict_json(verdict="false_positive", confidence=0.8)

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
            loop_messages=loop_messages,
        )

    assert result is not None
    assert len(captured) == 1
    # No backstop on the single-shot path: the bare name egresses verbatim, the
    # placeholder is absent, and the masked-value count is untouched (0).
    assert "filesrv" in captured[0]
    assert MASK_PLACEHOLDER not in captured[0]
    assert result.oracle_masked_values == 0


# ===========================================================================
# F2 — a lowercase opaque label must not evade the hallucination guard /
#      desanitize: neither a silent-empty literal query nor an opened leak.
# ===========================================================================


def test_desanitize_resolves_a_lowercase_label() -> None:
    """A real label the model emitted in the wrong case still rehydrates — else
    `source.ip:ip_01` runs as a literal and returns a misleading empty (the
    confidently-wrong 'no data')."""
    from soc_ai.oracle.sanitize import Mapping, desanitize

    mapping = Mapping()
    mapping.label_for("10.0.0.7", "IP")  # allocates IP_01
    assert desanitize("source.ip:ip_01", mapping) == "source.ip:10.0.0.7"
    # Exact-case still works, and a mixed-case variant too.
    assert desanitize("IP_01 and Ip_01", mapping) == "10.0.0.7 and 10.0.0.7"


def test_find_unknown_labels_flags_a_lowercase_hallucination_symmetrically() -> None:
    """A hallucinated label in lowercase (`ip_47`, no IP_47 allocated) is caught
    so the guard refuses instead of querying a literal placeholder; a real label
    in the wrong case is NOT flagged (symmetric with desanitize's restore)."""
    from soc_ai.oracle.sanitize import Mapping, find_unknown_oracle_labels

    mapping = Mapping()
    mapping.label_for("10.0.0.7", "IP")  # only IP_01 exists
    assert find_unknown_oracle_labels("source.ip:ip_47", mapping) == ["ip_47"]
    assert find_unknown_oracle_labels("source.ip:ip_01", mapping) == []


def test_oracle_guard_refuses_lowercase_hallucinated_label() -> None:
    """End-to-end through the guard: a lowercase hallucinated label raises
    OracleUnknownLabelError (→ a structured tool error), never a literal query."""
    from soc_ai.oracle.client import OracleToolGuard
    from soc_ai.oracle.redact import Mapping
    from soc_ai.oracle.sanitize import OracleUnknownLabelError

    mapping = Mapping()
    mapping.label_for("10.0.0.7", "IP")  # IP_01 only
    guard = OracleToolGuard(
        mapping=mapping, extra_hosts=(), extra_suffixes=(), allowlist=(), no_propagate=set()
    )
    with pytest.raises(OracleUnknownLabelError):
        guard.desanitize_obj({"query": "source.ip:ip_47"})
    # A real label in the wrong case resolves instead of refusing.
    assert guard.desanitize_obj({"query": "source.ip:ip_01"}) == {"query": "source.ip:10.0.0.7"}


# ===========================================================================
# F3 — the override gate must not be satisfiable by pure compute on
#      model-invented bytes: t_decode_payload is inference, not observation.
# ===========================================================================


@pytest.mark.asyncio
async def test_oracle_tools_decode_only_flip_is_withheld() -> None:
    """t_decode_payload is in-process compute over model-supplied bytes. A
    class-changing verdict backed ONLY by a decode call must NOT override — the
    Oracle could otherwise flip a verdict class with zero grid access by decoding
    a string it invented. Same non-evidential argument as t_host_dossier."""
    ctx = _real_ctx(_tools_settings())
    local = _stub_report(verdict="false_positive", confidence=0.6)
    model = _script_model(
        [
            ("tool", ("t_decode_payload", {"data": "48656c6c6f", "encoding": "hex"})),
            ("verdict", _valid_verdict_json(verdict="true_positive", confidence=0.95)),
        ]
    )
    with _patch_oracle_model(model):
        result = await adjudicate(
            ctx, enriched=_enriched_min(), local_report=local, transcript_text=""
        )

    assert result is not None
    assert result.oracle_tool_calls == 0  # the decode did not count as evidence
    assert result.override_withheld is True
    assert result.report.verdict == "false_positive"  # the local verdict stands
