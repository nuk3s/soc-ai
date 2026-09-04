"""Oracle evidence parity — the second opinion sees what the investigation saw.

Regression tests for the b3-rmm-admin-lateral finding: the local pipeline
retrieved and cited the discriminating evidence (a ConnectWise-signed MSI, a
ScreenConnect service name), but the Oracle payload carried only the
investigator's prose — every dict-shaped tool result was silently dropped —
so the Oracle rationally distrusted the local verdict, overrode it, and the
final report shipped with ``citations: []``.

Two fixes are pinned here:

1. **Evidence parity** — tool results from the investigation loop reach the
   Oracle payload as STRUCTURED data (so the field-aware harvest in
   ``sanitize_case`` can tokenise ``host.name``-style identifiers), bounded in
   size, and always through the sanitize → residue-sweep gate.
2. **Citation preservation** — an Oracle override never discards the local
   report's citations; recommended actions carry forward only when the Oracle
   agrees with the local verdict class (actions are verdict-specific).

All tests are hermetic: ``_call_oracle_raw`` is patched; no network egress.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.triage_models import RecommendedAction, TriageReport

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(**kwargs: Any) -> Settings:
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
    return SimpleNamespace(settings=settings)


def _stub_enriched(alert_id: str = "alert-b3") -> Any:
    from soc_ai.so_client.models import SoAlert
    from soc_ai.tools.get_alert_context import EnrichedAlertContext

    return EnrichedAlertContext(
        alert=SoAlert(id=alert_id, severity_label="medium", source_ip="10.0.0.1"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _stub_report(
    verdict: str = "false_positive",
    confidence: float = 0.72,
    citations: list[str] | None = None,
    recommended_actions: list[RecommendedAction] | None = None,
) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        summary="Sanctioned RMM: MSI signed by ConnectWise, service is ScreenConnect.",
        citations=citations if citations is not None else ["evt-msi-001", "evt-svc-002"],
        recommended_actions=recommended_actions or [],
    )


def _verdict_json(verdict: str = "true_positive", confidence: float = 0.60) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": confidence,
            "summary": "Adjudicated.",
            "reasoning": "Because reasons.",
        }
    )


def _tool_return(tool_name: str, content: Any) -> Any:
    """Duck-typed pydantic-ai ToolReturnPart."""
    return SimpleNamespace(part_kind="tool-return", tool_name=tool_name, content=content)


def _text_part(content: str) -> Any:
    """Duck-typed pydantic-ai TextPart."""
    return SimpleNamespace(part_kind="text", content=content)


def _msg(*parts: Any) -> Any:
    """Duck-typed pydantic-ai message."""
    return SimpleNamespace(parts=list(parts))


_DECISIVE_TOOL_RESULT: dict[str, Any] = {
    "total": 2,
    "hits": [
        {
            "_id": "evt-msi-001",
            "file": {
                "name": "ScreenConnect.ClientSetup.msi",
                "code_signature": {"subject_name": "ConnectWise, LLC", "trusted": True},
                "hash": {"sha256": "a" * 64},
            },
        },
        {
            "_id": "evt-svc-002",
            "service": {"name": "ScreenConnect Client (RMM)"},
        },
    ],
}


# ---------------------------------------------------------------------------
# Fix 1 reproduction: tool results carrying decisive fields reach the payload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_results_reach_oracle_payload() -> None:
    """The b3 reproduction: the loop's dict-shaped tool results — the query hits
    carrying the signer and the service name — must be present in the outbound
    Oracle payload. Before the fix they were dropped (`isinstance(content, str)`
    filtered every tool return), so the Oracle correctly observed 'no file hash,
    signature, or service name is actually present in the evidence'."""
    from soc_ai.oracle.client import adjudicate

    settings = _make_settings()
    ctx = _make_ctx(settings)

    loop_messages = [
        _msg(_tool_return("t_query_events_oql", _DECISIVE_TOOL_RESULT)),
        _msg(_text_part("The MSI is signed by ConnectWise; this is sanctioned RMM.")),
    ]

    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return _verdict_json()

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="The MSI is signed by ConnectWise; this is sanctioned RMM.",
            loop_messages=loop_messages,
        )

    assert result is not None
    assert len(captured) == 1
    payload = captured[0]
    # The decisive backing data — not just the prose assertion — is in the payload.
    assert "ConnectWise, LLC" in payload
    assert "ScreenConnect Client (RMM)" in payload
    assert "a" * 64 in payload  # the file hash the Oracle said was missing
    assert "evt-msi-001" in payload  # citations are now dereferenceable


@pytest.mark.asyncio
async def test_evidence_bullets_reach_oracle_payload() -> None:
    """The investigator's evidence bullets (claim → id index) are included when
    provided — they link the local narrative to the raw tool results."""
    from soc_ai.oracle.client import adjudicate

    settings = _make_settings()
    ctx = _make_ctx(settings)

    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return _verdict_json()

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
            evidence_bullets=[
                "MSI signed by 'ConnectWise, LLC' (trusted=true) — evt-msi-001",
            ],
        )

    assert result is not None
    assert "evt-msi-001" in captured[0]
    assert "ConnectWise, LLC" in captured[0]


# ---------------------------------------------------------------------------
# The security pin: planted internal identifiers NEVER reach the payload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_planted_internal_identifiers_in_tool_results_do_not_egress() -> None:
    """THE cloud-egress pin. Tool results are dense with internal IPs and
    hostnames; every one planted here must be tokenised before egress:

    - a private IP in a structured field AND in free text,
    - a bare internal hostname in ``host.name`` (only the field-aware harvest
      can know it is internal — proof the results travel STRUCTURED),
    - an internal FQDN under a configured suffix.

    adjudicate must still SUCCEED (sanitized, not refused): the identifiers
    are replaced by opaque labels, and the independent residue sweep passes.
    """
    from soc_ai.oracle.client import adjudicate

    settings = _make_settings()
    ctx = _make_ctx(settings)

    planted_result: dict[str, Any] = {
        "total": 1,
        "hits": [
            {
                "_id": "evt-planted-1",
                "source": {"ip": "192.168.77.10"},
                "host": {"name": "wsfinance07"},
                "dns": {"query": {"name": "dc01.corplab.example"}},
                "message": "conn from 192.168.77.10 to dc01.corplab.example on wsfinance07",
            }
        ],
    }
    loop_messages = [_msg(_tool_return("t_query_events_oql", planted_result))]

    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return _verdict_json()

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
            loop_messages=loop_messages,
            extra_suffixes=(".corplab.example",),
        )

    assert result is not None, "sanitization (not refusal) is the expected path"
    assert len(captured) == 1
    payload = captured[0]
    assert "192.168.77.10" not in payload, "private IP from a tool result egressed"
    assert "wsfinance07" not in payload.lower(), (
        "bare internal hostname from host.name egressed — the field-aware "
        "harvest never saw it (tool results must travel structured)"
    )
    assert "corplab.example" not in payload, "internal FQDN from a tool result egressed"
    # The evidence still reached the Oracle — as opaque labels.
    assert "IP_" in payload
    assert "HOST_" in payload
    assert "evt-planted-1" in payload


@pytest.mark.asyncio
async def test_residue_in_tool_results_fails_closed() -> None:
    """If sanitization misses residue inside a tool result, the independent
    residue sweep must refuse the whole adjudication — never send."""
    from soc_ai.oracle.client import adjudicate

    settings = _make_settings()
    ctx = _make_ctx(settings)

    loop_messages = [
        _msg(_tool_return("t_query_events_oql", {"total": 1, "hits": [{"ip": "192.168.50.10"}]}))
    ]

    raw_call = AsyncMock()

    def _broken_sanitize(case: dict[str, Any], mapping: Any, **_kw: Any) -> dict[str, Any]:
        return case  # simulate a sanitizer gap: residue survives

    with (
        patch("soc_ai.oracle.client.sanitize_case", _broken_sanitize),
        patch("soc_ai.oracle.client._call_oracle_raw", raw_call),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="",
            loop_messages=loop_messages,
        )

    assert result is None, "residue in a tool result must refuse the adjudication"
    raw_call.assert_not_awaited()


# ---------------------------------------------------------------------------
# Fix 2: an Oracle override never discards the local report's citations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oracle_override_preserves_local_citations() -> None:
    """b3's second defect: the Oracle verdict replaced a 10/10-cited local
    report with ``citations: []``. The adjudicated report must carry the local
    citations forward — the verdict that reaches the analyst stays traceable
    to the events it rests on."""
    from soc_ai.oracle.client import adjudicate

    settings = _make_settings()
    ctx = _make_ctx(settings)

    local = _stub_report(
        verdict="false_positive",
        confidence=0.72,
        citations=["evt-msi-001", "evt-svc-002"],
        recommended_actions=[
            RecommendedAction(
                tool_name="ack_alert",
                tool_args={"alert_id": "alert-b3"},
                rationale="Sanctioned RMM install.",
            )
        ],
    )

    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(return_value=_verdict_json(verdict="true_positive", confidence=0.60)),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=local,
            transcript_text="",
        )

    assert result is not None
    assert result.report.verdict == "true_positive"
    # Citations are verdict-neutral (they document the examined evidence) —
    # always carried forward.
    assert result.report.citations == ["evt-msi-001", "evt-svc-002"]
    # Recommended actions are verdict-SPECIFIC — an "ack as benign" action must
    # NOT survive a flip to true_positive.
    assert result.report.recommended_actions == []


@pytest.mark.asyncio
async def test_oracle_same_verdict_preserves_recommended_actions() -> None:
    """When the Oracle agrees with the local verdict class (it only adjusted
    confidence/summary), the local recommended actions remain valid and carry
    forward."""
    from soc_ai.oracle.client import adjudicate

    settings = _make_settings()
    ctx = _make_ctx(settings)

    action = RecommendedAction(
        tool_name="escalate_to_case",
        tool_args={"title": "Confirmed C2"},
        rationale="Beacon confirmed by payload decode.",
    )
    local = _stub_report(
        verdict="true_positive",
        confidence=0.55,
        citations=["evt-c2-777"],
        recommended_actions=[action],
    )

    with patch(
        "soc_ai.oracle.client._call_oracle_raw",
        AsyncMock(return_value=_verdict_json(verdict="true_positive", confidence=0.9)),
    ):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=local,
            transcript_text="",
        )

    assert result is not None
    assert result.report.verdict == "true_positive"
    assert result.report.citations == ["evt-c2-777"]
    assert result.report.recommended_actions == [action]


# ---------------------------------------------------------------------------
# Payload stays bounded with a large tool history
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_payload_bounded_with_large_tool_history() -> None:
    """200 fat tool results (~several MB raw) must not blow the request budget:
    the payload stays under a hard cap and the NEWEST results survive (the loop
    converges toward decisive evidence)."""
    from soc_ai.oracle.client import adjudicate

    settings = _make_settings()
    ctx = _make_ctx(settings)

    messages = []
    for i in range(200):
        hits = [
            {"_id": f"evt-{i}-{j}", "message": f"noise {i}-{j} " + ("x" * 300)} for j in range(40)
        ]
        messages.append(_msg(_tool_return("t_query_events_oql", {"total": 40, "hits": hits})))
    # The decisive, most recent result.
    messages.append(_msg(_tool_return("t_query_events_oql", _DECISIVE_TOOL_RESULT)))

    raw_size = len(json.dumps([m.parts[0].content for m in messages]))
    assert raw_size > 1_000_000  # sanity: the raw history really is huge

    captured: list[str] = []

    async def _capture(payload: str, *, settings: Any) -> str:
        captured.append(payload)
        return _verdict_json()

    with patch("soc_ai.oracle.client._call_oracle_raw", _capture):
        result = await adjudicate(
            ctx,
            enriched=_stub_enriched(),
            local_report=_stub_report(),
            transcript_text="prose " * 50_000,  # oversized prose transcript too
            loop_messages=messages,
        )

    assert result is not None
    assert len(captured) == 1
    payload = captured[0]
    assert len(payload) < 90_000, f"payload not bounded: {len(payload)} chars"
    # The newest (decisive) result survived the budget.
    assert "ConnectWise, LLC" in payload
    # The oldest noise did not.
    assert "evt-0-0" not in payload
