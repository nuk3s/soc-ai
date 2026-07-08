"""Tests for E4.2 deterministic investigation memory ("prior outcomes").

Store-level tier/filter/digest behavior lives in
``tests/test_store_investigations.py``; this file covers the pipeline wiring:

- round-1 block injection (present when enabled with seeded priors; absent when
  disabled / when there are no priors),
- the ``prior_outcomes`` timeline event (count + light items, emitted only when
  the block is injected),
- fail-soft on a store error (the investigation still completes),
- egress-guard interaction (a prior rationale's internal IP is redacted in the
  captured outbound message on the cloud-analyst path — the block is composed
  BEFORE the final sanitize sweep + ``_guard_egress``),
- the citation gate (prior-outcome text is prompt context, never materialized
  evidence — a citation quoting it does not resolve),
- config-console wiring (Memory keys visible + settable via the config API).

NO real gateway/model is ever called: the synth agent is a pydantic-ai
``TestModel`` stub whose ``run`` is an ``AsyncMock``, so
``fake_agent.run.call_args[0][0]`` IS the composed outbound round-1 prompt
(captured AFTER the sanitize sweep + egress check, exactly what would egress).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import InvestigationContext, investigate
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.tools.get_alert_context import EnrichedAlertContext

# NOTE: the rule name must not contain words the citation-gate tests quote
# ("prior"/"outcome"/"memory") — the semantic resolver matches word-boundary
# tokens against the WHOLE bundle dump, rule name included. It must also stay
# out of the malware/exploit class: a MALWARE-named rule trips the
# definitely-investigate + malware-rule-name gates, which would downgrade the
# stub FP verdict and muddy what these tests measure (memory wiring only).
RULE = "ET INFO Periodic Gateway Heartbeat"
SRC = "10.0.0.1"
DST = "10.0.0.2"

# Distinctive marker planted in seeded prior rationales. Long + unique so the
# block-presence assertions can't false-positive on unrelated prompt text, and
# so the citation-gate test exercises the >=8-char semantic-resolution branch.
MARKER = "heartbeat-Xq7Zk9pQ"

BLOCK_HEADER = "## Prior outcomes for similar alerts"


def _enriched(alert_id: str = "alert-001") -> EnrichedAlertContext:
    """Enriched stub whose alert carries the (rule, src, dest) the memory keys on."""
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            severity_label="low",
            rule_name=RULE,
            source_ip=SRC,
            destination_ip=DST,
        ),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _seed_prior(
    maker: Any,
    *,
    alert_es_id: str = "seed-1",
    rationale: str = f"Solicited echo replies; known {MARKER} pattern from the gateway.",
) -> str:
    """Seed one complete exact-triple prior; returns its investigation id."""
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_es_id,
            started_by="t",
            rule_name=RULE,
            src_ip=SRC,
            dest_ip=DST,
        )
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="false_positive",
            confidence=0.9,
            rationale=rationale,
        )
        return inv.id


def _make_ctx(settings: Settings, maker: Any = None) -> InvestigationContext:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=elastic,
        db_sessionmaker=maker,
    )


def _report(citations: list[str] | None = None) -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Internal heartbeat; expected periodic ICMP.",
        citations=citations if citations is not None else ["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )


def _strong_benign_candidate() -> Any:
    """Strong benign template match so a zero-tool FP verdict settles round-1."""
    from soc_ai.agent.decision_templates import CandidateVerdict

    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )


async def _drive(ctx: InvestigationContext, report: TriageReport) -> tuple[list[Any], Any]:
    """Run investigate() end-to-end with a stubbed synth agent.

    Returns ``(events, fake_agent)`` — ``fake_agent.run.call_args[0][0]`` is the
    composed outbound round-1 user message (post-sanitize, post-egress-check).
    """
    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=report))

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _enriched(aid)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=_strong_benign_candidate(),
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]
    return events, fake_agent


# =====================================================================
# Round-1 block injection + the prior_outcomes event
# =====================================================================


@pytest.mark.asyncio
async def test_memory_block_injected_when_enabled_with_priors(
    settings_kratos: Settings,
) -> None:
    """Memory on + a seeded exact-triple prior ⇒ the round-1 prompt carries the
    framed block and a light ``prior_outcomes`` event lands on the timeline."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    engine, maker = await _db(settings_kratos)
    prior_id = await _seed_prior(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx, _report())

    msg = fake_agent.run.call_args[0][0]
    assert BLOCK_HEADER in msg
    assert "CONTEXT ONLY" in msg and "NOT evidence" in msg
    assert "rule+src+dest" in msg
    assert MARKER in msg  # the prior's rationale digest made it into the prompt

    mem_ev = next(e for e in events if e.kind == "prior_outcomes")
    assert mem_ev.payload["count"] == 1
    assert mem_ev.payload["window_days"] == settings_kratos.memory_window_days
    assert mem_ev.payload["items"] == [
        {"id": prior_id, "verdict": "false_positive", "matched_on": "rule+src+dest"}
    ]
    # Light payload guarantee: rationale text lives in the prompt, never the event.
    assert MARKER not in json.dumps(mem_ev.payload)

    # The investigation still lands a verdict as usual.
    assert any(e.kind == "triage_report" for e in events)
    await engine.dispose()


@pytest.mark.asyncio
async def test_memory_block_absent_when_disabled(settings_kratos: Settings) -> None:
    """Default-off: with priors seeded but the flag off, the prompt and the
    event stream are byte-identical to the pre-E4.2 shape (no block, no event)."""
    settings_kratos.investigate_when_unsure = False
    assert settings_kratos.memory_enabled is False  # the shipped default
    engine, maker = await _db(settings_kratos)
    await _seed_prior(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx, _report())

    msg = fake_agent.run.call_args[0][0]
    assert BLOCK_HEADER not in msg
    assert MARKER not in msg
    assert not any(e.kind == "prior_outcomes" for e in events)
    await engine.dispose()


@pytest.mark.asyncio
async def test_memory_block_absent_when_no_priors(settings_kratos: Settings) -> None:
    """Memory on but nothing relevant in the store ⇒ no block AND no event —
    an empty recall must not spend prompt tokens or timeline rows."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    engine, maker = await _db(settings_kratos)  # empty investigations table
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx, _report())

    assert BLOCK_HEADER not in fake_agent.run.call_args[0][0]
    assert not any(e.kind == "prior_outcomes" for e in events)
    await engine.dispose()


@pytest.mark.asyncio
async def test_memory_store_error_is_fail_soft(settings_kratos: Settings) -> None:
    """A store error during recall logs + skips memory; the investigation still
    completes with a verdict (memory must never kill a run)."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    engine, maker = await _db(settings_kratos)
    await _seed_prior(maker)
    ctx = _make_ctx(settings_kratos, maker)

    with patch(
        "soc_ai.store.investigations.prior_outcomes",
        AsyncMock(side_effect=RuntimeError("db exploded")),
    ):
        events, fake_agent = await _drive(ctx, _report())

    assert BLOCK_HEADER not in fake_agent.run.call_args[0][0]
    assert not any(e.kind == "prior_outcomes" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert events[-1].kind == "done"
    await engine.dispose()


# =====================================================================
# Egress guard: the block rides the sanitize sweep + fail-closed check
# =====================================================================


@pytest.mark.asyncio
async def test_memory_block_redacted_on_cloud_analyst_path(
    settings_kratos: Settings,
) -> None:
    """With analyst_cloud_redaction + fail-closed ON, an internal IP inside a
    prior's rationale digest is redacted in the captured outbound message —
    proving the block is composed BEFORE the final sanitize sweep and
    ``_guard_egress``. Fail-closed makes this loud: had the IP survived, the
    model would never have been called (egress_blocked) and this test fails."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    settings_kratos.analyst_cloud_redaction = True
    settings_kratos.analyst_redaction_fail_closed = True
    engine, maker = await _db(settings_kratos)
    leak_ip = "10.99.88.77"
    await _seed_prior(
        maker,
        rationale=f"Beacon to {leak_ip} was change-window noise; cleared by the network team.",
    )
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx, _report())

    assert fake_agent.run.called, "the model call must proceed (nothing leaked)"
    assert not any(e.kind == "egress_blocked" for e in events)
    msg = fake_agent.run.call_args[0][0]
    # The block is present (its non-identifier prose survives)…
    assert BLOCK_HEADER in msg
    assert "change-window noise" in msg
    # …but the prior's internal IP was redacted to an opaque label.
    assert leak_ip not in msg
    await engine.dispose()


# =====================================================================
# Citation gate: priors are prompt context, never resolvable evidence
# =====================================================================


def test_prior_outcome_citation_does_not_resolve() -> None:
    """A citation quoting prior-outcome text has nothing to resolve against —
    the evidence bundle is the enriched context + tool history, and priors are
    deliberately NOT materialized into it. Unit-level proof on the exact
    resolver the pipeline uses."""
    from soc_ai.agent.gates import _resolve_citations

    citation = f"prior outcome: false_positive — {MARKER} (rule+src+dest)"
    res = _resolve_citations([citation], _enriched(), [], messages=None)
    assert res["counts"]["valid"] == 0
    assert res["counts"]["unresolved"] == 1
    assert res["coverage_ratio"] == 0.0


@pytest.mark.asyncio
async def test_report_citing_only_prior_text_fails_citation_gate(
    settings_kratos: Settings,
) -> None:
    """End-to-end gate check: with memory injected, a report whose ONLY
    citations quote the prior-outcome block resolves zero citations — the
    prompt block never becomes citable evidence, so the confidence-cap /
    floor machinery sees coverage 0 exactly as designed."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    engine, maker = await _db(settings_kratos)
    await _seed_prior(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(
        ctx, _report(citations=[f"prior outcome {MARKER} was false_positive"])
    )

    # The block WAS in the prompt (the citation is quoting something real)…
    assert MARKER in fake_agent.run.call_args[0][0]
    # …yet it resolves to nothing: the gate holds.
    cit_ev = next(e for e in events if e.kind == "citation_validation")
    assert cit_ev.payload["counts"]["valid"] == 0
    assert cit_ev.payload["coverage_ratio"] == 0.0
    await engine.dispose()


# =====================================================================
# Config console wiring
# =====================================================================


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def test_memory_settings_visible_and_settable_via_config(settings_kratos: Settings) -> None:
    for client in _client(settings_kratos):
        groups = {g["title"]: g["items"] for g in client.get("/api/v1/config").json()["groups"]}
        assert "Memory" in groups
        keys = {item["key"] for item in groups["Memory"]}
        assert keys == {"memory_enabled", "memory_window_days", "memory_max_items"}

        # All three are hot-apply (the orchestrator reads settings per run).
        # Values are stringified — the route coerces server-side (SettingIn.value).
        resp = client.post(
            "/api/v1/config/setting", json={"key": "memory_enabled", "value": "true"}
        )
        assert resp.status_code == 200
        assert resp.json()["restart_required"] is False
        resp = client.post(
            "/api/v1/config/setting", json={"key": "memory_window_days", "value": "30"}
        )
        assert resp.status_code == 200

        groups = {g["title"]: g["items"] for g in client.get("/api/v1/config").json()["groups"]}
        by_key = {item["key"]: item for item in groups["Memory"]}
        assert by_key["memory_enabled"]["value"] is True
        assert by_key["memory_enabled"]["source"] == "db"
        assert by_key["memory_window_days"]["value"] == 30
        # Out-of-bounds values are rejected by the spec bounds.
        resp = client.post("/api/v1/config/setting", json={"key": "memory_max_items", "value": "9"})
        assert resp.status_code == 400
