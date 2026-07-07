"""Mocked-ES harness + scenario runner for the golden-pipeline gate.

Builds an :class:`~soc_ai.agent.context.InvestigationContext` whose
Elasticsearch client is a deterministic double: ``ElasticClient.search`` is
replaced with a callable that inspects each query and returns the scenario's
canned hits (the triggering alert for the ``ids`` lookup, the scenario's pivots
for a ``community_id`` pivot query, empty otherwise). The FULL prefetch +
parse + enrichment + gate stack then runs for real over that canned data — so
this pins ``SoAlert.from_es_hit``, ``get_enriched_alert_context``, the decision
templates, and the deterministic post-synth gates, not just the orchestrator's
control flow.

:func:`run_scenario` drives ``investigate`` to completion and returns the final
verdict, confidence, and the set of event kinds seen.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, patch

from pydantic import SecretStr
from soc_ai.agent.context import InvestigationContext
from soc_ai.agent.orchestrator import investigate
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult

from tests.golden.model_double import patch_models_for_scenario
from tests.golden.scenarios import GoldenScenario


def _base_settings() -> Settings:
    """A minimal offline Settings tuned for a deterministic zero-network run.

    * ``oracle_enabled`` False (default) — no cloud second-opinion.
    * ``auto_ack_fp_enabled`` False — a confident-FP scenario must not attempt
      an SO write (which would need a live auth/SO client) or emit a spurious
      ``auto_ack`` event.
    * ``analyst_cloud_redaction`` False (default) — no egress guard.
    * ``verdict_consistency_samples`` 1 (default) — single synth, no re-vote.
    Per-scenario overrides (e.g. ``investigate_when_unsure``) are applied on top.
    """
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
        auto_ack_fp_enabled=False,
    )


def _make_search_double(scenario: GoldenScenario) -> AsyncMock:
    """An ``ElasticClient.search`` double keyed by query shape.

    * ``{"ids": {"values": [alert_id]}}`` (the alert lookup) → the alert hit.
    * a pivot ``bool`` query with a ``term`` on ``network.community_id`` → the
      scenario's ``community_id`` pivot hits (drives typed-Zeek signals like the
      solicited-ICMP-echo exchange).
    * anything else (host / user / process / file pivots, the host-risk agg,
      the behavioral-summary pivot) → empty hits.
    """
    alert_hit = {"_id": scenario.alert_id, "_source": scenario.alert_source}
    community_hits = [
        {"_id": h.get("_id", f"pivot-{i}"), "_source": h["_source"]}
        for i, h in enumerate(scenario.community_id_pivots)
    ]

    async def _search(index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        # Alert lookup by id.
        ids = _query_ids(query)
        if ids is not None:
            hits = [alert_hit] if scenario.alert_id in ids else []
            return EsSearchResult(total=len(hits), took_ms=1, hits=hits)
        # Pivot query — return community_id pivots only for the community_id term.
        term_field = _query_term_field(query)
        if term_field == "network.community_id":
            return EsSearchResult(total=len(community_hits), took_ms=1, hits=list(community_hits))
        # Host-risk aggregation, behavioral-summary pivot, and the other four
        # pivots contribute nothing in the golden set.
        aggs = kwargs.get("aggs")
        return EsSearchResult(
            total=0,
            took_ms=1,
            hits=[],
            aggregations={"rules": {"buckets": []}} if aggs else None,
        )

    return AsyncMock(side_effect=_search)


def _query_ids(query: dict[str, Any]) -> list[str] | None:
    """Extract the ids of a top-level ``{"ids": {"values": [...]}}`` query."""
    ids = query.get("ids")
    if isinstance(ids, dict):
        vals = ids.get("values")
        if isinstance(vals, list):
            return [str(v) for v in vals]
    return None


def _query_term_field(query: dict[str, Any]) -> str | None:
    """The field of the first ``term`` in a pivot ``bool.must`` clause, if any."""
    boolq = query.get("bool")
    if not isinstance(boolq, dict):
        return None
    for clause in boolq.get("must", []) or []:
        term = clause.get("term") if isinstance(clause, dict) else None
        if isinstance(term, dict) and term:
            return next(iter(term))
    return None


@dataclass
class ScenarioResult:
    verdict: str | None
    confidence: float | None
    event_kinds: set[str]
    events: list[Any]


def _make_ctx(scenario: GoldenScenario) -> InvestigationContext:
    settings = _base_settings()
    for key, value in scenario.settings_overrides.items():
        setattr(settings, key, value)

    # Construct a real ElasticClient with a mocked transport, then override its
    # ``search`` with the scenario double (same shape the pipeline calls).
    fake_transport = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_transport):
        elastic = ElasticClient(settings)
    elastic.search = _make_search_double(scenario)  # type: ignore[method-assign]

    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=elastic,
    )


async def run_scenario(scenario: GoldenScenario) -> ScenarioResult:
    """Replay a golden scenario end-to-end and collect the outcome.

    Runs ``investigate`` with the mocked ES + scripted model doubles, collects
    every yielded :class:`StepEvent`, and returns the final verdict/confidence
    (from the ``triage_report`` event) plus the set of event kinds seen.
    """
    ctx = _make_ctx(scenario)
    with patch_models_for_scenario(scenario.model_script):
        events = [ev async for ev in investigate(scenario.alert_id, ctx=ctx)]

    verdict: str | None = None
    confidence: float | None = None
    for ev in events:
        if ev.kind == "triage_report":
            verdict = ev.payload.get("verdict")
            confidence = ev.payload.get("confidence")

    return ScenarioResult(
        verdict=verdict,
        confidence=confidence,
        event_kinds={ev.kind for ev in events},
        events=events,
    )
