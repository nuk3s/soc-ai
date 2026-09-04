"""Run ONE scenario's hunt journey end to end and score it.

The flagship journey — **hunt** → **finding** → **promote** → **investigate**
→ **verdict** — has had every measuring piece since the quality-spine slice
landed (:mod:`soc_ai.eval.journey` scores it, ingest captures the citation
bridge, the runners carry the synth-eval marker) but nothing that ORCHESTRATES
them. This module is that orchestrator, behind ``soc-ai eval-journey``.

It reuses the REAL paths at every stage, so a journey score measures the
product and not a harness:

* ingest via :func:`soc_ai.eval.synth_ingest.ingest_scenarios` (which runs the
  production-containment pre-check before a single write);
* the hunt via :func:`soc_ai.api.hunt_runner.hunt_recorded_run` — the same
  recorded path the Hunt Console uses, drained inline instead of in a
  background task, under a context with ``include_synth=True``. That context
  is the ONE thing no API path ever builds (``ctx_from_state`` deliberately
  leaves the opt-in off), so it is threaded here, minimally, exactly as the
  eval harness does for single-alert runs;
* the promotion via the chain beneath ``POST /hunts/{id}/findings/{o}/
  investigate``: the route's own anchor resolution
  (:func:`soc_ai.api.webui.routes_hunts._resolve_finding_anchor`) and
  :func:`soc_ai.api.runner.run_recorded` with the route's exact kwargs
  (``kind="hunt"``, the provenance join keys, ``allow_so_writes=False``,
  ``focus_origin="hunt_finding"``, the inherited synth-eval marker). The
  route itself is not callable without a live app+Request; the manager it
  calls only adds background-task bookkeeping a CLI drains inline anyway.

Grid hygiene is deliberately the CALLER's job: run ``soc-ai synth-clean``
before (a stale fixture must not score this run) and after (no planted doc may
outlive the eval) — this runner never deletes anything from the grid itself.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from soc_ai.config import Settings
from soc_ai.eval.journey import (
    JourneyResult,
    JourneyStage,
    _finding_citation_sets,
    score_journey,
)
from soc_ai.eval.synth_loader import HuntJourney, Scenario
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store.models import Hunt, Investigation

_LOGGER = logging.getLogger(__name__)

# Exit codes shared with the CLI (documented in `soc-ai eval-journey --help`):
# 0 = the journey reached COMPLETE; 1 = it fell short (the JourneyResult says
# where — a legitimate, reportable outcome, distinct from a broken run);
# 2 = the scenario declares no hunt_journey; 5 = the run itself failed.
EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 1
EXIT_NO_JOURNEY = 2
EXIT_ERROR = 5

# `started_by` on the hunt + investigation rows, so a journey run is
# attributable in the UI and never mistaken for an analyst's own work.
STARTED_BY = "journey-eval"


@dataclass
class JourneyRunOutcome:
    """What one journey run produced, for the CLI to print and exit on."""

    exit_code: int
    # The stage-attributed score; None only when the run never got far enough
    # to score (ingest refusal, missing journey, scorer refusal) — ``detail``
    # then carries the reason.
    result: JourneyResult | None = None
    hunt_id: str | None = None
    investigation_id: str | None = None
    detail: str = ""


@dataclass
class _RunnerState:
    """The minimal ``app.state`` shape the recorded-run paths read.

    ``hunt_recorded_run`` / ``run_recorded`` touch only ``db_sessionmaker``
    (the recorders), ``settings`` (the whole-run backstop + the notify
    posture) and ``audit`` (the notify path's fail-soft channel; None here —
    the eval harness precedent).
    """

    settings: Settings
    db_sessionmaker: Any
    audit: Any = None


def _best_promotable_ordinal(
    journey: HuntJourney, hunt: Hunt, doc_ids_by_event: Mapping[str, Sequence[str]]
) -> int | None:
    """The finding to promote: the one citing the MOST expected events.

    Mirrors :func:`soc_ai.eval.journey.score_journey`'s promotability rule
    (exact ingested-``_id`` membership) so the runner promotes exactly what
    the scorer can credit. Ties break to the earliest finding; an empty
    expectation list makes finding 0 the pick (every finding is vacuously
    promotable then). None when no finding qualifies — the runner then skips
    promotion rather than spending a real investigation on a journey the
    scorer will attribute to the finding boundary regardless.
    """
    citation_sets = _finding_citation_sets(hunt)
    if not citation_sets:
        return None
    expected = journey.expected_cited_event_ids
    if not expected:
        return 0
    ids_by_event = {e: frozenset(doc_ids_by_event.get(e) or ()) for e in expected}
    coverage = [sum(1 for e in expected if ids_by_event[e] & cites) for cites in citation_sets]
    best = max(range(len(coverage)), key=lambda i: (coverage[i], -i))
    return best if coverage[best] else None


async def _promote_and_investigate(
    state: _RunnerState,
    ctx: Any,
    *,
    hunt: Hunt,
    ordinal: int,
    elastic: ElasticClient,
    emit: Callable[[str], None],
) -> str | None:
    """Promote finding ``ordinal`` through the real chain; return the inv id.

    Reuses the promotion route's own anchor resolution and passes
    ``run_recorded`` the exact kwargs the route's manager call does. Draining
    the generator to exhaustion IS waiting for a terminal status — the
    recorder finalizes the row before the stream ends. Returns None when no
    citation resolves to a doc on the grid (the route's 422 arm) — the scorer
    then attributes the never-promoted finding.
    """
    # Lazy: routes_hunts drags the FastAPI webui module graph; the runner only
    # needs its anchor picker (telemetry-beats-detector, id-shaped ids only).
    from soc_ai.api.runner import run_recorded  # noqa: PLC0415 - lazy
    from soc_ai.api.webui.routes_hunts import _resolve_finding_anchor  # noqa: PLC0415 - lazy

    findings = (hunt.report or {}).get("findings") or []
    finding: dict[str, Any] = findings[ordinal] if isinstance(findings[ordinal], dict) else {}
    raw_citations = finding.get("citations")
    if not isinstance(raw_citations, list):
        raw_citations = []
    # Same don't-trust-stored-JSON coercion as the route.
    citations = [str(c) for c in raw_citations if isinstance(c, (str, int))]
    anchor_id = await _resolve_finding_anchor(elastic, state.settings, citations)
    if anchor_id is None:
        emit(f"finding {ordinal}: no citation resolves to a grid doc — cannot promote")
        return None

    title = str(finding.get("title") or "Hunt finding")
    detail = str(finding.get("detail") or "")
    hosts = ", ".join(str(h) for h in (finding.get("hosts") or [])) or "—"
    # The promotion route's focus framing, verbatim — the investigation must
    # get the same brief a UI promotion would give it.
    focus = (
        f"Promoted hunt finding: {title}. {detail} Hosts involved: {hosts}. "
        "This investigation targets the finding's cited evidence event. Assess "
        "whether the finding describes real malicious activity; do not assume "
        "the hunt's framing is correct."
    )
    emit(f"promoting finding {ordinal} ({title}) on anchor {anchor_id}")

    inv_id: str | None = None
    async for name, data in run_recorded(
        state,
        ctx=ctx,
        alert_id=anchor_id,
        started_by=STARTED_BY,
        rule_name=title,
        focus_hint=focus,
        kind="hunt",
        hunt_id=hunt.id,
        finding_ordinal=ordinal,
        allow_so_writes=False,
        focus_origin="hunt_finding",
        is_synth_eval=True,
    ):
        if name == "investigation_created":
            inv_id = str(data.get("investigation_id"))
            emit(f"investigation {inv_id} running")
        elif name == "tool_call":
            payload = data.get("payload") or {}
            emit(f"  tool {payload.get('tool_name')}")
        elif name == "triage_report":
            payload = data.get("payload") or {}
            emit(f"verdict landed: {payload.get('verdict')!r}")
        elif name == "error":
            emit(f"investigation error: {data.get('message') or data}")
    return inv_id


def _eval_context(
    settings: Settings, *, auth: Any, elastic: ElasticClient, db_sessionmaker: Any
) -> Any:
    """Build the eval InvestigationContext — the one no API path ever builds.

    ``include_synth=True`` is the whole point: the hunt's tools (and the
    promoted investigation's prefetch) must see the planted docs, and both
    recorders derive the row's synth-eval marker from it. Mirrors the eval
    harness's ``_build_context`` (audit deliberately None), plus the store
    session factory the recorders and runbook lookups need.
    """
    from soc_ai.agent.orchestrator import (  # noqa: PLC0415 - lazy
        InvestigationContext,
        build_local_enrichment_context,
    )
    from soc_ai.tools.enrichment import MispClient  # noqa: PLC0415 - lazy

    enrichment = build_local_enrichment_context(settings)
    return InvestigationContext(
        settings=settings,
        auth=auth,
        elastic=elastic,
        misp=MispClient(settings) if settings.misp_url else None,
        audit=None,
        blocklist=enrichment.blocklist,
        maxmind=enrichment.maxmind,
        cloud=enrichment.cloud,
        include_synth=True,
        db_sessionmaker=db_sessionmaker,
    )


async def _drain_hunt(
    state: _RunnerState, ctx: Any, *, objective: str, emit: Callable[[str], None]
) -> str | None:
    """Run the recorded hunt inline; return the created hunt row's id.

    Draining ``hunt_recorded_run`` to exhaustion IS waiting for the hunt to
    finalize — the recorder lands the terminal status before the stream ends.
    """
    from soc_ai.api.hunt_runner import hunt_recorded_run  # noqa: PLC0415 - lazy

    hunt_id: str | None = None
    async for name, data in hunt_recorded_run(
        state, ctx=ctx, objective=objective, started_by=STARTED_BY, kind="chat"
    ):
        if name == "hunt_created":
            hunt_id = str(data.get("hunt_id"))
            emit(f"hunt {hunt_id} running")
        elif name == "tool_call":
            payload = data.get("payload") or {}
            emit(f"  tool {payload.get('tool_name')}")
        elif name == "error":
            payload = data.get("payload") or data
            message = payload.get("message") if isinstance(payload, dict) else payload
            emit(f"hunt error: {message}")
    return hunt_id


async def run_journey(
    settings: Settings,
    scenario: Scenario,
    *,
    elastic: ElasticClient,
    emit: Callable[[str], None] | None = None,
) -> JourneyRunOutcome:
    """Ingest ``scenario``, run its journey through the real chain, score it.

    ``elastic`` is caller-owned (built and closed by the CLI — the
    ``run_batch`` convention). The local store engine + the SO auth client
    are built and torn down here; migrations run first because the store may
    never have existed on this host (a scratch eval dir — the eval-nightly /
    discover-internal-identifiers idiom).
    """
    # Lazy: keep the module import light (the CLI imports this on dispatch).
    from soc_ai.eval.synth_ingest import ingest_scenarios  # noqa: PLC0415 - lazy
    from soc_ai.so_client.auth import make_auth  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    journey = scenario.hunt_journey
    if journey is None:
        return JourneyRunOutcome(
            exit_code=EXIT_NO_JOURNEY,
            detail=f"scenario {scenario.id!r} declares no hunt_journey — nothing to run",
        )

    def _emit(line: str) -> None:
        if emit is not None:
            emit(line)

    engine = make_engine(settings)
    auth = make_auth(settings)
    try:
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        ctx = _eval_context(settings, auth=auth, elastic=elastic, db_sessionmaker=maker)
        state = _RunnerState(settings=settings, db_sessionmaker=maker)

        # ── 1. Ingest (containment pre-check inside; hygiene is the caller's) ─
        try:
            ingest = (
                await ingest_scenarios([scenario], elastic=elastic, run_time=datetime.now(UTC))
            )[0]
        except Exception as e:
            return JourneyRunOutcome(exit_code=EXIT_ERROR, detail=f"ingest refused/failed: {e}")
        _emit(
            f"ingested {ingest.doc_count} doc(s) for {scenario.id} "
            f"(triage target {ingest.triage_doc_id})"
        )

        # ── 2. Hunt — the real recorded path, drained inline ──────────────────
        _emit(f"hunt objective: {journey.objective}")
        hunt_id = await _drain_hunt(state, ctx, objective=journey.objective, emit=_emit)
        if hunt_id is None:
            return JourneyRunOutcome(
                exit_code=EXIT_ERROR, detail="hunt stream ended before creating a hunt row"
            )
        async with maker() as db:
            hunt = await db.get(Hunt, hunt_id)
        if hunt is None:
            return JourneyRunOutcome(
                exit_code=EXIT_ERROR, hunt_id=hunt_id, detail=f"hunt row {hunt_id} not found"
            )
        n_findings = len((hunt.report or {}).get("findings") or [])
        _emit(f"hunt {hunt_id} finished status={hunt.status!r} with {n_findings} finding(s)")

        # ── 3. Promote the best-matching finding through the real chain ───────
        investigation: Investigation | None = None
        inv_id: str | None = None
        ordinal = _best_promotable_ordinal(journey, hunt, ingest.doc_ids_by_event)
        if ordinal is None:
            _emit(
                "no finding cites an expected event — skipping promotion "
                "(the scorer attributes the miss)"
            )
        else:
            inv_id = await _promote_and_investigate(
                state, ctx, hunt=hunt, ordinal=ordinal, elastic=elastic, emit=_emit
            )
            if inv_id is not None:
                async with maker() as db:
                    investigation = await db.get(Investigation, inv_id)

        # ── 4. Score ──────────────────────────────────────────────────────────
        try:
            result = score_journey(
                scenario,
                hunt=hunt,
                investigation=investigation,
                doc_ids_by_event=ingest.doc_ids_by_event,
            )
        except ValueError as e:
            return JourneyRunOutcome(
                exit_code=EXIT_ERROR,
                hunt_id=hunt_id,
                investigation_id=inv_id,
                detail=f"scorer refused: {e}",
            )
        return JourneyRunOutcome(
            exit_code=(
                EXIT_COMPLETE if result.reached is JourneyStage.COMPLETE else EXIT_INCOMPLETE
            ),
            result=result,
            hunt_id=hunt_id,
            investigation_id=inv_id,
            detail=result.detail,
        )
    finally:
        with contextlib.suppress(Exception):
            await auth.aclose()
        with contextlib.suppress(Exception):
            await engine.dispose()
