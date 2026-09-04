"""Stage-by-stage scoring of a scenario's hunt journey.

The flagship journey — **hunt** (an objective sweeps the network) →
**finding** (the hunt surfaces something, citing evidence) → **promote**
(the finding becomes an investigation) → **verdict** — gets one
:class:`JourneyResult` per scenario, attributing the FURTHEST stage the
journey legitimately reached. Per-stage attribution is the diagnostic
value: a single pass/fail would tell an operator almost nothing about
WHY the journey failed. The single-alert sibling is
:mod:`soc_ai.eval.synth_score`; this module is kept separate because the
two score different things.

Citation bridge — the one non-obvious join. A scenario's
``hunt_journey.expected_cited_event_ids`` are event ``index`` values
(events carry no id field; see :class:`~soc_ai.eval.synth_loader.HuntJourney`),
but a finding's citations are Elasticsearch ``_id``s that only exist
after ingest. The bridge is ``doc_ids_by_event``: event ``index`` → the
``_id``s ingest assigned to that scenario's docs, captured at ingest time
as :class:`~soc_ai.eval.synth_ingest.IngestResult`\\ ``.doc_ids_by_event``
(:func:`soc_ai.eval.synth_ingest._index_one` returns each ``_id``, and
``ingest_scenario`` records every one of them, keyed by the event's
``index``). Index-keying loses nothing: the expectations themselves are
index-granular. A citation counts for an expected event ONLY by exact
``_id`` membership in that event's ingested ids — the same resolution
discipline the post-hunt citation gate adopted in the 2026-08-25 audit
(:mod:`soc_ai.agent.hunt_gates`): substring/fuzzy matching over strings
the model (or an attacker-shaped doc) influences would silently report
false successes. When the bridge is missing an expected event, the
scorer REFUSES rather than scoring a journey that event could never win.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from soc_ai.eval.synth_loader import HuntJourney, Scenario
from soc_ai.store.models import Hunt, Investigation


class JourneyStage(StrEnum):
    """The furthest stage a scenario's hunt journey reached."""

    # The hunt surfaced no findings at all (including an errored hunt whose
    # report never landed) — the journey died at the hunt stage.
    HUNT_FOUND_NOTHING = "hunt_found_nothing"
    # Findings surfaced, but the finding→investigation boundary failed: no
    # finding cited any expected event, OR a right-evidence finding was never
    # promoted, OR the promotion anchored on a wrong-evidence finding. The
    # ``detail`` sentence says which.
    FINDING_NOT_PROMOTABLE = "finding_not_promotable"
    # Promoted from a right-evidence finding, but the investigation's verdict
    # is not the expected one (or hasn't landed yet).
    VERDICT_MISMATCH = "verdict_mismatch"
    # The full journey succeeded. Does NOT require every expected event cited
    # (promotability needs at least one) — coverage is read from
    # ``cited_expected_events``.
    COMPLETE = "complete"


@dataclass(frozen=True)
class JourneyResult:
    scenario_id: str
    reached: JourneyStage
    expected_verdict: str
    # The promoted investigation's verdict whenever one exists — reported even
    # when an earlier stage failed (a near-miss the operator should see);
    # None until a promoted investigation lands one.
    actual_verdict: str | None
    # Partial credit: the expected events that WERE cited (union across all
    # findings, in journey-declaration order), even when the stage failed —
    # so an operator can see how close the journey got.
    cited_expected_events: list[str]
    # One analyst-readable sentence naming what was missing at the failed
    # stage (or confirming completion).
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "reached": str(self.reached),
            "expected_verdict": self.expected_verdict,
            "actual_verdict": self.actual_verdict,
            "cited_expected_events": list(self.cited_expected_events),
            "detail": self.detail,
        }


def _finding_citation_sets(hunt: Hunt) -> list[frozenset[str]]:
    """Each finding's citations as an exact-string set, in report order.

    Reads the persisted ``HuntReport`` dict defensively: a malformed finding
    still COUNTS as surfaced (an empty citation set), so report corruption
    can never masquerade as ``HUNT_FOUND_NOTHING``.
    """
    report = hunt.report or {}
    raw = report.get("findings")
    if not isinstance(raw, list):
        return []
    sets: list[frozenset[str]] = []
    for finding in raw:
        citations = finding.get("citations") if isinstance(finding, dict) else None
        if isinstance(citations, list):
            sets.append(frozenset(c for c in citations if isinstance(c, str)))
        else:
            sets.append(frozenset())
    return sets


def _check_bridge(journey: HuntJourney, doc_ids_by_event: Mapping[str, Sequence[str]]) -> None:
    """Refuse a bridge that cannot resolve every expected event.

    An expected event with no ingested ``_id``s is uncitable by construction —
    scoring on would report ``FINDING_NOT_PROMOTABLE`` no matter what the hunt
    did, a false failure as poisonous to the diagnostic as a false success.
    """
    unbridged = [e for e in journey.expected_cited_event_ids if not doc_ids_by_event.get(e)]
    if unbridged:
        raise ValueError(
            f"doc_ids_by_event carries no ingested _ids for expected event(s) "
            f"{unbridged}; the citation bridge must be captured at ingest time "
            f"for every expected event — refusing to score a journey those "
            f"events could never win"
        )


def _check_promotion_join(hunt: Hunt, investigation: Investigation, n_findings: int) -> int:
    """Refuse a promoted row that does not join to the hunt being scored.

    Silently accepting a stray row would attribute another journey's verdict
    to this scenario. The join keys are migration 0031's provenance columns.
    Returns the validated ``finding_ordinal``.
    """
    if investigation.hunt_id != hunt.id:
        raise ValueError(
            f"investigation {investigation.id!r} was promoted from hunt "
            f"{investigation.hunt_id!r}, not the hunt being scored ({hunt.id!r})"
        )
    ordinal = investigation.finding_ordinal
    if ordinal is None or not 0 <= ordinal < n_findings:
        raise ValueError(
            f"investigation {investigation.id!r} has finding_ordinal={ordinal!r}, "
            f"which is not an index into the hunt's {n_findings} finding(s)"
        )
    return ordinal


def score_journey(
    scenario: Scenario,
    *,
    hunt: Hunt,
    investigation: Investigation | None,
    doc_ids_by_event: Mapping[str, Sequence[str]],
) -> JourneyResult:
    """Walk hunt → finding → investigation and attribute the furthest stage.

    Args:
        scenario: the catalogue scenario; must declare a ``hunt_journey``.
        hunt: the persisted synth-eval hunt row that ran the journey's
            objective (must carry the Task 4 ``is_synth_eval`` marker — an
            unmarked hunt could never have seen the planted docs, so scoring
            it would only ever produce a false failure).
        investigation: the investigation promoted from this hunt, or None if
            the promotion never happened. Its ``hunt_id``/``finding_ordinal``
            join keys must point back at ``hunt``.
        doc_ids_by_event: the ingest-time citation bridge — event ``index`` →
            the ES ``_id``s ingest assigned to that scenario's docs. Must
            cover every expected event (see module docstring).

    A finding is *promotable to the right evidence* when it cites at least one
    expected event's ingested ``_id`` (exact membership). ``COMPLETE``
    additionally requires that the finding the investigation was actually
    promoted from is such a finding, and that the verdict matches — a verdict
    landed on top of the wrong evidence stays ``FINDING_NOT_PROMOTABLE``.
    """
    journey = scenario.hunt_journey
    if journey is None:
        raise ValueError(f"scenario {scenario.id!r} declares no hunt_journey; nothing to score")
    if not hunt.is_synth_eval:
        raise ValueError(
            f"hunt {hunt.id!r} is not is_synth_eval-marked: it could not have "
            f"seen the planted scenario docs, so a journey score would be a "
            f"guaranteed false failure"
        )
    _check_bridge(journey, doc_ids_by_event)

    citation_sets = _finding_citation_sets(hunt)
    promoted_ordinal: int | None = None
    if investigation is not None:
        promoted_ordinal = _check_promotion_join(hunt, investigation, len(citation_sets))

    expected = journey.expected_cited_event_ids
    expected_verdict: str = journey.expected_promoted_verdict
    actual_verdict = investigation.verdict if investigation is not None else None

    # ── Stage 1: did the hunt surface anything at all? ──────────────────────
    if not citation_sets:
        return JourneyResult(
            scenario_id=scenario.id,
            reached=JourneyStage.HUNT_FOUND_NOTHING,
            expected_verdict=expected_verdict,
            actual_verdict=actual_verdict,
            cited_expected_events=[],
            detail=f"The hunt surfaced no findings at all (hunt status {hunt.status!r}).",
        )

    # ── Stage 2: is a finding promotable to the RIGHT evidence? ─────────────
    ids_by_event = {e: frozenset(doc_ids_by_event[e]) for e in expected}
    # Partial credit (union across findings, journey-declaration order).
    cited = [e for e in expected if any(ids_by_event[e] & cites for cites in citation_sets)]
    # An empty expectation list makes every finding vacuously promotable.
    promotable = [
        i
        for i, cites in enumerate(citation_sets)
        if not expected or any(ids_by_event[e] & cites for e in expected)
    ]

    if not promotable:
        return JourneyResult(
            scenario_id=scenario.id,
            reached=JourneyStage.FINDING_NOT_PROMOTABLE,
            expected_verdict=expected_verdict,
            actual_verdict=actual_verdict,
            cited_expected_events=cited,  # [] by construction here
            detail=(
                f"{len(citation_sets)} finding(s) surfaced but none cited any "
                f"expected event ({', '.join(expected)}) — nothing was "
                f"promotable to the right evidence."
            ),
        )

    if investigation is None:
        return JourneyResult(
            scenario_id=scenario.id,
            reached=JourneyStage.FINDING_NOT_PROMOTABLE,
            expected_verdict=expected_verdict,
            actual_verdict=None,
            cited_expected_events=cited,
            detail=(
                f"Finding {promotable[0]} cited expected evidence but was "
                f"never promoted to an investigation."
            ),
        )

    # Validated by _check_promotion_join above (investigation is not None here).
    ordinal = promoted_ordinal
    if ordinal is None:  # pragma: no cover - unreachable, join check ran
        raise ValueError(f"investigation {investigation.id!r} has no finding_ordinal")
    if ordinal not in promotable:
        return JourneyResult(
            scenario_id=scenario.id,
            reached=JourneyStage.FINDING_NOT_PROMOTABLE,
            expected_verdict=expected_verdict,
            actual_verdict=actual_verdict,
            cited_expected_events=cited,
            detail=(
                f"Promoted finding {ordinal} cited none of the expected events "
                f"({', '.join(expected)}); finding(s) "
                f"{', '.join(str(i) for i in promotable)} did but were not the "
                f"ones promoted."
            ),
        )

    # ── Stage 3: did the promoted investigation land the expected verdict? ──
    if actual_verdict is None:
        detail = (
            f"Promoted investigation {investigation.id} has not landed a "
            f"verdict (status {investigation.status!r})."
        )
    elif actual_verdict != expected_verdict:
        detail = f"Promoted investigation landed {actual_verdict!r}, expected {expected_verdict!r}."
    else:
        detail = (
            f"Journey complete: cited {len(cited)}/{len(expected)} expected "
            f"event(s), promoted finding {ordinal}, and the investigation "
            f"landed {actual_verdict!r}."
        )
    return JourneyResult(
        scenario_id=scenario.id,
        reached=(
            JourneyStage.COMPLETE
            if actual_verdict == expected_verdict
            else JourneyStage.VERDICT_MISMATCH
        ),
        expected_verdict=expected_verdict,
        actual_verdict=actual_verdict,
        cited_expected_events=cited,
        detail=detail,
    )
