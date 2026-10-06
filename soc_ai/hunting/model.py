"""The ``model`` evaluator: a spec that runs a tier 3 detector.

The third evaluator beside ``match`` and ``profile``. A ``model`` spec names a
detector and its parameters. The hourly prior sweep runs it with the same
time anchor as the profile specs, and its hits become observations with
source ``model``. Observations form leads, and the lead hunt triages them. The
analytic lifecycle and the ledger keep their meaning.

The evaluator holds the two rules every detector shares:

* **The false-all-clear rule.** Each entity a detector considered lands in
  the sweep with one of seven states (:data:`DETECTOR_STATES`), and the sweep
  notes count them per spec. Only ``measured`` means scored.
* **No hit without a document.** A hit that cites no document is dropped
  here, before any result or observation is built, and the drop is counted
  in the result and stated in a note.

A ``model`` observation is shadow when its analytic is. See :func:`record_model_hits`.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.detectors import logon_chain, plane_silence
from soc_ai.hunting.detectors.base import (
    DETECTOR_STATES,
    STATE_BLIND,
    Detector,
    DetectorContext,
    DetectorRun,
    ModelHit,
)
from soc_ai.hunting.leads import MAX_DOCUMENT_IDS, content_fingerprint, record_observation
from soc_ai.hunting.priors import PriorResult
from soc_ai.hunting.receipts import build_receipts, overlap_with_live
from soc_ai.hunting.spec import HuntSpec
from soc_ai.hunting.weight import Kind
from soc_ai.hunting.wording import plural

__all__ = [
    "DETECTORS",
    "MODEL_SOURCE",
    "ModelOutcome",
    "record_model_hits",
    "run_model_specs",
    "state_note",
]

# The observation source a ``model`` hit is written under. ``source`` names the
# adapter that wrote the row; ``shadow`` carries the status.
MODEL_SOURCE = "model"

# The detectors, by the id a spec names. A test replaces an entry to plant a
# hit.
DETECTORS: dict[str, Detector] = {
    plane_silence.DETECTOR_ID: plane_silence.detect,
    logon_chain.DETECTOR_ID: logon_chain.detect,
}

# The observation kind of each detector, for a result that holds no hit.
_KIND_OF: dict[str, Kind] = {
    "cross_plane_silence": Kind.TELEMETRY_SILENCE,
    "logon_chain": Kind.LOGON_CHAIN,
}


@dataclass(frozen=True)
class ModelOutcome:
    """What the model specs of one sweep concluded."""

    results: tuple[PriorResult, ...] = ()
    notes: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    # Hits dropped because they cited no document, over every model spec.
    dropped: int = 0


def _kind_of(spec: HuntSpec) -> Kind:
    detector = spec.model.detector if spec.model is not None else ""
    return _KIND_OF.get(detector, Kind.TELEMETRY_SILENCE)


def _blind(spec: HuntSpec, reason: str) -> PriorResult:
    """The one result of a detector that could read nothing."""
    return PriorResult(
        spec_id=spec.id,
        entity_kind="host",
        entity_key="*",
        coverage=STATE_BLIND,
        note=reason,
        kind=_kind_of(spec),
    )


def state_note(spec_id: str, counts: Counter[str]) -> str:
    """The per-entity states of one detector run, as one sentence.

    Every state is named, a zero too, so a run that measured nothing reads
    as such and never as a quiet estate.
    """
    parts = ", ".join(f"{state} {counts.get(state, 0)}" for state in DETECTOR_STATES)
    return f"{spec_id}: entity states: {parts}."


def _dropped_note(spec_id: str, dropped: int) -> str:
    return (
        f"{spec_id}: {plural(dropped, 'hit')} cited no document. soc-ai dropped "
        f"{'it' if dropped == 1 else 'them'} and wrote no observation."
    )


async def _run_one(spec: HuntSpec, detector: Detector, ctx: DetectorContext) -> DetectorRun:
    assert spec.model is not None
    return await detector(spec.model.params, ctx)


async def run_model_specs(specs: Sequence[HuntSpec], *, ctx: DetectorContext) -> ModelOutcome:
    """Run every ``model`` spec once against the context. Never raises.

    A detector that raises, or that names no registered detector, makes its
    spec blind for this run, with the error stated. A part of the estate
    scored as the whole is the false all-clear this layer exists to prevent.
    """
    results: list[PriorResult] = []
    notes: list[str] = []
    errors: list[str] = []
    dropped_total = 0
    for spec in specs:
        if spec.model is None:
            continue
        detector_id = spec.model.detector
        detector = DETECTORS.get(detector_id)
        if detector is None:
            reason = f"no detector named {detector_id} is installed"
            errors.append(f"{spec.id}: {reason}")
            results.append(_blind(spec, reason))
            continue
        try:
            run = await _run_one(spec, detector, ctx)
        except Exception as exc:
            reason = f"the {detector_id} detector failed: {type(exc).__name__}: {exc}"
            errors.append(f"{spec.id}: {reason}")
            results.append(_blind(spec, reason))
            continue
        notes.extend(f"{spec.id}: {note}" for note in run.notes)
        if run.blind is not None:
            results.append(_blind(spec, run.blind))
            notes.append(f"{spec.id}: {run.blind}")
            continue

        counts: Counter[str] = Counter()
        dropped = 0
        for entity in run.entities:
            counts[entity.state] += 1
            # The false-all-clear rule, applied before any result exists. A
            # hit with no cited document never reaches the record path.
            kept = tuple(h for h in entity.hits if h.document_ids)
            lost = len(entity.hits) - len(kept)
            dropped += lost
            results.append(
                PriorResult(
                    spec_id=spec.id,
                    entity_kind=entity.entity_kind,
                    entity_key=entity.entity_key,
                    coverage=entity.state,
                    note=entity.note,
                    kind=kept[0].kind if kept else _kind_of(spec),
                    hits=kept,
                    dropped=lost,
                )
            )
        notes.append(state_note(spec.id, counts))
        if dropped:
            notes.append(_dropped_note(spec.id, dropped))
            dropped_total += dropped
    return ModelOutcome(
        results=tuple(results),
        notes=tuple(notes),
        errors=tuple(errors),
        dropped=dropped_total,
    )


def _baseline_block(hit: ModelHit) -> dict[str, Any]:
    """What the hit departed from, in numbers, for the receipts and the evidence."""
    return {
        "statistic": hit.statistic,
        "statistic_value": hit.statistic_value,
        "baseline_value": hit.baseline_value,
        "features": dict(hit.features),
    }


async def record_model_hits(
    db: AsyncSession, result: PriorResult, *, shadow: bool, now: datetime | None = None
) -> int:
    """Write each hit of one model result as an observation. Returns how many.

    ``shadow`` is the analytic's own status, as the profile path reads it from
    ``shadow_ids``. A shipped detector declares ``ships_as: shadow``, so its
    first deploy writes shadow observations, and an approval to live lifts
    that. The self-healing hold moves a live detector back to shadow.
    """
    written = 0
    at = now or datetime.now(UTC)
    for hit in result.hits:
        ids = [str(i) for i in hit.document_ids if i]
        if not ids:
            # The evaluator drops these first. This guard keeps a direct
            # caller to the same rule.
            continue
        overlap = await overlap_with_live(db, entity_key=hit.entity_key, sample_ids=ids, now=at)
        receipts = build_receipts(
            matched_ids=ids,
            matched_fields=[str(name) for name in hit.features],
            dry_run=None,
            overlap=overlap,
            baseline=_baseline_block(hit),
            profile=True,
            requires_dry_run=False,
            requires_matched_ids=True,
        ).as_dict()
        await record_observation(
            db,
            entity_kind=hit.entity_kind,
            entity_key=hit.entity_key,
            kind=hit.kind,
            spec_id=result.spec_id,
            fingerprint=content_fingerprint(MODEL_SOURCE, *hit.fingerprint),
            summary=hit.reason,
            evidence={
                "sample_ids": ids,
                "anchor_id": ids[0],
                "reason": hit.reason,
                "baseline": _baseline_block(hit),
                "receipts": receipts,
            },
            source=MODEL_SOURCE,
            shadow=shadow,
            observed_at=hit.observed_at,
            now=now,
            statistic=hit.statistic,
            statistic_value=hit.statistic_value,
            baseline_value=hit.baseline_value,
            document_ids=ids[:MAX_DOCUMENT_IDS],
            rerun_query=hit.rerun_query,
        )
        written += 1
    return written
