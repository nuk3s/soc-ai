"""Run the catalog, gate the results, and record what survives.

The whole path in one function: for every spec, query the grid, drop conditions
already handled, and record the rest. A fresh candidate becomes an observation
on its entity, so the lead layer can join it with what the profile analytics
saw on the same entity. A visibility gap still records a hunt row. No model
runs at any point.

**Deliberately not a background loop.** This is a function an operator or a
scheduler calls. Wiring it into the lifespan task set is a separate change with
a separate flag, because an unattended loop that writes findings has a different
risk profile from one somebody typed, and the ordering here — gate before
record — is the part that wants to be proven first.

**A sweep records at most one hunt per spec.** Not one per candidate: the
findings of a spec that surfaced four accounts belong in one place an analyst
reads once, and four hunts would fragment the same condition across four rows.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.config import Settings
from soc_ai.hunting.execute import Candidate, SpecRun, run_spec
from soc_ai.hunting.findings import spec_report
from soc_ai.hunting.receipts import DRY_RUN_WINDOW_DAYS, build_receipts, overlap_with_live
from soc_ai.hunting.sources import observe_catalog_hits
from soc_ai.hunting.spec import HuntSpec
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import hunts as hunts_store
from soc_ai.store.hunt_spec_state import GAP_SCOPE, apply_gate, link_handled, link_hunt
from soc_ai.store.hunt_spec_sweeps import record as record_sweep
from soc_ai.tools._synth_scope import SynthScope

_LOGGER = logging.getLogger(__name__)

# Who a spec-authored hunt is attributed to. Not a real account, and
# deliberately not the operator who happened to start the sweep: nobody chose
# this hunt's objective, the catalog did.
SWEEP_ACTOR = "hunt-catalog"

# ``GAP_SCOPE`` is the scope a blind or errored run is gated on. A spec with no
# candidates cannot be gated on its candidates, and without a gate the blind
# path re-recorded a hunt on EVERY sweep: twenty-four sweeps of a permanently
# blind spec produced twenty-four hunts and twenty-four notification-bell
# entries, evicting the real ones. A deployment without OpenCanary is
# permanently blind on that spec by construction, so this is the normal case
# rather than an edge. It is defined in the gate rather than here because the
# gate is what treats it specially; see `soc_ai.store.hunt_spec_state`.


@dataclass
class SweepResult:
    """What one sweep did, per spec and in total."""

    ran: list[str] = field(default_factory=list)
    blind: list[str] = field(default_factory=list)
    errored: dict[str, str] = field(default_factory=dict)
    hunts: dict[str, str] = field(default_factory=dict)
    fresh_candidates: int = 0
    # Three different facts that were once summed into one field called
    # "suppressed" and reported as "held back by the budget". They are not the
    # same thing and conflating them made the number a lie: a run that held
    # back nothing reported three.
    already_handled: int = 0
    over_budget: int = 0
    truncated_docs: int = 0
    # Documents no spec in this sweep could decide, because an exclusion read a
    # field they do not carry. Summed across specs for the same reason
    # ``truncated_docs`` is: a sweep that reports only what it surfaced cannot
    # be told from one that surfaced nothing because it discarded everything.
    undecided_docs: int = 0
    # Blind specs whose gap was NEWLY reported this sweep, as opposed to blind
    # specs the gate already knows about. `len(blind)` counts both, so without
    # this a permanently-blind deployment looks identical to one that just went
    # dark — which is the transition an operator actually needs to see.
    blind_reported: int = 0
    # The other half of that transition, and it was missing entirely. A spec
    # whose plane came back retires its gap inside the gate, which is a column
    # update: no hunt, no bell entry, nothing on the report. So the sweep that
    # ended an outage was indistinguishable from the hundred sweeps before it
    # where nothing had been wrong, and "the blind marker is gone" was the only
    # evidence recovery had happened — a marker's ABSENCE, read by whoever
    # happened to remember it was there.
    #
    # Counted per spec, not per gap, in the sense that matters: a spec has one
    # plane and therefore one open gap, so this is normally the number of specs
    # that recovered on this sweep. Zero on an ordinary sweep, which is what
    # keeps it news.
    gaps_cleared: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ran": list(self.ran),
            "blind": list(self.blind),
            "errored": dict(self.errored),
            "hunts": dict(self.hunts),
            "fresh_candidates": self.fresh_candidates,
            "already_handled": self.already_handled,
            "over_budget": self.over_budget,
            "truncated_docs": self.truncated_docs,
            "undecided_docs": self.undecided_docs,
            "blind_reported": self.blind_reported,
            "gaps_cleared": self.gaps_cleared,
        }


async def sweep_spec(
    spec: HuntSpec,
    *,
    session: AsyncSession,
    elastic: ElasticClient,
    settings: Settings,
    since: str,
    until: str,
    now: datetime,
    backfill: bool = False,
    include_synth: SynthScope = False,
    record: bool = True,
    shadow_ids: frozenset[str] = frozenset(),
) -> tuple[SpecRun, str | None]:
    """Run one spec, gate it, and record a hunt if anything survived.

    Returns the run and the recorded hunt id, or ``None`` when nothing was
    recorded. A blind or errored run IS recorded, because both produce a
    ``visibility_gap`` finding an operator needs to see — silence there would be
    the false all-clear the precondition exists to prevent.

    A spec in ``shadow_ids`` runs beside the live ones and writes shadow
    observations with receipts. It records no hunt row and no visibility gap:
    an analytic that is being assessed must not spend the fire-once budget of
    the catalog, and a gap on an analytic nobody approved is not news.
    """
    shadow_spec = spec.id in shadow_ids
    started = time.monotonic()
    run = await run_spec(
        spec,
        elastic=elastic,
        settings=settings,
        since=since,
        until=until,
        include_synth=include_synth,
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    run = replace(run, duration_ms=duration_ms)

    if run.blind or run.error is not None:
        # Gate the gap the same way a finding is gated, so it reports once and
        # re-reports on TRANSITION (blind -> seeing -> blind) rather than every
        # sweep. The gate keys the gap on its SCOPE rather than on its
        # fingerprint, so while one gap is open a change of reason is a change
        # of detail on the same gap: the reason strings are not stable enough
        # to drive a report (an errored run carries the exception text, which
        # carries a shard count on a partial result and a rolled-over index
        # name on an API error).
        #
        # The retirement is the gate's, not this function's. Passing the run's
        # real candidates on a seeing sweep is what tells it the spec can see,
        # and a caller cannot forget to do that because it is the same call
        # that gates the candidates.
        gap = _gap_candidate(spec.id, run.error or "precondition matched nothing")
        decision = await apply_gate(
            session, spec.id, [gap], now=now, seed_only=backfill or not record or shadow_spec
        )
        # Same contract as the seeing path: a backfill seeds and reports
        # nothing. The early return used to skip this check entirely, so
        # `--backfill` on a blind spec recorded a hunt and contradicted its own
        # documented behaviour.
        if not decision.fresh or not record or backfill or shadow_spec:
            return run, None
        # Named apart from the catalog hunt row below. The two are different
        # rows on different paths, and one name for both hid which row a reader
        # was looking at.
        gap_hunt_id = await _record(
            spec,
            run,
            session=session,
            since=since,
            until=until,
            is_synth_eval=bool(include_synth),
        )
        await link_hunt(session, spec.id, decision.fresh, gap_hunt_id)
        return run, gap_hunt_id

    # Shadow mode seeds too, not just backfill: a shadow evaluation that spent
    # the fire-once budget would silence the spec it was assessing. It is also
    # what stops a shadow or backfill sweep retiring a live visibility gap,
    # which is the same violation read the other way round.
    #
    # A seeing run can still be un-clean without producing a single candidate:
    # documents the detection could not decide for want of a field an exclusion
    # reads, documents it matched and could not group, and documents the bucket
    # ceiling left out. ``candidate_findings`` writes a finding for each and
    # nothing recorded them, because the early return below asks only whether a
    # CANDIDATE survived the gate. A spec that discarded 5,240 documents and
    # bucketed none of them left no hunt and no notification at all.
    #
    # They ride the same gap scope as a blind run, so they report once and
    # re-report on transition instead of on every sweep, and a sweep where the
    # condition has cleared passes no gap and retires the open one. First in the
    # list so the ``top_k`` budget cannot cut the reason the run is not clean.
    gate_input = list(run.candidates)
    if run.undecided_docs or run.unattributed_docs or run.truncated_docs:
        gate_input.insert(0, _gap_candidate(spec.id, _unclean_reason(run)))

    decision = await apply_gate(
        session,
        spec.id,
        gate_input,
        now=now,
        seed_only=backfill or not record or shadow_spec,
        top_k=spec.top_k,
    )
    # The gap is bookkeeping, not a finding. Left in the list it would render as
    # a threat candidate on an entity called "visibility-gap"; the counters it
    # stands for are already on the run and ``candidate_findings`` reads those.
    fresh = [c for c in decision.fresh if c.scope_key != GAP_SCOPE]
    gap_is_fresh = len(fresh) != len(decision.fresh)

    # Rebuild the run from what survived the gate, so the recorded findings and
    # the narrative describe what was actually surfaced rather than what was
    # found. A hunt claiming four candidates while showing one would be worse
    # than either number alone.
    gated = SpecRun(
        spec_id=run.spec_id,
        since=run.since,
        until=run.until,
        blind=False,
        precondition_docs=run.precondition_docs,
        # Carried through so the recorded report names the window the
        # precondition actually asked about, not the one the detection ran over.
        precondition_since=run.precondition_since,
        matched_docs=run.matched_docs,
        candidates=fresh,
        truncated_docs=run.truncated_docs,
        # Carried through unchanged: the gate removes candidates, it does not
        # make their documents unattributable, and it never saw the documents
        # the detection could not decide.
        unattributed_docs=run.unattributed_docs,
        undecided_docs=run.undecided_docs,
        # With the count, not without it: the breakdown is what the finding
        # names a field from, and the finding is composed from THIS run.
        undecided_by_field=run.undecided_by_field,
        gate_already_handled=len([c for c in decision.already_handled if not _is_gap(c)]),
        gate_over_budget=len(decision.over_budget),
        # Only ever non-zero on this path, and only on a run that passed no gap
        # candidate: an unclean run passes one, so a spec that stopped being
        # blind and started discarding documents has not recovered and must not
        # report that it has.
        gate_gaps_retired=decision.gaps_retired,
        duration_ms=run.duration_ms,
    )
    # A backfill never records a hunt even though it has fresh candidates:
    # seeding is for memory and a digest, not for N findings.
    if not (fresh or gap_is_fresh) or not record or backfill:
        return gated, None

    # A synth-scope sweep can read planted documents, so it keeps the old path
    # and records one marked hunt. Observations carry no synth marker, and an
    # unmarked row on a shared surface is planted evidence read back as real.
    # Production cannot set this scope. See the module docstring.
    #
    # A shadow analytic is excluded: a hunt row is the one thing a shadow
    # analytic must not write, whatever scope the sweep runs under.
    if include_synth and not shadow_spec:
        # Named apart from the catalog hunt row below, for the same reason the
        # gap row is: this one is marked as a synthetic-evaluation row.
        synth_hunt_id = await _record(
            spec,
            gated,
            session=session,
            since=since,
            until=until,
            is_synth_eval=True,
        )
        await link_hunt(session, spec.id, decision.fresh, synth_hunt_id)
        return gated, synth_hunt_id

    # A hit is an observation. It is not a hunt row. The observation carries the
    # evidence ids, and the lead layer joins it with what the profile analytics
    # observed on the same host. A gap that rides beside the hits still records
    # its hunt row below, until the Analytics tab gives it a home.
    #
    # ``catalog_hunt_rows`` restores the old write for one release. It is off by
    # default. On, the sweep writes the hunt row BESIDE the observation, so a
    # deployment that reads the hit off the hunt list keeps its surface while it
    # moves. The observation is written either way.
    hunt_id: str | None = None
    if fresh:
        receipts_by_key = (
            await _shadow_receipts(
                spec,
                fresh,
                session=session,
                elastic=elastic,
                settings=settings,
                now=now,
                include_synth=include_synth,
            )
            if shadow_spec
            else {}
        )
        outcome = await observe_catalog_hits(
            session,
            spec=spec,
            candidates=fresh,
            now=now,
            shadow=shadow_spec,
            receipts=receipts_by_key,
        )
        _LOGGER.info(
            "spec sweep: %s wrote %d observation(s), formed %d lead(s)",
            spec.id,
            len(fresh),
            len(outcome.formed),
        )
        # Until this lands, the fired rows point at nothing and the gate treats
        # them as unhandled, so a crash between the two commits re-fires next
        # sweep instead of losing the finding forever.
        #
        # A shadow analytic writes no such rows: its gate call seeded, so there
        # is nothing to link and nothing to spend.
        if not shadow_spec:
            if settings.catalog_hunt_rows:
                hunt_id = await _record(
                    spec,
                    gated,
                    session=session,
                    since=since,
                    until=until,
                    is_synth_eval=bool(include_synth),
                )
                # The fired rows point at the hunt that reports them, as they
                # did before 1.5.0. The observation is written all the same.
                await link_hunt(session, spec.id, fresh, hunt_id)
            else:
                await link_handled(session, spec.id, fresh, "obs:" + spec.id[:27])
    if gap_is_fresh and not shadow_spec:
        gap_only = replace(gated, candidates=[])
        hunt_id = await _record(
            spec,
            gap_only,
            session=session,
            since=since,
            until=until,
            is_synth_eval=bool(include_synth),
        )
        gaps = [c for c in decision.fresh if _is_gap(c)]
        await link_hunt(session, spec.id, gaps, hunt_id)
    await session.commit()
    return gated, hunt_id


async def _shadow_receipts(
    spec: HuntSpec,
    candidates: list[Candidate],
    *,
    session: AsyncSession,
    elastic: ElasticClient,
    settings: Settings,
    now: datetime,
    include_synth: SynthScope,
) -> dict[str, dict[str, Any]]:
    """The receipts packet for each shadow hit, keyed by the entity it is about.

    One dry run over the last 30 days for the whole spec, because the question
    it answers ("how often does this fire") is about the analytic and not about
    one entity. The overlap is per entity, because that is the entity whose
    documents a live analytic might already hold.
    """
    dry = await run_spec(
        spec,
        elastic=elastic,
        settings=settings,
        since=f"now-{DRY_RUN_WINDOW_DAYS}d",
        until="now",
        include_synth=include_synth,
    )
    fields = spec.matched_fields()
    out: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        overlap = await overlap_with_live(
            session, entity_key=candidate.scope_key, sample_ids=candidate.sample_ids, now=now
        )
        out[candidate.scope_key] = build_receipts(
            matched_ids=list(candidate.sample_ids),
            matched_fields=fields,
            dry_run=dry,
            overlap=overlap,
            baseline=None,
            profile=False,
        ).as_dict()
    return out


def _is_gap(candidate: Candidate) -> bool:
    return candidate.scope_key == GAP_SCOPE


def _gap_candidate(spec_id: str, reason: str) -> Candidate:
    """The synthetic candidate a coverage gap is gated on.

    Carries no documents and no citation on purpose: it is a statement about
    what the run could NOT establish, and a sample id would invite a reader to
    treat it as evidence of something. The reason travels in ``anchor_index``
    because that is what the fingerprint is built from, so a change of reason
    is visible in the state row without being able to open a second gap.
    """
    return Candidate(
        spec_id=spec_id,
        scope_key=GAP_SCOPE,
        scope_kind="dataset",
        doc_count=0,
        sample_ids=(),
        anchor_id=None,
        anchor_index=reason[:120],
        first_seen=None,
        last_seen=None,
    )


def _unclean_reason(run: SpecRun) -> str:
    """Why a seeing run is not an all-clear, for the gap's state row."""
    parts = []
    if run.undecided_docs:
        parts.append(f"{run.undecided_docs} undecided")
    if run.unattributed_docs:
        parts.append(f"{run.unattributed_docs} unattributed")
    if run.truncated_docs:
        parts.append(f"{run.truncated_docs} truncated")
    return "document(s) not accounted for: " + ", ".join(parts)


def catalog_objective(spec: HuntSpec, since: str, until: str) -> str:
    """The objective a spec-authored hunt carries: the spec, and the window it swept.

    One function rather than an inline f-string because the demo seed writes
    the same hunt, and an objective it spelled differently would be the one
    the Hunts list's "Catalog" preset filters by kind but nobody recognises.
    """
    return f"[catalog] {spec.id}: {spec.title} ({since} → {until})"


async def _record(
    spec: HuntSpec,
    run: SpecRun,
    *,
    session: AsyncSession,
    since: str,
    until: str,
    is_synth_eval: bool = False,
) -> str:
    # ``is_synth_eval`` is the recorder half of the SynthScope contract: a
    # sweep that could see planted documents must not leave a hunt in the
    # queue that looks like a real one. The hunt list and the bell badge the
    # row from this flag and nothing else tells them apart.
    objective = catalog_objective(spec, since, until)
    hunt = await hunts_store.create(
        session,
        objective=objective,
        started_by=SWEEP_ACTOR,
        kind="triggered",
        is_synth_eval=is_synth_eval,
    )
    report = spec_report(spec, run)
    await hunts_store.finalize(
        session, hunt.id, status="complete", narrative=report["narrative"], report=report
    )
    return hunt.id


async def _leave_trail(
    session: AsyncSession,
    *,
    spec_id: str,
    run: SpecRun,
    hunt_id: str | None,
    shadow: bool,
    since: str,
    until: str,
    now: datetime,
) -> None:
    """Write the spec's sweep row in its own transaction; never let it fail the spec.

    Every spec leaves a row on every sweep, clean ones included — that is what
    makes "ran and saw nothing" a fact rather than an absence. By the time this
    runs the spec's own work is already committed (or rolled back), so a failure
    here cannot be allowed to re-label a spec that FIRED as errored: the hunt
    exists, the operator will read it, and the result must say so. The trail
    row is the lesser loss, and it is logged as one.
    """
    try:
        await record_sweep(
            session,
            spec_id=spec_id,
            run=run,
            hunt_id=hunt_id,
            shadow=shadow,
            since=since,
            until=until,
            now=now,
        )
    except Exception:
        _LOGGER.exception("spec sweep: could not record the sweep row for %s", spec_id)
        await session.rollback()


async def sweep_catalog(
    catalog: dict[str, HuntSpec],
    *,
    session: AsyncSession,
    elastic: ElasticClient,
    settings: Settings,
    since: str,
    until: str,
    now: datetime,
    backfill: bool = False,
    include_synth: SynthScope = False,
    record: bool = True,
    shadow_ids: frozenset[str] = frozenset(),
) -> SweepResult:
    """Sweep every spec. One spec's failure never stops the rest.

    Every spec leaves a ``hunt_spec_sweeps`` row, written AFTER its own commit
    or rollback so the trail is never part of the transaction it describes. A
    shadow sweep (``record=False``) writes its rows with ``shadow=True``.
    """
    result = SweepResult()
    for spec in catalog.values():
        if spec.evaluator != "match":
            # A ``profile`` spec compiles to no query — it is answered from an
            # entity's stored baseline by
            # :func:`soc_ai.hunting.prior_sweep.run_prior_sweep`. Sweeping it
            # here would call ``to_query`` and raise once per prior, turning a
            # healthy catalog sweep into nine errors and a non-zero exit.
            #
            # Skipped rather than trail-logged: a sweep row for a spec this
            # sweep does not evaluate is a claim it was checked and found
            # clean, which is the one thing the trail must never say.
            continue
        try:
            run, hunt_id = await sweep_spec(
                spec,
                session=session,
                elastic=elastic,
                settings=settings,
                since=since,
                until=until,
                now=now,
                backfill=backfill,
                include_synth=include_synth,
                record=record,
                shadow_ids=shadow_ids,
            )
            # Commit per spec, NOT once at the end of the catalog.
            #
            # `apply_gate` and `link_hunt` stage row mutations without
            # committing. On SQLite the next spec's SELECT autoflushes them,
            # which takes the single write lock — and the lock is then held
            # across that spec's Elasticsearch round-trips, and every remaining
            # spec's, until the caller finally commits.
            #
            # ES calls here are bounded at es_request_timeout_s x (1 + retries),
            # so a slow or hanging grid — the exact case this loop exists to
            # survive — held the write lock for minutes. `busy_timeout` is 5
            # seconds, so every other writer in the process (a verdict, an ack,
            # a config save, an LLM hunt finalising) would fail with "database
            # is locked" for the duration.
            #
            # Committing here bounds the hold to one spec's own DB work.
            await session.commit()
        except Exception as exc:
            # Roll back so a half-written spec cannot poison the next one's
            # flush, and record it the same way a grid error is recorded.
            await session.rollback()
            result.ran.append(spec.id)
            error = f"{type(exc).__name__}: {exc}"
            result.errored[spec.id] = error
            # After the rollback, in its own transaction: written before it,
            # the row would roll back with the failure it records.
            await _leave_trail(
                session,
                spec_id=spec.id,
                run=SpecRun(spec.id, since, until, False, 0, 0, error=error),
                hunt_id=None,
                shadow=not record or backfill or spec.id in shadow_ids,
                since=since,
                until=until,
                now=now,
            )
            continue
        result.ran.append(spec.id)
        if run.error is not None:
            result.errored[spec.id] = run.error
        elif run.blind:
            result.blind.append(spec.id)
            if hunt_id:
                result.blind_reported += 1
        else:
            result.fresh_candidates += len(run.candidates)
            result.truncated_docs += run.truncated_docs
            result.undecided_docs += run.undecided_docs
            result.already_handled += run.gate_already_handled
            result.over_budget += run.gate_over_budget
            # A seeing, clean run is the only kind that can close a gap: the
            # blind branch above passes a gap candidate and so does an unclean
            # one, and the gate retires nothing on a call that carries one.
            result.gaps_cleared += run.gate_gaps_retired
        if hunt_id:
            result.hunts[spec.id] = hunt_id
        # Shadow is "the fire-once budget was not spent", and a backfill spends
        # none of it either: it seeds the gate and records no hunt. Written as
        # live, a backfill row is fresh > 0 with no hunt — a state no live sweep
        # produces — and the catalog page reads it as a loop that found N and
        # recorded nothing.
        await _leave_trail(
            session,
            spec_id=spec.id,
            run=run,
            hunt_id=hunt_id,
            shadow=not record or backfill or spec.id in shadow_ids,
            since=since,
            until=until,
            now=now,
        )
    return result


__all__ = ["SWEEP_ACTOR", "SweepResult", "catalog_objective", "sweep_catalog", "sweep_spec"]
