"""A hunt investigates its subject findings, as part of the hunt.

The owner's decision of 2026-10-07, verbatim: "A hunt's findings should ALWAYS
be investigated and that should be part of the hunt. You don't look at a
smoking building and then not check for fire."

After the hunt agent returns and the hunt row holds its report, the runner
(:func:`soc_ai.api.hunt_runner.hunt_recorded_run`) calls
:func:`investigate_findings`. It opens one investigation per subject finding
(:func:`soc_ai.hunting.findings.finding_is_subject`) through the promotion
service, in priority order, two at a time, up to the per-hunt cap. The hunt
reads ``investigating`` while they run and ``complete`` when the last one
ends. A failed investigation counts as ended.

One investigation per subject. Before it opens one, the phase looks for a
running or complete investigation of the same subject from the last seven
days: the same alert, or the same subject fingerprint
(:func:`soc_ai.store.investigations.reusable_for_subject`). A match is reused.
The finding names it, and no new run starts.

The system path records no observation. An analyst's promotion records one,
because it is the analyst's judgement of the finding. A hunt's own
investigation is not, and an observation per finding would form a new lead on
the host of every lead hunt.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

from soc_ai.agent.context import InvestigationContext, build_hunt_subject
from soc_ai.hunting.findings import (
    finding_document_ids,
    subject_fingerprint,
    subject_ordinals,
)
from soc_ai.hunting.outcome import FindingVerdicts
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store import leads as leads_store
from soc_ai.store.models import Hunt, Investigation
from soc_ai.webui import finding_promotion

_LOGGER = logging.getLogger(__name__)

# The actor the hunt's own investigations record in ``started_by``, and the
# hand the lead store signs a close with when the verdicts decided it.
SYSTEM_HUNT_ACTOR = leads_store.SYSTEM_HUNT_ACTOR

# How many investigations of one hunt run at the same time.
CONCURRENCY = 2

# How often the phase reads the row of a reused investigation that no task of
# this process drives, while it waits for the run to end.
REUSED_POLL_S = 5.0

# The reasons a finding's entry records when no investigation started.
REASON_NO_EVIDENCE = "no_promotable_evidence"
REASON_GRID = "grid_unavailable"
REASON_NOT_STARTED = "could_not_start"
REASON_HUNT_CANCELLED = "hunt_cancelled"

_LOCK_ATTR = "_hunt_findings_lock"


@dataclass(frozen=True)
class FindingPlan:
    """The subject findings of one hunt, in priority order, split at the cap."""

    queued: list[int] = field(default_factory=list)
    over_cap: list[int] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.queued) + len(self.over_cap)

    def as_column(self) -> dict[str, dict[str, Any]]:
        """The plan as the hunt row's ``finding_investigations`` column holds it."""
        plan = {str(o): hunt_svc.plan_entry(hunt_svc.LINK_QUEUED) for o in self.queued}
        plan.update({str(o): hunt_svc.plan_entry(hunt_svc.LINK_OVER_CAP) for o in self.over_cap})
        return plan


def plan_findings(report: Any, settings: Any) -> FindingPlan | None:
    """The plan for a hunt's report, or None when the hunt investigates nothing.

    None when the switch ``hunt_findings_investigate`` is off, and when no
    finding is a subject. Such a hunt completes at once, as before.
    """
    if not bool(getattr(settings, "hunt_findings_investigate", True)):
        return None
    findings = report.get("findings") if isinstance(report, dict) else None
    ordinals = subject_ordinals(findings)
    if not ordinals:
        return None
    cap = max(1, int(getattr(settings, "hunt_findings_investigate_max", 20) or 1))
    return FindingPlan(queued=ordinals[:cap], over_cap=ordinals[cap:])


def _lock(state: Any) -> asyncio.Lock:
    """The one lock per app that orders a reuse check before its start.

    Held across the check and the start, so two findings of one subject never
    both start a run. Held across the write of a finding's entry too, because
    the entries share one JSON column and a write replaces it whole.
    """
    lock = getattr(state, _LOCK_ATTR, None)
    if lock is None:
        lock = asyncio.Lock()
        setattr(state, _LOCK_ATTR, lock)
    return lock


async def record_link(
    state: Any,
    hunt_id: str,
    ordinal: int,
    link_state: str,
    *,
    investigation_id: str | None = None,
    origin: str | None = None,
    reason: str | None = None,
) -> None:
    """Write one finding's entry on the hunt row. Never raises."""
    try:
        async with _lock(state), state.db_sessionmaker() as db:
            await hunt_svc.set_finding_link(
                db,
                hunt_id,
                ordinal,
                link_state,
                investigation_id=investigation_id,
                origin=origin,
                reason=reason,
            )
    except Exception:
        _LOGGER.exception("hunt %s: finding %s entry was not written", hunt_id, ordinal)


@dataclass(frozen=True)
class _Opened:
    investigation_id: str
    reused: bool
    running: bool


class _NotOpened(Exception):
    """No investigation started for the finding. ``reason`` names why."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def _reusable(
    state: Any, *, alert_id: str | None, fingerprint: str | None, is_synth_eval: bool
) -> Investigation | None:
    async with state.db_sessionmaker() as db:
        return await inv_svc.reusable_for_subject(
            db, alert_id=alert_id, fingerprint=fingerprint, is_synth_eval=is_synth_eval
        )


async def open_for_finding(
    state: Any,
    *,
    ctx: InvestigationContext,
    hunt_id: str,
    ordinal: int,
    finding: dict[str, Any],
    lead_id: int | None,
    is_synth_eval: bool,
    started_by: str = SYSTEM_HUNT_ACTOR,
) -> _Opened:
    """Reuse or start the investigation of one subject finding.

    The fingerprint test runs first, because it needs no grid read. The
    subject build and the anchor need one. The second test, with the anchor,
    and the start run under one lock.
    """
    fingerprint = subject_fingerprint(finding)
    existing = await _reusable(
        state, alert_id=None, fingerprint=fingerprint, is_synth_eval=is_synth_eval
    )
    if existing is not None:
        return _Opened(existing.id, reused=True, running=existing.status == "running")
    settings = ctx.settings
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            async with state.db_sessionmaker() as db:
                subject = await build_hunt_subject(
                    db,
                    elastic=ctx.elastic,
                    settings=settings,
                    hunt_id=hunt_id,
                    finding_ordinal=ordinal,
                    lead_id=lead_id,
                )
        subject = subject.model_copy(update={"subject_fingerprint": fingerprint})
        anchor_id = await finding_promotion.promotion_anchor(
            settings=settings,
            elastic=ctx.elastic,
            citations=finding_document_ids(finding),
            subject=subject,
        )
    except finding_promotion.PromotionRefused as exc:
        raise _NotOpened(exc.reason) from exc
    except LookupError as exc:
        raise _NotOpened(REASON_NOT_STARTED) from exc
    except Exception as exc:
        # A grid timeout, a transport error or a refused query. The run is
        # unknown, and the analyst can open it by hand when the grid answers.
        _LOGGER.warning("hunt %s finding %s: the grid read failed: %r", hunt_id, ordinal, exc)
        raise _NotOpened(REASON_GRID) from exc
    async with _lock(state):
        existing = await _reusable(
            state, alert_id=anchor_id, fingerprint=fingerprint, is_synth_eval=is_synth_eval
        )
        if existing is not None:
            return _Opened(existing.id, reused=True, running=existing.status == "running")
        try:
            inv_id = await finding_promotion.start_promotion(
                state,
                anchor_id=anchor_id,
                started_by=started_by,
                title=str(finding.get("title") or "Hunt finding"),
                detail=str(finding.get("detail") or ""),
                hosts=[str(h) for h in (finding.get("hosts") or [])],
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=ordinal,
                focus_origin="hunt_finding",
                is_synth_eval=is_synth_eval,
                subject=subject,
                ctx=finding_promotion.fresh_context(ctx),
            )
        except finding_promotion.PromotionRefused as exc:
            raise _NotOpened(exc.reason) from exc
    return _Opened(inv_id, reused=False, running=True)


async def wait_for_end(
    state: Any, inv_id: str, *, stopped: Callable[[], bool] | None = None
) -> None:
    """Wait until the investigation ``inv_id`` is no longer running.

    The manager's task is the signal for a run of this process. A run that no
    task here drives, such as a reused run of another process, is read from
    its row until it ends or until the investigation wall clock has passed.

    ``stopped`` ends the wait early. The phase passes its cancel flag: a run
    cancelled before its task took a first step never writes its end, and its
    row reads running until the reaper.
    """
    manager = finding_promotion.investigation_manager(state)
    await manager.wait(inv_id)
    settings = getattr(state, "settings", None)
    ceiling = float(getattr(settings, "investigation_run_timeout_s", 900) or 900) + 60.0
    deadline = monotonic() + ceiling
    while True:
        if stopped is not None and stopped():
            return
        async with state.db_sessionmaker() as db:
            inv = await db.get(Investigation, inv_id)
            status = inv.status if inv is not None else None
        if status != "running":
            return
        if manager.is_live(inv_id):
            await manager.wait(inv_id)
            continue
        if monotonic() >= deadline:
            _LOGGER.warning("investigation %s still reads running past its wall clock", inv_id)
            return
        await asyncio.sleep(REUSED_POLL_S)


async def investigate_findings(
    state: Any,
    *,
    hunt_id: str,
    ctx: InvestigationContext,
    plan: FindingPlan,
) -> FindingVerdicts | None:
    """Run the investigation phase of one hunt, then complete the hunt.

    Two workers take the queued findings in priority order, so at most two
    investigations this hunt opened run at a time. A reused running
    investigation holds no worker: the phase waits for it at the end.

    A cancel of the hunt cancels the findings still queued and the
    investigations this hunt opened that still run, then completes the hunt
    and re-raises. The hunt's report stands, so the hunt is complete. Its
    lead settles when the phase ends, by the rule of
    :func:`soc_ai.store.leads.settle_after_hunt`.

    Returns the verdict summary of the hunt's subject findings, for the
    notification. None when it could not be read.
    """
    async with state.db_sessionmaker() as db:
        hunt = await db.get(Hunt, hunt_id)
        report = dict(hunt.report or {}) if hunt is not None else {}
        lead_id = hunt.lead_id if hunt is not None else None
        is_synth_eval = bool(hunt.is_synth_eval) if hunt is not None else False
    raw = report.get("findings")
    phase = _Phase(
        state,
        ctx=ctx,
        hunt_id=hunt_id,
        findings=raw if isinstance(raw, list) else [],
        lead_id=lead_id,
        is_synth_eval=is_synth_eval,
        queued=plan.queued,
    )
    count = min(CONCURRENCY, len(plan.queued))
    workers = [asyncio.create_task(phase.worker()) for _ in range(count)]
    try:
        # asyncio.wait and not gather: a cancel of the hunt must not cancel
        # the workers. A task cancelled inside a database call can leave the
        # driver's connection close hanging, and the worker holds the lock
        # that orders the entry writes. The workers stop on the flag instead.
        if workers:
            await asyncio.wait(workers)
        await phase.wait_for_reused()
    except asyncio.CancelledError:
        await asyncio.shield(phase.stop(workers))
        await asyncio.shield(_complete(state, hunt_id))
        raise
    return await _complete(state, hunt_id)


class _Phase:
    """The investigation phase of one hunt: a queue, two workers and a ledger."""

    def __init__(
        self,
        state: Any,
        *,
        ctx: InvestigationContext,
        hunt_id: str,
        findings: list[Any],
        lead_id: int | None,
        is_synth_eval: bool,
        queued: list[int],
    ) -> None:
        self.state = state
        self.ctx = ctx
        self.hunt_id = hunt_id
        self.findings = findings
        self.lead_id = lead_id
        self.is_synth_eval = is_synth_eval
        self.queue: asyncio.Queue[int] = asyncio.Queue()
        for ordinal in queued:
            self.queue.put_nowait(ordinal)
        # The findings the hunt still owes an ended investigation, each with
        # the investigation it opened, for the cancel path. A finding leaves
        # the map when its entry reaches a final state.
        self.unfinished: dict[int, str | None] = dict.fromkeys(queued)
        # Reused runs of another hunt that still run. The hunt waits for them
        # at the end and never cancels them.
        self.reused_running: list[tuple[int, str]] = []
        # Set by a cancel of the hunt. A worker reads it after every wait, and
        # it starts no new investigation and records no end once it is set.
        # The workers are never cancelled. They stop on this flag.
        self.stopped = False

    def is_stopped(self) -> bool:
        return self.stopped

    async def link(self, ordinal: int, link_state: str, **fields: Any) -> None:
        await record_link(self.state, self.hunt_id, ordinal, link_state, **fields)

    async def settle(self, ordinal: int, link_state: str, **fields: Any) -> None:
        """Record a final entry. The finding no longer waits on the hunt."""
        self.unfinished.pop(ordinal, None)
        await self.link(ordinal, link_state, **fields)

    async def worker(self) -> None:
        while not self.stopped:
            try:
                ordinal = self.queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            await self.investigate_one(ordinal)

    async def stop(self, workers: list[asyncio.Task[None]]) -> None:
        """A cancel of the hunt: stop the workers, then cancel what the hunt owes.

        The order matters. The flag goes up first, so no worker starts a new
        run. The runs are cancelled next, so a worker that waits on one wakes.
        The workers end next, so none writes an entry later. The entries are
        written last, and no late write replaces them.
        """
        self.stopped = True
        manager = finding_promotion.investigation_manager(self.state)
        for inv_id in self.unfinished.values():
            if inv_id is not None:
                manager.cancel(inv_id)
        pending = [task for task in workers if not task.done()]
        if pending:
            await asyncio.wait(pending)
        await self.cancel_rest()

    async def open_one(self, ordinal: int) -> _Opened | None:
        """Open or reuse the investigation of one finding. None when none started."""
        finding = self.findings[ordinal] if 0 <= ordinal < len(self.findings) else None
        reason = REASON_NOT_STARTED
        if isinstance(finding, dict):
            try:
                return await open_for_finding(
                    self.state,
                    ctx=self.ctx,
                    hunt_id=self.hunt_id,
                    ordinal=ordinal,
                    finding=finding,
                    lead_id=self.lead_id,
                    is_synth_eval=self.is_synth_eval,
                )
            except _NotOpened as exc:
                reason = exc.reason
            except Exception:
                _LOGGER.exception("hunt %s: finding %s did not open", self.hunt_id, ordinal)
        if not self.stopped:
            await self.settle(ordinal, hunt_svc.LINK_FAILED, reason=reason)
        return None

    async def investigate_one(self, ordinal: int) -> None:
        opened = await self.open_one(ordinal)
        if opened is None:
            return
        inv_id = opened.investigation_id
        if self.stopped and not opened.reused:
            # The start won the race with the cancel. Cancel this run too.
            # The cancel path writes the entry, with this run's id.
            self.unfinished[ordinal] = inv_id
            finding_promotion.investigation_manager(self.state).cancel(inv_id)
            return
        if opened.reused:
            _LOGGER.info(
                "hunt %s finding %s reuses investigation %s", self.hunt_id, ordinal, inv_id
            )
            fields = {"investigation_id": inv_id, "origin": hunt_svc.ORIGIN_REUSED}
            if not opened.running:
                await self.settle(ordinal, hunt_svc.LINK_ENDED, **fields)
                return
            self.unfinished.pop(ordinal, None)
            self.reused_running.append((ordinal, inv_id))
            await self.link(ordinal, hunt_svc.LINK_INVESTIGATING, **fields)
            return
        self.unfinished[ordinal] = inv_id
        fields = {"investigation_id": inv_id, "origin": hunt_svc.ORIGIN_OPENED}
        await self.link(ordinal, hunt_svc.LINK_INVESTIGATING, **fields)
        await wait_for_end(self.state, inv_id, stopped=self.is_stopped)
        if self.stopped:
            # The cancel path recorded this finding's entry.
            return
        await self.settle(ordinal, hunt_svc.LINK_ENDED, **fields)

    async def wait_for_reused(self) -> None:
        for ordinal, inv_id in self.reused_running:
            await wait_for_end(self.state, inv_id, stopped=self.is_stopped)
            if self.stopped:
                return
            await self.link(
                ordinal,
                hunt_svc.LINK_ENDED,
                investigation_id=inv_id,
                origin=hunt_svc.ORIGIN_REUSED,
            )

    async def cancel_rest(self) -> None:
        """Record what the hunt still owed as cancelled: the queued findings and its runs.

        :meth:`stop` cancelled the runs already.
        """
        for ordinal, inv_id in list(self.unfinished.items()):
            await self.link(
                ordinal,
                hunt_svc.LINK_CANCELLED,
                investigation_id=inv_id,
                origin=hunt_svc.ORIGIN_OPENED if inv_id else None,
                reason=REASON_HUNT_CANCELLED,
            )
        self.unfinished.clear()
        _LOGGER.info("hunt %s: a cancel stopped the investigation of its findings", self.hunt_id)


async def _complete(state: Any, hunt_id: str) -> FindingVerdicts | None:
    """Complete the hunt, settle its lead and read the verdict summary."""
    verdicts: FindingVerdicts | None = None
    try:
        async with state.db_sessionmaker() as db:
            hunt = await hunt_svc.complete_investigating(db, hunt_id)
            verdicts = (await hunt_svc.finding_verdicts(db, [hunt_id])).get(hunt_id)
            if hunt is not None and hunt.lead_id is not None:
                moved = await leads_store.settle_after_hunt(db, hunt)
                _LOGGER.info("lead %s after hunt %s: %s", hunt.lead_id, hunt_id, moved)
    except Exception:
        _LOGGER.exception("hunt %s did not complete its investigation phase", hunt_id)
    return verdicts


__all__ = [
    "CONCURRENCY",
    "SYSTEM_HUNT_ACTOR",
    "FindingPlan",
    "investigate_findings",
    "open_for_finding",
    "plan_findings",
    "record_link",
    "wait_for_end",
]
