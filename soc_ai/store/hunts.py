"""Persistence service for threat hunts (Hunt Console).

A hunt row is created when a chat-driven hunt starts; events append as the
agent's trace streams; :func:`finalize` lands the narrative + the HuntReport.
Mirrors :mod:`soc_ai.store.investigations` — the hunt is broader (findings +
narrative across hosts/time) but the lifecycle + tee/finalize shape is the same.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any, NamedTuple

from sqlalchemy import and_, case, func, not_, select
from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from soc_ai.hunting.findings import threat_finding_count
from soc_ai.hunting.outcome import FindingVerdicts
from soc_ai.run_meter import RunCounters, apply_counters
from soc_ai.secret_scrub import (
    MODEL_TEXT_EVENT_KINDS,
    scrub_optional,
    scrub_secrets,
    scrub_value,
)
from soc_ai.store import chat_memory
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Hunt, HuntEvent, HuntSpecState, Investigation, Lead

STATUS_RUNNING = "running"
STATUS_COMPLETE = "complete"
# The hunt landed its report and its subject findings are under
# investigation (migration 0063). The hunt has not ended.
STATUS_INVESTIGATING = "investigating"
# The statuses of a hunt that has not ended.
OPEN_STATUSES: tuple[str, ...] = (STATUS_RUNNING, STATUS_INVESTIGATING)

# The state of one subject finding on the hunt (``finding_investigations``).
LINK_QUEUED = "queued"
LINK_INVESTIGATING = "investigating"
LINK_ENDED = "ended"
LINK_OVER_CAP = "over_cap"
LINK_FAILED = "failed"
LINK_CANCELLED = "cancelled"
# The states that count as an ended investigation. A failed one ended too.
LINK_ENDED_STATES: frozenset[str] = frozenset({LINK_ENDED, LINK_FAILED, LINK_CANCELLED})
# Who put the investigation on the finding: the hunt opened it, the hunt
# reused an investigation of the same subject, or an analyst opened it.
ORIGIN_OPENED = "opened"
ORIGIN_REUSED = "reused"
ORIGIN_MANUAL = "manual"

_WS_RE = re.compile(r"\s+")


async def latest_scheduled_runs(db: AsyncSession, objectives: list[str]) -> dict[str, str]:
    """The newest scheduled hunt for each objective, as objective to hunt id. One query.

    The schedule row stores when it last ran and not what it started, so the
    run is the newest ``scheduled`` hunt with the same objective hash.
    """
    hashes = {_objective_hash(o): o for o in objectives}
    if not hashes:
        return {}
    rows = await db.execute(
        select(Hunt.id, Hunt.objective_hash)
        .where(Hunt.kind == "scheduled", Hunt.objective_hash.in_(list(hashes)))
        .order_by(Hunt.created_at.desc(), Hunt.id.desc())
    )
    out: dict[str, str] = {}
    for hunt_id, digest in rows.all():
        objective = hashes.get(str(digest))
        if objective is not None and objective not in out:
            out[objective] = str(hunt_id)
    return out


def _objective_hash(objective: str) -> str:
    """Stable content hash of the NORMALIZED objective.

    Normalization = lowercase + collapse all whitespace runs to a single space +
    strip. So two re-runs whose objective text differs only in case or spacing
    ("Hunt for beaconing" vs "hunt   for  beaconing\n") share a hash and link as
    the same objective; a genuinely different objective does not. SHA-256 hex,
    truncated to 32 chars — plenty of collision resistance for one deployment's
    hunt history, and fits the indexed ``String(64)`` column.
    """
    normalized = _WS_RE.sub(" ", objective.strip().lower())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


async def create(
    db: AsyncSession,
    *,
    objective: str,
    started_by: str,
    kind: str = "chat",
    is_synth_eval: bool = False,
    starter: str = "analyst",
    lead_id: int | None = None,
) -> Hunt:
    """Create the hunt row.

    ``starter`` names the class that started it: analyst, schedule or lead.
    ``lead_id`` links a lead-started hunt to its lead.

    ``is_synth_eval`` marks a synthetic-evaluation run (the hunt could see
    planted synth scenarios) — set only from an explicit eval context by the
    hunt recorder, never from a request body."""
    hunt = Hunt(
        id=str(ULID()),
        objective=objective,
        objective_hash=_objective_hash(objective),
        started_by=started_by,
        kind=kind[:16],
        is_synth_eval=is_synth_eval,
        starter=starter[:16],
        lead_id=lead_id,
    )
    db.add(hunt)
    await db.commit()
    await db.refresh(hunt)
    return hunt


async def previous_completed_run(
    db: AsyncSession,
    *,
    objective_hash: str | None,
    before_created_at: datetime,
    exclude_id: str,
) -> Hunt | None:
    """The most recent COMPLETE hunt with the same objective_hash, before this one.

    Powers the "vs last run" diff: given the current hunt's ``objective_hash`` and
    ``created_at``, find the prior COMPLETE run of the SAME objective to diff
    against. Excludes ``exclude_id`` (the current hunt) so a self-match can't
    happen, and requires ``created_at`` strictly earlier so only an EARLIER run is
    the baseline. Returns ``None`` when there is no prior run (first run of an
    objective, or a legacy row with a NULL hash — the diff is then omitted).
    """
    if not objective_hash:
        return None
    q = (
        select(Hunt)
        .where(
            Hunt.objective_hash == objective_hash,
            Hunt.status == STATUS_COMPLETE,
            Hunt.id != exclude_id,
            Hunt.created_at < before_created_at,
        )
        .order_by(Hunt.created_at.desc(), Hunt.id.desc())
        .limit(1)
    )
    return (await db.scalars(q)).first()


async def append_events(db: AsyncSession, hunt_id: str, events: list[dict[str, Any]]) -> None:
    for ev in events:
        db.add(
            HuntEvent(
                hunt_id=hunt_id,
                sequence=int(ev.get("sequence", 0)),
                kind=str(ev.get("kind", ""))[:40],
                payload=(
                    scrub_value(ev.get("payload") or {})
                    if str(ev.get("kind", "")) in MODEL_TEXT_EVENT_KINDS
                    else ev.get("payload") or {}
                ),
            )
        )
    await db.commit()


async def finalize(
    db: AsyncSession,
    hunt_id: str,
    *,
    status: str,
    narrative: str | None = None,
    report: dict[str, Any] | None = None,
    counters: RunCounters | None = None,
    finding_plan: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Land the hunt's report and its status.

    ``finding_plan`` is the per-finding plan of a hunt that goes on to
    investigate its subject findings (status ``investigating``): one entry per
    subject, keyed by the ordinal as a string. ``findings_total`` is its size.
    """
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return
    hunt.status = status
    if finding_plan is not None:
        hunt.finding_investigations = finding_plan
        hunt.findings_total = len(finding_plan)
        hunt.findings_investigated = _ended_count(finding_plan)
    # What the run cost and its budget class (migration 0058).
    apply_counters(hunt, counters)
    # Credential values never reach the store: the narrative and the findings
    # are model-written text that every console user reads.
    if narrative is not None:
        hunt.narrative = scrub_optional(narrative)
    if report is not None:
        report = scrub_value(report)
        hunt.report = report
        # Denormalize the finding count so the /notifications bell never
        # deserializes the report blob to answer "N findings" (migration 0028).
        findings = report.get("findings")
        hunt.findings_count = len(findings) if isinstance(findings, list) else 0
        hunt.threat_findings_count = threat_finding_count(findings)
    hunt.finished_at = utcnow()
    await db.commit()


# ── The investigations of the subject findings (migration 0063) ────────────


class FindingLink(NamedTuple):
    """One subject finding's entry on the hunt row."""

    ordinal: int
    state: str
    investigation_id: str | None = None
    origin: str | None = None
    reason: str | None = None


def _ended_count(plan: dict[str, Any]) -> int:
    return sum(
        1
        for entry in plan.values()
        if isinstance(entry, dict) and entry.get("state") in LINK_ENDED_STATES
    )


def finding_links(hunt: Any) -> dict[int, FindingLink]:
    """The per-finding entries of a hunt, keyed by ordinal. Empty on an older row."""
    return finding_links_from(getattr(hunt, "finding_investigations", None))


def finding_links_from(raw: Any) -> dict[int, FindingLink]:
    """The per-finding entries of a stored ``finding_investigations`` value.

    The column is stored JSON and is not schema-enforced, so an entry with a
    key that is not an ordinal, or a value that is not a dict, is dropped.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[int, FindingLink] = {}
    for key, entry in raw.items():
        try:
            ordinal = int(key)
        except (TypeError, ValueError):
            continue
        if not isinstance(entry, dict) or ordinal < 0:
            continue
        inv_id = entry.get("investigation_id")
        out[ordinal] = FindingLink(
            ordinal=ordinal,
            state=str(entry.get("state") or LINK_QUEUED),
            investigation_id=str(inv_id) if inv_id else None,
            origin=str(entry["origin"]) if entry.get("origin") else None,
            reason=str(entry["reason"]) if entry.get("reason") else None,
        )
    return out


def plan_entry(
    state: str,
    *,
    investigation_id: str | None = None,
    origin: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """One entry of ``finding_investigations``, as the column stores it."""
    entry: dict[str, Any] = {"state": state}
    if investigation_id:
        entry["investigation_id"] = investigation_id
    if origin:
        entry["origin"] = origin
    if reason:
        entry["reason"] = reason
    return entry


async def set_finding_link(
    db: AsyncSession,
    hunt_id: str,
    ordinal: int,
    state: str,
    *,
    investigation_id: str | None = None,
    origin: str | None = None,
    reason: str | None = None,
) -> Hunt | None:
    """Write one finding's entry and recount the ended investigations.

    The dict is written back whole. The JSON column does not track an
    in-place change, and an entry the session did not see is lost.
    """
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return None
    plan = dict(hunt.finding_investigations or {})
    plan[str(ordinal)] = plan_entry(
        state, investigation_id=investigation_id, origin=origin, reason=reason
    )
    hunt.finding_investigations = plan
    hunt.findings_investigated = _ended_count(plan)
    await db.commit()
    return hunt


async def complete_investigating(db: AsyncSession, hunt_id: str) -> Hunt | None:
    """End the investigation phase: the hunt is complete.

    ``finished_at`` moves to now, because the hunt ends when its last
    investigation ends. A hunt in any other status is left alone, so a second
    call changes nothing.
    """
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None or hunt.status != STATUS_INVESTIGATING:
        return hunt
    plan = dict(hunt.finding_investigations or {})
    hunt.findings_investigated = _ended_count(plan)
    hunt.status = STATUS_COMPLETE
    hunt.finished_at = utcnow()
    await db.commit()
    return hunt


async def reap_investigating(db: AsyncSession) -> int:
    """Complete every hunt a restart left ``investigating``. Returns the count.

    The process that ran the investigations is gone. Its investigations were
    reaped as ``interrupted``, so an entry that names one has ended and reads
    as failed. An entry that never started an investigation is failed too.
    The report stands, so the hunt is complete.
    """
    rows = list((await db.scalars(select(Hunt).where(Hunt.status == STATUS_INVESTIGATING))).all())
    now = utcnow()
    for hunt in rows:
        plan: dict[str, Any] = {}
        for key, stored in (hunt.finding_investigations or {}).items():
            if not isinstance(stored, dict):
                continue
            state = stored.get("state")
            if state == LINK_QUEUED:
                plan[str(key)] = {**stored, "state": LINK_FAILED, "reason": "restart"}
            elif state == LINK_INVESTIGATING:
                plan[str(key)] = {**stored, "state": LINK_ENDED}
            else:
                plan[str(key)] = stored
        hunt.finding_investigations = plan
        hunt.findings_investigated = _ended_count(plan)
        hunt.status = STATUS_COMPLETE
        hunt.finished_at = now
    if rows:
        await db.commit()
    return len(rows)


async def finding_verdicts(db: AsyncSession, hunt_ids: Sequence[str]) -> dict[str, FindingVerdicts]:
    """The verdict summary of each hunt's subject findings. One query per table.

    A hunt with no subject finding is left out. The verdicts are read live from
    the investigations, so an analyst's override of a verdict moves the
    hunt's outcome with it.
    """
    wanted = [i for i in hunt_ids if i]
    if not wanted:
        return {}
    rows = (
        await db.execute(
            select(
                Hunt.id,
                Hunt.findings_total,
                Hunt.findings_investigated,
                Hunt.finding_investigations,
            ).where(Hunt.id.in_(wanted), Hunt.findings_total > 0)
        )
    ).all()
    links_by_hunt = {
        str(hunt_id): (int(total or 0), int(done or 0), finding_links_from(raw))
        for hunt_id, total, done, raw in rows
    }
    inv_ids = sorted(
        {
            link.investigation_id
            for _total, _done, links in links_by_hunt.values()
            for link in links.values()
            if link.investigation_id
        }
    )
    runs: dict[str, tuple[str, str | None, bool]] = {}
    for start in range(0, len(inv_ids), 500):
        chunk = inv_ids[start : start + 500]
        found = await db.execute(
            select(
                Investigation.id,
                Investigation.status,
                Investigation.verdict,
                Investigation.is_fallback,
            ).where(Investigation.id.in_(chunk))
        )
        for inv_id, status, verdict, fallback in found.all():
            runs[str(inv_id)] = (str(status or ""), verdict, bool(fallback))
    out: dict[str, FindingVerdicts] = {}
    for hunt_id, (total, done, links) in links_by_hunt.items():
        decided = threats = 0
        for link in links.values():
            run = runs.get(link.investigation_id or "")
            if run is None:
                continue
            status, verdict, fallback = run
            if status == "complete" and not fallback and verdict:
                decided += 1
                threats += verdict == "true_positive"
        out[hunt_id] = FindingVerdicts(
            total=total, investigated=done, decided=decided, threats=threats
        )
    return out


async def get_with_events(db: AsyncSession, hunt_id: str) -> tuple[Hunt, list[HuntEvent]] | None:
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return None
    events = (
        await db.scalars(
            select(HuntEvent)
            .where(HuntEvent.hunt_id == hunt_id)
            .order_by(HuntEvent.sequence, HuntEvent.id)
        )
    ).all()
    return hunt, list(events)


async def list_recent(
    db: AsyncSession,
    *,
    status: str | None = None,
    kind: str | None = None,
    exclude_kinds: Sequence[str] = (),
    limit: int = 100,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Hunt]:
    """Return hunts ordered by created_at desc, with optional status/kind filters.

    ``since``/``until`` bound ``created_at`` INCLUSIVELY on both ends
    (``since <= created_at <= until``) — matching the frontend's ``inRange``
    inclusive ``[from, to]`` (lib/timeRange.ts) and the store's inclusive
    lower-bound convention (``created_at >= cutoff``). Bounds must be naive
    UTC, like every stored timestamp (:func:`soc_ai.store.auth.utcnow`).
    Absent bounds keep the original unbounded behavior.

    ``exclude_kinds`` drops rows of those kinds. The hunt list uses it to leave
    out the catalog runs recorded before 1.5.0. It is a SQL clause rather than
    a filter over the page, because dropping rows AFTER a LIMIT is how a
    bounded query comes back short while matching rows sit past the cut.
    """
    q = select(Hunt).order_by(Hunt.created_at.desc(), Hunt.id.desc())
    if status is not None:
        q = q.where(Hunt.status == status)
    if kind is not None:
        q = q.where(Hunt.kind == kind)
    if exclude_kinds:
        q = q.where(Hunt.kind.not_in(tuple(exclude_kinds)))
    if since is not None:
        q = q.where(Hunt.created_at >= since)
    if until is not None:
        q = q.where(Hunt.created_at <= until)
    q = q.limit(limit)
    return list((await db.scalars(q)).all())


class WindowTotals(NamedTuple):
    """The counts of one hunt type over a window. The Hunts page header reads them."""

    hunts: int = 0
    findings: int = 0
    threat_findings: int = 0
    running: int = 0


async def window_totals(
    db: AsyncSession,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict[str, WindowTotals]:
    """The counts of every hunt in a window, per stored ``kind``.

    The window is the one :func:`list_recent` applies, inclusive on both ends,
    and it has no row cap. The list route caps a page at 100 rows, so a header
    that counted the page read "100 hunts" over a window of 140.

    The finding counts come from the denormalized columns, so no report blob is
    read for a stamped row. A row that holds a report and no stamped counts (a
    demo fixture, or a row written outside :func:`finalize`) is counted from
    its report, the way the list row counts it.
    """
    window: list[Any] = []
    if since is not None:
        window.append(Hunt.created_at >= since)
    if until is not None:
        window.append(Hunt.created_at <= until)
    stamped = and_(Hunt.findings_count.is_not(None), Hunt.threat_findings_count.is_not(None))
    rows = await db.execute(
        select(
            Hunt.kind,
            func.count(Hunt.id),
            func.sum(case((stamped, Hunt.findings_count), else_=0)),
            func.sum(case((stamped, Hunt.threat_findings_count), else_=0)),
            func.sum(case((Hunt.status == STATUS_RUNNING, 1), else_=0)),
        )
        .where(*window)
        .group_by(Hunt.kind)
    )
    out: dict[str, WindowTotals] = {
        str(kind): WindowTotals(int(n or 0), int(f or 0), int(t or 0), int(r or 0))
        for kind, n, f, t, r in rows.all()
    }
    unstamped = await db.execute(
        select(Hunt.kind, Hunt.report).where(*window, Hunt.report.is_not(None), not_(stamped))
    )
    for kind, report in unstamped.all():
        findings = report.get("findings") if isinstance(report, dict) else None
        counted = len(findings) if isinstance(findings, list) else 0
        base = out.get(str(kind), WindowTotals())
        out[str(kind)] = base._replace(
            findings=base.findings + counted,
            threat_findings=base.threat_findings + threat_finding_count(findings),
        )
    return out


class HuntNotifRow(NamedTuple):
    """The scalar columns the /notifications bell reads from a hunt — never the
    report blob. ``findings_count`` is the denormalized column (migration 0028),
    so the bell shows "N findings" without deserializing ``report``.
    ``is_synth_eval`` rides along because the bell DISPLAYS the row ("Hunt
    finished — N findings: <objective>") — a marked hunt's entry must carry the
    marker out to the wire like every other surface that shows the row."""

    id: str
    objective: str
    status: str
    created_at: datetime
    finished_at: datetime | None
    findings_count: int | None
    threat_findings_count: int | None
    is_synth_eval: bool
    # The storage kind and the actor. The bell names a catalog run
    # "Analytic" and folds the runs of one sweep into one line.
    kind: str = "chat"
    started_by: str = ""
    # The investigation phase counts (migration 0063), for the line of an
    # investigating hunt: "Investigating 2 of 3 findings".
    findings_total: int = 0
    findings_investigated: int = 0


async def list_recent_notifications(
    db: AsyncSession,
    *,
    status: str | None = None,
    statuses: Sequence[str] | None = None,
    limit: int = 100,
    finished_since: datetime | None = None,
) -> list[HuntNotifRow]:
    """Lightweight hunt rows for the notifications bell — scalar columns only.

    A column-scoped SELECT (not ``list_recent``, which loads full ORM entities
    including the ``report`` JSON) so the app's hottest poll never drags a
    report blob it only wants a finding count from. ``finished_since`` bounds AND
    orders the query on ``finished_at`` — the SAME clock the bell RENDERS ("N
    ago" is finished_at) and the one window definition the investigations sibling
    uses. This half previously bounded ``created_at``, so a hunt CREATED before
    the window but FINISHED inside it (a long-queued backlog hunt) was silently
    dropped. NULL ``finished_at`` (a running row) is excluded by the ``>=`` bound,
    which is correct: this query is only ever the completed half.
    """
    q = select(
        Hunt.id,
        Hunt.objective,
        Hunt.status,
        Hunt.created_at,
        Hunt.finished_at,
        Hunt.findings_count,
        Hunt.threat_findings_count,
        Hunt.is_synth_eval,
        Hunt.kind,
        Hunt.started_by,
        Hunt.findings_total,
        Hunt.findings_investigated,
    )
    if status is not None:
        q = q.where(Hunt.status == status)
    if statuses:
        q = q.where(Hunt.status.in_(tuple(statuses)))
    if finished_since is not None:
        q = q.where(Hunt.finished_at >= finished_since).order_by(
            Hunt.finished_at.desc(), Hunt.id.desc()
        )
    else:
        q = q.order_by(Hunt.created_at.desc(), Hunt.id.desc())
    q = q.limit(limit)
    return [HuntNotifRow(*row) for row in (await db.execute(q)).all()]


async def recent_run_seconds(db: AsyncSession, *, limit: int = 20) -> list[float]:
    """The wall time of the newest finished agent hunts, in seconds.

    A running hunt page states how long hunts on this grid take. Catalog runs
    are one query each and leave the count out.
    """
    rows = (
        await db.execute(
            select(Hunt.created_at, Hunt.finished_at)
            .where(
                Hunt.status == "complete",
                Hunt.finished_at.is_not(None),
                Hunt.kind != "triggered",
            )
            .order_by(Hunt.finished_at.desc())
            .limit(limit)
        )
    ).all()
    return [
        (finished - created).total_seconds()
        for created, finished in rows
        if created is not None and finished is not None
    ]


async def outcome_inputs(db: AsyncSession, ids: Sequence[str]) -> dict[str, tuple[list[Any], str]]:
    """The findings and the narrative of a few hunts, for the bell's outcome.

    The bell reads the scalar columns first and calls this only for the hunts
    whose outcome the threat count cannot decide: a hunt with no threat can
    be clean, unanswered or a failed run, and only the findings and the
    narrative tell those apart. Bounded by the bell's own row cap.
    """
    wanted = [i for i in ids if i]
    if not wanted:
        return {}
    rows = (
        await db.execute(select(Hunt.id, Hunt.report, Hunt.narrative).where(Hunt.id.in_(wanted)))
    ).all()
    out: dict[str, tuple[list[Any], str]] = {}
    for hunt_id, report, narrative in rows:
        body = report if isinstance(report, dict) else {}
        findings = body.get("findings")
        out[str(hunt_id)] = (
            findings if isinstance(findings, list) else [],
            str(narrative or body.get("narrative") or ""),
        )
    return out


async def findings_for_entity(
    db: AsyncSession, value: str, *, scan_limit: int = 100
) -> list[dict[str, Any]]:
    """Hunt findings that name an entity in their ``hosts[]`` — for the entity page.

    Findings live inside the ``report`` JSON (``report["findings"][].hosts[]``),
    which is NOT indexed, so this is the one potentially-costly bit of the E3.5
    read-model: it scans the last ``scan_limit`` hunts' reports in Python. BOUND it
    (default 100 hunts) so it stays cheap. A future index / denormalization of
    finding→host is Epoch territory (a `hunt_findings` projection table) — until
    then, the bound is the guardrail.

    Returns light dicts (NOT the whole finding), newest hunt first:
    ``{hunt_id, hunt_objective, title, severity, category, ts}`` where ``ts`` is the
    hunt's ``created_at`` (findings have no own timestamp). Only COMPLETE hunts
    carry a report worth scanning; running/errored rows are skipped.

    Synth-eval hunts (migration 0032) are skipped too — same decision as
    ``investigations.for_entity``, the query that feeds the other half of the
    entity timeline: the page narrates a host's REAL history, and a planted
    scenario's findings describe nothing that happened on the box. The hunts
    stay fully visible (badged) on the Hunts list and detail surfaces.
    """
    if not value:
        return []
    recent = await list_recent(db, status=STATUS_COMPLETE, limit=scan_limit)
    out: list[dict[str, Any]] = []
    for hunt in recent:
        if hunt.is_synth_eval:
            continue
        report = hunt.report if isinstance(hunt.report, dict) else {}
        findings = report.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            hosts = f.get("hosts") or []
            if not isinstance(hosts, list) or value not in [str(h) for h in hosts]:
                continue
            out.append(
                {
                    "hunt_id": hunt.id,
                    "hunt_objective": hunt.objective,
                    "title": str(f.get("title") or ""),
                    "severity": str(f.get("severity") or "info"),
                    "category": str(f.get("category") or "threat"),
                    "ts": hunt.created_at,
                }
            )
    return out


async def reap_stale_running(
    db: AsyncSession, *, older_than_minutes: int | None, status: str = "error"
) -> int:
    """Mark orphaned ``running`` hunts terminal. Returns the count.

    ``older_than_minutes=None`` reaps EVERY running row (startup: any row still
    ``running`` was orphaned by the restart); a positive int reaps only rows
    older than that many minutes (periodic sweep). Mirrors the investigation
    reaper: startup uses ``interrupted`` (a clean restart cut the run off, not a
    failure), the periodic sweep uses ``error``.
    """
    q = select(Hunt).where(Hunt.status == STATUS_RUNNING)
    if older_than_minutes is not None:
        cutoff = utcnow() - timedelta(minutes=older_than_minutes)
        q = q.where(Hunt.created_at < cutoff)
    rows = list((await db.scalars(q)).all())
    now = utcnow()
    interrupted = status == "interrupted"
    for hunt in rows:
        hunt.status = status
        hunt.finished_at = now
        if not hunt.narrative:
            hunt.narrative = (
                "A service restart interrupted the hunt before it finished. Run the hunt again."
                if interrupted
                else "The hunt did not finish. A restart or a timeout stopped it."
            )
    if rows:
        await db.commit()
    return len(rows)


async def delete(db: AsyncSession, hunt_id: str) -> bool:
    """Delete a hunt and its events in one transaction.

    Returns True if the hunt existed (and was removed), False otherwise.

    Neither ``Lead.hunt_id`` nor ``HuntSpecState.hunt_id`` is a foreign key,
    so the rows that name the hunt are released here, in the same transaction.
    A lead left ``hunting`` on a hunt that is gone could never be hunted again:
    the button answered with the dead id, the loop only takes a lead with no
    id, and Promote wanted the hunt it could not find. The lead goes back to
    ``open`` with no hunt, which is where it was before the hunt started, so
    with the auto-hunt loop on, deleting a lead's hunt queues a new one. A
    reopened lead keeps its dismissal as history and only loses the id. A
    fired catalog condition pointing at the deleted hunt read as handled while
    nothing was left for an operator to read; with the id gone the gate fires
    it again on the next sweep, the way it does after a crash.
    """
    hunt = await db.get(Hunt, hunt_id)
    if hunt is None:
        return False
    now = utcnow()
    await db.execute(
        sa_update(Lead)
        .where(Lead.hunt_id == hunt_id, Lead.status == "hunting")
        .values(status="open", updated_at=now)
    )
    await db.execute(
        sa_update(Lead).where(Lead.hunt_id == hunt_id).values(hunt_id=None, updated_at=now)
    )
    await db.execute(
        sa_update(HuntSpecState).where(HuntSpecState.hunt_id == hunt_id).values(hunt_id=None)
    )
    await db.execute(sa_delete(HuntEvent).where(HuntEvent.hunt_id == hunt_id))
    # The hunt's chat thread was projected into chat_memory (dual-write below) —
    # remove it in the same transaction so a deleted hunt can't keep echoing
    # into future prompts via retrieval.
    await chat_memory.delete_thread(db, hunt_id)
    await db.delete(hunt)
    await db.commit()
    return True


# ── Follow-up "Chat about this hunt" thread ──────────────────────────────────
#
# A completed hunt gets a read-only Q&A thread, exactly like an investigation's
# follow-up chat. Rather than reuse ``chat_messages`` (whose ``investigation_id``
# is a FK into ``investigations`` — a hunt id would violate it), the thread is
# stored as ``hunt_events`` on the SAME hunt, keyed by these two kinds. They are
# hidden from the hunt's execution timeline (see ``_HUNT_TL_SKIP``) and surfaced
# only through the dedicated ``/hunts/{id}/chat`` endpoint.

CHAT_USER = "chat_user"
CHAT_ASSISTANT = "chat_assistant"


async def _next_chat_sequence(db: AsyncSession, hunt_id: str) -> int:
    """One past the hunt's max event sequence — chat rows append after the trace."""
    top = (
        await db.execute(select(func.max(HuntEvent.sequence)).where(HuntEvent.hunt_id == hunt_id))
    ).scalar()
    return int(top or 0) + 1


async def add_chat_user_message(db: AsyncSession, hunt_id: str, content: str) -> HuntEvent:
    ev = HuntEvent(
        hunt_id=hunt_id,
        sequence=await _next_chat_sequence(db, hunt_id),
        kind=CHAT_USER,
        payload={"content": content, "status": "done"},
    )
    db.add(ev)
    # Dual-write into the chat_memory projection (same transaction — atomic).
    # App-level rather than a SQL trigger because content/status live inside
    # the JSON payload here; see soc_ai.store.chat_memory.
    chat_memory.record_message(
        db,
        source=chat_memory.SOURCE_HUNT,
        thread_id=hunt_id,
        role="user",
        content=content,
    )
    await db.commit()
    await db.refresh(ev)
    return ev


async def create_pending_chat_assistant(db: AsyncSession, hunt_id: str) -> HuntEvent:
    ev = HuntEvent(
        hunt_id=hunt_id,
        sequence=await _next_chat_sequence(db, hunt_id),
        kind=CHAT_ASSISTANT,
        payload={"content": "", "status": "pending"},
    )
    db.add(ev)
    await db.commit()
    await db.refresh(ev)
    return ev


async def finish_chat_assistant(
    db: AsyncSession,
    event_id: int,
    *,
    content: str,
    status: str = "done",
    meta: dict[str, Any] | None = None,
) -> None:
    ev = await db.get(HuntEvent, event_id)
    if ev is None:
        return
    content = scrub_secrets(content)
    payload = dict(ev.payload or {})
    payload["content"] = content
    payload["status"] = status
    if meta is not None:
        payload["meta"] = meta
    ev.payload = payload
    # Project the COMPLETED assistant turn into chat_memory (mirrors
    # soc_ai.store.chat.finish_assistant — done-only, same transaction).
    if status == "done":
        chat_memory.record_message(
            db,
            source=chat_memory.SOURCE_HUNT,
            thread_id=ev.hunt_id,
            role="assistant",
            content=content,
        )
    await db.commit()


async def reap_stale_pending_chat(db: AsyncSession) -> int:
    """Mark every ``pending`` hunt-chat assistant turn ``error``. Returns the count.

    The startup twin of :func:`soc_ai.store.chat.reap_stale_pending`. The hunt
    follow-up chat keeps its turns in ``hunt_events``, so the chat reapers never
    see them, and a turn whose task died with the old process stayed pending
    for ever: the panel spun and every later question on that hunt was refused
    as busy. Startup only, because a hunt event carries no timestamp, so a
    periodic sweep could not tell an orphan from a turn still being written.
    At startup every pending row is an orphan: the task writing it is gone.
    """
    rows = list(
        (
            await db.scalars(
                select(HuntEvent).where(
                    HuntEvent.kind == CHAT_ASSISTANT,
                    HuntEvent.payload["status"].as_string() == "pending",
                )
            )
        ).all()
    )
    for ev in rows:
        payload = dict(ev.payload or {})
        payload["status"] = "error"
        if not payload.get("content"):
            payload["content"] = (
                "The assistant did not finish this turn. A restart is the likely cause. Ask again."
            )
        # Reassigned rather than mutated in place, so the JSON column is dirty.
        ev.payload = payload
    if rows:
        await db.commit()
    return len(rows)


async def set_progress(db: AsyncSession, event_id: int, tools: list[str]) -> None:
    """Record the tools a still-``pending`` hunt-chat turn has called so far.

    The hunt-events twin of :func:`soc_ai.store.general_chat.set_progress`:
    written from the shared engine's per-tool callback so the poll endpoint can
    render live progress instead of a bare typing indicator. Best-effort by
    contract — the caller swallows failures, because a progress write must never
    break the turn producing the real answer. The meta lives INSIDE the event
    payload here (``payload["meta"]["progress_tools"]``), not on a column.
    """
    ev = await db.get(HuntEvent, event_id)
    if ev is None:
        return
    payload = dict(ev.payload or {})
    if payload.get("status") != "pending":
        return  # finished (or resolved) between the tool call and this write
    meta = dict(payload.get("meta") or {})
    meta["progress_tools"] = tools[-12:]
    payload["meta"] = meta
    ev.payload = payload
    await db.commit()


async def list_chat_messages(db: AsyncSession, hunt_id: str) -> list[HuntEvent]:
    """The hunt's chat thread (user + assistant rows), in order."""
    rows = (
        await db.scalars(
            select(HuntEvent)
            .where(
                HuntEvent.hunt_id == hunt_id,
                HuntEvent.kind.in_((CHAT_USER, CHAT_ASSISTANT)),
            )
            .order_by(HuntEvent.sequence, HuntEvent.id)
        )
    ).all()
    return list(rows)


async def get_chat_event(db: AsyncSession, event_id: int) -> HuntEvent | None:
    return await db.get(HuntEvent, event_id)


async def chat_counts_for(db: AsyncSession, hunt_ids: list[str]) -> dict[str, int]:
    """hunt_id -> chat-message count, one grouped COUNT query (mirrors
    ``soc_ai.store.chat.counts_for``). Hunts with no chat rows are omitted —
    callers treat missing keys as 0."""
    if not hunt_ids:
        return {}
    rows = (
        await db.execute(
            select(HuntEvent.hunt_id, func.count().label("n"))
            .where(
                HuntEvent.hunt_id.in_(hunt_ids),
                HuntEvent.kind.in_((CHAT_USER, CHAT_ASSISTANT)),
            )
            .group_by(HuntEvent.hunt_id)
        )
    ).all()
    return {row.hunt_id: row.n for row in rows}


async def chat_history_for_agent(db: AsyncSession, hunt_id: str) -> list[tuple[str, str]]:
    """Completed (role, content) chat turns to seed the follow-up agent — excludes
    the in-flight pending assistant row and any errored turns."""
    out: list[tuple[str, str]] = []
    for ev in await list_chat_messages(db, hunt_id):
        p = ev.payload or {}
        content = str(p.get("content") or "")
        if p.get("status") == "done" and content:
            role = "user" if ev.kind == CHAT_USER else "assistant"
            out.append((role, content))
    return out
