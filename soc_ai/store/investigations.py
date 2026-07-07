"""Persistence service for triage investigations (web UI phase 3).

Rows are created when an /investigate run starts; events append as the
SSE stream flows; finalize() lands the verdict. Badge queries return the
most recent investigation per rule / per alert.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from soc_ai.store.auth import utcnow
from soc_ai.store.models import ChatMessage, Investigation, InvestigationEvent

VERDICTS_RUNNING = "running"

# The verdict strings the detection-tuning FP-trend tally buckets. Any other
# verdict value a row carries is ignored, so the three buckets always sum to
# their "total". `inconclusive` (the self-consistency split outcome) is a
# non-decision and is folded into the needs_more_info bucket at tally time.
_COUNTED_VERDICTS = ("true_positive", "false_positive", "needs_more_info")


async def create(
    db: AsyncSession,
    *,
    alert_es_id: str,
    started_by: str,
    rule_name: str | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
) -> Investigation:
    # Seed the display name at birth when the caller already knows it (the alert
    # grid / re-hunt / group sweep all do). Otherwise it stays NULL and the
    # recorder backfills it from the first alert_context event — but a run that
    # dies before that event (e.g. a prefetch ES error) would then leave the row
    # permanently nameless. Seeding closes that window.
    seed_name = rule_name[:512] if rule_name else None
    inv = Investigation(
        id=str(ULID()),
        alert_es_id=alert_es_id,
        started_by=started_by,
        rule_name=seed_name,
        src_ip=src_ip,
        dest_ip=dest_ip,
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    return inv


async def set_alert_fields(
    db: AsyncSession,
    inv_id: str,
    *,
    rule_name: str | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
) -> None:
    """Set investigation fields only if currently unset (only-set-if-unset semantics)."""
    inv = await db.get(Investigation, inv_id)
    if inv is None:
        return
    changed = False
    if rule_name is not None and not inv.rule_name:
        inv.rule_name = rule_name[:512]
        changed = True
    if src_ip is not None and inv.src_ip is None:
        inv.src_ip = src_ip[:64]
        changed = True
    if dest_ip is not None and inv.dest_ip is None:
        inv.dest_ip = dest_ip[:64]
        changed = True
    if changed:
        await db.commit()


async def set_rule_name(db: AsyncSession, inv_id: str, rule_name: str) -> None:
    """Thin wrapper around set_alert_fields for rule_name-only updates."""
    await set_alert_fields(db, inv_id, rule_name=rule_name)


async def append_events(db: AsyncSession, inv_id: str, events: list[dict[str, Any]]) -> None:
    for ev in events:
        db.add(
            InvestigationEvent(
                investigation_id=inv_id,
                sequence=int(ev.get("sequence", 0)),
                kind=str(ev.get("kind", ""))[:40],
                payload=ev.get("payload") or {},
            )
        )
    await db.commit()


async def finalize(
    db: AsyncSession,
    inv_id: str,
    *,
    status: str,
    verdict: str | None = None,
    confidence: float | None = None,
    rationale: str | None = None,
    summary: str | None = None,
    report: dict[str, Any] | None = None,
) -> None:
    inv = await db.get(Investigation, inv_id)
    if inv is None:
        return
    inv.status = status
    if verdict is not None:
        inv.verdict = verdict
    if confidence is not None:
        inv.confidence = confidence
    if rationale is not None:
        inv.rationale = rationale
    if summary is not None:
        inv.summary = summary
    if report is not None:
        inv.report = report
    inv.finished_at = utcnow()
    await db.commit()


async def resolve(
    db: AsyncSession,
    inv_id: str,
    *,
    verdict: str,
    confidence: float | None,
    rationale: str | None,
    recommended_actions: list[dict[str, Any]] | None,
    resolved_by: str,
    resolved_via: str = "chat",
    source_message_id: int | None = None,
) -> Investigation | None:
    """Change a completed investigation's verdict — from a chat resolution or a manual override.

    Preserves the original verdict + provenance in ``report["resolution"]`` and
    (optionally) writes the proposal's ``recommended_actions`` so the verdict's
    withheld actions surface. Returns the updated row, or ``None`` if not found.

    ``resolved_via`` is "chat" for chat-proposal applies and "manual" for analyst
    overrides from the UI.  ``source_message_id`` is only set for chat resolutions;
    it is omitted from the resolution dict when ``None``.
    """
    inv = await db.get(Investigation, inv_id)
    if inv is None:
        return None
    report = dict(inv.report or {})
    # Preserve the prior resolution in history so the full audit chain survives
    # repeated overrides.  The frontend reads report["resolution"] (singular) for
    # the current state; report["resolution_history"] is available for audit queries.
    if "resolution" in report:
        history: list[dict[str, Any]] = list(report.get("resolution_history") or [])
        history.append(report["resolution"])
        report["resolution_history"] = history
    resolution: dict[str, Any] = {
        "original_verdict": inv.verdict,
        "resolved_via": resolved_via,
        "resolved_by": resolved_by,
        "resolved_at": utcnow().isoformat(),
    }
    if source_message_id is not None:
        resolution["source_message_id"] = source_message_id
    report["resolution"] = resolution
    if recommended_actions is not None:
        report["recommended_actions"] = recommended_actions
    inv.verdict = verdict
    inv.confidence = confidence
    if rationale is not None:
        inv.rationale = rationale
    inv.report = report  # reassign so the JSON column persists the mutation
    if source_message_id:
        # Mark the source proposal applied in the SAME transaction as the verdict
        # change, so a concurrent or retried apply can't slip past the idempotency
        # check and double-resolve.
        proposal_msg = await db.get(ChatMessage, source_message_id)
        if proposal_msg is not None:
            proposal_msg.meta = {**(proposal_msg.meta or {}), "applied": True}
    await db.commit()
    await db.refresh(inv)
    return inv


async def reap_stale_running(
    db: AsyncSession, *, older_than_minutes: int | None, status: str = "error"
) -> int:
    """Mark orphaned ``running`` investigations terminal. Returns the count.

    ``older_than_minutes=None`` reaps EVERY running row — used at startup, where
    any row still ``running`` was orphaned by the restart (its background task is
    gone). A positive int reaps only rows whose ``created_at`` is older than that
    many minutes — used by the periodic sweep so a legitimately in-flight hunt is
    never killed. ``created_at`` and ``utcnow()`` are both naive UTC, so the
    comparison is consistent.

    ``status`` is the terminal status to write: the periodic sweep uses ``error``
    (a hunt that ran too long is a genuine failure), while the startup reap uses
    ``interrupted`` — a clean restart cut the run off; it didn't fail, and the
    state stays re-huntable (see :func:`blocks_rehunt`).
    """
    q = select(Investigation).where(Investigation.status == VERDICTS_RUNNING)
    if older_than_minutes is not None:
        cutoff = utcnow() - timedelta(minutes=older_than_minutes)
        q = q.where(Investigation.created_at < cutoff)
    rows = list((await db.scalars(q)).all())
    now = utcnow()
    interrupted = status == "interrupted"
    for inv in rows:
        inv.status = status
        inv.finished_at = now
        if not inv.rationale:
            inv.rationale = (
                "Investigation was interrupted by a service restart before it finished — re-run it."
                if interrupted
                else "Investigation did not finish (interrupted by a restart or timed out)."
            )
    if rows:
        await db.commit()
    return len(rows)


async def get_with_events(
    db: AsyncSession, inv_id: str
) -> tuple[Investigation, list[InvestigationEvent]] | None:
    inv = await db.get(Investigation, inv_id)
    if inv is None:
        return None
    events = (
        await db.scalars(
            select(InvestigationEvent)
            .where(InvestigationEvent.investigation_id == inv_id)
            .order_by(InvestigationEvent.sequence, InvestigationEvent.id)
        )
    ).all()
    return inv, list(events)


async def _latest_by(db: AsyncSession, column: Any, keys: list[str]) -> dict[str, Investigation]:
    if not keys:
        return {}
    rows = (
        await db.scalars(
            select(Investigation)
            .where(column.in_(keys))
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
            # Bound the scan: we only keep the newest row per key, so at most a
            # small multiple of len(keys) is ever needed. Without this the query
            # returns every historical re-investigation for the keys.
            .limit(len(keys) * 10)
        )
    ).all()
    out: dict[str, Investigation] = {}
    for inv in rows:
        key = getattr(inv, column.key)
        if key is not None and key not in out:
            out[key] = inv
    return out


async def latest_for_rules(db: AsyncSession, rule_names: list[str]) -> dict[str, Investigation]:
    """Most recent investigation per rule name, ANY status (used to detect an
    in-flight re-hunt for the Triaging… flag — NOT for the verdict badge)."""
    return await _latest_by(db, Investigation.rule_name, rule_names)


async def latest_complete_for_rules(
    db: AsyncSession, rule_names: list[str]
) -> dict[str, Investigation]:
    """Most recent COMPLETE, verdict-bearing investigation per rule name.

    This is the rule's STANDING VERDICT for the alerts feed. Unlike
    :func:`latest_for_rules`, it skips running/error/cancelled and verdictless
    rows, so a later interrupted run (a re-hunt cancelled by a deploy, an errored
    run) never erases the verdict the rule already earned — the source of the
    "group says untriaged but its events are investigated/inherited" mismatch.
    """
    if not rule_names:
        return {}
    rows = (
        await db.scalars(
            select(Investigation)
            .where(
                Investigation.rule_name.in_(rule_names),
                Investigation.status == "complete",
                Investigation.verdict.is_not(None),
            )
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
            # Bounded like _latest_by: only the newest complete row per rule is
            # kept, so a small multiple of len(rule_names) suffices.
            .limit(len(rule_names) * 10)
        )
    ).all()
    out: dict[str, Investigation] = {}
    for inv in rows:
        if inv.rule_name and inv.rule_name not in out:
            out[inv.rule_name] = inv
    return out


async def verdict_counts_by_rule(
    db: AsyncSession, rule_names: list[str]
) -> dict[str, dict[str, int]]:
    """Per-rule verdict tallies over COMPLETE investigations (detection tuning).

    For each name in ``rule_names``, count how many of its ``complete``,
    verdict-bearing investigations landed each verdict. The shape is::

        {rule_name: {"true_positive": int, "false_positive": int,
                     "needs_more_info": int, "total": int}}

    Only rules with ≥1 complete investigation appear in the result. ``total`` is
    the sum of the three buckets (any other verdict string is ignored, so the
    buckets always sum to ``total``). This is the FP-trend signal the noisy-rule
    nominator joins against the alert volume — a rule fired a lot and investigated
    mostly false-positive with zero true-positive is a mute candidate.
    """
    out: dict[str, dict[str, int]] = {}
    if not rule_names:
        return out
    rows = await db.execute(
        select(Investigation.rule_name, Investigation.verdict, func.count())
        .where(
            Investigation.rule_name.in_(rule_names),
            Investigation.status == "complete",
            Investigation.verdict.is_not(None),
        )
        .group_by(Investigation.rule_name, Investigation.verdict)
    )
    for rule_name, verdict, count in rows.all():
        if rule_name is None:
            continue
        # `inconclusive` is a terminal non-decision (self-consistency split) —
        # count it with needs_more_info so the FP-trend never reads it as a
        # committed verdict and the buckets still sum to `total`.
        bucket_verdict = "needs_more_info" if verdict == "inconclusive" else verdict
        if bucket_verdict not in _COUNTED_VERDICTS:
            continue
        bucket = out.setdefault(
            rule_name,
            {"true_positive": 0, "false_positive": 0, "needs_more_info": 0, "total": 0},
        )
        # += (not =): needs_more_info can receive two group-by rows (its own
        # + folded inconclusive). Identical to `=` for un-merged verdicts.
        bucket[bucket_verdict] += count
        bucket["total"] += count
    return out


async def latest_for_alerts(db: AsyncSession, alert_ids: list[str]) -> dict[str, Investigation]:
    """Most recent investigation per alert _id (badge on event rows)."""
    return await _latest_by(db, Investigation.alert_es_id, alert_ids)


def blocks_rehunt(inv: Investigation) -> bool:
    """Whether a prior investigation should suppress starting a NEW hunt for its
    alert. Only an in-flight (``running``) or genuinely finished (``complete``)
    run blocks; an ``error`` or ``cancelled`` run produced no usable verdict and
    must stay re-huntable — otherwise an errored investigation silently locks the
    alert out of triage forever (the cause of the "selected 2, only 1 ran" bug)."""
    return inv.status in ("running", "complete")


async def delete(db: AsyncSession, inv_id: str) -> bool:
    """Delete an investigation and its events + chat messages in one transaction.

    Returns True if the investigation existed (and was removed), False otherwise.
    Used by the admin "delete investigation" action to clear broken/orphaned runs.
    """
    inv = await db.get(Investigation, inv_id)
    if inv is None:
        return False
    await db.execute(
        sa_delete(InvestigationEvent).where(InvestigationEvent.investigation_id == inv_id)
    )
    await db.execute(sa_delete(ChatMessage).where(ChatMessage.investigation_id == inv_id))
    await db.delete(inv)
    await db.commit()
    return True


async def list_recent(
    db: AsyncSession,
    *,
    status: str | None = None,
    limit: int = 100,
) -> list[Investigation]:
    """Return investigations ordered by created_at desc, with optional status filter."""
    q = select(Investigation).order_by(Investigation.created_at.desc(), Investigation.id.desc())
    if status is not None:
        q = q.where(Investigation.status == status)
    q = q.limit(limit)
    return list((await db.scalars(q)).all())


async def latest_for_pairs(
    db: AsyncSession,
    pairs: list[tuple[str, str, str]],
    *,
    window_days: int,
) -> dict[tuple[str, str, str], Investigation]:
    """Most recent COMPLETE investigation per (rule_name, src_ip, dest_ip),
    no older than the window. Running/error rows never propagate."""
    if not pairs:
        return {}
    cutoff = utcnow() - timedelta(days=window_days)
    rules = list({p[0] for p in pairs})
    rows = (
        await db.scalars(
            select(Investigation)
            .where(
                Investigation.rule_name.in_(rules),
                Investigation.status == "complete",
                Investigation.created_at >= cutoff,
                Investigation.src_ip.is_not(None),
                Investigation.dest_ip.is_not(None),
            )
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        )
    ).all()
    wanted = set(pairs)
    out: dict[tuple[str, str, str], Investigation] = {}
    for inv in rows:
        key = (inv.rule_name or "", inv.src_ip or "", inv.dest_ip or "")
        if key in wanted and key not in out:
            out[key] = inv
    return out


async def running_for_pairs(
    db: AsyncSession,
    pairs: list[tuple[str, str, str]],
) -> set[tuple[str, str, str]]:
    """The subset of (rule_name, src_ip, dest_ip) pairs with an IN-FLIGHT run.

    :func:`latest_for_pairs` is complete-only by design (a running run must not
    hand out a verdict) — but a sweep planner that consults only completed runs
    will queue a SECOND investigation of a pair whose first run is still
    executing: a newer event id in the cluster defeats the direct id check, and
    the pair check can't see the running row. That is how the same flow got
    investigated twice minutes apart. The planner subtracts these pairs.
    No window: wedged ``running`` rows are reaped to ``error``, so a crashed
    run can't suppress its pair for long.
    """
    if not pairs:
        return set()
    rules = list({p[0] for p in pairs})
    rows = (
        await db.scalars(
            select(Investigation).where(
                Investigation.rule_name.in_(rules),
                Investigation.status == "running",
                Investigation.src_ip.is_not(None),
                Investigation.dest_ip.is_not(None),
            )
        )
    ).all()
    wanted = set(pairs)
    return {
        key
        for inv in rows
        if (key := (inv.rule_name or "", inv.src_ip or "", inv.dest_ip or "")) in wanted
    }
