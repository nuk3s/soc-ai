"""Persistence service for triage investigations (web UI phase 3).

Rows are created when an /investigate run starts; events append as the
SSE stream flows; finalize() lands the verdict. Badge queries return the
most recent investigation per rule / per alert.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

from sqlalchemy import and_, case, func, literal, or_, select
from sqlalchemy import delete as sa_delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, load_only
from ulid import ULID

from soc_ai.store import chat_memory
from soc_ai.store.auth import utcnow
from soc_ai.store.models import ChatMessage, Investigation, InvestigationEvent
from soc_ai.triage_models import is_pipeline_fallback

_LOGGER = logging.getLogger(__name__)

VERDICTS_RUNNING = "running"

# The subject type of a run whose subject is a hunt (migration 0050).
HUNT_SUBJECT_TYPE = "hunt"

# The kinds a promotion lands: a hunt finding ('hunt') or a lead ('lead').
# Both anchor on a cited telemetry document with nothing in Security Onion
# behind it, so every SO-write guard that asks "did a promotion anchor here?"
# must ask about both kinds, never 'hunt' alone.
PROMOTED_KINDS: tuple[str, ...] = ("hunt", "lead")


def is_promoted(inv: Any) -> bool:
    """Whether this row was landed by a promotion (finding or lead).

    The row-level twin of the anchor test in :func:`hunt_anchor_ids`: a
    promoted kind, or a hunt subject whatever the kind says.
    """
    return getattr(inv, "kind", None) in PROMOTED_KINDS or is_hunt_subject(inv)


def is_hunt_subject(inv: Any) -> bool:
    """Whether this run investigated a hunt rather than the alert it anchors on.

    D2. A hunt-subject run carries one of the hunt's cited documents in
    ``alert_es_id``, because the pipeline anchors every time window on one
    timestamp. The document is a time anchor, not the subject. Read as the
    alert's run, the promotion of lead 10 made the alert's own investigation
    a superseded "earlier run" and put a false positive about the HUNT's
    hypothesis on the alert. Nobody investigated that alert.

    This is the predicate every reader that groups by ``alert_es_id`` asks
    first. :func:`alert_group_id` is its answer for one row and
    :func:`not_hunt_subject` is the same rule in SQL. One rule, three shapes,
    so a hunt run cannot stand alone in the list and join the group in a
    query.
    """
    subject = getattr(inv, "subject_json", None)
    return isinstance(subject, dict) and subject.get("type") == HUNT_SUBJECT_TYPE


def alert_group_id(inv: Any) -> str | None:
    """The alert this run groups under, or None when the run stands alone.

    The row-level twin of :func:`not_hunt_subject`. A caller that groups runs
    keys on this, never on ``alert_es_id`` itself.
    """
    return None if is_hunt_subject(inv) else getattr(inv, "alert_es_id", None)


def not_hunt_subject() -> Any:
    """The SQL for a run that belongs to the alert it names.

    ``json_extract`` returns NULL for an alert run, whose ``subject_json`` is
    NULL, and the coalesce keeps that row in the set. A NULL compared to a
    string is NULL, which is not true, and the filter would have dropped every
    alert run.
    """
    return (
        func.coalesce(func.json_extract(Investigation.subject_json, "$.type"), "")
        != HUNT_SUBJECT_TYPE
    )


async def _observe_verdict(db: AsyncSession, inv: Investigation) -> None:
    """Write the alert observation for this verdict. Never fail the caller.

    The import is inside the function because :mod:`soc_ai.hunting.leads`
    imports :mod:`soc_ai.store.models`. A module-level import here would make a
    cycle.
    """
    if not inv.alert_es_id:
        return
    if is_hunt_subject(inv):
        # The verdict is on the hunt, not on the anchor document. The hunt's
        # findings already wrote their observations, and the lead behind the
        # hunt is the thing the analyst promoted. An alert observation here
        # would feed a second lead on the same ground.
        return
    from soc_ai.hunting.sources import observe_alert_verdict  # noqa: PLC0415 - cycle

    try:
        await observe_alert_verdict(
            db,
            alert_id=str(inv.alert_es_id),
            rule_name=inv.rule_name,
            verdict=inv.verdict,
            confidence=inv.confidence,
            hosts=[inv.src_ip, inv.dest_ip, inv.host_name],
            now=datetime.now(UTC),
        )
    except Exception:
        _LOGGER.exception("alert observation failed for investigation %s", inv.id)


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
    kind: str = "suricata",
    hunt_id: str | None = None,
    finding_ordinal: int | None = None,
    is_synth_eval: bool = False,
    subject: dict[str, Any] | None = None,
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
        kind=kind,
        hunt_id=hunt_id,
        finding_ordinal=finding_ordinal,
        # Synth-eval marker: from the eval context (recorded_run) or inherited
        # from a marked hunt at promotion — never from an API request body.
        is_synth_eval=is_synth_eval,
        # What the run investigates (migration 0050). None on an alert run.
        # A hunt run passes the subject the promotion built, so the row says
        # what it was about even if the run dies before its first event.
        subject_json=subject,
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
    community_id: str | None = None,
    host_name: str | None = None,
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
    if community_id is not None and inv.community_id is None:
        inv.community_id = community_id[:128]
        changed = True
    if host_name is not None and inv.host_name is None:
        inv.host_name = host_name[:255]
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
        # Denormalize the pipeline-fallback marker so query_page's aggregate reads
        # a column instead of json_extract'ing every row's report on each poll
        # (migration 0028). Recomputed from the report just written, so it always
        # agrees with is_pipeline_fallback(report).
        inv.is_fallback = is_pipeline_fallback(report)
    inv.finished_at = utcnow()
    await db.commit()
    if verdict is not None and inv.status == "complete":
        await _observe_verdict(db, inv)


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
    # The override replaced report["resolution"] with a manual/chat resolution
    # (no `provenance`), so the row is no longer a pipeline fallback — recompute
    # the denormalized flag from the report just written, keeping it in step with
    # is_pipeline_fallback(report) exactly as the pre-column json_extract did.
    inv.is_fallback = is_pipeline_fallback(report)
    if source_message_id:
        # Mark the source proposal applied in the SAME transaction as the verdict
        # change, so a concurrent or retried apply can't slip past the idempotency
        # check and double-resolve.
        proposal_msg = await db.get(ChatMessage, source_message_id)
        if proposal_msg is not None:
            proposal_msg.meta = {**(proposal_msg.meta or {}), "applied": True}
    await db.commit()
    await db.refresh(inv)
    await _observe_verdict(db, inv)
    return inv


async def dismiss_error(db: AsyncSession, inv_id: str) -> Investigation | None:
    """Stamp the operator's ack of a pipeline-error run.

    Idempotent: an already-dismissed row keeps its ORIGINAL timestamp (the first
    ack is the auditable moment). Returns the row, or ``None`` if not found.
    Whether the run actually IS a pipeline fallback is the caller's check —
    this helper only records the ack.
    """
    inv = await db.get(Investigation, inv_id)
    if inv is None:
        return None
    if inv.error_dismissed_at is None:
        inv.error_dismissed_at = utcnow()
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


async def _latest_by(
    db: AsyncSession, column: Any, keys: list[str], *, where: Any = None
) -> dict[str, Investigation]:
    """Newest row per key. ``where`` narrows the set BEFORE the ranking.

    The filter has to sit inside the subquery: applied after it, a row the
    caller does not want would still win its partition and take the key's
    answer with it.
    """
    if not keys:
        return {}
    # Newest row PER KEY via a window function. A global ORDER BY … LIMIT is
    # wrong here: one noisy key with many recent rows can push every other key's
    # newest row past the limit and drop it from the map entirely. ROW_NUMBER()
    # partitions per key so each key's newest row is selected independently.
    ranked = (
        select(
            Investigation,
            func.row_number()
            .over(
                partition_by=column,
                order_by=(Investigation.created_at.desc(), Investigation.id.desc()),
            )
            .label("rn"),
        )
        .where(column.in_(keys) if where is None else and_(column.in_(keys), where))
        .subquery()
    )
    latest = aliased(Investigation, ranked)
    rows = (await db.scalars(select(latest).where(ranked.c.rn == 1))).all()
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
    db: AsyncSession, rule_names: list[str], *, window_days: int | None = None
) -> dict[str, Investigation]:
    """Most recent COMPLETE, verdict-bearing investigation per rule name.

    This is the rule's STANDING VERDICT. Unlike :func:`latest_for_rules`, it skips
    running/error/cancelled and verdictless rows, so a later interrupted run (a
    re-hunt cancelled by a deploy, an errored run) never erases the verdict the
    rule already earned — the source of the "group says untriaged but its events
    are investigated/inherited" mismatch.

    ``window_days`` bounds the verdict's age. The PER-ALERT inheritance fallback
    passes ``webui_inherit_window_days`` so a stale standing verdict isn't
    inherited onto fresh alerts (mirroring the pair tier in
    :func:`latest_for_pairs`); the rule-GROUP standing badge omits it to reflect
    the rule's last disposition regardless of age. ``None`` = unbounded.
    """
    if not rule_names:
        return {}
    conds = [
        Investigation.rule_name.in_(rule_names),
        Investigation.status == "complete",
        Investigation.verdict.is_not(None),
    ]
    if window_days is not None:
        conds.append(Investigation.created_at >= utcnow() - timedelta(days=window_days))
    # Newest complete row PER RULE via a window function (see :func:`_latest_by`):
    # a global ORDER BY … LIMIT lets one noisy rule's recent rows evict every
    # other rule's standing verdict, so partition per rule and take rn == 1.
    ranked = (
        select(
            Investigation,
            func.row_number()
            .over(
                partition_by=Investigation.rule_name,
                order_by=(Investigation.created_at.desc(), Investigation.id.desc()),
            )
            .label("rn"),
        )
        .where(*conds)
        .subquery()
    )
    latest = aliased(Investigation, ranked)
    rows = (await db.scalars(select(latest).where(ranked.c.rn == 1))).all()
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


async def verdict_counts_since(db: AsyncSession, cutoff: datetime) -> dict[str, int]:
    """Verdicts landed since *cutoff*, tallied by verdict across the whole table.

    The dashboard chat's posture line. Deliberately NOT ``list_recent(limit=N)``
    plus an in-Python tally: a capped scan reports a FLOOR as a total the moment
    a backlog drain completes more investigations than the cap, and the seed
    block states this number to the model as fact — a wrong-but-confident number
    in the anchor is the failure this project keeps paying for.

    Only ``complete``, verdict-bearing rows count: a running or errored run has
    decided nothing. Verdict strings are returned as stored (no bucketing —
    unlike :func:`verdict_counts_by_rule`, whose three buckets have to sum to a
    total), so a new verdict value shows up here rather than vanishing.
    ``cutoff`` is naive UTC, matching ``created_at`` and :func:`utcnow`.
    """
    rows = await db.execute(
        select(Investigation.verdict, func.count())
        .where(
            Investigation.status == "complete",
            Investigation.verdict.is_not(None),
            Investigation.created_at >= cutoff,
        )
        .group_by(Investigation.verdict)
    )
    return {str(verdict): int(count) for verdict, count in rows.all()}


async def override_counts_by_rule(
    db: AsyncSession, rule_names: list[str]
) -> dict[str, dict[str, int]]:
    """Per-rule ANALYST-override tallies over COMPLETE investigations (detection tuning).

    Where :func:`verdict_counts_by_rule` reads the AI verdict trend, this reads the
    HUMAN feedback: how often an analyst overrode a rule's verdict (via chat or a
    manual UI override) and in which direction. That is a stronger tuning signal
    than the AI verdict alone — a rule the analyst keeps correcting TO false-positive
    is institutional memory that it is benign. The shape is::

        {rule_name: {"overridden_to_fp": int, "overridden_to_tp": int,
                     "chat_resolved": int, "manual_resolved": int}}

    An analyst override is a completed investigation whose
    ``report["resolution"]`` carries ``resolved_via`` in ``{"chat", "manual"}``
    (stamped by :func:`resolve`). This is DELIBERATELY distinct from an E1.2
    pipeline_fallback, whose ``report["resolution"]`` carries ``provenance ==
    "pipeline_fallback"`` and NO ``resolved_via`` — so a synth-failure fallback is
    never miscounted as human feedback. ``overridden_to_fp`` counts corrections TO
    false-positive (current verdict is false_positive and the original was not);
    ``overridden_to_tp`` the mirror TO true-positive. Only rules with ≥1 analyst
    override appear in the result.

    ``report`` is a portable JSON column, so this loads the rows and inspects the
    resolution in Python rather than issuing a JSON-path query — bounded like
    :func:`verdict_counts_by_rule` (a small multiple of ``len(rule_names)``).
    """
    out: dict[str, dict[str, int]] = {}
    if not rule_names:
        return out
    # Bound PER RULE, not with a global LIMIT: a window function keeps each
    # rule's 25 most-recent completions so one noisy rule can't evict another
    # rule's overrides from the scan. Analyst overrides are rare relative to raw
    # completions, so 25 recent rows per rule covers the history that drives a
    # nomination.
    ranked = (
        select(
            Investigation,
            func.row_number()
            .over(
                partition_by=Investigation.rule_name,
                order_by=(Investigation.created_at.desc(), Investigation.id.desc()),
            )
            .label("rn"),
        )
        .where(
            Investigation.rule_name.in_(rule_names),
            Investigation.status == "complete",
            Investigation.verdict.is_not(None),
        )
        .subquery()
    )
    recent = aliased(Investigation, ranked)
    rows = (await db.scalars(select(recent).where(ranked.c.rn <= 25))).all()
    for inv in rows:
        if inv.rule_name is None:
            continue
        resolution = (inv.report or {}).get("resolution")
        if not isinstance(resolution, dict):
            continue
        resolved_via = resolution.get("resolved_via")
        # ONLY an analyst override counts. A pipeline_fallback stamps a resolution
        # with `provenance` and no `resolved_via`, so it is skipped here.
        if resolved_via not in ("chat", "manual"):
            continue
        bucket = out.setdefault(
            inv.rule_name,
            {
                "overridden_to_fp": 0,
                "overridden_to_tp": 0,
                "chat_resolved": 0,
                "manual_resolved": 0,
            },
        )
        if resolved_via == "chat":
            bucket["chat_resolved"] += 1
        else:
            bucket["manual_resolved"] += 1
        original = resolution.get("original_verdict")
        if inv.verdict == "false_positive" and original != "false_positive":
            bucket["overridden_to_fp"] += 1
        elif inv.verdict == "true_positive" and original != "true_positive":
            bucket["overridden_to_tp"] += 1
    return out


async def latest_for_alerts(db: AsyncSession, alert_ids: list[str]) -> dict[str, Investigation]:
    """Most recent investigation per alert _id (badge on event rows).

    A hunt-subject run is left out: it anchors on a cited document and is not
    that alert's run (:func:`is_hunt_subject`).
    """
    return await _latest_by(db, Investigation.alert_es_id, alert_ids, where=not_hunt_subject())


async def complete_for_alert(db: AsyncSession, alert_id: str) -> Investigation | None:
    """The most recent COMPLETED investigation for *alert_id*, or None.

    Distinct from :func:`latest_for_alerts`, which returns the newest row of ANY
    status. The demo replay reuse guard needs "does a completed replay row exist
    for this alert" independent of a newer non-complete row: a client that aborts
    the inline ``/investigate`` SSE mid-stream lands an ``error`` row that would
    otherwise become the latest and defeat a latest-based reuse check, so each
    abort would both add a row and force the next post to persist a fresh one.
    Querying the completed set directly closes that.
    """
    q = (
        select(Investigation)
        .where(
            Investigation.alert_es_id == alert_id,
            Investigation.status == "complete",
            # A hunt-subject run anchors on a cited document. It is not a
            # completed run OF this alert.
            not_hunt_subject(),
        )
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        .limit(1)
    )
    return (await db.scalars(q)).first()


async def latest_for_finding(
    db: AsyncSession, hunt_id: str, finding_ordinal: int
) -> Investigation | None:
    """Newest investigation promoted from this exact finding — the promotion
    route's idempotency probe (re-promoting returns it instead of spawning a
    duplicate). May return rows whose hunt has since been deleted: hunt_id has
    no FK on purpose, so the provenance link can dangle."""
    # scalars().first() rather than db.scalar(): identical result, but typed
    # (db.scalar returns Any under mypy --strict) and it matches the module's
    # other single-row readers.
    rows = await db.scalars(
        select(Investigation)
        .where(
            Investigation.hunt_id == hunt_id,
            Investigation.finding_ordinal == finding_ordinal,
        )
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        .limit(1)
    )
    return rows.first()


async def hunt_anchor_ids(db: AsyncSession, alert_ids: Sequence[str]) -> set[str]:
    """Subset of *alert_ids* that anchor at least one promoted investigation.

    A promoted hunt finding's ``alert_es_id`` is a cited telemetry document,
    not a Security Onion alert — there is nothing in SO to ack/escalate, ever.
    A promoted lead anchors the same way and lands ``kind='lead'`` with the
    hunt as its subject, so the test is :data:`PROMOTED_KINDS` or a hunt
    subject, never ``'hunt'`` alone. The SO-write guards key off THIS check
    (the anchor document itself) rather than a row's own ``kind``, so a fresh
    non-hunt investigation opened over the same anchor (a re-investigation via
    ``POST /investigate``) cannot launder the document past the hunt-kind
    refusal.
    """
    ids = [i for i in alert_ids if i]
    if not ids:
        return set()
    rows = await db.scalars(
        select(Investigation.alert_es_id).where(
            or_(Investigation.kind.in_(PROMOTED_KINDS), ~not_hunt_subject()),
            Investigation.alert_es_id.in_(ids),
        )
    )
    return set(rows.all())


async def latest_per_finding(db: AsyncSession, hunt_id: str) -> dict[int, Investigation]:
    """Newest investigation per promoted finding of one hunt — the hunt page's
    per-card promotion state. One indexed query; first row seen per ordinal
    wins (newest-first ordering).

    Column-scoped via ``load_only``: the caller (the hunt detail's per-finding
    card) renders id / status / verdict / confidence and nothing else, and
    GET /hunts/{id} is polled by the SPA — loading every promotion row's
    ``report``/``summary`` blob would deserialize megabytes per tick to answer
    four scalars. ``raiseload=True`` makes an accidental read of an unloaded
    column a loud error instead of a silent async lazy-load.
    """
    rows = await db.scalars(
        select(Investigation)
        .options(
            load_only(
                Investigation.id,
                Investigation.finding_ordinal,
                Investigation.status,
                Investigation.verdict,
                Investigation.confidence,
                Investigation.created_at,
                raiseload=True,
            )
        )
        .where(Investigation.hunt_id == hunt_id, Investigation.finding_ordinal.is_not(None))
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
    )
    out: dict[int, Investigation] = {}
    for inv in rows:
        ordinal = inv.finding_ordinal
        if ordinal is not None and ordinal not in out:
            out[ordinal] = inv
    return out


def blocks_rehunt(inv: Investigation) -> bool:
    """Whether a prior investigation should suppress starting a NEW hunt for its
    alert. Only an in-flight (``running``) or genuinely finished (``complete``)
    run blocks; an ``error`` or ``cancelled`` run produced no usable verdict and
    must stay re-huntable — otherwise an errored investigation silently locks the
    alert out of triage forever (the cause of the "selected 2, only 1 ran" bug).

    A pipeline fallback is that same shape wearing a ``complete`` status. It is
    written when the synth path raises — model truncation, a gateway 5xx, schema
    validation exhausted — and it stores a placeholder ``needs_more_info`` the
    pipeline never reasoned to. So it is a failure by every measure except the
    status column, and it must not block either.

    This was the "pipeline errors that never heal" report. The two halves of the
    product disagreed: the investigations list counted a fallback as needing a
    retry (:func:`_needs_retry`, ``fallback or noVerdict``), while this predicate
    counted it as finished and the sweep skipped its alert as ``already_triaged``.
    On the home deployment nine alerts sat in exactly that gap — permanently
    listed as needing attention, permanently ineligible for the only thing that
    would clear them. Both halves now read a failure the same way.
    """
    if inv.status == "running":
        return True
    if inv.status != "complete":
        return False
    # Either source of truth: the column is stamped at finalize, the report is
    # the canonical predicate every other consumer derives from. A row written
    # before the column existed carries the marker only in the report.
    return not (inv.is_fallback is True or is_pipeline_fallback(inv.report))


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
    # The chat thread was projected into chat_memory (dual-write in
    # soc_ai.store.chat) — remove it in the same transaction so a deleted
    # investigation can't keep echoing into future prompts via retrieval.
    await chat_memory.delete_thread(db, inv_id)
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


class NotifRow(NamedTuple):
    """The scalar columns the /notifications bell reads from an investigation.

    The bell renders id / rule_name / verdict / status / the two timestamps /
    the synth-eval marker and nothing else — never the ``report`` JSON blob.
    Selecting exactly these keeps the app's hottest poll from materializing a
    report column it discards, the way :class:`RunRef` does for primacy.
    ``is_synth_eval`` rides along because the bell DISPLAYS the row ("Verdict
    true_positive: <rule>") — a marked run's entry must carry the marker out to
    the wire like every other surface that shows the row.
    """

    id: str
    rule_name: str | None
    verdict: str | None
    status: str
    created_at: datetime
    finished_at: datetime | None
    is_synth_eval: bool
    error_dismissed_at: datetime | None


async def list_recent_notifications(
    db: AsyncSession,
    *,
    status: str | None = None,
    limit: int = 100,
    finished_since: datetime | None = None,
    no_verdict: bool = False,
    exclude_dismissed: bool = False,
) -> list[NotifRow]:
    """Lightweight investigation rows for the notifications bell — scalar columns only.

    Column-scoped (not :func:`list_recent`, which loads full ORM entities with
    the ``report`` blob). ``finished_since`` bounds AND orders the query on
    ``finished_at`` IN SQL — the completed-runs half of the bell previously took
    the newest-N page by ``created_at`` and dropped out-of-window rows in Python
    afterwards, so a run created before the window but finished inside it fell
    off the created_at page and never appeared. finished_at is the clock the
    bell renders, so it is the one window definition for both halves. NULL
    ``finished_at`` (a running row) is excluded by the ``>=`` bound, which is
    correct: the bound is only ever passed for the completed query, and the
    running query keeps its ``created_at`` order (the stamp it renders).

    ``status`` matches the DISPLAY status (:func:`_display_status_sql`), not the
    stored column, so the bell grades a row the way every other surface renders
    it. A 'complete' run with a blank verdict displays as an error, so asking
    for completions no longer hands back a run that reached no decision and
    titles it "Verdict untriaged". Asking for errors finds it instead.

    ``no_verdict`` narrows to runs that ended without one, and
    ``exclude_dismissed`` drops the ones an operator has already acknowledged
    (``POST /investigations/{id}/dismiss-error``). Together they are the bell's
    failed-triage half. Both are SQL conditions rather than a Python filter over
    the page, because dropping rows after a LIMIT is how a bounded query comes
    back empty while matching rows sit just past the cut.
    """
    q = select(
        Investigation.id,
        Investigation.rule_name,
        Investigation.verdict,
        Investigation.status,
        Investigation.created_at,
        Investigation.finished_at,
        Investigation.is_synth_eval,
        Investigation.error_dismissed_at,
    )
    if status is not None:
        q = q.where(_display_status_sql() == status)
        if status != "error":
            # Redundant, and kept on purpose. 'error' is the only display status
            # a row can reach from a DIFFERENT stored value, so for every other
            # one the raw column is an exact restatement of the CASE, and a plain
            # equality is what the (status, created_at) index can serve.
            # Without it the bell's two hot queries, polled every 15s by every
            # open tab, would fall back to scanning the table.
            q = q.where(Investigation.status == status)
    if no_verdict:
        q = q.where(_blank_verdict_sql())
    if exclude_dismissed:
        q = q.where(Investigation.error_dismissed_at.is_(None))
    if finished_since is not None:
        q = q.where(Investigation.finished_at >= finished_since).order_by(
            Investigation.finished_at.desc(), Investigation.id.desc()
        )
    else:
        q = q.order_by(Investigation.created_at.desc(), Investigation.id.desc())
    q = q.limit(limit)
    return [NotifRow(*row) for row in (await db.execute(q)).all()]


# The stored statuses the backend actually writes (anything else renders as
# 'error'). The ONE list: the display-status CASE below, the route's filter
# validation, and the route's renderer (``_row_status``'s ``_STATUS`` is
# ``frozenset(DISPLAY_STATUSES)``) all read it, so a status added here cannot
# reach one of the three and leave the other two disagreeing about it.
DISPLAY_STATUSES = ("running", "complete", "error", "cancelled", "interrupted")

# The synthetic verdict-filter member: not a stored verdict string but "this run
# produced no usable verdict". Two shapes qualify. One is the E1.2 fallback: the
# pipeline failed, wrote a placeholder needs_more_info and marked the report. The
# other is a run that died outright: no verdict, no rationale, no report to mark
# (:func:`failed_triage_sql`). Only the first was ever in this filter, which is
# why 188 dead runs on the deployed instance were unreachable from the Dashboard
# count, its deep link, and the screen's own Verdict filter. Spelled here because
# the SQL translation of both shapes lives in this module.
PIPELINE_ERROR_VERDICT = "pipeline_error"

# Cap shared with the route (mirrors list_recent's historical clamp).
MAX_PAGE_LIMIT = 500


def _blank_verdict_sql() -> Any:
    """ "This run reached no verdict", as a SQL expression.

    The trim charset is spelled out because the renderer's blank test is
    ``str.strip()``, which strips ALL whitespace, while SQL ``trim(x)`` with no
    charset strips SPACES ONLY — a tab-only verdict rendered as 'error' and
    filtered as 'complete'. The charset is Python's ``string.whitespace``, so
    the two agree over ASCII whitespace and the differential test pins that.
    They still part company on the Unicode whitespace ``str.strip()`` strips and
    ``string.whitespace`` omits (NEL, NBSP, U+2028…); closing that would mean
    enumerating Unicode space codepoints into a SQL charset for a column the
    backend only ever writes from a fixed verdict enum, so the ASCII half is
    where this stops. The two-argument ``trim`` this emits is SQLite's spelling,
    not portable SQL.
    """
    blank = " \t\n\r\x0b\x0c"
    return or_(Investigation.verdict.is_(None), func.trim(Investigation.verdict, blank) == "")


def _display_status_sql() -> Any:
    """The status a row will RENDER with, as a SQL expression.

    Mirrors ``routes_investigations._row_status``: an unknown stored status is
    'error', and a 'complete' run with no (or blank) verdict is 'error'. The
    filter must use THIS, not the raw column — filtering on the raw column would
    let status=complete return rows the table then displays as errors, and
    status=error miss them: a filter promising a set the screen contradicts.
    """
    return case(
        (and_(Investigation.status == "complete", _blank_verdict_sql()), "error"),
        (Investigation.status.not_in(DISPLAY_STATUSES), "error"),
        else_=Investigation.status,
    )


def failed_triage_sql() -> Any:
    """ "The triage died and left no answer", as a SQL expression.

    A run that displays as an error AND carries no verdict: no disposition, no
    rationale, nothing for the queue to have learned. Distinct from an errored
    run that DID reach a verdict, which is reachable under that verdict and is
    not a hole in the coverage.

    Named, exported and shared because three surfaces have to agree on it or the
    hole opens again: the Dashboard's count, the notification bell, and the
    dismiss endpoint that clears one. The deployed instance carried 188 rows in
    this state over ten weeks: none acknowledged, none re-queued, none mentioned
    anywhere in the product.

    ``cancelled`` is deliberately outside it: an operator asked for that stop.
    So is ``interrupted``: a restart cut the run off and the row stays
    re-huntable (:func:`blocks_rehunt`), so auto-triage picks it up again.
    """
    return and_(_display_status_sql() == "error", _blank_verdict_sql())


@dataclass(frozen=True)
class InvestigationPage:
    """One SQL page of the investigations list, with counts that stay honest.

    ``total``/``running``/``true_positives`` describe the whole FILTER SET, not
    the page — a figure tallied from the rows on screen describes one page while
    reading as the query's (the phantom-untriaged defect). ``total_all`` and
    ``active`` describe the whole table: the client needs "is the store empty or
    did my filter match nothing" and "is anything running anywhere" (poll
    gating), and neither can be derived from a filtered page.
    """

    rows: list[Investigation]
    total: int
    running: int
    true_positives: int
    total_all: int
    active: bool


async def query_page(
    db: AsyncSession,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    verdicts: Sequence[str] | None = None,
    statuses: Sequence[str] | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> InvestigationPage:
    """The investigations list as a real query: filters, counts and paging in SQL.

    This exists because the screen used to filter a newest-100
    :func:`list_recent` page client-side — on a deployment whose newest 100 runs
    were one saturated outcome, every older errored run was unreachable under
    ANY filter the operator could set. :func:`list_recent` is left untouched for
    its other callers (the bell's bounded running/completed lists).

    ``since``/``until`` bound ``created_at`` inclusively (naive UTC, matching
    the column). ``statuses`` filters on the DISPLAY status
    (:func:`_display_status_sql`) so the filter agrees with what the table
    renders. ``verdicts`` matches stored verdict strings, plus the synthetic
    :data:`PIPELINE_ERROR_VERDICT`: a fallback-marked row matches ONLY that
    member — its stored needs_more_info must not leak into the NMI filter — and
    a row matches a real verdict only when it is NOT fallback-marked, mirroring
    the screen's matchesVerdict semantics (the ``true_positives`` figure applies
    that same guard, so it never counts a row the verdict filter would exclude).
    A run that died without a verdict (:func:`failed_triage_sql`) matches that
    same member; it needs no exclusion from the real-verdict branch because it
    has no verdict string to match one with.
    Unknown members simply match nothing (the route drops them before calling).

    ``q`` is the operator's free text, matched case-insensitively as a substring
    of the rule name, the source address or the destination address — the three
    things the table actually renders, so a row that matches is a row whose
    match is visible. It joins ``conds``, which means it narrows the header
    counts alongside the rows: a search that shrank the table while the counts
    described the whole store is the phantom-count defect this query exists to
    prevent. ``autoescape`` keeps a typed ``%`` a percent sign rather than
    "match everything".

    Three queries: the page, one aggregate over the filter set (total / running
    / true-positive), one over the whole table (total_all / active). The
    ``(status, created_at)`` index (migration 0028) serves the ORDER BY.
    Fallback membership reads the persisted ``is_fallback`` column — stamped at
    finalize/resolve — rather than ``json_extract``'ing every row's report blob
    on each poll (the growth defect this query used to carry). Reordering the
    conjunction to test the cheap verdict first would NOT be sound: SQLite does
    not guarantee left-to-right evaluation of AND terms.
    """
    # ``is_fallback`` is a nullable Boolean: True only on rows finalize/resolve
    # stamped as pipeline fallbacks. ``.isnot(True)`` folds both False AND NULL
    # (legacy / not-yet-finalized rows) to not-a-fallback — the same treatment
    # the old `or_(provenance.is_(None), provenance != ...)` gave a NULL path.
    is_fallback = Investigation.is_fallback.is_(True)
    not_fallback = Investigation.is_fallback.isnot(True)

    conds: list[Any] = []
    if since is not None:
        conds.append(Investigation.created_at >= since)
    if until is not None:
        conds.append(Investigation.created_at <= until)
    if statuses:
        conds.append(_display_status_sql().in_(list(statuses)))
    if verdicts:
        stored = [v for v in verdicts if v != PIPELINE_ERROR_VERDICT]
        terms: list[Any] = []
        if PIPELINE_ERROR_VERDICT in verdicts:
            terms.append(or_(is_fallback, failed_triage_sql()))
        if stored:
            terms.append(and_(not_fallback, Investigation.verdict.in_(stored)))
        conds.append(or_(*terms))
    needle = (q or "").strip()
    if needle:
        conds.append(
            or_(
                Investigation.rule_name.icontains(needle, autoescape=True),
                Investigation.src_ip.icontains(needle, autoescape=True),
                Investigation.dest_ip.icontains(needle, autoescape=True),
            )
        )

    limit = max(1, min(limit, MAX_PAGE_LIMIT))
    offset = max(0, offset)

    rows = list(
        (
            await db.scalars(
                select(Investigation)
                .where(*conds)
                .order_by(Investigation.created_at.desc(), Investigation.id.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )
    total, running, true_positives = (
        await db.execute(
            select(
                func.count(Investigation.id),
                func.coalesce(
                    func.sum(case((_display_status_sql() == VERDICTS_RUNNING, 1), else_=0)), 0
                ),
                # Same not-a-fallback guard the ROW filter applies to
                # verdict=true_positive. Without it a fallback-marked row that
                # still carries a true_positive verdict counts here while
                # rendering a pipeline-error chip below — a header figure
                # describing a set its own rows are not in.
                func.coalesce(
                    func.sum(
                        case(
                            (and_(not_fallback, Investigation.verdict == "true_positive"), 1),
                            else_=0,
                        )
                    ),
                    0,
                ),
            ).where(*conds)
        )
    ).one()
    total_all, running_all = (
        await db.execute(
            select(
                func.count(Investigation.id),
                func.coalesce(
                    func.sum(case((Investigation.status == VERDICTS_RUNNING, 1), else_=0)), 0
                ),
            )
        )
    ).one()
    return InvestigationPage(
        rows=rows,
        total=int(total),
        running=int(running),
        true_positives=int(true_positives),
        total_all=int(total_all),
        active=int(running_all) > 0,
    )


class RunRef(NamedTuple):
    """The columns primacy is decided from — and nothing else.

    :func:`runs_for_alerts` fans out over a page's alert ids (up to the 500-row
    page cap), and each alert contributes its WHOLE retry group. Fetching full
    ORM rows there would drag every retry's ``report`` JSON blob through the
    session to answer a question that reads four scalar columns.
    """

    id: str
    alert_es_id: str | None
    status: str
    created_at: datetime


async def runs_for_alerts(db: AsyncSession, alert_ids: Sequence[str]) -> list[RunRef]:
    """EVERY run for the given alerts, newest first — the primacy input.

    Every run OF the alert. A hunt-subject run names one of the hunt's
    documents and is not one of them (:func:`is_hunt_subject`).

    The canonical ("primary") run per alert is decided over the alert's WHOLE
    group. Deciding it over a filtered page instead would crown whichever
    sibling happened to match the filter — under status=error an errored retry
    would arrive labelled primary while its complete sibling (the run that
    actually holds the verdict) sat excluded.

    One indexed query (``alert_es_id`` carries an index), no LIMIT. The row
    count is the sum of the page's group sizes: deliberately unbounded PER
    ALERT, because a bound would make primacy depend on which runs fit it —
    the accident this function exists to prevent. In practice groups stay
    small (``blocks_rehunt`` refuses re-runs of running/complete alerts and
    bulk rehunt starts at most 3), and the theoretical worst case — every row
    in the table retries an alert on the page — is a scan of :class:`RunRef`
    tuples, not of report blobs.
    """
    if not alert_ids:
        return []
    rows = await db.execute(
        select(
            Investigation.id,
            Investigation.alert_es_id,
            Investigation.status,
            Investigation.created_at,
        )
        .where(Investigation.alert_es_id.in_(list(alert_ids)), not_hunt_subject())
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
    )
    return [RunRef(*row) for row in rows.all()]


async def for_entity(db: AsyncSession, value: str, *, limit: int = 50) -> list[Investigation]:
    """Investigations touching an entity — where ``src_ip == value OR dest_ip == value``.

    Powers the entity pivot page (E3.5): every investigation whose source OR
    destination is this host/IP, newest first, bounded. ANY status (a running or
    errored run is still part of "what we know about this box"). The
    ``ix_investigations_similarity`` composite index leads with ``rule_name`` so it
    doesn't serve this OR directly, but ``src_ip``/``dest_ip`` are low-cardinality
    and the scan is ``limit``-bounded, so it stays cheap for the read-model.

    Synth-eval rows (migration 0032) are EXCLUDED, not badged. Both callers
    narrate a host's REAL history — the entity timeline and the host page's
    latest-investigation chip (``routes_dossier._investigation_lookup``,
    limit=1) — and a planted scenario describes nothing that happened on the
    box. At limit=1 a newer planted run would otherwise SHADOW the newest real
    one and become the host's "latest disposition". The runs themselves stay
    fully visible (badged) on the Investigations list and detail surfaces.
    """
    if not value:
        return []
    q = (
        select(Investigation)
        .where((Investigation.src_ip == value) | (Investigation.dest_ip == value))
        .where(Investigation.is_synth_eval.is_(False))
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        .limit(limit)
    )
    return list((await db.scalars(q)).all())


# The key a verdict travels along: rule, then the subject it was about.
#
# ``(rule_name, src_ip, dest_ip, host_name)``, and the host component is
# CONDITIONAL — see :func:`pair_key` for why it is empty whenever a flow is
# present.
PairKey = tuple[str, str, str, str]

# The key with a rule and nothing else. It names no subject: not an address,
# not a machine, nothing but "this detection, somewhere". Verdicts do not
# travel along it (see :func:`latest_for_pairs`).
_SUBJECTLESS = ("", "", "")


def pair_key(
    rule_name: str | None,
    src_ip: str | None,
    dest_ip: str | None,
    host_name: str | None = None,
) -> PairKey:
    """The inheritance key for one alert or one investigation row.

    Every producer of a key goes through here — the sweep planner's clustering,
    the alert grid's per-event pill, and the two lookups' re-derivation from DB
    rows — because a key built two ways is a key that silently misses.

    A missing component degrades to ``""`` rather than dropping the alert: these
    detections have to be triageable at all, and dropping them is what made the
    scheduled sweep network-flow-only.

    **The host is conditional.** It joins the key only when BOTH endpoints are
    empty. On a multi-sensor grid one flow is seen by two sensors under two
    ``host.name`` values, so keying a flow on the host would split one
    investigation into two of the same thing. A detection with no flow has no
    such collision, and the host is the only subject it has: without it, every
    Sigma host rule collapsed into one cluster covering every machine on the
    estate, forever.
    """
    src = src_ip or ""
    dest = dest_ip or ""
    host = "" if (src or dest) else (host_name or "")
    return (rule_name or "", src, dest, host)


def names_a_subject(key: PairKey) -> bool:
    """Whether a key identifies WHAT a verdict would be about.

    ``(rule, "", "", "")`` does not. It says a detection fired and nothing about
    where, so a verdict reached under it is a verdict about the rule, not about
    anything that happened.
    """
    return key[1:] != _SUBJECTLESS


async def latest_for_pairs(
    db: AsyncSession,
    pairs: list[PairKey],
    *,
    window_days: int,
) -> dict[PairKey, Investigation]:
    """Most recent COMPLETE investigation per :data:`PairKey`, no older than the
    window. Running/error rows never propagate.

    A NULL endpoint is a KEY VALUE, not a reason to skip the row: it coalesces to
    ``""``, the same degrade the sweep planner and the alert grid apply when they
    build the keys they ask about. Filtering NULLs out in SQL made every
    endpoint/process-shaped detection (Sigma host rules carry no ``source.*`` /
    ``destination.*``, so the recorder leaves both columns NULL) invisible here —
    the rows were discarded before the coalescing below could key them, so a
    no-IP cluster never inherited its own prior verdict and was re-investigated
    on every sweep that saw a newer event id. Both-endpoint rows are unaffected:
    a coalesced key always carries an empty component where the row had a NULL,
    so it can never collide with a flow's key.

    **A key that names no subject inherits nothing.** Admitting the NULL rows
    fixed the re-investigation, and left ``(rule, "", "")`` matching every
    address-free alert of that rule on every machine, indefinitely. One benign
    verdict silenced the rule estate-wide and re-armed itself on each sweep,
    because the alerts it silenced were never investigated to contradict it. The
    host now carries these clusters (see :func:`pair_key`); when even that is
    absent there is nothing left to have been right about, and the key is
    refused rather than matched. Such an alert is re-investigated, which is the
    honest outcome for a detection soc-ai cannot tell apart from any other
    firing of the same rule.

    ``kind == "hunt"`` rows are EXCLUDED at the query level: a promoted
    finding's verdict is about its cited evidence, never a license to ack a
    whole detection group. Its ``rule_name`` is the finding's title, which can
    collide with a live rule's name by coincidence — without this filter such
    a row would become an inheritance source and ``_ack_inherited_fps`` would
    write unattended acks against real SO alerts it never investigated.

    Column-scoped via ``load_only``, as :func:`latest_per_finding` is: this
    runs on every alerts-page poll and every auto-triage sweep, over every
    complete in-window row of every rule on the page, and its callers read
    the id, the key columns, the verdict and confidence and when it ran.
    Loading each row's ``report``/``summary``/``rationale`` blob to answer
    that grew linearly with completed-investigation volume. ``raiseload=True``
    makes an accidental read of an unloaded column a loud error instead of a
    silent async lazy-load.
    """
    wanted = {key for key in pairs if names_a_subject(key)}
    if not wanted:
        return {}
    cutoff = utcnow() - timedelta(days=window_days)
    rules = list({key[0] for key in wanted})
    rows = (
        await db.scalars(
            select(Investigation)
            .options(
                load_only(
                    Investigation.id,
                    Investigation.rule_name,
                    Investigation.src_ip,
                    Investigation.dest_ip,
                    Investigation.host_name,
                    Investigation.verdict,
                    Investigation.confidence,
                    Investigation.created_at,
                    raiseload=True,
                )
            )
            .where(
                Investigation.rule_name.in_(rules),
                Investigation.status == "complete",
                Investigation.created_at >= cutoff,
                Investigation.kind != "hunt",
            )
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        )
    ).all()
    out: dict[PairKey, Investigation] = {}
    for inv in rows:
        key = pair_key(inv.rule_name, inv.src_ip, inv.dest_ip, inv.host_name)
        if key in wanted and key not in out:
            out[key] = inv
    return out


# Tier-rank → matched_on label for prior_outcomes(). Index == the CASE rank the
# query computes: 0 = exact triple, 1 = same rule + one shared endpoint, 2 = rule.
_PRIOR_TIER_LABELS = ("rule+src+dest", "rule+endpoint", "rule")

# Digest budget for a prior-outcome rationale. ~280 chars keeps one digest to a
# single compact prompt line; truncation lands on a word boundary (below).
_PRIOR_DIGEST_CHARS = 280


def _digest_rationale(rationale: str | None, *, max_chars: int = _PRIOR_DIGEST_CHARS) -> str | None:
    """Collapse + truncate a rationale into a compact single-line digest.

    All whitespace (including newlines) collapses to single spaces so one digest
    is one prompt line. Over-long text is cut at the last WORD BOUNDARY at or
    before ``max_chars`` and marked with an ellipsis — a mid-word fragment reads
    like corruption to both analysts and models. Falls back to a hard cut only
    when the boundary would discard more than half the budget (one enormous
    unbroken token, e.g. a base64 blob). ``None``/empty stays ``None`` so the
    caller can render an explicit "(no rationale recorded)" placeholder.
    """
    if not rationale:
        return None
    text = " ".join(rationale.split())
    if len(text) <= max_chars:
        return text
    cut = text.rfind(" ", 0, max_chars + 1)
    if cut < max_chars // 2:
        cut = max_chars
    return text[:cut].rstrip() + "…"


async def prior_outcomes(
    db: AsyncSession,
    *,
    rule_name: str,
    src_ip: str | None,
    dest_ip: str | None,
    exclude_id: str | None,
    window_days: int,
    limit: int,
) -> list[dict[str, Any]]:
    """The most relevant PRIOR verdicts for a (rule, src, dest) alert — E4.2 memory.

    Deterministic feature-match generalization of the exact-triple inheritance
    in :func:`latest_for_pairs`: analysts generalize ("I've seen this rule on
    this host before"), so the synth round-1 prompt can too — via plain SQL,
    never embeddings. Candidates are COMPLETE, verdict-bearing investigations
    for the same ``rule_name`` within ``window_days``, ranked into three
    similarity tiers (higher tier first):

    1. ``rule+src+dest`` — exact triple (both endpoints match).
    2. ``rule+endpoint`` — same rule plus one shared endpoint (prior ``src_ip``
       == our src OR prior ``dest_ip`` == our dest; same-position match, so a
       reversed flow ranks as rule-only — deterministic and cheap over guessing
       direction semantics).
    3. ``rule`` — same rule only.

    Within a tier: newest first (``created_at`` desc, id desc as tiebreak).
    Implemented as ONE query with a CASE ranking rather than 3 stacked queries:
    the ``rule_name`` equality prefix rides ``ix_investigations_similarity``
    either way, and a single ordered scan keeps the tier/recency ordering in
    SQL where it is trivially deterministic. A ``None`` endpoint contributes no
    tier condition (NULL == NULL is shared *absence*, not a shared endpoint).

    Pipeline-fallback rows (E1.2 failure noise, never memory) are excluded IN
    SQL via the persisted ``is_fallback`` column — the twin of
    :func:`~soc_ai.triage_models.is_pipeline_fallback` stamped at
    finalize/resolve. ``.isnot(True)`` folds NULL (legacy / not-yet-finalized
    rows) to not-a-fallback, exactly as :func:`query_page` does. That retires
    the old load-every-report Python post-filter and its 5x overscan: the query
    now selects only the digest columns and fetches exactly ``limit`` rows.

    ``kind == "hunt"`` rows are excluded for the same reason as
    :func:`latest_for_pairs`: a promoted finding's ``rule_name`` is the
    finding's TITLE, which can collide with a live rule's name by coincidence —
    without the filter a promotion's verdict would bleed into a real alert's
    prior-outcome prompt as if that rule had been triaged before.

    ``exclude_id`` drops the caller's own row. The orchestrator's in-flight row
    is still ``running`` (complete-only already excludes it) — this is for
    callers/tests that hold a concrete completed row id.

    Returns light digests (never full reports)::

        {id, created_at, verdict, confidence,
         matched_on ("rule+src+dest" | "rule+endpoint" | "rule"),
         rationale_digest (rationale collapsed + word-boundary-truncated ~280)}
    """
    if not rule_name or limit <= 0:
        return []
    cutoff = utcnow() - timedelta(days=window_days)
    whens: list[tuple[Any, int]] = []
    if src_ip is not None and dest_ip is not None:
        whens.append((and_(Investigation.src_ip == src_ip, Investigation.dest_ip == dest_ip), 0))
    endpoint_terms = []
    if src_ip is not None:
        endpoint_terms.append(Investigation.src_ip == src_ip)
    if dest_ip is not None:
        endpoint_terms.append(Investigation.dest_ip == dest_ip)
    if endpoint_terms:
        whens.append((or_(*endpoint_terms), 1))
    # No known endpoint at all ⇒ every candidate is tier 2 (rule-only).
    tier = case(*whens, else_=2) if whens else literal(2)
    q = (
        # Digest columns only — never the ORM entity, whose report/summary
        # blobs this function would deserialize just to throw away.
        select(
            Investigation.id,
            Investigation.created_at,
            Investigation.verdict,
            Investigation.confidence,
            Investigation.rationale,
            tier.label("tier"),
        )
        .where(
            Investigation.rule_name == rule_name,
            Investigation.status == "complete",
            Investigation.verdict.is_not(None),
            Investigation.created_at >= cutoff,
            # NULL-tolerant not-a-fallback, same treatment as query_page.
            Investigation.is_fallback.isnot(True),
            # A promoted hunt finding is titled, not ruled — see the docstring.
            Investigation.kind != "hunt",
        )
        .order_by(tier, Investigation.created_at.desc(), Investigation.id.desc())
        .limit(limit)
    )
    if exclude_id is not None:
        q = q.where(Investigation.id != exclude_id)
    rows = (await db.execute(q)).all()
    return [
        {
            "id": row.id,
            "created_at": row.created_at,
            "verdict": row.verdict,
            "confidence": row.confidence,
            "matched_on": _PRIOR_TIER_LABELS[int(row.tier)],
            "rationale_digest": _digest_rationale(row.rationale),
        }
        for row in rows
    ]


# How far back a community id still means "the same session". A community id is
# a hash of the five-tuple, and a five-tuple is reused: the same client port
# talking to the same service days later is a different conversation wearing the
# same name. A day is generous for one session and short enough that a reuse
# rarely lands inside it. The two range alerts that reached opposite verdicts
# were twenty-eight minutes apart.
SESSION_WINDOW_MINUTES = 1440


async def session_verdicts(
    db: AsyncSession,
    *,
    community_id: str,
    exclude_id: str | None = None,
    window_minutes: int = SESSION_WINDOW_MINUTES,
    limit: int = 3,
) -> list[dict[str, Any]]:
    """Verdicts already reached on the SAME network session, newest first.

    The community id is the hashed five-tuple, so this is the five-tuple key the
    row could not carry before migration 0038: same source, same destination,
    same ports, same protocol. Sibling of :func:`prior_outcomes` and
    deliberately not a tier of it. A prior outcome is a resemblance and reaches
    the model as context it may weigh against the evidence in front of it; this
    is the same conversation, already read, and it reaches the model as a
    constraint. Two alerts from one session that settle opposite ways are not
    two opinions, they are one contradiction, and the range produced exactly
    that: a true positive recommending escalation and a false positive
    recommending acknowledgement, twenty-eight minutes apart on one TCP session.

    Same candidate filters as :func:`prior_outcomes` and for the same reasons:
    COMPLETE and verdict-bearing (a running row hands out nothing), inside the
    window, not a pipeline fallback, and never a promoted hunt finding. Synthetic
    evaluation rows are excluded too, which the rule-keyed sibling does not need
    to do: a synth run is allowed to see planted scenarios, so its verdict must
    never bind a real one.

    An empty ``community_id`` returns nothing rather than matching every row
    whose session is unknown. NULL is the absence of a session, never a shared
    one.

    Returns light digests (never full reports)::

        {id, created_at, verdict, confidence, rationale_digest}
    """
    if not community_id or limit <= 0:
        return []
    cutoff = utcnow() - timedelta(minutes=window_minutes)
    q = (
        select(
            Investigation.id,
            Investigation.created_at,
            Investigation.verdict,
            Investigation.confidence,
            Investigation.rationale,
        )
        .where(
            Investigation.community_id == community_id,
            Investigation.status == "complete",
            Investigation.verdict.is_not(None),
            Investigation.created_at >= cutoff,
            Investigation.is_fallback.isnot(True),
            Investigation.kind != "hunt",
            Investigation.is_synth_eval.isnot(True),
        )
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        .limit(limit)
    )
    if exclude_id is not None:
        q = q.where(Investigation.id != exclude_id)
    rows = (await db.execute(q)).all()
    return [
        {
            "id": row.id,
            "created_at": row.created_at,
            "verdict": row.verdict,
            "confidence": row.confidence,
            "rationale_digest": _digest_rationale(row.rationale),
        }
        for row in rows
    ]


async def running_for_pairs(
    db: AsyncSession,
    pairs: list[PairKey],
) -> set[PairKey]:
    """The subset of :data:`PairKey` keys with an IN-FLIGHT run.

    :func:`latest_for_pairs` is complete-only by design (a running run must not
    hand out a verdict) — but a sweep planner that consults only completed runs
    will queue a SECOND investigation of a pair whose first run is still
    executing: a newer event id in the cluster defeats the direct id check, and
    the pair check can't see the running row. That is how the same flow got
    investigated twice minutes apart. The planner subtracts these pairs.
    No window: wedged ``running`` rows are reaped to ``error``, so a crashed
    run can't suppress its pair for long.

    NULL endpoints coalesce to ``""`` rather than excluding the row, exactly as
    in :func:`latest_for_pairs` — otherwise the guard covers only network flows
    and a host-shaped rule can be investigated twice concurrently (a manual run
    in flight would not block the scheduled one).

    Unlike :func:`latest_for_pairs`, a key naming no subject is NOT refused
    here. The two answer different questions. That one hands out a verdict, so
    it needs to know the verdict was about this alert; this one only stops the
    same work being started twice while it is already running, and a coarse
    stop is safe where a coarse verdict is not. Refusing it would let one sweep
    launch a run per address-free alert of a rule at once.

    ``kind == "hunt"`` rows are excluded exactly as in :func:`latest_for_pairs`:
    a promotion's ``rule_name`` is a finding title that can collide with a live
    rule's name, and an in-flight promotion must not suppress the sweep from
    investigating that rule's real alerts.
    """
    if not pairs:
        return set()
    rules = list({key[0] for key in pairs})
    rows = (
        await db.scalars(
            select(Investigation).where(
                Investigation.rule_name.in_(rules),
                Investigation.status == "running",
                Investigation.kind != "hunt",
            )
        )
    ).all()
    wanted = set(pairs)
    return {
        key
        for inv in rows
        if (key := pair_key(inv.rule_name, inv.src_ip, inv.dest_ip, inv.host_name)) in wanted
    }


# One recorded acknowledgement fan-out, written onto the investigation whose
# verdict was inherited, so the writes an old verdict is still producing stay
# attributable to it and outlive the sweep that made them.
INHERITED_ACK_EVENT_KIND = "inherited_ack"

# Recorded event kinds that can carry a retrieval. Mirrors
# ``soc_ai.agent.evidence.RETRIEVAL_EVENT_KINDS``, spelled here rather than
# imported because the store never imports the agent package.
_RETRIEVAL_EVENT_KINDS = ("tool_result", "targeted_tool_result", "oracle_adjudication")


async def retrieval_events_for(
    db: AsyncSession, inv_ids: Sequence[str]
) -> dict[str, list[tuple[str, Any]]]:
    """Recorded retrieval-shaped events, grouped by investigation id.

    Only :data:`_RETRIEVAL_EVENT_KINDS` are read: the rest of a run's event
    stream is prompt assembly, model text and bookkeeping, and pulling it would
    load every model response on the box to answer a yes/no question.

    Deliberately dumb — it returns rows, and the caller asks
    :func:`soc_ai.agent.evidence.recorded_run_retrieved_evidence` what they mean.
    """
    if not inv_ids:
        return {}
    rows = (
        await db.execute(
            select(
                InvestigationEvent.investigation_id,
                InvestigationEvent.kind,
                InvestigationEvent.payload,
            ).where(
                InvestigationEvent.investigation_id.in_(list(dict.fromkeys(inv_ids))),
                InvestigationEvent.kind.in_(_RETRIEVAL_EVENT_KINDS),
            )
        )
    ).all()
    out: dict[str, list[tuple[str, Any]]] = {}
    for inv_id, kind, payload in rows:
        out.setdefault(inv_id, []).append((kind, payload))
    return out


# How many acknowledged alert ids one fan-out row keeps. The audit index holds
# the complete per-alert trail (one ``auto_ack_inherited`` record each, carrying
# ``inherited_from``); this is a recent sample so the row is readable and the
# payload cannot grow to the size of the fan-out itself.
_INHERITED_ACK_SAMPLE = 50


async def record_inherited_acks(
    db: AsyncSession, *, source_id: str, alert_ids: Sequence[str], rule_name: str | None = None
) -> None:
    """Record a sweep's fan-out on the investigation the verdict came from.

    The inheritance path acknowledges alerts in Security Onion without creating
    an investigation of its own, so until now the only trace was a per-sweep
    counter on :class:`~soc_ai.webui.autotriage.AutoTriageStatus` that died when
    the sweep ended. On the deployed instance that counter had reached 110,635
    grid writes against 2,768 from the direct path, and no surface in the
    product could say so.

    Writing it onto the SOURCE investigation answers the question in the
    direction an analyst asks it: not "how many acks happened last night" but
    "what has this one false positive been acknowledging on my grid since I
    closed it".

    ONE row per source, updated in place. The sweep runs every few minutes and
    the largest single fan-out on record is 945 acknowledgements, so a row per
    sweep would bury the investigation's own timeline under its own aftermath
    and grow without limit. The count is cumulative and the id list keeps the
    most recent :data:`_INHERITED_ACK_SAMPLE`; the audit trail holds all of them.
    """
    ids = [a for a in alert_ids if a]
    if not ids:
        return
    now = utcnow().isoformat()
    existing = (
        await db.scalars(
            select(InvestigationEvent)
            .where(
                InvestigationEvent.investigation_id == source_id,
                InvestigationEvent.kind == INHERITED_ACK_EVENT_KIND,
            )
            .order_by(InvestigationEvent.sequence)
            .limit(1)
        )
    ).first()
    if existing is not None:
        prior = existing.payload if isinstance(existing.payload, dict) else {}
        prior_ids = prior.get("alert_ids")
        prior_ids = list(prior_ids) if isinstance(prior_ids, list) else []
        prior_count = prior.get("acked")
        prior_count = prior_count if isinstance(prior_count, int) else len(prior_ids)
        # Reassigned, not mutated in place: SQLAlchemy's plain JSON column does
        # not track in-place edits, so an .append() here would commit nothing.
        existing.payload = {
            "acked": prior_count + len(ids),
            "alert_ids": (prior_ids + ids)[-_INHERITED_ACK_SAMPLE:],
            "rule_name": prior.get("rule_name") or rule_name or "",
            "first_at": prior.get("first_at") or prior.get("at") or now,
            "last_at": now,
        }
        await db.commit()
        return
    next_seq = (
        await db.scalar(
            select(func.coalesce(func.max(InvestigationEvent.sequence), 0) + 1).where(
                InvestigationEvent.investigation_id == source_id
            )
        )
    ) or 1
    db.add(
        InvestigationEvent(
            investigation_id=source_id,
            sequence=int(next_seq),
            kind=INHERITED_ACK_EVENT_KIND,
            payload={
                "acked": len(ids),
                "alert_ids": ids[-_INHERITED_ACK_SAMPLE:],
                "rule_name": rule_name or "",
                "first_at": now,
                "last_at": now,
            },
        )
    )
    await db.commit()


async def inherited_ack_total(db: AsyncSession, *, source_id: str | None = None) -> int:
    """Alerts acknowledged by verdict inheritance — all time, or for one source.

    Summed in SQL over the recorded fan-outs (``json_extract`` on the payload,
    the expression the fallback-provenance denormalization already uses) so the
    running total costs one query rather than a scan of every payload in Python.
    """
    stmt = select(
        func.coalesce(func.sum(func.json_extract(InvestigationEvent.payload, "$.acked")), 0)
    ).where(InvestigationEvent.kind == INHERITED_ACK_EVENT_KIND)
    if source_id is not None:
        stmt = stmt.where(InvestigationEvent.investigation_id == source_id)
    return int(await db.scalar(stmt) or 0)
