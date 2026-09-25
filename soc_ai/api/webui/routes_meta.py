"""Data sources, workspaces, notifications, current-user (/me) and /health endpoints."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_serializer
from sqlalchemy import select

from soc_ai import __version__
from soc_ai.api.data_sources import DataSourceOut, collect_data_sources
from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui import routes_hunts
from soc_ai.api.webui._shared import (
    _ago,
    _iso_utc,
    client_ip,
    open_router,
    require_admin_api,
    router,
)
from soc_ai.api.webui.kind_labels import kind_label
from soc_ai.bootstrap_credential import clear_bootstrap_credential
from soc_ai.config import Settings
from soc_ai.demo.guard import is_demo
from soc_ai.doctor import CheckResult, run_doctor
from soc_ai.store import auth as auth_svc
from soc_ai.store import host_dossier as dossier_svc
from soc_ai.store import hunts as hunts_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store import quality as quality_svc
from soc_ai.store import saved_views as views_svc
from soc_ai.webui import (
    probes,
)
from soc_ai.webui import (
    updates as updates_svc,
)
from soc_ai.webui.deps import current_user

_LOGGER = logging.getLogger(__name__)


class DataSourcesOut(BaseModel):
    sources: list[DataSourceOut]


@router.get(
    "/config/data-sources",
    response_model=DataSourcesOut,
    dependencies=[Depends(require_admin_api)],
)
async def get_data_sources(
    settings: Settings = Depends(get_settings_dep),
) -> DataSourcesOut:
    """Every enrichment data source — local feeds + opt-in online lookups — with
    freshness and key/enable status, for the config console's Data Sources panel."""
    return DataSourcesOut(sources=collect_data_sources(settings))


# ── Demo flag (open) ────────────────────────────────────────────────────────


class DemoStatusOut(BaseModel):
    demo: bool


@open_router.get("/demo-status", response_model=DemoStatusOut)
async def demo_status(settings: Settings = Depends(get_settings_dep)) -> DemoStatusOut:
    """Whether this deployment is the public demo (``SOC_AI_DEMO``).

    Deliberately on ``open_router`` (pre-auth): the SPA's honesty banner —
    rendered by both route roots (AppShell and the login screen) — must show on
    EVERY screen under ANY auth config, including before login. Boolean only;
    no secrets, no config.
    """
    return DemoStatusOut(demo=settings.soc_ai_demo)


# ── Shell chrome: workspaces + notifications ───────────────────────────────


class WorkspaceOut(BaseModel):
    name: str
    env: str


class NotificationOut(BaseModel):
    id: str
    tone: str
    title: str
    when: str
    href: str | None = None
    # Synth-eval marker (migration 0032): the bell displays investigation and
    # hunt rows, so a run against planted scenarios must carry its marker here
    # like on every other surface — "Verdict true_positive: <planted rule>"
    # with nothing beside it reads as real activity. Defaults False for the
    # entries minted from non-run state (dep outages, dossier conflicts).
    isSynthEval: bool = False
    # Whether the client may silence this entry. Defaults True: every standing
    # bell entry is client-dismissible on a stable id, and that is the whole
    # mechanism. False is for the one finding that must not be silenceable from
    # a browser's local storage: an audit record whose content no longer
    # matches its own hash, which "Clear all" would otherwise sweep away in a
    # click (see soc_ai.audit.verify.finding_is_dismissible).
    dismissible: bool = True
    # Which section of the Notifications screen this entry belongs to. The
    # screen grouped on the title text, so a lead and a shadow hit landed in
    # different sections and a renamed title moved an entry. "hunting" is the
    # leads and the shadow hits. Everything else is "system".
    group: str = "system"


@router.get("/workspaces", response_model=list[WorkspaceOut])
async def list_workspaces(settings: Settings = Depends(get_settings_dep)) -> list[WorkspaceOut]:
    host = str(settings.so_host or "Security Onion")
    name = host.replace("https://", "").replace("http://", "").rstrip("/") or "Security Onion"
    return [WorkspaceOut(name=name, env="prod")]


# How far back completed runs/hunts stay in the bell. Long enough to survive a
# shift handover, short enough that the panel is "what happened recently", not
# a history screen. Items are client-dismissible (stable ids → localStorage).
_NOTIF_WINDOW = timedelta(hours=24)

# Host-dossier conflicts shown at once. A standing disagreement is a slow,
# durable thing — the whole list is on the dossier conflicts screen, and the
# bell holds 12 items total, so a network-wide re-address must not push every
# investigation and hunt off it.
_DOSSIER_NOTIF_CAP = 3

# Failed triages shown at once. A gateway outage can fail dozens of runs in a
# window, and the bell holds 12 items total, so an outage must not be the whole
# panel. The Dashboard's pipeline-error tile carries the full standing count and
# the list behind it is the complete set; this is the "it is happening now"
# signal, not the ledger.
_FAILED_NOTIF_CAP = 3

# What to call the trouble, per probe classification (soc_ai.webui.probes). The
# bell said "unreachable" for every one of them, including a grid answering 429
# in the same second (dogfood 2026-08-14, D9). An unclassified failure keeps
# "unreachable" — it is the honest fallback when nothing more is known.
_DEP_TROUBLE = {
    "partial": "reading only part of the grid",
    "overloaded": "overloaded and shedding load",
    "timeout": "not answering",
    # Reachable but with no events index pattern configured: the connection is
    # fine and nothing can be read through it, which "unreachable" would
    # misdescribe and send the reader at the network.
    "unreadable": "reachable but not readable, with no events index pattern",
}


def _conflict_line(host: Any, field: Any) -> str:
    """One line naming the disagreement, in the operator's terms."""
    if field.conflict_kind == "rebound":
        detail = "a different machine may now hold this address"
    elif field.conflict_kind == "retracted":
        detail = "the evidence behind your value is gone"
    else:
        inferred = (field.inferred_value or "?")[:40]
        operator = (field.operator_value or "?")[:40]
        detail = f'telemetry says "{inferred}", yours says "{operator}"'
    return f"Dossier conflict on {host.ip}, {field.field}: {detail}"


def _audit_chain_notifications(request: Request) -> list[NotificationOut]:
    """A standing bell entry while the tamper-evident audit chain is broken.

    Read straight off the scheduled verification's in-memory alarm slot (see
    :func:`soc_ai.main._audit_verify_loop`) — this endpoint is polled every 15
    seconds and must never scan the audit index itself. The notification
    webhook is off by default, so on a stock install this is the ONLY path a
    tamper finding has to a human; that is why it is here and not only there.

    The id is the identity of the FINDING (see
    :func:`~soc_ai.audit.verify.finding_key`), so a dismissal holds for that
    finding and anything that breaks afterwards arrives undismissed. It used to
    be keyed on the moment of detection, which every run moves, so the entry
    could not be cleared at all: on the deployed instance that was an
    undismissable danger notification every day until a forked stretch of
    history aged out of the seven-day window. A finding that includes a record
    whose content no longer matches its own hash is not dismissible at any
    price (``dismissible=False``). See
    :func:`~soc_ai.audit.verify.finding_is_dismissible`.

    Clearing is still automatic as well: the loop empties the slot as soon as a
    verification comes back clean.
    """
    alarm = getattr(getattr(request.app.state, "_audit_verify_status", None), "alarm", None)
    if not isinstance(alarm, dict):
        return []
    detected = str(alarm.get("detected_at") or "")
    # Fall back to the detection stamp only for an alarm raised by an older
    # process that had no finding key; the entry is still shown either way.
    key = str(alarm.get("alarm_key") or detected)
    since = str(alarm.get("alarm_since") or detected)
    kind = str(alarm.get("break_kind") or "unknown")
    detail = str(
        alarm.get("blast_radius")
        or alarm.get("break_detail")
        or "the audit hash chain does not verify"
    )
    # Say WHEN this was measured and OVER WHAT. On the range the bell read four
    # duplicated positions while `soc-ai audit verify` reported six, and neither
    # surface said why: the scheduled check scans `audit_verify_days` (7 here)
    # and the CLI defaults to the whole retained chain, so they were answering
    # different questions with the same-shaped sentence. Both numbers were right.
    #
    # Two integrity surfaces disagreeing about the size of an integrity problem
    # is its own finding. The fix is not to pick one — it is to make each say
    # what it looked at, so an operator can see they are not in conflict.
    measured = _ago(detected) if detected else ""
    window = alarm.get("window_days")
    scope = f"the last {window} days" if isinstance(window, int) and window > 0 else ""
    covered = f" The check covered {scope}." if scope else ""
    if not measured:
        ran = ""
    elif measured == "now":
        ran = " The check ran just now."
    else:
        ran = f" The check ran {measured} ago."
    dated = f"{detail}{covered}{ran}"
    return [
        NotificationOut(
            id=f"audit-chain-break:{key}",
            tone="danger",
            title=f"Audit trail broken ({kind}): {dated}",
            when=_ago(since) if since else "just now",
            href="/config",
            dismissible=alarm.get("dismissible") is not False,
        )
    ]


async def _dossier_conflict_notifications(request: Request) -> list[NotificationOut]:
    """Bell entries for host-dossier prods the sweep has actually fired.

    This is the delivery half of the conflict state machine. Firing writes
    ``conflict_last_prompted_at`` / ``conflict_prompt_count`` inside the build's
    transaction, which burns the 14-day rate limit and escalates the "keep mine"
    backoff — so a prod with no surface is worse than no prod at all: the
    operator meets the question for the first time already snoozed toward the
    90-day cap.

    Gated on ``conflict_prompt_count`` rather than on the conflict being open,
    so the bell mirrors the rate-limited machine and not every disagreement (the
    full list lives on the dossier conflicts screen). The id carries the cycle
    counter: a client-side dismissal then holds for THIS prod and does not
    swallow the next one.

    DB-only and fail-soft, like everything else on this endpoint — it is polled
    every 15s and has to keep working when a part of the system is broken.
    """
    settings = getattr(request.app.state, "settings", None)
    if settings is None or not getattr(settings, "dossier_enabled", False):
        return []
    try:
        async with request.app.state.db_sessionmaker() as db:
            rows, _total = await dossier_svc.conflicts_due(
                db,
                min_observations=int(settings.dossier_conflict_min_observations),
                limit=_DOSSIER_NOTIF_CAP,
            )
    except Exception:
        _LOGGER.warning("notifications: dossier conflict read failed (continuing)", exc_info=True)
        return []

    out: list[NotificationOut] = []
    for host, field in rows:
        cycle = field.conflict_prompt_count or 0
        if not cycle:
            continue  # the machine has not raised this one yet
        raised = field.conflict_last_prompted_at or field.conflict_first_seen_at
        out.append(
            NotificationOut(
                id=f"dossier-conflict:{host.ip}:{field.field}:{cycle}",
                tone="warn",
                title=_conflict_line(host, field),
                when=_ago(raised.isoformat()) if raised is not None else "",
                href=f"/entity/{host.ip}",
            )
        )
    return out


# The bell id prefix the Quality card ALREADY mints for its own dismiss control
# (frontend/src/components/QualityCard.tsx::DISMISS_PREFIX). Reused verbatim, and
# with the same `<alarm_key>@<alarm_since>` body, so the card and the bell are two
# views of one finding and one dismissal silences both. Two prefixes would have
# meant clearing the same alarm twice, in two places, forever.
_QUALITY_ALARM_PREFIX = "quality-alarm:"

# The one alarm code that is NOT about verdict quality: the eval errored, so
# nothing was graded. Mirrors QualityCard's CODE_ERROR_CEILING — "the grader
# could not run" and "the verdicts got worse" need different responses from an
# operator, so they must not share a headline here either.
_CODE_ERROR_CEILING = "error_ceiling"


async def _quality_alarm_notifications(request: Request) -> list[NotificationOut]:
    """A standing bell entry while the nightly quality alarm is up.

    The alarm had two channels and neither reached a human on a stock install:
    an audit record, which nobody reads unprompted, and a webhook that is off by
    default and stays off on any deployment that has not opted into egress. That
    left the Quality card on the dashboard as the only surface where a verdict
    regression could be learned about — a card you have to already suspect
    something to go and look at. Every other standing condition in this product
    (dependency down, audit chain broken, dossier conflict) has a bell entry;
    this is the same class of fact and now has one too.

    Read from the newest snapshot only, because the alarm is a statement about
    the CURRENT state of the trend and an older alarmed point is history the card
    already plots. One indexed `ORDER BY id DESC LIMIT 1` — this endpoint is
    polled every 15 seconds by every open tab and must stay DB-fast.

    **The id is the identity of the CONDITION, not the moment it was noticed.**
    ``alarm_key`` (the sorted rule codes) says which condition, ``alarm_since``
    says which instance of it, and the writer holds ``alarm_since`` steady for as
    long as the condition persists. So a dismissal lasts exactly as long as the
    operator's judgement does: it survives every re-observation of the same
    condition, and a genuinely new alarm — a different code, or the same code
    raised again after a clean night — arrives undismissed. Keying on the run
    that observed it would produce an entry that cannot be cleared, which is the
    bug the audit-chain entry had and was fixed for.

    A pre-0027 row carries no key, so there is no identity to dismiss against and
    no entry is minted: an undismissable danger notification is worse than a
    quiet one, and the card still shows it.

    Fail-soft like every other read here — a broken store must not take the whole
    bell down with it.
    """
    try:
        async with request.app.state.db_sessionmaker() as db:
            rows = await quality_svc.recent_snapshots(db, limit=1)
    except Exception:
        _LOGGER.warning("notifications: quality alarm read failed (continuing)", exc_info=True)
        return []
    if not rows:
        return []
    latest = rows[0]
    if not latest.alarmed or not latest.alarm_key:
        return []

    codes = [c for c in str(latest.alarm_key).split("+") if c]
    pipeline_only = codes == [_CODE_ERROR_CEILING]
    if pipeline_only:
        # Naming it accurately matters more than the fright: an operator who
        # reads "verdict quality regressed" when the eval simply crashed goes
        # looking for a model problem that is not there.
        title = f"Nightly quality eval failing: {latest.n_error} of "
        title += f"{latest.n_ok + latest.n_error} runs errored. Nothing was graded."
        tone = "warn"
    else:
        title = f"Verdict quality alarm ({'+'.join(codes)})"
        # The detector's own first reason, which carries the live numbers the
        # codes cannot. Absent on a row written before the reasons were stored,
        # and the codes alone are still a usable sentence, so it is appended
        # rather than depended on.
        reasons = latest.alarm_reasons or []
        if reasons:
            title += f": {reasons[0]}"
        # Danger, matching the audit-chain entry: a regression in the verdicts
        # this product exists to produce is not an operational nuisance.
        tone = "danger"

    since = _iso_utc(latest.alarm_since) if latest.alarm_since else _iso_utc(latest.created_at)
    return [
        NotificationOut(
            id=f"{_QUALITY_ALARM_PREFIX}{latest.alarm_key}@{since}",
            tone=tone,
            title=title,
            when=_ago(since),
            href="/dashboard",
        )
    ]


# Shadow hits and leads shown in the bell at once. The panel scrolls and the
# Notifications screen holds the full list, so these caps only stop one noisy
# night from pushing every investigation and hunt off the panel.
_SHADOW_HIT_NOTIF_CAP = 20
_LEAD_NOTIF_CAP = 20


async def _shadow_hit_notifications(request: Request) -> list[NotificationOut]:
    """One bell entry per unread shadow hit.

    The unread flag is the transition gate: opening the receipts on Hunts sets
    ``read_at`` and the entry goes. The entry is not client-dismissible for the
    same reason the audit-chain entry is not. A shadow analytic that found a
    true positive and was cleared from a browser is the failure this layer
    exists to prevent.

    The rows are the ones ``GET /hunts/needs-you`` counts. The clause lives in
    one place, so the bell cannot announce a hit the hits surface hides. It
    announced a hit from a retired analytic, and the analyst could neither find
    the card nor read the row away.

    DB-only and fail-soft, like everything else on this endpoint. It is polled
    every 15 s and has to keep working when a part of the system is broken.
    """
    from soc_ai.api.webui.routes_analytics import (  # noqa: PLC0415 - lazy
        unread_shadow_hits_where,
    )
    from soc_ai.hunting.catalog_tiers import effective_catalog  # noqa: PLC0415 - lazy
    from soc_ai.store.models import EntityObservation  # noqa: PLC0415 - lazy

    try:
        async with request.app.state.db_sessionmaker() as db:
            cat = await effective_catalog(db)
            rows = (
                await db.scalars(
                    select(EntityObservation)
                    .where(*unread_shadow_hits_where(cat))
                    .order_by(EntityObservation.born_at.desc())
                    .limit(_SHADOW_HIT_NOTIF_CAP)
                )
            ).all()
    except Exception:
        _LOGGER.warning("notifications: shadow-hit read failed (continuing)", exc_info=True)
        return []

    out: list[NotificationOut] = []
    for observation in rows:
        spec = cat.listed.get(observation.spec_id)
        title = spec.title if spec is not None else observation.spec_id
        out.append(
            NotificationOut(
                id=f"shadow-hit:{observation.id}",
                tone="warn",
                title=f"Shadow hit: {title} on {observation.entity_key}",
                when=_ago(observation.born_at.replace(tzinfo=UTC).isoformat()),
                # The filter that holds the hit, not a bare anchor. The anchor
                # scrolled the block into view on filter All, where the card
                # the bell named was one of many.
                href="/hunts?hits=unread",
                dismissible=False,
                group="hunting",
            )
        )
    return out


async def _lead_notifications(request: Request) -> list[NotificationOut]:
    """One bell entry per lead formed in the window.

    The id carries the lead id, so a client-side dismissal holds for that lead
    and the bell announces one lead once. A shadow lead reads warn because it
    still needs a read. A shadow lead starts nothing by itself.
    """
    from soc_ai.store.models import Lead  # noqa: PLC0415 - lazy

    cutoff = auth_svc.utcnow() - _NOTIF_WINDOW
    try:
        async with request.app.state.db_sessionmaker() as db:
            rows = (
                await db.scalars(
                    select(Lead)
                    .where(Lead.formed_at >= cutoff, Lead.status.in_(("open", "hunting")))
                    .order_by(Lead.formed_at.desc())
                    .limit(_LEAD_NOTIF_CAP)
                )
            ).all()
    except Exception:
        _LOGGER.warning("notifications: lead read failed (continuing)", exc_info=True)
        return []

    out: list[NotificationOut] = []
    for lead in rows:
        entities = [
            str(entity[1])
            for entity in (lead.entities_json or [])
            if isinstance(entity, list | tuple) and len(entity) == 2
        ]
        kinds = ", ".join(kind_label(kind) for kind in (lead.kinds_json or []))
        out.append(
            NotificationOut(
                id=f"lead:{lead.id}",
                tone="warn" if lead.shadow else "accent",
                title=f"Lead {lead.id} formed on {', '.join(entities) or 'an entity'}: {kinds}",
                when=_ago(lead.formed_at.replace(tzinfo=UTC).isoformat()),
                href=f"/leads/{lead.id}",
                group="hunting",
            )
        )
    return out


@router.get("/notifications", response_model=list[NotificationOut])
async def list_notifications(request: Request) -> list[NotificationOut]:
    """In-flight runs + last-24h completions (investigations and hunts).

    The bell badge counts exactly this list — it must never advertise an item
    the panel can't show (the dogfood-2026-07-15 "badge=1, panel empty"
    phantom). Completions are durable, dismissible entries rather than
    transient in-flight state that vanishes between polls.
    """
    cutoff = auth_svc.utcnow() - _NOTIF_WINDOW
    out: list[NotificationOut] = []
    # Status notifications (dogfood 2026-08-05): a currently-down dependency is
    # a standing bell entry. Derived ONLY from the warm health cache + the
    # transition map _cached_health_probes maintains — this endpoint must stay
    # DB-fast and never probe ES itself (it is polled every 15s and must keep
    # working precisely when ES is down). Id is stable per outage (keyed on the
    # flip time) so a client-side dismissal holds for the outage's duration.
    _DEP_LABEL = {
        "es": "Security Onion / Elasticsearch",
        "llm": "LLM gateway",
        "so": "Security Onion API",
    }
    down_since = getattr(request.app.state, "_dep_down_since", None) or {}
    down_kind = getattr(request.app.state, "_dep_down_kind", None) or {}
    for dep, since in down_since.items():
        trouble = _DEP_TROUBLE.get(str(down_kind.get(dep) or ""), "unreachable")
        out.append(
            NotificationOut(
                id=f"dep-down:{dep}:{since.strftime('%Y%m%d%H%M%S')}",
                tone="danger",
                title=f"{_DEP_LABEL.get(dep, dep)} {trouble}. Investigations are degraded.",
                when=_ago(since.isoformat()),
                href=None,
            )
        )
    out.extend(_audit_chain_notifications(request))
    out.extend(await _quality_alarm_notifications(request))
    out.extend(await _dossier_conflict_notifications(request))
    out.extend(await _shadow_hit_notifications(request))
    out.extend(await _lead_notifications(request))
    # Column-scoped reads (never the report JSON blob): the bell reads ~5 scalar
    # fields from investigations and a denormalized findings_count from hunts, and
    # this endpoint is polled every 15s by every open tab. Both completed-runs
    # queries share ONE window definition — `finished_since` bounds and orders on
    # finished_at, the clock the bell renders — so a run created before the window
    # but finished inside it appears for investigations AND hunts alike.
    async with request.app.state.db_sessionmaker() as db:
        running = await inv_svc.list_recent_notifications(db, status="running", limit=20)
        completed = await inv_svc.list_recent_notifications(
            db, status="complete", limit=20, finished_since=cutoff
        )
        failed = await inv_svc.list_recent_notifications(
            db,
            status="error",
            limit=_FAILED_NOTIF_CAP,
            finished_since=cutoff,
            no_verdict=True,
            exclude_dismissed=True,
        )
        hunts_done = await hunts_svc.list_recent_notifications(
            db, status="complete", limit=10, finished_since=cutoff
        )
    # A triage that died goes with the standing entries, not the completions:
    # it is the same class of fact as a dependency being down, and putting it
    # behind a busy hour's verdicts is how it stays unseen. Ten weeks of these
    # accumulated on the deployed instance without one surface saying so.
    for inv in failed:
        stamp = inv.finished_at or inv.created_at
        out.append(
            NotificationOut(
                id=f"inv-failed:{inv.id}",
                tone="danger",
                title=f"Triage failed, no verdict: {inv.rule_name or inv.id}",
                when=_ago(stamp.isoformat()),
                href=f"/investigation/{inv.id}",
                isSynthEval=bool(inv.is_synth_eval),
            )
        )
    for inv in running:
        out.append(
            NotificationOut(
                id=f"inv:{inv.id}",
                tone="accent",
                title=f"Investigating: {inv.rule_name or inv.id}",
                when=_ago(inv.created_at.isoformat()),
                href=f"/investigation/{inv.id}",
                isSynthEval=bool(inv.is_synth_eval),
            )
        )
    done: list[NotificationOut] = []
    for inv in completed:
        fin = inv.finished_at
        if fin is None or fin < cutoff:
            continue
        verdict = inv.verdict or "untriaged"
        tone = (
            "danger"
            if verdict == "true_positive"
            else "warn"
            if verdict in ("needs_more_info", "inconclusive")
            else "accent"
        )
        done.append(
            NotificationOut(
                id=f"inv-done:{inv.id}",
                tone=tone,
                title=f"Verdict {verdict}: {inv.rule_name or inv.id}",
                when=_ago(fin.isoformat()),
                href=f"/investigation/{inv.id}",
                isSynthEval=bool(inv.is_synth_eval),
            )
        )
    for h in hunts_done:
        # Denormalized counts (migrations 0028, 0044) — no report blob here.
        n = h.findings_count or 0
        threats = h.threat_findings_count
        if n and threats == 0:
            # Every finding is a gap or an observation. "1 finding" over a
            # timed-out query was the most alarming line the app can print,
            # meaning nothing; the count is dropped because counting gaps as
            # findings is how it got there.
            # One phrase for this outcome, from routes_hunts. The list, the
            # bell and the hunt page must not each invent their own words.
            title = f"{routes_hunts.GAP_NOTIFICATION_TITLE}. {h.objective[:80]}"
            tone = "accent"
        else:
            shown = threats if threats is not None else n
            title = f"Hunt finished, {shown} finding{'' if shown == 1 else 's'}: {h.objective[:80]}"
            tone = "warn" if shown else "accent"
        done.append(
            NotificationOut(
                id=f"hunt-done:{h.id}",
                tone=tone,
                title=title,
                when=_ago((h.finished_at or h.created_at).isoformat()),
                href=f"/hunts/{h.id}",
                isSynthEval=bool(h.is_synth_eval),
            )
        )
    return (out + done)[:12]


# ── Scheduled maintenance (backup + blocklist cron visibility) ─────────────


class BackupArchiveOut(BaseModel):
    name: str
    size_bytes: int
    modified: str  # tz-aware ISO


class MaintenanceOut(BaseModel):
    backups: list[BackupArchiveOut]
    backups_dir: str
    blocklists_dir: str
    # Newest blocklist file's mtime — when the feeds were last refreshed.
    blocklists_refreshed: str | None = None
    blocklist_files: int = 0


_BACKUP_LIST_CAP = 8


def _scan_maintenance_dirs(settings: Settings) -> MaintenanceOut:
    """Stat the backup + blocklist dirs. **Blocking** — call via ``to_thread``.

    A glob with a per-entry ``stat()`` sort key, a second ``stat()`` per listed
    archive, and an ``iterdir()`` with ``is_file()``/``stat()`` per blocklist
    file are all synchronous pathlib syscalls. On slow or contended storage, or
    once the blocklist dir has grown to thousands of feed files, running them in
    the coroutine would block the loop — so the whole scan lives here and the
    handler offloads it, matching the repo's pcap-SSH and maxmind pattern.
    Missing dirs are a normal cold state, never a 500.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    def _iso(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=UTC).isoformat()

    backups_dir = settings.soc_ai_data_dir / "backups"
    archives: list[BackupArchiveOut] = []
    try:
        candidates = sorted(
            backups_dir.glob("soc-ai-backup-*.tar.gz"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for p in candidates[:_BACKUP_LIST_CAP]:
            st = p.stat()
            archives.append(
                BackupArchiveOut(name=p.name, size_bytes=st.st_size, modified=_iso(st.st_mtime))
            )
    except OSError:
        pass  # no backups yet — cold state, not an error

    newest: float | None = None
    n_files = 0
    try:
        for p in settings.blocklist_data_dir.iterdir():
            if not p.is_file():
                continue
            n_files += 1
            mt = p.stat().st_mtime
            newest = mt if newest is None or mt > newest else newest
    except OSError:
        pass

    return MaintenanceOut(
        backups=archives,
        backups_dir=str(backups_dir),
        blocklists_dir=str(settings.blocklist_data_dir),
        blocklists_refreshed=_iso(newest) if newest is not None else None,
        blocklist_files=n_files,
    )


@router.get(
    "/maintenance",
    response_model=MaintenanceOut,
    dependencies=[Depends(require_admin_api)],
)
async def get_maintenance(settings: Settings = Depends(get_settings_dep)) -> MaintenanceOut:
    """Observed maintenance facts for the Config panel.

    The nightly backup/blocklist crons run OUTSIDE the app (host crontab), so
    the product can't promise a schedule — it reports what actually happened:
    the archives sitting in ``<data_dir>/backups`` and the blocklist feeds'
    freshness. Automation the user can't see in the UI doesn't exist (user
    requirement, 2026-07-16). The filesystem scan is blocking, so it runs in a
    worker thread (:func:`_scan_maintenance_dirs`).
    """
    return await asyncio.to_thread(_scan_maintenance_dirs, settings)


# ── Current-user endpoints ────────────────────────────────────────────────


class MeOut(BaseModel):
    username: str
    role: str
    status: str
    # Whether a real user ROW is behind this request, which is a different
    # question from "did this request get through". A bearer token is
    # authenticated and has no user row; a deployment with the gate down has
    # neither. Both are the states where per-user features (saved views,
    # ownership as a way of telling analysts apart) cannot mean what they say,
    # and the SPA had no way to find out: it rendered a Save-view control that
    # 401s, or none at all, with nothing to tell an analyst which
    # (dogfood 2026-09-07, D3).
    signed_in: bool = False


class SetStatusIn(BaseModel):
    status: str = Field(default="", max_length=120)


# The identity an unauthenticated deployment answers with. The name is the one
# ``identify_caller`` already records on every write, and that agreement is the
# whole point: it used to say "analyst" while the store said "anonymous", so
# claiming an alert group grew an avatar and an owned chip while the Mine filter
# stayed at zero forever. Both names render "AN" as initials, so nothing on
# screen gave it away. The role stays admin because the admin surfaces genuinely
# ARE open when ``api_auth_required`` is off.
_DEV_ME = MeOut(username="anonymous", role="admin", status="", signed_in=False)


@router.get("/me", response_model=MeOut)
async def get_me(request: Request) -> MeOut:
    """Return the current user's username, role, status, and whether they are
    actually signed in.

    A session-cookie user reports their own identity. With no session:

    - ``api_auth_required`` False (dev / lab default): a stable fallback so the
      SPA always has a user to render, carrying the same name every write on
      this deployment is recorded under.
    - ``api_auth_required`` True: the caller reached here on a valid bearer token
      (``require_api_auth`` 401s otherwise, and it does NOT resolve a session),
      so report the TOKEN's identity — never the dev admin fallback, which would
      advertise an ``admin`` role the token cannot exercise.

    ``signed_in`` is true only in the first case. It is what lets a surface that
    needs a user row say so plainly instead of failing quietly.
    """
    user = await current_user(request)
    if user is not None:
        return MeOut(username=user.username, role=user.role, status=user.status, signed_in=True)
    settings = request.app.state.settings
    if not settings.api_auth_required:
        return _DEV_ME
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        async with request.app.state.db_sessionmaker() as db:
            token = await auth_svc.check_api_token(db, authz[7:].strip())
        if token is not None:
            return MeOut(username=f"token:{token.name}", role="token", status="", signed_in=False)
    raise HTTPException(status_code=401, detail={"reason": "no_session"})


@router.post("/me/status")
async def set_my_status(request: Request, body: SetStatusIn) -> dict[str, str | bool]:
    """Update the current user's status string (trim + cap at 64 chars).

    In dev mode with no session the request is a no-op that echoes back the
    (sanitised) status — nothing is persisted.
    """
    trimmed = body.status.strip()[:64]
    user = await current_user(request)
    if user is None:
        # No session (dev / no-auth mode, or a bearer-token caller with no user
        # row): nothing to persist, echo back. The CSRF layer already governs
        # who may POST here; this endpoint is also the suite's canonical
        # authenticated-POST probe, so it must stay a 200 for bearer callers.
        return {"ok": True, "status": trimmed}
    async with request.app.state.db_sessionmaker() as db:
        await auth_svc.set_user_status(db, user.id, trimmed)
    return {"ok": True, "status": trimmed}


class ChangePasswordIn(BaseModel):
    # Bounded like every other credential field (routes_auth.LoginIn,
    # routes_admin.CreateUserIn) so an unbounded string can't be buffered. The
    # real rules live in the handler: MIN_PASSWORD_LENGTH below, bcrypt's 72-byte
    # ceiling above (PasswordTooLongError → a clean 400), so everything inside
    # this bound gets the house error shape rather than a 422.
    #
    # Anything OUTSIDE the bound is a 422 from FastAPI's validation layer, whose
    # default body echoes the offending `input` — i.e. the plaintext password.
    # That is scrubbed app-wide in main.py's RequestValidationError handler.
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


@router.post("/me/password")
async def change_my_password(request: Request, body: ChangePasswordIn) -> dict[str, bool]:
    """Change the calling user's own password. Session auth, any role.

    Requires a real session user: this endpoint asks "prove you know the
    CURRENT password", which only means something for an account with a stored
    hash. A bearer-token caller (or the no-auth dev fallback) has no such
    account, so it gets a 401 rather than a confusing no-op — the deliberate
    contrast with ``/me/status``, which echoes for those callers.

    The current password is verified BEFORE the new one is validated: proving
    the credential is the authentication step, so a caller riding a borrowed
    cookie learns nothing about the password policy.

    Wrong guesses are throttled exactly as login's are. "Prove you know this
    password" is an online guessing oracle wherever it is offered, and this one
    sits behind a cookie an attacker may already have stolen — leaving it
    unthrottled would hand them the plaintext (and let them lock the analyst
    out) at thousands of attempts a minute. The lockout is checked BEFORE the
    bcrypt verify so a flood also can't pin the shared thread pool.
    """
    user = await current_user(request)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail={
                "reason": "no_session",
                "hint": "A password change requires a signed-in session.",
            },
        )
    settings = request.app.state.settings
    caller_ip = client_ip(request, settings)
    throttle = auth_svc.password_change_throttle  # NOT login's — see store.auth
    if throttle.is_locked(caller_ip, user.username):
        _LOGGER.warning(
            "password change locked out for user=%r from ip=%s (too many wrong "
            "current-password attempts)",
            user.username,
            caller_ip,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "too_many_attempts",
                "hint": "Too many incorrect attempts. Try again later.",
            },
        )
    if not await auth_svc.verify_password(body.current_password, user.password_hash):
        if throttle.record_failure(caller_ip, user.username):
            _LOGGER.warning(
                "password-change throttle engaged for user=%r from ip=%s",
                user.username,
                caller_ip,
            )
        raise HTTPException(
            status_code=400,
            detail={"reason": "bad_credentials", "hint": "Current password is incorrect."},
        )
    throttle.clear(caller_ip, user.username)
    if len(body.new_password) < auth_svc.MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "password_too_short",
                "hint": (
                    f"The password must be at least {auth_svc.MIN_PASSWORD_LENGTH} characters."
                ),
            },
        )
    async with request.app.state.db_sessionmaker() as db:
        try:
            await auth_svc.change_own_password(
                db,
                user.id,
                body.new_password,
                # Keep the tab the analyst is typing in signed in; drop the rest.
                keep_raw_token=request.cookies.get(auth_svc.SESSION_COOKIE),
            )
        except auth_svc.PasswordTooLongError as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "password_too_long",
                    "hint": "The password must be at most 72 bytes. That is the bcrypt limit.",
                },
            ) from exc
    # Only after the change actually landed: the startup log tells the operator
    # to change this password and delete the sidecar, so doing the second half
    # for them is what closes the loop. A no-op for every other account.
    clear_bootstrap_credential(settings, user.username)
    return {"ok": True}


# ── Saved list views ──────────────────────────────────────────────────────────


class SavedViewOut(BaseModel):
    id: int
    screen: str
    name: str
    query: dict[str, Any]
    created_at: str | None = None


class SavedViewListOut(BaseModel):
    rows: list[SavedViewOut]


class SaveViewIn(BaseModel):
    screen: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=views_svc.NAME_MAX)
    # The screen's own filter state, opaque here on purpose — see the model.
    query: dict[str, Any] = Field(default_factory=dict)


def _view_out(row: Any) -> SavedViewOut:
    return SavedViewOut(
        id=int(row.id),
        screen=str(row.screen),
        name=str(row.name),
        query=dict(row.query_json or {}),
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


async def _require_user(request: Request) -> Any:
    """The signed-in user, or a 401 in the house shape.

    A saved view belongs to a person, so there is no dev fallback here: a
    bearer-token caller and a no-auth dev session have no user row to own one.
    """
    user = await current_user(request)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail={
                "reason": "no_session",
                "hint": "Saved views belong to a signed-in user.",
            },
        )
    return user


@router.get("/me/views", response_model=SavedViewListOut)
async def list_my_views(request: Request, screen: str | None = None) -> SavedViewListOut:
    """This user's saved views, oldest first, optionally for one screen."""
    user = await _require_user(request)
    async with request.app.state.db_sessionmaker() as db:
        rows = await views_svc.list_views(db, user.id, screen=screen or None)
    return SavedViewListOut(rows=[_view_out(r) for r in rows])


@router.post("/me/views", response_model=SavedViewOut)
async def save_my_view(request: Request, body: SaveViewIn) -> SavedViewOut:
    """Save the current filter set under a name. Re-saving a name replaces it."""
    user = await _require_user(request)
    if body.screen not in views_svc.SAVED_VIEW_SCREENS:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "unknown_screen",
                "hint": f"expected one of: {', '.join(views_svc.SAVED_VIEW_SCREENS)}",
            },
        )
    name = body.name.strip()
    if not name:
        raise HTTPException(
            status_code=400,
            detail={"reason": "empty_name", "hint": "A view needs a name."},
        )
    try:
        views_svc.validate_query(body.query)
    except views_svc.QueryTooLargeError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": exc.reason, "hint": exc.hint}
        ) from exc
    async with request.app.state.db_sessionmaker() as db:
        try:
            row = await views_svc.upsert_view(
                db, user.id, screen=body.screen, name=name, query=body.query
            )
        except views_svc.TooManyViewsError as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "too_many_views",
                    "hint": (
                        f"You can keep {views_svc.MAX_VIEWS_PER_USER} saved views. "
                        "Delete one first."
                    ),
                },
            ) from exc
    return _view_out(row)


@router.delete("/me/views/{view_id}")
async def delete_my_view(request: Request, view_id: int) -> dict[str, bool]:
    """Delete one of this user's views.

    Someone else's id is a 404, not a 403: the row is scoped out of existence
    for this caller, so probing ids reveals nothing about another analyst.
    """
    user = await _require_user(request)
    async with request.app.state.db_sessionmaker() as db:
        gone = await views_svc.delete_view(db, user.id, view_id)
    if not gone:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    return {"ok": True}


# ── Upstream health (ES / LLM / PCAP) — drives the live status indicator ───────

_PCAP_PROBE_TTL_S = 300.0  # SSH is heavy; cache the PCAP probe between polls.
# ES + LLM probes are cheap HTTP, but the dashboard polls /health every ~30s and
# several tabs can poll at once — a short TTL keeps a burst of near-simultaneous
# polls from fanning out to the upstreams while still feeling live.
_HEALTH_PROBE_TTL_S = 15.0


class HealthComponentOut(BaseModel):
    ok: bool
    detail: str
    # WHICH failure, when ok is False: "partial", "overloaded", "timeout",
    # "refused" (see soc_ai.webui.probes). Every surface used to hardcode
    # "<dep> not reachable", so a grid answering 429 — up, replying, shedding
    # load — sent the analyst off to check firewalls (dogfood 2026-08-14, D9).
    kind: str = ""

    @model_serializer
    def _serialize(self) -> dict[str, Any]:
        """Carry ``kind`` only when the probe actually classified something.

        Presence then MEANS "this failure was identified", which is the contract
        the banner reads: a healthy component, an unclassified failure and a
        probe too old to classify are all indistinguishable on the wire, and all
        three correctly get the generic phrasing.
        """
        out: dict[str, Any] = {"ok": self.ok, "detail": self.detail}
        if self.kind:
            out["kind"] = self.kind
        return out


class HealthOut(BaseModel):
    es: HealthComponentOut
    llm: HealthComponentOut
    # The Security Onion web API. Not optional: it is the path every
    # acknowledge, escalate and case write travels, and the header pill it feeds
    # is the product's one always-on trust indicator. Leaving it out is what let
    # the pill say "connected" beside a card reporting a Security Onion timeout.
    so: HealthComponentOut
    pcap: HealthComponentOut | None = None  # only when pcap_enabled


async def _cached_pcap_probe(state: Any, settings: Settings) -> dict[str, Any]:
    """The pcap sensor probe result, TTL-cached (single-flight).

    Each probe is an ssh login to the sensor, bounded only by the ssh timeout,
    so concurrent polls against a cold cache must share ONE in-flight probe:
    result-only caching would fork one ssh child per dashboard tab, all pinned
    to a sensor that may already be the slow thing. The lock is separate from
    ``_health_probe_lock`` so a wedged sensor never holds up the ES/LLM/SO legs.
    """
    lock = getattr(state, "_pcap_probe_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        state._pcap_probe_lock = lock
    async with lock:
        now = time.monotonic()
        cached = getattr(state, "_pcap_probe_cache", None)
        if cached is not None and now - cached[0] < _PCAP_PROBE_TTL_S:
            return cached[1]  # type: ignore[no-any-return]
        result = await probes.probe_pcap(settings)
        state._pcap_probe_cache = (now, result)
        return result


# Hard bound on ONE health probe leg. Without it, probe_es rides the ES
# client's own timeout+retry stack (~90s worst case with a down grid) — which
# made /health, the very endpoint the UI's degraded-mode banner keys off, the
# slowest thing on the page during an outage (dogfood 2026-08-05).
_HEALTH_PROBE_LEG_TIMEOUT_S = 5.0


async def _bounded_probe(coro: Any, dep: str) -> dict[str, Any]:
    """One probe leg under the hard bound; a timeout IS the down verdict."""
    try:
        async with asyncio.timeout(_HEALTH_PROBE_LEG_TIMEOUT_S):
            return await coro  # type: ignore[no-any-return]
    except TimeoutError:
        return {
            "ok": False,
            "kind": "timeout",
            "detail": (
                f"the {dep} probe exceeded {_HEALTH_PROBE_LEG_TIMEOUT_S:.0f} s. "
                "soc-ai treats it as down."
            ),
        }


async def _cached_health_probes(state: Any, settings: Settings) -> dict[str, dict[str, Any]]:
    """The ES + LLM + Security Onion probe results, TTL-cached (single-flight).

    Both are cheap when healthy, but a 30s dashboard poll across several tabs
    would otherwise hit ES + the gateway every time; the short TTL collapses
    those into one probe per window. The LOCK matters as much as the TTL: with
    a down grid, N concurrent polls against a cold cache used to launch N
    parallel hanging probes (result-only caching has no single-flight), which
    ate the browser's connection budget exactly when the UI most needed
    /health to answer. Returns ``{"es": {...}, "llm": {...}, "so": {...}}``.

    The three legs run under one lock and one TTL on purpose: they feed a single
    indicator, so probing them on different clocks would let the pill's colour
    disagree with its own dropdown.
    """
    lock = getattr(state, "_health_probe_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        state._health_probe_lock = lock
    async with lock:
        now = time.monotonic()
        cached = getattr(state, "_health_probe_cache", None)
        if cached is not None and now - cached[0] < _HEALTH_PROBE_TTL_S:
            return cached[1]  # type: ignore[no-any-return]
        result = {
            "es": await _bounded_probe(probes.probe_es(state.elastic, settings), "elasticsearch"),
            "llm": await _bounded_probe(probes.probe_llm(settings), "llm gateway"),
            "so": await _bounded_probe(
                probes.probe_so_api(getattr(state, "auth", None), settings),
                "security onion api",
            ),
        }
        state._health_probe_cache = (now, result)
        _note_dep_transitions(state, result)
        return result


def _note_dep_transitions(state: Any, probed: dict[str, dict[str, Any]]) -> None:
    """Track when each dependency last flipped down, for status notifications.

    ``state._dep_down_since`` maps dep name -> naive-UTC datetime of the flip.
    Kept in process memory on purpose: a restart re-probes within one TTL and
    re-detects a still-down dep, and notification ids stay stable across polls
    within an outage (client-side dismissal keys on the id).

    ``state._dep_down_kind`` carries the CURRENT failure class beside it, so the
    bell can say which trouble this is. It is refreshed on every probe rather
    than pinned at the flip: a grid that starts refusing connections and comes
    back shedding load is one outage (same id, same dismissal) whose entry
    should stop saying "unreachable" the moment it is answering again.
    """
    down_since = getattr(state, "_dep_down_since", None)
    if down_since is None:
        down_since = {}
        state._dep_down_since = down_since
    down_kind = getattr(state, "_dep_down_kind", None)
    if down_kind is None:
        down_kind = {}
        state._dep_down_kind = down_kind
    for dep, res in probed.items():
        if res.get("ok"):
            down_since.pop(dep, None)
            down_kind.pop(dep, None)
            continue
        down_kind[dep] = str(res.get("kind") or "")
        if dep not in down_since:
            down_since[dep] = auth_svc.utcnow()


@router.get("/health", response_model=HealthOut)
async def health(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> HealthOut:
    """Live status of the upstreams the UI depends on. ES, the model gateway and
    the Security Onion web API are cheap HTTP probes (short-TTL cached); PCAP
    (heavy SSH) is cached longer. Secret-free."""
    probed = await _cached_health_probes(request.app.state, settings)
    out = HealthOut(
        es=HealthComponentOut(**probed["es"]),
        llm=HealthComponentOut(**probed["llm"]),
        so=HealthComponentOut(**probed["so"]),
    )
    if settings.pcap_enabled:
        out.pcap = HealthComponentOut(**await _cached_pcap_probe(request.app.state, settings))
    return out


# ── Preflight (cached doctor checks minus fitness) — Dashboard setup-health ─
#
# The Wave-1 `soc-ai doctor` checks, reachable from the app itself: a closed
# projection any authenticated caller may read (DossierSweepHealthOut
# precedent, routes_dossier.py), plus an admin-only row-level detail. Fitness
# (worst-case ~130s, _FITNESS_TIMEOUT_S) is excluded — run_doctor's slowest
# remaining check is upstream reachability at _REACH_TIMEOUT_S=15s, and the
# gather runs concurrently, so a cold-cache first hit costs at most ~15s. That
# is fine for a background poll (the Dashboard card polls every 5 minutes)
# and never acceptable for a page load, which is why it is TTL-cached below.

_PREFLIGHT_TTL_S = 600.0  # 10 minutes: the checks hit SO/ES/the gateway, and
# the FE polls every 5 minutes, so this amortizes to about one real doctor run
# per two poll cycles instead of one per poll.


class PreflightSummaryOut(BaseModel):
    """Closed preflight projection any authenticated caller may read.

    ``extra="forbid"`` so a refactor can't quietly widen this past the four
    fields the Dashboard card is allowed to see — row-level detail (names,
    hints) is admin-only, via :class:`PreflightDetailOut`.
    """

    model_config = ConfigDict(extra="forbid")

    status: Literal["green", "degraded"]
    failing: int
    warned: int
    checked_at: str


class PreflightRowOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    status: str
    detail: str
    hint: str = ""


class PreflightDetailOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rows: list[PreflightRowOut]
    checked_at: str


async def _cached_preflight(request: Request, *, refresh: bool) -> tuple[list[CheckResult], str]:
    """The doctor checks (minus fitness), TTL-cached on app state (single-flight).

    Mirrors :func:`_cached_health_probes` exactly, including why the LOCK
    matters as much as the TTL: without it, several concurrent pollers hitting
    a cold or just-expired cache would each launch their own full doctor
    gather (worst case ~15s apiece, hitting SO/ES/the gateway every time)
    instead of collapsing onto one run. ``refresh=True`` (the detail route's
    ``?refresh=true``) bypasses a fresh-enough cache on purpose, for an
    explicit "recheck now" action; either way the result is re-cached so the
    TTL clock restarts from the run that actually happened.
    """
    state: Any = request.app.state
    settings = get_settings_dep(request)

    # Third instance of the demo false-alarm class already hotfixed for
    # probe_llm (soc_ai/webui/probes.py:226-233) and probe_model_fitness
    # (soc_ai/webui/probes.py:828-841): every check that reaches an upstream
    # would hit the egress guard and FAIL unconditionally — demo mode —
    # replayed fixtures, no live upstreams; the egress guard's refusal is the
    # demo working as designed, not degradation. Short-circuit before the
    # lock/doctor with a synthetic green result, cached normally so the TTL
    # machinery stays uniform.
    if is_demo(settings):
        now = time.monotonic()
        checked_at = datetime.now(tz=UTC).isoformat()
        result: tuple[list[CheckResult], str] = ([], checked_at)
        # Never actually read back: every future call re-hits this same
        # is_demo branch and returns before reaching the cache read further
        # down. Written anyway only so `_preflight_cache` holds the same
        # (monotonic-time, result) shape whether or not the branch above ran.
        state._preflight_cache = (now, result)
        return result

    lock = getattr(state, "_preflight_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        state._preflight_lock = lock
    async with lock:
        now = time.monotonic()
        cached = getattr(state, "_preflight_cache", None)
        # Two concurrent ?refresh=true admins each pass the `not refresh` gate
        # and both re-run the doctor (serialized by the lock, not deduped) —
        # accepted: the route is admin-gated and the double-run is bounded by
        # however many admins click "recheck now" at once, not open to the
        # public.
        if not refresh and cached is not None and now - cached[0] < _PREFLIGHT_TTL_S:
            return cached[1]  # type: ignore[no-any-return]
        rows = await run_doctor(settings, include_fitness=False)
        checked_at = datetime.now(tz=UTC).isoformat()
        result = (rows, checked_at)
        state._preflight_cache = (now, result)
        return result


@router.get("/health/preflight", response_model=PreflightSummaryOut)
async def health_preflight(request: Request) -> PreflightSummaryOut:
    """Closed setup-health summary for any authenticated caller.

    Backs the Dashboard's persistent setup-health card. ``degraded`` iff any
    check FAILed; WARN rows are counted but never flip the status (the same
    exit_code semantics ``soc-ai doctor`` uses on the CLI). INFO rows are
    excluded from both counts.

    Latency: a cold cache runs the full doctor gather concurrently, so
    worst-case first-hit latency is ~``_REACH_TIMEOUT_S`` (15s) — the slowest
    check still included once fitness is excluded. That is fine for a
    background poll and never acceptable for a page load; the FE polls this
    every 5 minutes, and ``_PREFLIGHT_TTL_S`` (10 minutes) amortizes it to
    roughly one real doctor run per two poll cycles.
    """
    rows, checked_at = await _cached_preflight(request, refresh=False)
    graded = [r for r in rows if r.status in ("PASS", "WARN", "FAIL")]
    failing = sum(1 for r in graded if r.status == "FAIL")
    warned = sum(1 for r in graded if r.status == "WARN")
    return PreflightSummaryOut(
        status="degraded" if failing else "green",
        failing=failing,
        warned=warned,
        checked_at=checked_at,
    )


@router.get(
    "/health/preflight/detail",
    response_model=PreflightDetailOut,
    dependencies=[Depends(require_admin_api)],
)
async def health_preflight_detail(request: Request, refresh: bool = False) -> PreflightDetailOut:
    """Admin-only row-level detail behind the summary above.

    ``?refresh=true`` bypasses the TTL cache for an explicit "recheck now"
    action; otherwise it serves the same cached rows the summary reads.
    """
    rows, checked_at = await _cached_preflight(request, refresh=refresh)
    return PreflightDetailOut(
        rows=[
            PreflightRowOut(name=r.name, status=r.status, detail=r.detail, hint=r.hint)
            for r in rows
        ],
        checked_at=checked_at,
    )


class AboutOut(BaseModel):
    version: str
    repo_url: str
    license: str
    update_check_enabled: bool
    general_chat_enabled: bool
    sigma_authoring_enabled: bool


class UpdateCheckOut(BaseModel):
    enabled: bool
    ok: bool = False
    current_version: str
    latest_version: str | None = None
    update_available: bool = False
    detail: str


@router.get("/about", response_model=AboutOut)
async def about(settings: Settings = Depends(get_settings_dep)) -> AboutOut:
    """Static build metadata for the About panel and the sidebar version line.

    Readable by any authenticated user; reaches no upstream and carries no
    secret. Whether the update check is available is reported so the UI can show
    the button only when an admin has opted in.

    ``general_chat_enabled`` rides along for the same reason, one screen earlier:
    the Dashboard mounts before it has any other way to learn the feature is off,
    so without this flag a disabled deployment would render the Ask box and then
    fail the first request an analyst made — an error on the landing screen of a
    deployment that turned the feature off deliberately.

    ``sigma_authoring_enabled`` rides along the same way for the detection-bridge
    "Draft detection" affordance (Investigation / hunt-finding screens): off by
    default, so the SPA hides the button rather than rendering one whose first
    click is a guaranteed 403.
    """
    return AboutOut(
        version=__version__,
        repo_url=updates_svc.REPO_URL,
        license=updates_svc.LICENSE,
        update_check_enabled=settings.update_check_enabled,
        general_chat_enabled=settings.general_chat_enabled,
        sigma_authoring_enabled=settings.sigma_authoring_enabled,
    )


@router.post(
    "/updates/check",
    response_model=UpdateCheckOut,
    dependencies=[Depends(require_admin_api)],
)
async def check_updates(settings: Settings = Depends(get_settings_dep)) -> UpdateCheckOut:
    """Manually compare the running version against the latest GitHub release.

    Admin-only and opt-in: off by default (no network I/O), never raises, and
    sends nothing about the deployment. See :func:`soc_ai.webui.updates.check_for_update`.
    """
    result = await updates_svc.check_for_update(settings)
    return UpdateCheckOut(**result)
