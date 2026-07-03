"""Auto-triage: hunt alerts above a configurable severity floor, deduped by similarity.

One Target per uncovered (rule, src_ip, dst_ip) cluster among groups at or
above the configured severity floor is queued for a sequential investigation
run.  Progress is tracked in ``AutoTriageStatus`` on ``app.state``.

The severity floor is read from ``settings.auto_triage_min_severity`` (default
"high") and derived into a band by the API layer before being passed in.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from soc_ai.api.deps import ctx_from_state
from soc_ai.api.runner import run_recorded
from soc_ai.so_client.fields import get_dotted
from soc_ai.store import investigations as inv_svc
from soc_ai.webui import alerts_query as aq

_LOGGER = logging.getLogger(__name__)

# Fallback band used only when no severity band is passed explicitly (e.g. in
# tests that construct AutoTriageStatus directly without going through the API
# layer, which normally derives the band from settings.auto_triage_min_severity).
_DEFAULT_SEVERITIES: tuple[str, ...] = ("critical", "high")

_STATE_ATTR = "_autotriage_status"


@dataclass
class Target:
    """One investigation target: the newest event in an uncovered cluster."""

    alert_es_id: str
    rule_name: str
    src_ip: str
    dst_ip: str


@dataclass
class AutoTriageStatus:
    active: bool = False
    total: int = 0
    hunted: int = 0
    skipped: int = 0
    failed: int = 0
    finished_at: str | None = None
    # severities this run operates on (shown in the status chip)
    severities: tuple[str, ...] = _DEFAULT_SEVERITIES
    # live progress: rule name (or alert id) currently being investigated
    current: str | None = None
    # cumulative tool calls fired across the run so far
    tool_calls: int = 0
    # set by the stop endpoint; the worker checks it between targets and aborts.
    cancelled: bool = False
    # internal: keep a reference to the running task to prevent GC
    _task: asyncio.Task[None] | None = field(default=None, repr=False, compare=False)

    def reset(
        self,
        *,
        active: bool,
        total: int,
        skipped: int,
        severities: tuple[str, ...] = _DEFAULT_SEVERITIES,
    ) -> None:
        self.active = active
        self.total = total
        self.hunted = 0
        self.skipped = skipped
        self.failed = 0
        self.finished_at = None
        self.severities = severities
        self.current = None
        self.tool_calls = 0
        self.cancelled = False


def request_stop(state: Any) -> bool:
    """Signal an in-flight auto-triage run to stop after the current target.

    Returns True if a run was active (so the caller can report it). The worker
    loop checks ``status.cancelled`` between targets; the task reference is left
    to finish its current investigation cleanly rather than hard-cancelled.
    """
    status = get_status(state)
    if not status.active:
        return False
    status.cancelled = True
    return True


def get_status(state: Any) -> AutoTriageStatus:
    """Lazily attach an :class:`AutoTriageStatus` to *app.state* and return it."""
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, AutoTriageStatus())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


async def plan_targets(
    state: Any,
    *,
    time_range: str,
    oql: str | None,
    severities: tuple[str, ...] = _DEFAULT_SEVERITIES,
) -> tuple[list[Target], int]:
    """Plan investigation targets for the auto-triage run.

    For each severity in *severities*, fetch the grouped-by-rule view,
    then flat-fetch up to 20 recent events per group.  Cluster events by
    (src_ip, dst_ip); events missing either IP are skipped (counted but not
    queued) because unkeyable clusters cannot dedupe future events.

    Drop clusters whose (rule, src_ip, dst_ip) already has:
    - a direct verdict on any clustered event id (latest_for_alerts) — this
      check is status-agnostic (any verdict, including running), whereas
    - a pair verdict within the inherit-window (latest_for_pairs) — this
      check is complete-only, so in-flight runs don't suppress new targets.

    Returns (targets, skipped_count).
    """
    settings = state.settings
    elastic = state.elastic

    # Collect all groups across the chosen severities
    all_groups: list[aq.AlertGroup] = []
    for severity in severities:
        try:
            groups, _ = await aq.fetch_groups(
                elastic,
                settings,
                time_range=time_range,
                severity=severity,
                oql=oql,
            )
            all_groups.extend(groups)
        except Exception:
            _LOGGER.exception("auto-triage: fetch_groups failed for severity=%s", severity)

    if not all_groups:
        return [], 0

    # For each group, fetch up to 20 recent events
    # Build: rule_name -> list[AlertEvent]
    rule_events: dict[str, list[aq.AlertEvent]] = {}
    for group in all_groups:
        try:
            events = await aq.fetch_group_events(
                elastic,
                settings,
                rule_name=group.rule_name,
                time_range=time_range,
                oql=oql,
                size=20,
            )
            rule_events[group.rule_name] = events
        except Exception:
            _LOGGER.exception("auto-triage: fetch_group_events failed for rule=%s", group.rule_name)

    skipped = 0
    # Cluster events by (rule_name, src_ip, dst_ip)
    # Key: (rule_name, src_ip, dst_ip) -> newest AlertEvent in that cluster
    clusters: dict[tuple[str, str, str], aq.AlertEvent] = {}

    for rule_name, events in rule_events.items():
        for ev in events:
            if ev.src_ip is None or ev.dst_ip is None:
                # Can't dedupe: count as skipped (no target produced)
                skipped += 1
                continue
            key = (rule_name, ev.src_ip, ev.dst_ip)
            if key not in clusters:
                # events are newest-first from fetch_group_events
                clusters[key] = ev

    if not clusters:
        return [], skipped

    # Gather all event ids in clusters for direct-verdict check
    all_event_ids = [ev.es_id for ev in clusters.values()]

    # Gather all pairs for windowed-pair check
    all_pairs = list(clusters.keys())

    # Inheritance: skip a (rule, src, dst) cluster that already has a verdict in
    # the window — it inherits that sibling's verdict instead of being re-triaged.
    # This is what keeps a continuous sweep tenable. Toggleable: with inheritance
    # off, every cluster is investigated (no pair-skip).
    inherit_on = getattr(settings, "auto_triage_inheritance_enabled", True)
    async with state.db_sessionmaker() as db:
        direct_hits = await inv_svc.latest_for_alerts(db, all_event_ids)
        pair_hits = (
            await inv_svc.latest_for_pairs(
                db, all_pairs, window_days=settings.webui_inherit_window_days
            )
            if inherit_on
            else {}
        )

    targets: list[Target] = []
    for (rule_name, src_ip, dst_ip), ev in clusters.items():
        # Skip only if this event's investigation is in-flight or settled; an
        # errored/cancelled run stays re-huntable (see blocks_rehunt).
        direct = direct_hits.get(ev.es_id)
        if direct is not None and inv_svc.blocks_rehunt(direct):
            skipped += 1
            continue
        # Skip if (rule, src, dst) pair has a verdict in the window
        if (rule_name, src_ip, dst_ip) in pair_hits:
            skipped += 1
            continue
        targets.append(
            Target(
                alert_es_id=ev.es_id,
                rule_name=rule_name,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )
        )

    # Safety cap: bound a single run so one click can't spawn dozens of hunts.
    # Overflow targets have no verdict yet, so the next run picks them up.
    max_targets = getattr(settings, "auto_triage_max_targets", 0)
    if max_targets and len(targets) > max_targets:
        _LOGGER.info(
            "auto-triage: capping %d planned targets to %d (auto_triage_max_targets)",
            len(targets),
            max_targets,
        )
        targets = targets[:max_targets]

    return targets, skipped


async def plan_targets_for_ids(
    state: Any,
    *,
    alert_ids: list[str],
) -> tuple[list[Target], int]:
    """Plan targets from an explicit operator selection of alert ES ids.

    Unlike :func:`plan_targets`, this does no severity/range planning and
    applies no max-targets cap — the operator picked these alerts on purpose.
    Ids that already carry a verdict (complete *or* running) are skipped so a
    click never re-runs work that is already done or in-flight.  Order is
    preserved and duplicates collapse.  Returns ``(targets, skipped_count)``.
    """
    # De-dupe while preserving the operator's order; drop blanks.
    seen: set[str] = set()
    ids: list[str] = []
    for aid in alert_ids:
        if aid and aid not in seen:
            seen.add(aid)
            ids.append(aid)
    if not ids:
        return [], 0

    async with state.db_sessionmaker() as db:
        direct_hits = await inv_svc.latest_for_alerts(db, ids)

    # Resolve rule names for the whole selection in ONE ES lookup so each row is
    # named at creation — a selected-id run that dies before its first
    # alert_context event must not leave a nameless "Alert <id>…" row. Best-effort:
    # an ES failure here just leaves names blank and the recorder backfills from
    # the stream (the prior behaviour).
    id_to_rule = await _resolve_rule_names(state, ids)

    targets: list[Target] = []
    skipped = 0
    for aid in ids:
        # Skip only settled/in-flight runs; errored/cancelled stay re-huntable.
        direct = direct_hits.get(aid)
        if direct is not None and inv_svc.blocks_rehunt(direct):
            skipped += 1
            continue
        # src/dst are only used by plan_targets() clustering; the worker resolves
        # those from alert_es_id. rule_name is seeded so the row is named at birth.
        targets.append(
            Target(alert_es_id=aid, rule_name=id_to_rule.get(aid, ""), src_ip="", dst_ip="")
        )
    return targets, skipped


async def _resolve_rule_names(state: Any, ids: list[str]) -> dict[str, str]:
    """Batch-resolve ``alert_es_id -> rule.name`` for a selection in one ES query.

    Falls back to ``event.dataset`` / ``event.category`` for non-Suricata
    detections (no ``rule.name``). Never raises — on any ES error returns an empty
    map so callers degrade to stream-backfill rather than failing the sweep.
    """
    if not ids:
        return {}
    try:
        lookup = await state.elastic.search(
            state.settings.events_index_pattern,
            {"ids": {"values": ids}},
            size=len(ids),
        )
    except Exception:
        _LOGGER.exception("auto-triage: rule-name resolution lookup failed")
        return {}
    resolved: dict[str, str] = {}
    for hit in lookup.hits:
        aid = hit.get("_id", "")
        source = hit.get("_source", {})
        name = (
            get_dotted(source, "rule.name")
            or get_dotted(source, "event.dataset")
            or get_dotted(source, "event.category")
        )
        if aid and name:
            resolved[aid] = str(name)
    return resolved


async def run_auto_triage(
    state: Any,
    *,
    targets: list[Target],
    started_by: str,
) -> None:
    """Sequential worker: hunt each target, update status, never raise.

    Drains ``run_recorded`` per target.  Failures are logged and counted;
    they never abort the remaining targets.  Sets ``active=False`` and
    ``finished_at`` when done.
    """
    status = get_status(state)
    try:
        ctx = ctx_from_state(state)
        per_target_timeout = getattr(state.settings, "auto_triage_per_target_timeout_s", 600)

        for i, target in enumerate(targets):
            if status.cancelled:  # stop requested — abort before the next target
                _LOGGER.info("auto-triage: stop requested, aborting after %d targets", i)
                break
            label = target.rule_name if target.rule_name else target.alert_es_id
            status.current = label
            try:
                stream_errored = False
                # Hold the generator so we can guarantee it is closed if the
                # wall-clock backstop fires mid-stream — a hung LLM read would
                # otherwise leak the coroutine and stall the whole sweep.
                stream = run_recorded(
                    state,
                    ctx=ctx,
                    alert_id=target.alert_es_id,
                    started_by=started_by,
                    # Group sweeps know the rule name up front; selected-id runs
                    # carry "" and fall back to stream-extraction.
                    rule_name=target.rule_name or None,
                )
                try:
                    async with asyncio.timeout(per_target_timeout):
                        async for name, _data in stream:
                            if name == "error":
                                stream_errored = True
                            elif name == "tool_call":
                                status.tool_calls += 1
                finally:
                    # run_recorded is an async generator at runtime; aclose()
                    # cancels a mid-stream read cleanly on timeout. It is typed
                    # as AsyncIterator (no aclose in that protocol), so reach the
                    # method defensively.
                    aclose = getattr(stream, "aclose", None)
                    if aclose is not None:
                        await aclose()
                if stream_errored:
                    _LOGGER.warning("auto-triage: stream error for alert_id=%s", target.alert_es_id)
                    status.failed += 1
                else:
                    status.hunted += 1
            except TimeoutError:
                _LOGGER.warning(
                    "auto-triage: target timed out after %ss, alert_id=%s — moving to next target",
                    per_target_timeout,
                    target.alert_es_id,
                )
                status.failed += 1
            except Exception:
                _LOGGER.exception(
                    "auto-triage: investigation failed for alert_id=%s", target.alert_es_id
                )
                status.failed += 1
            finally:
                status.current = None
    finally:
        status.active = False
        status.finished_at = datetime.now(UTC).isoformat()


def config_severity_band(settings: Any) -> tuple[str, ...]:
    """The severity band at/above ``settings.auto_triage_min_severity`` (critical
    first) — the SCOPE of a config-floor sweep. Falls back to high if unset."""
    ladder = list(aq.SEVERITIES)  # ("critical", "high", "medium", "low")
    floor = getattr(settings, "auto_triage_min_severity", "high")
    idx = ladder.index(floor) if floor in ladder else ladder.index("high")
    return tuple(ladder[: idx + 1])


async def start_config_sweep(state: Any, *, started_by: str) -> int:
    """Plan + launch a config-floor auto-triage sweep (single-flight). Never raises.

    Sweeps every untriaged detection at/above ``auto_triage_min_severity`` and
    launches a background :func:`run_auto_triage`. Returns the number of targets
    launched, or 0 if a sweep is already running / there is nothing to triage.
    Used by the continuous scheduler loop; mirrors the ⚡ endpoint's config-band
    path.
    """
    status = get_status(state)
    if status.active:
        return 0
    band = config_severity_band(state.settings)
    status.active = True  # claim the single-flight slot before any await
    try:
        targets, skipped = await plan_targets(
            state, time_range=aq.DEFAULT_RANGE, oql=None, severities=band
        )
    except Exception:
        status.active = False
        _LOGGER.exception("auto-triage: scheduled planning failed")
        return 0
    if not targets:
        status.reset(active=False, total=0, skipped=skipped, severities=band)
        status.finished_at = datetime.now(UTC).isoformat()
        return 0
    status.reset(active=True, total=len(targets), skipped=skipped, severities=band)
    status._task = asyncio.create_task(
        run_auto_triage(state, targets=targets, started_by=started_by)
    )
    return len(targets)
