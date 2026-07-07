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
class InheritedAck:
    """An alert skipped by verdict inheritance whose inherited verdict qualifies
    for auto-ack.

    Inheritance used to be display-only: the sweep skipped the cluster and the
    UI showed the inherited FP verdict, but nothing ever acknowledged the alert
    in Security Onion — inherited FPs lingered unacked forever. When
    ``auto_ack_fp_enabled`` is on, the worker acks these (same confidence
    threshold + high-stakes guard as a direct auto-ack)."""

    alert_es_id: str
    rule_name: str
    inherited_from: str  # investigation id the verdict was inherited from
    confidence: float


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
    # inherited-verdict FP alerts this run acknowledged in SO (auto_ack_fp_enabled)
    inherited_acked: int = 0
    # per-reason breakdown of ``skipped`` for this run (reason code -> count).
    # Written by the planner (plan_targets / plan_targets_for_ids) so the polling
    # status can explain WHICH class of skip happened, not just a bare count.
    # The values always sum to ``skipped``. reset() leaves this alone — the
    # planner is its sole writer and runs before every reset in production.
    skipped_reasons: dict[str, int] = field(default_factory=dict)
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
        self.inherited_acked = 0
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


def _stash_skipped_reasons(state: Any, reasons: dict[str, int]) -> None:
    """Record the planner's per-reason skip breakdown on the run's status.

    Written by the planner before it returns (and before the caller's
    ``status.reset(...)``, which deliberately leaves this field alone). The
    planner is the sole writer, so it always overwrites any prior run's tally —
    a fresh run with no skips lands an empty dict, never stale reasons.
    """
    get_status(state).skipped_reasons = dict(reasons)


def _bump(counts: dict[str, int], reason: str) -> None:
    """Increment a per-reason skip tally in place."""
    counts[reason] = counts.get(reason, 0) + 1


def _cluster_events(
    rule_events: dict[str, list[aq.AlertEvent]],
) -> tuple[dict[tuple[str, str, str], aq.AlertEvent], dict[str, int]]:
    """Cluster events by (rule, src_ip, dst_ip), keeping the newest per cluster.

    Events missing either IP can't be keyed/deduped, so they are dropped and
    tallied under ``"no_ip"``. Returns ``(clusters, skipped_reasons)`` where
    ``skipped_reasons`` seeds the run's per-reason skip breakdown.
    """
    clusters: dict[tuple[str, str, str], aq.AlertEvent] = {}
    skipped_reasons: dict[str, int] = {}
    for rule_name, events in rule_events.items():
        for ev in events:
            if ev.src_ip is None or ev.dst_ip is None:
                _bump(skipped_reasons, "no_ip")
                continue
            key = (rule_name, ev.src_ip, ev.dst_ip)
            if key not in clusters:
                # events are newest-first from fetch_group_events
                clusters[key] = ev
    return clusters, skipped_reasons


async def plan_targets(
    state: Any,
    *,
    time_range: str,
    oql: str | None,
    severities: tuple[str, ...] = _DEFAULT_SEVERITIES,
) -> tuple[list[Target], int, list[InheritedAck]]:
    """Plan investigation targets for the auto-triage run.

    For each severity in *severities*, fetch the grouped-by-rule view,
    then flat-fetch up to 20 recent events per group.  Cluster events by
    (src_ip, dst_ip); events missing either IP are skipped (counted but not
    queued) because unkeyable clusters cannot dedupe future events.

    Drop clusters whose (rule, src_ip, dst_ip) already has:
    - a direct verdict on any clustered event id (latest_for_alerts) — this
      check is status-agnostic (any verdict, including running);
    - an IN-FLIGHT run on the pair (running_for_pairs) — without this, a
      newer event id in the cluster launched a duplicate investigation of a
      pair whose first run was still executing (same alert triaged twice
      minutes apart);
    - a pair verdict within the inherit-window (latest_for_pairs) — the
      inheritance skip. When the inherited verdict is a qualifying FP and
      ``auto_ack_fp_enabled`` is on, the cluster's events are emitted as
      :class:`InheritedAck` candidates for the worker to acknowledge in SO
      (inheritance used to leave them unacked forever).

    Returns (targets, skipped_count, inherited_acks). A per-reason breakdown of
    the skip count (``{"no_ip"|"already_triaged"|"running"|"inherited": n}``) is
    additionally stashed on the run's :class:`AutoTriageStatus` so the polling
    status can explain the skips without widening this tuple's signature.
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
        _stash_skipped_reasons(state, {})
        return [], 0, []

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

    # Per-reason tally of ``skipped`` — surfaced on the status so the completion
    # note can say WHICH class of skip happened, not just a bare count. Events
    # missing an IP can't be clustered/deduped, so they are skipped up front.
    clusters, skipped_reasons = _cluster_events(rule_events)

    if not clusters:
        _stash_skipped_reasons(state, skipped_reasons)
        return [], sum(skipped_reasons.values()), []

    direct_hits, running_pairs, pair_hits = await _coverage_maps(state, clusters)

    targets: list[Target] = []
    inherited_acks: list[InheritedAck] = []
    for (rule_name, src_ip, dst_ip), ev in clusters.items():
        # Skip only if this event's investigation is in-flight or settled; an
        # errored/cancelled run stays re-huntable (see blocks_rehunt).
        direct = direct_hits.get(ev.es_id)
        if direct is not None and inv_svc.blocks_rehunt(direct):
            _bump(skipped_reasons, "already_triaged")
            continue
        # Skip if the pair is being investigated RIGHT NOW — the running run's
        # verdict will cover this cluster via inheritance when it completes.
        if (rule_name, src_ip, dst_ip) in running_pairs:
            _bump(skipped_reasons, "running")
            continue
        # Skip if (rule, src, dst) pair has a verdict in the window. A
        # qualifying inherited FP additionally queues the cluster's events for
        # acknowledgement — the verdict alone never reached SO.
        inherited = pair_hits.get((rule_name, src_ip, dst_ip))
        if inherited is not None:
            _bump(skipped_reasons, "inherited")
            inherited_acks.extend(
                _inherited_ack_candidates(
                    settings, inherited, rule_events.get(rule_name, []), src_ip, dst_ip
                )
            )
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

    _stash_skipped_reasons(state, skipped_reasons)
    return targets, sum(skipped_reasons.values()), inherited_acks


async def _coverage_maps(
    state: Any,
    clusters: dict[tuple[str, str, str], aq.AlertEvent],
) -> tuple[dict[str, Any], set[tuple[str, str, str]], dict[tuple[str, str, str], Any]]:
    """The three existing-coverage lookups for the planned clusters.

    - direct verdicts on the clustered event ids (status-agnostic);
    - pairs with an IN-FLIGHT run (unconditional — duplicate concurrent work
      is waste regardless of the inheritance setting);
    - pair verdicts within the inherit-window. Inheritance keeps a continuous
      sweep tenable: a covered cluster inherits its sibling's verdict instead
      of being re-triaged. Toggleable — with inheritance off the map is empty
      and every cluster is investigated.
    """
    settings = state.settings
    all_event_ids = [ev.es_id for ev in clusters.values()]
    all_pairs = list(clusters.keys())
    inherit_on = getattr(settings, "auto_triage_inheritance_enabled", True)
    async with state.db_sessionmaker() as db:
        direct_hits = await inv_svc.latest_for_alerts(db, all_event_ids)
        running_pairs = await inv_svc.running_for_pairs(db, all_pairs)
        pair_hits = (
            await inv_svc.latest_for_pairs(
                db, all_pairs, window_days=settings.webui_inherit_window_days
            )
            if inherit_on
            else {}
        )
    return direct_hits, running_pairs, pair_hits


def _qualifies_for_inherited_ack(settings: Any, inv: Any) -> bool:
    """Same bar as a direct auto-ack (minus the high-stakes gate, which needs
    the alert doc and is applied by the worker per event)."""
    return bool(
        getattr(settings, "auto_ack_fp_enabled", False)
        and inv.verdict == "false_positive"
        and (inv.confidence or 0.0) >= getattr(settings, "auto_ack_fp_threshold", 0.7)
    )


def _inherited_ack_candidates(
    settings: Any,
    inherited: Any,
    events: list[aq.AlertEvent],
    src_ip: str,
    dst_ip: str,
) -> list[InheritedAck]:
    """The cluster's events as ack candidates, when the inherited verdict
    qualifies (empty list otherwise)."""
    if not _qualifies_for_inherited_ack(settings, inherited):
        return []
    return [
        InheritedAck(
            alert_es_id=e.es_id,
            rule_name=inherited.rule_name or "",
            inherited_from=inherited.id,
            confidence=inherited.confidence or 0.0,
        )
        for e in events
        if e.src_ip == src_ip and e.dst_ip == dst_ip
    ]


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
    preserved and duplicates collapse.  Returns ``(targets, skipped_count)``; a
    per-reason breakdown (``{"already_triaged": n}``) is stashed on the run's
    :class:`AutoTriageStatus` (see :func:`plan_targets`).
    """
    # De-dupe while preserving the operator's order; drop blanks.
    seen: set[str] = set()
    ids: list[str] = []
    for aid in alert_ids:
        if aid and aid not in seen:
            seen.add(aid)
            ids.append(aid)
    if not ids:
        _stash_skipped_reasons(state, {})
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
    skipped_reasons: dict[str, int] = {}
    for aid in ids:
        # Skip only settled/in-flight runs; errored/cancelled stay re-huntable.
        direct = direct_hits.get(aid)
        if direct is not None and inv_svc.blocks_rehunt(direct):
            skipped += 1
            _bump(skipped_reasons, "already_triaged")
            continue
        # src/dst are only used by plan_targets() clustering; the worker resolves
        # those from alert_es_id. rule_name is seeded so the row is named at birth.
        targets.append(
            Target(alert_es_id=aid, rule_name=id_to_rule.get(aid, ""), src_ip="", dst_ip="")
        )
    _stash_skipped_reasons(state, skipped_reasons)
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


async def _ack_inherited_fps(
    state: Any,
    ctx: Any,
    acks: list[InheritedAck],
    status: AutoTriageStatus,
) -> None:
    """Acknowledge inherited-FP alerts in SO. Best-effort; never raises.

    One batched ES lookup fetches every candidate's doc; each is then gated:
    already-acked events are skipped (idempotent across sweeps — the feed the
    planner reads does not hide acked events), and the same high-stakes guard
    as a direct auto-ack applies per event (a critical/high or malware/exploit
    class alert is never auto-acked, even off an inherited verdict). The write
    goes through :func:`execute_write_tool` so it is audited like every other
    unattended ack.
    """
    # Heavy import at call time, mirroring the runner's own orchestrator import.
    from soc_ai.agent.orchestrator import _is_high_stakes_alert  # noqa: PLC0415
    from soc_ai.so_client.models import SoAlert  # noqa: PLC0415
    from soc_ai.tools.write_exec import execute_write_tool  # noqa: PLC0415

    if not acks:
        return
    try:
        lookup = await state.elastic.search(
            state.settings.events_index_pattern,
            {"ids": {"values": [a.alert_es_id for a in acks]}},
            size=len(acks),
        )
    except Exception:
        _LOGGER.exception("auto-triage: inherited-ack lookup failed — skipping inherited acks")
        return
    hits_by_id = {h.get("_id"): h for h in lookup.hits}
    for cand in acks:
        if status.cancelled:
            break
        hit = hits_by_id.get(cand.alert_es_id)
        if hit is None:
            continue
        if get_dotted(hit.get("_source", {}), "event.acknowledged"):
            continue  # already acked (a human, or a previous sweep)
        try:
            alert = SoAlert.from_es_hit(hit)
        except Exception:
            _LOGGER.warning("auto-triage: unparseable alert %s — not acking", cand.alert_es_id)
            continue
        if _is_high_stakes_alert(alert):
            continue
        _result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": cand.alert_es_id},
            auth=ctx.auth,
            settings=ctx.settings,
            audit=ctx.audit,
            session_id=f"auto-ack-inherited:{cand.alert_es_id}",
            user="auto-ack:inherited",
        )
        if error:
            _LOGGER.warning(
                "auto-triage: inherited-FP ack failed for %s (verdict from %s): %s",
                cand.alert_es_id,
                cand.inherited_from,
                error,
            )
        else:
            status.inherited_acked += 1
            _LOGGER.info(
                "auto-triage: acked inherited FP %s (rule=%s, conf=%.2f, from %s)",
                cand.alert_es_id,
                cand.rule_name,
                cand.confidence,
                cand.inherited_from,
            )


async def run_auto_triage(
    state: Any,
    *,
    targets: list[Target],
    started_by: str,
    inherited_acks: list[InheritedAck] | None = None,
) -> None:
    """Sequential worker: hunt each target, update status, never raise.

    Drains ``run_recorded`` per target.  Failures are logged and counted;
    they never abort the remaining targets.  Sets ``active=False`` and
    ``finished_at`` when done. Inherited-FP ack candidates (see
    :class:`InheritedAck`) are processed first — they need no LLM.
    """
    status = get_status(state)
    try:
        ctx = ctx_from_state(state)
        per_target_timeout = getattr(state.settings, "auto_triage_per_target_timeout_s", 600)

        try:
            await _ack_inherited_fps(state, ctx, inherited_acks or [], status)
        except Exception:
            _LOGGER.exception("auto-triage: inherited-ack pass failed")

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
        targets, skipped, inherited_acks = await plan_targets(
            state, time_range=aq.DEFAULT_RANGE, oql=None, severities=band
        )
    except Exception:
        status.active = False
        _LOGGER.exception("auto-triage: scheduled planning failed")
        return 0
    if not targets and not inherited_acks:
        status.reset(active=False, total=0, skipped=skipped, severities=band)
        status.finished_at = datetime.now(UTC).isoformat()
        return 0
    # An all-inherited sweep (0 targets, N acks) still runs the worker — the
    # ack pass is exactly how a standing FP backlog drains without LLM calls.
    status.reset(active=True, total=len(targets), skipped=skipped, severities=band)
    status._task = asyncio.create_task(
        run_auto_triage(
            state, targets=targets, started_by=started_by, inherited_acks=inherited_acks
        )
    )
    return len(targets)
