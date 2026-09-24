"""Auto-triage: hunt alerts above a configurable severity floor, deduped by similarity.

One Target per uncovered cluster among groups at or above the configured
severity floor is queued for a sequential investigation run. A cluster is a
rule plus the subject it fired about: the two flow endpoints, or the machine
when there was no flow (see :func:`soc_ai.store.investigations.pair_key`).
Endpoint-shaped detections cluster rather than being dropped. Progress is
tracked in ``AutoTriageStatus`` on ``app.state``.

The severity floor is read from ``settings.auto_triage_min_severity`` (default
"high") and derived into a band by the API layer before being passed in.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from elasticsearch import ApiError

from soc_ai.api.deps import ctx_from_state
from soc_ai.api.runner import run_recorded
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.fields import get_dotted
from soc_ai.store import investigations as inv_svc
from soc_ai.webui import alerts_query as aq

_LOGGER = logging.getLogger(__name__)

# Fallback band used only when no severity band is passed explicitly (e.g. in
# tests that construct AutoTriageStatus directly without going through the API
# layer, which normally derives the band from settings.auto_triage_min_severity).
# Carries the unlabelled selector for the reason config_severity_band does.
_DEFAULT_SEVERITIES: tuple[str, ...] = ("critical", "high", aq.UNKNOWN_SEVERITY)

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
    # Every inherited-verdict ack ever written, read back from the store at the
    # end of the pass. The per-run counter above dies with the sweep, which is
    # how this path reached 110,693 writes to the analyst's grid without any
    # surface in the product being able to say so.
    inherited_acked_total: int = 0
    # Why inherited acks were held back this run (reason code -> count):
    # ``no_investigation`` (the source verdict retrieved nothing),
    # ``high_stakes``. Reset per run alongside ``inherited_acked``.
    inherited_refused: dict[str, int] = field(default_factory=dict)
    # per-reason breakdown of ``skipped`` for this run (reason code -> count).
    # Written by the planner (plan_targets / plan_targets_for_ids) so the polling
    # status can explain WHICH class of skip happened, not just a bare count.
    # The values always sum to ``skipped``. reset() leaves this alone — the
    # planner is its sole writer and runs before every reset in production.
    skipped_reasons: dict[str, int] = field(default_factory=dict)
    # What this run could NOT read off the grid — one short label per failed
    # query ("severity critical", "rule ET SCAN thing"). Written by the planner
    # on the same contract as ``skipped_reasons`` (sole writer, survives
    # reset()). Labels name the QUERY, never the exception text: a raw
    # elastic_transport error carries the grid's host:port and this field is
    # rendered in the console.
    #
    # A sweep that could not look must not report a drained queue: while this is
    # non-empty the dashboard tile says "degraded", not "0 investigated".
    grid_errors: list[str] = field(default_factory=list)
    # set by the stop endpoint; the worker checks it between targets and aborts.
    cancelled: bool = False
    # internal: keep a reference to the running task to prevent GC
    _task: asyncio.Task[None] | None = field(default=None, repr=False, compare=False)

    @property
    def degraded(self) -> bool:
        """True when part (or all) of this run's planning could not read the grid.

        The counters alone cannot express this: a sweep that read nothing and a
        sweep that found nothing both land total=0, failed=0.
        """
        return bool(self.grid_errors)

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
        self.inherited_refused = {}
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


def _stash_grid_errors(state: Any, labels: list[str]) -> None:
    """Record which grid queries this run could not read (same contract as
    :func:`_stash_skipped_reasons`: the planner is the sole writer, so a run that
    read the grid overwrites a previous run's marks with an empty list).

    One asymmetry with ``skipped_reasons``, and it is the whole point of this
    field: an empty list is a CLAIM about the grid, not a bookkeeping default.
    Only a planner that got an answer out of the grid may make it —
    :func:`plan_targets_for_ids` calls this with ``[]`` only when its one lookup
    came back, because a path that asked nothing has learned nothing.
    """
    get_status(state).grid_errors = list(labels)


def _bump(counts: dict[str, int], reason: str) -> None:
    """Increment a per-reason skip tally in place."""
    counts[reason] = counts.get(reason, 0) + 1


def _event_key(rule_name: str, ev: aq.AlertEvent) -> inv_svc.PairKey:
    """The store's inheritance key for one alert-queue event."""
    return inv_svc.pair_key(rule_name, ev.src_ip, ev.dst_ip, ev.subject_host)


def _cluster_events(
    rule_events: dict[str, list[aq.AlertEvent]],
) -> dict[inv_svc.PairKey, aq.AlertEvent]:
    """Cluster events by :func:`inv_svc.pair_key`, keeping the newest per cluster.

    A missing endpoint DEGRADES the key to ``""`` rather than dropping the
    event. Dropping is what this used to do — tallying the event under a
    ``"no_ip"`` skip — and it made the scheduled sweep network-flow-only: every
    endpoint/process-shaped detection (Sigma host rules carry no ``source.*`` /
    ``destination.*`` at all) was seen and discarded on every 5-minute sweep,
    forever. Prod bore that out — every no-IP investigation on record was
    started by a human, none by the scheduler.

    Degrading rather than abandoning the key preserves the dedupe the clustering
    exists for: all events of ONE rule on ONE subject collapse into ONE cluster,
    so a chatty host rule yields one investigation per sweep, not one per event.
    A per-event fallback key would have destroyed exactly that.

    The host is in the key only when both endpoints are empty, and the reason is
    in :func:`inv_svc.pair_key`: a flow seen by two sensors carries two
    ``host.name`` values and must not split, while a detection with no flow has
    no other subject at all. Until it did, two machines tripping one Sigma rule
    were one cluster and one verdict.

    The key shape is load-bearing beyond this dict: the keys are handed straight
    to the store's lookups (:func:`inv_svc.running_for_pairs`,
    :func:`inv_svc.latest_for_pairs`), which re-derive the same key from DB rows.
    """
    clusters: dict[inv_svc.PairKey, aq.AlertEvent] = {}
    for rule_name, events in rule_events.items():
        for ev in events:
            key = _event_key(rule_name, ev)
            if key not in clusters:
                # events are newest-first from fetch_group_events
                clusters[key] = ev
    return clusters


class _BlindSweep(Exception):
    """Internal: planning read NOTHING off the grid.

    Carries the real ES exception so the caller can re-raise it (the route needs
    it to tell a transport failure from an ES 4xx) plus the per-query labels for
    the degraded marker.
    """

    def __init__(self, cause: Exception, labels: list[str]) -> None:
        super().__init__("auto-triage planning could not read the grid")
        self.cause = cause
        self.labels = labels


def _is_query_class(exc: BaseException) -> bool:
    """True when the failure is about the QUERY, not about the grid's health.

    A filter the OQL parser refuses never reaches the grid, and one the grid
    itself answers 4xx to (a parsing_exception, a mapping conflict) was read and
    rejected — the grid is up either way. Both are deterministic: they fail
    identically for every severity and retrying will not help. Neither may be
    labelled into ``grid_errors``, or a bad filter on a perfectly healthy grid
    leaves the dashboard claiming an outage until the next sweep. A degraded
    mark that fires on operator error is a mark analysts learn to ignore — the
    same defect as the false all-clear, aimed the other way. These are re-raised
    unlabelled for the route to map to a 400.

    429 is the one 4xx that fails both halves of that test, and it is carved out
    here for the same reason ``routes_alerts._es_api_error_http`` carves it out:
    a saturated grid — search queue full, or an aggregation tripping the parent
    circuit breaker — answers 429 to a query that is perfectly well formed and
    that succeeds unchanged once the cluster recovers. Nothing about it is the
    operator's doing, so filing it by HTTP number accuses the analyst of a typo
    and, worse here than on the routes, keeps it out of ``grid_errors``: the
    sweep never ran, yet the tile records a finished batch that found nothing.

    Nor is it deterministic-and-unretryable the way its 4xx siblings are.
    ``ElasticClient`` sets ``retry_on_status=(429, 502, 503, 504)``, so a 429
    that reaches application code has ALREADY been retried ``es_max_retries``
    times and lost every time. That is sustained saturation rather than a blip,
    and it is what makes "the grid is degraded" the honest reading of this
    status rather than a guess.

    408 is carved out beside it, and more plainly still: a request-timeout status
    is a statement about the GRID, never about the query text. Nothing an analyst
    can type makes a search finish inside a proxy's patience, and RFC 9110 says
    outright that the client may repeat the request — the definition of
    retryable, and the opposite of the deterministic 4xx this function exists to
    let through. In practice it is a load balancer in front of Elasticsearch
    giving up under load: 429's story with a different number on it, and the harm
    of misfiling it is 429's harm too — the sweep read nothing, and the tile
    records a finished batch that found nothing.
    """
    if isinstance(exc, OqlValidationError):
        return True
    if isinstance(exc, ApiError):
        status = getattr(getattr(exc, "meta", None), "status", None)
        return status is not None and 400 <= status < 500 and status not in (408, 429)
    return False


async def _read_backlog(
    state: Any,
    *,
    time_range: str,
    oql: str | None,
    severities: tuple[str, ...],
) -> tuple[dict[str, list[aq.AlertEvent]], list[str]]:
    """Read the alert backlog: groups per severity, then events per group.

    Returns ``(rule_name -> events, labels of the queries that failed)``. A
    partial failure is survivable and returns what WAS readable; a total failure
    raises :class:`_BlindSweep`, because "we read nothing" and "there is nothing"
    are the same empty dict and must not be the same answer.
    """
    settings = state.settings
    elastic = state.elastic
    # Labels for the queries this run could not read (see AutoTriageStatus.grid_errors).
    grid_errors: list[str] = []
    last_error: Exception | None = None

    all_groups: list[aq.AlertGroup] = []
    severities_read = 0
    for severity in severities:
        try:
            page = await aq.fetch_groups(
                elastic, settings, time_range=time_range, severity=severity, oql=oql
            )
            all_groups.extend(page.groups)
            severities_read += 1
        except Exception as exc:
            if _is_query_class(exc):
                raise
            _LOGGER.exception("auto-triage: fetch_groups failed for severity=%s", severity)
            # These labels are shown to the operator, so the unlabelled read
            # names what it was reading. "severity unknown" would read as not
            # knowing which query failed.
            grid_errors.append(
                "alerts with no severity"
                if severity == aq.UNKNOWN_SEVERITY
                else f"severity {severity}"
            )
            last_error = exc

    if severities and severities_read == 0 and last_error is not None:
        raise _BlindSweep(last_error, grid_errors)
    if not all_groups:
        return {}, grid_errors

    # For each group, fetch up to 20 recent events.
    rule_events: dict[str, list[aq.AlertEvent]] = {}
    for group in all_groups:
        try:
            rule_events[group.rule_name] = await aq.fetch_group_events(
                elastic,
                settings,
                rule_name=group.rule_name,
                # A Zeek notice's name lives in notice.note, not rule.name; without
                # the group's own kind this defaults to "suricata" and a notice
                # group fetches ZERO events, so it is never queued nor counted as
                # skipped — it silently vanishes from the sweep.
                kind=group.kind,
                time_range=time_range,
                oql=oql,
                size=20,
            )
        except Exception as exc:
            if _is_query_class(exc):
                raise
            _LOGGER.exception("auto-triage: fetch_group_events failed for rule=%s", group.rule_name)
            grid_errors.append(f"rule {group.rule_name}")
            last_error = exc

    # Groups read fine but not one of their event fetches did: the cluster map
    # would come out empty and the sweep would report a clean zero for a backlog
    # it never saw. Same rule as the all-severities case above.
    if not rule_events and last_error is not None:
        raise _BlindSweep(last_error, grid_errors)
    return rule_events, grid_errors


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
    (src_ip, dst_ip); a missing endpoint degrades to ``""`` so endpoint-shaped
    detections are triageable at all (see :func:`_cluster_events`).

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
    the skip count (``{"already_triaged"|"running"|"inherited": n}``) is
    additionally stashed on the run's :class:`AutoTriageStatus` so the polling
    status can explain the skips without widening this tuple's signature.

    RAISES when NOTHING could be read — every severity's group query failed, or
    every group's event query did. A sweep that could not look must not return
    the empty tuple a genuinely quiet backlog returns: that is how a blind
    sensor was reported to the analyst as a drained queue, run after run, for
    the whole outage. A PARTIAL failure is different and does not raise: the
    readable severities are swept and the failures are stashed as
    ``status.grid_errors`` so the surface can say "degraded" while still doing
    the work a flaky grid still allows.
    """
    settings = state.settings

    try:
        rule_events, grid_errors = await _read_backlog(
            state, time_range=time_range, oql=oql, severities=severities
        )
    except _BlindSweep as blind:
        # Nothing readable at all. Stash the marks, then re-raise the REAL
        # exception so the route can tell a transport failure (503) from an ES
        # 4xx (400) — and so the scheduler's own catch lands a degraded status.
        _stash_skipped_reasons(state, {})
        _stash_grid_errors(state, blind.labels)
        raise blind.cause from None

    # Per-reason tally of ``skipped`` — surfaced on the status so the completion
    # note can say WHICH class of skip happened, not just a bare count.
    # Clustering itself no longer skips anything: every fetched event lands in a
    # cluster, so only the coverage checks below can add to this.
    skipped_reasons: dict[str, int] = {}
    clusters = _cluster_events(rule_events)

    if not clusters:
        _stash_skipped_reasons(state, skipped_reasons)
        _stash_grid_errors(state, grid_errors)
        return [], 0, []

    direct_hits, running_pairs, pair_hits = await _coverage_maps(state, clusters)

    targets: list[Target] = []
    inherited_acks: list[InheritedAck] = []
    for key, ev in clusters.items():
        rule_name, src_ip, dst_ip = key[0], key[1], key[2]
        # Skip only if this event's investigation is in-flight or settled; an
        # errored/cancelled run stays re-huntable (see blocks_rehunt).
        direct = direct_hits.get(ev.es_id)
        if direct is not None and inv_svc.blocks_rehunt(direct):
            _bump(skipped_reasons, "already_triaged")
            continue
        # Skip if the cluster is being investigated RIGHT NOW — the running
        # run's verdict will cover it via inheritance when it completes.
        if key in running_pairs:
            _bump(skipped_reasons, "running")
            continue
        # Skip if the cluster has a verdict in the window. A qualifying
        # inherited FP additionally queues the cluster's events for
        # acknowledgement — the verdict alone never reached SO. A key that
        # names no subject never appears here: the store refuses to hand a
        # verdict along it (see inv_svc.latest_for_pairs).
        inherited = pair_hits.get(key)
        if inherited is not None:
            _bump(skipped_reasons, "inherited")
            inherited_acks.extend(
                _inherited_ack_candidates(settings, inherited, rule_events.get(rule_name, []), key)
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
    _stash_grid_errors(state, grid_errors)
    return targets, sum(skipped_reasons.values()), inherited_acks


async def _coverage_maps(
    state: Any,
    clusters: dict[inv_svc.PairKey, aq.AlertEvent],
) -> tuple[dict[str, Any], set[inv_svc.PairKey], dict[inv_svc.PairKey, Any]]:
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
    key: inv_svc.PairKey,
) -> list[InheritedAck]:
    """The cluster's events as ack candidates, when the inherited verdict
    qualifies (empty list otherwise).

    Membership is re-derived through :func:`_event_key` rather than compared
    field by field, so an event joins the ack fan-out on exactly the terms that
    put it in the cluster. Spelling the comparison out separately is how the
    host dimension would go missing here and acks would spill onto the machines
    the verdict was never about.
    """
    if not _qualifies_for_inherited_ack(settings, inherited):
        return []
    rule_name = key[0]
    return [
        InheritedAck(
            alert_es_id=e.es_id,
            rule_name=inherited.rule_name or "",
            inherited_from=inherited.id,
            confidence=inherited.confidence or 0.0,
        )
        for e in events
        if _event_key(rule_name, e) == key
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
        # No query goes out, so this run learned nothing about the grid. See the
        # _stash_grid_errors call at the end for why silence is not written down
        # as health.
        _stash_skipped_reasons(state, {})
        return [], 0

    async with state.db_sessionmaker() as db:
        direct_hits = await inv_svc.latest_for_alerts(db, ids)

    # Resolve rule names for the whole selection in ONE ES lookup so each row is
    # named at creation — a selected-id run that dies before its first
    # alert_context event must not leave a nameless "Alert <id>…" row. Best-effort:
    # an ES failure here just leaves names blank and the recorder backfills from
    # the stream (the prior behaviour). It is also the only thing this path asks
    # the grid, hence the second return value — see below.
    id_to_rule, grid_answered = await _resolve_rule_names(state, ids)

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
    # An explicit selection reads no group/event queries, so it can never be
    # blind in the plan_targets sense. That is NOT a reason to clear a standing
    # mark: an empty grid_errors does not say "this run was not blind", it says
    # "the grid is readable", and clearing it unconditionally asserted that on a
    # path that never asked. Mid-outage the two clicks are adjacent — a refused
    # sweep lands the mark, the analyst ticks rows on the (stale) alerts list and
    # hits Bulk Investigate, and the tile drops the degraded note and reports a
    # tidy "Last batch · N investigated" while every search is still answering
    # 429. Same false all-clear as D4, laundered through a second click.
    #
    # The rule-name lookup above is the one real question this path puts to the
    # grid, so it is the only thing that can answer it. A reply clears the mark
    # (recovery must be able to clear it, or a note nothing retires is a note
    # analysts stop reading); a refusal or an unasked question leaves the last
    # run's finding standing, because neither is evidence of health.
    _stash_skipped_reasons(state, skipped_reasons)
    if grid_answered:
        _stash_grid_errors(state, [])
    return targets, skipped


async def _resolve_rule_names(state: Any, ids: list[str]) -> tuple[dict[str, str], bool]:
    """Batch-resolve ``alert_es_id -> rule.name`` for a selection in one ES query.

    Falls back to ``event.dataset`` / ``event.category`` for non-Suricata
    detections (no ``rule.name``). Never raises — on any ES error returns an empty
    map so callers degrade to stream-backfill rather than failing the sweep.

    Returns ``(names, the grid answered)``. The flag is not about the names: an
    empty map is the same value whether the grid replied with no matching docs or
    refused the query outright, and :func:`plan_targets_for_ids` has to tell those
    apart to know whether it may retire a standing degraded mark.
    """
    if not ids:
        return {}, False
    try:
        lookup = await state.elastic.search(
            state.settings.events_index_pattern,
            {"ids": {"values": ids}},
            size=len(ids),
        )
    except Exception:
        _LOGGER.exception("auto-triage: rule-name resolution lookup failed")
        return {}, False
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
    return resolved, True


async def _grounded_inheritance_sources(state: Any, source_ids: list[str]) -> set[str]:
    """Which of *source_ids* reached their verdict by retrieving something.

    Same bar the direct auto-ack applies to its own run — a successful tool
    call, a Phase-D targeted dispatch that returned discriminating data, or a
    tool call in the Oracle's own loop — asked of the recorded events instead of
    a live message history (see
    :func:`soc_ai.agent.evidence.recorded_run_retrieved_evidence`).

    FAILS CLOSED. On a store error this returns the empty set, so every
    candidate is refused: "the database did not answer" is not permission to
    write to the analyst's grid, and the alerts stay in the queue for the next
    sweep or a human.
    """
    from soc_ai.agent.evidence import recorded_run_retrieved_evidence  # noqa: PLC0415

    if not source_ids:
        return set()
    try:
        async with state.db_sessionmaker() as db:
            by_source = await inv_svc.retrieval_events_for(db, source_ids)
    except Exception:
        _LOGGER.exception(
            "auto-triage: could not read the inheritance sources' evidence — refusing %d "
            "inherited acks this sweep",
            len(source_ids),
        )
        return set()
    return {sid for sid in source_ids if recorded_run_retrieved_evidence(by_source.get(sid, []))}


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

    The evidence bar the direct path got on 2026-09-05 applies here too, and
    this is where it matters most. Measured on the deployed instance: 110,693
    grid writes came out of this function against 2,768 from the direct path,
    and 16 percent of them inherited a verdict from an investigation that had
    made no successful tool call, no targeted dispatch and no Oracle retrieval.
    One uninvestigated false positive fans out to a mean of 145 acknowledgements
    on the analyst's own grid, and the largest single one reached 790. A verdict
    nothing was retrieved for is not a verdict to lend.

    Two records come out of every write. ``auto_ack_inherited`` in the audit
    trail carries ``inherited_from``, so an ack can be walked back to the
    reasoning that authorized it (``execute_write_tool``'s own records name the
    alert and the user, and nothing else). An ``inherited_ack`` event on the
    SOURCE investigation carries the running total, because a counter on the
    sweep's status object dies with the sweep and this fan-out does not.
    """
    # Heavy import at call time, mirroring the runner's own orchestrator import.
    from soc_ai.agent.orchestrator import _is_high_stakes_alert  # noqa: PLC0415
    from soc_ai.so_client.models import SoAlert  # noqa: PLC0415
    from soc_ai.tools.write_exec import execute_write_tool  # noqa: PLC0415

    if not acks:
        return
    grounded = await _grounded_inheritance_sources(
        state, list(dict.fromkeys(a.inherited_from for a in acks))
    )
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
    written: dict[str, list[str]] = {}
    rule_of: dict[str, str] = {}
    for cand in acks:
        if status.cancelled:
            break
        hit = hits_by_id.get(cand.alert_es_id)
        if hit is None:
            continue
        if get_dotted(hit.get("_source", {}), "event.acknowledged"):
            continue  # already acked (a human, or a previous sweep)
        if cand.inherited_from not in grounded:
            # The verdict is not being overturned — it still reads as a
            # confident false positive on the console. It just stops
            # authorizing writes to Security Onion that nobody looked at.
            _bump(status.inherited_refused, "no_investigation")
            _LOGGER.info(
                "auto-triage: not acking %s — the inherited verdict (from %s) had no "
                "successful tool call, targeted dispatch or Oracle retrieval behind it",
                cand.alert_es_id,
                cand.inherited_from,
            )
            continue
        try:
            alert = SoAlert.from_es_hit(hit)
        except Exception:
            _LOGGER.warning("auto-triage: unparseable alert %s — not acking", cand.alert_es_id)
            continue
        if _is_high_stakes_alert(alert):
            _bump(status.inherited_refused, "high_stakes")
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
            written.setdefault(cand.inherited_from, []).append(cand.alert_es_id)
            rule_of.setdefault(cand.inherited_from, cand.rule_name)
            _LOGGER.info(
                "auto-triage: acked inherited FP %s (rule=%s, conf=%.2f, from %s)",
                cand.alert_es_id,
                cand.rule_name,
                cand.confidence,
                cand.inherited_from,
            )
        await _record_inherited_ack_provenance(ctx, cand, ok=not error)
    await _persist_inherited_acks(state, status, written, rule_of)


async def _record_inherited_ack_provenance(ctx: Any, cand: InheritedAck, *, ok: bool) -> None:
    """Audit the ack with the investigation whose verdict authorized it.

    Best-effort and never raises: ``execute_write_tool`` has already written the
    fail-closed intent record, so a lost provenance line must not turn a
    completed SO write into an exception that aborts the rest of the sweep.
    """
    audit = getattr(ctx, "audit", None)
    if audit is None:
        return
    try:
        await audit.log_kind(
            f"auto-ack-inherited:{cand.alert_es_id}",
            "auto_ack_inherited",
            {
                "alert_id": cand.alert_es_id,
                "inherited_from": cand.inherited_from,
                "rule_name": cand.rule_name,
                "confidence": cand.confidence,
                "ok": ok,
            },
            user="auto-ack:inherited",
            approved_by="auto-ack:inherited",
        )
    except Exception:
        _LOGGER.warning(
            "auto-triage: inherited-ack provenance record failed for %s", cand.alert_es_id
        )


async def _persist_inherited_acks(
    state: Any,
    status: AutoTriageStatus,
    written: dict[str, list[str]],
    rule_of: dict[str, str],
) -> None:
    """Land this sweep's fan-out on the source investigations and refresh the total."""
    if not written:
        return
    try:
        async with state.db_sessionmaker() as db:
            for source_id, alert_ids in written.items():
                await inv_svc.record_inherited_acks(
                    db, source_id=source_id, alert_ids=alert_ids, rule_name=rule_of.get(source_id)
                )
            status.inherited_acked_total = await inv_svc.inherited_ack_total(db)
    except Exception:
        _LOGGER.exception("auto-triage: could not record the inherited-ack fan-out")


# Headroom the outer per-target cap keeps over the inner whole-run backstop, so
# the inner one always wins the race and lands a diagnosable error. Proportional
# rather than a fixed number of seconds so the invariant holds at any scale — a
# test (or a fast-model deployment) can dial BOTH bounds down together and still
# get a tight sweep, which a fixed additive floor would make impossible.
_PER_TARGET_HEADROOM_RATIO = 1.25


def _effective_per_target_timeout(settings: Any) -> float:
    """Per-target wall-clock cap, floored above the inner whole-run backstop.

    Two nested guards bound an auto-triage investigation, and they are NOT
    equivalent on expiry:

    - INNER, ``recorded_run``'s ``investigation_run_timeout_s``: finalizes the
      row *and* records an ``error`` event with type/phase/hint, so the run shows
      up in the pipeline-error drilldown with a reason.
    - OUTER, this cap: cancels the event generator from the consumer side. The
      recorder's ``CancelledError`` branch lands ``status='error'`` but the
      generator never gets to emit an error event — a silent, undiagnosable row.

    So the outer cap must only ever fire for a stream the inner backstop could
    not stop at all. Clamping here (rather than trusting the setting) keeps that
    invariant even when an operator lowers the knob or an old config_overrides
    row carries the pre-2026-08-03 default of 600, which was TIGHTER than the
    inner 900s backstop and silently ate 49 of 64 error rows in 14 days.
    """
    configured = float(getattr(settings, "auto_triage_per_target_timeout_s", 1200))
    inner = float(getattr(settings, "investigation_run_timeout_s", 900))
    return max(configured, inner * _PER_TARGET_HEADROOM_RATIO)


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
        per_target_timeout = _effective_per_target_timeout(state.settings)

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
            # Fresh per-target context. InvestigationContext carries per-run tool
            # state (default_time_anchor, dedup, prefetched community ids) that the
            # orchestrator only resets on the investigation-loop path — a target
            # that finalizes on round 1 and takes the Phase-D path would otherwise
            # inherit the PREVIOUS target's default_time_anchor and fetch PCAP
            # centred on the wrong alert's timestamp. ctx_from_state only rebinds
            # the shared app.state clients, so this is cheap.
            ctx = ctx_from_state(state)
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
    first), plus the alerts that carry no severity label — the SCOPE of a
    config-floor sweep. Falls back to high if unset.

    The unlabelled selector rides along at EVERY floor, including "critical". A
    floor is a comparison, and there is nothing to compare an absent label
    against; the only two options are to sweep those alerts or to drop them
    without saying so, and dropping them is what made this band unreachable.
    Measured in-process on the deployed host on 2026-09-06: over 24 hours the
    critical, high, medium and low queries each returned 0 groups, and the
    documents with no label returned 3 groups over 40 events, which was the
    entire queue. They were 37 Elastic Defend endpoint alerts and 3 OpenCanary
    honeypot hits, neither of which is low-priority merely because the shipper
    omitted a field.

    Appended rather than mixed in, so the ladder part of the band is unchanged
    in both content and order and a labelled alert is planned exactly as before.
    """
    ladder = list(aq.SEVERITIES)  # ("critical", "high", "medium", "low")
    floor = getattr(settings, "auto_triage_min_severity", "high")
    idx = ladder.index(floor) if floor in ladder else ladder.index("high")
    return (*ladder[: idx + 1], aq.UNKNOWN_SEVERITY)


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
        _LOGGER.exception("auto-triage: scheduled planning failed")
        # The scheduler must not die, so the exception stops here — which makes
        # the persisted status the ONLY place a blind cycle can show up.
        #
        # A failed GRID READ lands as a finished, DEGRADED run (plan_targets
        # stashed the grid_errors before raising): the tile says "could not read
        # the grid" for the whole outage instead of the previous cycle's clean
        # numbers. Any OTHER failure (an app-side crash after the backlog was
        # read, say) has no such mark, so writing a finished zero here would
        # print a brand-new, freshly-timestamped "Last batch · 0 investigated"
        # over a cycle that crashed — trading one false all-clear for another.
        # For that class, only the single-flight slot is released; the last real
        # batch stands as the last thing that actually happened. (A mark left by
        # an earlier blind cycle also lands in the first branch — erring toward
        # "degraded" is the safe direction here; erring toward "clean" is the
        # entire defect this batch exists to fix.)
        if status.grid_errors:
            status.reset(active=False, total=0, skipped=0, severities=band)
            status.finished_at = datetime.now(UTC).isoformat()
        else:
            status.active = False
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
