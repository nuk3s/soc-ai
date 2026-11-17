"""Shared nightly quality-eval runner.

One implementation behind three triggers: the ``soc-ai eval-nightly`` CLI
(host cron), the Config-console "Run now" endpoint, and the in-app schedule
loop (``eval_nightly_enabled``). Extracted from the CLI's inlined ``_go()``
closure so the app can run the eval in-process — the nightly used to be
schedulable only from host cron (user requirement 2026-07-16: schedulable
from the UI).

The micro-eval: investigate ``quality_nightly_n`` real alerts at concurrency 1
through the existing batch machinery, aggregate, land ONE row in
``quality_snapshots`` (pruned to the newest 90), and alarm (audit event +
opt-in webhook) when the point regresses against its own trailing same-mode
history.

Beside the real alerts each batch plants ``quality_nightly_synth_n`` synthetic
true positives (:func:`pick_nightly_scenarios`), because real alerts carry no
ground truth. The batch runner has taken scenarios since the catalogue landed
and this module never passed it one: 113 production batches held 539 rows and
not one of them was planted, so the trend measured no recall. The planted runs
are scored against their own ground truth and are never sent to the Oracle.

Every alarmed point is RECORDED, but only a new condition is REPORTED —
see :func:`_record_trend_point` for why those are different questions.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from soc_ai.eval.synth_loader import Scenario

# Exit codes shared with the CLI (documented in `soc-ai eval-nightly --help`):
# 0 ok · 2 no eligible alerts (no snapshot) · 4 aborted-but-written · 5 error.
EXIT_OK = 0
EXIT_NO_ALERTS = 2
EXIT_ABORTED = 4
EXIT_ERROR = 5

# Bundle directory for callers that don't name one (the in-app scheduler and
# the Config-console "Run now" — i.e. every unattended container run).
#
# It is a SIBLING OF THE DATA DIR rather than a relative path, because the
# relative default resolved against the container's WORKDIR (/opt/soc-ai),
# which is not a volume: every `docker compose up -d` recreate deleted every
# bundle, and with them the oracle critiques that are the only evidence behind
# an alarm on the quality trend. On 2026-08-07 a recreate destroyed the
# artifacts for both of that day's alarms while they were being diagnosed.
# In the packaged layout every persisted directory lives under one root
# (/var/lib/soc-ai/{data,blocklists,maxmind,...}), so deriving from
# ``soc_ai_data_dir`` puts bundles on the volume docker-compose.yml mounts
# without inventing a second source of truth for the install's data root.
_BUNDLE_DIR_NAME = "evals"

# What a host/dev install gets: a relative data dir means there is no packaged
# root to sit inside, so keep the historical ./evals.
_RELATIVE_BUNDLE_DIR = Path(_BUNDLE_DIR_NAME)

# The scenario catalogue shipped with the package.
_SCENARIOS_DIR = Path(__file__).parent / "synth_scenarios"

# Which tier the nightly plants from. A miss raises an alarm, so the pool holds
# only scenarios that MUST be caught. The catalogue's own contract for this tier
# (synth_scenarios/README.md): "Recall on this tier should approach 100%; if it
# doesn't, the pipeline is broken." The medium and hard tiers are measured by
# ``validate-batch --repeats``, where one unlucky run cannot page anyone.
NIGHTLY_SYNTH_TIER = "easy"

# Upper bound of ``quality_nightly_synth_n``. Each plant is one more full
# investigation in an unattended batch that runs at concurrency 1.
NIGHTLY_SYNTH_MAX = 3

# Every plant key of a nightly run carries ``::nightly-<utc timestamp>``, so a
# document an earlier run left behind is never readable under tonight's key.
NIGHTLY_PLANT_TAG_PREFIX = "nightly-"

# How old the documents of another batch must be before this run removes them.
# Longer than any one batch can last (13 runs at the 30-minute cap is 6.5
# hours), so a batch that is running now is never touched, and shorter than
# the day between two scheduled runs.
_STALE_PLANT_AGE = timedelta(hours=12)


def nightly_synth_pool(scenarios: Sequence[Scenario]) -> list[Scenario]:
    """The scenarios the nightly may plant, in a stable order.

    Three conditions, each for a reason. The ground truth is ``true_positive``:
    a benign twin has no positive to miss. The scenario has a triage target: one
    with no alert in it belongs to the declarative instrument and cannot be
    triaged. The tier is :data:`NIGHTLY_SYNTH_TIER`.
    """
    return sorted(
        (
            s
            for s in scenarios
            if s.tier == NIGHTLY_SYNTH_TIER
            and s.ground_truth is not None
            and s.ground_truth.verdict == "true_positive"
            and any(event.is_triage_target for event in s.events)
        ),
        key=lambda s: s.id,
    )


def unmet_requirement(scenario: Scenario, blocklist: Any) -> str | None:
    """Why the deployment cannot detect ``scenario`` tonight, or None when it can.

    Checks each entry of ``Scenario.requires`` against what is LOADED, read from
    the same blocklist store the run itself will query. Two conditions for a
    feed: the feed is loaded, and a loaded feed lists the address the scenario
    relies on. A feed that is on the disk and has dropped the address fails the
    second, and that is the condition the detection needs.

    A scenario that fails either one must not be planted. The run would see an
    alert with its strongest evidence missing, and a miss would raise a verdict
    alarm for a feed that is not there. That is a fact about the deployment,
    and the snapshot states it as one.
    """
    loaded = set(getattr(blocklist, "loaded_sources", None) or [])
    for need in scenario.requires:
        if need.blocklist not in loaded:
            return f"the blocklist {need.blocklist} is not loaded"
        if need.ip and not blocklist.lookup_ip(need.ip):
            return f"no loaded blocklist lists {need.ip}"
    return None


def split_eligible(
    pool: Sequence[Scenario], blocklist: Any
) -> tuple[list[Scenario], list[tuple[str, str]]]:
    """Split the pool into the eligible scenarios and ``(id, reason)`` for the rest."""
    eligible: list[Scenario] = []
    ineligible: list[tuple[str, str]] = []
    for scenario in pool:
        reason = unmet_requirement(scenario, blocklist)
        if reason is None:
            eligible.append(scenario)
        else:
            ineligible.append((scenario.id, reason))
    return eligible, ineligible


def _rotate(pool: Sequence[Scenario], *, n: int, day: date) -> list[Scenario]:
    if n <= 0 or not pool:
        return []
    start = day.toordinal() % len(pool)
    return [pool[(start + i) % len(pool)] for i in range(min(n, len(pool)))]


def pick_nightly_scenarios(
    scenarios: Sequence[Scenario], *, n: int, day: date, blocklist: Any = None
) -> list[Scenario]:
    """Pick ``n`` scenarios for the batch of ``day``, rotating through the pool.

    The start moves one place each day, so the pool is covered in as many
    nights as it holds scenarios. One fixed scenario every night would fit the
    trend to one alert. A random pick would make two runs of one day differ for
    no reason an operator could see. The date is the whole input, so a second
    run on the same day plants the same scenario and the two are comparable.

    Never more than the pool holds: a scenario is planted at most once.

    With a ``blocklist`` the rotation runs over the ELIGIBLE scenarios only
    (:func:`unmet_requirement`), so a scenario the deployment cannot detect
    never takes a night away from one it can.
    """
    pool = nightly_synth_pool(scenarios)
    if blocklist is not None:
        pool, _ineligible = split_eligible(pool, blocklist)
    return _rotate(pool, n=n, day=day)


class _NothingLoaded:
    """The stand-in when the reputation feeds cannot be read at all.

    Every scenario with a requirement is then not eligible, which is the safe
    reading: an unreadable feed is a feed the run cannot use.
    """

    loaded_sources: tuple[str, ...] = ()

    def lookup_ip(self, _ip: str) -> list[Any]:
        return []


def _loaded_blocklist(settings: Any) -> Any:
    """The blocklist store as the run itself will see it.

    Built by the same function the harness uses for each run
    (``build_local_enrichment_context``), so the eligibility check and the run
    read one set of feeds.
    """
    from soc_ai.tools.enrichment import build_local_enrichment_context  # noqa: PLC0415 - lazy

    try:
        return build_local_enrichment_context(settings).blocklist
    except Exception:
        return _NothingLoaded()


@dataclass(frozen=True)
class _PlantPlan:
    """What one nightly run intends to plant, decided before the batch starts."""

    scenarios: tuple[Scenario, ...]
    run_time: datetime
    # Why nothing could be planned although the setting asked for a plant.
    note: str | None = None
    # The scenarios of the pool the deployment cannot detect tonight, each with
    # its reason. They are never planted. See :func:`unmet_requirement`.
    ineligible: tuple[tuple[str, str], ...] = ()

    @property
    def tag(self) -> str | None:
        """The key suffix of this run, or None when it plants nothing.

        One suffix for each run. The pool is small and is planted again every
        few nights on one grid, so a plant an earlier night failed to take back
        must never be readable under tonight's key.
        """
        if not self.scenarios:
            return None
        return f"{NIGHTLY_PLANT_TAG_PREFIX}{self.run_time:%Y%m%dT%H%M%S}"

    @property
    def scenario_ids(self) -> tuple[str, ...]:
        return tuple(s.id for s in self.scenarios)


def _plan_plants(settings: Any, now: datetime) -> _PlantPlan:
    """Decide the plants of this run from the setting and the date.

    ``getattr``: a settings double that predates the knob plants nothing, which
    is what the nightly did before the knob. The value is clamped to the bounds
    the config console enforces, so a stray environment value cannot turn the
    unattended nightly into a benchmark.

    A catalogue that fails to load costs the night its known positive and
    nothing else, like a refused plant. The reason reaches the snapshot.
    """
    n = max(0, min(NIGHTLY_SYNTH_MAX, int(getattr(settings, "quality_nightly_synth_n", 0))))
    if n <= 0:
        return _PlantPlan(scenarios=(), run_time=now)
    from soc_ai.eval.synth_loader import load_all_scenarios  # noqa: PLC0415 - lazy

    try:
        pool = nightly_synth_pool(load_all_scenarios(_SCENARIOS_DIR))
    except Exception as e:
        note = f"the scenario catalogue did not load: {type(e).__name__}: {e}"[:300]
        return _PlantPlan(scenarios=(), run_time=now, note=note)
    if not pool:
        note = "the scenario catalogue holds no easy true positive"
        return _PlantPlan(scenarios=(), run_time=now, note=note)
    eligible, ineligible = split_eligible(pool, _loaded_blocklist(settings))
    if not eligible:
        return _PlantPlan(
            scenarios=(),
            run_time=now,
            note="no scenario is eligible on this deployment",
            ineligible=tuple(ineligible),
        )
    return _PlantPlan(
        scenarios=tuple(_rotate(eligible, n=n, day=now.date())),
        run_time=now,
        ineligible=tuple(ineligible),
    )


async def _nightly_runner(
    alert_id: str,
    *,
    grade: bool,
    expected_verdict: str | None = None,
    **kw: Any,
) -> Any:
    """The harness, with the two rules that are the nightly's own.

    **A planted run is never graded.** It carries its ground truth
    (``expected_verdict``), and the verdict is scored against that. A critique
    would add no fact and would cost one Oracle call each night against a quota
    that has already lost whole nights. It also keeps the planted run
    measurable in local mode and on a night the Oracle is not available.

    **A failed grade request keeps the investigation.** The verdict, the
    latency and the served model of a run that completed are all real, and the
    snapshot reports the lost grade as a lost grade.

    ``grade`` stays a keyword bound by ``functools.partial`` in the caller, so
    the zero-egress wiring of local mode is still visible on the runner.
    """
    from soc_ai.eval import harness  # noqa: PLC0415 - lazy: keep module import light

    return await harness.run(
        alert_id,
        grade=grade and expected_verdict is None,
        expected_verdict=expected_verdict,
        tolerate_grader_failure=True,
        **kw,
    )


def resolve_out_dir(settings: Any, out_dir: str | Path | None) -> tuple[Path, str | None]:
    """Pick the batch-artifact directory. Returns ``(dir, warning)``.

    An explicit *out_dir* (the CLI's ``--out-dir``) always wins. Otherwise the
    bundles land beside the persisted data dir — see :data:`_BUNDLE_DIR_NAME`
    for why that matters more than it looks.

    The warning exists for one failure mode: a named volume mounted at a path
    the image never created is owned by root, so the container user cannot
    write it. Falling back keeps the unattended nightly producing trend points
    instead of failing every night, but silently writing to a directory the
    next recreate will delete is exactly the bug this function fixes — so the
    caller surfaces the reason.
    """
    if out_dir is not None:
        return Path(out_dir), None

    data_dir = Path(getattr(settings, "soc_ai_data_dir", _BUNDLE_DIR_NAME))
    if not data_dir.is_absolute():
        return _RELATIVE_BUNDLE_DIR, None

    target = data_dir.parent / _BUNDLE_DIR_NAME
    try:
        target.mkdir(parents=True, exist_ok=True)
        writable = os.access(target, os.W_OK)
    except OSError as e:
        return _RELATIVE_BUNDLE_DIR, f"cannot use {target} for eval bundles ({e}); using ./evals"
    if not writable:
        return (
            _RELATIVE_BUNDLE_DIR,
            f"cannot use {target} for eval bundles (not writable by this user); "
            "using ./evals — these artifacts will NOT survive a container recreate",
        )
    return target, None


@dataclass
class NightlyRunResult:
    exit_code: int
    mode: str
    # Set on any run that wrote a snapshot (exit 0 / 4); None on 2 / 5.
    metrics: Any | None = None
    batch_dir: str | None = None
    alarm_reasons: list[str] | None = None
    # The condition this point recorded (sorted rule codes) and whether it is a
    # CHANGE from the previous same-mode point. Only a change fires side
    # effects; ``alarm_reasons`` stays populated for every alarmed run, so a
    # caller printing the run's outcome still reports a persisting condition.
    alarm_key: str | None = None
    alarm_is_new: bool = False
    # One analyst-facing line for status surfaces / error detail on 2 / 5.
    detail: str = ""


def resolve_mode(settings: Any, *, graded: bool = False, local: bool = False) -> str:
    """Explicit flag wins; otherwise follow the install's oracle posture —
    ``oracle_enabled`` is the operator's standing declaration that cloud-oracle
    egress is acceptable, so it gates the nightly grader too."""
    if graded:
        return "graded"
    if local:
        return "local"
    return "graded" if settings.oracle_enabled else "local"


@dataclass(frozen=True)
class AlarmOutcome:
    """What one recorded point means: what it SAYS, and whether it is NEWS.

    Two separate questions that the pre-0027 code conflated into one bare
    ``if reasons``. ``reasons`` is what the row stores — a measurement, repeated
    honestly for as long as the condition holds. ``is_transition`` is the only
    thing that may fire a side effect.
    """

    reasons: list[str]
    alarm_key: str | None
    alarm_since: datetime | None
    is_transition: bool


def _verdict_agreement_of(detail: Any) -> dict[str, Any]:
    """The verdict agreement a stored snapshot recorded, as TrendPoint fields.

    Defensive on every key: the column is free JSON. A row with no record, or
    with a record this build cannot read, gives None counts. The window rule
    leaves such a night out, which is the honest reading of a night that never
    asked the Oracle for its verdict.
    """
    record = detail.get("verdict_agreement") if isinstance(detail, dict) else None
    if not isinstance(record, dict):
        return {}
    agree, compared, pairs = record.get("agree"), record.get("compared"), record.get("pairs")
    if not isinstance(agree, int) or not isinstance(compared, int):
        return {}
    return {
        "verdict_agree": agree,
        "verdict_compared": compared,
        "verdict_pairs": (
            {str(k): int(v) for k, v in pairs.items() if isinstance(v, int)}
            if isinstance(pairs, dict)
            else None
        ),
    }


async def _record_trend_point(
    db: Any,
    *,
    metrics: Any,
    mode: str,
    alarm_drop: float,
    batch_dir: str,
    analyst_model: str | None = None,
    detail: dict[str, Any] | None = None,
) -> AlarmOutcome:
    """Read same-mode history, run the detector, insert + prune — one txn.

    Split out of the run function so the read → decide → write sequence stays
    one readable unit: the decision MUST be made against history that excludes
    the row being written, and the write must carry the counts the next night's
    decision will pool.

    **The transition rule lives here, not in the detector.** The detector has no
    memory by design, so a condition that persists is re-reported every run that
    re-observes it — prod rows 9/10/11 are one "agreement 0.80 against a median
    of 1.00" condition that paged three times in 27 hours, and the reason
    strings could not be compared to notice, because each embeds that run's live
    numbers. So the row always records what was measured (``alarmed`` and
    ``alarm_reasons`` exactly as decided — a suppressed alarm must never read as
    a clean night on the trend), and only a CONDITION the previous SAME-MODE row
    did not hold is reported as new.

    A condition, not a key (:func:`soc_ai.eval.quality.alarm_conditions`). A
    key is every code that fired, so it also changes when one condition CLEARS
    beside another that stands. With one rule that could not happen. With five
    it is the ordinary case: a standing alarm and a planted miss that comes one
    night and is gone the next. Comparing whole keys would report the third
    night as news, for the one condition that had already been reported.

    ``alarm_since`` follows the same reading. It is carried forward while the
    new point shares a condition with the previous one and re-stamped when it
    shares none, so the date of a standing condition does not move each time a
    second condition visits.

    A previous row with a NULL key is treated as UNKNOWN, not as "same": it is
    either a clean night or a pre-0027 row, and firing one extra time after an
    upgrade is recoverable where a swallowed first page is not.
    """
    from soc_ai.eval.quality import (  # noqa: PLC0415 - lazy: keep module import light
        BASELINE_WINDOW,
        CODE_AGREEMENT_DROP,
        TrendPoint,
        alarm_codes_from_key,
        alarm_conditions,
        alarm_key_for,
        detect_regression,
    )
    from soc_ai.store import quality as quality_store  # noqa: PLC0415 - lazy
    from soc_ai.store.auth import utcnow  # noqa: PLC0415 - lazy

    # BASELINE_WINDOW, not the 7 the median rules use: the agreement test POOLS
    # these counts into one baseline rate, and seven nights of five grades is
    # too few to tell a bad week from a bad model. The detector slices its own
    # median window off the front — the store returns newest-first, which that
    # slice relies on.
    history = await quality_store.recent_snapshots(db, limit=BASELINE_WINDOW, mode=mode)
    reasons = detect_regression(
        metrics,
        [
            TrendPoint(
                agreement_rate=h.agreement_rate,
                fallback_rate=h.fallback_rate,
                n_yes=h.n_yes,
                n_classified=h.n_classified,
                # Only an AGREEMENT alarm disqualifies a night from the
                # agreement baseline. A fallback-jump alarm says nothing about
                # whether that night's grades were representative.
                agreement_alarmed=CODE_AGREEMENT_DROP in alarm_codes_from_key(h.alarm_key),
                **_verdict_agreement_of(h.detail),
            )
            for h in history
        ],
        alarm_drop=alarm_drop,
    )

    # Same-mode, newest-first — so this is the point an operator would compare
    # tonight's card against.
    previous = history[0] if history else None
    alarm_key = alarm_key_for(reasons)
    conditions = alarm_conditions(alarm_key)
    previous_conditions = alarm_conditions(previous.alarm_key if previous is not None else None)
    # News is a condition that was not there. A NULL previous key gives an
    # empty set, so every condition of this point is new against it.
    is_transition = bool(conditions - previous_conditions)
    alarm_since = None
    if alarm_key is not None:
        # Carried forward while a condition holds, so the card can say
        # "ongoing since <date>" without a scan of history the prune may have
        # already eaten.
        standing = previous is not None and bool(conditions & previous_conditions)
        carried = previous.alarm_since if previous is not None and standing else None
        alarm_since = carried or utcnow()

    # The reasons are stored as the plain strings they have always been: the
    # column, the audit payload and the webhook body are wire surfaces, and the
    # codes reach the UI as their own field (alarm_key) instead.
    messages = [r.message for r in reasons]
    await quality_store.insert_snapshot(
        db,
        mode=mode,
        n_ok=metrics.n_ok,
        n_error=metrics.n_error,
        agreement_rate=metrics.agreement_rate,
        fallback_rate=metrics.fallback_rate,
        error_rate=metrics.error_rate,
        verdict_counts=metrics.verdict_counts,
        latency_p50_ms=metrics.latency_p50_ms,
        batch_dir=batch_dir,
        alarmed=bool(reasons),
        alarm_reasons=messages or None,
        alarm_key=alarm_key,
        alarm_since=alarm_since,
        n_yes=metrics.n_yes,
        n_partial=metrics.n_partial,
        n_no=metrics.n_no,
        n_classified=metrics.n_classified,
        # Which route these verdicts came out of (0040). The row already records
        # the running version and build; this is the third thing that can move
        # under a fixed one, and the class docstring names it as the failure the
        # trend was built for — a gateway repointing a route at a different
        # backend regresses the numbers with the code unchanged.
        analyst_model=analyst_model,
        # What the numbers cannot hold (0066): the served model of the runs,
        # the planted true positives, and the grades the grader never gave.
        detail=detail,
    )
    return AlarmOutcome(
        reasons=messages,
        alarm_key=alarm_key,
        alarm_since=alarm_since,
        is_transition=is_transition,
    )


async def _remove_documents(
    elastic: Any, batch_dir: Path, emit: Callable[[str], None]
) -> str | None:
    """Delete, by id, the documents the ledger of ``batch_dir`` lists.

    Returns None when nothing is left on the grid, or one sentence that says
    how many documents are still there and why. That sentence is the report of
    a failed delete: it goes to the progress lines, to the detail of the run
    and to the snapshot. A synthetic alert that stays on the grid is visible in
    Security Onion, so a failure here must not pass unseen. It must not fail
    the night either: the measurement is already taken.

    The ledger is rewritten with what is left, so the next run tries those
    documents again and no other.
    """
    from soc_ai.eval import synth_ingest  # noqa: PLC0415 - lazy

    planted_at, documents = synth_ingest.read_ledger(batch_dir)
    if not documents:
        return None
    try:
        removed, failures = await synth_ingest.delete_synth_documents(elastic, documents)
    except Exception as e:
        reason = f"{type(e).__name__}: {e}"
        removed, failures = 0, [(index, doc_id, reason) for index, doc_id in documents]
    with contextlib.suppress(OSError):
        synth_ingest.write_ledger(
            batch_dir,
            [(index, doc_id) for index, doc_id, _reason in failures],
            planted_at=planted_at,
        )
    if removed:
        emit(f"removed {removed} synthetic documents from the grid")
    if not failures:
        return None
    note = (
        f"{len(failures)} synthetic documents are still on the grid. "
        f"The delete failed: {failures[0][2].rstrip('.')}. The next run tries again. "
        "To remove them by hand, run `soc-ai synth-clean`."
    )
    emit(note)
    return note


def _stale_ledgers(bundle_dir: Path, now: datetime) -> list[Path]:
    """The batch directories whose ledger still lists documents and is old enough."""
    from soc_ai.eval import synth_ingest  # noqa: PLC0415 - lazy

    stale: list[Path] = []
    for ledger in sorted(bundle_dir.glob(f"batch-*/{synth_ingest.LEDGER_NAME}")):
        planted_at, documents = synth_ingest.read_ledger(ledger.parent)
        if not documents or planted_at is None:
            continue
        if planted_at.tzinfo is None:
            planted_at = planted_at.replace(tzinfo=UTC)
        if now - planted_at >= _STALE_PLANT_AGE:
            stale.append(ledger.parent)
    return stale


async def _remove_leftovers(
    elastic: Any, bundle_dir: Path, now: datetime, emit: Callable[[str], None]
) -> str | None:
    """Remove what earlier runs left on the grid, from their own ledgers.

    A run that was killed (a restart, a power loss) never reached its own
    removal, and its synthetic alert would sit in Security Onion until someone
    asked what it was. Its ledger is still in its batch directory. Only a
    ledger older than :data:`_STALE_PLANT_AGE` is used, so a batch that another
    process is running now keeps its documents.
    """
    notes: list[str] = []
    for batch_dir in _stale_ledgers(bundle_dir, now):
        note = await _remove_documents(elastic, batch_dir, emit)
        if note is not None:
            notes.append(note)
    return notes[0] if notes else None


async def _store_point(
    settings: Any,
    *,
    metrics: Any,
    mode: str,
    alarm_drop: float,
    batch_dir: str,
    cleanup_error: str | None = None,
) -> AlarmOutcome:
    """Open the store, record the point, close the store.

    Builds its own engine: the eval may run before the app ever booted against
    this store (fresh install, cron-first), the same idiom as
    discover-internal-identifiers.
    """
    from soc_ai.eval.quality import snapshot_detail  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    configured_model = getattr(settings, "analyst_model", None)
    detail = snapshot_detail(metrics, configured_model=configured_model)
    # None when every synthetic document is off the grid. Otherwise the
    # sentence that says how many are left and why the delete failed.
    detail["synth_cleanup_error"] = cleanup_error
    engine = make_engine(settings)
    try:
        await run_migrations(engine)
        async with make_sessionmaker(engine)() as db:
            return await _record_trend_point(
                db,
                metrics=metrics,
                mode=mode,
                alarm_drop=alarm_drop,
                batch_dir=batch_dir,
                # The CONFIGURED route, as before. What actually served the
                # runs is in the detail, because the two can differ and the
                # difference is the finding.
                analyst_model=configured_model,
                detail=detail,
            )
    finally:
        with contextlib.suppress(Exception):
            await engine.dispose()


async def run_eval_nightly(
    settings: Any,
    *,
    mode: str | None = None,
    oql: str | None = None,
    out_dir: str | Path | None = None,
    per_run_timeout_s: int = 1800,
    emit: Callable[[str], None] | None = None,
    fire_alarm: Callable[..., Awaitable[None]] | None = None,
) -> NightlyRunResult:
    """Run one nightly quality micro-eval and persist its trend point.

    ``mode`` None follows the oracle posture (:func:`resolve_mode`); ``oql``
    None uses the web-UI alerts-feed query — the same population the dashboard
    shows; ``out_dir`` None lands the bundles beside the data dir
    (:func:`resolve_out_dir`). ``emit`` receives progress lines (the CLI colors
    them; the app logs them). ``fire_alarm`` fires regression side effects
    (audit + webhook) on a TRANSITION into a new condition only; None skips
    them entirely. Builds its own engine + Elastic client
    on purpose: the
    eval must be runnable before the app ever booted against this store
    (cron-first installs) and must not contend with the app's pools.

    The run WRITES to the grid when ``quality_nightly_synth_n`` is above 0: it
    plants the scenario documents under ``logs-synth-*`` and removes them when
    the batch ends. Each document is deleted by its own id
    (:func:`soc_ai.eval.synth_ingest.delete_synth_documents`). The run sends no
    delete by query. Every read path of the product excludes those documents
    (:mod:`soc_ai.tools._synth_scope`). Security Onion itself does not, so the
    planted alert is visible there until the removal. A delete that fails is in
    ``detail`` and in the snapshot.

    ``detail`` on the result is no longer empty on a clean run: it states what
    became of each planted true positive, and any grade the grader did not
    give. Exit 0 with a detail is a run that worked and has something to say.
    """
    import functools  # noqa: PLC0415 - lazy: keep module import light

    from soc_ai.eval.batch import BatchConfig, run_batch  # noqa: PLC0415 - lazy
    from soc_ai.eval.quality import (  # noqa: PLC0415 - lazy
        compute_snapshot_metrics,
        not_measured_text,
        run_errors_text,
        synth_text,
    )
    from soc_ai.eval.report import build_report, load_index  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy

    def _emit(line: str) -> None:
        if emit is not None:
            emit(line)

    eval_mode = mode or resolve_mode(settings)
    # Clamp to the documented bounds even for env-sourced values: the config
    # console enforces [1,10] / [0.05,0.5], but a stray .env must not turn the
    # unattended nightly into an hour-long batch or a hair-trigger pager.
    n = max(1, min(10, settings.quality_nightly_n))
    alarm_drop = max(0.05, min(0.5, settings.quality_alarm_drop))
    eval_oql = oql or settings.webui_alerts_query
    bundle_dir, bundle_warning = resolve_out_dir(settings, out_dir)
    if bundle_warning is not None:
        _emit(bundle_warning)

    # The known positives of this batch.
    plan = _plan_plants(settings, datetime.now(UTC))

    _emit(
        f"eval-nightly · mode={eval_mode} n={n} "
        f"synth={','.join(plan.scenario_ids) or 'none'} oql={eval_oql!r} out={bundle_dir}"
    )

    cfg = BatchConfig(
        oql=eval_oql,
        n=n,
        # Concurrency 1: the nightly runs unattended on possibly-shared
        # inference infra — it must never contend with live triage.
        concurrency=1,
        out_dir=bundle_dir,
        per_run_timeout_s=per_run_timeout_s,
        synth_scenarios=plan.scenarios or None,
        synth_run_time=plan.run_time,
        # The real alerts are the batch. A plant that fails is reported and
        # costs nothing else, and a grid with no eligible alert is not planted.
        synth_optional=True,
        synth_plant_tag=plan.tag,
    )

    elastic = ElasticClient(settings)
    try:
        # What an earlier run left on the grid, by the ids in its own ledger.
        # Before the plant, and also on a night that plants nothing: the
        # documents are there whatever tonight's setting is.
        leftover_error = await _remove_leftovers(elastic, bundle_dir, plan.run_time, _emit)
        try:
            summary = await run_batch(
                cfg,
                settings=settings,
                elastic=elastic,
                # grade=False keeps the per-alert oracle call OUT of local
                # mode — the whole zero-egress contract hangs on this kwarg.
                runner=functools.partial(_nightly_runner, grade=(eval_mode == "graded")),
                progress=_emit,
            )
        except Exception as e:
            # A batch that died after its plant left a ledger in a directory
            # this function never learned. The next run removes those documents
            # from that ledger, and the detail says so.
            transport = "" if isinstance(e, RuntimeError) else f" (transport): {type(e).__name__}"
            detail = f"eval-nightly failed{transport}: {e}"
            if plan.scenarios:
                detail = (
                    f"{detail.rstrip('.')}. Synthetic documents of this run can still be "
                    "on the grid. The next run removes them."
                )
            return NightlyRunResult(exit_code=EXIT_ERROR, mode=eval_mode, detail=detail)

        # The synthetic documents leave the grid as soon as their runs are
        # done, each by its own id.
        cleanup_error = await _remove_documents(elastic, summary.batch_dir, _emit) or leftover_error

        if summary.n_planned == 0:
            return NightlyRunResult(
                exit_code=EXIT_NO_ALERTS,
                mode=eval_mode,
                detail=f"no eligible alerts for {eval_oql!r} — no snapshot written"
                + (f". {cleanup_error}" if cleanup_error else ""),
            )
        if summary.aborted_reason:
            # Still record the point below: a fully-broken engine (every run
            # failing) is precisely the regression the trend exists to catch —
            # swallowing it would blind the alarm.
            _emit(summary.aborted_reason)

        # Aggregate (pure; no oracle, no meta-analysis) + reduce to a point.
        _json_path, _md_path, agg = build_report(summary.batch_dir)
        metrics = compute_snapshot_metrics(
            load_index(summary.batch_dir),
            agg,
            mode=eval_mode,
            synth_planned=plan.scenario_ids,
            synth_note=summary.synth_error or plan.note,
            synth_ineligible=plan.ineligible,
            n_planned=summary.n_planned,
        )

        # Trend: read same-mode history, detect, insert + prune in one txn.
        outcome = await _store_point(
            settings,
            metrics=metrics,
            mode=eval_mode,
            alarm_drop=alarm_drop,
            batch_dir=str(summary.batch_dir),
            cleanup_error=cleanup_error,
        )

        # Transition, not "alarmed": a condition that persists is one problem,
        # and paging once per run for it is what taught the operator to ignore
        # the card (prod rows 9/10/11). The row above recorded the alarm either
        # way, so nothing is lost — only repeated.
        if outcome.is_transition and fire_alarm is not None:
            await fire_alarm(
                settings,
                elastic=elastic,
                mode=eval_mode,
                reasons=outcome.reasons,
                metrics=metrics,
            )

        # What the run has to say for itself, in one line: an abort, the grades
        # the grader never gave, and what became of each planted true positive.
        # The caller prints or logs it. It also reaches the attempt record, and
        # from there the freshness line of the Quality card.
        notes = [
            summary.aborted_reason,
            run_errors_text(metrics),
            not_measured_text(metrics),
            *synth_text(metrics),
            cleanup_error,
        ]

        return NightlyRunResult(
            exit_code=EXIT_ABORTED if summary.aborted_reason else EXIT_OK,
            mode=eval_mode,
            metrics=metrics,
            batch_dir=str(summary.batch_dir),
            alarm_reasons=outcome.reasons or None,
            alarm_key=outcome.alarm_key,
            alarm_is_new=outcome.is_transition,
            detail=" ".join(note for note in notes if note),
        )
    finally:
        with contextlib.suppress(Exception):
            await elastic.aclose()
