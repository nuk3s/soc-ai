"""Replay the tier 2 detectors against the grid, into a scratch store, and report the hit rate.

The four-tier methodology sets a budget before any tier 2 statistic moves: at
most one hit per 100 host-days on 30 days of production replay. The synthetic
replay in ``tests/test_tier2_replay.py`` proves the loop on a fake grid. This
module runs the same loop against the grid an install reads:

* for each replayed day, the profile build anchored at the start of the day;
* for each replayed hour, the prior sweep with ``now`` at that hour. It
  records observations and forms leads, as the hourly loop does.

The sweep runs two evaluators, as the hourly loop does: ``profile``, which
reads the stored baselines, and ``model``, which runs the learned detectors
against the grid with the same time anchor. ``--evaluator`` picks one or both.
The ``match`` analytics stay out: the catalog sweep runs them. With no
``profile`` analytic in the plan, the replay builds no profile.

Every read goes through the client the caller hands in, against
``settings.events_index_pattern``. Every write goes to a fresh SQLite store.
The live store is opened read-only, once, for the estate's address space and,
on request, for its census. A store path that resolves to the live store is
refused before anything runs.

Two words have one meaning each in the report:

* a **host-day** is one host on one replayed day that the analytic measured
  at least once. For a ``model`` analytic the host is the machine that the
  detector names. A detector state folds into the four states of the report
  the way the trail and the ledger fold it (``PriorResult.trail_state``);
* a **hit** is one host on one replayed day on which the analytic recorded a
  new observation or a new sighting of an existing one. ``born_at`` moves only
  on a new sighting, so the report reads the hits of a day back from the
  scratch store when the day ends. A re-read of the same documents is no hit.

Each analytic runs at the status it has on the live install. An analytic in
shadow writes shadow observations, as it does live, and a shadow hit counts
as a hit. The shipped detectors ship in shadow.

Memory stays flat over the length of the replay: the loop keeps counters and
the host sets of the current day only. The observations stay in the store.
"""

from __future__ import annotations

import json
import logging
import math
import os
import urllib.parse
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import URL, event, func, insert, make_url, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from soc_ai.dossier.profile import (
    _CATEGORICAL,
    _SHAPED_CANDIDATES,
    _SHAPED_PROBE_FIELD,
    member_alternates,
)
from soc_ai.dossier.profile_job import _BATCH_KEYS, build_profiles
from soc_ai.dossier.stages import CountingGrid, StageClock, counting
from soc_ai.hunting.model import MODEL_SOURCE
from soc_ai.hunting.prior_sweep import _ceiling_note, run_prior_sweep
from soc_ai.hunting.priors import (
    COVERAGE_BLIND,
    COVERAGE_LEARNING,
    COVERAGE_MEASURED,
    COVERAGE_NOT_APPLICABLE,
)
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog
from soc_ai.store.db import (
    SQLITE_DRIVER,
    SQLITE_FILENAME,
    StoreUrlError,
    engine_for_url,
    is_postgres_url,
    make_private_dir,
    make_sessionmaker,
    restrict_file,
    run_migrations,
    store_url,
)
from soc_ai.store.models import (
    EntityObservation,
    HostDossier,
    HostDossierField,
    HostMachine,
    Lead,
)

__all__ = [
    "BUDGET_PER_100_HOST_DAYS",
    "REPLAY_EVALUATORS",
    "LiveEstate",
    "ReplayPlan",
    "ReplayRefused",
    "ReplayReport",
    "census_size",
    "describe_plan",
    "evaluator_notes",
    "fold_verdicts",
    "host_days_needed",
    "live_store_paths",
    "plan_replay",
    "profile_analytics",
    "read_live_estate",
    "render_markdown",
    "replay_analytics",
    "run_replay",
    "summary_lines",
    "wilson_upper",
    "write_report",
]

_LOGGER = logging.getLogger(__name__)

# The budget of the methodology: hits per 100 host-days, per analytic.
BUDGET_PER_100_HOST_DAYS = 1.0
# The normal quantile of a two-sided 95 percent interval.
_Z95 = 1.959963984540054
# How many hosts the report names per analytic, and how many errors per hour.
_TOP_HOSTS = 5
_ERRORS_KEPT = 3
_ERROR_CHARS = 300
# Rows per insert when the census is copied into the scratch store.
_SEED_CHUNK = 500

WITHIN = "within budget"
OVER = "over budget"
# The rate is at or under the budget, and the Wilson upper bound is over it.
# The replay holds too few host-days to show that the rate is under the
# budget. 0 hits in 7 host-days read "within budget" with an upper bound of 35
# per 100.
TOO_FEW = "not enough host-days"
NOT_MEASURED = "not measured"

_STATES = (COVERAGE_MEASURED, COVERAGE_LEARNING, COVERAGE_BLIND, COVERAGE_NOT_APPLICABLE)

# The evaluators a replay runs, in the order the report lists them. The
# catalog sweep runs the ``match`` analytics, so the replay leaves them out.
REPLAY_EVALUATORS: tuple[str, ...] = ("profile", "model")
# The observation source each evaluator writes under.
_SOURCES = {"profile": "profile", "model": MODEL_SOURCE}
# The least searches one detector makes per sweep on a grid that carries its
# planes. cross_plane_silence: one page of the host read and one page of the
# flow read. logon_chain: one page of the edge read and one recent read. A
# hit adds a search for each document it cites.
_DETECTOR_SEARCHES = {"cross_plane_silence": 2, "logon_chain": 2}
# What a detector note says when a read stopped at its entity ceiling.
_DETECTOR_CEILING = "stopped at the ceiling"


class ReplayRefused(ValueError):
    """The replay will not run as asked. The message says why, in the operator's words."""


# ---------------------------------------------------------------------------
# Arithmetic
# ---------------------------------------------------------------------------


def wilson_upper(hits: int, trials: int, *, z: float = _Z95) -> float | None:
    """The upper bound of the Wilson score interval for ``hits`` in ``trials``.

    None for no trials: a rate over nothing has no bound.
    """
    if trials <= 0:
        return None
    p = min(1.0, max(0.0, hits / trials))
    z2 = z * z
    centre = p + z2 / (2 * trials)
    margin = z * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials))
    return min(1.0, (centre + margin) / (1 + z2 / trials))


def _per_100(hits: int, host_days: int) -> float | None:
    return None if host_days <= 0 else round(100.0 * hits / host_days, 4)


def _upper_per_100(hits: int, host_days: int) -> float | None:
    upper = wilson_upper(hits, host_days)
    return None if upper is None else round(100.0 * upper, 4)


def _verdict(hits: int, host_days: int) -> str:
    """The verdict of one analytic against the budget.

    Over budget when the rate is over the budget. Within budget only when the
    Wilson upper bound is at or under it. Between the two, the replay holds
    too few host-days to judge.
    """
    if host_days <= 0:
        return NOT_MEASURED
    if 100.0 * hits / host_days > BUDGET_PER_100_HOST_DAYS:
        return OVER
    upper = wilson_upper(hits, host_days)
    if upper is not None and 100.0 * upper <= BUDGET_PER_100_HOST_DAYS:
        return WITHIN
    return TOO_FEW


def host_days_needed(budget_per_100: float = BUDGET_PER_100_HOST_DAYS) -> int:
    """The fewest host-days with no hit whose Wilson upper bound is at or under the budget.

    381 at the budget of 1 per 100. With fewer host-days, a replay with no
    hit cannot show that the rate is under the budget.
    """
    budget = budget_per_100 / 100.0
    if budget <= 0.0:
        raise ValueError("the budget must be above zero")
    # With no hit, the upper bound is z^2 / (n + z^2).
    needed = max(1, math.ceil(_Z95 * _Z95 * (1.0 - budget) / budget))
    while needed > 1 and (wilson_upper(0, needed - 1) or 1.0) <= budget:
        needed -= 1
    while (wilson_upper(0, needed) or 1.0) > budget:
        needed += 1
    return needed


# ---------------------------------------------------------------------------
# The plan
# ---------------------------------------------------------------------------


def _runs_on(spec: HuntSpec, evaluator: str) -> bool:
    if evaluator == "profile":
        return spec.evaluator == "profile" and spec.profile is not None
    if evaluator == "model":
        return spec.evaluator == "model" and spec.model is not None
    return False


def replay_analytics(
    catalog: Mapping[str, HuntSpec] | None = None,
    evaluators: Sequence[str] = REPLAY_EVALUATORS,
) -> dict[str, HuntSpec]:
    """Every shipped analytic of ``evaluators`` that the prior sweep runs, by id.

    Grouped by evaluator in the order of :data:`REPLAY_EVALUATORS`, and by id
    inside each group.
    """
    specs = catalog if catalog is not None else load_catalog(CATALOG_DIR)
    return {
        spec_id: spec
        for evaluator in REPLAY_EVALUATORS
        if evaluator in evaluators
        for spec_id, spec in sorted(specs.items())
        if _runs_on(spec, evaluator)
    }


def profile_analytics(catalog: Mapping[str, HuntSpec] | None = None) -> dict[str, HuntSpec]:
    """Every shipped analytic that the prior sweep scores on a stored baseline, by id."""
    return replay_analytics(catalog, ("profile",))


def live_store_paths(settings: Any) -> list[Path]:
    """The SQLite files that are, or may be, the live store.

    The file in the data directory is always on the list. With a PostgreSQL
    store it is the file a copy left behind, and a replay must not write over
    it either.
    """
    paths = [Path(settings.soc_ai_data_dir) / SQLITE_FILENAME]
    try:
        url = store_url(settings)
    except StoreUrlError:
        return paths
    if not is_postgres_url(url) and url.database:
        paths.append(Path(str(url.database)))
    return paths


def _same_file(a: Path, b: Path) -> bool:
    if a.resolve() == b.resolve():
        return True
    try:
        return a.exists() and b.exists() and os.path.samefile(a, b)
    except OSError:
        return False


def _refuse_live_store(store: Path, settings: Any) -> None:
    for live in live_store_paths(settings):
        if _same_file(store, live):
            raise ReplayRefused(
                f"the store {store} resolves to the live store {live.resolve()}. "
                "A replay writes observations and leads. Name a scratch path with --store."
            )


def _parse_end(raw: str | datetime | None, *, present: datetime) -> datetime:
    """The end of the window as an aware UTC time on a whole hour."""
    if raw is None:
        at = present
    elif isinstance(raw, datetime):
        at = raw
    else:
        try:
            at = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError:
            raise ReplayRefused(
                f"--end {raw!r} is not an ISO 8601 time. Write it as 2026-10-01T00:00:00Z."
            ) from None
    at = at.replace(tzinfo=UTC) if at.tzinfo is None else at.astimezone(UTC)
    return at.replace(minute=0, second=0, microsecond=0)


def _dimensions(specs: Iterable[HuntSpec]) -> tuple[str, ...]:
    out: dict[str, None] = {}
    for spec in specs:
        if spec.profile is not None:
            out[spec.profile.dimension] = None
    return tuple(out)


def _detector(spec: HuntSpec) -> str:
    return spec.model.detector if spec.model is not None else ""


def _evaluators(raw: Sequence[str]) -> tuple[str, ...]:
    """The evaluators that ``--evaluator`` names, in report order. None named is both."""
    named = [str(e).strip().lower() for e in raw if str(e).strip()]
    if not named:
        return REPLAY_EVALUATORS
    if "match" in named:
        raise ReplayRefused(
            "--evaluator match: the replay does not run the match evaluator. The catalog "
            "sweep runs the match analytics. Name profile, model or both."
        )
    unknown = [e for e in named if e not in REPLAY_EVALUATORS]
    if unknown:
        raise ReplayRefused(
            f"--evaluator {unknown[0]} is not an evaluator. Name profile, model or both."
        )
    return tuple(e for e in REPLAY_EVALUATORS if e in named)


@dataclass(frozen=True)
class ReplayPlan:
    """What one replay reads and where it writes. Every time is aware UTC."""

    start: datetime
    end: datetime
    days: int
    analytics: tuple[str, ...]
    dimensions: tuple[str, ...]
    store: Path
    out: Path
    hosts_from_census: bool
    evaluators: tuple[str, ...] = REPLAY_EVALUATORS
    # The analytics of each evaluator in ``evaluators``, in report order.
    by_evaluator: dict[str, tuple[str, ...]] = field(default_factory=dict)
    # The detector of each model analytic, in the order of the analytics.
    detectors: tuple[str, ...] = ()

    @property
    def hours(self) -> int:
        return self.days * 24

    @property
    def builds(self) -> int:
        """One profile build per day when a profile analytic runs. None otherwise."""
        return self.days if self.by_evaluator.get("profile") else 0

    def day_starts(self) -> list[datetime]:
        return [self.start + timedelta(days=n) for n in range(self.days)]


def plan_replay(
    settings: Any,
    *,
    days: int = 7,
    end: str | datetime | None = None,
    analytics: Sequence[str] = (),
    store: str | Path | None = None,
    out: str | Path | None = None,
    hosts_from_census: bool = False,
    now: datetime | None = None,
    catalog: Mapping[str, HuntSpec] | None = None,
    evaluators: Sequence[str] = (),
) -> ReplayPlan:
    """Check the arguments and fix the window. Raises :class:`ReplayRefused`.

    The window ends at ``end``, on a whole hour, and starts ``days`` days
    before it. Each replayed day is 24 hours from its start. An end at
    midnight UTC aligns the days to calendar days. An end later than the
    present hour is refused: a sweep over hours the grid has not seen yet
    reads every host as silent.

    ``evaluators`` names the evaluators to run. None named is ``profile`` and
    ``model``. ``analytics`` narrows them to the analytics it names. An
    analytic of an evaluator that ``evaluators`` leaves out is refused.
    """
    if days < 1:
        raise ReplayRefused("--days must be 1 or more.")
    present = (now or datetime.now(UTC)).astimezone(UTC)
    present_hour = present.replace(minute=0, second=0, microsecond=0)
    window_end = _parse_end(end, present=present)
    if window_end > present_hour:
        raise ReplayRefused(
            f"--end {window_end.isoformat()} is later than the present hour "
            f"{present_hour.isoformat()}. The grid holds no documents for those hours."
        )

    chosen = _evaluators(evaluators)
    every = replay_analytics(catalog)
    shipped = {a: spec for a, spec in every.items() if spec.evaluator in chosen}
    wanted = list(dict.fromkeys(analytics)) or list(shipped)
    unknown = [a for a in wanted if a not in every]
    if unknown:
        raise ReplayRefused(
            f"{', '.join(unknown)} is not a shipped analytic of the profile or model "
            f"evaluator. The analytics of --evaluator {' '.join(chosen)} are: "
            f"{', '.join(shipped)}."
        )
    outside = [a for a in wanted if a not in shipped]
    if outside:
        missing = sorted({str(every[a].evaluator) for a in outside})
        raise ReplayRefused(
            f"--evaluator {' '.join(chosen)} does not run {', '.join(outside)}. "
            f"Add --evaluator {' --evaluator '.join(missing)}."
        )
    by_evaluator = {
        evaluator: tuple(a for a in shipped if a in wanted and shipped[a].evaluator == evaluator)
        for evaluator in chosen
    }
    planned = [a for evaluator in chosen for a in by_evaluator[evaluator]]

    data_dir = Path(settings.soc_ai_data_dir)
    stamp = present.strftime("%Y%m%dT%H%M%SZ")
    store_path = Path(store) if store is not None else data_dir / "replay" / f"{stamp}.db"
    store_path = store_path.expanduser().absolute()
    _refuse_live_store(store_path, settings)
    if store_path.exists():
        raise ReplayRefused(
            f"the store {store_path} exists. A replay starts from a fresh store, "
            "so the report counts this replay only. Name a new path with --store."
        )
    out_path = Path(out) if out is not None else store_path.with_suffix("")
    return ReplayPlan(
        start=window_end - timedelta(days=days),
        end=window_end,
        days=days,
        analytics=tuple(planned),
        dimensions=_dimensions(shipped[a] for a in by_evaluator.get("profile", ())),
        store=store_path,
        out=out_path.expanduser().absolute(),
        hosts_from_census=hosts_from_census,
        evaluators=chosen,
        by_evaluator=by_evaluator,
        detectors=tuple(_detector(shipped[a]) for a in by_evaluator.get("model", ())),
    )


# ---------------------------------------------------------------------------
# The estimate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SearchEstimate:
    """The searches a replay makes at least. A paged read or a split batch adds more."""

    per_build: int
    per_sweep: int
    total: int
    # The part of ``per_sweep`` and of ``total`` that the model evaluator makes.
    per_model_sweep: int = 0
    model_total: int = 0


def _batches(keys: int) -> int:
    return 0 if keys <= 0 else math.ceil(keys / _BATCH_KEYS)


def estimate_searches(plan: ReplayPlan, *, addresses: int = 0, names: int = 0) -> SearchEstimate:
    """The least number of searches the plan makes against a grid that carries every plane.

    The build probes each plane once. It then reads each categorical dimension
    and the shaped read (an entity count and one partition) once per batch,
    and once more outside the census. A batch reads only the dimensions keyed
    by the key type it holds. A sweep probes and reads each dimension once,
    and runs each detector of the model analytics. A plan with no profile
    analytic builds no profile.
    """
    per_model = sum(_DETECTOR_SEARCHES.get(d, 0) for d in plan.detectors)
    if not plan.builds:
        return SearchEstimate(
            per_build=0,
            per_sweep=per_model,
            total=plan.hours * per_model,
            per_model_sweep=per_model,
            model_total=plan.hours * per_model,
        )
    probes = {
        (candidates, "|".join((probe, *member_alternates(dim))))
        for dim, candidates, probe, _entity, _member in _CATEGORICAL
    }
    probes.add((_SHAPED_CANDIDATES, _SHAPED_PROBE_FIELD))
    by_name = sum(1 for row in _CATEGORICAL if row[3] == "host.name")
    by_address = len(_CATEGORICAL) - by_name
    shaped = 2
    per_build = (
        len(probes)
        + _batches(addresses) * (by_address + shaped)
        + _batches(names) * by_name
        + len(_CATEGORICAL)
        + shaped
    )
    per_sweep = 2 * len(plan.dimensions) + per_model
    return SearchEstimate(
        per_build=per_build,
        per_sweep=per_sweep,
        total=plan.builds * per_build + plan.hours * per_sweep,
        per_model_sweep=per_model,
        model_total=plan.hours * per_model,
    )


def describe_plan(
    plan: ReplayPlan,
    *,
    census: tuple[int, int] | None = None,
    catalog: Mapping[str, HuntSpec] | None = None,
) -> str:
    """The dry-run text: the window, the runs, the evaluators, the paths and the searches."""
    addresses, names = census if census is not None else (0, 0)
    estimate = estimate_searches(plan, addresses=addresses, names=names)
    full = catalog if catalog is not None else load_catalog(CATALOG_DIR)
    if not plan.hosts_from_census:
        seeded = (
            "Census: not seeded. The build reads the estate in one search per dimension. "
            "Each search holds at most 500 hosts."
        )
    elif census is None:
        seeded = "Census: seeded from the live store. The size is unknown."
    else:
        seeded = (
            f"Census: seeded from the live store, {addresses:,} addresses "
            f"and {names:,} agent names."
        )
    builds = (
        f"Profile builds: {plan.builds}, one at the start of each day"
        if plan.builds
        else "Profile builds: 0. No profile analytic runs, so the replay builds no profile."
    )
    detector_of = dict(zip(plan.by_evaluator.get("model", ()), plan.detectors, strict=True))
    covered: list[str] = []
    for evaluator in plan.evaluators:
        ids = plan.by_evaluator.get(evaluator, ())
        covered.append(f"  {evaluator} evaluator: {_count(len(ids), 'analytic')}")
        covered += [
            f"    {a}, detector {detector_of[a]}" if a in detector_of else f"    {a}" for a in ids
        ]
    searches = (
        f"Searches estimated: at least {estimate.total:,}. Each build makes at least "
        f"{estimate.per_build:,} and each sweep at least {estimate.per_sweep:,}."
    )
    if "model" in plan.evaluators:
        searches += (
            f" The model evaluator makes at least {estimate.per_model_sweep:,} of the searches "
            f"of each sweep, {estimate.model_total:,} in total. A detector hit adds a search "
            "for each document that it cites."
        )
    left = _left_out_notes(full, plan.analytics, plan.evaluators)
    lines = [
        "spec-replay plan. The dry run sends no search.",
        f"Window start: {plan.start.isoformat()}",
        f"Window end: {plan.end.isoformat()}",
        f"Replayed days: {plan.days}",
        builds,
        f"Prior sweeps: {plan.hours}, one at each hour",
        f"Evaluators: {', '.join(plan.evaluators)}",
        f"Analytics: {len(plan.analytics)}",
        *covered,
        *(["Left out:", *(f"  {note}" for note in left)] if left else []),
        f"Store: {plan.store}",
        f"Report: {plan.out / 'report.json'} and {plan.out / 'report.md'}",
        seeded,
        f"{searches} A paged read or a split batch adds more.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The live store, read-only
# ---------------------------------------------------------------------------


@dataclass
class LiveEstate:
    """What the replay reads from the live store: the address space, the statuses, the census.

    ``statuses`` holds the status of each shipped analytic as the effective
    catalog of the live store reads it. An analytic with no entry has the
    status its file ships with, which is the rule of the effective catalog
    for an analytic with no state row.
    """

    cidrs: list[Any]
    dossiers: list[dict[str, Any]] = field(default_factory=list)
    fields: list[dict[str, Any]] = field(default_factory=list)
    machines: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    statuses: dict[str, str] = field(default_factory=dict)


def _read_only_engine(url: URL) -> AsyncEngine:
    """An engine on the live store that cannot write.

    SQLite opens the file with ``mode=ro``, so a write raises in the driver.
    PostgreSQL sets every session read-only.
    """
    if is_postgres_url(url):
        engine = engine_for_url(url, pool_size=1)

        @event.listens_for(engine.sync_engine, "connect")
        def _read_only(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            cursor.close()

        return engine
    path = urllib.parse.quote(str(Path(str(url.database)).resolve()))
    return create_async_engine(f"{SQLITE_DRIVER}:///file:{path}?mode=ro&uri=true")


def _live_url(settings: Any) -> URL:
    try:
        url = store_url(settings)
    except StoreUrlError as exc:
        raise ReplayRefused(str(exc)) from None
    if not is_postgres_url(url) and not Path(str(url.database)).is_file():
        raise ReplayRefused(f"the live store {url.database} does not exist.")
    return url


def _settings_cidrs(settings: Any) -> list[Any]:
    import ipaddress  # noqa: PLC0415 - lazy

    return [
        ipaddress.ip_network(str(net), strict=False)
        for net in getattr(settings, "internal_cidrs", ())
    ]


async def census_size(settings: Any) -> tuple[int, int]:
    """How many addresses and agent names the live census holds. Read-only."""
    engine = _read_only_engine(_live_url(settings))
    try:
        async with make_sessionmaker(engine)() as db:
            addresses = int(await db.scalar(select(func.count(HostDossier.id))) or 0)
            names = int(
                await db.scalar(
                    select(func.count(HostMachine.id)).where(HostMachine.agent_name.is_not(None))
                )
                or 0
            )
    finally:
        await engine.dispose()
    return addresses, names


async def read_live_estate(settings: Any, *, census: bool) -> LiveEstate:
    """The estate's address space, the analytic statuses and, with ``census``, the census.

    Read-only. The address space is the one the hourly loop reads: the
    configured networks, and the ones the store learned. The statuses are
    the ones the hourly loop runs the analytics at. A store that cannot be
    read leaves the configured networks and the statuses of the files, with
    a note. The census cannot fall back: ``census`` with no readable store
    raises.
    """
    from soc_ai.oracle.identifiers import effective_internal_identifiers  # noqa: PLC0415

    try:
        url = _live_url(settings)
    except ReplayRefused as exc:
        if census:
            raise ReplayRefused(f"--hosts-from-census reads the live store: {exc}") from None
        return LiveEstate(
            cidrs=_settings_cidrs(settings),
            notes=[f"The live store was not read: {exc} {_FALLBACK}"],
        )

    engine = _read_only_engine(url)
    try:
        async with make_sessionmaker(engine)() as db:
            identifiers = await effective_internal_identifiers(db, settings)
            estate = LiveEstate(cidrs=list(identifiers.cidrs))
            estate.statuses = await _live_statuses(db, estate.notes)
            if census:
                estate.dossiers = [
                    dict(row)
                    for row in (
                        await db.execute(
                            select(
                                HostDossier.id,
                                HostDossier.host_key,
                                HostDossier.ip,
                                HostDossier.first_seen,
                                HostDossier.last_seen,
                                HostDossier.machine_id,
                                HostDossier.address_kind,
                            )
                        )
                    ).mappings()
                ]
                estate.fields = [
                    dict(row)
                    for row in (
                        await db.execute(
                            select(
                                HostDossierField.dossier_id,
                                HostDossierField.field,
                                HostDossierField.inferred_value,
                                HostDossierField.inferred_confidence,
                                HostDossierField.inferred_source,
                                HostDossierField.inferred_retracted_at,
                                HostDossierField.operator_value,
                                HostDossierField.operator_set_at,
                            ).where(HostDossierField.field.in_(("role", "hostname")))
                        )
                    ).mappings()
                ]
                estate.machines = [
                    dict(row)
                    for row in (
                        await db.execute(
                            select(
                                HostMachine.id,
                                HostMachine.machine_key,
                                HostMachine.name,
                                HostMachine.name_source,
                                HostMachine.primary_ip,
                                HostMachine.agent_id,
                                HostMachine.agent_name,
                                HostMachine.agent_last_report,
                                HostMachine.first_seen,
                                HostMachine.last_seen,
                            )
                        )
                    ).mappings()
                ]
    except Exception as exc:
        if census:
            raise ReplayRefused(
                f"--hosts-from-census could not read the live store: {exc}"
            ) from None
        return LiveEstate(
            cidrs=_settings_cidrs(settings),
            notes=[f"The live store was not read: {exc}. {_FALLBACK}"],
        )
    finally:
        await engine.dispose()
    return estate


_FALLBACK = (
    "The networks come from the settings. Each analytic runs at the status that its file "
    "ships with."
)


async def _live_statuses(db: Any, notes: list[str]) -> dict[str, str]:
    """The status of each shipped analytic, read the way the hourly loop reads it.

    The effective catalog holds the one rule: a shipped state row speaks for
    the analytic, and with no row the file decides. It is read with no seed,
    so it writes nothing. A failure leaves the statuses of the files, with a
    note.
    """
    from soc_ai.hunting.catalog_tiers import effective_catalog  # noqa: PLC0415 - lazy

    try:
        catalog = await effective_catalog(db)
    except Exception as exc:
        await db.rollback()
        notes.append(
            f"The analytic statuses were not read: {exc}. Each analytic runs at the status "
            "that its file ships with."
        )
        return {}
    return {
        analytic: status for analytic, (tier, status) in catalog.tiers.items() if tier == "shipped"
    }


async def _seed_census(maker: async_sessionmaker[Any], estate: LiveEstate) -> None:
    """Copy the census into the scratch store, ids and all. The scratch store is empty."""
    async with maker() as db:
        for model, rows in (
            (HostMachine, estate.machines),
            (HostDossier, estate.dossiers),
            (HostDossierField, estate.fields),
        ):
            for start in range(0, len(rows), _SEED_CHUNK):
                await db.execute(insert(model), rows[start : start + _SEED_CHUNK])
        await db.commit()


# ---------------------------------------------------------------------------
# The replay
# ---------------------------------------------------------------------------


class _ReplaySettings:
    """The install's settings, with the profile build switched on.

    The build is off by default and returns at once when it is off. A replay
    measures the detectors. It builds the profiles whatever the setting says.
    """

    entity_profiles_enabled = True

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


@dataclass
class AnalyticRow:
    """One analytic's line of the report.

    ``dimension`` is set for a profile analytic, ``detector`` for a model
    analytic. ``status`` is the status the analytic ran at. ``folded_states``
    counts the detector states that the four state columns hold under another
    name, by the name of the detector state.
    """

    analytic: str
    dimension: str
    evaluator: str = "profile"
    status: str = "live"
    detector: str = ""
    host_days: int = 0
    hits: int = 0
    per_100_host_days: float | None = None
    wilson_upper_95_per_100: float | None = None
    verdict: str = NOT_MEASURED
    observations: int = 0
    sightings: int = 0
    leads: int = 0
    measured: int = 0
    learning: int = 0
    blind: int = 0
    not_applicable: int = 0
    folded_states: dict[str, int] = field(default_factory=dict)
    capped_hours: int = 0
    top_hosts: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DayRow:
    """One replayed day: the build, the sweeps, their cost."""

    day: int
    start: str
    build_seconds: float = 0.0
    build_searches: int = 0
    build_rows: int = 0
    sweep_seconds: float = 0.0
    sweep_searches: int = 0
    hours_unread: int = 0
    hits: int = 0
    build_errors: list[str] = field(default_factory=list)


@dataclass
class ReplayReport:
    """Everything one replay concluded. ``to_dict`` is ``report.json``."""

    start: str
    end: str
    days: int
    hours: int
    store: str
    analytics: list[AnalyticRow]
    day_rows: list[DayRow]
    unread_hours: list[dict[str, Any]]
    hits: int = 0
    host_days: int = 0
    estate_host_days: int = 0
    observations: int = 0
    sightings: int = 0
    leads: int = 0
    fleet_conditions: int = 0
    searches: int = 0
    seconds: float = 0.0
    verdict: str = NOT_MEASURED
    notes: list[str] = field(default_factory=list)

    @property
    def per_100_host_days(self) -> float | None:
        return _per_100(self.hits, self.host_days)

    @property
    def wilson_upper_95_per_100(self) -> float | None:
        return _upper_per_100(self.hits, self.host_days)

    @property
    def exit_code(self) -> int:
        """5 when the measurement is incomplete, 3 over budget, 4 too few host-days, else 0."""
        if self.unread_hours or self.verdict == NOT_MEASURED:
            return 5
        if self.verdict == OVER:
            return 3
        return 4 if self.verdict == TOO_FEW else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "window": {
                "start": self.start,
                "end": self.end,
                "days": self.days,
                "hours": self.hours,
            },
            "budget_per_100_host_days": BUDGET_PER_100_HOST_DAYS,
            "host_days_needed_with_no_hit": host_days_needed(),
            "verdict": self.verdict,
            "totals": {
                "hits": self.hits,
                "host_days": self.host_days,
                "per_100_host_days": self.per_100_host_days,
                "wilson_upper_95_per_100": self.wilson_upper_95_per_100,
                "estate_host_days": self.estate_host_days,
                "observations": self.observations,
                "sightings": self.sightings,
                "leads": self.leads,
                "fleet_conditions": self.fleet_conditions,
                "searches": self.searches,
                "seconds": round(self.seconds, 3),
                "hours_unread": len(self.unread_hours),
            },
            "analytics": [asdict(row) for row in self.analytics],
            "days": [asdict(row) for row in self.day_rows],
            "unread_hours": list(self.unread_hours),
            "store": self.store,
            "notes": list(self.notes),
        }


def _naive(at: datetime) -> datetime:
    return at.astimezone(UTC).replace(tzinfo=None)


def _short(text: str) -> str:
    return text if len(text) <= _ERROR_CHARS else text[: _ERROR_CHARS - 3] + "..."


def _capped(row: AnalyticRow, notes: set[str]) -> bool:
    """Whether a read of the analytic stopped at its entity ceiling on this sweep.

    The recent read of a profile dimension writes one note for the dimension.
    A detector writes its own note, under the id of its analytic.
    """
    if row.dimension:
        return _ceiling_note(row.dimension) in notes
    prefix = f"{row.analytic}: "
    return bool(row.detector) and any(
        note.startswith(prefix) and _DETECTOR_CEILING in note for note in notes
    )


class _Tally:
    """The counters of one replay. Per-day host sets only; nothing per hour survives."""

    def __init__(
        self, specs: Mapping[str, HuntSpec], statuses: Mapping[str, str] | None = None
    ) -> None:
        self.rows = {
            spec_id: AnalyticRow(
                analytic=spec_id,
                dimension=spec.profile.dimension if spec.profile is not None else "",
                evaluator=str(spec.evaluator),
                status=(statuses or {}).get(spec_id, spec.ships_as),
                detector=_detector(spec),
            )
            for spec_id, spec in specs.items()
        }
        self.sources = sorted({_SOURCES[row.evaluator] for row in self.rows.values()})
        self.host_hits: Counter[tuple[str, str]] = Counter()
        self.unread: list[dict[str, Any]] = []
        self.estate_host_days = 0
        self._day: dict[str, set[str]] = {spec_id: set() for spec_id in specs}

    def sweep(self, sweep: Any, hour: datetime) -> None:
        """Count the states of one sweep and the hosts it measured.

        One rule folds the seven detector states into the four columns: the
        trail's, which the ledger reads too. Held is measured. Unmeasurable,
        stale and drifted are blind. A held machine counts as a host-day.
        """
        for result in sweep.results:
            row = self.rows.get(result.spec_id)
            if row is None:
                continue
            state = result.trail_state
            setattr(row, state, getattr(row, state) + 1)
            if result.coverage != state:
                row.folded_states[result.coverage] = row.folded_states.get(result.coverage, 0) + 1
            if state == COVERAGE_MEASURED and result.entity_key != "*":
                self._day[result.spec_id].add(str(result.entity_key))
        notes = set(sweep.notes)
        for row in self.rows.values():
            if _capped(row, notes):
                row.capped_hours += 1
        if sweep.errors:
            self.unread_hour(hour, list(sweep.errors))

    def unread_hour(self, hour: datetime, errors: Sequence[str]) -> None:
        self.unread.append(
            {"hour": hour.isoformat(), "errors": [_short(e) for e in errors[:_ERRORS_KEPT]]}
        )

    async def close_day(
        self, maker: async_sessionmaker[Any], start: datetime, end: datetime
    ) -> int:
        """Read the day's hits back from the store and fold the day's host sets."""
        async with maker() as db:
            pairs = (
                await db.execute(
                    select(EntityObservation.spec_id, EntityObservation.entity_key)
                    .where(
                        EntityObservation.source.in_(self.sources),
                        EntityObservation.born_at >= _naive(start),
                        EntityObservation.born_at < _naive(end),
                    )
                    .distinct()
                )
            ).all()
        hits = 0
        for spec_id, key in pairs:
            row = self.rows.get(str(spec_id))
            if row is None:
                continue
            row.hits += 1
            hits += 1
            self.host_hits[(str(spec_id), str(key))] += 1
            # A host the analytic fired on was measured that day.
            self._day[str(spec_id)].add(str(key))
        estate: set[str] = set()
        for spec_id, hosts in self._day.items():
            self.rows[spec_id].host_days += len(hosts)
            estate |= hosts
            hosts.clear()
        self.estate_host_days += len(estate)
        return hits


@dataclass
class _Run:
    """What every replayed day of one run shares."""

    maker: async_sessionmaker[Any]
    grid: CountingGrid
    settings: _ReplaySettings
    specs: dict[str, HuntSpec]
    cidrs: list[Any]
    tally: _Tally
    # The analytics that write shadow observations, as on the live install.
    shadow_ids: frozenset[str] = frozenset()
    # The profile build runs only when a profile analytic reads its baselines.
    build: bool = True

    async def day(self, number: int, start: datetime) -> tuple[DayRow, StageClock]:
        """The build at the start of the day, then one sweep at each hour."""
        day = DayRow(day=number, start=start.isoformat())
        clock = StageClock(label=f"spec replay day {number}", grid=self.grid, logger=_LOGGER)
        if self.build:
            with clock.stage("build") as stage:
                build = await build_profiles(
                    self.grid, self.maker, self.settings, self.cidrs, now=start
                )
                stage.detail = f"{build.written} rows, {len(build.errors)} errors"
            day.build_rows = build.written
            day.build_errors = [_short(e) for e in build.errors[:_ERRORS_KEPT]]
        unread_before = len(self.tally.unread)
        with clock.stage("sweeps") as stage:
            for offset in range(24):
                await self.hour(start + timedelta(hours=offset))
            day.hours_unread = len(self.tally.unread) - unread_before
            stage.detail = f"{24 - day.hours_unread} of 24 hours read"
        day.hits = await self.tally.close_day(self.maker, start, start + timedelta(days=1))
        for done in clock.stages:
            if done.name == "build":
                day.build_seconds, day.build_searches = round(done.seconds, 3), done.searches
            else:
                day.sweep_seconds, day.sweep_searches = round(done.seconds, 3), done.searches
        return day, clock

    async def hour(self, hour: datetime) -> None:
        """One sweep at ``hour``. A sweep that raises marks the hour unread."""
        try:
            async with self.maker() as db:
                sweep = await run_prior_sweep(
                    elastic=self.grid,
                    settings=self.settings,
                    db=db,
                    catalog=self.specs,
                    record=True,
                    cidrs=self.cidrs,
                    shadow_ids=self.shadow_ids,
                    now=hour,
                )
                await db.commit()
        except Exception as exc:
            self.tally.unread_hour(hour, [f"{type(exc).__name__}: {exc}"])
            return
        self.tally.sweep(sweep, hour)


async def run_replay(
    grid: Any,
    settings: Any,
    plan: ReplayPlan,
    *,
    estate: LiveEstate,
    catalog: Mapping[str, HuntSpec] | None = None,
) -> ReplayReport:
    """Run the plan against ``grid`` into the scratch store and return the report.

    Never writes outside ``plan.store``. A sweep that reports an error, or
    raises, marks its hour unread, and the replay goes on to the next hour.
    A build error is kept on its day, and the sweeps of the day run on the
    profiles the store holds.

    The replay runs the evaluators of the plan. The notes name the
    evaluators it ran, the analytics each covers and the analytics it left
    out. Each analytic runs at its status on the live install. An analytic
    that is not live writes shadow observations, as the hourly loop writes
    them, and the report counts a shadow hit as a hit.
    """
    full = dict(catalog) if catalog is not None else load_catalog(CATALOG_DIR)
    shipped = replay_analytics(full, plan.evaluators)
    specs = {spec_id: shipped[spec_id] for spec_id in plan.analytics}
    statuses = {a: estate.statuses.get(a, spec.ships_as) for a, spec in specs.items()}
    shadow_ids = frozenset(a for a, status in statuses.items() if status != "live")
    make_private_dir(plan.store.parent)
    engine = engine_for_url(make_url(f"{SQLITE_DRIVER}:///{plan.store}"))
    counted = counting(grid)
    day_rows: list[DayRow] = []
    seconds = 0.0
    try:
        await run_migrations(engine)
        run = _Run(
            maker=make_sessionmaker(engine),
            grid=counted,
            settings=_ReplaySettings(settings),
            specs=specs,
            cidrs=list(estate.cidrs),
            tally=_Tally(specs, statuses),
            shadow_ids=shadow_ids,
            build=bool(plan.builds),
        )
        if plan.hosts_from_census:
            await _seed_census(run.maker, estate)
        for number, day_start in enumerate(plan.day_starts(), start=1):
            day, clock = await run.day(number, day_start)
            seconds += clock.total_seconds
            day_rows.append(day)
            _LOGGER.info(
                "spec replay day %d of %d: %d hits, %d searches, %.1f s",
                number,
                plan.days,
                day.hits,
                clock.total_searches,
                clock.total_seconds,
            )
        report = await _report(run.maker, plan, run.tally, day_rows)
    finally:
        await engine.dispose()
    report.searches = counted.searches
    report.seconds = seconds
    report.notes.extend(evaluator_notes(full, plan.analytics, plan.evaluators))
    shadow = sorted(shadow_ids)
    if shadow:
        report.notes.append(
            f"{_count(len(shadow), 'analytic')} ran in shadow, as on the live install: "
            f"{', '.join(shadow)}. Each wrote shadow observations. The replay counts a shadow "
            "hit as a hit."
        )
    report.notes.extend(estate.notes)
    return report


def _catalog_ids(catalog: Mapping[str, HuntSpec]) -> dict[str, list[str]]:
    """The ids of the catalog, by evaluator. A replay evaluator holds the analytics it runs."""
    out: dict[str, list[str]] = {}
    for spec_id, spec in sorted(catalog.items()):
        evaluator = str(spec.evaluator)
        if evaluator in REPLAY_EVALUATORS and not _runs_on(spec, evaluator):
            continue
        out.setdefault(evaluator, []).append(spec_id)
    return out


def _left_out_notes(
    catalog: Mapping[str, HuntSpec],
    ran: Sequence[str],
    evaluators: Sequence[str] = REPLAY_EVALUATORS,
) -> list[str]:
    """The analytics of the catalog that the replay leaves out, and why, by evaluator."""
    by_evaluator = _catalog_ids(catalog)
    chosen = set(ran)
    notes: list[str] = []
    for evaluator in REPLAY_EVALUATORS:
        ids = by_evaluator.pop(evaluator, [])
        if not ids:
            continue
        if evaluator not in evaluators:
            notes.append(
                f"The replay leaves out the {evaluator} evaluator: {', '.join(ids)}. "
                "--evaluator does not name it. The report holds no rate for them."
            )
            continue
        unnamed = [a for a in ids if a not in chosen]
        if unnamed:
            notes.append(
                f"The replay leaves out {_count(len(unnamed), f'{evaluator} analytic')} that "
                f"--analytic does not name: {', '.join(unnamed)}."
            )
    for evaluator, ids in sorted(by_evaluator.items()):
        runner = " The catalog sweep runs them." if evaluator == "match" else ""
        notes.append(
            f"The replay leaves out the {evaluator} evaluator: {_count(len(ids), 'analytic')}."
            f"{runner} The report holds no rate for them."
        )
    return notes


def evaluator_notes(
    catalog: Mapping[str, HuntSpec],
    ran: Sequence[str],
    evaluators: Sequence[str] = REPLAY_EVALUATORS,
) -> list[str]:
    """The evaluators the replay runs, the analytics each covers, and what it leaves out.

    The replay ran the ``profile`` analytics and its report said nothing of
    the two ``model`` analytics. An operator read the verdict as the verdict
    of every learned detector. Each evaluator now has its own line.
    """
    by_evaluator = _catalog_ids(catalog)
    chosen = set(ran)
    notes = []
    for evaluator in REPLAY_EVALUATORS:
        if evaluator not in evaluators:
            continue
        covered = [a for a in by_evaluator.get(evaluator, []) if a in chosen]
        names = f": {', '.join(covered)}" if covered else ""
        notes.append(
            f"The replay runs the {evaluator} evaluator on "
            f"{_count(len(covered), 'analytic')}{names}."
        )
    return notes + _left_out_notes(catalog, ran, evaluators)


def fold_verdicts(rows: Sequence[AnalyticRow]) -> tuple[str, list[str]]:
    """The verdict of the whole replay from the verdicts of its rows, and its notes.

    Not measured when no row measured a host. Over budget when one row is
    over. Not enough host-days when one row is short and none is over.
    Within budget only when every measured row is.
    """
    measured = [row for row in rows if row.verdict != NOT_MEASURED]
    if not measured:
        verdict = NOT_MEASURED
    elif any(row.verdict == OVER for row in measured):
        verdict = OVER
    elif any(row.verdict == TOO_FEW for row in measured):
        verdict = TOO_FEW
    else:
        verdict = WITHIN
    notes: list[str] = []
    silent = [row.analytic for row in rows if row.verdict == NOT_MEASURED]
    if silent and measured:
        notes.append(
            f"No host-day was measured for {', '.join(silent)}. "
            "The verdict holds for the other analytics only."
        )
    short = [row.analytic for row in rows if row.verdict == TOO_FEW]
    if short:
        notes.append(_too_few_note(short))
    return verdict, notes


async def _report(
    maker: async_sessionmaker[Any],
    plan: ReplayPlan,
    tally: _Tally,
    day_rows: list[DayRow],
) -> ReplayReport:
    """Fold the counters and read the observations and the leads back from the store."""
    async with maker() as db:
        per_spec = (
            await db.execute(
                select(
                    EntityObservation.spec_id,
                    func.count(EntityObservation.id),
                    func.coalesce(func.sum(EntityObservation.occurrences), 0),
                    func.count(func.distinct(EntityObservation.lead_id)),
                )
                .where(EntityObservation.source.in_(tally.sources))
                .group_by(EntityObservation.spec_id)
            )
        ).all()
        leads = dict(
            (await db.execute(select(Lead.status, func.count(Lead.id)).group_by(Lead.status))).all()
        )
    for spec_id, rows, sightings, lead_count in per_spec:
        row = tally.rows.get(str(spec_id))
        if row is None:
            continue
        row.observations = int(rows)
        row.sightings = int(sightings)
        row.leads = int(lead_count)

    by_spec: dict[str, list[tuple[str, int]]] = {}
    for (spec_id, host), count in tally.host_hits.items():
        by_spec.setdefault(spec_id, []).append((host, count))
    for row in tally.rows.values():
        row.per_100_host_days = _per_100(row.hits, row.host_days)
        row.wilson_upper_95_per_100 = _upper_per_100(row.hits, row.host_days)
        row.verdict = _verdict(row.hits, row.host_days)
        ranked = sorted(by_spec.get(row.analytic, []), key=lambda pair: (-pair[1], pair[0]))
        row.top_hosts = [{"host": host, "hits": count} for host, count in ranked[:_TOP_HOSTS]]

    rows = list(tally.rows.values())
    verdict, notes = fold_verdicts(rows)
    return ReplayReport(
        start=plan.start.isoformat(),
        end=plan.end.isoformat(),
        days=plan.days,
        hours=plan.hours,
        store=str(plan.store),
        analytics=rows,
        day_rows=day_rows,
        unread_hours=list(tally.unread),
        hits=sum(row.hits for row in rows),
        host_days=sum(row.host_days for row in rows),
        estate_host_days=tally.estate_host_days,
        observations=sum(row.observations for row in rows),
        sightings=sum(row.sightings for row in rows),
        leads=int(sum(leads.values())),
        fleet_conditions=int(leads.get("fleet_condition", 0)),
        verdict=verdict,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


def _num(value: float | None) -> str:
    return "none" if value is None else f"{value:.2f}"


def _too_few_note(analytics: Sequence[str]) -> str:
    """What the report says about the analytics with too few host-days."""
    return (
        f"Not enough host-days for {', '.join(analytics)}. Each Wilson upper bound is over "
        f"the budget. A within-budget verdict needs {host_days_needed()} host-days with no hit. "
        "Replay more days, or more hosts."
    )


def render_markdown(report: ReplayReport) -> str:
    """``report.md``: the verdict first, then the tables. Table cells may be fragments."""
    lines = [
        "# Tier 2 replay report",
        "",
        f"Verdict: {report.verdict}. The budget is {BUDGET_PER_100_HOST_DAYS:g} hit per 100 "
        "host-days for each analytic.",
        "",
        "Within budget needs the Wilson upper bound at or under the budget. Over budget is a "
        f"rate over the budget. With no hit, within budget needs {host_days_needed()} host-days.",
        "",
        "A shadow hit counts as a hit. An analytic in shadow writes shadow observations, as it "
        "does on the live install. The Status column gives the status of each analytic.",
        "",
    ]
    if report.unread_hours:
        lines += [
            f"The replay could not read {len(report.unread_hours)} of {report.hours} hours. "
            "The verdict holds for the hours read only. The hours are in the last table.",
            "",
        ]
    lines += [
        "## Summary",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Window start | {report.start} |",
        f"| Window end | {report.end} |",
        f"| Replayed days | {report.days} |",
        f"| Hours swept | {report.hours} |",
        f"| Hours unread | {len(report.unread_hours)} |",
        f"| Hits | {report.hits} |",
        f"| Analytic host-days | {report.host_days} |",
        f"| Hits per 100 analytic host-days | {_num(report.per_100_host_days)} |",
        f"| Wilson 95 percent upper bound per 100 | {_num(report.wilson_upper_95_per_100)} |",
        f"| Estate host-days | {report.estate_host_days} |",
        f"| Observations in the store | {report.observations} |",
        f"| Sightings | {report.sightings} |",
        f"| Leads formed | {report.leads} |",
        f"| Fleet conditions | {report.fleet_conditions} |",
        f"| Searches | {report.searches} |",
        f"| Wall time, seconds | {report.seconds:.1f} |",
        f"| Scratch store | `{report.store}` |",
        "",
        "## Analytics",
        "",
        "| Analytic | Evaluator | Status | Dimension or detector | Host-days | Hits | Per 100 "
        "| Wilson upper per 100 | Verdict | Observations | Leads | Measured | Learning | Blind "
        "| Not applicable | Folded states | Capped hours |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in report.analytics:
        lines.append(
            f"| `{row.analytic}` | {row.evaluator} | {row.status} "
            f"| {row.dimension or row.detector} | {row.host_days} | {row.hits} "
            f"| {_num(row.per_100_host_days)} | {_num(row.wilson_upper_95_per_100)} "
            f"| {row.verdict} | {row.observations} | {row.leads} | {row.measured} "
            f"| {row.learning} | {row.blind} | {row.not_applicable} "
            f"| {_folded(row.folded_states)} | {row.capped_hours} |"
        )
    lines += ["", "## Hosts with the most hits", ""]
    ranked = [row for row in report.analytics if row.top_hosts]
    if not ranked:
        lines += ["No analytic recorded a hit.", ""]
    for row in ranked:
        lines += [f"### {row.analytic}", "", "| Host | Hits |", "|---|---|"]
        lines += [f"| {entry['host']} | {entry['hits']} |" for entry in row.top_hosts]
        lines.append("")
    lines += [
        "## Days",
        "",
        "| Day | Start | Build seconds | Build searches | Rows built | Sweep seconds "
        "| Sweep searches | Hits | Hours unread | Build errors |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for day in report.day_rows:
        errors = "; ".join(day.build_errors) if day.build_errors else "none"
        lines.append(
            f"| {day.day} | {day.start} | {day.build_seconds:.1f} | {day.build_searches} "
            f"| {day.build_rows} | {day.sweep_seconds:.1f} | {day.sweep_searches} | {day.hits} "
            f"| {day.hours_unread} | {_cell(errors)} |"
        )
    lines += ["", "## Unread hours", ""]
    if not report.unread_hours:
        lines.append("The replay read every hour.")
    else:
        lines += ["| Hour | Error |", "|---|---|"]
        for entry in report.unread_hours:
            lines.append(f"| {entry['hour']} | {_cell('; '.join(entry['errors']))} |")
    if report.notes:
        lines += ["", "## Notes", ""]
        lines += [f"- {note}" for note in report.notes]
    lines += [
        "",
        "## Definitions",
        "",
        "- A host-day is one host on one replayed day that the analytic measured at least once.",
        "- For a model analytic, the host is the machine that the detector names.",
        "- A hit is one host on one replayed day on which the analytic recorded a new "
        "observation or a new sighting of an existing one. A re-read of the same documents "
        "is no hit.",
        "- A shadow hit is a hit. The replay counts the observations of an analytic in shadow "
        "the same way as the observations of a live analytic.",
        "- The rate is hits per 100 host-days. The Wilson bound is the upper end of the "
        "95 percent interval of that rate.",
        "- Measured, learning, blind and not applicable count host-hours. Capped hours count "
        "the hours on which a read of the analytic stopped at its entity ceiling.",
        "- A model analytic has seven states. The report folds them into four, as the ledger "
        "does. Held counts as measured. Unmeasurable, stale and drifted count as blind. "
        "Folded states gives the host-hours of each folded state.",
        "- Estate host-days count each host key that an analytic measured on a day. An address "
        "and a machine name are two keys.",
        "",
    ]
    return "\n".join(lines)


def _folded(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{state} {n}" for state, n in sorted(counts.items())) or "none"


def _count(value: int, noun: str) -> str:
    return f"{value} {noun if value == 1 else noun + 's'}"


def _cell(text: str) -> str:
    return text.replace("|", "/").replace("\n", " ")


def write_report(report: ReplayReport, out: Path) -> tuple[Path, Path]:
    """Write ``report.json`` and ``report.md`` into ``out``. Returns both paths."""
    make_private_dir(out)
    json_path = out / "report.json"
    md_path = out / "report.md"
    json_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    # The report names hosts and their hits. Only the service user reads it.
    restrict_file(json_path)
    restrict_file(md_path)
    return json_path, md_path


def summary_lines(report: ReplayReport) -> list[str]:
    """What the command prints when the replay ends."""
    lines = [
        f"Verdict: {report.verdict}. The budget is {BUDGET_PER_100_HOST_DAYS:g} hit per 100 "
        "host-days for each analytic.",
        f"Total: {_count(report.hits, 'hit')} in {report.host_days} analytic host-days. "
        f"Rate per 100: {_num(report.per_100_host_days)}. "
        f"Wilson upper bound per 100: {_num(report.wilson_upper_95_per_100)}.",
    ]
    for row in report.analytics:
        lines.append(
            f"  {row.analytic} [{row.evaluator}, {row.status}]: {_count(row.hits, 'hit')} in "
            f"{row.host_days} host-days, {_num(row.per_100_host_days)} per 100, "
            f"Wilson upper {_num(row.wilson_upper_95_per_100)}, {row.verdict}"
        )
    if any(row.verdict == TOO_FEW for row in report.analytics):
        lines.append(f"A within-budget verdict needs {host_days_needed()} host-days with no hit.")
    if report.unread_hours:
        lines.append(f"Unread hours: {len(report.unread_hours)} of {report.hours}.")
    lines.append(f"Searches: {report.searches}. Wall time: {report.seconds:.1f} s.")
    return lines
