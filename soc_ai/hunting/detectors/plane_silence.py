"""Detector 1: one telemetry plane of a machine stops while another keeps going.

An attacker who kills an endpoint agent leaves the network sensor running.
An agent that stops shipping its process events still ships its host logs.
The tier 2 collapse analytic reads one plane at a time, so it cannot tell a
silenced agent from a machine that is switched off, and it fired on every
machine that slept. This detector compares the planes of one machine with
each other.

**What it reads.** Per machine, the document count of each plane in each
complete hour of the recent window, and in the same hours of the week in the
earlier weeks. The planes are the six host coverage planes of
:mod:`soc_ai.dossier.coverage`, keyed by ``host.name``, and the network flows
of the sensor, keyed by the machine's own addresses. The two keys join
through the ``host.ip`` values the machine's agent reports, held to the
estate's census.

**What it learns.** For each plane, the expected count of each hour of the
week and the dispersion around it, through the seasonal residual helper of
tier 2 (:func:`soc_ai.dossier.profile_math.seasonal_from_samples`).

**When it fires.** A plane is silent in an hour when its count is at or under
``floor_share`` of the expected count, the expected count is ``min_expected``
or more, and the residual sits ``threshold`` dispersions under it. Another
plane of the same machine is live in that hour when it holds ``live_share`` of
its own expected count. ``min_silent_hours`` silent hours in a row, with one
plane live in each of them, is a hit.

**What it does not report.** A machine whose every plane fell is off or gone.
That is a coverage fact, and the hit needs a live plane. A plane that always
dips at the weekend expects nothing then and cannot fall silent. One plane
silent on most machines that ship it at once is the grid's condition, and the
detector holds those hits and says so in a note.

**What a hit cites.** The newest document of the silent plane before the end
of the silence, and a document of the live plane inside it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.dossier.coverage import PLANES, plane_dataset_clause, plane_label, planes_of
from soc_ai.dossier.profile import _dataset_clause, _scope_must_not
from soc_ai.dossier.profile_math import Seasonal, hour_of_week, seasonal_from_samples
from soc_ai.hunting.detectors.base import (
    STATE_HELD,
    STATE_LEARNING,
    STATE_MEASURED,
    STATE_UNMEASURABLE,
    STATISTIC_PLANE_DOCUMENTS,
    DetectorContext,
    DetectorRun,
    EntityState,
    ModelHit,
    complete_hours,
    hour_floor,
    iso,
    oql_stamp,
    plain_address,
)
from soc_ai.hunting.detectors.params import CrossPlaneSilenceParams
from soc_ai.hunting.estate import windows_for
from soc_ai.hunting.rerun import oql_value
from soc_ai.hunting.weight import Kind
from soc_ai.hunting.wording import plural
from soc_ai.so_client.paging import CompositeRead

__all__ = ["DETECTOR_ID", "FLOW_DATASETS", "FLOW_PLANE", "detect"]

DETECTOR_ID = "cross_plane_silence"

# The sensor's flow plane. It is the machine's traffic as the network saw it,
# so it keeps going when the machine's own agent stops. The endpoint's own
# network events are a host plane, keyed by name, and stop with the agent.
FLOW_PLANE = "network_flows"
FLOW_DATASETS: tuple[str, ...] = ("zeek.conn", "network_traffic.flow")

# Every plane in the order a sentence lists them.
_PLANE_ORDER: tuple[str, ...] = (*PLANES, FLOW_PLANE)

# How many machines one page of the host read holds, and the most one read
# holds. A page carries a dataset and an hour histogram under every machine,
# and the bucket limit is 65,536. The reader halves a refused page.
_PAGE = 100
_MAX_MACHINES = 20_000
# The most addresses one machine's agent reports that the join reads.
_MAX_ADDRESSES = 16
_MAX_DATASETS = 100


def _label(plane: str) -> str:
    return "network flows" if plane == FLOW_PLANE else plane_label(plane)


@dataclass
class _Machine:
    """One machine, as the host read named it, and its counts per plane and hour."""

    name: str
    addresses: list[str] = field(default_factory=list)
    counts: dict[str, dict[datetime, int]] = field(default_factory=dict)
    datasets: dict[str, set[str]] = field(default_factory=dict)

    def add(self, plane: str, hour: datetime, count: int, dataset: str | None) -> None:
        per_hour = self.counts.setdefault(plane, {})
        per_hour[hour] = per_hour.get(hour, 0) + count
        if dataset:
            self.datasets.setdefault(plane, set()).add(dataset)

    def planes(self) -> list[str]:
        return [p for p in _PLANE_ORDER if any(c > 0 for c in self.counts.get(p, {}).values())]


@dataclass(frozen=True)
class _Windows:
    """The recent hours and the same hours in each earlier week."""

    recent: tuple[datetime, ...]
    # slices[k - 1] holds the hours k weeks back.
    slices: tuple[tuple[datetime, ...], ...]

    @property
    def ranges(self) -> list[tuple[datetime, datetime]]:
        out = [(self.recent[0], self.recent[-1] + timedelta(hours=1))]
        out.extend((s[0], s[-1] + timedelta(hours=1)) for s in self.slices)
        return out


def _windows(params: CrossPlaneSilenceParams, now: datetime) -> _Windows:
    recent = tuple(complete_hours(hours=params.window_hours, end=now))
    week = timedelta(days=7)
    slices = tuple(tuple(h - week * k for h in recent) for k in range(1, params.baseline_weeks + 1))
    return _Windows(recent=recent, slices=slices)


def _time_clause(windows: _Windows) -> dict[str, Any]:
    return {
        "bool": {
            "should": [
                {"range": {"@timestamp": {"gte": iso(a), "lt": iso(b)}}} for a, b in windows.ranges
            ],
            "minimum_should_match": 1,
        }
    }


def _stamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


def _hours_of(bucket: Any) -> list[tuple[datetime, int]]:
    rows = ((bucket.get("per_hour") or {}).get("buckets")) if isinstance(bucket, dict) else None
    out: list[tuple[datetime, int]] = []
    for row in rows or ():
        at = _stamp(row.get("key_as_string")) if isinstance(row, dict) else None
        if at is not None:
            out.append((hour_floor(at), int(row.get("doc_count") or 0)))
    return out


def _per_hour() -> dict[str, Any]:
    return {
        "date_histogram": {"field": "@timestamp", "calendar_interval": "hour", "min_doc_count": 1}
    }


async def _read_hosts(
    ctx: DetectorContext, windows: _Windows, notes: list[str]
) -> dict[str, _Machine]:
    """Every machine that ships a host plane, with its counts per plane and hour."""
    query = {
        "bool": {
            "filter": [
                _time_clause(windows),
                plane_dataset_clause(),
                {"exists": {"field": "host.name"}},
            ],
            "must_not": _scope_must_not(),
        }
    }
    aggs = {
        "datasets": {
            "terms": {"field": "event.dataset", "size": _MAX_DATASETS},
            "aggs": {"per_hour": _per_hour()},
        },
        "addresses": {"terms": {"field": "host.ip", "size": _MAX_ADDRESSES}},
    }
    reader = CompositeRead(
        ctx.elastic,
        ctx.index,
        query,
        name="plane_hosts",
        field="host.name",
        aggs=aggs,
        page_size=_PAGE,
        ceiling=_MAX_MACHINES,
    )
    machines: dict[str, _Machine] = {}
    async for page in reader.pages():
        for bucket in page:
            name = bucket.get("key")
            if not isinstance(name, str) or not name.strip():
                continue
            machine = machines.setdefault(name.casefold(), _Machine(name=name))
            for ds in ((bucket.get("datasets") or {}).get("buckets")) or ():
                dataset = ds.get("key") if isinstance(ds, dict) else None
                if not isinstance(dataset, str):
                    continue
                for plane in planes_of(dataset):
                    for hour, count in _hours_of(ds):
                        machine.add(plane, hour, count, dataset)
            for row in ((bucket.get("addresses") or {}).get("buckets")) or ():
                address = plain_address(row.get("key")) if isinstance(row, dict) else None
                if address and ctx.in_estate(address) and address not in machine.addresses:
                    machine.addresses.append(address)
    if reader.capped:
        notes.append(
            f"the host read stopped at the ceiling of {_MAX_MACHINES:,} machines. "
            "The detector did not score the machines past the ceiling."
        )
    # An address two machines report belongs to neither. Every Docker host
    # reports the same bridge gateway.
    owners: dict[str, int] = {}
    for machine in machines.values():
        for address in machine.addresses:
            owners[address] = owners.get(address, 0) + 1
    for machine in machines.values():
        machine.addresses = sorted(a for a in machine.addresses if owners[a] == 1)
    return machines


async def _read_flows(
    ctx: DetectorContext, windows: _Windows, machines: dict[str, _Machine]
) -> None:
    """Add the sensor's flow counts to each machine, by the machine's own addresses."""
    by_address = {a: m for m in machines.values() for a in m.addresses}
    if not by_address:
        return
    query = {
        "bool": {
            "filter": [
                _time_clause(windows),
                {
                    "bool": {
                        "should": [_dataset_clause(d) for d in FLOW_DATASETS],
                        "minimum_should_match": 1,
                    }
                },
                {"terms": {"source.ip": sorted(by_address)}},
            ],
            "must_not": _scope_must_not(),
        }
    }
    reader = CompositeRead(
        ctx.elastic,
        ctx.index,
        query,
        name="plane_flows",
        field="source.ip",
        aggs={"per_hour": _per_hour()},
        page_size=_PAGE * 5,
        ceiling=len(by_address),
    )
    async for page in reader.pages():
        for bucket in page:
            machine = by_address.get(str(bucket.get("key") or ""))
            if machine is None:
                continue
            for hour, count in _hours_of(bucket):
                machine.add(FLOW_PLANE, hour, count, None)
    for machine in machines.values():
        if FLOW_PLANE in machine.counts:
            machine.datasets[FLOW_PLANE] = set(FLOW_DATASETS)


@dataclass(frozen=True)
class _Plane:
    """One plane of one machine, as the score reads it."""

    plane: str
    seasonal: Seasonal | None
    history_days: float
    recent: dict[datetime, int]

    def expected(self, hour: datetime, tz: str) -> tuple[float | None, float | None]:
        if self.seasonal is None:
            return None, None
        how = hour_of_week(hour, tz=tz)
        return self.seasonal.expected[how], self.seasonal.sigma(how)


def _plane(
    machine: _Machine,
    plane: str,
    windows: _Windows,
    *,
    now: datetime,
    tz: str,
    exclude: Sequence[tuple[datetime, datetime]],
) -> _Plane:
    """The learned baseline of one plane, from the same hours in earlier weeks.

    An hour with no document inside a week the plane already shipped in is a
    count of zero. The weeks before the plane's first document are not
    filled: the plane may not have existed then.
    """
    counts = machine.counts.get(plane, {})
    with_data = [
        k for k, hours in enumerate(windows.slices, 1) if any(counts.get(h) for h in hours)
    ]
    samples: list[tuple[datetime, float]] = []
    oldest: datetime | None = None
    if with_data:
        for hours in windows.slices[: max(with_data)]:
            samples.extend((h, float(counts.get(h, 0))) for h in hours)
        seen = [h for hours in windows.slices for h in hours if counts.get(h)]
        oldest = min(seen)
    seasonal = seasonal_from_samples(samples, tz=tz, exclude=exclude) if samples else None
    history = (now - oldest).total_seconds() / 86400.0 if oldest is not None else 0.0
    return _Plane(
        plane=plane,
        seasonal=seasonal,
        history_days=history,
        recent={h: counts.get(h, 0) for h in windows.recent},
    )


@dataclass(frozen=True)
class _Silence:
    """A run of hours in which one plane was silent and another was live."""

    silent: str
    live: str
    hours: tuple[datetime, ...]
    silent_count: int
    silent_expected: float
    live_count: int
    live_expected: float


def _silent(p: _Plane, hour: datetime, params: CrossPlaneSilenceParams, tz: str) -> bool:
    expected, sigma = p.expected(hour, tz)
    if expected is None or sigma is None or expected < params.min_expected:
        return False
    count = p.recent.get(hour, 0)
    return (
        count <= params.floor_share * expected and (count - expected) / sigma <= -params.threshold
    )


def _live(p: _Plane, hour: datetime, params: CrossPlaneSilenceParams, tz: str) -> bool:
    expected, _sigma = p.expected(hour, tz)
    if expected is None:
        return False
    count = p.recent.get(hour, 0)
    return count > 0 and count >= params.live_share * expected


def _silences(
    planes: list[_Plane], hours: Sequence[datetime], params: CrossPlaneSilenceParams, tz: str
) -> list[_Silence]:
    """The longest run per silent plane, with the live plane that held it best."""
    out: list[_Silence] = []
    for silent in planes:
        best: _Silence | None = None
        for live in planes:
            if live.plane == silent.plane:
                continue
            run: list[datetime] = []
            runs: list[list[datetime]] = []
            for hour in hours:
                if _silent(silent, hour, params, tz) and _live(live, hour, params, tz):
                    run.append(hour)
                elif run:
                    runs.append(run)
                    run = []
            if run:
                runs.append(run)
            for one in runs:
                if len(one) < params.min_silent_hours:
                    continue
                candidate = _Silence(
                    silent=silent.plane,
                    live=live.plane,
                    hours=tuple(one),
                    silent_count=sum(silent.recent.get(h, 0) for h in one),
                    silent_expected=sum(silent.expected(h, tz)[0] or 0.0 for h in one),
                    live_count=sum(live.recent.get(h, 0) for h in one),
                    live_expected=sum(live.expected(h, tz)[0] or 0.0 for h in one),
                )
                if best is None or (len(candidate.hours), candidate.live_count) > (
                    len(best.hours),
                    best.live_count,
                ):
                    best = candidate
        if best is not None:
            out.append(best)
    return out


def _plane_clause(machine: _Machine, plane: str) -> list[dict[str, Any]]:
    """The documents of one plane of one machine."""
    if plane == FLOW_PLANE:
        return [
            {
                "bool": {
                    "should": [_dataset_clause(d) for d in FLOW_DATASETS],
                    "minimum_should_match": 1,
                }
            },
            {"terms": {"source.ip": machine.addresses}},
        ]
    datasets = sorted(machine.datasets.get(plane, set()))
    return [
        {"terms": {"event.dataset": datasets}},
        {"term": {"host.name": machine.name}},
    ]


async def _newest(
    ctx: DetectorContext,
    machine: _Machine,
    plane: str,
    *,
    since: datetime,
    until: datetime,
) -> tuple[str, datetime | None] | None:
    """The id and the time of the newest document of one plane in a window."""
    query = {
        "bool": {
            "filter": [
                *_plane_clause(machine, plane),
                {"range": {"@timestamp": {"gte": iso(since), "lt": iso(until)}}},
            ],
            "must_not": _scope_must_not(),
        }
    }
    result = await ctx.elastic.search(
        ctx.index, query, size=1, sort=[{"@timestamp": {"order": "desc"}}], source=False
    )
    for hit in result.hits or ():
        if isinstance(hit, dict) and hit.get("_id"):
            return str(hit["_id"]), _sort_time(hit)
    return None


def _sort_time(hit: dict[str, Any]) -> datetime | None:
    sort = hit.get("sort")
    if isinstance(sort, list) and sort and isinstance(sort[0], (int, float)):
        if isinstance(sort[0], bool):
            return None
        return datetime.fromtimestamp(float(sort[0]) / 1000.0, tz=UTC)
    return None


def _rerun(machine: _Machine, silence: _Silence) -> str:
    """The OQL query that shows both planes over the silence and the hour before it."""
    start = silence.hours[0] - timedelta(hours=1)
    end = silence.hours[-1] + timedelta(hours=1)
    subject = f"host.name:{oql_value(machine.name)}"
    if FLOW_PLANE in (silence.silent, silence.live) and machine.addresses:
        addresses = " OR ".join(f"source.ip:{oql_value(a)}" for a in machine.addresses[:4])
        subject = f"({subject} OR {addresses})"
    return (
        f'{subject} AND @timestamp:["{oql_stamp(start)}" TO "{oql_stamp(end)}"] '
        "| groupby event.dataset"
    )


def _number(value: float) -> str:
    return f"{value:,.0f}"


def _reason(machine: _Machine, s: _Silence) -> str:
    """The hit in words: the silent plane and the live plane, with their numbers."""
    return (
        f"The {_label(s.silent)} of {machine.name} fell to "
        f"{plural(s.silent_count, 'document')} in {plural(len(s.hours), 'hour')}. "
        f"The baseline expects {_number(s.silent_expected)} in those hours. "
        f"The {_label(s.live)} of {machine.name} held {plural(s.live_count, 'document')} "
        f"against an expected {_number(s.live_expected)}."
    )


async def _hit(
    ctx: DetectorContext, machine: _Machine, s: _Silence, params: CrossPlaneSilenceParams
) -> ModelHit:
    """The hit, with the documents it cites. A lookup that finds nothing cites nothing."""
    start = s.hours[0]
    end = s.hours[-1] + timedelta(hours=1)
    lookback = timedelta(days=7 * params.baseline_weeks)
    ids: list[str] = []
    observed: datetime | None = None
    last_silent = await _newest(ctx, machine, s.silent, since=start - lookback, until=end)
    if last_silent is not None:
        ids.append(last_silent[0])
    current_live = await _newest(ctx, machine, s.live, since=start, until=end)
    if current_live is not None:
        ids.append(current_live[0])
        observed = current_live[1]
    return ModelHit(
        entity_key=machine.name,
        kind=Kind.TELEMETRY_SILENCE,
        fingerprint=(DETECTOR_ID, s.silent),
        statistic=STATISTIC_PLANE_DOCUMENTS,
        statistic_value=float(s.silent_count),
        baseline_value=round(s.silent_expected, 1),
        document_ids=tuple(ids),
        rerun_query=_rerun(machine, s),
        reason=_reason(machine, s),
        features={
            "silent_plane": s.silent,
            "silent_documents": s.silent_count,
            "silent_expected": round(s.silent_expected, 1),
            "live_plane": s.live,
            "live_documents": s.live_count,
            "live_expected": round(s.live_expected, 1),
            "silent_hours": len(s.hours),
            "silent_from": iso(start),
            "silent_until": iso(end),
            "silent_last_document": last_silent[0] if last_silent else None,
            "live_document": current_live[0] if current_live else None,
        },
        observed_at=observed,
    )


@dataclass
class _Scored:
    machine: _Machine
    state: str
    note: str = ""
    silences: list[_Silence] = field(default_factory=list)
    measured: list[str] = field(default_factory=list)


def _score(
    machine: _Machine,
    windows: _Windows,
    params: CrossPlaneSilenceParams,
    ctx: DetectorContext,
) -> _Scored:
    planes = machine.planes()
    if len(planes) < 2:
        shipped = _label(planes[0]) if planes else "no plane"
        return _Scored(
            machine,
            STATE_UNMEASURABLE,
            f"the machine ships one plane, {shipped}. A silence needs a second plane.",
        )
    exclude = windows_for(ctx.windows, machine.name)
    for address in machine.addresses:
        exclude.extend(w for w in windows_for(ctx.windows, address) if w not in exclude)
    read = [_plane(machine, p, windows, now=ctx.now, tz=ctx.tz, exclude=exclude) for p in planes]
    measured = [p for p in read if p.history_days >= params.min_history_days]
    learning = [p.plane for p in read if p.history_days < params.min_history_days]
    if len(measured) < 2:
        return _Scored(
            machine,
            STATE_LEARNING,
            "learning: under "
            f"{plural(params.min_history_days, 'day')} of history on "
            + ", ".join(_label(p) for p in learning)
            + ".",
        )
    note = (
        "learning on " + ", ".join(_label(p) for p in learning) + ". The other planes are measured."
        if learning
        else ""
    )
    return _Scored(
        machine,
        STATE_MEASURED,
        note,
        silences=_silences(measured, windows.recent, params, ctx.tz),
        measured=[p.plane for p in measured],
    )


async def detect(params: CrossPlaneSilenceParams, ctx: DetectorContext) -> DetectorRun:
    """Score every machine that ships a host plane. Raises when a grid read fails.

    The evaluator turns a raise into a blind result for the spec. A part of
    the estate scored as the whole is the false all-clear the states exist to
    prevent.
    """
    notes: list[str] = []
    windows = _windows(params, ctx.now)
    machines = await _read_hosts(ctx, windows, notes)
    if not machines:
        return DetectorRun(
            notes=tuple(notes),
            blind=(
                "no host telemetry plane holds a document in the window or in the "
                f"same hours of the last {plural(params.baseline_weeks, 'week')}"
            ),
        )
    await _read_flows(ctx, windows, machines)
    scored = [_score(m, windows, params, ctx) for m in machines.values()]

    # A plane silent on most machines that ship it is the grid's condition:
    # a sensor or a pipeline stopped. The hits are held, and the note says so.
    held_planes: set[str] = set()
    for plane in _PLANE_ORDER:
        shipping = [s for s in scored if plane in s.measured]
        silent = [s for s in shipping if any(x.silent == plane for x in s.silences)]
        if len(silent) >= params.grid_min_machines and len(silent) > params.grid_share * len(
            shipping
        ):
            held_planes.add(plane)
            notes.append(
                f"the {_label(plane)} fell silent on {len(silent)} of "
                f"{plural(len(shipping), 'machine')} at once. The condition is the grid's. "
                "The detector held these hits."
            )

    entities: list[EntityState] = []
    for s in scored:
        kept = [x for x in s.silences if x.silent not in held_planes]
        held = len(kept) < len(s.silences)
        hits = tuple([await _hit(ctx, s.machine, x, params) for x in kept])
        state = STATE_HELD if held and not hits else s.state
        note = s.note
        if hits:
            note = " ".join(h.reason for h in hits)
        elif held:
            note = "held: the silence is on most machines at once. The condition is the grid's."
        elif s.state == STATE_MEASURED and not note:
            note = "Nothing departed."
        entities.append(EntityState(entity_key=s.machine.name, state=state, note=note, hits=hits))
    flows = sum(1 for m in machines.values() if FLOW_PLANE in m.counts)
    notes.append(
        f"read {plural(len(machines), 'machine')} with a host plane. "
        f"{plural(flows, 'machine')} also ship network flows."
    )
    return DetectorRun(entities=tuple(entities), notes=tuple(notes))
