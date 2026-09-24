"""A week of hunt catalog sweeps for the demo store, generated rather than recorded.

The rest of the demo's content is recorded on a live grid, sanitized, and
shipped as ``fixtures.json``. The catalog's sweep trail is not: a demo grid
never runs a sweep, so there is nothing to record, and without rows in
``hunt_spec_sweeps`` the Operate hub's catalog panel says "not yet swept" for
every spec and the Hunts screen's "Catalog" preset is empty. The one screen
that exists to show the catalog working showed it never running.

Generated in code rather than stored as fixture rows because the trail is
mechanical, relative to now, and keyed by spec id against the catalog on
disk. A JSON copy would go stale the day a spec was renamed, and the panel
would read "not yet swept" again with nothing to say why. Here the ids and
titles come from :data:`~soc_ai.hunting.spec.CATALOG_DIR`, the hunt is built
by the sweep's own report builder, and every row is the row
:func:`~soc_ai.store.hunt_spec_sweeps.sweep_row` builds for a live sweep, so
what the demo shows is the shape a real deployment writes.

The story the trail tells, read newest to oldest:

* every spec swept on a fixed cadence for seven days, the newest sweep a few
  minutes ago;
* the decoy spec blind on every sweep (a demo grid has no canary), which is
  the panel's amber marker rather than a firing;
* the DCSync spec firing once about two days ago and recording the one
  triggered hunt, then holding the same account back as already handled on
  the sweeps that followed, including inside the last day;
* one transient grid error four days back on the AS-REP spec, so the red
  marker has been exercised in the history without sitting on any spec's
  newest row.

Seeded once, keyed on the hunt's primary key the way every fixture row is,
with the sweep rows riding along the way a hunt's events do.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.hunting.execute import Candidate, SpecRun
from soc_ai.hunting.findings import spec_report
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog
from soc_ai.hunting.sweep import SWEEP_ACTOR, catalog_objective
from soc_ai.store.auth import utcnow
from soc_ai.store.hunt_spec_sweeps import sweep_row
from soc_ai.store.hunts import _objective_hash
from soc_ai.store.models import Hunt, HuntSpecSweep

# Deterministic, ULID-shaped like every other demo row id, so a restart finds
# it and skips the whole trail.
CATALOG_HUNT_ID = "01DEMOHUNT0000000000DCSYNC"

# The shipped specs the story is written around. Named here rather than
# picked by position so a catalog change fails a test instead of quietly
# moving the firing onto a different spec.
FIRED_SPEC = "identity-4662-dcsync-nonmachine"
BLIND_SPEC = "decoy-opencanary-interaction"
ERRORED_SPEC = "identity-4768-preauth-disabled"

# One row every six hours for a week. The loop's default cadence is hourly,
# which would be 168 rows per spec for the same story; the panel reads the
# newest row and a 24-hour rate, and neither needs the density.
TRAIL_DAYS = 7
STEP = timedelta(hours=6)
ROWS_PER_SPEC = TRAIL_DAYS * 24 // 6

# How the loop spells its window (soc_ai/main.py): the default 1440-minute
# look-back against an hourly interval, as ES date math.
WINDOW_SINCE = "now-1440m"
WINDOW_UNTIL = "now"

# The newest row's age, so the status line reads "last sweep N min ago"
# rather than "just now" on a page that never sweeps.
NEWEST_AGE = timedelta(minutes=20)

# Positions in the trail, in steps back from the newest row.
FIRED_STEPS_AGO = 8  # about two days
ERROR_STEPS_AGO = 16  # about four days
# The same account replicated again about half a day ago; the fire-once gate
# knows the scope and holds it back, which is what a live trail shows for an
# unremediated finding and what puts a non-zero "handled" inside the panel's
# 24-hour window.
REPEAT_STEPS_AGO = 2
# How many six-hour rows the 1440-minute look-back keeps a document in view
# for after the sweep that first saw it.
STEPS_IN_WINDOW = 3

# Documents the precondition sees in a 24-hour window, per spec, as
# (base, spread): a small domain's worth of 4662, 4768 and 4769 traffic. A
# spec not named here sweeps clean at a modest count.
_PRECONDITION_DOCS = {
    "identity-4662-dcsync-nonmachine": (1400, 180),
    "identity-4768-preauth-disabled": (900, 140),
    "identity-4769-rc4-service-ticket": (3200, 360),
}
_DEFAULT_PRECONDITION_DOCS = (500, 80)

# The one grid error, in the form run_spec records one: the phase, then the
# client's own exception.
_TRANSIENT_ERROR = "detection: ConnectionTimeout: Connection timed out"

_FIRED_SCOPE = "it-admin-07"
_FIRED_SAMPLE_IDS = ("demo-4662-000001", "demo-4662-000002")


@dataclass(frozen=True)
class TrailRow:
    """One planned sweep row: which spec, when, what it saw, what it recorded."""

    spec_id: str
    at: datetime
    run: SpecRun
    hunt_id: str | None


def _jitter(seed: int, spread: int) -> int:
    """A fixed, evenly spread offset in ``[-spread, spread]`` for one row.

    An integer hash finaliser, not a random generator: the trail must come
    out the same on every seed so the tests can pin it, and the numbers only
    need to not read as a constant or a ramp.
    """
    h = (seed * 2654435761) & 0xFFFFFFFF
    h ^= h >> 15
    h = (h * 2246822519) & 0xFFFFFFFF
    h ^= h >> 13
    return h % (2 * spread + 1) - spread


def _es_time(at: datetime) -> str:
    """A naive-UTC datetime the way an aggregation's ``value_as_string`` spells it."""
    return at.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _fired_candidate(spec: HuntSpec, at: datetime) -> Candidate:
    """The non-machine account the DCSync spec caught, with its two documents."""
    return Candidate(
        spec_id=spec.id,
        scope_key=_FIRED_SCOPE,
        scope_kind=spec.scope_kind,
        doc_count=len(_FIRED_SAMPLE_IDS),
        sample_ids=_FIRED_SAMPLE_IDS,
        anchor_id=_FIRED_SAMPLE_IDS[0],
        anchor_index="logs-windows.forwarded-default",
        first_seen=_es_time(at - timedelta(minutes=41)),
        last_seen=_es_time(at - timedelta(minutes=38)),
    )


def _run_for(spec: HuntSpec, index: int, steps_ago: int, at: datetime) -> SpecRun:
    """What one sweep of ``spec`` saw, ``steps_ago`` rows before the newest."""
    # Taken from the spec, as a live sweep takes it. The blind spec here is the
    # decoy, whose precondition looks back ninety days, and its recorded
    # narrative names the window it was blind over.
    pre_since = spec.precondition_since(WINDOW_SINCE)
    if spec.id == BLIND_SPEC:
        return SpecRun(
            spec.id, WINDOW_SINCE, WINDOW_UNTIL, True, 0, 0, precondition_since=pre_since
        )
    if spec.id == ERRORED_SPEC and steps_ago == ERROR_STEPS_AGO:
        return SpecRun(
            spec.id,
            WINDOW_SINCE,
            WINDOW_UNTIL,
            False,
            0,
            0,
            error=_TRANSIENT_ERROR,
            precondition_since=pre_since,
        )

    base, spread = _PRECONDITION_DOCS.get(spec.id, _DEFAULT_PRECONDITION_DOCS)
    precondition = base + _jitter(steps_ago + 31 * index, spread)
    matched = 0
    handled = 0
    candidates: list[Candidate] = []
    if spec.id == FIRED_SPEC:
        docs = len(_FIRED_SAMPLE_IDS)
        if steps_ago == FIRED_STEPS_AGO:
            matched = docs
            candidates = [_fired_candidate(spec, at)]
        elif FIRED_STEPS_AGO - STEPS_IN_WINDOW <= steps_ago < FIRED_STEPS_AGO:
            # The firing's documents are still inside the look-back; the gate
            # knows the scope and reports it handled rather than fresh.
            matched, handled = docs, 1
        elif steps_ago <= REPEAT_STEPS_AGO:
            matched, handled = 1, 1
    return SpecRun(
        spec_id=spec.id,
        since=WINDOW_SINCE,
        until=WINDOW_UNTIL,
        blind=False,
        precondition_docs=precondition,
        matched_docs=matched,
        candidates=candidates,
        gate_already_handled=handled,
        precondition_since=pre_since,
    )


def plan_trail(catalog: dict[str, HuntSpec], *, now: datetime) -> list[TrailRow]:
    """Every row of the trail, in the order a live loop would have written them.

    Sorted by time and then catalog order, so the integer key ascends with
    time the way it does under the real loop. :func:`catalog_status` reads
    each spec's newest row by ``max(id)`` and would otherwise be reading the
    wrong one.
    """
    rows: list[TrailRow] = []
    for index, spec in enumerate(catalog.values()):
        for steps_ago in range(ROWS_PER_SPEC):
            at = now - NEWEST_AGE - STEP * steps_ago
            run = _run_for(spec, index, steps_ago, at)
            hunt_id = CATALOG_HUNT_ID if run.candidates else None
            rows.append(TrailRow(spec.id, at, run, hunt_id))
    rows.sort(key=lambda row: row.at)
    return rows


def build_catalog_hunt(spec: HuntSpec, run: SpecRun, *, at: datetime) -> Hunt:
    """The hunt the sweep's ``_record`` would have written for ``run``.

    Same objective, same actor, same report builder, no event stream: a
    sweep-recorded hunt has none, and the demo must not invent one.
    """
    objective = catalog_objective(spec, WINDOW_SINCE, WINDOW_UNTIL)
    report = spec_report(spec, run)
    return Hunt(
        id=CATALOG_HUNT_ID,
        objective=objective,
        objective_hash=_objective_hash(objective),
        kind="triggered",
        status="complete",
        narrative=report["narrative"],
        report=report,
        findings_count=len(report["findings"]),
        started_by=SWEEP_ACTOR,
        created_at=at,
        finished_at=at + timedelta(seconds=2),
    )


async def seed_catalog_trail(
    sessionmaker: async_sessionmaker[AsyncSession], *, now: datetime | None = None
) -> int:
    """Seed the trail and its hunt; skip everything if the hunt already exists.

    One transaction for the hunt and all of its rows, so a store can never
    hold half a trail: a crash mid-seed leaves nothing, and the next start
    seeds again. Returns the number of parent rows added (the hunt: 1 or 0),
    counted the way :func:`~soc_ai.demo.fixtures.seed_fixtures` counts.
    """
    now = now or utcnow()
    catalog = load_catalog(CATALOG_DIR)
    async with sessionmaker() as db:
        if await db.get(Hunt, CATALOG_HUNT_ID) is not None:
            return 0
        rows = plan_trail(catalog, now=now)
        fired = next(row for row in rows if row.hunt_id is not None)
        db.add(build_catalog_hunt(catalog[fired.spec_id], fired.run, at=fired.at))
        sweeps: list[HuntSpecSweep] = [
            sweep_row(
                spec_id=row.spec_id,
                run=row.run,
                hunt_id=row.hunt_id,
                shadow=False,
                since=WINDOW_SINCE,
                until=WINDOW_UNTIL,
                now=row.at,
            )
            for row in rows
        ]
        db.add_all(sweeps)
        await db.commit()
    return 1


__all__ = [
    "BLIND_SPEC",
    "CATALOG_HUNT_ID",
    "ERRORED_SPEC",
    "FIRED_SPEC",
    "ROWS_PER_SPEC",
    "TrailRow",
    "build_catalog_hunt",
    "plan_trail",
    "seed_catalog_trail",
]
