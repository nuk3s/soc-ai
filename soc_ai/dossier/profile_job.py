"""Build and persist every entity's behavioural profile: one job, two callers.

The dossier sweep ran this as a private step, and the prior sweep loop read
whatever the step had left. On the range the dossier schedule was off and the
host timer that used to run the sweep was retired, so the loop evaluated
baselines that were three days old every hour and reported them as if they
were current. The job has a name of its own so the loop can run it when the
baselines are stale, whatever the dossier schedule says.

Three things are decided here and nowhere else:

* per-host coverage for the dimensions the lane left silent (the fill);
* the ``unmeasurable`` rows for a dimension the grid refused, with the reason;
* which rows a clean build expires.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from soc_ai.dossier.profile import ProfileSweep, collect_entity_profiles
from soc_ai.store import entity_profiles

_LOGGER = logging.getLogger(__name__)

__all__ = ["ProfileBuild", "build_profiles", "freshness"]

# Dimensions an agent on the machine supplies, grouped by the plane that feeds
# them. A host that ships no document on a plane is BLIND for every dimension
# that plane feeds -- not empty, blind.
#
# The agent inventory used to decide this. It cannot: an agent that ships
# security logs and runs no Sysmon is listed, and the domain controller's
# process, process-pair and logon-user dimensions all read "measured, none
# observed" while nothing on that host could produce a process document.
_AGENT_PLANES: tuple[tuple[str, ...], ...] = (
    ("process_names", "process_parents"),
    ("logon_users",),
)
# Dimensions every host with flow can answer, when a plane carries them. A
# host that has flow and no row here genuinely did none of this: measured,
# and empty. A dimension no plane on the grid carries is blind on every host.
_FLOW_DIMENSIONS: tuple[str, ...] = ("served_ports", "consumed_ports", "peers_out", "dns_names")

# The shape an unmeasurable row records, so the host page renders the right row.
_SHAPE_OF: dict[str, str] = {"active_hours": "active_hours", "connection_rate": "numeric"}


@dataclass
class ProfileBuild:
    """What one run of the job did. ``errors`` are failures; ``notes`` are facts."""

    written: int = 0
    purged: int = 0
    expired: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _coverage_fill(
    sweep: ProfileSweep, *, unanswered: frozenset[str]
) -> list[tuple[str, str, str, int]]:
    """Rows to write for dimensions a host has NO row for: (key, dim, coverage, support).

    The lane emits one grid-level placeholder when no plane can answer a
    dimension at all, and nothing for a host that simply has no data in it.
    On the page those two absences and "we never tried" looked identical, so
    per-host coverage is decided here:

    * an agent dimension whose plane returned no document for this host is
      ``blind``;
    * an agent dimension whose plane DID answer for this host, with no rows of
      its own, is measured and empty;
    * a flow dimension on a host that has flow rows is measured and empty,
      UNLESS no plane on the grid carries it (``unanswered``), in which case
      it is blind on every host. Production wrote 178 measured-and-empty DNS
      rows on a grid with no DNS plane before this clause existed.

    A row exists for a host only when the aggregation returned a bucket for
    it, so the presence of any row from a plane is the proof that the plane
    answered. The row is read whatever entity kind it carries: the logon
    dimension keys its rows on the host and labels them ``user``.
    """
    have: dict[str, set[str]] = {}
    answered: dict[str, set[str]] = {}
    support: dict[str, int] = {}
    for b in sweep.profiles:
        if b.entity_key == "*":
            continue
        answered.setdefault(b.entity_key, set()).add(b.dimension)
        if b.entity_kind != "host":
            continue
        have.setdefault(b.entity_key, set()).add(b.dimension)
        support[b.entity_key] = max(support.get(b.entity_key, 0), int(b.support_days or 0))

    fill: list[tuple[str, str, str, int]] = []
    for key, dims in have.items():
        days = support.get(key, 0)
        seen = answered.get(key, set())
        for plane in _AGENT_PLANES:
            measured = bool(seen & set(plane))
            for dim in plane:
                if dim in dims:
                    continue
                fill.append((key, dim, "measured" if measured else "blind", days))
        if dims & set(_FLOW_DIMENSIONS):
            for dim in _FLOW_DIMENSIONS:
                if dim in dims:
                    continue
                fill.append((key, dim, "blind" if dim in unanswered else "measured", days))
    return fill


def _unmeasurable_rows(sweep: ProfileSweep) -> list[tuple[str, str, str, str]]:
    """(key, dimension, shape, reason) for every host the sweep saw, per refused dimension.

    Every host, because the refusal was about the grid's size and not about
    any one host: a row per host is what lets the host page say "not
    measured: <reason>" instead of "nothing observed".
    """
    if not sweep.unmeasurable:
        return []
    hosts = sorted(
        {b.entity_key for b in sweep.profiles if b.entity_kind == "host" and b.entity_key != "*"}
    )
    return [
        (key, dim, _SHAPE_OF.get(dim, "categorical"), reason)
        for key in hosts
        for dim, reason in sorted(sweep.unmeasurable.items())
    ]


async def build_profiles(
    elastic: Any,
    sessionmaker: Any,
    settings: Any,
    cidrs: Sequence[Any] = (),
) -> ProfileBuild:
    """Build and persist behavioural profiles, if the deployment has opted in.

    Runs once per call rather than once per host: the aggregations are keyed
    by entity, so one pass produces every entity's row.

    Gated OFF by default. The design does not let this layer influence
    anything before a shadow week has been read.

    Never raises. A caller that aborted because a baseline could not be built
    would have traded a working feature for a new one.

    Expiry: after a build that reports no error, rows stamped before the run
    started are deleted. They describe hosts the window no longer holds or
    dimensions the build no longer writes, and ``upsert`` never deletes. A
    build with an error expires nothing, because the dimension that failed
    wrote no row this run and its old rows are the only baseline left.
    """
    build = ProfileBuild()
    if not getattr(settings, "entity_profiles_enabled", False):
        return build

    window_days = max(1, int(getattr(settings, "entity_profile_window_days", 30)))
    lag_hours = max(0, int(getattr(settings, "entity_profile_lag_hours", 24)))
    started = datetime.now(UTC).replace(tzinfo=None)
    try:
        sweep = await collect_entity_profiles(
            elastic=elastic,
            settings=settings,
            window_hours=window_days * 24,
            # The baseline stops where the prior sweep's recent window starts.
            # Without the gap it contains the very window it is compared
            # against and nothing can ever be novel.
            lag_hours=lag_hours,
            # Host entities are scoped to the estate's own address space, or
            # the lane profiles the internet.
            cidrs=cidrs,
        )
    except Exception as exc:
        build.errors.append(f"entity profiles: {exc}")
        return build

    for detail in sweep.errors:
        build.errors.append(f"entity profiles: {detail}")
    for note in sweep.notes:
        build.notes.append(note)
    for dim, reason in sorted(sweep.unmeasurable.items()):
        build.notes.append(f"{dim}: unmeasurable: {reason}")
    if sweep.planes:
        build.notes.append(
            "profile planes: "
            + "; ".join(f"{k}={','.join(v)}" for k, v in sorted(sweep.planes.items()))
        )

    unanswered = frozenset(sweep.unanswered)
    try:
        async with sessionmaker() as db:
            # Before writing: drop anything the current scope excludes. The
            # builder was scoped to the estate's CIDRs, but upsert never
            # deletes, so without this a scoping change leaves the profiles it
            # now excludes sitting in the table being reported on.
            build.purged = await entity_profiles.purge_out_of_scope(db, cidrs=cidrs)
            for built in sweep.profiles:
                # The blind placeholder the lane emits is keyed "*": it says
                # the GRID cannot answer this dimension, which is a note on
                # the run, not a row about an entity that does not exist.
                if built.entity_key == "*":
                    continue
                await entity_profiles.upsert_profile(
                    db,
                    entity_kind=built.entity_kind,
                    entity_key=built.entity_key,
                    dimension=built.dimension,
                    shape=built.shape,
                    vector=built.vector,
                    coverage=built.coverage,
                    support_days=built.support_days,
                    window_days=window_days,
                )
                build.written += 1
            for key, dim, coverage, days in _coverage_fill(sweep, unanswered=unanswered):
                await entity_profiles.upsert_profile(
                    db,
                    entity_kind="host",
                    entity_key=key,
                    dimension=dim,
                    shape="categorical",
                    vector=None if coverage == "blind" else {},
                    coverage=coverage,
                    support_days=days if coverage != "blind" else 0,
                    window_days=window_days,
                )
                build.written += 1
            for key, dim, shape, reason in _unmeasurable_rows(sweep):
                await entity_profiles.upsert_profile(
                    db,
                    entity_kind="host",
                    entity_key=key,
                    dimension=dim,
                    shape=shape,
                    vector=None,
                    coverage=entity_profiles.COVERAGE_UNMEASURABLE,
                    coverage_reason=reason,
                    support_days=0,
                    window_days=window_days,
                )
                build.written += 1
            if not sweep.errors:
                build.expired = await entity_profiles.purge_older_than(db, built_before=started)
    except Exception as exc:
        build.errors.append(f"entity profiles: persist failed: {exc}")
        return build

    detail = f"entity profiles: wrote {build.written} row(s)"
    if build.purged:
        detail += f", purged {build.purged} out of scope"
    if build.expired:
        detail += f", expired {build.expired} stale row(s)"
    build.notes.append(detail)
    return build


async def freshness(sessionmaker: Any) -> entity_profiles.ProfileFreshness:
    """What the table says about itself, for a caller that holds a sessionmaker."""
    async with sessionmaker() as db:
        return await entity_profiles.freshness(db)
