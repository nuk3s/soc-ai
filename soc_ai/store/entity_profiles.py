"""Read and write what is normal for one entity on one dimension.

Two things here are not bookkeeping and should not be refactored away.

**The rebind guard.** :func:`load_profiles` takes an optional
``identity_fingerprint``. When one is supplied and the stored profile carries a
*different* non-null one, the row is not returned. An address that changed
hands must not inherit its predecessor's history, because every departure
scored against that history would be charging the wrong machine. Callers that
only want to render a profile pass nothing and see everything; callers that are
about to score against it pass the dossier's current fingerprint.

**Scorability is not emptiness.** ``coverage`` distinguishes a dimension that
was measured and found empty — a real fact, against which a new member is a
real departure — from one that could not be measured at all. Those two render
identically as an empty set, and conflating them is how a host with no agent
comes to read as a host with nothing unusual on it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import EntityProfile

if TYPE_CHECKING:
    from sqlalchemy import CursorResult

__all__ = [
    "COVERAGE_BEHIND_PROXY",
    "COVERAGE_BLIND",
    "COVERAGE_LEARNING",
    "COVERAGE_MEASURED",
    "ProfileRow",
    "load_profiles",
    "profiles_for_role",
    "purge_entity",
    "purge_out_of_scope",
    "upsert_profile",
]

COVERAGE_MEASURED = "measured"
COVERAGE_BLIND = "blind"
COVERAGE_LEARNING = "learning"
COVERAGE_BEHIND_PROXY = "behind_proxy"

# The only coverage state a departure may be scored against. ``learning`` and
# ``behind_proxy`` are excluded deliberately: the first has not earned the
# right to call anything unusual, and for the second the dimension has moved
# to the proxy, so absence here says nothing about the host.
_SCORABLE = frozenset({COVERAGE_MEASURED})


@dataclass(frozen=True)
class ProfileRow:
    """One profile, as callers see it."""

    entity_kind: str
    entity_key: str
    dimension: str
    shape: str
    vector: Any | None
    coverage: str
    support_days: int
    role: str | None
    role_confidence: float | None
    identity_fingerprint: str | None
    window_days: int
    first_seen: datetime | None
    last_seen: datetime | None
    built_at: datetime | None

    @property
    def is_scorable(self) -> bool:
        """Whether a departure may be scored against this profile.

        A blind dimension cannot produce a departure, and neither can one still
        learning. Both would otherwise produce the most dangerous output this
        system has: a confident all-clear from a measurement that never ran.
        """
        return self.coverage in _SCORABLE


def _row(model: EntityProfile) -> ProfileRow:
    return ProfileRow(
        entity_kind=model.entity_kind,
        entity_key=model.entity_key,
        dimension=model.dimension,
        shape=model.shape,
        vector=model.vector_json,
        coverage=model.coverage,
        support_days=model.support_days,
        role=model.role,
        role_confidence=model.role_confidence,
        identity_fingerprint=model.identity_fingerprint,
        window_days=model.window_days,
        first_seen=model.first_seen,
        last_seen=model.last_seen,
        built_at=model.built_at,
    )


async def upsert_profile(
    db: AsyncSession,
    *,
    entity_kind: str,
    entity_key: str,
    dimension: str,
    shape: str,
    vector: Any | None,
    coverage: str = COVERAGE_MEASURED,
    support_days: int = 0,
    role: str | None = None,
    role_confidence: float | None = None,
    identity_fingerprint: str | None = None,
    window_days: int = 30,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> None:
    """Write one profile, replacing any previous one for the same dimension.

    Replacing rather than appending: the sweep runs repeatedly, and a table
    that grows a row per sweep forces every reader to work out which row is
    current — a question with no right answer once two sweeps overlap.
    """
    existing = (
        await db.execute(
            select(EntityProfile).where(
                EntityProfile.entity_kind == entity_kind,
                EntityProfile.entity_key == entity_key,
                EntityProfile.dimension == dimension,
            )
        )
    ).scalar_one_or_none()

    if existing is None:
        db.add(
            EntityProfile(
                entity_kind=entity_kind,
                entity_key=entity_key,
                dimension=dimension,
                shape=shape,
                vector_json=vector,
                coverage=coverage,
                support_days=support_days,
                role=role,
                role_confidence=role_confidence,
                identity_fingerprint=identity_fingerprint,
                window_days=window_days,
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )
    else:
        existing.shape = shape
        existing.vector_json = vector
        existing.coverage = coverage
        existing.support_days = support_days
        existing.role = role
        existing.role_confidence = role_confidence
        existing.identity_fingerprint = identity_fingerprint
        existing.window_days = window_days
        existing.first_seen = first_seen
        existing.last_seen = last_seen
        existing.built_at = datetime.now()

    await db.commit()


async def load_profiles(
    db: AsyncSession,
    *,
    entity_kind: str,
    entity_key: str,
    identity_fingerprint: str | None = None,
) -> dict[str, ProfileRow]:
    """Every dimension for one entity, keyed by dimension name.

    When ``identity_fingerprint`` is supplied, rows carrying a *different*
    non-null fingerprint are withheld: the address changed hands and the stored
    profile belongs to whoever held it before.

    A row with NO stored fingerprint is returned for any fingerprint asked for.
    The dossier only fingerprints hosts it can name — hostname plus MAC — and
    withholding profiles from the rest would make every un-fingerprinted host
    permanently blind, which on a network-only grid is almost all of them.
    """
    rows = (
        (
            await db.execute(
                select(EntityProfile).where(
                    EntityProfile.entity_kind == entity_kind,
                    EntityProfile.entity_key == entity_key,
                )
            )
        )
        .scalars()
        .all()
    )

    out: dict[str, ProfileRow] = {}
    for model in rows:
        if (
            identity_fingerprint is not None
            and model.identity_fingerprint is not None
            and model.identity_fingerprint != identity_fingerprint
        ):
            continue
        out[model.dimension] = _row(model)
    return out


async def profiles_for_role(db: AsyncSession, *, role: str, dimension: str) -> list[ProfileRow]:
    """Every scorable profile for one role and dimension — the peer group.

    Unscorable members are excluded rather than counted as empty. A blind peer
    contributes no evidence about what is normal for the role, and leaving it
    in the denominator makes every membership look rarer than it is — which
    pushes shrinkage toward calling ordinary things novel.
    """
    rows = (
        (
            await db.execute(
                select(EntityProfile).where(
                    EntityProfile.role == role,
                    EntityProfile.dimension == dimension,
                )
            )
        )
        .scalars()
        .all()
    )
    return [row for model in rows if (row := _row(model)).is_scorable]


async def purge_out_of_scope(db: AsyncSession, *, cidrs: Sequence[Any]) -> int:
    """Delete HOST profiles whose address is outside the estate. Returns how many.

    Scoping the BUILDER is not enough on its own. ``upsert_profile`` writes and
    never deletes, so when host entities were first scoped to the estate's own
    CIDRs the previously-built profiles for an external server, the loopback
    address and an upstream gateway stayed in the table — and the prior sweep
    went on reporting findings about them for as long as they sat there.

    Fails OPEN on an empty CIDR list, matching the lane: that means nobody has
    told this deployment what its own network is, and purging everything on
    that basis would delete every baseline on an unconfigured estate.

    User entities are never touched. A principal has no address, and running
    one through an address test deletes every user profile on the grid.
    """
    if not cidrs:
        return 0

    from soc_ai.enrichment.discovery import _is_internal_ip  # noqa: PLC0415 - lazy, avoids a cycle

    rows = (
        (await db.execute(select(EntityProfile).where(EntityProfile.entity_kind == "host")))
        .scalars()
        .all()
    )
    doomed = [r.id for r in rows if not _is_internal_ip(r.entity_key, list(cidrs))]
    if not doomed:
        return 0

    result = await db.execute(delete(EntityProfile).where(EntityProfile.id.in_(doomed)))
    await db.commit()
    # cast: AsyncSession.execute is typed Result, but a DELETE returns a
    # CursorResult, whose rowcount is the number of rows removed.
    return int(cast("CursorResult[Any]", result).rowcount or 0)


async def purge_entity(db: AsyncSession, *, entity_kind: str, entity_key: str) -> int:
    """Delete every dimension for one entity. Returns how many rows went.

    Used by the rebind guard. The old profile is deleted rather than merely
    hidden, so it cannot reappear if the fingerprint is later lost — which
    happens whenever a host stops shipping the hostname the fingerprint is
    built from.
    """
    result = await db.execute(
        delete(EntityProfile).where(
            EntityProfile.entity_kind == entity_kind,
            EntityProfile.entity_key == entity_key,
        )
    )
    await db.commit()
    # cast: same contract as purge_out_of_scope above.
    return int(cast("CursorResult[Any]", result).rowcount or 0)
