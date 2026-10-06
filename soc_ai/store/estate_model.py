"""The estate model's own records: each fit, and the learned group of each host.

Two rules live here, and neither is bookkeeping.

**A model file is trusted by its row.** A fit writes a JSON file under
``<data dir>/models/estate/`` and records the file name and the sha256 of its
bytes in ``estate_model_fits``. The loader in
:mod:`soc_ai.hunting.estate_model.artifact` reads a file only when the hash of
its bytes is the hash recorded here for that name. :func:`recorded_files` is
the map it checks against. A file that soc-ai did not write has no row, and a
file that somebody edited has another hash.

**A learned group serves only from a usable fit.** :func:`usable_fit` is the
newest fit in state ``measured`` that is younger than
:data:`LEARNED_GROUP_MAX_AGE`. A drifted or held fit, and a learning fit of 20
hosts or more, writes its groups for the record, and no reader takes them as
peers. A learning fit under 20 hosts fits no model and writes no group.

The challenger rule is a record only. A new fit is a ``challenger`` for 24
hours. :func:`promote_challengers` makes it the ``champion`` at the next fit
after that and retires the champion before it. soc-ai scores once, with the
newest fit, and does not score the champion beside it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import EstateModelFit, EstatePeerGroup

__all__ = [
    "CHALLENGER_HOURS",
    "LEARNED_GROUP_MAX_AGE",
    "ROLE_CHALLENGER",
    "ROLE_CHAMPION",
    "ROLE_RETIRED",
    "STATES",
    "STATE_DRIFTED",
    "STATE_HELD",
    "STATE_LEARNING",
    "STATE_MEASURED",
    "FitRecord",
    "GroupRow",
    "LearnedGroup",
    "files_beyond",
    "group_members",
    "latest_fit",
    "latest_model_fit",
    "learned_group",
    "learned_map",
    "promote_challengers",
    "record_fit",
    "recorded_files",
    "replace_groups",
    "update_fit",
    "usable_fit",
]

STATE_MEASURED = "measured"
STATE_LEARNING = "learning"
STATE_DRIFTED = "drifted"
STATE_HELD = "held"
STATES: tuple[str, ...] = (STATE_MEASURED, STATE_LEARNING, STATE_DRIFTED, STATE_HELD)

ROLE_CHALLENGER = "challenger"
ROLE_CHAMPION = "champion"
ROLE_RETIRED = "retired"

# How long a new fit stays a challenger before the next fit promotes it.
CHALLENGER_HOURS = 24

# The oldest fit whose groups a peer reader takes. Two daily fits missed in a
# row and the groups describe an estate that may have moved on.
LEARNED_GROUP_MAX_AGE = timedelta(hours=48)

# Rows per INSERT and ids per IN list. SQLite builds before 3.32 cap a
# statement at 999 bound variables.
_CHUNK = 500


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _naive(at: datetime) -> datetime:
    return at.astimezone(UTC).replace(tzinfo=None) if at.tzinfo is not None else at


@dataclass(frozen=True)
class FitRecord:
    """One fit, as callers see it."""

    id: int
    fitted_at: datetime
    state: str
    reason: str | None
    model_sha256: str | None
    model_file: str | None
    hosts: int
    features: int
    groups: int
    silhouette: float | None
    support_days: int | None
    psi: float | None
    drifted: list[dict[str, Any]]
    groups_detail: list[dict[str, Any]]
    outliers: int
    unexplained: int
    shared: int
    no_documents: int
    observations: int
    role: str
    challenger_until: datetime | None
    audited: bool

    def group(self, group_id: int) -> dict[str, Any] | None:
        """The stored detail of one group: size, centroid, medians."""
        for entry in self.groups_detail:
            if int(entry.get("id", -1)) == int(group_id):
                return entry
        return None


def _record(row: EstateModelFit) -> FitRecord:
    return FitRecord(
        id=int(row.id),
        fitted_at=row.fitted_at,
        state=str(row.state),
        reason=row.reason,
        model_sha256=row.model_sha256,
        model_file=row.model_file,
        hosts=int(row.hosts or 0),
        features=int(row.features or 0),
        groups=int(row.groups or 0),
        silhouette=row.silhouette,
        support_days=row.support_days,
        psi=row.psi,
        drifted=list(row.drifted_json or []),
        groups_detail=list(row.groups_json or []),
        outliers=int(row.outliers or 0),
        unexplained=int(row.unexplained or 0),
        shared=int(row.shared or 0),
        no_documents=int(row.no_documents or 0),
        observations=int(row.observations or 0),
        role=str(row.role),
        challenger_until=row.challenger_until,
        audited=bool(row.audited),
    )


async def record_fit(
    db: AsyncSession,
    *,
    fitted_at: datetime,
    state: str,
    reason: str | None = None,
    model_sha256: str | None = None,
    model_file: str | None = None,
    hosts: int = 0,
    features: int = 0,
    groups: int = 0,
    silhouette: float | None = None,
    support_days: int | None = None,
    psi: float | None = None,
    drifted: Sequence[dict[str, Any]] | None = None,
    groups_detail: Sequence[dict[str, Any]] | None = None,
) -> int:
    """Write one fit as a challenger. Returns its id."""
    if state not in STATES:
        raise ValueError(f"unknown estate model state: {state}")
    at = _naive(fitted_at)
    row = EstateModelFit(
        fitted_at=at,
        state=state,
        reason=reason,
        model_sha256=model_sha256,
        model_file=model_file,
        hosts=hosts,
        features=features,
        groups=groups,
        silhouette=silhouette,
        support_days=support_days,
        psi=psi,
        drifted_json=list(drifted) if drifted else None,
        groups_json=list(groups_detail) if groups_detail else None,
        outliers=0,
        unexplained=0,
        shared=0,
        no_documents=0,
        observations=0,
        role=ROLE_CHALLENGER,
        challenger_until=at + timedelta(hours=CHALLENGER_HOURS),
        audited=False,
    )
    db.add(row)
    await db.commit()
    return int(row.id)


async def update_fit(db: AsyncSession, fit_id: int, **values: Any) -> None:
    """Write the counts a fit learns after its row exists: observations, audit."""
    allowed = {
        "state",
        "reason",
        "outliers",
        "unexplained",
        "shared",
        "no_documents",
        "observations",
        "audited",
    }
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"not an updatable fit column: {sorted(unknown)}")
    if "state" in values and values["state"] not in STATES:
        raise ValueError(f"unknown estate model state: {values['state']}")
    await db.execute(update(EstateModelFit).where(EstateModelFit.id == fit_id).values(**values))
    await db.commit()


async def latest_fit(db: AsyncSession) -> FitRecord | None:
    """The newest fit, whatever its state."""
    row = (
        await db.execute(
            select(EstateModelFit)
            .order_by(EstateModelFit.fitted_at.desc(), EstateModelFit.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return _record(row) if row is not None else None


async def latest_model_fit(db: AsyncSession) -> FitRecord | None:
    """The newest fit that wrote a model file."""
    row = (
        await db.execute(
            select(EstateModelFit)
            .where(EstateModelFit.model_sha256.isnot(None), EstateModelFit.model_file.isnot(None))
            .order_by(EstateModelFit.fitted_at.desc(), EstateModelFit.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return _record(row) if row is not None else None


async def recorded_files(db: AsyncSession) -> dict[str, str]:
    """Every model file name a fit wrote, with the sha256 the fit recorded."""
    rows = (
        await db.execute(
            select(EstateModelFit.model_file, EstateModelFit.model_sha256).where(
                EstateModelFit.model_file.isnot(None), EstateModelFit.model_sha256.isnot(None)
            )
        )
    ).all()
    return {str(name): str(sha) for name, sha in rows}


async def files_beyond(db: AsyncSession, *, keep: int) -> list[str]:
    """The file names of every fit older than the newest ``keep`` that wrote one."""
    rows = (
        await db.execute(
            select(EstateModelFit.model_file)
            .where(EstateModelFit.model_file.isnot(None))
            .order_by(EstateModelFit.fitted_at.desc(), EstateModelFit.id.desc())
            .offset(max(0, keep))
        )
    ).all()
    return [str(name) for (name,) in rows]


async def promote_challengers(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Promote the newest challenger whose 24 hours are over. Returns how many moved.

    The newest such challenger becomes the champion, and the champion before it
    is retired. An older challenger that a newer fit overtook is retired with
    it. A challenger still inside its 24 hours stays one.
    """
    at = _naive(now or _utcnow())
    due = (
        (
            await db.execute(
                select(EstateModelFit)
                .where(
                    EstateModelFit.role == ROLE_CHALLENGER,
                    EstateModelFit.challenger_until.isnot(None),
                    EstateModelFit.challenger_until <= at,
                )
                .order_by(EstateModelFit.fitted_at.desc(), EstateModelFit.id.desc())
            )
        )
        .scalars()
        .all()
    )
    if not due:
        return 0
    newest = due[0]
    moved = 0
    await db.execute(
        update(EstateModelFit)
        .where(EstateModelFit.role == ROLE_CHAMPION, EstateModelFit.id != newest.id)
        .values(role=ROLE_RETIRED)
    )
    newest.role = ROLE_CHAMPION
    moved += 1
    for older in due[1:]:
        older.role = ROLE_RETIRED
        moved += 1
    await db.commit()
    return moved


@dataclass(frozen=True)
class GroupRow:
    """The learned group of one host, as a fit writes it."""

    entity_key: str
    group_id: int
    distance: float
    score: float | None


async def replace_groups(
    db: AsyncSession,
    rows: Sequence[GroupRow],
    *,
    model_sha256: str,
    fitted_at: datetime,
    entity_kind: str = "host",
) -> int:
    """Replace every learned group with the groups of one fit. Returns the row count.

    One transaction. A table half old and half new would put two fits' groups
    side by side, and a group id means something only inside its own fit.
    """
    at = _naive(fitted_at)
    await db.execute(delete(EstatePeerGroup))
    payload = [
        {
            "entity_kind": entity_kind,
            "entity_key": row.entity_key[:255],
            "group_id": int(row.group_id),
            "distance": float(row.distance),
            "score": None if row.score is None else float(row.score),
            "model_sha256": model_sha256,
            "fitted_at": at,
        }
        for row in rows
    ]
    for start in range(0, len(payload), _CHUNK):
        await db.execute(insert(EstatePeerGroup), payload[start : start + _CHUNK])
    await db.commit()
    return len(payload)


async def usable_fit(db: AsyncSession, *, now: datetime | None = None) -> FitRecord | None:
    """The newest fit whose groups a peer reader may take, or None.

    Only the newest fit counts. When the newest is learning, drifted or held,
    an older measured fit does not stand in for it, because the groups table
    holds the newest fit's groups.
    """
    fit = await latest_fit(db)
    if fit is None or fit.state != STATE_MEASURED or fit.model_sha256 is None:
        return None
    at = _naive(now or _utcnow())
    if at - fit.fitted_at > LEARNED_GROUP_MAX_AGE:
        return None
    return fit


@dataclass(frozen=True)
class LearnedGroup:
    """The learned group of one host, with the detail of the group."""

    entity_key: str
    group_id: int
    distance: float
    score: float | None
    model_sha256: str
    fitted_at: datetime
    size: int
    centroid: dict[str, float]


async def learned_group(
    db: AsyncSession, entity_key: str, *, now: datetime | None = None
) -> LearnedGroup | None:
    """The learned group of one host from the usable fit, or None."""
    fit = await usable_fit(db, now=now)
    if fit is None:
        return None
    row = (
        await db.execute(
            select(EstatePeerGroup).where(
                EstatePeerGroup.entity_kind == "host",
                EstatePeerGroup.entity_key == entity_key,
                EstatePeerGroup.model_sha256 == fit.model_sha256,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    detail = fit.group(int(row.group_id)) or {}
    return LearnedGroup(
        entity_key=str(row.entity_key),
        group_id=int(row.group_id),
        distance=float(row.distance),
        score=row.score,
        model_sha256=str(row.model_sha256),
        fitted_at=row.fitted_at,
        size=int(detail.get("size", 0)),
        centroid={str(k): float(v) for k, v in (detail.get("centroid") or {}).items()},
    )


async def learned_map(db: AsyncSession, *, model_sha256: str) -> dict[str, int]:
    """Every host of one fit, mapped to its learned group id."""
    rows = (
        await db.execute(
            select(EstatePeerGroup.entity_key, EstatePeerGroup.group_id).where(
                EstatePeerGroup.entity_kind == "host",
                EstatePeerGroup.model_sha256 == model_sha256,
            )
        )
    ).all()
    return {str(key): int(group) for key, group in rows}


async def group_members(db: AsyncSession, *, group_id: int, model_sha256: str) -> list[str]:
    """The host keys of one learned group of one fit, in key order."""
    rows = (
        await db.execute(
            select(EstatePeerGroup.entity_key)
            .where(
                EstatePeerGroup.entity_kind == "host",
                EstatePeerGroup.group_id == group_id,
                EstatePeerGroup.model_sha256 == model_sha256,
            )
            .order_by(EstatePeerGroup.entity_key)
        )
    ).all()
    return [str(key) for (key,) in rows]
