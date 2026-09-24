"""The local analytics tier and the version trail.

A local analytic is a spec that an analyst or the drafter wrote. It starts as a
candidate. An analyst moves it to shadow, approves it to live, or retires it. A
shipped analytic can only be retired, because the file on disk is the analytic
and an in-place local edit would make the repository and the database disagree
about what ran.

Every transition writes a version row with the spec text before and after, so
the history of an analytic is readable and diffable in the app.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.spec import CATALOG_DIR, load_catalog, parse_spec
from soc_ai.store.models import AnalyticState, AnalyticVersion

__all__ = [
    "ALLOWED_TRANSITIONS",
    "STATUSES",
    "create_local",
    "retire_shipped",
    "states",
    "transition",
    "versions",
]

STATUSES: tuple[str, ...] = ("candidate", "shadow", "live", "retired")

# Each status, and the statuses it may move to. A candidate never goes straight
# to live: it must run in shadow first and bring receipts.
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "candidate": frozenset({"shadow", "retired"}),
    "shadow": frozenset({"live", "retired", "candidate"}),
    "live": frozenset({"retired"}),
    "retired": frozenset({"shadow"}),
}


def _now(now: datetime | None) -> datetime:
    return (now or datetime.now(UTC)).replace(tzinfo=None)


async def states(db: AsyncSession) -> dict[str, AnalyticState]:
    """Every state row, keyed by analytic id."""
    rows = await db.scalars(select(AnalyticState))
    return {row.analytic_id: row for row in rows}


async def versions(db: AsyncSession, analytic_id: str) -> Sequence[AnalyticVersion]:
    """The transitions of one analytic, in the order they were written.

    By id, not by ``at``. The trail is an append-only log with one writer, so
    the key IS the order. A caller that back-dates one transition and not the
    next would otherwise read its own history out of sequence.
    """
    rows = await db.scalars(
        select(AnalyticVersion)
        .where(AnalyticVersion.analytic_id == analytic_id)
        .order_by(AnalyticVersion.id.asc())
    )
    return rows.all()


async def create_local(
    db: AsyncSession, *, spec_text: str, by: str, now: datetime | None = None
) -> AnalyticState:
    """Validate the text, store it as a candidate, and write the first version row.

    The text is validated before it is stored. A row that does not parse is an
    analytic the catalog must list and cannot run, and the analyst who wrote it
    has already gone.

    A shipped id is refused. The two tiers share one id space, so a local row
    that took a shipped id replaced the file on disk and inherited its sweep
    trail. The shipped analytic then stopped running and its ledger counted the
    runs of the local one.
    """
    text = spec_text.strip() + "\n"
    spec = parse_spec(text)
    if spec.id in load_catalog(CATALOG_DIR):
        raise ValueError(
            f"the id {spec.id!r} is a shipped analytic. Choose another id, or "
            "retire the shipped one."
        )
    if await db.get(AnalyticState, spec.id) is not None:
        raise ValueError(f"an analytic with id {spec.id!r} already exists")
    at = _now(now)
    state = AnalyticState(
        analytic_id=spec.id,
        tier="local",
        status="candidate",
        spec_text=text,
        created_by=by[:80],
        created_at=at,
        updated_at=at,
    )
    db.add(state)
    db.add(
        AnalyticVersion(
            analytic_id=spec.id,
            from_status=None,
            to_status="candidate",
            who=by[:80],
            at=at,
            why="created",
            spec_before=None,
            spec_after=text,
        )
    )
    await db.commit()
    await db.refresh(state)
    return state


async def transition(
    db: AsyncSession,
    analytic_id: str,
    *,
    to_status: str,
    by: str,
    why: str | None,
    receipts: Any | None = None,
    now: datetime | None = None,
) -> AnalyticState:
    """Move one analytic to a new status. Writes one version row."""
    state = await db.get(AnalyticState, analytic_id)
    if state is None:
        raise LookupError(analytic_id)
    if to_status not in ALLOWED_TRANSITIONS.get(state.status, frozenset()):
        raise ValueError(f"{state.status} -> {to_status} is not allowed")
    at = _now(now)
    db.add(
        AnalyticVersion(
            analytic_id=analytic_id,
            from_status=state.status,
            to_status=to_status,
            who=by[:80],
            at=at,
            why=(why or "").strip() or None,
            spec_before=state.spec_text,
            spec_after=state.spec_text,
            # An empty list is not a receipt. Stored as [], the detail view
            # showed an approval that brought evidence and then showed none.
            receipts_json=receipts or None,
        )
    )
    state.status = to_status
    state.reason = (why or "").strip() or None
    state.updated_at = at
    await db.commit()
    await db.refresh(state)
    return state


async def retire_shipped(
    db: AsyncSession,
    analytic_id: str,
    *,
    shipped_text: str,
    by: str,
    why: str,
    now: datetime | None = None,
) -> AnalyticState:
    """Retire a shipped analytic locally. The file on disk does not change.

    A second retirement of the same analytic writes no second version row. A
    retirement is a state, and a repeated request must not make the trail say
    that it happened twice.
    """
    at = _now(now)
    state = await db.get(AnalyticState, analytic_id)
    if state is None:
        state = AnalyticState(
            analytic_id=analytic_id,
            tier="shipped",
            status="live",
            spec_text=None,
            created_by=by[:80],
            created_at=at,
            updated_at=at,
        )
        db.add(state)
        await db.flush()
    if state.status == "retired":
        return state
    db.add(
        AnalyticVersion(
            analytic_id=analytic_id,
            from_status=state.status,
            to_status="retired",
            who=by[:80],
            at=at,
            why=why.strip(),
            spec_before=shipped_text,
            spec_after=shipped_text,
        )
    )
    state.status = "retired"
    state.reason = why.strip()
    state.updated_at = at
    await db.commit()
    await db.refresh(state)
    return state
