"""The local analytics tier and the version trail.

A local analytic is a spec that an analyst or the drafter wrote. It starts as a
candidate. An analyst moves it to shadow, approves it to live, or retires it. A
shipped analytic can only be retired, and reinstated through shadow, because
the file on disk is the analytic and an in-place local edit would make the
repository and the database disagree about what ran. It never becomes a
candidate: there is no text to edit.

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
    "allowed_transitions",
    "create_local",
    "drafted_for_finding",
    "drafted_for_hunt",
    "drafted_from",
    "pinned_analytics",
    "pins_of",
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


def allowed_transitions(tier: str, status: str) -> frozenset[str]:
    """The statuses one analytic may move to, given its tier.

    A shipped analytic has no candidate. Candidate is the status of a spec text
    an analyst is still writing, and the spec of a shipped analytic is the file
    on disk. A shipped row parked there read as editable and never ran.
    """
    targets = ALLOWED_TRANSITIONS.get(status, frozenset())
    if tier == "shipped":
        return targets - {"candidate"}
    return targets


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


def drafted_from(hunt_id: str, ordinal: int) -> str:
    """The reason the first version row of an analytic drafted from a finding carries.

    The draft route reads it back to find the analytic a finding already has.
    """
    return f"drafted from hunt {hunt_id} finding {int(ordinal)}"


def pins_of(version: AnalyticVersion) -> list[str]:
    """The generalization pins a version row carries. Empty for any other row."""
    packet = version.receipts_json
    if not isinstance(packet, dict):
        return []
    found = packet.get("generalization")
    pinned = found.get("pinned") if isinstance(found, dict) else None
    return [str(p) for p in pinned] if isinstance(pinned, list) else []


async def pinned_analytics(db: AsyncSession) -> dict[str, list[str]]:
    """The generalization pins of every drafted analytic that has any. One query.

    Read from the first version row, which the draft route writes. The list
    marks such an analytic "specific", and the drawer lists the pins.
    """
    rows = await db.scalars(
        select(AnalyticVersion).where(
            AnalyticVersion.from_status.is_(None),
            AnalyticVersion.receipts_json.is_not(None),
        )
    )
    out: dict[str, list[str]] = {}
    for version in rows:
        pins = pins_of(version)
        if pins:
            out[version.analytic_id] = pins
    return out


async def drafted_for_finding(db: AsyncSession, hunt_id: str, ordinal: int) -> str | None:
    """The id of the analytic already drafted from this finding, or None.

    A retired analytic does not count: the analyst rejected it, and a new
    draft is a new question.
    """
    rows = await db.execute(
        select(AnalyticVersion.analytic_id)
        .join(AnalyticState, AnalyticState.analytic_id == AnalyticVersion.analytic_id)
        .where(
            AnalyticVersion.why == drafted_from(hunt_id, ordinal),
            AnalyticState.status != "retired",
        )
        .order_by(AnalyticVersion.at.desc())
        .limit(1)
    )
    found = rows.scalar_one_or_none()
    return str(found) if found else None


async def drafted_for_hunt(db: AsyncSession, hunt_id: str) -> dict[int, str]:
    """The analytic drafted from each finding of one hunt, by ordinal. One query.

    The hunt page reads it, so a finding that has an analytic links it and
    offers no second draft, after a reload too.
    """
    prefix = drafted_from(hunt_id, 0).removesuffix("0")
    rows = await db.execute(
        select(AnalyticVersion.why, AnalyticVersion.analytic_id)
        .join(AnalyticState, AnalyticState.analytic_id == AnalyticVersion.analytic_id)
        .where(
            AnalyticVersion.why.startswith(prefix, autoescape=True),
            AnalyticState.status != "retired",
        )
        .order_by(AnalyticVersion.at.asc())
    )
    out: dict[int, str] = {}
    for why, analytic_id in rows.all():
        tail = str(why or "").removeprefix(prefix)
        if tail.isdigit():
            out[int(tail)] = str(analytic_id)
    return out


async def create_local(
    db: AsyncSession,
    *,
    spec_text: str,
    by: str,
    now: datetime | None = None,
    why: str = "created",
    generalization: dict[str, Any] | None = None,
) -> AnalyticState:
    """Validate the text, store it as a candidate, and write the first version row.

    ``generalization`` is what the drafter's generalization check found. It
    rides on the first version row as ``{"generalization": {...}}`` in
    ``receipts_json``. Receipts of an approval are a list, so the two shapes
    never meet.

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
            why=why,
            spec_before=None,
            spec_after=text,
            receipts_json={"generalization": generalization} if generalization else None,
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
    if to_status not in allowed_transitions(state.tier, state.status):
        raise ValueError(
            f"{state.status} -> {to_status} is not allowed for a {state.tier} analytic"
        )
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
