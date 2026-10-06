"""The local analytics tier and the version trail.

A local analytic is a spec that an analyst or the drafter wrote. It starts as a
candidate. An analyst moves it to shadow, approves it to live, or retires it. A
shipped analytic can only be retired, and reinstated through shadow, because
the file on disk is the analytic and an in-place local edit would make the
repository and the database disagree about what ran. It never becomes a
candidate: there is no text to edit.

Every transition writes a version row with the spec text before and after, so
the history of an analytic is readable and diffable in the app.

A shipped analytic whose file says ``ships_as: shadow`` gets a shadow row on
the first catalog load that finds none (:func:`seed_shipped_shadow`). The
system writes that row. Approval to live stays an analyst's action.

One transition belongs to the system alone: live to shadow
(:func:`demote_to_shadow`). The self-healing hold calls it when a live analytic
breaches its fire budget or its precision floor. A system actor can never
approve an analytic to live and can never retire one. Both stay human.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.spec import CATALOG_DIR, load_catalog, parse_spec
from soc_ai.store.models import AnalyticState, AnalyticVersion

if TYPE_CHECKING:
    from soc_ai.hunting.spec import HuntSpec

__all__ = [
    "ALLOWED_TRANSITIONS",
    "CATALOG_ACTOR",
    "SHIPPED_IN_SHADOW_REASON",
    "STATUSES",
    "SYSTEM_ACTOR",
    "SystemActorRefused",
    "allowed_transitions",
    "create_local",
    "demote_to_shadow",
    "drafted_for_finding",
    "drafted_for_hunt",
    "drafted_from",
    "evidence_of",
    "is_system_actor",
    "is_system_demotion",
    "latest_live_at",
    "latest_system_demotion",
    "pinned_analytics",
    "pins_of",
    "retire_shipped",
    "seed_shipped_shadow",
    "states",
    "system_holds",
    "transition",
    "versions",
]

STATUSES: tuple[str, ...] = ("candidate", "shadow", "live", "retired")

# The hands soc-ai signs its own transitions with. A username cannot hold a
# colon (the user route checks the pattern), and an API token signs as
# ``token:<name>``, so a ``system:`` actor names a code path and never a person.
# The bare word ``system`` counts as well. A person with that username then
# cannot approve or retire, and a refusal is the safe side of that mistake.
SYSTEM_ACTOR = "system:self-heal"
CATALOG_ACTOR = "system:catalog"

# The reason on the first row of a shipped analytic that ships in shadow.
SHIPPED_IN_SHADOW_REASON = (
    "The analytic shipped in shadow. An analyst approves it to live after the shadow week."
)


def is_system_actor(by: str) -> bool:
    """Whether a transition is signed by soc-ai itself and by no person."""
    hand = (by or "").strip().lower()
    return hand == "system" or hand.startswith("system:")


# The statuses a system actor may never move an analytic to. Approval to live
# and retirement are an analyst's decisions: an agentic outcome can lower trust
# in a detector, and only an analyst decision can raise it or end it.
_HUMAN_ONLY_TARGETS: frozenset[str] = frozenset({"live", "retired"})


class SystemActorRefused(ValueError):
    """A system actor asked for a transition only an analyst may take.

    A ValueError, so every caller that refuses a transition it does not allow
    refuses this one the same way.
    """


def _refuse_system(by: str, to_status: str) -> None:
    if to_status in _HUMAN_ONLY_TARGETS and is_system_actor(by):
        verb = "approve an analytic to live" if to_status == "live" else "retire an analytic"
        raise SystemActorRefused(f"a system actor ({by}) cannot {verb}. An analyst decides that.")


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
    if "ships_as" in spec.model_fields_set:
        # Read only for a shipped analytic with no row. A local analytic
        # always has a row and starts as a candidate, so the field would be
        # parsed, stored and never read.
        raise ValueError(
            "ships_as applies to a shipped analytic. A local analytic starts as a "
            "candidate. Remove the field."
        )
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
    """Move one analytic to a new status. Writes one version row.

    A system actor is refused a move to live or to retired, before the row is
    read. The system has one transition of its own, :func:`demote_to_shadow`.
    """
    _refuse_system(by, to_status)
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

    A system actor is refused. A retirement is an analyst's decision.
    """
    _refuse_system(by, "retired")
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


async def seed_shipped_shadow(
    db: AsyncSession,
    shipped: Mapping[str, HuntSpec],
    *,
    now: datetime | None = None,
) -> list[str]:
    """Write a shadow row for each shipped analytic that ships in shadow and has no row.

    Returns the ids it wrote. A second call writes nothing, because the row
    exists. Any row stops the write, whatever its status: a row is a decision
    already on record. A retired analytic stays retired, and an analytic held
    in shadow stays in shadow until an analyst approves it. A file that ships
    live writes nothing, so every shipped analytic with no field stays live.

    The catalog reads such an analytic as shadow before the row exists (see
    :func:`soc_ai.hunting.catalog_tiers.effective_catalog`), so a read path
    that never writes still never runs it live. The row is what an approval
    moves.
    """
    wanted = [spec_id for spec_id, spec in shipped.items() if spec.ships_as == "shadow"]
    if not wanted:
        return []
    have = set(
        (
            await db.scalars(
                select(AnalyticState.analytic_id).where(AnalyticState.analytic_id.in_(wanted))
            )
        ).all()
    )
    at = _now(now)
    written: list[str] = []
    for spec_id in wanted:
        if spec_id in have:
            continue
        db.add(
            AnalyticState(
                analytic_id=spec_id,
                tier="shipped",
                status="shadow",
                spec_text=None,
                created_by=CATALOG_ACTOR,
                created_at=at,
                updated_at=at,
                reason=SHIPPED_IN_SHADOW_REASON,
            )
        )
        db.add(
            AnalyticVersion(
                analytic_id=spec_id,
                from_status=None,
                to_status="shadow",
                who=CATALOG_ACTOR,
                at=at,
                why=SHIPPED_IN_SHADOW_REASON,
                spec_before=None,
                spec_after=None,
            )
        )
        written.append(spec_id)
    if written:
        await db.commit()
    return written


def _shipped_text(analytic_id: str) -> str | None:
    """The file of a shipped analytic, or None when this deployment does not ship one."""
    try:
        return (CATALOG_DIR / f"{analytic_id}.yaml").read_text()
    except OSError:
        return None


async def demote_to_shadow(
    db: AsyncSession,
    analytic_id: str,
    *,
    reason: str,
    evidence: dict[str, Any] | None,
    actor: str = SYSTEM_ACTOR,
    now: datetime | None = None,
) -> AnalyticState:
    """Move one live analytic back to shadow, in a system hand. Writes one version row.

    The version row holds the actor, the reason and the evidence. The evidence
    rides in ``receipts_json`` as ``{"evidence": {...}}``: the receipts of an
    approval are a list and the pins of a draft are ``{"generalization": ...}``,
    so the three shapes never meet.

    The observations the analytic wrote stay as they are. They were written
    live and they were read live. Marking them shadow afterwards would rewrite
    what the analyst already saw. The next sweep writes the analytic's new
    observations in shadow.

    A shipped analytic with no row is live by default. The demotion writes its
    first row. An analytic already in shadow returns unchanged with no second
    version row: a hold is a state, and a repeated check must not make the
    trail say that it happened twice. Any other status is refused, so a
    demotion can never revive a retired analytic.

    Only a system actor demotes. An analyst who disagrees with an analytic
    retires it with a reason, which this function never does.
    """
    if not is_system_actor(actor):
        raise ValueError(
            f"{actor!r} is not a system actor. An analyst retires an analytic with a reason."
        )
    why = (reason or "").strip()
    if not why:
        raise ValueError("a demotion needs a reason")
    at = _now(now)
    state = await db.get(AnalyticState, analytic_id)
    if state is None:
        if _shipped_text(analytic_id) is None:
            raise LookupError(analytic_id)
        state = AnalyticState(
            analytic_id=analytic_id,
            tier="shipped",
            status="live",
            spec_text=None,
            created_by=actor[:80],
            created_at=at,
            updated_at=at,
        )
        db.add(state)
        await db.flush()
    if state.status == "shadow":
        return state
    if state.status != "live":
        raise ValueError(f"{state.status} -> shadow is not a demotion. Only a live analytic moves.")
    text = state.spec_text if state.tier == "local" else _shipped_text(analytic_id)
    db.add(
        AnalyticVersion(
            analytic_id=analytic_id,
            from_status="live",
            to_status="shadow",
            who=actor[:80],
            at=at,
            why=why,
            spec_before=text,
            spec_after=text,
            receipts_json={"evidence": evidence} if evidence else None,
        )
    )
    state.status = "shadow"
    state.reason = why
    state.updated_at = at
    await db.commit()
    await db.refresh(state)
    return state


def evidence_of(version: AnalyticVersion) -> dict[str, Any] | None:
    """The evidence a demotion row carries. None for any other row."""
    packet = version.receipts_json
    if not isinstance(packet, dict):
        return None
    found = packet.get("evidence")
    return dict(found) if isinstance(found, dict) else None


def is_system_demotion(version: AnalyticVersion) -> bool:
    """Whether a version row is a live-to-shadow move in a system hand."""
    return (
        version.from_status == "live"
        and version.to_status == "shadow"
        and is_system_actor(version.who)
    )


async def _newest_rows(
    db: AsyncSession, *where: Any, analytic_ids: Sequence[str] | None = None
) -> dict[str, AnalyticVersion]:
    """The newest version row per analytic among the rows that match ``where``.

    Newest by id: the trail is an append-only log with one writer, so the key
    IS the order. One query.
    """
    newest = select(func.max(AnalyticVersion.id)).where(*where)
    if analytic_ids is not None:
        wanted = list(dict.fromkeys(str(i) for i in analytic_ids))
        if not wanted:
            return {}
        newest = newest.where(AnalyticVersion.analytic_id.in_(wanted))
    newest = newest.group_by(AnalyticVersion.analytic_id)
    rows = await db.scalars(select(AnalyticVersion).where(AnalyticVersion.id.in_(newest)))
    return {row.analytic_id: row for row in rows}


async def latest_live_at(
    db: AsyncSession, analytic_ids: Sequence[str] | None = None
) -> dict[str, datetime]:
    """When each analytic last moved to live. An analytic never moved there is absent.

    A shipped analytic that has been live since its file shipped has no such
    row. Its window then starts at the window's own edge.
    """
    rows = await _newest_rows(db, AnalyticVersion.to_status == "live", analytic_ids=analytic_ids)
    return {analytic_id: row.at for analytic_id, row in rows.items()}


async def latest_system_demotion(
    db: AsyncSession, analytic_ids: Sequence[str] | None = None
) -> dict[str, AnalyticVersion]:
    """The newest live-to-shadow row in a system hand, per analytic."""
    rows = await _newest_rows(
        db,
        AnalyticVersion.from_status == "live",
        AnalyticVersion.to_status == "shadow",
        func.lower(AnalyticVersion.who).startswith("system"),
        analytic_ids=analytic_ids,
    )
    return {analytic_id: row for analytic_id, row in rows.items() if is_system_demotion(row)}


async def system_holds(db: AsyncSession) -> dict[str, AnalyticVersion]:
    """The analytics a system demotion holds in shadow now, with that demotion row.

    An analytic counts when its newest version row is a system demotion and it
    is still in shadow. An approval or a retirement writes a newer row, and the
    hold then ends. The Analytics tab, the drawer and the bell read this one
    answer.
    """
    newest = await _newest_rows(db)
    held = {analytic_id: row for analytic_id, row in newest.items() if is_system_demotion(row)}
    if not held:
        return {}
    shadow = set(
        (
            await db.scalars(
                select(AnalyticState.analytic_id).where(
                    AnalyticState.analytic_id.in_(list(held)),
                    AnalyticState.status == "shadow",
                )
            )
        ).all()
    )
    return {analytic_id: row for analytic_id, row in held.items() if analytic_id in shadow}
