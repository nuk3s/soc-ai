"""Analytics: two tiers, a lifecycle, a ledger, and the shadow-hit list.

The catalog reads as one list. A shipped analytic is a file in the repository
and is live unless an analyst retired it. A local analytic is a row and runs
only once an analyst has put it in shadow.

The shadow-hit routes live here rather than beside the other ``/hunts`` routes
for one reason: ``/hunts/{hunt_id}`` is registered in ``routes_hunts`` and
would swallow ``/hunts/shadow-hits``. The package imports its route modules in
name order, so these two land on the shared router first.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml
from fastapi import Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import (
    LEGACY_OBSERVATION_SOURCE,
    observation_source,
    router,
)
from soc_ai.api.webui.kind_labels import kind_label
from soc_ai.config import Settings
from soc_ai.hunting.catalog_tiers import Catalog, effective_catalog
from soc_ai.hunting.ledger import Ledger, analytic_ledger
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec
from soc_ai.hunting.weight import live_weight
from soc_ai.hunting.wording import reword_legacy_summary
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import analytics as analytics_store
from soc_ai.store.models import EntityObservation

_LOGGER = logging.getLogger(__name__)

# The list shows a week. The detail view shows a month. The list is read at a
# glance and a month of counters on twenty rows hides the one that changed;
# the detail view is read to decide a retirement, and a week is too short to
# decide one on.
_LEDGER_DAYS_LIST = 7
_LEDGER_DAYS_DETAIL = 30

_MAX_SHADOW_HITS = 200
_MAX_RECENT_OBSERVATIONS = 50
_MAX_RECENT_ENTITIES = 20
_MAX_APPROVAL_RECEIPTS = 20

# The host page asks for one week. A host with more observations than this in
# one window is a fleet condition. The panel is not the place to read one.
_MAX_ENTITY_OBSERVATIONS = 200
_MAX_OBSERVATION_DAYS = 90

# The sources that write an analytic hit. ``candidate`` is the retired word
# for the same adapter, and rows written under it are still hits.
_HIT_SOURCES = ("catalog", LEGACY_OBSERVATION_SOURCE)


def _not_found(analytic_id: str) -> HTTPException:
    return api_error(
        404,
        "analytic_not_found",
        f"No analytic has the id '{analytic_id}'. The Analytics tab lists every analytic.",
    )


class AnalyticRowOut(BaseModel):
    """One analytic as the list and the drawer header show it."""

    id: str
    title: str
    level: str
    evaluator: str
    scope_kind: str
    tier: str
    status: str
    no_benign_baseline: bool = False
    observations_7d: int = 0
    leads_7d: int = 0
    hunted_7d: int = 0
    dismissed_7d: int = 0
    shadow_hits_7d: int = 0
    unread_shadow_hits: int = 0


class AnalyticsListOut(BaseModel):
    analytics: list[AnalyticRowOut]
    counts: dict[str, int]


class AnalyticVersionOut(BaseModel):
    from_status: str | None
    to_status: str
    who: str
    at: str
    why: str | None
    has_receipts: bool = False


class AnalyticDetailOut(AnalyticRowOut):
    description: str
    spec_text: str
    reason: str | None = None
    ledger: dict[str, Any]
    versions: list[AnalyticVersionOut]
    recent: list[dict[str, Any]]


class AnalyticCreateIn(BaseModel):
    spec_text: str = Field(min_length=10, max_length=20000)


class AnalyticStatusIn(BaseModel):
    to: str
    why: str | None = None


class DryRunOut(BaseModel):
    """The 30-day dry run of one shadow analytic: how often it fires, and on what."""

    window_days: int = 0
    fires: int = 0
    entities: list[str] = []


class OverlapOut(BaseModel):
    """One live analytic that already observed the same documents."""

    analytic: str = ""
    documents: int = 0


class ReceiptsOut(BaseModel):
    """The evidence behind one shadow hit, in a fixed shape.

    A model rather than a free dictionary. The sweep writes this packet in
    pieces, and a packet that lost a key reached the card as ``undefined`` and
    rendered an empty receipts drawer that looked like a complete one. Every
    part now has a default, so a partial packet is visibly partial.
    """

    matched_ids: list[str] = []
    matched_fields: list[str] = []
    dry_run: DryRunOut | None = None
    overlap: list[OverlapOut] = []
    baseline: dict[str, Any] | None = None
    complete: bool = False
    missing: list[str] = []


class ShadowHitOut(BaseModel):
    """One shadow hit, with enough to render the card and open the receipts.

    ``state`` is ``hit`` only when the receipts are complete. Anything else
    reads ``could_not_run`` and ``missing`` names the part. A hit is never
    hidden: a shadow week that found a true positive and showed nothing is the
    outcome this layer exists to prevent.
    """

    id: int
    analytic_id: str
    analytic_title: str
    entity_kind: str
    entity_key: str
    born_at: str | None
    summary: str | None
    state: str
    missing: list[str]
    receipts: ReceiptsOut | None
    read: bool
    lead_id: int | None
    first_seen_at: str | None = None
    occurrences: int = 1


class ShadowHitsOut(BaseModel):
    hits: list[ShadowHitOut]
    unread: int


class AnalyticHitOut(BaseModel):
    """One analytic hit, live or shadow, as the Analytic hits section renders it.

    The shadow half carries the same fields the shadow band already showed.
    Four fields are added for the joined list. ``analytic_status`` and ``tier``
    let the card carry the chips without a second call. ``lead_status`` tells
    the card whether a lead already holds the hit, which decides the action.
    ``document_count`` is the length of the evidence ids.

    ``analytic_status`` is the status of the analytic now. ``recorded_in_shadow``
    is the flag on the row, which is the status at the last sighting. The two
    differ from an approval until the next sweep refreshes the row.

    ``read`` is null on a live hit. A live hit has no read flag, and false
    there would draw an unread dot on a hit nobody can read.
    """

    id: int
    analytic_id: str
    analytic_title: str
    analytic_status: str
    # True when the row was written while the analytic was in shadow. This is
    # the flag that picks the half, so the card says where the hit was recorded
    # without reading the status as a fact about the hit.
    recorded_in_shadow: bool = False
    tier: str
    entity_kind: str
    entity_key: str
    born_at: str | None
    first_seen_at: str | None = None
    occurrences: int = 1
    summary: str | None
    state: str
    missing: list[str]
    receipts: ReceiptsOut | None
    read: bool | None
    lead_id: int | None
    lead_status: str | None
    document_count: int
    # Whether ``analytic_id`` is an analytic the catalog lists. A hit whose
    # analytic was renamed or removed stays on the surface, so the card has to
    # know that the title opens no drawer.
    analytic_exists: bool = False


class AnalyticHitCountsOut(BaseModel):
    """The four filter chips, counted over the window rather than over the page.

    A page of fifty rows on a night of three hundred must not report the page
    as the night. The shadow band learned this once already.
    """

    all: int = 0
    unread: int = 0
    live: int = 0
    shadow: int = 0


class AnalyticHitsOut(BaseModel):
    hits: list[AnalyticHitOut]
    counts: AnalyticHitCountsOut


def _iso(value: Any) -> str | None:
    return None if value is None else value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def _row(spec_id: str, spec: HuntSpec, cat: Catalog, ledger: Ledger) -> AnalyticRowOut:
    tier, status = cat.status_of(spec_id)
    return AnalyticRowOut(
        id=spec_id,
        title=spec.title,
        level=spec.level,
        evaluator=spec.evaluator,
        scope_kind=str(spec.scope_kind),
        tier=tier,
        status=status,
        no_benign_baseline=bool(spec.no_benign_baseline),
        observations_7d=ledger.observations,
        leads_7d=ledger.leads,
        hunted_7d=ledger.hunted,
        dismissed_7d=sum(ledger.dismissed.values()),
        shadow_hits_7d=ledger.shadow_hits,
        unread_shadow_hits=ledger.unread_shadow_hits,
    )


def _spec_text(analytic_id: str, state: Any) -> str:
    """The YAML of one analytic, from the row for a local one and the file otherwise.

    Raises ``OSError`` if the shipped file is gone. The catalog is loaded from
    the same directory, so this happens only when a deployment lists a file it
    no longer ships. The caller answers 404 and names the file.
    """
    if state is not None and state.spec_text:
        return str(state.spec_text)
    return (CATALOG_DIR / f"{analytic_id}.yaml").read_text()


async def _ledgers_for(
    db: AsyncSession, analytic_ids: list[str], *, since: datetime, now: datetime
) -> dict[str, Ledger]:
    """A ledger per analytic, in one call if the store has a bulk reader.

    The list page reads one ledger per analytic, and each one is four queries.
    Twenty analytics is eighty round trips on every poll. Imported lazily and
    used only if present, so this route works either side of the bulk reader
    landing.
    """
    from soc_ai.hunting import ledger as ledger_module  # noqa: PLC0415 - lazy

    bulk = getattr(ledger_module, "analytic_ledgers", None)
    if bulk is not None:
        try:
            got = await bulk(db, analytic_ids, since=since, now=now)
        except Exception:
            # A read path. A bulk reader that does not answer falls back to the
            # per-analytic one rather than emptying the Analytics tab.
            _LOGGER.warning("bulk ledger read failed; falling back", exc_info=True)
        else:
            return {
                spec_id: got.get(spec_id) or Ledger(analytic_id=spec_id, since=since)
                for spec_id in analytic_ids
            }
    return {
        spec_id: await analytic_ledger(db, spec_id, since=since, now=now)
        for spec_id in analytic_ids
    }


@router.get("/analytics", response_model=AnalyticsListOut)
async def list_analytics(request: Request) -> AnalyticsListOut:
    """Every analytic the app lists, with its tier, its status and a week of outcomes."""
    now = datetime.now(UTC)
    async with request.app.state.db_sessionmaker() as db:
        cat = await effective_catalog(db)
        ledgers = await _ledgers_for(
            db,
            list(cat.listed),
            since=now - timedelta(days=_LEDGER_DAYS_LIST),
            now=now,
        )
    rows = [_row(spec_id, spec, cat, ledgers[spec_id]) for spec_id, spec in cat.listed.items()]
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    return AnalyticsListOut(analytics=rows, counts=counts)


@router.get("/analytics/{analytic_id}", response_model=AnalyticDetailOut)
async def get_analytic(request: Request, analytic_id: str) -> AnalyticDetailOut:
    """One analytic with its ledger, its version history and its recent observations."""
    now = datetime.now(UTC)
    async with request.app.state.db_sessionmaker() as db:
        cat = await effective_catalog(db)
        spec = cat.listed.get(analytic_id)
        if spec is None:
            raise _not_found(analytic_id)
        ledger = await analytic_ledger(
            db, analytic_id, since=now - timedelta(days=_LEDGER_DAYS_DETAIL), now=now
        )
        versions = await analytics_store.versions(db, analytic_id)
        states = await analytics_store.states(db)
        recent_rows = (
            await db.scalars(
                select(EntityObservation)
                .where(EntityObservation.spec_id == analytic_id)
                .order_by(EntityObservation.born_at.desc())
                .limit(_MAX_RECENT_OBSERVATIONS)
            )
        ).all()
    state = states.get(analytic_id)
    by_entity: dict[str, dict[str, Any]] = {}
    for observation in recent_rows:
        entry = by_entity.setdefault(
            observation.entity_key,
            {"entity": observation.entity_key, "count": 0, "lead_id": None, "last": None},
        )
        entry["count"] += int(observation.occurrences or 1)
        entry["lead_id"] = entry["lead_id"] or observation.lead_id
        entry["last"] = entry["last"] or _iso(observation.born_at)
    try:
        spec_text = _spec_text(analytic_id, state)
    except OSError as exc:
        raise api_error(
            404,
            "spec_file_missing",
            f"The catalog lists '{analytic_id}' and this deployment does not ship its file. "
            "Reinstall the app or retire the analytic.",
        ) from exc
    return AnalyticDetailOut(
        **_row(analytic_id, spec, cat, ledger).model_dump(),
        description=spec.description,
        spec_text=spec_text,
        reason=state.reason if state is not None else None,
        ledger=ledger.as_dict(),
        versions=[
            AnalyticVersionOut(
                from_status=version.from_status,
                to_status=version.to_status,
                who=version.who,
                at=_iso(version.at) or "",
                why=version.why,
                has_receipts=bool(version.receipts_json),
            )
            for version in versions
        ],
        recent=list(by_entity.values())[:_MAX_RECENT_ENTITIES],
    )


@router.post("/analytics", status_code=201, response_model=AnalyticRowOut)
async def create_analytic(request: Request, body: AnalyticCreateIn) -> AnalyticRowOut:
    """Store one local analytic as a candidate. It runs only once it is in shadow."""
    by = await identify_caller(request)
    now = datetime.now(UTC)
    async with request.app.state.db_sessionmaker() as db:
        try:
            state = await analytics_store.create_local(db, spec_text=body.spec_text, by=by)
        except (ValueError, yaml.YAMLError) as exc:
            # The store converts most parse failures to ValueError. A YAML
            # error from the loader itself is the same class of mistake and
            # reached the analyst as a 500 with an empty body.
            raise api_error(422, "bad_spec", str(exc)) from exc
        cat = await effective_catalog(db)
        ledger = await analytic_ledger(
            db, state.analytic_id, since=now - timedelta(days=_LEDGER_DAYS_LIST), now=now
        )
    return _row(state.analytic_id, cat.listed[state.analytic_id], cat, ledger)


@router.post("/analytics/{analytic_id}/status", response_model=AnalyticRowOut)
async def set_analytic_status(
    request: Request,
    analytic_id: str,
    body: AnalyticStatusIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> AnalyticRowOut:
    """Move one analytic to a new status.

    A retirement needs a reason: the sharpening loop reads it later, and a
    retirement with no reason is an analytic that disappeared. A shipped
    analytic that is still live can only be retired, because its file on disk
    is the analytic and an in-place local edit would make the repository and
    the database disagree about what ran.
    """
    by = await identify_caller(request)
    now = datetime.now(UTC)
    if body.to not in analytics_store.STATUSES:
        raise api_error(
            422,
            "unknown_status",
            f"'{body.to}' is not an analytic status. "
            f"Use one of: {', '.join(analytics_store.STATUSES)}.",
        )
    if body.to == "retired" and not (body.why or "").strip():
        raise api_error(
            422,
            "reason_required",
            "A retirement needs a reason. Type why you retire this analytic.",
        )
    async with request.app.state.db_sessionmaker() as db:
        cat = await effective_catalog(db)
        if analytic_id not in cat.listed:
            raise _not_found(analytic_id)
        tier, status = cat.status_of(analytic_id)
        try:
            if tier == "shipped" and status == "live":
                if body.to != "retired":
                    raise ValueError("a shipped analytic can only be retired")
                await analytics_store.retire_shipped(
                    db,
                    analytic_id,
                    shipped_text=_spec_text(analytic_id, None),
                    by=by,
                    why=body.why or "",
                )
            else:
                receipts = None
                if body.to == "live":
                    # An empty list is stored as nothing. A shadow analytic
                    # that never fired can still go live, and the version row
                    # must not claim receipts it does not hold.
                    receipts = await _receipts_for_approval(db, analytic_id) or None
                await analytics_store.transition(
                    db, analytic_id, to_status=body.to, by=by, why=body.why, receipts=receipts
                )
        except ValueError as exc:
            allowed = sorted(analytics_store.ALLOWED_TRANSITIONS.get(status, frozenset()))
            targets = ", ".join(allowed) if allowed else "no other status"
            raise api_error(
                422,
                "transition_not_allowed",
                f"An analytic at status '{status}' can move to: {targets}.",
            ) from exc
        except LookupError as exc:
            raise _not_found(analytic_id) from exc
        cat = await effective_catalog(db)
        if body.to == "shadow" and analytic_id in cat.specs:
            # The hourly sweep looks back 24 h. An analytic that enters shadow
            # runs once over the dry-run window now, so its first hit does not
            # wait for a document that may never come inside 24 h.
            await _first_shadow_run(
                db, cat.specs[analytic_id], elastic=elastic, settings=settings, now=now
            )
        ledger = await analytic_ledger(
            db, analytic_id, since=now - timedelta(days=_LEDGER_DAYS_LIST), now=now
        )
    return _row(analytic_id, cat.listed[analytic_id], cat, ledger)


async def _first_shadow_run(
    db: AsyncSession, spec: Any, *, elastic: Any, settings: Any, now: datetime
) -> None:
    """One sweep of a new shadow analytic over the dry-run window. Never fails the caller."""
    from soc_ai.hunting.receipts import DRY_RUN_WINDOW_DAYS  # noqa: PLC0415 - lazy
    from soc_ai.hunting.sweep import sweep_spec  # noqa: PLC0415 - lazy

    try:
        await sweep_spec(
            spec,
            elastic=elastic,
            settings=settings,
            session=db,
            since=f"now-{DRY_RUN_WINDOW_DAYS}d",
            until="now",
            now=now.replace(tzinfo=None),
            record=True,
            backfill=False,
            include_synth=False,
            shadow_ids=frozenset({spec.id}),
        )
        await db.commit()
    except Exception:
        _LOGGER.exception("first shadow run failed for %s", spec.id)


async def _receipts_for_approval(db: AsyncSession, analytic_id: str) -> list[dict[str, Any]]:
    """The receipts of this analytic's shadow hits, attached to the approval.

    An approval to live is a decision, and the version row has to hold the
    evidence it was taken on. Read later, "who approved this and why" is only
    answerable with the receipts they read.
    """
    rows = (
        await db.scalars(
            select(EntityObservation)
            .where(
                EntityObservation.spec_id == analytic_id,
                EntityObservation.shadow.is_(True),
            )
            .order_by(EntityObservation.born_at.desc())
            .limit(_MAX_APPROVAL_RECEIPTS)
        )
    ).all()
    out: list[dict[str, Any]] = []
    for observation in rows:
        evidence = observation.evidence_json if isinstance(observation.evidence_json, dict) else {}
        if isinstance(evidence.get("receipts"), dict):
            out.append(
                {
                    "entity": observation.entity_key,
                    "born_at": _iso(observation.born_at),
                    **evidence["receipts"],
                }
            )
    return out


def _retired_analytics(cat: Catalog) -> list[str]:
    """Analytics an analyst rejected. Their hits leave every hits surface.

    Retirement is the one status that hides a hit. The analyst said the
    analytic is wrong, so what it found is not work.

    An approval hides nothing. The hit is the evidence the approval rests on,
    and it stays a shadow hit, with its read state, until the sweep refreshes
    it as a live observation. Hiding on approval as well took the card off
    every hits surface for the life of the row: too shadow for the live half
    and gone from the shadow half.

    A hit whose analytic the catalog does not know at all stays visible, so a
    renamed or removed analytic cannot hide its hits.
    """
    return [sid for sid, (_tier, status) in cat.tiers.items() if status == "retired"] or [""]


def unread_shadow_hits_where(cat: Catalog) -> tuple[Any, ...]:
    """What makes an unread shadow hit. Every surface that shows one reads this.

    Five surfaces count the same rows: the hits filter, the Needs-you strip,
    the sidebar badge, the Dashboard card and the bell. The bell wrote its own
    query, so it counted a hit from a retired analytic that the page hid, sent
    the analyst to a block that did not hold it, and stayed at one while the
    page read zero. One clause is what keeps them from disagreeing.
    """
    return (
        EntityObservation.shadow.is_(True),
        EntityObservation.read_at.is_(None),
        EntityObservation.spec_id.not_in(_retired_analytics(cat)),
    )


def _evidence_of(observation: EntityObservation) -> dict[str, Any]:
    return observation.evidence_json if isinstance(observation.evidence_json, dict) else {}


def _receipts_of(observation: EntityObservation) -> ReceiptsOut | None:
    """The receipts packet of one hit, or ``None`` when the sweep wrote none."""
    packet = _evidence_of(observation).get("receipts")
    return ReceiptsOut.model_validate(packet) if isinstance(packet, dict) else None


def _hit_state(
    observation: EntityObservation, receipts: ReceiptsOut | None
) -> tuple[str, list[str]]:
    """The state of one hit, and what the receipts are missing.

    The receipts are the proof a shadow analytic works, so the rule applies to
    a shadow hit only. A live analytic was approved on its receipts already.
    The sweep writes no packet for it, and reading the absent packet as
    ``could_not_run`` would mark every live hit broken.
    """
    if not observation.shadow:
        return "hit", []
    complete = bool(receipts and receipts.complete)
    return ("hit" if complete else "could_not_run"), list(
        receipts.missing if receipts else ["receipts"]
    )


def _document_count(observation: EntityObservation) -> int:
    """How many documents the hit cites. The card prints this number."""
    evidence = _evidence_of(observation)
    ids = evidence.get("sample_ids") or evidence.get("citations") or []
    return len(ids) if isinstance(ids, list) else 0


@router.get("/hunts/shadow-hits", response_model=ShadowHitsOut)
async def list_shadow_hits(request: Request, limit: int = 50) -> ShadowHitsOut:
    """Shadow hits, unread first and then newest first.

    A hit without complete receipts reads ``could_not_run`` and names the
    missing part. It is still listed: the analyst must be able to see that an
    analytic fired and could not prove it.
    """
    async with request.app.state.db_sessionmaker() as db:
        cat = await effective_catalog(db)
        rows = (
            await db.scalars(
                select(EntityObservation)
                .where(
                    EntityObservation.shadow.is_(True),
                    EntityObservation.spec_id.not_in(_retired_analytics(cat)),
                )
                .order_by(
                    EntityObservation.read_at.is_not(None),
                    EntityObservation.born_at.desc(),
                )
                .limit(max(1, min(int(limit), _MAX_SHADOW_HITS)))
            )
        ).all()
        # Counted over the whole table, not over this page. The band, the bell
        # and the sidebar all render this number, and a count of the first 50
        # rows says "3 shadow hits need your read" on a night that has 60.
        unread = await _count_hits(db, *unread_shadow_hits_where(cat))
    hits: list[ShadowHitOut] = []
    for observation in rows:
        receipts = _receipts_of(observation)
        state, missing = _hit_state(observation, receipts)
        spec = cat.listed.get(observation.spec_id)
        hits.append(
            ShadowHitOut(
                id=observation.id,
                analytic_id=observation.spec_id,
                analytic_title=spec.title if spec else observation.spec_id,
                entity_kind=observation.entity_kind,
                entity_key=observation.entity_key,
                born_at=_iso(observation.born_at),
                first_seen_at=_iso(observation.first_seen_at),
                occurrences=int(observation.occurrences or 1),
                summary=reword_legacy_summary(observation.summary),
                state=state,
                missing=missing,
                receipts=receipts,
                read=observation.read_at is not None,
                lead_id=observation.lead_id,
            )
        )
    return ShadowHitsOut(hits=hits, unread=unread)


@router.post("/hunts/shadow-hits/{obs_id}/read")
async def mark_shadow_hit_read(request: Request, obs_id: int) -> dict[str, bool]:
    """Mark one shadow hit read. Opening the receipts is what reads it."""
    async with request.app.state.db_sessionmaker() as db:
        row = await db.get(EntityObservation, obs_id)
        if row is None or not row.shadow:
            raise api_error(
                404,
                "shadow_hit_not_found",
                f"No shadow hit has the id {obs_id}. "
                "The shadow band on the Hunts page lists every shadow hit.",
            )
        if row.read_at is None:
            row.read_at = datetime.now(UTC).replace(tzinfo=None)
            await db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Analytic hits: one surface for the live half and the shadow half
# ---------------------------------------------------------------------------
#
# The shadow band showed the shadow half only, so nobody could see what a real
# hit looks like. This list holds both. The live half comes first and carries
# the weight. The shadow half is provisional and follows, unread first.
#
# The routes sit here rather than beside the other /hunts routes for the reason
# the module docstring gives: ``/hunts/{hunt_id}`` in ``routes_hunts`` matches
# one path segment, and the package registers these modules in name order.

_HIT_FILTERS = ("all", "unread", "live", "shadow")
_MAX_HIT_DAYS = 30
_MAX_HITS = 200


def _hit_bounds(days: int, hit_filter: str, limit: int) -> tuple[int, str, int]:
    """Check the three query parameters, or refuse with a reason and a hint."""
    if not 1 <= days <= _MAX_HIT_DAYS:
        raise api_error(
            422,
            "bad_days",
            f"Ask for 1 to {_MAX_HIT_DAYS} days. The section shows 7 days by default.",
        )
    if hit_filter not in _HIT_FILTERS:
        raise api_error(
            422,
            "bad_filter",
            "Name a hit type in 'filter': all, unread, live or shadow.",
        )
    if not 1 <= limit <= _MAX_HITS:
        raise api_error(
            422,
            "bad_limit",
            f"Ask for 1 to {_MAX_HITS} hits. The section asks for 50 by default.",
        )
    return days, hit_filter, limit


def _hit_row(
    observation: EntityObservation, cat: Catalog, lead_status: str | None
) -> AnalyticHitOut:
    """One hit as the card renders it."""
    receipts = _receipts_of(observation)
    state, missing = _hit_state(observation, receipts)
    spec = cat.listed.get(observation.spec_id)
    tier, status = cat.status_of(observation.spec_id)
    shadow = bool(observation.shadow)
    # The status of the analytic now. The card offered "Approve analytic" on an
    # analytic the analyst had approved already, because it read the row flag as
    # the status. The catalog answers for every analytic it knows. For one it
    # lost, the flag on the row is the only answer left.
    now_status = status if observation.spec_id in cat.tiers else ("shadow" if shadow else "live")
    return AnalyticHitOut(
        id=observation.id,
        analytic_id=observation.spec_id,
        analytic_title=spec.title if spec else observation.spec_id,
        analytic_status=now_status,
        # The flag that put the row in one half or the other. It stays until
        # the sweep writes the row again, so the card can say where the hit was
        # recorded without calling an approved analytic provisional.
        recorded_in_shadow=shadow,
        tier=tier,
        entity_kind=observation.entity_kind,
        entity_key=observation.entity_key,
        born_at=_iso(observation.born_at),
        first_seen_at=_iso(observation.first_seen_at),
        occurrences=int(observation.occurrences or 1),
        summary=reword_legacy_summary(observation.summary),
        state=state,
        missing=missing,
        receipts=receipts,
        read=(observation.read_at is not None) if shadow else None,
        lead_id=observation.lead_id,
        lead_status=lead_status,
        document_count=_document_count(observation),
        analytic_exists=spec is not None,
    )


@router.get("/hunts/hits", response_model=AnalyticHitsOut)
async def list_analytic_hits(
    request: Request,
    days: int = Query(default=7, description="How many days the section covers. 1 to 30."),
    hit_filter: str = Query(default="all", alias="filter"),
    limit: int = Query(default=50),
) -> AnalyticHitsOut:
    """Every analytic hit from the last ``days`` days, live and shadow.

    Order: live hits first, newest first. Then shadow hits, unread first, then
    newest first. The live hit is the real signal and it leads the list.

    ``counts`` is read over the whole window, not over the returned page. The
    chips would otherwise report the page as the night.
    """
    from soc_ai.store.models import Lead  # noqa: PLC0415 - lazy, as the leads routes do

    days, hit_filter, limit = _hit_bounds(days, hit_filter, limit)
    since = (datetime.now(UTC) - timedelta(days=days)).replace(tzinfo=None)
    async with request.app.state.db_sessionmaker() as db:
        cat = await effective_catalog(db)
        in_window = (
            EntityObservation.source.in_(_HIT_SOURCES),
            EntityObservation.born_at >= since,
        )
        # The flag on the row picks the half. The two halves therefore hold
        # every hit in the window except the retired ones, and no hit can fall
        # between them. Reading the analytic's status for the live half instead
        # hid every hit whose analytic the catalog no longer knows.
        retired = _retired_analytics(cat)
        is_shadow = (
            EntityObservation.shadow.is_(True),
            EntityObservation.spec_id.not_in(retired),
        )
        is_live = (
            EntityObservation.shadow.is_(False),
            EntityObservation.spec_id.not_in(retired),
        )
        live_rows: list[EntityObservation] = []
        shadow_rows: list[EntityObservation] = []
        if hit_filter in ("all", "live"):
            live_rows = list(
                (
                    await db.scalars(
                        select(EntityObservation)
                        .where(*in_window, *is_live)
                        .order_by(EntityObservation.born_at.desc(), EntityObservation.id.desc())
                        .limit(limit)
                    )
                ).all()
            )
        if hit_filter in ("all", "shadow", "unread"):
            unread_only = (EntityObservation.read_at.is_(None),) if hit_filter == "unread" else ()
            shadow_rows = list(
                (
                    await db.scalars(
                        select(EntityObservation)
                        .where(*in_window, *is_shadow, *unread_only)
                        .order_by(
                            EntityObservation.read_at.is_not(None),
                            EntityObservation.born_at.desc(),
                            EntityObservation.id.desc(),
                        )
                        .limit(limit)
                    )
                ).all()
            )
        rows = (live_rows + shadow_rows)[:limit]
        counts = AnalyticHitCountsOut(
            live=await _count_hits(db, *in_window, *is_live),
            shadow=await _count_hits(db, *in_window, *is_shadow),
            unread=await _count_hits(
                db, *in_window, *is_shadow, EntityObservation.read_at.is_(None)
            ),
        )
        counts.all = counts.live + counts.shadow
        lead_ids = {int(r.lead_id) for r in rows if r.lead_id}
        lead_status: dict[int, str] = {}
        if lead_ids:
            lead_status = {
                int(lead.id): str(lead.status)
                for lead in (await db.scalars(select(Lead).where(Lead.id.in_(lead_ids)))).all()
            }
    return AnalyticHitsOut(
        hits=[_hit_row(r, cat, lead_status.get(int(r.lead_id or 0))) for r in rows],
        counts=counts,
    )


async def _count_hits(db: AsyncSession, *where: Any) -> int:
    return int((await db.scalar(select(func.count(EntityObservation.id)).where(*where))) or 0)


class NeedsYouOut(BaseModel):
    """What waits on the analyst right now.

    The sidebar badge on Hunts and the Needs-you strip both read this. Two
    things wait: a shadow hit nobody has read, and a lead nobody has decided.
    """

    unread_shadow_hits: int = 0
    leads_needing_decision: int = 0
    total: int = 0
    # The live "A lead starts its own hunt" setting. The leads block reads it
    # here, because the config route is for admins and the block must say
    # which of the two rules this deployment runs.
    lead_auto_hunt: bool = True


@router.get("/hunts/needs-you", response_model=NeedsYouOut)
async def needs_you(request: Request) -> NeedsYouOut:
    """The Needs-you count.

    A lead waits on a decision when it is hunting and its hunt has finished. A
    hunt has finished when it is not running and not queued. A cancelled hunt
    and an interrupted hunt are terminal, so the lead behind one waits on a
    decision as well.

    A lead with no hunt waits only when nothing will start one for it: the
    auto-hunt loop is off, or the lead was reopened. The rule is the lead
    store's, and the Needs decision tab reads the same one.
    """
    from soc_ai.store import leads as leads_store  # noqa: PLC0415 - lazy
    from soc_ai.store.models import Hunt, Lead  # noqa: PLC0415 - lazy

    auto_hunt = bool(getattr(request.app.state.settings, "lead_auto_hunt", False))
    async with request.app.state.db_sessionmaker() as db:
        cat = await effective_catalog(db)
        unread = await _count_hits(db, *unread_shadow_hits_where(cat))
        leads = int(
            (
                await db.scalar(
                    select(func.count(Lead.id))
                    .outerjoin(Hunt, Hunt.id == Lead.hunt_id)
                    .where(leads_store.needs_decision_clause(auto_hunt=auto_hunt))
                )
            )
            or 0
        )
    return NeedsYouOut(
        unread_shadow_hits=unread,
        leads_needing_decision=leads,
        total=unread + leads,
        lead_auto_hunt=auto_hunt,
    )


class EntityObservationOut(BaseModel):
    """One observation on one entity, as the host page lists it."""

    id: int
    kind: str
    # The analyst's words for `kind`. The panel prints this one.
    kind_label: str = ""
    spec_id: str
    source: str
    shadow: bool
    summary: str | None
    weight_now: float
    lead_id: int | None
    born_at: str | None
    # When the row was first written. The panel says "first seen 3d ago"
    # beside the sweep count, so a repeat reads as a duration and not a tally.
    first_seen_at: str | None = None
    occurrences: int
    read: bool
    # Whether ``spec_id`` is an analytic the catalog lists. An alert verdict
    # and a promoted hunt finding are recorded under a spec id that names the
    # adapter, so the row links to no analytic.
    analytic_exists: bool = False


class EntityObservationsOut(BaseModel):
    entity: str
    days: int
    observations: list[EntityObservationOut]


@router.get("/hunts/observations", response_model=EntityObservationsOut)
async def list_observations(
    request: Request,
    entity: str = Query(default="", description="The entity key. One entity per call."),
    days: int = Query(default=7, ge=1, le=_MAX_OBSERVATION_DAYS),
) -> EntityObservationsOut:
    """Every observation on one entity from every source, newest first.

    The live weight is computed on read, as it is on the lead page. A repeated
    single signal is visible here before it forms a lead.

    ``entity`` is required and must hold a value. The route checks it rather
    than the query validator, so a blank one answers ``entity_required``
    instead of the generic ``bad_request``. A blank entity used to match no row
    and read as "this host has no observations".

    This route sits beside the shadow-hit routes for the reason the module
    docstring gives. ``/hunts/{hunt_id}`` in ``routes_hunts`` matches one path
    segment and is registered first, so the same route defined there answers
    404 with ``hunt_id`` set to ``observations``.
    """
    entity = entity.strip()
    if not entity:
        raise api_error(
            422,
            "entity_required",
            "Name the entity in the 'entity' parameter. One call reads one entity.",
        )
    now = datetime.now(UTC)
    since = (now - timedelta(days=days)).replace(tzinfo=None)
    async with request.app.state.db_sessionmaker() as db:
        cat = await effective_catalog(db)
        rows = (
            await db.scalars(
                select(EntityObservation)
                .where(
                    EntityObservation.entity_key == entity,
                    EntityObservation.born_at >= since,
                )
                .order_by(EntityObservation.born_at.desc(), EntityObservation.id.desc())
                .limit(_MAX_ENTITY_OBSERVATIONS)
            )
        ).all()
    return EntityObservationsOut(
        entity=entity,
        days=days,
        observations=[
            EntityObservationOut(
                id=observation.id,
                kind=observation.kind,
                kind_label=kind_label(observation.kind),
                spec_id=observation.spec_id,
                source=observation_source(observation.source),
                shadow=bool(observation.shadow),
                summary=reword_legacy_summary(observation.summary),
                weight_now=round(
                    live_weight(
                        float(observation.birth_weight or 0.0),
                        born_at=observation.born_at,
                        count=int(observation.occurrences or 1),
                        now=now,
                    ),
                    3,
                ),
                lead_id=observation.lead_id,
                born_at=_iso(observation.born_at),
                first_seen_at=_iso(observation.first_seen_at),
                occurrences=int(observation.occurrences or 1),
                read=observation.read_at is not None,
                analytic_exists=observation.spec_id in cat.listed,
            )
            for observation in rows
        ],
    )
