"""The lead layer after the production review of 2026-11-12.

Each block pins one rule and names the production case behind it. The review
report is `hunts.md`. Every block holds a negative control: a case that must
still hold after the change.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.leads import content_fingerprint, form_leads, record_observation
from soc_ai.hunting.weight import Kind, decay_horizon_hours
from soc_ai.store import leads as leads_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, Hunt, Lead
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

_HOST = ("host", "10.1.10.21")


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _observe(  # type: ignore[no-untyped-def]
    db,
    kind: Kind,
    member: str,
    *,
    now: datetime,
    ids: tuple[str, ...],
    host: str = _HOST[1],
    spec: str = "s",
    shadow: bool = False,
    observed_at: datetime | None = None,
    **fields: Any,
) -> EntityObservation:
    """One observation on one host. ``ids`` are the documents the sighting cites."""
    return await record_observation(
        db,
        entity_kind="host",
        entity_key=host,
        kind=kind,
        spec_id=spec,
        fingerprint=content_fingerprint("dim", member),
        summary=f"{kind.value}: {member}",
        evidence={"sample_ids": list(ids)},
        now=now,
        shadow=shadow,
        observed_at=observed_at,
        **fields,
    )


async def _three_kinds(db, *, now: datetime, ids: str) -> None:  # type: ignore[no-untyped-def]
    """Three types on the host. Together they form one lead."""
    await _observe(db, Kind.NOVEL_DESTINATION, "203.0.113.10", now=now, ids=(f"{ids}1",))
    await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe", now=now, ids=(f"{ids}2",))
    await _observe(db, Kind.OFF_HOURS, "03:14", now=now, ids=(f"{ids}3",))


async def _rows(db) -> list[EntityObservation]:  # type: ignore[no-untyped-def]
    return list(
        (await db.execute(select(EntityObservation).order_by(EntityObservation.id))).scalars().all()
    )


async def _hunt(  # type: ignore[no-untyped-def]
    db,
    lead_id: int,
    *,
    hunt_id: str,
    findings: list[dict[str, Any]] | None = None,
    finished_at: datetime | None = None,
) -> Hunt:
    """A complete lead hunt on the lead, and the lead marked hunting on it."""
    hunt = Hunt(
        id=hunt_id,
        objective="o",
        objective_hash="x",
        started_by="auto-hunt",
        kind="lead",
        starter="lead",
        status="complete",
        lead_id=lead_id,
        narrative="No malicious indication on the host. The traffic is a backup job.",
        report={"findings": findings or [], "narrative": "n"},
        finished_at=finished_at.replace(tzinfo=None) if finished_at else None,
    )
    db.add(hunt)
    await db.commit()
    await leads_store.mark_hunting(db, lead_id, hunt_id=hunt_id)
    return hunt


# ---------------------------------------------------------------------------
# C6. A new sighting after a lead closes does not join the closed lead
# ---------------------------------------------------------------------------
#
# hunts.md finding 11. 32 observations fired again after their lead closed and
# stayed attached to it. A lead on a build host closed on 2026-10-14. Four
# telemetry silence rows fired again from 2026-11-09, with 350 occurrences,
# and no lead could form: the closed lead consumed every repeat for all time.


async def test_a_fresh_sighting_past_the_horizon_leaves_the_promoted_lead(
    settings_kratos: Settings,
) -> None:
    now = datetime.now(UTC)
    closed_at = now - timedelta(hours=decay_horizon_hours() + 2)
    formed_at = closed_at - timedelta(hours=1)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _three_kinds(db, now=formed_at, ids="a")
        first = await form_leads(db, entity_keys=[_HOST], now=formed_at)
        lead_id = first.formed[0]
        await leads_store.mark_promoted(db, lead_id, investigation_id="01INV", now=closed_at)

        # The same three conditions fire again, each on a new document.
        await _three_kinds(db, now=now, ids="b")
        second = await form_leads(db, entity_keys=[_HOST], now=now)
        rows = await _rows(db)
        closed = await db.get(Lead, lead_id)
    assert closed.status == "promoted"
    # Free to form under the normal rules: three types over the threshold.
    assert len(second.formed) == 1 and second.formed[0] != lead_id
    assert {r.lead_id for r in rows} == {second.formed[0]}
    # The sightings the closed lead answered do not count again.
    assert {r.occurrences for r in rows} == {1}


async def test_a_reread_of_the_same_documents_stays_on_the_closed_lead(
    settings_kratos: Settings,
) -> None:
    """A re-read is no sighting. Only a new document after the close releases a row."""
    now = datetime.now(UTC)
    closed_at = now - timedelta(hours=decay_horizon_hours() + 2)
    formed_at = closed_at - timedelta(hours=1)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _three_kinds(db, now=formed_at, ids="a")
        first = await form_leads(db, entity_keys=[_HOST], now=formed_at)
        await leads_store.mark_promoted(db, first.formed[0], investigation_id="01I", now=closed_at)
        await _three_kinds(db, now=now, ids="a")
        again = await form_leads(db, entity_keys=[_HOST], now=now)
        rows = await _rows(db)
    assert again.formed == () and again.updated == ()
    assert {r.lead_id for r in rows} == {first.formed[0]}


async def test_a_document_older_than_the_close_does_not_release_the_row(
    settings_kratos: Settings,
) -> None:
    """The sweep reads a window that reaches back before the close.

    A new sample document of the event that the closed lead already answered
    is no new sighting. Released, the row would form a second lead on the
    activity that the lead was closed on.
    """
    now = datetime.now(UTC)
    closed_at = now - timedelta(hours=decay_horizon_hours() + 2)
    formed_at = closed_at - timedelta(hours=1)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _three_kinds(db, now=formed_at, ids="a")
        first = await form_leads(db, entity_keys=[_HOST], now=formed_at)
        await leads_store.mark_promoted(db, first.formed[0], investigation_id="01I", now=closed_at)
        row = await _observe(
            db,
            Kind.NOVEL_DESTINATION,
            "203.0.113.10",
            now=now,
            ids=("late",),
            observed_at=formed_at,
        )
    assert row.lead_id == first.formed[0]


async def test_a_repeat_inside_the_horizon_of_a_hunt_close_stays_as_history(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. The hunt answered these types on this host.

    Inside the decay horizon of the close the same repeat would start the
    same hunt. The repeat stays on the closed lead and forms nothing. Past the
    horizon the row is released.
    """
    now = datetime.now(UTC)
    formed_at = now - timedelta(hours=30)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _three_kinds(db, now=formed_at, ids="a")
        first = await form_leads(db, entity_keys=[_HOST], now=formed_at)
        lead_id = first.formed[0]
        hunt = await _hunt(db, lead_id, hunt_id="01HUNTCLEAN")
        closed_at = now - timedelta(hours=29)
        assert await leads_store.settle_after_hunt(db, hunt, now=closed_at) == "closed"

        await _three_kinds(db, now=now, ids="b")
        inside = await form_leads(db, entity_keys=[_HOST], now=now)
        held = {r.lead_id for r in await _rows(db)}

        later = closed_at + timedelta(hours=decay_horizon_hours() + 1)
        await _three_kinds(db, now=later, ids="c")
        outside = await form_leads(db, entity_keys=[_HOST], now=later)
        rows = await _rows(db)
    assert inside.formed == () and inside.updated == ()
    assert held == {lead_id}
    assert len(outside.formed) == 1 and outside.formed[0] != lead_id
    assert {r.lead_id for r in rows} == {outside.formed[0]}


@pytest.mark.parametrize("reason", leads_store.DISMISS_REASONS)
async def test_a_dismissal_by_an_analyst_mutes_the_repeats_with_no_time_limit(
    settings_kratos: Settings, reason: str
) -> None:
    """NEGATIVE CONTROL. Every reason an analyst can give mutes the same way.

    The console states the scope of a dismissal: "The observations on this
    lead and their repeats form no new lead. No time window applies. Select
    Reopen to undo." The store reads no reason code to decide it, so the mute
    holds for each of the nine reasons, far past the decay horizon.
    """
    now = datetime.now(UTC)
    formed_at = now - timedelta(days=60)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _three_kinds(db, now=formed_at, ids="a")
        first = await form_leads(db, entity_keys=[_HOST], now=formed_at)
        lead_id = first.formed[0]
        await leads_store.dismiss(
            db, lead_id, reason=reason, note=None, by="ann", now=formed_at + timedelta(hours=1)
        )
        await _three_kinds(db, now=now, ids="b")
        repeat = await form_leads(db, entity_keys=[_HOST], now=now)
        rows = await _rows(db)
        # The scope is the observations on the lead. A new observation on the
        # same host forms a new lead at once.
        await _observe(db, Kind.NOVEL_PROCESS, "rundll32.exe", now=now, ids=("n1",))
        await _observe(db, Kind.NOVEL_SERVED_PORT, "4444", now=now, ids=("n2",))
        fresh = await form_leads(db, entity_keys=[_HOST], now=now)
    assert repeat.formed == () and repeat.updated == ()
    assert {r.lead_id for r in rows} == {lead_id}
    assert {r.occurrences for r in rows} == {2}
    assert len(fresh.formed) == 1


async def test_reopen_ends_the_mute_of_a_dismissal(settings_kratos: Settings) -> None:
    """The mute lasts until an analyst reopens the lead. The rows are then on an open lead."""
    now = datetime.now(UTC)
    formed_at = now - timedelta(hours=5)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _three_kinds(db, now=formed_at, ids="a")
        first = await form_leads(db, entity_keys=[_HOST], now=formed_at)
        lead_id = first.formed[0]
        await leads_store.dismiss(db, lead_id, reason="lab_host", note=None, by="ann", now=now)
        await leads_store.reopen(db, lead_id, "ann", now=now)
        await _three_kinds(db, now=now, ids="b")
        await _observe(db, Kind.NOVEL_PROCESS, "rundll32.exe", now=now, ids=("n1",))
        again = await form_leads(db, entity_keys=[_HOST], now=now)
        lead = await db.get(Lead, lead_id)
    assert again.updated == (lead_id,)
    assert "novel_process" in lead.kinds_json


# ---------------------------------------------------------------------------
# C1. A true-positive alert lands in an open live lead, and that lead gets a hunt
# ---------------------------------------------------------------------------
#
# hunts.md finding 1. 23 of 30 alert observations joined a fleet condition
# lead that gets no hunt, including all 9 PHP2Shell true-positive verdicts.
# Lead 69 formed as a fleet condition on its first true-positive alert. The
# activity reached a hunt after 24.5 hours, by the daily schedule.

_RATE_SPEC = "profile-connection-rate-spiked"


async def _shadow_rate_hit(  # type: ignore[no-untyped-def]
    db, host: str, *, now: datetime, cell: str = "weekday-evening", ids: tuple[str, ...] = ()
) -> EntityObservation:
    """One hit of the shadow rate analytic. The fingerprint holds the cell and no host."""
    return await record_observation(
        db,
        entity_kind="host",
        entity_key=host,
        kind=Kind.ABOVE_BASELINE,
        spec_id=_RATE_SPEC,
        fingerprint=content_fingerprint("connection_rate", cell),
        summary="The connection rate is 341 per hour. The baseline expects 97 per hour.",
        evidence={"sample_ids": list(ids or (f"rate-{host}-{cell}",))},
        source="profile",
        shadow=True,
        now=now,
    )


async def _estate_rate_hits(db, *, now: datetime, hosts: int = 12) -> None:  # type: ignore[no-untyped-def]
    """The same shadow rate condition on many other hosts, past the span cap."""
    for i in range(hosts):
        await _shadow_rate_hit(db, f"10.1.20.{i + 1}", now=now)


_RULE = "ET EXPLOIT php2shell chunked upload"


async def _true_positive(  # type: ignore[no-untyped-def]
    db, alert_id: str, *, now: datetime, host: str = _HOST[1], rule: str = _RULE
):
    """One true-positive alert verdict on the host, from an external source."""
    from soc_ai.hunting.sources import observe_alert_verdict

    return await observe_alert_verdict(
        db,
        alert_id=alert_id,
        rule_name=rule,
        verdict="true_positive",
        confidence=0.75,
        hosts=["8.8.4.4", host],
        now=now,
    )


async def _leads_on(db, host: str = _HOST[1]) -> list[Lead]:  # type: ignore[no-untyped-def]
    rows = (await db.execute(select(Lead).order_by(Lead.id))).scalars().all()
    return [r for r in rows if ["host", host] in (r.entities_json or [])]


async def test_a_true_positive_on_a_host_with_a_shadow_rate_hit_forms_an_open_live_lead(
    settings_kratos: Settings,
) -> None:
    """The shape of production lead 69: the first alert and a live shadow rate hit."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _estate_rate_hits(db, now=now)
        await _shadow_rate_hit(db, _HOST[1], now=now)
        outcome = await _true_positive(db, "alert-1", now=now)
        leads = await _leads_on(db)
        rows = [r for r in await _rows(db) if r.entity_key == _HOST[1]]
    assert len(outcome.formed) == 1 and outcome.fleet_conditions == ()
    assert [(lead.status, lead.shadow, lead.kinds_json) for lead in leads] == [
        ("open", False, ["alert"])
    ]
    # The shadow hit changes nothing. It stays where it was, in no lead.
    assert {r.spec_id: r.lead_id for r in rows} == {"alert": leads[0].id, _RATE_SPEC: None}


async def test_a_true_positive_never_joins_a_fleet_condition_lead(
    settings_kratos: Settings,
) -> None:
    """The shape of production leads 13 and 52: the host holds a fleet condition lead."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _estate_rate_hits(db, now=now)
        # The rate hit repeats until it forms a lead alone. The span makes
        # that lead a fleet condition.
        for i in range(30):
            await _shadow_rate_hit(db, _HOST[1], now=now, ids=(f"r{i}",))
        first = await form_leads(db, entity_keys=[_HOST], now=now)
        assert len(first.fleet_conditions) == 1
        fleet_id = first.fleet_conditions[0]

        outcome = await _true_positive(db, "alert-1", now=now)
        again = await _true_positive(db, "alert-2", now=now + timedelta(minutes=5))
        leads = {lead.id: lead for lead in await _leads_on(db)}
        rows = [r for r in await _rows(db) if r.entity_key == _HOST[1]]
    assert len(outcome.formed) == 1 and outcome.formed[0] != fleet_id
    live = leads[outcome.formed[0]]
    assert (live.status, live.shadow) == ("open", False)
    # The second true positive joins the live lead. No third lead forms.
    assert again.formed == () and len(leads) == 2
    assert {r.lead_id for r in rows if r.spec_id == "alert"} == {live.id}
    # The fleet condition keeps its own observation and its own state.
    assert leads[fleet_id].status == "fleet_condition" and leads[fleet_id].shadow is True
    assert {r.lead_id for r in rows if r.spec_id == _RATE_SPEC} == {fleet_id}


async def test_a_true_positive_never_joins_a_held_shadow_lead(settings_kratos: Settings) -> None:
    """The shape of production lead 3: a shadow lead whose hunt ended weeks ago."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(30):
            await _shadow_rate_hit(db, _HOST[1], now=now, ids=(f"r{i}",))
        first = await form_leads(db, entity_keys=[_HOST], now=now)
        shadow_id = first.formed[0]
        await _hunt(db, shadow_id, hunt_id="01HUNTOLD")

        outcome = await _true_positive(db, "alert-1", now=now)
        leads = {lead.id: lead for lead in await _leads_on(db)}
    assert leads[shadow_id].shadow is True and leads[shadow_id].status == "hunting"
    assert len(outcome.formed) == 1 and outcome.formed[0] != shadow_id
    live = leads[outcome.formed[0]]
    assert (live.status, live.shadow, live.hunt_id) == ("open", False, None)


async def test_a_later_shadow_hit_does_not_join_the_lead_of_a_true_positive(
    settings_kratos: Settings,
) -> None:
    """The rule from the other side. One shadow observation marks its whole lead shadow."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        outcome = await _true_positive(db, "alert-1", now=now)
        lead_id = outcome.formed[0]
        for cell in ("weekday-evening", "weekend-night"):
            await _shadow_rate_hit(db, _HOST[1], now=now, cell=cell)
            await form_leads(db, entity_keys=[_HOST], now=now)
        lead = await db.get(Lead, lead_id)
        rows = [r for r in await _rows(db) if r.entity_key == _HOST[1]]
    assert (lead.status, lead.shadow, lead.kinds_json) == ("open", False, ["alert"])
    assert {r.lead_id for r in rows if r.spec_id == _RATE_SPEC} == {None}


async def test_a_true_positive_after_a_clean_hunt_is_not_absorbed_as_history(
    settings_kratos: Settings,
) -> None:
    """The path the guard could miss: a hunt closed the lead clean days before.

    A repeat of a type the hunt cleared joins the closed lead as history and
    starts nothing. A true-positive alert is not a repeat. Absorbed, it would
    reach no hunt, by a different door.
    """
    now = datetime.now(UTC)
    formed_at = now - timedelta(hours=30)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # The first lead holds the alert type, from two verdicts that need more info.
        from soc_ai.hunting.sources import observe_alert_verdict

        await observe_alert_verdict(
            db,
            alert_id="nmi-1",
            rule_name="ET SCAN",
            verdict="needs_more_info",
            confidence=0.5,
            hosts=[_HOST[1]],
            now=formed_at,
        )
        await _observe(db, Kind.NOVEL_DESTINATION, "203.0.113.10", now=formed_at, ids=("d1",))
        first = await form_leads(db, entity_keys=[_HOST], now=formed_at)
        closed_id = first.formed[0]
        hunt = await _hunt(db, closed_id, hunt_id="01HUNTCLEAN")
        assert await leads_store.settle_after_hunt(db, hunt, now=formed_at) == "closed"

        # NEGATIVE CONTROL. An alert that needs more info is the type the hunt
        # cleared. It joins the closed lead as history.
        history = await observe_alert_verdict(
            db,
            alert_id="nmi-2",
            rule_name="ET SCAN",
            verdict="needs_more_info",
            confidence=0.5,
            hosts=[_HOST[1]],
            now=now,
        )
        outcome = await _true_positive(db, "alert-1", now=now)
        rows = {r.fingerprint: r.lead_id for r in await _rows(db)}
        closed = await db.get(Lead, closed_id)
        live = await db.get(Lead, outcome.formed[0])
    assert history.formed == () and history.updated == ()
    assert rows["nmi-2"] == closed_id
    assert closed.status == "dismissed"
    assert outcome.formed[0] != closed_id and rows["alert-1"] == live.id
    assert (live.status, live.shadow, live.hunt_id) == ("open", False, None)


async def test_a_wide_condition_with_no_finding_is_still_a_fleet_condition(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. The fleet rule holds for every lead that no live finding forms.

    The same shadow rate condition on thirteen hosts is one condition. It
    forms a fleet condition, and the loop hunts none of it. A shadow hit of
    an analytic that declares no benign population is finding grade, and it
    is shadow, so it changes nothing here.
    """
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _estate_rate_hits(db, now=now)
        for i in range(30):
            await _shadow_rate_hit(db, _HOST[1], now=now, ids=(f"r{i}",))
        await record_observation(
            db,
            entity_kind="host",
            entity_key=_HOST[1],
            kind=Kind.PRIOR_NO_BASELINE,
            spec_id="local-shadow-prior",
            fingerprint="p1",
            evidence={"sample_ids": ["p1"]},
            source="catalog",
            shadow=True,
            now=now,
        )
        outcome = await form_leads(db, entity_keys=[_HOST], now=now)
        leads = await _leads_on(db)
    assert outcome.formed == () and len(outcome.fleet_conditions) == 1
    assert [(lead.status, lead.shadow) for lead in leads] == [("fleet_condition", True)]


async def _wake(monkeypatch: pytest.MonkeyPatch, maker, started: list[dict[str, Any]]) -> None:  # type: ignore[no-untyped-def]
    """One wake of the real auto-hunt loop, with a console that records a running hunt."""
    import asyncio
    import contextlib
    from types import SimpleNamespace

    from soc_ai import main as main_mod

    async def _start(_state: Any, **kwargs: Any) -> str:
        started.append(kwargs)
        hunt_id = f"01STORM{len(started):03d}"
        async with maker() as db:
            db.add(
                Hunt(
                    id=hunt_id,
                    objective=str(kwargs["objective"]),
                    objective_hash="x",
                    started_by=str(kwargs["started_by"]),
                    kind="lead",
                    starter="lead",
                    status="running",
                    lead_id=int(kwargs["lead_id"]),
                )
            )
            await db.commit()
        return hunt_id

    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: SimpleNamespace(start=_start)
    )
    calls = {"n": 0}

    async def _sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] > 1:
            raise asyncio.CancelledError

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)
    app = SimpleNamespace(
        state=SimpleNamespace(
            db_sessionmaker=maker,
            settings=SimpleNamespace(lead_auto_hunt=True, lead_auto_hunt_concurrency=2),
        )
    )
    with contextlib.suppress(asyncio.CancelledError):
        await main_mod._lead_auto_hunt_loop(app)


async def test_twenty_true_positives_on_one_host_are_one_lead_and_one_hunt(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """No hunt storm. The loop wakes after each verdict, and it starts one hunt.

    The host holds a fleet condition lead from the shadow rate analytic, as
    34 production hosts do. The verdicts arrive before the hunt, while it
    runs, and after it ends with a threat finding that waits on the analyst.
    """
    now = datetime.now(UTC)
    engine, maker = await _db(settings_kratos)
    started: list[dict[str, Any]] = []
    async with maker() as db:
        await _estate_rate_hits(db, now=now)
        for i in range(30):
            await _shadow_rate_hit(db, _HOST[1], now=now, ids=(f"r{i}",))
        fleet = await form_leads(db, entity_keys=[_HOST], now=now)
        assert len(fleet.fleet_conditions) == 1

    for n in range(1, 21):
        async with maker() as db:
            await _true_positive(db, f"alert-{n}", now=now + timedelta(minutes=n))
        await _wake(monkeypatch, maker, started)
        if n == 8:
            # The hunt ends with a threat finding. The lead waits on the analyst.
            async with maker() as db:
                hunt = await db.get(Hunt, "01STORM001")
                hunt.status = "complete"
                hunt.report = {
                    "findings": [{"title": "Exploit attempts", "severity": "high"}],
                    "narrative": "n",
                }
                await db.commit()

    async with maker() as db:
        leads = await _leads_on(db)
        hunts = (await db.execute(select(Hunt))).scalars().all()
        alerts = [r for r in await _rows(db) if r.spec_id == "alert"]
    live = [lead for lead in leads if lead.status != "fleet_condition"]
    assert len(live) == 1 and len(leads) == 2
    assert (live[0].status, live[0].shadow, live[0].hunt_id) == ("hunting", False, "01STORM001")
    assert len(started) == 1 and len(hunts) == 1
    assert started[0]["lead_id"] == live[0].id and started[0]["started_by"] == "auto-hunt"
    assert len(alerts) == 20 and {r.lead_id for r in alerts} == {live[0].id}
    await engine.dispose()


# ---------------------------------------------------------------------------
# C5. Only a grid failure holds a lead. The lead row states the hunt result
# ---------------------------------------------------------------------------
#
# hunts.md finding 6. Seven of eight open leads waited although their hunt
# found no threat. Any visibility gap finding and any failed tool call held a
# lead. 23 of 32 failed tool results were query errors that the model
# corrected on its next call.

_SEEN: dict[str, Any] = {
    "title": "The new ports are mail DNS source ports",
    "category": "observation",
    "severity": "info",
}
_NO_AGENT: dict[str, Any] = {
    "title": "No endpoint agent on the host",
    "category": "visibility_gap",
    "severity": "low",
    "detail": "The host ships no process telemetry. The hunt read its network records.",
}
_OQL = "t_query_events_oql"
_QUERY_ERROR = {
    "error": True,
    "type": "OqlValidationError",
    "message": "unknown field zeek.ssh.auth_success",
}
_GRID_DOWN = {"error": True, "type": "ConnectionTimeout", "reason": "grid_unavailable"}
_ANSWER = {"total": 3, "hits": [{"_id": "d1"}]}


def _tool(sequence: int, tool: str, result: Any) -> dict[str, Any]:
    return {
        "kind": "tool_result",
        "sequence": sequence,
        "payload": {"tool_name": tool, "result": result},
    }


async def _settle(  # type: ignore[no-untyped-def]
    settings: Settings,
    *,
    findings: list[dict[str, Any]],
    events: list[dict[str, Any]],
    hunt_id: str = "01SETTLE",
):
    """A lead under a complete lead hunt with this report and trace, settled once."""
    from soc_ai.store import hunts as hunt_svc

    _engine, maker = await _db(settings)
    async with maker() as db:
        lead = Lead(
            status="open",
            entities_json=[["host", _HOST[1]]],
            kinds_json=["novel_served_port"],
            weight_at_formation=1.5,
            shadow=False,
        )
        db.add(lead)
        await db.commit()
        hunt = await _hunt(db, int(lead.id), hunt_id=hunt_id, findings=findings)
        await hunt_svc.append_events(db, hunt_id, events)
        assert leads_store.hunt_outcome_of(hunt) == "clean"
        outcome = await leads_store.settle_after_hunt(db, hunt)
        lead = await leads_store.get(db, int(lead.id))
        reason = leads_store.hold_reason_of(lead)
    return outcome, lead, leads_store.hold_sentence_of(lead, reason)


async def test_the_store_reads_the_reason_the_tool_boundary_stamps() -> None:
    from soc_ai.agent.toolset import GRID_UNAVAILABLE_REASON

    assert leads_store._GRID_UNAVAILABLE == GRID_UNAVAILABLE_REASON


@pytest.mark.parametrize("corrected", [True, False])
async def test_a_query_error_holds_no_lead(settings_kratos: Settings, corrected: bool) -> None:
    """The model wrote a query that the validator refused. The grid lost nothing.

    Corrected on the next call or not, the error says the model asked wrong.
    A hunt whose every grid query was refused is degraded, and that still
    holds the lead (see the degraded control below).
    """
    events = [_tool(1, _OQL, _ANSWER), _tool(2, _OQL, _QUERY_ERROR)]
    if corrected:
        events.append(_tool(3, _OQL, _ANSWER))
    outcome, lead, _sentence = await _settle(settings_kratos, findings=[_SEEN], events=events)
    assert outcome == "closed"
    assert (lead.status, lead.dismissed_reason) == ("dismissed", "hunt_clean")


async def test_a_standing_gap_holds_no_lead(settings_kratos: Settings) -> None:
    """Production leads 4, 11 and 12 waited on "no agent on the host" for six weeks.

    16 of 1,870 machine records have an agent. A gap finding with no grid
    failure in the trace states a standing fact, and no hunt can remove it.
    """
    outcome, lead, _sentence = await _settle(
        settings_kratos, findings=[_SEEN, _NO_AGENT], events=[_tool(1, _OQL, _ANSWER)]
    )
    assert outcome == "closed" and lead.status == "dismissed"


async def test_a_grid_failure_with_no_later_answer_holds_the_lead(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. The grid did not answer, and the hunt never got that answer.

    Another tool answered after the failure. That is no recovery: the read
    the grid lost is still lost.
    """
    outcome, lead, sentence = await _settle(
        settings_kratos,
        findings=[_SEEN],
        events=[_tool(1, _OQL, _GRID_DOWN), _tool(2, "t_host_summary", _ANSWER)],
    )
    assert outcome == "waits" and lead.status == "hunting"
    assert leads_store.hold_reason_of(lead) == leads_store.HOLD_PARTIAL_READ
    assert sentence == (
        "The grid did not answer a query of the hunt. The hunt did not get that answer later."
    )


async def test_a_grid_failure_that_a_later_call_recovered_closes_the_lead(
    settings_kratos: Settings,
) -> None:
    """A repeat of the same call is a duplicate, and a duplicate is no answer."""
    events = [
        _tool(1, _OQL, _GRID_DOWN),
        _tool(2, _OQL, {"duplicate_call": True}),
    ]
    held, _lead, _s = await _settle(settings_kratos, findings=[_SEEN], events=events)
    assert held == "waits"
    outcome, lead, _sentence = await _settle(
        settings_kratos,
        findings=[_SEEN],
        events=[*events, _tool(3, _OQL, _ANSWER)],
        hunt_id="01RECOVERED",
    )
    assert outcome == "closed" and lead.dismissed_reason == "hunt_clean"


async def test_a_recovered_grid_failure_beside_a_gap_holds_the_lead(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. The gap can be the read that the grid lost."""
    outcome, _lead, sentence = await _settle(
        settings_kratos,
        findings=[_SEEN, _NO_AGENT],
        events=[_tool(1, _OQL, _GRID_DOWN), _tool(2, _OQL, _ANSWER)],
    )
    assert outcome == "waits"
    assert sentence == "The grid did not answer a query, and the hunt reports a visibility gap."


@pytest.mark.parametrize(
    ("error_type", "expected"),
    [
        ("ConnectionTimeout", "waits"),
        ("ConnectionError", "waits"),
        ("GridPartialResultsError", "waits"),
        ("ApiError", "waits"),
        ("TimeoutError", "waits"),
        ("BadRequestError", "closed"),
        ("ValueError", "closed"),
    ],
)
async def test_a_grid_failure_that_a_tool_caught_holds_the_lead(
    settings_kratos: Settings, error_type: str, expected: str
) -> None:
    """The path the guard could miss. Some tools catch the exception themselves.

    Such a result carries the class name and no ``reason``. A transport error
    there is the same grid failure. A 400 from the grid is a query error.
    """
    outcome, _lead, _sentence = await _settle(
        settings_kratos,
        findings=[_SEEN],
        events=[_tool(1, "t_host_summary", {"error": True, "type": error_type, "message": "x"})],
    )
    assert outcome == expected


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        (
            {"kind": "done", "sequence": 9, "payload": {"degraded": False, "partial": True}},
            "The hunt reached its budget before it read all evidence.",
        ),
        (
            {
                "kind": "done",
                "sequence": 9,
                "payload": {"degraded": True, "degraded_reason": "grid_queries_rejected"},
            },
            "The grid rejected every query of the hunt.",
        ),
        (
            {
                "kind": "done",
                "sequence": 9,
                "payload": {"degraded": True, "degraded_reason": "grid_unavailable"},
            },
            "Every grid query of the hunt failed.",
        ),
        (
            {"kind": "error", "sequence": 9, "payload": {"message": "boom"}},
            "The hunt recorded an error before it finished.",
        ),
    ],
)
async def test_a_cut_short_run_still_holds_the_lead_and_names_the_cause(
    settings_kratos: Settings, event: dict[str, Any], expected: str
) -> None:
    """NEGATIVE CONTROL. The rule relaxes a failed tool call and a gap, and nothing else."""
    outcome, lead, sentence = await _settle(settings_kratos, findings=[_SEEN], events=[event])
    assert outcome == "waits"
    assert leads_store.hold_reason_of(lead) == leads_store.HOLD_PARTIAL_READ
    assert sentence == expected


async def test_a_true_positive_that_joined_after_the_hunt_started_holds_the_lead(
    settings_kratos: Settings,
) -> None:
    """The shape of production lead 3, on a live lead.

    A second true positive joins the open lead of its host and starts no
    second hunt. The lead must then not close as clean on a hunt that did not
    read the alert. The evidence block of a hunt is written at its start, so
    an alert that arrives while the hunt runs is not in it either.
    """
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _true_positive(db, "alert-1", now=now - timedelta(hours=3))
        lead_id = first.formed[0]
        hunt = await _hunt(db, lead_id, hunt_id="01LATER", findings=[_SEEN])
        hunt.created_at = (now - timedelta(hours=2)).replace(tzinfo=None)
        await db.commit()
        # NEGATIVE CONTROL. The lead holds what the hunt read. No hold.
        assert await leads_store._clean_close_blocker(db, hunt) is None

        await _true_positive(db, "alert-2", now=now - timedelta(hours=1))
        assert await leads_store.settle_after_hunt(db, hunt, now=now) == "waits"
        lead = await leads_store.get(db, lead_id)
        reason = leads_store.hold_reason_of(lead)
        alerts = {r.lead_id for r in await _rows(db) if r.spec_id == "alert"}
    assert alerts == {lead_id} and lead.status == "hunting"
    assert reason == leads_store.HOLD_LATER_FINDING
    assert leads_store.hold_sentence_of(lead, reason) == (
        "A true-positive alert joined this lead after the hunt started. The hunt did not read it."
    )


async def test_a_hold_recorded_before_the_cause_was_stated_gains_its_note_in_place(
    settings_kratos: Settings,
) -> None:
    """A lead held before this change has a ``held`` entry with no note.

    The next wake states the cause on that entry. It adds no second entry.
    """
    from soc_ai.store import hunts as hunt_svc

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = Lead(status="open", entities_json=[["host", _HOST[1]]], kinds_json=[], shadow=False)
        db.add(lead)
        await db.commit()
        hunt = await _hunt(db, int(lead.id), hunt_id="01OLDHOLD", findings=[_SEEN])
        await hunt_svc.append_events(db, "01OLDHOLD", [_tool(1, _OQL, _GRID_DOWN)])
        leads_store.record_decision(
            lead,
            "held",
            datetime.now(UTC),
            by=leads_store.AUTO_HUNT_ACTOR,
            reason=leads_store.HOLD_PARTIAL_READ,
            hunt_id="01OLDHOLD",
        )
        await db.commit()
        assert leads_store.hold_sentence_of(lead, "partial_read") == (
            "The hunt could not read all evidence."
        )
        assert await leads_store.settle_after_hunt(db, hunt) == "waits"
        assert await leads_store.settle_after_hunt(db, hunt) == "waits"
        lead = await leads_store.get(db, int(lead.id))
    held = [d for d in leads_store.decisions_of(lead) if d["action"] == "held"]
    assert len(held) == 1
    assert leads_store.hold_sentence_of(lead, "partial_read") == (
        "The grid did not answer a query of the hunt. The hunt did not get that answer later."
    )


# ---------------------------------------------------------------------------
# C8. A shadow hit is keyed on the machine. A repeat keeps its read mark
# ---------------------------------------------------------------------------
#
# hunts.md finding 5. 123 of 233 unread shadow hits existed before the window
# and fired again, and each new sighting cleared the read mark. The owner read
# 318 hits in four passes, and the pile grew back. The hits are keyed on the
# address: mainsrv held 89 rows on its bridge and container addresses.


async def _rate_hit(  # type: ignore[no-untyped-def]
    db,
    host: str,
    z: float,
    *,
    doc: str,
    now: datetime,
    cell: str = "weekday-evening",
    spec: str = _RATE_SPEC,
    kind: Kind = Kind.ABOVE_BASELINE,
    weight: float | None = None,
    statistic: str | None = "residual_z",
) -> EntityObservation:
    """One sighting of the shadow rate analytic, with its z score and one document."""
    return await record_observation(
        db,
        entity_kind="host",
        entity_key=host,
        kind=kind,
        spec_id=spec,
        fingerprint=content_fingerprint("connection_rate", cell),
        summary=f"A residual z of {z}.",
        evidence={"sample_ids": [doc]},
        source="profile",
        shadow=True,
        now=now,
        weight=weight,
        statistic=statistic,
        statistic_value=z if statistic else None,
        baseline_value=97.0 if statistic else None,
    )


async def _read(db, row: EntityObservation) -> None:  # type: ignore[no-untyped-def]
    """The analyst opens the hit. The route writes the same column."""
    row.read_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()


async def _machine(  # type: ignore[no-untyped-def]
    db, name: str, addresses: list[str], containers: list[str] | None = None
) -> None:
    """One machine record with its addresses and its container addresses."""
    from soc_ai.store.models import HostDossier, HostMachine

    machine = HostMachine(
        machine_key=f"agent:{name}",
        name=name,
        name_source="agent",
        names_json=[{"value": name, "source": "agent"}],
        primary_ip=addresses[0],
        agent_id=name,
        agent_name=name,
        address_count=len(addresses),
        container_count=len(containers or []),
    )
    db.add(machine)
    await db.flush()
    for ip in addresses:
        db.add(HostDossier(host_key=ip, ip=ip, machine_id=machine.id, address_kind="agent"))
    for ip in containers or []:
        db.add(HostDossier(host_key=ip, ip=ip, machine_id=machine.id, address_kind="container"))
    await db.commit()


async def test_a_repeat_that_is_no_larger_keeps_the_read_mark(settings_kratos: Settings) -> None:
    """The departure the analyst read was 9.8 dispersions. A repeat at 3.5 is not new.

    The row still counts the sighting and states the newest numbers. A later
    repeat at 5.0 is larger than the last sighting and smaller than the one
    the analyst read, so it stays read. A repeat at 10.2 is materially new.
    """
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await _rate_hit(db, _HOST[1], 9.8, doc="d1", now=now)
        await _read(db, row)
        row = await _rate_hit(db, _HOST[1], 3.5, doc="d2", now=now + timedelta(hours=1))
        assert row.read_at is not None
        assert (row.occurrences, row.statistic_value) == (2, 3.5)
        row = await _rate_hit(db, _HOST[1], 5.0, doc="d3", now=now + timedelta(hours=2))
        assert row.read_at is not None and row.occurrences == 3
        row = await _rate_hit(db, _HOST[1], 9.8, doc="d4", now=now + timedelta(hours=3))
        assert row.read_at is not None, "equal to the one the analyst read is not larger"
        row = await _rate_hit(db, _HOST[1], 10.2, doc="d5", now=now + timedelta(hours=4))
    assert row.read_at is None and row.occurrences == 5


async def test_a_collapse_is_larger_when_it_falls_further(settings_kratos: Settings) -> None:
    """The size of a rate departure is its distance from the baseline, in both directions."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    collapse = {"spec": "profile-connection-rate-collapsed", "kind": Kind.BELOW_BASELINE}
    async with maker() as db:
        row = await _rate_hit(db, _HOST[1], -6.0, doc="d1", now=now, **collapse)
        await _read(db, row)
        row = await _rate_hit(db, _HOST[1], -4.0, doc="d2", now=now, **collapse)
        assert row.read_at is not None
        row = await _rate_hit(db, _HOST[1], -8.0, doc="d3", now=now, **collapse)
    assert row.read_at is None


async def test_a_repeat_with_a_higher_weight_is_materially_new(settings_kratos: Settings) -> None:
    """The weight is the severity of a sighting. A rise in it asks for a read."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await _rate_hit(db, _HOST[1], 9.8, doc="d1", now=now, weight=0.35)
        await _read(db, row)
        row = await _rate_hit(db, _HOST[1], 3.0, doc="d2", now=now, weight=0.35)
        assert row.read_at is not None
        row = await _rate_hit(db, _HOST[1], 3.0, doc="d3", now=now, weight=0.6)
    assert row.read_at is None


async def test_a_repeat_with_no_score_is_new_when_it_cites_a_new_document(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. With no score there is no size to compare.

    A new document is then the only sign of a new sighting, and it clears the
    read mark as before. A re-read of the same document changes nothing.
    """
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await _rate_hit(db, _HOST[1], 0.0, doc="d1", now=now, statistic=None)
        await _read(db, row)
        row = await _rate_hit(db, _HOST[1], 0.0, doc="d1", now=now, statistic=None)
        assert row.read_at is not None
        row = await _rate_hit(db, _HOST[1], 0.0, doc="d2", now=now, statistic=None)
    assert row.read_at is None


async def test_the_same_hit_on_another_address_of_the_machine_is_a_repeat(
    settings_kratos: Settings,
) -> None:
    """The analyst read the hit on one address of mainsrv. Its containers are mainsrv too.

    The same analytic and the same value on another address of the machine is
    a repeat of the hit that the analyst read. It is born read, unless it is
    larger. Each address keeps its own row, because each address has its own
    baseline and its own numbers.
    """
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _machine(db, "mainsrv", ["10.1.8.75"], containers=["172.18.0.9", "172.18.0.12"])
        await _machine(db, "appsrv", ["10.1.8.129"])
        first = await _rate_hit(db, "10.1.8.75", 9.8, doc="d1", now=now)
        await _read(db, first)

        same_hit = await _rate_hit(db, "172.18.0.9", 4.0, doc="d2", now=now)
        larger = await _rate_hit(db, "172.18.0.12", 12.0, doc="d3", now=now)
        # NEGATIVE CONTROLS. Another machine, another value and another
        # analytic are each a different hit, and each starts unread.
        other_machine = await _rate_hit(db, "10.1.8.129", 4.0, doc="d4", now=now)
        other_value = await _rate_hit(db, "172.18.0.9", 4.0, doc="d5", now=now, cell="weekend")
        other_analytic = await _rate_hit(
            db,
            "172.18.0.9",
            -4.0,
            doc="d6",
            now=now,
            spec="profile-connection-rate-collapsed",
            kind=Kind.BELOW_BASELINE,
        )
        no_machine = await _rate_hit(db, "10.1.99.1", 4.0, doc="d7", now=now)
        rows = await _rows(db)
    assert same_hit.read_at is not None and same_hit.entity_key == "172.18.0.9"
    assert larger.read_at is None
    assert other_machine.read_at is None
    assert other_value.read_at is None and other_analytic.read_at is None
    assert no_machine.read_at is None
    assert len(rows) == 7


async def test_a_repeat_reads_the_largest_sighting_read_on_the_machine(
    settings_kratos: Settings,
) -> None:
    """Two addresses of one machine, both read. The larger read sets the bar for both."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _machine(db, "mainsrv", ["10.1.8.75"], containers=["172.18.0.9"])
        host = await _rate_hit(db, "10.1.8.75", 9.8, doc="d1", now=now)
        container = await _rate_hit(db, "172.18.0.9", 3.0, doc="d2", now=now)
        await _read(db, host)
        await _read(db, container)
        container = await _rate_hit(db, "172.18.0.9", 5.0, doc="d3", now=now)
        assert container.read_at is not None
        container = await _rate_hit(db, "172.18.0.9", 11.0, doc="d4", now=now)
    assert container.read_at is None


async def test_a_live_hit_is_never_born_read(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. The read mark belongs to a shadow hit. A live hit has none."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _machine(db, "mainsrv", ["10.1.8.75"], containers=["172.18.0.9"])
        first = await _rate_hit(db, "10.1.8.75", 9.8, doc="d1", now=now)
        await _read(db, first)
        live = await record_observation(
            db,
            entity_kind="host",
            entity_key="172.18.0.9",
            kind=Kind.ABOVE_BASELINE,
            spec_id=_RATE_SPEC,
            fingerprint=content_fingerprint("connection_rate", "weekday-evening"),
            evidence={"sample_ids": ["d2"]},
            source="profile",
            shadow=False,
            now=now,
            statistic="residual_z",
            statistic_value=4.0,
        )
    assert live.read_at is None


async def test_the_score_names_are_the_ones_the_analytics_write() -> None:
    """The size rule names each statistic. A renamed statistic must not fall out of it."""
    from soc_ai.hunting import leads, priors
    from soc_ai.hunting.detectors import base

    assert {priors.STATISTIC_RESIDUAL_Z, priors.STATISTIC_ROBUST_Z} == leads._SIZE_IS_DISTANCE
    assert {priors.STATISTIC_DOCUMENTS, priors.STATISTIC_HOUR_DOCUMENTS} <= leads._SIZE_RISES
    assert {
        priors.STATISTIC_ESTATE_HOSTS,
        priors.STATISTIC_PEER_SHARE,
        base.STATISTIC_PLANE_DOCUMENTS,
    } == leads._SIZE_FALLS
    assert leads.departure_size("residual_z", -6.0) == 6.0
    assert leads.departure_size("estate_hosts", 4.0) == -4.0
    assert leads.departure_size("chain_minutes", 3.0) is None
    assert leads.departure_size("residual_z", None) is None


# ---------------------------------------------------------------------------
# C1, second pass. The paths an independent review found on 2026-11-13
# ---------------------------------------------------------------------------


async def test_a_shadow_hit_does_not_reopen_a_closed_lead_that_holds_a_true_positive(
    settings_kratos: Settings,
) -> None:
    """A hunt storm with no new evidence. One alert, and one hunt for each sweep.

    A clean hunt closed the lead of a true positive. A shadow hit of a type
    the lead did not hold reopened it, and the guard kept the hit out of it.
    The hit stayed loose, the loop hunted the lead again, the hunt closed it,
    and the next sweep reopened it. A shadow observation cannot join that
    lead, so it does not reopen it either.
    """
    from soc_ai.hunting.lead_hunt import leads_awaiting_a_hunt

    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _true_positive(db, "alert-1", now=now)
        lead_id = first.formed[0]
        hunt = await _hunt(db, lead_id, hunt_id="01H0", findings=[_SEEN], finished_at=now)
        assert await leads_store.settle_after_hunt(db, hunt, now=now) == "closed"
        for n in (1, 2, 3):
            at = now + timedelta(hours=n)
            await _shadow_rate_hit(db, _HOST[1], now=at, ids=("r1",))
            outcome = await form_leads(db, entity_keys=[_HOST], now=at)
            lead = await db.get(Lead, lead_id)
            assert outcome.formed == () and outcome.updated == ()
            assert (lead.status, lead.dismissed_reason) == ("dismissed", "hunt_clean")
            assert await leads_awaiting_a_hunt(db) == []
        rate = next(r for r in await _rows(db) if r.spec_id == _RATE_SPEC)
    assert rate.lead_id is None


async def test_a_live_type_still_reopens_a_closed_lead_that_holds_a_true_positive(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. A live observation of a new type is a new question, as before."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _true_positive(db, "alert-1", now=now)
        lead_id = first.formed[0]
        hunt = await _hunt(db, lead_id, hunt_id="01H0", findings=[_SEEN], finished_at=now)
        assert await leads_store.settle_after_hunt(db, hunt, now=now) == "closed"
        at = now + timedelta(hours=1)
        await _observe(db, Kind.NOVEL_PROCESS, "rundll32.exe", now=at, ids=("n1",))
        outcome = await form_leads(db, entity_keys=[_HOST], now=at)
        lead = await db.get(Lead, lead_id)
    assert outcome.updated == (lead_id,)
    assert (lead.status, lead.shadow, lead.hunt_id) == ("open", False, None)


async def _needs_more_info(db, alert_id: str, *, now: datetime, rule: str = _RULE):  # type: ignore[no-untyped-def]
    from soc_ai.hunting.sources import observe_alert_verdict

    return await observe_alert_verdict(
        db,
        alert_id=alert_id,
        rule_name=rule,
        verdict="needs_more_info",
        confidence=0.5,
        hosts=["8.8.4.4", _HOST[1]],
        now=now,
    )


@pytest.mark.parametrize("held_in", ["fleet_condition", "shadow_lead"])
async def test_an_alert_that_becomes_a_true_positive_leaves_the_lead_that_is_not_live(
    settings_kratos: Settings, held_in: str
) -> None:
    """The verdict of one alert changes. The Oracle confirms it, or a run is sent again.

    The alert joined a fleet condition or a shadow lead while it needed more
    info, which the rule allows. The same row is then a true positive. It
    stayed in that lead, and no hunt started. Production true positives that
    sit in fleet condition leads take the same path at their next sweep.
    """
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        if held_in == "fleet_condition":
            await _estate_rate_hits(db, now=now)
        for i in range(30):
            await _shadow_rate_hit(db, _HOST[1], now=now, ids=(f"r{i}",))
        first = await form_leads(db, entity_keys=[_HOST], now=now)
        old_id = (first.fleet_conditions or first.formed)[0]
        joined = await _needs_more_info(db, "alert-1", now=now)
        row = next(r for r in await _rows(db) if r.spec_id == "alert")
        assert joined.formed == () and row.lead_id == old_id

        outcome = await _true_positive(db, "alert-1", now=now + timedelta(minutes=5))
        row = next(r for r in await _rows(db) if r.spec_id == "alert")
        old = await db.get(Lead, old_id)
        live = await db.get(Lead, outcome.formed[0])
    assert row.birth_weight == 1.0 and row.lead_id == live.id != old_id
    assert (live.status, live.shadow, live.hunt_id) == ("open", False, None)
    assert old.shadow is True and "alert" not in old.kinds_json


async def test_an_alert_that_becomes_a_true_positive_leaves_the_lead_a_hunt_closed(
    settings_kratos: Settings,
) -> None:
    """The alert joined a closed lead as history while it needed more info.

    The hunt that closed the lead ended before the alert arrived. NEGATIVE
    CONTROL: the alert that the hunt did read stays on the closed lead when
    its verdict changes. Released, it would start the same hunt again.
    """
    now = datetime.now(UTC)
    formed_at = now - timedelta(hours=30)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _needs_more_info(db, "read-by-the-hunt", now=formed_at)
        await _observe(db, Kind.NOVEL_DESTINATION, "203.0.113.10", now=formed_at, ids=("d1",))
        first = await form_leads(db, entity_keys=[_HOST], now=formed_at)
        closed_id = first.formed[0]
        hunt = await _hunt(db, closed_id, hunt_id="01HUNTCLEAN")
        assert await leads_store.settle_after_hunt(db, hunt, now=formed_at) == "closed"
        other = "ET SCAN Nmap sweep"
        later = now - timedelta(hours=2)
        history = await _needs_more_info(db, "after-the-close", now=later, rule=other)
        assert history.formed == ()

        control = await _true_positive(db, "read-by-the-hunt", now=now)
        outcome = await _true_positive(db, "after-the-close", now=now, rule=other)
        rows = {r.fingerprint: r.lead_id for r in await _rows(db)}
    assert control.formed == () and rows["read-by-the-hunt"] == closed_id
    assert len(outcome.formed) == 1 and rows["after-the-close"] == outcome.formed[0]


async def test_a_row_that_turns_shadow_does_not_mark_the_lead_of_a_true_positive(
    settings_kratos: Settings,
) -> None:
    """soc-ai moves a live analytic back to shadow. Its row sits in the lead of an alert.

    One shadow row marked its whole lead shadow, and the loop hunts no shadow
    lead. NEGATIVE CONTROL: the same flip in a lead with no live finding
    still marks that lead.
    """
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)

    async def catalog(db, host: str, *, shadow: bool):  # type: ignore[no-untyped-def]
        return await _observe(
            db, Kind.CATALOG_MATCH, "c", now=now, ids=("c1",), host=host, shadow=shadow, spec="x"
        )

    async with maker() as db:
        await catalog(db, _HOST[1], shadow=False)
        first = await _true_positive(db, "alert-1", now=now)
        lead_id = first.formed[0]
        await catalog(db, _HOST[1], shadow=True)
        flipped = (await db.get(Lead, lead_id)).shadow
        await form_leads(db, entity_keys=[_HOST], now=now)
        lead = await db.get(Lead, lead_id)

        other = ("host", "10.1.10.99")
        await catalog(db, other[1], shadow=False)
        await _observe(db, Kind.NOVEL_PROCESS, "p", now=now, ids=("p1",), host=other[1])
        plain = await form_leads(db, entity_keys=[other], now=now)
        await catalog(db, other[1], shadow=True)
        control = await db.get(Lead, plain.formed[0])
    assert flipped is False
    assert (lead.status, lead.shadow) == ("open", False)
    assert control.shadow is True


# ---------------------------------------------------------------------------
# C8, second pass. The paths an independent review found on 2026-11-13
# ---------------------------------------------------------------------------


async def test_a_reread_does_not_move_the_size_that_the_analyst_read(
    settings_kratos: Settings,
) -> None:
    """The sweep reads the same documents again and writes a new score.

    That is no sighting, and the analyst did not read it. The size they read
    stays the bar in both directions: a lower re-read does not lower it, and
    a higher re-read does not raise it.
    """
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    other = "10.1.10.22"
    async with maker() as db:
        row = await _rate_hit(db, _HOST[1], 9.0, doc="d1", now=now)
        await _read(db, row)
        await _rate_hit(db, _HOST[1], 3.0, doc="d1", now=now)
        row = await _rate_hit(db, _HOST[1], 7.0, doc="d2", now=now)
        assert row.read_at is not None, "7.0 is smaller than the 9.0 that the analyst read"

        row = await _rate_hit(db, other, 4.0, doc="e1", now=now)
        await _read(db, row)
        await _rate_hit(db, other, 9.0, doc="e1", now=now)
        row = await _rate_hit(db, other, 7.0, doc="e2", now=now)
    assert row.read_at is None, "7.0 is larger than the 4.0 that the analyst read"


async def _catalog_hit(db, host: str, documents: int, *, doc: str, now: datetime):  # type: ignore[no-untyped-def]
    """One shadow hit of a match analytic. Its fingerprint holds the entity."""
    return await record_observation(
        db,
        entity_kind="host",
        entity_key=host,
        kind=Kind.CATALOG_MATCH,
        spec_id="local-match",
        fingerprint=content_fingerprint("local-match", host),
        summary=f"local match: {host}",
        evidence={"sample_ids": [doc]},
        source="catalog",
        shadow=True,
        now=now,
        statistic="documents",
        statistic_value=float(documents),
    )


async def test_a_match_hit_on_another_address_of_the_machine_is_a_repeat(
    settings_kratos: Settings,
) -> None:
    """A match analytic writes the entity into its fingerprint. The machine key still holds."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _machine(db, "mainsrv", ["10.1.8.75"], containers=["172.18.0.9", "172.18.0.12"])
        first = await _catalog_hit(db, "10.1.8.75", 6, doc="d1", now=now)
        await _read(db, first)
        same_hit = await _catalog_hit(db, "172.18.0.9", 4, doc="d2", now=now)
        larger = await _catalog_hit(db, "172.18.0.12", 9, doc="d3", now=now)
        elsewhere = await _catalog_hit(db, "10.1.99.1", 4, doc="d4", now=now)
    assert same_hit.read_at is not None
    assert larger.read_at is None and elsewhere.read_at is None


async def test_a_read_covers_the_same_hit_on_the_other_addresses_of_the_machine(
    settings_kratos: Settings,
) -> None:
    """The analyst reads the hit on one address. The hit is the machine's.

    The rows of the same hit on the other addresses are read with it, when
    they are no larger. A larger one stays unread: the analyst did not see
    its numbers. Another machine and another value are not touched.
    """
    from soc_ai.hunting.leads import read_hit

    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _machine(db, "mainsrv", ["10.1.8.75"], containers=["172.18.0.9", "172.18.0.12"])
        opened = await _rate_hit(db, "10.1.8.75", 9.8, doc="d1", now=now)
        smaller = await _rate_hit(db, "172.18.0.9", 4.0, doc="d2", now=now)
        larger = await _rate_hit(db, "172.18.0.12", 12.0, doc="d3", now=now)
        other_value = await _rate_hit(db, "172.18.0.9", 4.0, doc="d4", now=now, cell="weekend")
        elsewhere = await _rate_hit(db, "10.1.99.1", 4.0, doc="d5", now=now)
        marked = await read_hit(db, opened, at=now.replace(tzinfo=None))
    assert marked == 2
    assert opened.read_at is not None and smaller.read_at is not None
    assert larger.read_at is None and other_value.read_at is None and elsewhere.read_at is None


# ---------------------------------------------------------------------------
# C1, the bound after a close. One rule on one host, for the decay horizon
# ---------------------------------------------------------------------------
#
# After a lead closed, each new true positive on its host formed a new lead
# and a new hunt, with no limit. An edge host that draws internet scans got a
# hunt after every close. A true positive whose rule the closed lead held at
# its close joins that lead for 207 hours, and starts nothing.


async def _close(db, lead_id: int, how: str, *, at: datetime) -> None:  # type: ignore[no-untyped-def]
    if how == "hunt_clean":
        hunt = await _hunt(db, lead_id, hunt_id="01CLOSE", findings=[_SEEN])
        assert await leads_store.settle_after_hunt(db, hunt, now=at) == "closed"
    elif how == "promoted":
        await leads_store.mark_promoted(db, lead_id, investigation_id="01INV", now=at)
    else:
        await leads_store.dismiss(
            db, lead_id, reason="authorized_test", note=None, by="ann", now=at
        )


@pytest.mark.parametrize("how", ["hunt_clean", "promoted", "dismissed"])
async def test_a_true_positive_of_a_rule_the_closed_lead_held_joins_it_and_starts_no_hunt(
    settings_kratos: Settings, how: str
) -> None:
    """Twenty repeats of one rule after a close: no new lead and no hunt, for each close type."""
    from soc_ai.hunting.lead_hunt import leads_awaiting_a_hunt

    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _true_positive(db, "alert-1", now=now - timedelta(hours=4))
        lead_id = first.formed[0]
        await _close(db, lead_id, how, at=now - timedelta(hours=3))
        newest = now
        for n in range(2, 22):
            newest = now - timedelta(hours=2) + timedelta(minutes=n)
            outcome = await _true_positive(db, f"alert-{n}", now=newest)
            assert outcome.formed == () and outcome.updated == ()
        leads = await _leads_on(db)
        alerts = [r for r in await _rows(db) if r.spec_id == "alert"]
        waiting = await leads_awaiting_a_hunt(db)
        repeats = leads_store.repeats_after_close(leads[0], alerts)
    assert [lead.id for lead in leads] == [lead_id] and waiting == []
    assert leads[0].status in ("dismissed", "promoted")
    assert len(alerts) == 21 and {r.lead_id for r in alerts} == {lead_id}
    assert repeats == (20, newest.replace(tzinfo=None))


async def test_the_bound_after_a_close_is_one_rule_on_one_host(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROLS. Another rule and another host each get a lead that the loop hunts.

    A true positive on a host with an open live lead joins that lead, also
    when a closed lead on the host holds its rule.
    """
    from soc_ai.hunting.lead_hunt import leads_awaiting_a_hunt

    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _true_positive(db, "alert-1", now=now - timedelta(hours=4))
        closed_id = first.formed[0]
        await _close(db, closed_id, "promoted", at=now - timedelta(hours=3))

        elsewhere = await _true_positive(db, "alert-2", now=now, host="10.1.10.77")
        new_rule = await _true_positive(db, "alert-3", now=now, rule="ET SCAN Nmap sweep")
        joins_open = await _true_positive(db, "alert-4", now=now)
        rows = {r.fingerprint: r.lead_id for r in await _rows(db)}
        waiting = {lead.id for lead in await leads_awaiting_a_hunt(db)}
    assert len(elsewhere.formed) == 1 and len(new_rule.formed) == 1
    assert waiting == {elsewhere.formed[0], new_rule.formed[0]}
    assert joins_open.formed == () and rows["alert-4"] == new_rule.formed[0]
    assert rows["alert-1"] == closed_id


async def test_the_bound_after_a_close_ends_at_the_decay_horizon(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. The same rule 208 hours after the close gets a lead and a hunt."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _true_positive(db, "alert-1", now=now - timedelta(hours=210))
        await _close(db, first.formed[0], "promoted", at=now - timedelta(hours=208))
        inside = await _true_positive(db, "alert-2", now=now - timedelta(hours=2))
        outside = await _true_positive(db, "alert-3", now=now)
        lead = await db.get(Lead, outside.formed[0])
    assert inside.formed == ()
    assert (lead.status, lead.shadow, lead.hunt_id) == ("open", False, None)


async def test_a_reopen_by_the_analyst_ends_the_bound(settings_kratos: Settings) -> None:
    """The lead is open again, so the true positive joins it by the normal rule."""
    now = datetime.now(UTC)
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _true_positive(db, "alert-1", now=now - timedelta(hours=4))
        lead_id = first.formed[0]
        await _close(db, lead_id, "dismissed", at=now - timedelta(hours=3))
        await leads_store.reopen(db, lead_id, "ann", now=now - timedelta(hours=1))
        await _true_positive(db, "alert-2", now=now)
        lead = await db.get(Lead, lead_id)
        rows = [r for r in await _rows(db) if r.spec_id == "alert"]
    assert lead.status == "open" and {r.lead_id for r in rows} == {lead_id}
    assert leads_store.repeats_after_close(lead, rows) == (0, None)
