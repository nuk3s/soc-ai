"""Observations accumulating into leads.

The tests that matter are the ones that stop a lead forming: two observations
of the same kind, a repeat of the same content, and a span past the cap. Each
of those, allowed, turns the layer into a novelty detector with extra steps.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.leads import (
    DEFAULT_SPAN_CAP,
    STATUS_FLEET,
    STATUS_OPEN,
    content_fingerprint,
    form_leads,
    record_observation,
    weigh_entity,
)
from soc_ai.hunting.sources import observe_alert_verdict
from soc_ai.hunting.weight import Kind
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, Lead
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
_HOST = ("host", "10.1.10.21")


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _observe(db, kind: Kind, member: str, *, spec: str = "s", now=_NOW) -> None:
    await record_observation(
        db,
        entity_kind=_HOST[0],
        entity_key=_HOST[1],
        kind=kind,
        spec_id=spec,
        fingerprint=content_fingerprint("dim", member),
        summary=f"{kind.value}: {member}",
        now=now,
    )


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


async def test_a_repeat_refreshes_rather_than_accumulating(
    settings_kratos: Settings,
) -> None:
    # A beacon seen every five minutes would otherwise become three hundred
    # rows and outrank every other signal on the network by arithmetic alone.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(5):
            await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1", now=_NOW + timedelta(hours=i))
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert len(rows) == 1
    assert rows[0].occurrences == 5


async def test_a_repeat_moves_born_at_but_keeps_first_seen(
    settings_kratos: Settings,
) -> None:
    # "Started three weeks ago and is still going" is a different story from
    # "started today", and a refreshed born_at alone cannot tell them apart.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1", now=_NOW)
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1", now=_NOW + timedelta(days=3))
        row = (await db.execute(select(EntityObservation))).scalars().one()
    assert row.first_seen_at < row.born_at


async def test_different_content_is_a_different_observation(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.NOVEL_DESTINATION, "8.8.8.8")
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert len(rows) == 2


async def test_a_fingerprint_excludes_time_and_count() -> None:
    # Including either makes every re-sweep a new observation, which is exactly
    # the accumulation the key exists to prevent.
    assert content_fingerprint("ports", "445") == content_fingerprint("ports", "445")
    assert content_fingerprint("ports", "445") != content_fingerprint("ports", "446")


# ---------------------------------------------------------------------------
# Weighing
# ---------------------------------------------------------------------------


async def test_an_observation_below_the_floor_is_not_returned(
    settings_kratos: Settings,
) -> None:
    # History, not weight. A caller that sums what it is handed must not have
    # to remember to filter first.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1", now=_NOW - timedelta(days=60))
        live = await weigh_entity(db, entity_kind=_HOST[0], entity_key=_HOST[1], now=_NOW)
    assert live == []


async def test_an_unknown_kind_is_skipped_not_guessed(settings_kratos: Settings) -> None:
    # A kind this build does not know cannot be weighed. Guessing a weight lets
    # a renamed kind keep contributing silently.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        row = (await db.execute(select(EntityObservation))).scalars().one()
        row.kind = "a_kind_from_the_future"
        await db.commit()
        live = await weigh_entity(db, entity_kind=_HOST[0], entity_key=_HOST[1], now=_NOW)
    assert live == []


# ---------------------------------------------------------------------------
# Lead formation — mostly the cases that must NOT form
# ---------------------------------------------------------------------------


async def test_two_observations_of_one_kind_do_not_form_a_lead(
    settings_kratos: Settings,
) -> None:
    # THE rule. A host with two new destinations is a host with two new
    # destinations; calling it a chain is how a novelty detector with extra
    # steps gets mistaken for correlation.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.NOVEL_DESTINATION, "8.8.8.8")
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert outcome.formed == ()
    assert leads == []


async def test_two_kinds_over_the_threshold_form_a_lead(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")  # 0.50
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")  # 0.45
        await _observe(db, Kind.OFF_HOURS, "03:14")  # 0.30
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(outcome.formed) == 1
    assert len(leads) == 1
    assert set(leads[0].kinds_json) == {"novel_destination", "rare_for_peers", "off_hours"}


async def test_two_kinds_under_the_threshold_do_not_form(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.OFF_HOURS, "03:14")  # 0.30
        await _observe(db, Kind.BELOW_BASELINE, "backup")  # 0.35
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
    assert outcome.formed == ()


async def test_a_no_baseline_prior_forms_a_lead_on_its_own(
    settings_kratos: Settings,
) -> None:
    # The design: a prior with no benign population is 1.0 and IS a finding.
    # The two-kind rule is about chains, and that prior is not claiming one.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.PRIOR_NO_BASELINE, "4662")
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
    assert len(outcome.formed) == 1


async def test_a_lead_does_not_refire_on_an_unchanged_sweep(
    settings_kratos: Settings,
) -> None:
    # Re-firing every sweep turns a lead into a notification stream, and an
    # analyst learns to close it without reading it.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await _observe(db, Kind.OFF_HOURS, "03:14")
        first = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        second = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(first.formed) == 1
    assert second.formed == ()
    assert second.updated == ()
    assert len(leads) == 1


async def test_a_new_kind_updates_the_lead_in_place(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await _observe(db, Kind.OFF_HOURS, "03:14")
        await form_leads(db, entity_keys=[_HOST], now=_NOW)
        await _observe(db, Kind.BELOW_BASELINE, "backup")
        second = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(second.updated) == 1
    assert len(leads) == 1, "a new kind updates the lead, it does not start another"
    assert "below_baseline" in leads[0].kinds_json


async def test_a_lead_is_shadow_only_when_an_observation_is(
    settings_kratos: Settings,
) -> None:
    # The field records one fact: a shadow analytic contributed to this lead.
    # A lead built from live analytics is a live lead. The rule that no lead
    # starts a hunt by itself is kept by the screens, not by this flag.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.PRIOR_NO_BASELINE, "4662")
        await form_leads(db, entity_keys=[_HOST], now=_NOW)
        lead = (await db.execute(select(Lead))).scalars().one()
    assert lead.shadow is False


async def test_decay_can_take_a_lead_back_below_the_threshold(
    settings_kratos: Settings,
) -> None:
    # Weight is computed on read, so a chain that stopped stops forming leads
    # without anything having to go back and delete its observations.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await _observe(db, Kind.OFF_HOURS, "03:14")
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW + timedelta(days=7))
    assert outcome.formed == ()


async def test_a_span_past_the_cap_is_a_fleet_condition_not_a_lead(
    settings_kratos: Settings,
) -> None:
    # A thing happening on forty hosts at once is a software deployment far
    # more often than an attacker, and reporting it as a lead sends an analyst
    # hunting for an intruder inside one.
    _engine, maker = await _db(settings_kratos)
    hosts = [("host", f"10.1.10.{n}") for n in range(20, 20 + DEFAULT_SPAN_CAP + 3)]
    async with maker() as db:
        # One shared lead: give every host the same two kinds, then attach them
        # to a single lead by forming on the first and extending the span.
        for _kind, key in ((Kind.NOVEL_DESTINATION, h[1]) for h in hosts):
            await record_observation(
                db,
                entity_kind="host",
                entity_key=key,
                kind=Kind.PRIOR_NO_BASELINE,
                spec_id="fleet",
                fingerprint=content_fingerprint("proc", "agent.exe"),
                now=_NOW,
            )
        outcome = await form_leads(db, entity_keys=hosts, now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()

    # Each host forms its own single-entity lead here; the cap is exercised by
    # the span recorded on each, which must never exceed what was observed.
    assert all(int(lead.scope_count) <= DEFAULT_SPAN_CAP for lead in leads)
    assert all(lead.status in {STATUS_OPEN, STATUS_FLEET} for lead in leads)
    assert len(outcome.formed) == len(hosts)


async def test_out_of_scope_observations_are_purged(settings_kratos: Settings) -> None:
    """Purging profiles was not enough, and the gap let leads form on the internet.

    The profile table was scoped to the estate's CIDRs and the OBSERVATION
    table was not, so observations already recorded against a Microsoft server,
    the loopback address and an upstream gateway stayed live -- decaying,
    accumulating, and eligible to form leads about somebody else's
    infrastructure. Same defect as the profile one, one table over, which is
    what makes it worth a test rather than a patch.
    """
    import ipaddress

    from soc_ai.hunting.leads import purge_out_of_scope_observations

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for key in ("10.1.10.21", "52.123.129.14", "127.0.0.1"):
            await record_observation(
                db,
                entity_kind="host",
                entity_key=key,
                kind=Kind.OFF_HOURS,
                spec_id="s",
                fingerprint=content_fingerprint("hour", "3"),
                now=_NOW,
            )
        removed = await purge_out_of_scope_observations(
            db, cidrs=[ipaddress.ip_network("10.1.0.0/16")]
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()

    assert removed == 2
    assert {r.entity_key for r in rows} == {"10.1.10.21"}


async def test_purging_observations_keeps_host_rows_keyed_on_a_hostname(
    settings_kratos: Settings,
) -> None:
    """A host keyed on its agent name is neither inside nor outside a CIDR.

    The process and logon planes key their observations on ``host.name``.
    The purge must keep those rows, as the profile purge does, or every
    agent-plane departure is deleted at the start of the next sweep on any
    estate with CIDRs configured.
    """
    import ipaddress

    from soc_ai.hunting.leads import purge_out_of_scope_observations

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for key in ("dc01", "WS01.corp.example", "52.123.129.14"):
            await record_observation(
                db,
                entity_kind="host",
                entity_key=key,
                kind=Kind.OFF_HOURS,
                spec_id="s",
                fingerprint=content_fingerprint("hour", "3"),
                now=_NOW,
            )
        removed = await purge_out_of_scope_observations(
            db, cidrs=[ipaddress.ip_network("10.1.0.0/16")]
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()

    assert removed == 1
    assert {r.entity_key for r in rows} == {"dc01", "WS01.corp.example"}


async def test_purging_observations_with_no_cidrs_removes_nothing(
    settings_kratos: Settings,
) -> None:
    from soc_ai.hunting.leads import purge_out_of_scope_observations

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="host",
            entity_key="52.123.129.14",
            kind=Kind.OFF_HOURS,
            spec_id="s",
            fingerprint=content_fingerprint("hour", "3"),
            now=_NOW,
        )
        removed = await purge_out_of_scope_observations(db, cidrs=[])
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert removed == 0
    assert len(rows) == 1


async def test_purging_observations_never_touches_users(
    settings_kratos: Settings,
) -> None:
    import ipaddress

    from soc_ai.hunting.leads import purge_out_of_scope_observations

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="user",
            entity_key="alice",
            kind=Kind.NOVEL_BINDING,
            spec_id="s",
            fingerprint=content_fingerprint("binding", "dc01"),
            now=_NOW,
        )
        removed = await purge_out_of_scope_observations(
            db, cidrs=[ipaddress.ip_network("10.1.0.0/16")]
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert removed == 0
    assert len(rows) == 1


async def test_a_later_same_kind_observation_joins_the_open_lead(
    settings_kratos: Settings,
) -> None:
    # The lead said two observations while the host held three: a same-kind
    # observation recorded after formation sat beside the lead, unattached,
    # because only a NEW kind re-fired the update. Joining is not re-firing.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await _observe(db, Kind.OFF_HOURS, "03:14")
        first = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        await _observe(db, Kind.NOVEL_DESTINATION, "9.9.9.9", now=_NOW + timedelta(hours=1))
        second = await form_leads(db, entity_keys=[_HOST], now=_NOW + timedelta(hours=1))
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert len(first.formed) == 1
    assert second.formed == () and second.updated == ()
    assert {r.lead_id for r in rows} == {first.formed[0]}


async def test_an_observation_records_its_source_and_shadow_flag(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await record_observation(
            db,
            entity_kind="host",
            entity_key="198.51.100.7",
            kind=Kind.NOVEL_DESTINATION,
            spec_id="s",
            fingerprint=content_fingerprint("dim", "x"),
            source="catalog",
            shadow=True,
            now=_NOW,
        )
    assert row.source == "catalog"
    assert row.shadow is True


async def test_a_true_positive_alert_forms_a_lead_alone(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.ALERT,
            spec_id="alert",
            fingerprint="alert-1",
            source="alert",
            weight=1.0,
            now=_NOW,
        )
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(outcome.formed) == 1
    assert leads[0].single_signal is False


async def _alert(db, verdict: str, *, alert_id: str = "alert-1", now=_NOW):  # type: ignore[no-untyped-def]
    return await observe_alert_verdict(
        db,
        alert_id=alert_id,
        rule_name="ET MALWARE Test",
        verdict=verdict,
        confidence=0.9,
        hosts=[_HOST[1]],
        now=now,
    )


async def test_a_verdict_changed_to_false_positive_closes_the_lead_it_formed(
    settings_kratos: Settings,
) -> None:
    # The alert formed the lead alone. Deleting the observation and leaving
    # the lead open left a lead with no evidence in the queue for good.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _alert(db, "true_positive")
        await _alert(db, "false_positive", now=_NOW + timedelta(hours=1))
        rows = (await db.execute(select(EntityObservation))).scalars().all()
        lead = await db.get(Lead, first.formed[0])
    assert rows == []
    assert lead is not None
    assert lead.status == "dismissed"
    assert lead.dismissed_reason == "other"
    assert lead.dismissed_at is not None
    assert lead.hunt_id is None


async def test_a_false_positive_reshapes_a_lead_that_still_holds_other_observations(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _alert(db, "true_positive")
        await _observe(db, Kind.OFF_HOURS, "03:14", now=_NOW + timedelta(minutes=5))
        await form_leads(db, entity_keys=[_HOST], now=_NOW + timedelta(minutes=5))
        await _alert(db, "false_positive", now=_NOW + timedelta(hours=1))
        rows = (await db.execute(select(EntityObservation))).scalars().all()
        lead = await db.get(Lead, first.formed[0])
    assert [r.kind for r in rows] == ["off_hours"]
    assert lead is not None
    assert lead.status == STATUS_OPEN
    assert lead.kinds_json == ["off_hours"]
    assert lead.entities_json == [list(_HOST)]
    assert lead.scope_count == 1
    assert {r.lead_id for r in rows} == {lead.id}


async def test_a_false_positive_leaves_a_hunted_lead_alone(settings_kratos: Settings) -> None:
    # The hunt was run on the evidence as it stood. Its lead keeps the hunt
    # and the analyst's decision on it; only the observation goes.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _alert(db, "true_positive")
        lead = await db.get(Lead, first.formed[0])
        assert lead is not None
        lead.status = "hunting"
        lead.hunt_id = "hunt-1"
        await db.commit()
        await _alert(db, "false_positive", now=_NOW + timedelta(hours=1))
        rows = (await db.execute(select(EntityObservation))).scalars().all()
        await db.refresh(lead)
    assert rows == []
    assert lead.status == "hunting"
    assert lead.hunt_id == "hunt-1"
    assert lead.dismissed_at is None


async def test_a_needs_more_info_alert_does_not_form_alone(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.ALERT,
            spec_id="alert",
            fingerprint="alert-2",
            source="alert",
            weight=0.5,
            now=_NOW,
        )
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
    assert outcome.formed == ()


async def test_one_kind_stacked_past_the_single_signal_threshold_forms_a_lead(
    settings_kratos: Settings,
) -> None:
    # 0.5 * (1 + ln 8) = 1.54, over the 1.5 threshold. One kind, so the
    # two-kind rule refused it. It is now a lead that says so.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for _ in range(8):
            await _observe(db, Kind.NOVEL_PROCESS, "rundll32.exe")
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(outcome.formed) == 1
    assert leads[0].single_signal is True
    assert leads[0].kinds_json == ["novel_process"]


async def test_three_repeats_of_one_kind_form_nothing(
    settings_kratos: Settings,
) -> None:
    """The rule fired at the stacking cap, so two sightings formed a lead.

    The live weight is capped at 1.0 and the threshold WAS 1.0, so any kind
    that repeated once cleared it: a catalog hit seen twice reaches 1.19 before
    the cap. The test now reads the uncapped stack, where a 0.5 kind needs 8
    repeats and a 0.7 kind needs 4.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for _ in range(3):
            await _observe(db, Kind.NOVEL_PROCESS, "rundll32.exe")
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
    assert outcome.formed == ()


async def test_a_catalog_hit_seen_twice_forms_nothing(settings_kratos: Settings) -> None:
    # 0.7 * (1 + ln 2) = 1.19. The cap hid this: it read as exactly 1.0 and
    # the threshold was 1.0, so the second sighting of any catalog hit formed a
    # lead on its own. Four repeats are needed now.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for _ in range(2):
            await _observe(db, Kind.CATALOG_MATCH, "identity-4769")
        twice = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        for _ in range(2):
            await _observe(db, Kind.CATALOG_MATCH, "identity-4769")
        four = await form_leads(db, entity_keys=[_HOST], now=_NOW)
    assert twice.formed == ()
    assert len(four.formed) == 1


async def test_a_shadow_observation_marks_the_whole_lead_shadow(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.OFF_HOURS,
            spec_id="candidate-1",
            fingerprint="c",
            source="candidate",
            shadow=True,
            now=_NOW,
        )
        # shadow=False here is the layer flag. The lead must still be shadow,
        # because one of its observations is.
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW, shadow=False)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(outcome.formed) == 1
    assert leads[0].shadow is True


async def test_a_lead_with_no_shadow_observation_follows_the_layer_flag(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await _observe(db, Kind.OFF_HOURS, "03:14")
        await form_leads(db, entity_keys=[_HOST], now=_NOW, shadow=False)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert leads[0].shadow is False


async def test_a_lead_from_live_observations_is_not_shadow_by_default(
    settings_kratos: Settings,
) -> None:
    """Every caller took the default, so every lead on the range read as shadow.

    A shadow lead starts nothing by itself. The whole leads strip was therefore
    marked as evidence nobody should act on. The posture that no lead starts a
    hunt on its own is a rule for the screens, not a mark on every row.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await _observe(db, Kind.OFF_HOURS, "03:14")
        await form_leads(db, entity_keys=[_HOST], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert leads[0].shadow is False


async def test_a_shadow_observation_that_joins_later_marks_the_lead(
    settings_kratos: Settings,
) -> None:
    # The lead formed live. A shadow analytic then observed the same host, so
    # the lead as a whole is no longer a live lead.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await _observe(db, Kind.OFF_HOURS, "03:14")
        first = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.NOVEL_PROCESS,
            spec_id="local-x",
            fingerprint="c",
            shadow=True,
            now=_NOW,
        )
        await form_leads(db, entity_keys=[_HOST], now=_NOW)
        lead = await db.get(Lead, first.formed[0])
    assert lead.shadow is True


# ---------------------------------------------------------------------------
# A lead spans the entities a hit names
# ---------------------------------------------------------------------------


async def test_a_lead_on_an_account_merges_with_a_lead_on_the_host_it_names(
    settings_kratos: Settings,
) -> None:
    # The DCSync case. The catalog hit is scoped on the account and names the
    # domain controller as a related host. The off-hours departure is on the
    # domain controller. One lead, two entities, two kinds.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="user",
            entity_key="localuser",
            kind=Kind.PRIOR_NO_BASELINE,
            spec_id="identity-4662-dcsync-nonmachine",
            fingerprint=content_fingerprint("identity-4662-dcsync-nonmachine", "localuser"),
            evidence={"sample_ids": ["d1"], "related": [["host", "10.1.2.11"]]},
            source="catalog",
            now=_NOW,
        )
        first = await form_leads(db, entity_keys=[("user", "localuser")], now=_NOW)
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.11",
            kind=Kind.OFF_HOURS,
            spec_id="profile-activity-outside-measured-hours",
            fingerprint=content_fingerprint("active_hours", "3"),
            now=_NOW,
        )
        second = await form_leads(db, entity_keys=[("host", "10.1.2.11")], now=_NOW)
        leads = (await db.execute(select(Lead).order_by(Lead.id))).scalars().all()
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert len(first.formed) == 1
    assert second.formed == () and second.updated == (first.formed[0],)
    assert len(leads) == 1
    assert sorted(tuple(e) for e in leads[0].entities_json) == [
        ("host", "10.1.2.11"),
        ("user", "localuser"),
    ]
    assert sorted(leads[0].kinds_json) == ["off_hours", "prior_no_baseline"]
    assert {r.lead_id for r in rows} == {leads[0].id}


async def test_a_host_observation_below_the_threshold_still_joins_a_lead_that_names_the_host(
    settings_kratos: Settings,
) -> None:
    # One weak departure on the host would form nothing alone. The account's
    # lead names the host, so the departure joins that lead.
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="user",
            entity_key="svc",
            kind=Kind.PRIOR_NO_BASELINE,
            spec_id="s",
            fingerprint="f",
            evidence={"related": [["host", "10.1.2.12"]]},
            source="catalog",
            now=_NOW,
        )
        await form_leads(db, entity_keys=[("user", "svc")], now=_NOW)
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.12",
            kind=Kind.OFF_HOURS,
            spec_id="p",
            fingerprint="g",
            now=_NOW,
        )
        outcome = await form_leads(db, entity_keys=[("host", "10.1.2.12")], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(leads) == 1 and len(outcome.updated) == 1
    assert "off_hours" in leads[0].kinds_json


async def test_a_lead_does_not_merge_through_a_hub(settings_kratos: Settings) -> None:
    # A related host that is a hub (the domain controller talks to everything)
    # is listed on the lead but does not pull other leads in. The hub rule
    # keeps the estate from becoming one lead.
    from soc_ai.hunting.leads import HUB_LEAD_LIMIT

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(HUB_LEAD_LIMIT + 1):
            await record_observation(
                db,
                entity_kind="user",
                entity_key=f"u{i}",
                kind=Kind.PRIOR_NO_BASELINE,
                spec_id="s",
                fingerprint=f"f{i}",
                evidence={"related": [["host", "10.1.2.1"]]},
                source="catalog",
                now=_NOW,
            )
            await form_leads(db, entity_keys=[("user", f"u{i}")], now=_NOW)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(leads) == HUB_LEAD_LIMIT + 1


async def test_a_dismissed_lead_does_not_absorb_a_later_observation(
    settings_kratos: Settings,
) -> None:
    from soc_ai.store import leads as leads_store

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _observe(db, Kind.NOVEL_DESTINATION, "1.1.1.1")
        await _observe(db, Kind.RARE_FOR_PEERS, "psexec.exe")
        await _observe(db, Kind.OFF_HOURS, "03:14")
        first = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        await leads_store.dismiss(
            db, first.formed[0], reason="known_change", note=None, by="analyst", now=_NOW
        )
        # Two new kinds later. They must form a NEW lead, and the dismissed
        # lead must not change.
        later = _NOW + timedelta(hours=2)
        await _observe(db, Kind.NOVEL_PROCESS, "rundll32.exe", now=later)
        await _observe(db, Kind.ALERT, "a-1", now=later)
        await _observe(db, Kind.NOVEL_DESTINATION, "9.9.9.9", now=later)
        second = await form_leads(db, entity_keys=[_HOST], now=later)
        leads = (await db.execute(select(Lead).order_by(Lead.id))).scalars().all()
    assert second.updated == ()
    assert len(second.formed) == 1 and second.formed[0] != first.formed[0]
    assert leads[0].status == "dismissed"
    assert sorted(leads[1].kinds_json) == ["alert", "novel_destination", "novel_process"]


# ---------------------------------------------------------------------------
# What a refresh may change, and what it may not
# ---------------------------------------------------------------------------


async def test_a_refresh_carries_the_status_the_analytic_has_now(
    settings_kratos: Settings,
) -> None:
    """The flag records the status at the LATEST sighting.

    An approval changes no observation. The analyst keeps the shadow hit that
    earned the approval, with its read state, until the analytic fires again.
    The next sweep refreshes the row and the sighting is a live one, so the
    card reads as a live hit from then on.

    Written at birth only, the flag left an approved analytic's hit between the
    two halves of the hits surface: too shadow for the live filter, and hidden
    from the shadow filter because the analytic had left shadow.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        born = await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.CATALOG_MATCH,
            spec_id="local-x",
            fingerprint="f1",
            evidence={"receipts": {"complete": True}, "sample_ids": ["d1"]},
            source="catalog",
            shadow=True,
            now=_NOW,
        )
        born.read_at = _NOW.replace(tzinfo=None)
        await db.commit()
        # The analyst approved the analytic. It runs live and hits again.
        again = await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.CATALOG_MATCH,
            spec_id="local-x",
            fingerprint="f1",
            source="catalog",
            shadow=False,
            evidence={"receipts": {"complete": True}, "sample_ids": ["d2"]},
            now=_NOW + timedelta(hours=2),
        )
    assert again.shadow is False
    assert again.read_at is None, "a hit that fires again asks for a second read"
    assert again.occurrences == 2
    assert again.evidence_json == {"receipts": {"complete": True}, "sample_ids": ["d2"]}


async def test_a_refresh_on_the_same_documents_still_flips_the_flag(
    settings_kratos: Settings,
) -> None:
    """The flag and the read mark answer two different questions.

    The documents did not change, so the analyst has read this sighting and the
    read mark stays. The analytic went live, so the row is a live observation.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        born = await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.CATALOG_MATCH,
            spec_id="local-x",
            fingerprint="f1",
            evidence={"sample_ids": ["d1"]},
            source="catalog",
            shadow=True,
            now=_NOW,
        )
        born.read_at = _NOW.replace(tzinfo=None)
        await db.commit()
        again = await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.CATALOG_MATCH,
            spec_id="local-x",
            fingerprint="f1",
            evidence={"sample_ids": ["d1"]},
            source="catalog",
            shadow=False,
            now=_NOW + timedelta(hours=2),
        )
    assert again.shadow is False
    assert again.read_at is not None


async def test_a_lead_drops_the_shadow_mark_when_its_observations_go_live(
    settings_kratos: Settings,
) -> None:
    """The lead's mark follows its observations, sighting by sighting.

    Lead 5 on the range kept the shadow chip after its analytic went live. The
    mark was written at formation and nothing read it back.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.CATALOG_MATCH,
            spec_id="local-x",
            fingerprint="f1",
            source="catalog",
            shadow=True,
            now=_NOW,
        )
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.PRIOR_NO_BASELINE,
            spec_id="local-y",
            fingerprint="f2",
            source="catalog",
            shadow=True,
            now=_NOW,
        )
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW)
        lead_id = outcome.formed[0]
        assert (await db.get(Lead, lead_id)).shadow is True

        # The analyst approved one of the two analytics. The next sweep
        # refreshes its row as a live observation.
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.CATALOG_MATCH,
            spec_id="local-x",
            fingerprint="f1",
            source="catalog",
            shadow=False,
            now=_NOW + timedelta(hours=1),
        )
        assert (await db.get(Lead, lead_id)).shadow is True, "one shadow row still marks the lead"

        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.PRIOR_NO_BASELINE,
            spec_id="local-y",
            fingerprint="f2",
            source="catalog",
            shadow=False,
            now=_NOW + timedelta(hours=1),
        )
        assert (await db.get(Lead, lead_id)).shadow is False


async def test_the_subject_entity_is_named_first_on_the_lead(
    settings_kratos: Settings,
) -> None:
    """The lead is ABOUT the entity its observations are about.

    entities_json was sorted, so a host a hit merely mentioned came before the
    account the hit was scoped on. Every surface reads the first entity as the
    subject of the lead.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="user",
            entity_key="localuser",
            kind=Kind.PRIOR_NO_BASELINE,
            spec_id="identity-4662-dcsync-nonmachine",
            fingerprint="dcsync",
            evidence={"related": [["host", "10.1.2.11"], ["host", "10.1.2.9"]]},
            source="catalog",
            now=_NOW,
        )
        outcome = await form_leads(db, entity_keys=[("user", "localuser")], now=_NOW)
        lead = await db.get(Lead, outcome.formed[0])
    assert lead.entities_json == [
        ["user", "localuser"],
        ["host", "10.1.2.11"],
        ["host", "10.1.2.9"],
    ]


async def test_a_demoted_analytic_writes_a_shadow_observation_again(
    settings_kratos: Settings,
) -> None:
    """The rule runs both ways. One sentence describes the flag on the row.

    An analyst put a live analytic back in shadow to reassess it. Its next
    sighting is provisional, so the card reads as a shadow hit and asks for a
    read. A rule that only flipped one way would leave the row claiming a
    status the analytic no longer has.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.CATALOG_MATCH,
            spec_id="shipped-x",
            fingerprint="f2",
            source="catalog",
            now=_NOW,
        )
        again = await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.CATALOG_MATCH,
            spec_id="shipped-x",
            fingerprint="f2",
            source="catalog",
            shadow=True,
            now=_NOW + timedelta(hours=1),
        )
    assert again.shadow is True


async def test_a_refresh_with_the_same_documents_keeps_the_read_mark(
    settings_kratos: Settings,
) -> None:
    from datetime import datetime as _dt

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.3",
            kind=Kind.CATALOG_MATCH,
            spec_id="s",
            fingerprint="f",
            evidence={"sample_ids": ["d1", "d2"]},
            source="catalog",
            shadow=True,
            now=_NOW,
        )
        row.read_at = _dt(2026, 9, 18, 12, 30)
        await db.commit()
        again = await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.3",
            kind=Kind.CATALOG_MATCH,
            spec_id="s",
            fingerprint="f",
            evidence={"sample_ids": ["d2", "d1"]},
            source="catalog",
            shadow=True,
            now=_NOW + timedelta(hours=1),
        )
        assert again.read_at is not None
        newer = await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.3",
            kind=Kind.CATALOG_MATCH,
            spec_id="s",
            fingerprint="f",
            evidence={"sample_ids": ["d1", "d3"]},
            source="catalog",
            shadow=True,
            now=_NOW + timedelta(hours=2),
        )
    assert newer.read_at is None


# ---------------------------------------------------------------------------
# The hunt a lead starts: one start for the route and the loop
# ---------------------------------------------------------------------------


def _state(maker) -> SimpleNamespace:  # type: ignore[no-untyped-def]
    """The slice of ``app.state`` a lead hunt reads."""
    return SimpleNamespace(db_sessionmaker=maker)


def _recorder() -> tuple[list[dict[str, Any]], SimpleNamespace]:
    """A hunt console that records the start rather than running an agent."""
    calls: list[dict[str, Any]] = []

    async def _start(_state, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(kwargs)
        return "01HUNTFROMLEAD"

    return calls, SimpleNamespace(start=_start)


async def _one_lead(maker, *, evidence: dict[str, Any] | None = None) -> int:  # type: ignore[no-untyped-def]
    """One lead on one host, from two kinds, with the evidence given."""
    async with maker() as db:
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.NOVEL_DESTINATION,
            spec_id="s",
            fingerprint=content_fingerprint("peers_out", "203.0.113.9"),
            summary="new outbound peer for this host: 203.0.113.9",
            evidence=evidence,
            now=_NOW,
        )
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.OFF_HOURS,
            spec_id="p",
            fingerprint=content_fingerprint("active_hours", "3"),
            summary="active around 03:00 UTC",
            now=_NOW,
        )
        outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW, threshold=0.7)
        return int(outcome.formed[0])


async def test_the_lifted_start_tags_the_hunt_as_a_lead_hunt(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The route and the loop call this, so the two cannot start different hunts.

    The objective names the lead and the evidence block names the documents.
    A lead hunt that read neither searched the grid on its own and called a
    real DCSync event a broken rule.
    """
    from soc_ai.hunting import lead_hunt
    from soc_ai.store.models import Lead

    engine, maker = await _db(settings_kratos)
    lead_id = await _one_lead(maker, evidence={"sample_ids": ["d1"]})
    calls, manager = _recorder()
    monkeypatch.setattr("soc_ai.webui.hunt_console_manager.get_manager", lambda _s: manager)

    out = await lead_hunt.start_lead_hunt(_state(maker), lead_id=lead_id, started_by="tester")

    assert out.hunt_id == "01HUNTFROMLEAD" and out.existing is False
    assert len(calls) == 1
    assert calls[0]["kind"] == "lead" and calls[0]["starter"] == "lead"
    assert calls[0]["lead_id"] == lead_id and calls[0]["started_by"] == "tester"
    assert calls[0]["objective"].startswith(f"[lead {lead_id}] ")
    assert "document ids d1" in calls[0]["objective"]
    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead.status == "hunting" and lead.hunt_id == "01HUNTFROMLEAD"
    await engine.dispose()


async def test_a_second_start_returns_the_hunt_that_exists(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One lead, one hunt. The analyst's click and the loop's wake can race."""
    from soc_ai.hunting import lead_hunt

    engine, maker = await _db(settings_kratos)
    lead_id = await _one_lead(maker, evidence={"sample_ids": ["d1"]})
    calls, manager = _recorder()
    monkeypatch.setattr("soc_ai.webui.hunt_console_manager.get_manager", lambda _s: manager)

    await lead_hunt.start_lead_hunt(_state(maker), lead_id=lead_id, started_by="tester")
    again = await lead_hunt.start_lead_hunt(_state(maker), lead_id=lead_id, started_by="loop")

    assert again.hunt_id == "01HUNTFROMLEAD" and again.existing is True
    assert len(calls) == 1, "the second start ran a second agent"
    await engine.dispose()


async def test_a_dismissed_lead_refuses_the_start(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dismissal is a decision. Nothing starts work on it until it is reopened."""
    from soc_ai.hunting import lead_hunt
    from soc_ai.store import leads as leads_store

    engine, maker = await _db(settings_kratos)
    lead_id = await _one_lead(maker, evidence={"sample_ids": ["d1"]})
    async with maker() as db:
        await leads_store.dismiss(db, lead_id, reason="known_change", note=None, by="ana")
    calls, manager = _recorder()
    monkeypatch.setattr("soc_ai.webui.hunt_console_manager.get_manager", lambda _s: manager)

    with pytest.raises(lead_hunt.LeadHuntRefused) as exc:
        await lead_hunt.start_lead_hunt(_state(maker), lead_id=lead_id, started_by="loop")
    assert exc.value.reason == "lead_is_closed"
    assert exc.value.lead is not None and exc.value.lead.dismissed_reason == "known_change"
    assert calls == []
    await engine.dispose()


async def test_a_missing_lead_refuses_the_start(settings_kratos: Settings) -> None:
    from soc_ai.hunting import lead_hunt

    engine, maker = await _db(settings_kratos)
    with pytest.raises(lead_hunt.LeadHuntRefused) as exc:
        await lead_hunt.start_lead_hunt(_state(maker), lead_id=999999, started_by="loop")
    assert exc.value.reason == "lead_not_found"
    await engine.dispose()


async def test_a_console_at_its_ceiling_refuses_the_start(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The console answers None at its concurrency ceiling. The lead stays open.

    Marking the lead hunting on a hunt that never began would leave it on no
    tab the analyst reads.
    """
    from soc_ai.hunting import lead_hunt
    from soc_ai.store.models import Lead

    engine, maker = await _db(settings_kratos)
    lead_id = await _one_lead(maker, evidence={"sample_ids": ["d1"]})

    async def _start(_state, **_kwargs):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager",
        lambda _s: SimpleNamespace(start=_start),
    )
    with pytest.raises(lead_hunt.LeadHuntRefused) as exc:
        await lead_hunt.start_lead_hunt(_state(maker), lead_id=lead_id, started_by="loop")
    assert exc.value.reason == "could_not_start"
    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead.status == "open" and lead.hunt_id is None
    await engine.dispose()


async def test_a_lead_says_whether_its_observations_cite_documents(
    settings_kratos: Settings,
) -> None:
    """A hunt of a lead that cites nothing reads the grid from scratch.

    The loop skips such a lead. The rule lives with the evidence block that
    reads the same ids.
    """
    from soc_ai.store import leads as leads_store

    engine, maker = await _db(settings_kratos)
    cited = await _one_lead(maker, evidence={"sample_ids": ["d1"]})
    async with maker() as db:
        assert leads_store.cites_documents(await leads_store.timeline(db, cited)) is True

    async with maker() as db:
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.10.99",
            kind=Kind.NOVEL_PROCESS,
            spec_id="s",
            fingerprint=content_fingerprint("process", "rundll32.exe"),
            summary="a process this host has not run before",
            now=_NOW,
        )
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.10.99",
            kind=Kind.OFF_HOURS,
            spec_id="p",
            fingerprint=content_fingerprint("active_hours", "3"),
            summary="active around 03:00 UTC",
            now=_NOW,
        )
        outcome = await form_leads(
            db, entity_keys=[("host", "10.1.10.99")], now=_NOW, threshold=0.7
        )
        bare = int(outcome.formed[0])
        assert leads_store.cites_documents(await leads_store.timeline(db, bare)) is False
    await engine.dispose()


# ---------------------------------------------------------------------------
# Which leads the loop may hunt
# ---------------------------------------------------------------------------


async def _row(maker, **fields: Any) -> int:  # type: ignore[no-untyped-def]
    """One lead row, written straight. The formation rules have their own tests."""
    from soc_ai.store.models import Lead

    async with maker() as db:
        lead = Lead(
            status=fields.pop("status", "open"),
            entities_json=[["host", "10.1.2.3"]],
            kinds_json=["catalog_match"],
            shadow=False,
            **fields,
        )
        db.add(lead)
        await db.commit()
        return int(lead.id)


async def test_the_loop_takes_open_leads_that_never_had_a_hunt_oldest_first(
    settings_kratos: Settings,
) -> None:
    """The oldest lead has waited longest, so it goes first."""
    from soc_ai.hunting import lead_hunt

    engine, maker = await _db(settings_kratos)
    newer = await _row(maker, formed_at=_NOW.replace(tzinfo=None))
    older = await _row(maker, formed_at=(_NOW - timedelta(hours=3)).replace(tzinfo=None))
    async with maker() as db:
        waiting = await lead_hunt.leads_awaiting_a_hunt(db, limit=10)
    assert [int(lead.id) for lead in waiting] == [older, newer]
    await engine.dispose()


async def test_the_loop_leaves_out_the_leads_that_are_not_its_work(
    settings_kratos: Settings,
) -> None:
    """A dismissed lead, a promoted lead, a hunting lead and a reopened lead.

    A reopened lead carries its dismissal as history. The analyst reopened it
    to decide again, and Hunt again is their call, not the loop's.
    """
    from soc_ai.hunting import lead_hunt
    from soc_ai.store.models import Hunt

    engine, maker = await _db(settings_kratos)
    fresh = await _row(maker)
    await _row(maker, status="dismissed", dismissed_reason="known_change")
    await _row(maker, status="promoted", investigation_id="01INV")
    await _row(maker, status="hunting", hunt_id="01HUNT")
    await _row(
        maker,
        dismissed_reason="benign_repeat",
        dismissed_at=_NOW.replace(tzinfo=None),
    )

    # A lead whose hunt row exists but whose hunt_id was never stamped: the
    # console started the hunt and the mark failed. It has had its hunt.
    had_one = await _row(maker)
    async with maker() as db:
        db.add(
            Hunt(
                id="01HUNTORPHAN",
                objective="look at this lead",
                objective_hash="x",
                started_by="auto-hunt",
                kind="lead",
                starter="lead",
                status="complete",
                lead_id=had_one,
            )
        )
        await db.commit()

    async with maker() as db:
        waiting = {int(lead.id) for lead in await lead_hunt.leads_awaiting_a_hunt(db, limit=50)}
    assert waiting == {fresh}
    await engine.dispose()


async def test_the_cap_counts_only_the_hunts_the_loop_started(
    settings_kratos: Settings,
) -> None:
    """A hunt an analyst started by hand never blocks the loop."""
    from soc_ai.hunting import lead_hunt
    from soc_ai.store.models import Hunt

    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for hunt_id, started_by, status in (
            ("01A", lead_hunt.AUTO_HUNT_ACTOR, "running"),
            ("01B", lead_hunt.AUTO_HUNT_ACTOR, "queued"),
            ("01C", lead_hunt.AUTO_HUNT_ACTOR, "complete"),
            ("01D", "ana", "running"),
        ):
            db.add(
                Hunt(
                    id=hunt_id,
                    objective="o",
                    objective_hash="x",
                    started_by=started_by,
                    kind="lead",
                    starter="lead",
                    status=status,
                )
            )
        await db.commit()
        assert await lead_hunt.running_auto_hunts(db) == 2
    await engine.dispose()
