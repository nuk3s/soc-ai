"""Lead status changes and the objective a lead writes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.leads import content_fingerprint, form_leads, record_observation
from soc_ai.hunting.weight import Kind
from soc_ai.store import leads as leads_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt, Lead
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
_HOST = ("host", "198.51.100.7")
# A new destination is worth 0.5 and off-hours activity is worth 0.3. The pair
# is worth 0.8, below the 0.85 default. The seed names its own threshold so the
# two kinds this file needs form one lead.
_THRESHOLD = 0.7


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _lead(db) -> Lead:  # type: ignore[no-untyped-def]
    await record_observation(
        db,
        entity_kind=_HOST[0],
        entity_key=_HOST[1],
        kind=Kind.NOVEL_DESTINATION,
        spec_id="s",
        fingerprint=content_fingerprint("peers_out", "203.0.113.9"),
        summary="new outbound peer for this host: 203.0.113.9 (seen once)",
        evidence={"sample_ids": ["d1"]},
        now=_NOW,
    )
    await record_observation(
        db,
        entity_kind=_HOST[0],
        entity_key=_HOST[1],
        kind=Kind.OFF_HOURS,
        spec_id="p",
        fingerprint=content_fingerprint("active_hours", "3"),
        summary="active around 03:00 UTC, outside the hours this host is normally active",
        now=_NOW,
    )
    outcome = await form_leads(db, entity_keys=[_HOST], now=_NOW, threshold=_THRESHOLD)
    return await leads_store.get(db, outcome.formed[0])


async def test_the_new_columns_exist(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        hunt = Hunt(
            id="01HUNTLEAD",
            objective="x",
            started_by="analyst",
            kind="lead",
            starter="lead",
            lead_id=lead.id,
        )
        db.add(hunt)
        await db.commit()
        row = (await db.execute(select(Hunt))).scalar_one()
    assert row.starter == "lead" and row.lead_id == lead.id
    assert lead.dismissed_reason is None and lead.investigation_id is None


async def test_get_and_timeline(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        rows = await leads_store.timeline(db, lead.id)
        assert [r.kind for r in rows] == ["novel_destination", "off_hours"] or [
            r.kind for r in rows
        ] == ["off_hours", "novel_destination"]
        assert await leads_store.get(db, 999) is None


async def test_dismiss_requires_a_known_reason(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        with pytest.raises(ValueError):
            await leads_store.dismiss(
                db, lead.id, reason="because", note=None, by="analyst", now=_NOW
            )
        lead = await leads_store.dismiss(
            db,
            lead.id,
            reason="expected_for_role",
            note="the router does this",
            by="analyst",
            now=_NOW,
        )
    assert lead.status == "dismissed"
    assert lead.dismissed_reason == "expected_for_role"
    assert lead.dismissed_by == "analyst"
    assert lead.dismissed_at is not None


async def test_mark_hunting_and_promoted(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        lead = await leads_store.mark_hunting(db, lead.id, hunt_id="01HUNT")
        assert lead.status == "hunting" and lead.hunt_id == "01HUNT"
        lead = await leads_store.mark_promoted(db, lead.id, investigation_id="01INV")
    assert lead.status == "promoted" and lead.investigation_id == "01INV"


async def test_a_second_dismissal_changes_nothing(settings_kratos: Settings) -> None:
    """A dismissal is an answer. A repeat of it must not rewrite the answer.

    The route is a button. A double click used to overwrite the reason, the
    note and the hand that wrote them.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        await leads_store.dismiss(
            db, lead.id, reason="known_change", note="the rollout", by="ann", now=_NOW
        )
        again = await leads_store.dismiss(
            db,
            lead.id,
            reason="other",
            note="second thoughts",
            by="bob",
            now=_NOW + timedelta(hours=1),
        )
    assert again.dismissed_reason == "known_change"
    assert again.dismissed_note == "the rollout"
    assert again.dismissed_by == "ann"


async def test_a_dismissed_lead_refuses_a_hunt_and_a_promotion(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        await leads_store.dismiss(
            db, lead.id, reason="benign_repeat", note=None, by="ann", now=_NOW
        )
        with pytest.raises(ValueError, match="Reopen it first"):
            await leads_store.mark_hunting(db, lead.id, hunt_id="01HUNT")
        with pytest.raises(ValueError, match="Reopen it first"):
            await leads_store.mark_promoted(db, lead.id, investigation_id="01INV")
        assert lead.status == "dismissed"


async def test_a_promoted_lead_refuses_a_hunt(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        await leads_store.mark_promoted(db, lead.id, investigation_id="01INV")
        with pytest.raises(ValueError, match="Reopen it first"):
            await leads_store.mark_hunting(db, lead.id, hunt_id="01HUNT")
        assert lead.status == "promoted"


async def test_reopen_keeps_the_dismissal_as_history(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        await leads_store.dismiss(
            db,
            lead.id,
            reason="bad_baseline",
            note="the baseline was 2 days old",
            by="ann",
            now=_NOW,
        )
        reopened = await leads_store.reopen(db, lead.id, by="bob")
        assert reopened.status == "open"
        # The dismissal stays readable. The sharpening loop reads the reason
        # later, and a reopening that erased it would erase the lesson too.
        assert reopened.dismissed_reason == "bad_baseline"
        assert reopened.dismissed_by == "ann"
        assert reopened.dismissed_at is not None
        hunting = await leads_store.mark_hunting(db, lead.id, hunt_id="01HUNT")
    assert hunting.status == "hunting"


async def test_reopen_keeps_the_hunt_the_lead_already_had(settings_kratos: Settings) -> None:
    """The hunt is the work that was done. A reopen does not undo it.

    The reopened lead is open again and still names its hunt, which is the
    state :func:`needs_decision_clause` has to hold: the analyst reads the
    hunt and decides.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        await leads_store.mark_hunting(db, lead.id, hunt_id="01HUNT")
        await leads_store.dismiss(
            db, lead.id, reason="benign_repeat", note=None, by="ann", now=_NOW
        )
        reopened = await leads_store.reopen(db, lead.id, by="bob")
    assert reopened.status == "open"
    assert reopened.hunt_id == "01HUNT"


async def test_the_objective_names_the_lead_and_nothing_else(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        rows = await leads_store.timeline(db, lead.id)
        text = leads_store.objective_for(lead, rows)
    assert text.startswith(f"[lead {lead.id}] ")
    assert "198.51.100.7" in text
    assert "new outbound peer" in text and "03:00 UTC" in text
    assert "novel_destination" not in text  # kinds are named in words, not enum values
    assert "d1" not in text  # evidence ids ride in the case, not in the sentence


async def test_the_evidence_block_lists_the_document_ids_per_observation(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
        rows = await leads_store.timeline(db, lead.id)
    block = leads_store.evidence_block_for(rows)
    assert block.startswith("Evidence documents, by observation:")
    assert "document ids d1" in block
    assert "no document ids recorded" in block
    assert "get_event_raw" in block


async def test_a_profile_observation_names_the_documents_behind_it(
    settings_kratos: Settings,
) -> None:
    """The range read "no document ids recorded" three times in one objective.

    Every observation in that lead came from the profile path, so the hunt had
    nothing to open, re-queried the grid on its own, and could not confirm the
    departure it had been sent to confirm.
    """
    from soc_ai.store.models import EntityObservation

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind=_HOST[0],
            entity_key=_HOST[1],
            kind=Kind.OFF_HOURS,
            spec_id="p",
            fingerprint=content_fingerprint("active_hours", "3"),
            summary="active around 03:00 UTC, outside the hours this host is normally active",
            evidence={
                "sample_ids": ["a", "b", "c"],
                "anchor_id": "a",
                "baseline": {"dimension": "active_hours", "member": "3"},
            },
            source="profile",
            now=_NOW,
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()

    block = leads_store.evidence_block_for(rows)
    assert "document ids a, b, c" in block
    assert "no document ids recorded" not in block
    assert "get_event_raw" in block


# ---------------------------------------------------------------------------
# Related leads — a lead spans the entities one hit names, an attack does not
# ---------------------------------------------------------------------------

# Two analytics that name one ATT&CK technique between them, T1078.002. The
# ids come from the shipped catalog, because the technique is read from the
# analytic file and not from anything the test writes.
_FIRST_LOGON = "prior-workstation-account-first-logon-to-dc"
_GROUP_CHANGED = "prior-privileged-group-membership-changed"


async def _seed_lead(  # type: ignore[no-untyped-def]
    db,
    *,
    host: str,
    spec_id: str,
    born_at: datetime,
    formed_at: datetime | None = None,
    status: str = "open",
    evidence: dict | None = None,
    member: str | None = None,
) -> Lead:
    """One lead row on one host, with one observation under one analytic.

    Written at the row level. These tests pin what relates two leads, and the
    formation rule has its own tests.

    ``member`` is the value the observation fingerprints. Two leads on one
    host under one analytic need two values, because the observation table
    holds one row per (entity, analytic, fingerprint).
    """
    from soc_ai.store.models import EntityObservation

    at = (formed_at or born_at).replace(tzinfo=None)
    lead = Lead(
        status=status,
        entities_json=[["host", host]],
        kinds_json=["catalog_match"],
        formed_at=at,
        updated_at=at,
        shadow=False,
    )
    db.add(lead)
    await db.flush()
    db.add(
        EntityObservation(
            entity_kind="host",
            entity_key=host,
            kind="catalog_match",
            spec_id=spec_id,
            fingerprint=content_fingerprint(spec_id, member or host),
            birth_weight=0.6,
            born_at=born_at.replace(tzinfo=None),
            first_seen_at=born_at.replace(tzinfo=None),
            summary=f"{spec_id} on {host}",
            evidence_json=evidence,
            source="catalog",
            lead_id=lead.id,
        )
    )
    await db.commit()
    await db.refresh(lead)
    return lead


async def test_two_leads_on_one_analytic_inside_a_day_are_related(
    settings_kratos: Settings,
) -> None:
    """The strongest share: one analytic, two entities, inside a working day.

    The analytic id here is not in the catalog, so the pair can only relate by
    the analytic. A catalog id would also share a technique, and the test
    would pass on the wrong reason.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(db, host="10.1.1.5", spec_id="s", born_at=_NOW)
        other = await _seed_lead(
            db, host="10.1.1.6", spec_id="s", born_at=_NOW - timedelta(hours=6)
        )
        related = await leads_store.related_leads(db, mine, now=_NOW)
    assert [r.lead_id for r in related] == [other.id]
    assert related[0].reason == "same analytic within 24 h"
    assert related[0].entities == [["host", "10.1.1.6"]]
    assert related[0].status == "open"
    assert related[0].formed_at is not None


async def test_two_alert_leads_on_different_rules_are_not_related(
    settings_kratos: Settings,
) -> None:
    """Every alert observation carries the one spec id "alert".

    On the range that id related five different attacks as one campaign. The
    rule that raised the alert is the share, not the constant.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(
            db,
            host="10.1.1.5",
            spec_id="alert",
            born_at=_NOW,
            evidence={"alert_id": "a1", "rule_name": "ET EXPLOIT One"},
        )
        await _seed_lead(
            db,
            host="10.1.1.6",
            spec_id="alert",
            born_at=_NOW - timedelta(hours=1),
            evidence={"alert_id": "a2", "rule_name": "ET EXPLOIT Two"},
        )
        assert await leads_store.related_leads(db, mine, now=_NOW) == []


async def test_two_alert_leads_on_one_rule_inside_a_day_are_related(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(
            db,
            host="10.1.1.5",
            spec_id="alert",
            born_at=_NOW,
            evidence={"alert_id": "a1", "rule_name": "ET INFO Suspected Impacket WMIExec"},
        )
        other = await _seed_lead(
            db,
            host="10.1.1.6",
            spec_id="alert",
            born_at=_NOW - timedelta(hours=3),
            evidence={"alert_id": "a2", "rule_name": "ET INFO Suspected Impacket WMIExec"},
        )
        related = await leads_store.related_leads(db, mine, now=_NOW)
    assert [r.lead_id for r in related] == [other.id]
    assert related[0].reason == "same alert rule within 24 h"


async def test_the_same_analytic_two_days_apart_is_not_a_relation(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(db, host="10.1.1.5", spec_id="s", born_at=_NOW)
        await _seed_lead(
            db,
            host="10.1.1.6",
            spec_id="s",
            born_at=_NOW - timedelta(hours=48),
            formed_at=_NOW - timedelta(hours=48),
        )
        assert await leads_store.related_leads(db, mine, now=_NOW) == []


async def test_two_leads_on_one_external_network_are_related(
    settings_kratos: Settings,
) -> None:
    """Two hosts talking to one /24 outside the estate.

    The analytics differ and neither is in the catalog, so the address is the
    only thing the two leads share. The addresses differ in the last octet,
    which is the comparison the design asks for.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(
            db,
            host="10.1.1.5",
            spec_id="s",
            born_at=_NOW,
            evidence={"sample_ids": ["d1"], "baseline": {"member": "203.0.113.9"}},
        )
        other = await _seed_lead(
            db,
            host="10.1.1.6",
            spec_id="p",
            born_at=_NOW,
            evidence={"sample_ids": ["d2"], "baseline": {"member": "203.0.113.44"}},
        )
        related = await leads_store.related_leads(db, mine, now=_NOW)
    assert [r.lead_id for r in related] == [other.id]
    assert related[0].reason == "same external address 203.0.113.0/24"


async def test_an_internal_address_relates_nothing(settings_kratos: Settings) -> None:
    """Every host inside the estate would otherwise relate to every other one."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(
            db,
            host="10.1.1.5",
            spec_id="s",
            born_at=_NOW,
            evidence={"related": [["host", "10.1.1.200"]]},
        )
        await _seed_lead(
            db,
            host="10.1.1.6",
            spec_id="p",
            born_at=_NOW,
            evidence={"related": [["host", "10.1.1.201"]]},
        )
        assert await leads_store.related_leads(db, mine, now=_NOW) == []


async def test_two_leads_on_one_technique_are_related(settings_kratos: Settings) -> None:
    """Two different analytics that name one technique between them."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(db, host="10.1.1.5", spec_id=_FIRST_LOGON, born_at=_NOW)
        other = await _seed_lead(
            db, host="10.1.1.6", spec_id=_GROUP_CHANGED, born_at=_NOW - timedelta(days=2)
        )
        related = await leads_store.related_leads(db, mine, now=_NOW)
    assert [r.lead_id for r in related] == [other.id]
    assert related[0].reason == "same technique T1078.002"


async def test_two_analytics_with_no_technique_in_common_are_not_related(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(db, host="10.1.1.5", spec_id=_FIRST_LOGON, born_at=_NOW)
        await _seed_lead(
            db,
            host="10.1.1.6",
            spec_id="profile-connection-rate-collapsed",
            born_at=_NOW - timedelta(days=2),
        )
        assert await leads_store.related_leads(db, mine, now=_NOW) == []


async def test_nothing_relates_across_the_seven_day_window(settings_kratos: Settings) -> None:
    """A lead formed ten days ago is a different story, however well it matches."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(db, host="10.1.1.5", spec_id="s", born_at=_NOW)
        await _seed_lead(
            db,
            host="10.1.1.6",
            spec_id="s",
            born_at=_NOW - timedelta(hours=6),
            formed_at=_NOW - timedelta(days=10),
        )
        assert await leads_store.related_leads(db, mine, now=_NOW) == []


async def test_a_closed_lead_is_never_related(settings_kratos: Settings) -> None:
    """A dismissal and a promotion are answers. Neither is offered again."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(db, host="10.1.1.5", spec_id="s", born_at=_NOW)
        dismissed = await _seed_lead(db, host="10.1.1.6", spec_id="s", born_at=_NOW)
        promoted = await _seed_lead(db, host="10.1.1.7", spec_id="s", born_at=_NOW)
        assert {r.lead_id for r in await leads_store.related_leads(db, mine, now=_NOW)} == {
            dismissed.id,
            promoted.id,
        }
        await leads_store.dismiss(
            db, dismissed.id, reason="known_change", note=None, by="ann", now=_NOW
        )
        await leads_store.mark_promoted(db, promoted.id, investigation_id="01INV")
        assert await leads_store.related_leads(db, mine, now=_NOW) == []


async def test_a_successor_lead_on_the_same_entity_is_not_related(
    settings_kratos: Settings,
) -> None:
    """Related leads answer "did this move?". One entity cannot answer it.

    A closed lead and the lead that forms next on the same host are the same
    story told twice. The panel named the successor as a relation, under the
    reason the two leads were always going to share: their own analytic.
    """
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(db, host="10.1.1.5", spec_id="s", born_at=_NOW)
        successor = await _seed_lead(
            db, host="10.1.1.5", spec_id="s", born_at=_NOW - timedelta(hours=2), member="again"
        )
        elsewhere = await _seed_lead(
            db, host="10.1.1.6", spec_id="s", born_at=_NOW - timedelta(hours=2)
        )
        related = await leads_store.related_leads(db, mine, now=_NOW)
        counts = await leads_store.related_counts(db, [mine], now=_NOW)
    assert [r.lead_id for r in related] == [elsewhere.id]
    assert successor.id not in {r.lead_id for r in related}
    assert counts == {mine.id: 1}


async def test_related_counts_answers_the_whole_page_at_once(
    settings_kratos: Settings,
) -> None:
    """The list row carries a count. One page must not cost one query per row."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await _seed_lead(db, host="10.1.1.5", spec_id="s", born_at=_NOW)
        second = await _seed_lead(db, host="10.1.1.6", spec_id="s", born_at=_NOW)
        alone = await _seed_lead(db, host="10.1.1.7", spec_id="q", born_at=_NOW)
        counts = await leads_store.related_counts(db, [first, second, alone], now=_NOW)
    assert counts == {first.id: 1, second.id: 1, alone.id: 0}


async def test_the_objective_names_the_related_leads_and_asks_for_a_campaign(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        mine = await _seed_lead(db, host="10.1.1.5", spec_id="s", born_at=_NOW)
        other = await _seed_lead(db, host="10.1.1.6", spec_id="s", born_at=_NOW)
        rows = await leads_store.timeline(db, mine.id)
        related = await leads_store.related_leads(db, mine, now=_NOW)
        text = leads_store.objective_for(mine, rows, related)
        plain = leads_store.objective_for(mine, rows)
    # The list is a snapshot. The hunt reads it hours after the API computed
    # it, and the two can disagree by then, so the line says when it was read.
    assert "Related leads at the start of this hunt:" in text
    assert f"- lead {other.id} on 10.1.1.6: same analytic within 24 h" in text
    assert "State whether these leads and this one are one campaign, with the evidence." in text
    # The argument is optional, so the caller that has none reads what it read
    # before.
    assert "Related leads" not in plain
    assert "one campaign" not in plain
