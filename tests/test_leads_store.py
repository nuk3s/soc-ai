"""Lead status changes and the objective a lead writes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

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


# Three finding shapes, one per outcome the hunt rule reads. A title that
# ends in ": could not run" is the shape spec_report writes for a query that
# raised, and the category is what finding_category reads first.
_THREAT: dict[str, Any] = {
    "title": "Beaconing to a rare external address",
    "severity": "high",
    "hosts": ["198.51.100.7"],
    "citations": ["es-1"],
}
_GAP: dict[str, Any] = {"title": "No telemetry in the window", "category": "visibility_gap"}
_OBSERVATION: dict[str, Any] = {
    "title": "New ports are mail DNS source ports",
    "category": "observation",
    "severity": "info",
}
_FAILED: dict[str, Any] = {
    "title": "net-rare-served-port: could not run",
    "category": "visibility_gap",
}


def test_hunt_outcome_names_the_four_outcomes() -> None:
    """The rule the Hunts page paints from, now readable by the store."""
    from soc_ai.hunting.findings import hunt_outcome

    assert hunt_outcome("complete", []) == (0, "clean")
    assert hunt_outcome("complete", [_THREAT]) == (1, "threats")
    assert hunt_outcome("complete", [_GAP]) == (0, "gap")
    assert hunt_outcome("complete", [_GAP, _FAILED]) == (0, "failed")
    assert hunt_outcome("complete", [_OBSERVATION, _GAP, _FAILED]) == (0, "failed")


def test_a_hunt_that_saw_the_host_and_noted_one_gap_is_clean() -> None:
    """A gap is the whole outcome only when the hunt saw nothing else.

    The first two lead hunts on a production grid each explained the lead as a
    benign pattern in four observation findings and added one honest caveat
    ("mail payload content not inspected") as a visibility gap. The old rule
    read any gap as the outcome, so both leads waited on the analyst for
    ever. A hunt that saw the host and found no threat is clean; a hunt that
    saw only blindness is a gap.
    """
    from soc_ai.hunting.findings import hunt_outcome

    assert hunt_outcome("complete", [_OBSERVATION, _GAP]) == (0, "clean")
    assert hunt_outcome("complete", [_OBSERVATION]) == (0, "clean")
    assert hunt_outcome("complete", [_GAP, _GAP]) == (0, "gap")
    assert hunt_outcome("error", [_THREAT]) == (1, "")
    assert hunt_outcome("complete", None) == (0, "")


async def _lead_row(
    db,  # type: ignore[no-untyped-def]
    *,
    hunt_id: str | None = None,
    dismissed_reason: str | None = None,
    dismissed_by: str | None = None,
    dismissed_at: datetime | None = None,
) -> Lead:
    """One lead row on its own host, so several can exist side by side.

    ``_lead`` forms through the rule and merges a second lead into the first.
    The settle tests need three leads with three hunts, written at the row
    level, because they pin the transition and not the formation.
    """
    lead = Lead(
        status="hunting" if hunt_id else "open",
        entities_json=[["host", "198.51.100.7"]],
        kinds_json=["novel_served_port"],
        weight_at_formation=1.5,
        shadow=False,
        hunt_id=hunt_id,
        dismissed_reason=dismissed_reason,
        dismissed_by=dismissed_by,
        dismissed_at=dismissed_at,
    )
    db.add(lead)
    await db.commit()
    await db.refresh(lead)
    return lead


async def _hunt_row(
    db,  # type: ignore[no-untyped-def]
    *,
    hunt_id: str,
    lead_id: int,
    status: str = "complete",
    findings: list[dict[str, Any]] | None = None,
    started_by: str = "auto-hunt",
) -> Hunt:
    hunt = Hunt(
        id=hunt_id,
        objective="o",
        objective_hash="x",
        started_by=started_by,
        kind="lead",
        starter="lead",
        status=status,
        lead_id=lead_id,
        report=None if findings is None else {"findings": findings, "narrative": "n"},
    )
    db.add(hunt)
    await db.commit()
    await db.refresh(hunt)
    return hunt


async def test_a_clean_hunt_closes_its_lead(settings_kratos: Settings) -> None:
    """The hunt answered the question the lead asked. Nobody has to click."""
    _engine, maker = await _db(settings_kratos)
    now = datetime.now(UTC)
    async with maker() as db:
        lead = await _lead_row(db, hunt_id="01CLEAN")
        hunt = await _hunt_row(db, hunt_id="01CLEAN", lead_id=lead.id, findings=[])
        assert await leads_store.settle_after_hunt(db, hunt, now=now) == "closed"
        lead = await leads_store.get(db, lead.id)
    assert lead.status == "dismissed"
    assert lead.dismissed_reason == leads_store.HUNT_CLEAN_REASON == "hunt_clean"
    assert lead.dismissed_by == leads_store.AUTO_HUNT_ACTOR == "auto-hunt"
    assert lead.dismissed_at == now.replace(tzinfo=None)
    assert lead.hunt_id == "01CLEAN"


async def test_threat_findings_and_a_visibility_gap_leave_the_lead_on_the_analyst(
    settings_kratos: Settings,
) -> None:
    """A threat is the analyst's decision. A gap cannot be hunted away."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        threats = await _lead_row(db, hunt_id="01THREAT")
        hunt = await _hunt_row(db, hunt_id="01THREAT", lead_id=threats.id, findings=[_THREAT])
        assert await leads_store.settle_after_hunt(db, hunt) == "waits"
        gap = await _lead_row(db, hunt_id="01GAP")
        hunt = await _hunt_row(db, hunt_id="01GAP", lead_id=gap.id, findings=[_GAP])
        assert await leads_store.settle_after_hunt(db, hunt) == "waits"
        threats = await leads_store.get(db, threats.id)
        gap = await leads_store.get(db, gap.id)
    assert threats.status == "hunting" and threats.dismissed_reason is None
    assert gap.status == "hunting" and gap.dismissed_reason is None


async def test_a_hunt_that_did_not_run_returns_the_lead_to_open(
    settings_kratos: Settings,
) -> None:
    """The lead keeps the hunt it names, so the row can say "Could not run"."""
    _engine, maker = await _db(settings_kratos)
    cases = [
        ("01ERR", "error", None),
        ("01CANCEL", "cancelled", None),
        ("01INTERRUPT", "interrupted", None),
        ("01FAILED", "complete", [_GAP, _FAILED]),
    ]
    async with maker() as db:
        for hunt_id, status, findings in cases:
            lead = await _lead_row(db, hunt_id=hunt_id)
            hunt = await _hunt_row(
                db, hunt_id=hunt_id, lead_id=lead.id, status=status, findings=findings
            )
            assert await leads_store.settle_after_hunt(db, hunt) == "reopened", hunt_id
            lead = await leads_store.get(db, lead.id)
            assert lead.status == "open" and lead.hunt_id == hunt_id, hunt_id
            assert lead.dismissed_reason is None, hunt_id


async def test_an_analyst_dismissal_in_the_history_blocks_the_automatic_close(
    settings_kratos: Settings,
) -> None:
    """The analyst reopened this lead to decide again. The rule does not decide for them."""
    _engine, maker = await _db(settings_kratos)
    dismissed_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=2)
    async with maker() as db:
        lead = await _lead_row(
            db,
            hunt_id="01AGAIN",
            dismissed_reason="benign_repeat",
            dismissed_by="ann",
            dismissed_at=dismissed_at,
        )
        hunt = await _hunt_row(db, hunt_id="01AGAIN", lead_id=lead.id, findings=[])
        assert await leads_store.settle_after_hunt(db, hunt) == "waits"
        lead = await leads_store.get(db, lead.id)
    assert lead.status == "hunting"
    assert lead.dismissed_reason == "benign_repeat" and lead.dismissed_by == "ann"
    assert lead.dismissed_at == dismissed_at


async def test_settle_is_idempotent_and_ignores_a_hunt_the_lead_no_longer_names(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead_row(db, hunt_id="01SECOND")
        first = await _hunt_row(db, hunt_id="01FIRST", lead_id=lead.id, findings=[])
        second = await _hunt_row(db, hunt_id="01SECOND", lead_id=lead.id, findings=[_THREAT])
        # The first hunt is history. Its clean answer must not close a lead
        # whose current hunt found a threat.
        assert await leads_store.settle_after_hunt(db, first) == "none"
        assert await leads_store.settle_after_hunt(db, second) == "waits"
        assert await leads_store.settle_after_hunt(db, second) == "waits"
        lead = await leads_store.get(db, lead.id)
        assert lead.status == "hunting"
        closed = await _lead_row(db, hunt_id="01ONCE")
        hunt = await _hunt_row(db, hunt_id="01ONCE", lead_id=closed.id, findings=[])
        assert await leads_store.settle_after_hunt(db, hunt) == "closed"
        assert await leads_store.settle_after_hunt(db, hunt) == "none"
        running = await _lead_row(db, hunt_id="01RUNS")
        hunt = await _hunt_row(db, hunt_id="01RUNS", lead_id=running.id, status="running")
        assert await leads_store.settle_after_hunt(db, hunt) == "none"


async def test_hunt_did_not_run_reads_the_status_and_the_could_not_run_finding(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead_row(db)
        error = await _hunt_row(db, hunt_id="01E", lead_id=lead.id, status="error")
        failed = await _hunt_row(db, hunt_id="01F", lead_id=lead.id, findings=[_GAP, _FAILED])
        clean = await _hunt_row(db, hunt_id="01C", lead_id=lead.id, findings=[])
        gap = await _hunt_row(db, hunt_id="01G", lead_id=lead.id, findings=[_GAP])
        running = await _hunt_row(db, hunt_id="01R", lead_id=lead.id, status="running")
    assert leads_store.hunt_did_not_run(error) is True
    assert leads_store.hunt_did_not_run(failed) is True
    assert leads_store.hunt_did_not_run(clean) is False
    assert leads_store.hunt_did_not_run(gap) is False
    assert leads_store.hunt_did_not_run(running) is False


async def test_settle_finished_hunts_settles_every_hunting_lead_with_a_terminal_hunt(
    settings_kratos: Settings,
) -> None:
    """The reconciliation: one call, every stuck lead, and a second call does nothing."""
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        clean = await _lead_row(db, hunt_id="01CLEAN")
        await _hunt_row(db, hunt_id="01CLEAN", lead_id=clean.id, findings=[])
        threat = await _lead_row(db, hunt_id="01THREAT")
        await _hunt_row(db, hunt_id="01THREAT", lead_id=threat.id, findings=[_THREAT])
        lost = await _lead_row(db, hunt_id="01LOST")
        await _hunt_row(db, hunt_id="01LOST", lead_id=lost.id, status="interrupted")
        running = await _lead_row(db, hunt_id="01RUNS")
        await _hunt_row(db, hunt_id="01RUNS", lead_id=running.id, status="running")
        assert await leads_store.settle_finished_hunts(db) == 2
        assert await leads_store.settle_finished_hunts(db) == 0
        rows = {
            lead.id: lead.status
            for lead in (await db.scalars(select(Lead).order_by(Lead.id))).all()
        }
    assert rows == {
        clean.id: "dismissed",
        threat.id: "hunting",
        lost.id: "open",
        running.id: "hunting",
    }


async def test_the_recorder_settles_the_lead_when_its_hunt_lands(
    settings_kratos: Settings,
) -> None:
    """The one call site. A hunt that lands clean closes its lead in the same breath."""
    from soc_ai.api.hunt_recorder import HuntRecorder

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
    recorder = HuntRecorder(
        maker, objective="o", started_by="auto-hunt", kind="lead", starter="lead", lead_id=lead.id
    )
    hunt_id = await recorder.start()
    assert hunt_id
    async with maker() as db:
        await leads_store.mark_hunting(db, lead.id, hunt_id=hunt_id)
    await recorder.record("hunt_report", 1, {"findings": [], "narrative": "Nothing notable."})
    await recorder.finish("complete")
    async with maker() as db:
        lead = await leads_store.get(db, lead.id)
        hunt = await db.get(Hunt, hunt_id)
    assert hunt.status == "complete"
    assert lead.status == "dismissed" and lead.dismissed_reason == "hunt_clean"
    assert lead.dismissed_by == "auto-hunt" and lead.hunt_id == hunt_id


async def test_the_recorder_returns_the_lead_to_open_when_the_hunt_errors(
    settings_kratos: Settings,
) -> None:
    from soc_ai.api.hunt_recorder import HuntRecorder

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead(db)
    recorder = HuntRecorder(
        maker, objective="o", started_by="auto-hunt", kind="lead", starter="lead", lead_id=lead.id
    )
    hunt_id = await recorder.start()
    async with maker() as db:
        await leads_store.mark_hunting(db, lead.id, hunt_id=hunt_id)
    recorder.note_failure(RuntimeError("gateway 502"))
    await recorder.finish("error")
    async with maker() as db:
        lead = await leads_store.get(db, lead.id)
    assert lead.status == "open" and lead.hunt_id == hunt_id
