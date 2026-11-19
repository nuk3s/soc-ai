"""What is new in a campaign since the decision that a reopen ended (SD2).

:func:`since_decision.since_decisions` is the one reader. A campaign with a
decision in force and a campaign that never had a decision give no answer. A
campaign that opened again gives the earlier decision, the cause and the time
of the reopen, the boundary and the facts of the investigations with an event
after the boundary.

The data is synthetic: placeholder addresses, names and rule names. Each time
is relative to now.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from soc_ai.campaigns import decisions, service, since_decision
from soc_ai.config import Settings
from soc_ai.store import authorized_activity as aa
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, CampaignChange, Investigation
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_authorization import record as authorization_record
from tests.test_campaign_facts import RULE_B, TARGET_2, seed_hosts, seed_run


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _campaign(maker: async_sessionmaker[AsyncSession]) -> int:
    """One campaign of actor-a against web-1: three runs, 4, 3 and 2 hours ago."""
    async with maker() as db:
        await seed_hosts(db)
        for n in (1, 2, 3):
            await seed_run(db, f"alert-000{n}", event_hours_ago=5 - n, created_minutes_ago=50 - n)
        await service.rebuild(db)
    async with maker() as db:
        (row,) = (await db.scalars(select(Campaign))).all()
        return row.id


async def _close(maker: async_sessionmaker[AsyncSession], campaign_id: int, **over: Any) -> None:
    """Close the campaign as the close route does, with the basis of the stored row."""
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        row.decision = decisions.DECISION_CLOSED
        row.close_reason = "test_over"
        row.decision_note = "The red team ended the test."
        row.decided_by = "casey"
        row.decided_at = over.get("at") or utcnow()
        row.decision_basis = await decisions.basis_for(db, row)
        db.add(
            decisions.change(
                campaign_id,
                decisions.CHANGE_DECIDED,
                {"decision": "closed", "reason": "test_over", "by": "casey"},
                row.decided_at,
            )
        )
        await db.commit()


async def _since(
    maker: async_sessionmaker[AsyncSession], campaign_id: int
) -> since_decision.SinceDecision | None:
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        return await since_decision.since_decision(db, row)


async def _rebuild_with(maker: async_sessionmaker[AsyncSession], *runs: dict[str, Any]) -> None:
    async with maker() as db:
        for run in runs:
            await seed_run(db, **run)
        await service.rebuild(db)


# ── No answer ──────────────────────────────────────────────────────────────


async def test_a_campaign_that_never_had_a_decision_states_no_since(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _campaign(maker)
    await _rebuild_with(maker, {"alert_id": "alert-n", "event_hours_ago": 0.5})
    assert await _since(maker, campaign_id) is None


async def test_a_campaign_with_a_decision_in_force_states_none(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id)
    await _rebuild_with(maker, {"alert_id": "alert-n", "event_hours_ago": 0.5})
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        # The rebuild opened it again: close it again, and the answer goes.
        assert row.decision is None
    await _close(maker, campaign_id)
    assert await _since(maker, campaign_id) is None


async def test_an_authorized_campaign_does_not_open_again_by_activity(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _campaign(maker)
    now = utcnow()
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        decisions.write_authorize(
            db,
            row,
            authorization_id=1,
            label="Red team test",
            by="casey",
            basis=await decisions.basis_for(db, row),
            now=now,
        )
        await db.commit()
    await _rebuild_with(maker, {"alert_id": "alert-n", "event_hours_ago": 0.5})
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None and row.decision == "authorized"
        types = (
            await db.scalars(
                select(CampaignChange.type).where(CampaignChange.campaign_id == campaign_id)
            )
        ).all()
        assert "reopened" not in types
    assert await _since(maker, campaign_id) is None


# ── A reopen by the rebuild ────────────────────────────────────────────────


async def test_new_activity_states_the_earlier_close_and_the_new_investigations(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id)
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None and row.decision_basis is not None
        covered_at = row.decision_basis["last_event"]
    await _rebuild_with(
        maker,
        {"alert_id": "alert-n1", "event_hours_ago": 0.9, "created_minutes_ago": 5},
        {"alert_id": "alert-n2", "event_hours_ago": 0.5, "rule": RULE_B, "created_minutes_ago": 4},
    )
    since = await _since(maker, campaign_id)
    assert since is not None
    assert since.earlier.decision == "closed"
    assert (since.earlier.reason, since.earlier.label) == ("test_over", "Test that is over")
    assert (since.earlier.by, since.earlier.note, since.earlier.note_known) == (
        "casey",
        "The red team ended the test.",
        True,
    )
    assert since.cause == "activity"
    assert (since.boundary_source, since.boundary.isoformat()) == ("basis", covered_at)
    assert since.investigations == 2
    assert since.verdicts == (("true_positive", 2),)
    assert ([m.words for m in since.actors], [m.words for m in since.targets]) == (
        ["actor-a"],
        ["web-1"],
    )
    assert since.rules == 2
    assert since.first_event is not None and since.last_event is not None
    assert since.first_event < since.last_event
    assert (since.stage_before, since.stage_now, since.stage_rose) == ("attempt", "attempt", False)
    assert since.new_machines == ()
    assert since.authorized == 0


async def test_an_old_event_that_soc_ai_investigated_later_is_not_new(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The boundary reads the time of the event, never the time of the investigation."""
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id)
    async with maker() as db:
        # An event before the close, investigated a minute ago.
        old = await seed_run(db, "alert-old", event_hours_ago=2.5, created_minutes_ago=1)
        new = await seed_run(db, "alert-n", event_hours_ago=0.5, created_minutes_ago=2)
        await service.rebuild(db)
    since = await _since(maker, campaign_id)
    assert since is not None
    assert since.run_ids == (new,)
    assert old not in since.run_ids


async def test_a_higher_stage_and_a_new_machine_state_the_stage_and_the_machine(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id)
    await _rebuild_with(
        maker,
        {"alert_id": "alert-s", "event_hours_ago": 0.5, "report": {"stage": "access"}},
        {"alert_id": "alert-p", "dst": TARGET_2, "event_hours_ago": 0.4},
    )
    since = await _since(maker, campaign_id)
    assert since is not None
    assert since.cause == "stage"
    assert (since.stage_before, since.stage_now, since.stage_rose) == ("attempt", "access", True)
    assert since.stage == "access"
    assert since.new_machines == ("web-2",)
    assert sorted(m.words for m in since.targets) == ["web-1", "web-2"]


async def test_the_authorization_mark_count_reads_the_marks_that_hold(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id)
    async with maker() as db:
        marked = await seed_run(db, "alert-n1", event_hours_ago=0.9)
        await seed_run(db, "alert-n2", event_hours_ago=0.5)
        await service.rebuild(db)
    async with maker() as db:
        record = await authorization_record(db, campaign_id=campaign_id)
        inv = await db.get(Investigation, marked)
        assert inv is not None
        inv.authorization_id = record.id
        await db.commit()
    since = await _since(maker, campaign_id)
    assert since is not None and since.authorized == 1
    # A negative control: a revoked record holds nothing.
    async with maker() as db:
        await aa.revoke(db, record.id, by="casey", reason="The test ended.", now=utcnow())
    since = await _since(maker, campaign_id)
    assert since is not None and since.authorized == 0


# ── A reopen by the analyst, and a change of an earlier release ────────────


async def test_open_again_by_the_analyst_states_the_analyst_and_the_events_after_the_close(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id, at=utcnow() - timedelta(minutes=30))
    async with maker() as db:
        # An event after the last event of the basis: the rebuild keeps the
        # close only when it reads no later event, so add it after a reopen.
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        decisions.write_reopen(db, row, by="morgan", note="A new upload.", now=utcnow())
        await db.commit()
    await _rebuild_with(maker, {"alert_id": "alert-n", "event_hours_ago": 0.5})
    since = await _since(maker, campaign_id)
    assert since is not None
    assert (since.cause, since.reopened_by) == ("analyst", "morgan")
    assert since.earlier.by == "casey"
    assert since.investigations == 1


async def test_a_reopen_of_an_earlier_release_reads_the_newest_decided_change(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A stored ``reopened`` change with no ``was``: the note is unknown."""
    campaign_id = await _campaign(maker)
    decided_at = utcnow() - timedelta(hours=1, minutes=30)
    async with maker() as db:
        db.add_all(
            [
                # An older decision that an earlier reopen ended gives nothing.
                decisions.change(
                    campaign_id,
                    decisions.CHANGE_DECIDED,
                    {"decision": "closed", "reason": "accepted_risk", "by": "riley"},
                    decided_at - timedelta(hours=1),
                ),
                decisions.change(
                    campaign_id,
                    decisions.CHANGE_REOPENED,
                    {"cause": "analyst", "by": "riley"},
                    decided_at - timedelta(minutes=30),
                ),
                decisions.change(
                    campaign_id,
                    decisions.CHANGE_DECIDED,
                    {"decision": "closed", "reason": "test_over", "by": "casey"},
                    decided_at,
                ),
                decisions.change(
                    campaign_id, decisions.CHANGE_REOPENED, {"cause": "activity"}, utcnow()
                ),
            ]
        )
        await db.commit()
    since = await _since(maker, campaign_id)
    assert since is not None
    assert (since.earlier.decision, since.earlier.label, since.earlier.by) == (
        "closed",
        "Test that is over",
        "casey",
    )
    assert (since.earlier.note, since.earlier.note_known) == (None, False)
    assert (since.boundary_source, since.boundary) == ("decision", decided_at)
    # The runs of 2 hours ago are before the decision; none is new.
    assert since.investigations == 0
    assert (since.stage_before, since.stage_rose) == ("attempt", False)


async def test_a_batch_read_gives_one_answer_for_each_reopened_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id)
    await _rebuild_with(maker, {"alert_id": "alert-n", "event_hours_ago": 0.5})
    async with maker() as db:
        rows = list((await db.scalars(select(Campaign))).all())
        found = await since_decision.since_decisions(db, rows)
    assert list(found) == [campaign_id]
    assert found[campaign_id].investigations == 1


async def test_a_false_positive_on_the_pair_counts_in_the_verdicts(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Production, 2026-11-18: five true positives and one false positive after the close."""
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id)
    async with maker() as db:
        await seed_run(db, "alert-n", event_hours_ago=0.6, community_id="1:pair")
        await seed_run(
            db, "alert-f", event_hours_ago=0.5, verdict="false_positive", community_id="1:pair"
        )
        await service.rebuild(db)
    since = await _since(maker, campaign_id)
    assert since is not None
    assert since.verdicts == (("true_positive", 1), ("false_positive", 1))
    assert since.investigations == 2


async def test_the_true_positives_outside_the_authorization_are_counted_and_named(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """W1, round 3 part 2: the banner names what the authorization does not hold.

    Production, 2026-11-18: an authorization held 3 of 5 new true positives,
    and the analyst had to open a hunt finding to learn the other 2.
    """
    campaign_id = await _campaign(maker)
    await _close(maker, campaign_id)
    async with maker() as db:
        marked = await seed_run(db, "alert-n1", event_hours_ago=0.9)
        await seed_run(db, "alert-n2", event_hours_ago=0.8, rule=RULE_B)
        await seed_run(db, "alert-n3", event_hours_ago=0.7, rule=RULE_B)
        # A false positive that no mark holds is no true positive outside.
        await seed_run(db, "alert-f", event_hours_ago=0.6, verdict="false_positive")
        await service.rebuild(db)
    async with maker() as db:
        record = await authorization_record(db, campaign_id=campaign_id)
        inv = await db.get(Investigation, marked)
        assert inv is not None
        inv.authorization_id = record.id
        await db.commit()
    since = await _since(maker, campaign_id)
    assert since is not None
    assert (since.authorized, since.outside, since.outside_names) == (1, 2, (RULE_B,))
    (holding,) = since.holding
    assert (holding.id, holding.label, holding.state, holding.investigations) == (
        record.id,
        "Red team test",
        "active",
        1,
    )
    words = since_decision.authorization_sentence(since)
    assert words.startswith("The authorization Red team test holds 1. It expires ")
    assert words.endswith(f" It does not hold 2 true positives: {RULE_B}.")
    # A negative control: after a revoke no authorization holds, and the
    # line names no authorization.
    async with maker() as db:
        await aa.revoke(db, record.id, by="casey", reason="The test ended.", now=utcnow())
    since = await _since(maker, campaign_id)
    assert since is not None
    assert (since.authorized, since.outside, since.holding) == (0, 3, ())
    assert since_decision.authorization_sentence(since) == ""
