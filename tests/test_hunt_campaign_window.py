"""The window block and the campaign blocks state each record one time (H4).

A true positive, a finding or a lead that a campaign block states leaves the
three lists of the window block, so the hunt reads it one time. The all-clear
gate still reads it: the window keeps every true positive in ``confirmed``,
and a hunt with no window reads the true positives of its campaign blocks. The
authorized block keeps a campaign record only when no campaign block states
that campaign.

The data is synthetic: TEST-NET addresses and placeholder names. Times are
relative to now.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

from soc_ai.campaigns import lead_tags
from soc_ai.config import Settings
from soc_ai.hunting import authorized, campaign_block, earlier
from soc_ai.hunting.campaign_block import CampaignBlocks
from soc_ai.store import authorized_activity as aa
from soc_ai.store.models import EntityObservation

from tests.test_hunt_campaign_block import (
    ACTOR,
    OTHER,
    TARGET,
    _Guard,
    alert_run,
    drive,
    now,
    seed_campaign,
    store,
)
from tests.test_hunt_window_block import _f, _finding_run, _hunt, _lead

_OBJECTIVE = "Hunt for malicious activity over the past 72 hours."
_CAMPAIGN_RULE = "ET EXPLOIT php2shell remote code execution attempt"
_OTHER_RULE = "ET SCAN Nmap sweep of an internal host"
_ALL_CLEAR = "No malicious cyber activity in the 72 hours ending now."


async def _covered(maker: Any, at: Any) -> CampaignBlocks:
    blocks = await campaign_block.blocks_for_hunt(
        maker, scope=campaign_block.EVERY_CAMPAIGN, hours=72, now=at
    )
    return CampaignBlocks(kept=blocks)


async def test_a_true_positive_of_a_campaign_leaves_the_window_and_stays_in_the_gate(
    settings_kratos: Settings,
) -> None:
    engine, maker = await store(settings_kratos)
    at = now()
    held = await alert_run(maker, "alert-held", at=at - timedelta(hours=1), rule=_CAMPAIGN_RULE)
    await alert_run(
        maker, "alert-free", at=at - timedelta(hours=2), rule=_OTHER_RULE, src=OTHER, dest=OTHER
    )
    await seed_campaign(maker, last=at - timedelta(hours=1), members=[(held, at)])

    plain = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=at)
    blocks = await _covered(maker, at)
    window = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=at, covered=blocks.covered)

    assert plain is not None and window is not None
    assert _CAMPAIGN_RULE in plain.text
    # The campaign block states it, so the window does not list it again.
    assert _CAMPAIGN_RULE not in window.text
    assert _OTHER_RULE in window.text
    assert held not in window.refs.get("investigations", [])
    # The gate reads both true positives, as before the campaign block.
    assert [c.rule for c in window.confirmed] == [c.rule for c in plain.confirmed]
    assert {c.rule for c in window.confirmed} == {_CAMPAIGN_RULE, _OTHER_RULE}
    await engine.dispose()


async def test_a_finding_and_a_lead_of_a_campaign_leave_the_window(
    settings_kratos: Settings,
) -> None:
    engine, maker = await store(settings_kratos)
    at = now()
    run = await _finding_run(maker, title="Shell on web01", verdict="true_positive", confidence=0.9)
    await _hunt(
        maker,
        at=at - timedelta(hours=3),
        findings=[_f("Shell on web01", hosts=[TARGET])],
        runs={0: run},
        objective="Other objective",
        kind="chat",
        starter="analyst",
    )
    alert = await alert_run(maker, "alert-of-lead", at=at - timedelta(hours=1))
    tagged = await _lead(maker, TARGET, at=at - timedelta(minutes=30), summaries=())
    loose = await _lead(maker, ACTOR, at=at - timedelta(minutes=20), summaries=())
    async with maker() as db:
        db.add(
            EntityObservation(
                entity_kind="host", entity_key=TARGET, kind="alert", spec_id="alert",
                fingerprint="alert-of-lead", summary="x", lead_id=tagged,
            )
        )  # fmt: skip
        # Negative control: a lead with a statistics observation on a machine
        # of the campaign is no lead of the campaign. It stays in the window.
        db.add(
            EntityObservation(
                entity_kind="host", entity_key=ACTOR, kind="profile_departure",
                spec_id="profile", fingerprint="stat-1", summary="rare peer", lead_id=loose,
            )
        )  # fmt: skip
        await db.commit()
    await seed_campaign(maker, last=at, members=[(run, at - timedelta(hours=3)), (alert, at)])
    # The step after a rebuild stores the campaign of a lead. The hunt block
    # reads that stored fact, so the leads lane and the hunt agree.
    async with maker() as db:
        await lead_tags.tag(db, now=at)

    blocks = await _covered(maker, at)
    window = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=at, covered=blocks.covered)

    assert blocks.covered.lead_ids == frozenset({tagged})
    assert window is not None
    assert "Shell on web01" not in window.text
    assert str(tagged) not in window.refs.get("leads", [])
    assert str(loose) in window.refs.get("leads", [])
    # The finding stays a true positive of the gate.
    assert any("Shell on web01" in c.phrase for c in window.confirmed)
    await engine.dispose()


async def test_the_gate_refuses_an_all_clear_over_a_true_positive_of_a_campaign(
    settings_kratos: Settings,
) -> None:
    """Negative control: the line leaves the window block. The gate still reads it."""
    engine, maker = await store(settings_kratos)
    at = now()
    held = await alert_run(maker, "alert-held", at=at - timedelta(hours=1), rule=_CAMPAIGN_RULE)
    await seed_campaign(maker, last=at - timedelta(hours=1), members=[(held, at)])
    window = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=at)

    seen = await drive(settings_kratos, maker, narrative=_ALL_CLEAR, earlier=window)

    # The window lists the true positive no more, and the hunt read it in the
    # campaign block.
    assert _CAMPAIGN_RULE not in seen["user_msg"]
    assert campaign_block.CAMPAIGN_HEADER in seen["user_msg"]
    narrative = seen["report"].payload["narrative"]
    assert narrative.startswith(f"**{earlier.ALL_CLEAR_LABEL}.**")
    assert _CAMPAIGN_RULE in narrative
    await engine.dispose()


async def test_an_analyst_hunt_is_held_to_the_true_positives_of_its_campaign_blocks(
    settings_kratos: Settings,
) -> None:
    engine, maker = await store(settings_kratos)
    at = now()
    held = await alert_run(maker, "alert-held", at=at - timedelta(hours=1), rule=_CAMPAIGN_RULE)
    await seed_campaign(maker, last=at - timedelta(hours=1), members=[(held, at)])

    clear = await drive(settings_kratos, maker, narrative=_ALL_CLEAR)
    named = await drive(
        settings_kratos, maker, narrative=f"The campaign against {TARGET} shows no new event."
    )

    assert clear["report"].payload["narrative"].startswith(f"**{earlier.ALL_CLEAR_LABEL}.**")
    # A report that names the target of the campaign gets no line.
    assert not named["report"].payload["narrative"].startswith("**")
    await engine.dispose()


async def test_a_dropped_campaign_block_leaves_its_records_in_the_window(
    settings_kratos: Settings,
) -> None:
    engine, maker = await store(settings_kratos)
    at = now()
    held = await alert_run(maker, "alert-held", at=at - timedelta(hours=1), rule=_CAMPAIGN_RULE)
    await seed_campaign(
        maker,
        last=at - timedelta(hours=1),
        members=[(held, at)],
        parties=[("target", "machine:web01", "SECRET-NAME", [TARGET])],
        title="SECRET-NAME campaign",
    )
    window = await earlier.earlier_for_objective(maker, _OBJECTIVE, now=at)
    settings = settings_kratos.model_copy(
        update={"analyst_cloud_redaction": True, "analyst_redaction_fail_closed": True}
    )

    seen = await drive(settings, maker, guard=_Guard("SECRET-NAME"), earlier=window)

    assert campaign_block.CAMPAIGN_HEADER not in seen["user_msg"]
    # The hunt reads the true positive in the window block, as before.
    assert _CAMPAIGN_RULE in seen["user_msg"]
    await engine.dispose()


def _record(scope_id: int, campaign_id: int | None) -> aa.Scope:
    start = now() - timedelta(days=1)
    return aa.Scope(
        id=scope_id,
        label=f"Test {scope_id}",
        sources=(),
        target=aa.ScopeEntry(""),
        rule_names=(),
        rule_class="",
        starts_at=start,
        expires_at=start + timedelta(days=7),
        campaign_id=campaign_id,
        parties=(aa.PartyEntry("ip:t1", "target", "web-1", (TARGET,)),),
    )


async def test_the_authorized_block_keeps_a_campaign_record_only_when_no_block_states_it() -> None:
    scopes = [_record(1, 9), _record(2, 10), _record(3, None)]

    @asynccontextmanager
    async def maker() -> AsyncIterator[object]:
        yield object()

    with patch.object(aa, "in_force", AsyncMock(return_value=scopes)):
        block = await authorized.block_for_hunt(maker, skip_campaigns=[9])
        every = await authorized.block_for_hunt(maker)

    assert block is not None and every is not None
    assert set(block.ids) == {2, 3}
    assert set(every.ids) == {1, 2, 3}
