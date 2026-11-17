"""The rule prior holds back an alert on a machine of an open campaign (round prior-b, P2).

A campaign joins true positives of the same activity. A new alert on one of
its machines can be the next stage, and the prior must never give it the
noise of a rule as cover. Open means what the campaign page states:
``campaign_svc.api_status`` reads an active campaign with a last event inside
one horizon as open. The sweep reads the stored rows and never rebuilds.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

from soc_ai.config import Settings
from soc_ai.store import rule_prior as prior_store
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Campaign, CampaignParty

from tests.test_rule_prior import (
    DST,
    OUTSIDE,
    SRC,
    _decide,
    _seed_history,
    _settings,
    _store,
    _target,
)
from tests.test_rule_prior_external import _seed


async def _campaign(
    maker: Any,
    *,
    addresses: list[str],
    machine_key: str = "agent:web-1",
    status: str = "active",
    hours_ago: float = 2.0,
    decision: str | None = None,
) -> None:
    last = utcnow() - timedelta(hours=hours_ago)
    async with maker() as db:
        row = Campaign(
            status=status,
            seed_run_id="seed",
            title="actor-a against web-1",
            bottom_line="actor-a reached web-1.",
            stage="access",
            first_event=last - timedelta(hours=5),
            last_event=last,
            member_count=3,
            detail={},
            built_at=utcnow(),
            decision=decision,
        )
        db.add(row)
        await db.flush()
        db.add(
            CampaignParty(
                campaign_id=row.id,
                machine_key=machine_key,
                role="target",
                name="web-1",
                addresses=addresses,
                member_runs=3,
                beyond=False,
            )
        )
        await db.commit()


async def test_a_machine_of_an_open_campaign_is_not_covered(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    await _campaign(maker, addresses=[DST])
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "campaign_machine")


async def test_an_address_key_of_a_party_counts(settings_kratos: Settings) -> None:
    """A party that the Hosts data knows by its address alone has an ip: key."""
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    await _campaign(maker, addresses=[], machine_key=f"ip:{SRC}")
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "campaign_machine")


async def test_a_known_external_address_of_an_open_campaign_is_not_covered(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed(maker, external=[(SRC, OUTSIDE), (SRC, OUTSIDE)])
    before = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await _campaign(maker, addresses=[OUTSIDE], machine_key=f"ip:{OUTSIDE}")
    after = await _decide(maker, settings, _target(dst_ip=OUTSIDE))
    await engine.dispose()
    # The control: with no campaign the external address is known.
    assert (before.applies, before.reason) == (True, "covered_known_external")
    assert (after.applies, after.reason) == (False, "campaign_machine")


async def test_an_ended_withdrawn_or_merged_campaign_does_not_hold(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    # Last event 10 days ago: more than one horizon, so the page reads it as ended.
    await _campaign(maker, addresses=[DST], hours_ago=24 * 10)
    await _campaign(maker, addresses=[DST], status="withdrawn")
    await _campaign(maker, addresses=[SRC], status="merged")
    # An open campaign of another machine.
    await _campaign(maker, addresses=["192.0.2.99"])
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (True, "covered")


async def test_a_closed_campaign_holds_no_machine(settings_kratos: Settings) -> None:
    """The analyst closed the campaign: its activity is over. Its machines
    then read the other safeguards as any machine does."""
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    await _campaign(maker, addresses=[DST], decision="closed")
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (True, "covered")


async def test_an_authorized_campaign_still_holds_its_machines(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    await _campaign(maker, addresses=[DST], decision="authorized")
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "campaign_machine")


async def test_a_campaign_read_error_fails_closed(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)

    async def broken(*_a: Any, **_kw: Any) -> bool:
        raise RuntimeError("the campaign tables are locked")

    with patch.object(prior_store, "in_open_campaign", broken):
        decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "evaluation_failed")


async def test_a_bad_party_address_is_skipped(settings_kratos: Settings) -> None:
    """A party row with a broken address list holds nothing, and breaks nothing."""
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    await _campaign(maker, addresses=["not-an-address", None, 7])  # type: ignore[list-item]
    async with maker() as db:
        held = await prior_store.in_open_campaign(db, (SRC, DST), now=utcnow())
    await engine.dispose()
    assert held is False
