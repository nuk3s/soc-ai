"""The demo holds the data of the rule decision (round 3).

The demo seeds ``soc_ai/demo/fixtures.json``. The page of a rule and the fold
"Standing rule decisions" need data there: one rule with open false
positives in both groups, one rule with an open false positive that also
holds a true positive, and one standing decision in force. The selection
reads the seeded store as the demo does, with no grid read yet.
"""

from __future__ import annotations

import pytest
from soc_ai.config import Settings
from soc_ai.demo.fixtures import load_fixtures, seed_fixtures
from soc_ai.store import rule_decisions as rd_store
from soc_ai.store.auth import utcnow
from soc_ai.webui import rule_decisions as rd

from tests.test_rule_decision_selection import maker_for

DROPBOX = "ET POLICY Dropbox.com Offsite File Backup in Use"
BEACON = "ET HUNTING Periodic Outbound HTTPS Connection Possible Beacon"
IPIFY = "ET INFO External IP Lookup Domain (ipify .org) in DNS Lookup"


@pytest.mark.asyncio
async def test_the_demo_seeds_two_rules_and_a_standing_decision(settings_kratos: Settings) -> None:
    maker = await maker_for(settings_kratos)
    await seed_fixtures(maker, load_fixtures())

    async with maker() as db:
        rules = rd.by_rule(
            await rd.open_false_positives(db, threshold=settings_kratos.auto_ack_fp_threshold)
        )
        beacon_tps = await rd_store.standing_true_positives(db, BEACON)
        standing = await rd_store.in_force(db, IPIFY, now=utcnow())

    dropbox = rules[DROPBOX]
    assert sorted(r.group for r in dropbox) == ["confident", "confident", "weak"]
    assert {r.reason for r in dropbox} == {"high_stakes", "auto_ack_off", "below_threshold"}
    assert len(rules[BEACON]) == 1
    assert beacon_tps, "the beacon rule holds a true positive"
    assert standing is not None and standing.acknowledged == 4
