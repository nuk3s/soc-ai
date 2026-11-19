"""The time by which a stage held (:mod:`soc_ai.campaigns.ladder`).

One test on 2026-11-17 read "Access" two weeks after "Action on the target".
The first investigation that proved the access itself was a late one. An
action on a target needs access to it, so the ladder states the earlier time.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from soc_ai.api.webui.routes_campaigns import _step_out
from soc_ai.campaigns import case as campaign_case
from soc_ai.campaigns.ladder import HeldBy, held_by
from soc_ai.campaigns.types import StageStep
from soc_ai.hunting import campaign_block
from soc_ai.hunting.campaign_block import CampaignFacts, _Machine

T0 = datetime(2026, 10, 24, 1, 11)
ACTION = T0 + timedelta(days=4, hours=21)
LATE = T0 + timedelta(days=19)


def test_an_action_before_the_first_proof_of_access_gives_the_earlier_time() -> None:
    out = held_by({"attempt": T0, "access": LATE, "action": ACTION})

    assert out == {"access": HeldBy(ACTION, "action")}


def test_access_with_no_proof_of_its_own_holds_by_the_action() -> None:
    assert held_by({"attempt": T0, "action": ACTION}) == {"access": HeldBy(ACTION, "action")}


def test_a_target_that_acts_also_proves_access() -> None:
    moved = ACTION - timedelta(hours=3)

    assert held_by({"access": LATE, "action": ACTION, "movement": moved}) == {
        "access": HeldBy(moved, "movement")
    }
    # The same time on both later stages names the lower one.
    assert held_by({"action": ACTION, "movement": ACTION}) == {"access": HeldBy(ACTION, "action")}


def test_a_stage_with_the_earliest_proof_of_its_own_keeps_it() -> None:
    # NEGATIVE CONTROL: the rule never moves a time later, and an equal time
    # is no earlier time.
    assert held_by({"access": T0, "action": ACTION}) == {}
    assert held_by({"access": ACTION, "action": ACTION}) == {}


def test_no_other_stage_takes_a_time_from_a_later_stage() -> None:
    # NEGATIVE CONTROL: an attempt needs no seen reconnaissance, and access
    # needs no seen attempt. Only access has a later stage that needs it.
    out = held_by({"reconnaissance": LATE, "attempt": LATE, "access": T0, "action": T0})

    assert out == {}
    assert held_by({}) == {}
    assert held_by({"access": LATE, "action": None}) == {}


def test_the_payload_of_a_stage_states_the_time_and_the_stage_that_gives_it() -> None:
    step = StageStep("access", True, LATE, 1, "inv-1")

    out = _step_out(step, {}, HeldBy(ACTION, "action"))

    assert out.firstAt is not None and out.firstAt.startswith("2026-11-12")
    assert out.heldBy is not None
    assert out.heldBy.stage == "action"
    assert out.heldBy.at.startswith("2026-10-28T22:11")
    assert _step_out(step, {}).heldBy is None


def test_the_campaign_block_of_a_hunt_states_the_earlier_time_with_by() -> None:
    facts = CampaignFacts(
        id=2,
        title="actor-a against web-1",
        stage="action",
        first_event=T0,
        last_event=LATE,
        machines=(
            _Machine(role="actor", key="ip:192.0.2.10", addresses=("192.0.2.10",)),
            _Machine(role="target", key="machine:web-1", name="web-1", addresses=("192.0.2.20",)),
        ),
        stages=(("attempt", T0), ("access", LATE), ("action", ACTION)),
    )

    text = campaign_block.render(facts)

    assert (
        "- Stages reached: Attempt at 2026-10-24 01:11 UTC; Access by 2026-10-28 22:11 UTC; "
        "Action on the target at 2026-10-28 22:11 UTC. The highest stage is Action on the target."
    ) in text
    assert "2026-11-12" not in text.split("- Period:")[0]


def test_the_case_text_states_the_earlier_time_with_by() -> None:
    text = campaign_case.case_description(
        campaign_id=2,
        bottom_line="actor-a acted on web-1.",
        stages=[
            campaign_case.StageLine("attempt", T0, "A probe."),
            campaign_case.StageLine("access", ACTION, "A file read.", by=True),
            campaign_case.StageLine("action", ACTION, "A command."),
        ],
        machines=[],
        first_event=T0,
        last_event=LATE,
        alerts=0,
        findings=0,
        note="",
        link="https://console.example.test/app/campaigns/2",
    )

    assert "- Attempt, 2026-10-24 01:11 UTC. A probe." in text
    assert "- Access, by 2026-10-28 22:11 UTC. A file read." in text
    assert "- Action on the target, 2026-10-28 22:11 UTC. A command." in text
