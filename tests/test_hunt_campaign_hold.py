"""A finding that restates a campaign gets no investigation of its own (H5, H7).

Prod, 2026-11-14: the scheduled hunt reported again a file read that a campaign
already held, and soc-ai investigated it again. A threat finding is now held
by a campaign when each host that it names is a machine of one active campaign
that the hunt read, it names two machines or the campaign has one target, it
cites stored documents that are not after the last event, and its stage is not
above the stage of the campaign. The entry reads the state ``campaign``.

The rule is strict on purpose. Every doubt goes to "investigate", and each
negative control below is a finding that must still get its investigation.

The data is synthetic: TEST-NET addresses and placeholder names.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting import campaign_hold, outcome
from soc_ai.hunting.campaign_hold import HoldCampaign, HoldParty
from soc_ai.hunting.finding_match import StoredDocument
from soc_ai.notify import event_for_hunt
from soc_ai.store import hunts as hunt_svc
from soc_ai.webui import hunt_findings

from tests.test_hunt_campaign_block import seed_campaign
from tests.test_hunt_findings_investigated import (
    FakeManager,
    _hunt,
    _investigating_hunt,
    _run_phase,
    _runs,
    _store,
)

ACTOR = "192.0.2.226"
TARGET = "192.0.2.164"
OUTSIDE = "198.51.100.77"
D1 = "docAAAAAAAAAAAAAAAA1"
D2 = "docAAAAAAAAAAAAAAAA2"
LAST = datetime(2026, 11, 14, 12, 0)

CAMPAIGN = HoldCampaign(
    id=7,
    title=f"{ACTOR} against web01",
    stage="action",
    last_event=LAST,
    parties=(
        HoldParty(key=f"ip:{ACTOR}", role="actor", addresses=(ACTOR,)),
        HoldParty(key="machine:web01", role="target", name="web01", addresses=(TARGET,)),
    ),
)
TWO_TARGETS = HoldCampaign(
    id=8,
    title="two targets",
    stage="action",
    last_event=LAST,
    parties=(
        HoldParty(key=f"ip:{ACTOR}", role="actor", addresses=(ACTOR,)),
        HoldParty(key="machine:web02", role="target", addresses=("192.0.2.30",)),
        HoldParty(key="machine:web03", role="target", addresses=("192.0.2.31",)),
    ),
)


def finding(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": "File read on web01",
        "detail": "The request read a file.",
        "severity": "high",
        "category": "threat",
        "hosts": [ACTOR, TARGET],
        "citations": [D1, D2],
        "stage": "action",
    }
    base.update(over)
    return base


def docs(at: datetime | None = LAST - timedelta(minutes=5)) -> dict[str, StoredDocument]:
    return {d: StoredDocument(key=d, at=at) for d in (D1, D2)}


def held(f: dict[str, Any], **over: Any) -> HoldCampaign | None:
    kwargs: dict[str, Any] = {
        "campaigns": [CAMPAIGN, TWO_TARGETS],
        "read": {7, 8},
        "documents": docs(),
    }
    kwargs.update(over)
    return campaign_hold.held_by(f, **kwargs)


# ── the rule ────────────────────────────────────────────────────────────────


def test_a_finding_that_restates_its_campaign_is_held() -> None:
    assert held(finding()) == CAMPAIGN
    # A name of the machine counts as the machine, and a lower stage too.
    assert held(finding(hosts=[ACTOR, "WEB01"], stage="access")) == CAMPAIGN
    # One host is enough when the campaign has one target.
    assert held(finding(hosts=[TARGET])) == CAMPAIGN


@pytest.mark.parametrize(
    ("why", "over"),
    [
        ("a machine outside the campaign", {"hosts": [ACTOR, TARGET, OUTSIDE]}),
        ("only a machine outside the campaign", {"hosts": [OUTSIDE]}),
        ("a cited address outside the campaign", {"citations": [D1, OUTSIDE]}),
        ("a stage above the reached stage", {"stage": "movement"}),
        ("no stage", {"stage": None}),
        ("a stage off the ladder", {"stage": "exfiltration"}),
        ("no cited document", {"citations": []}),
        ("only a tool citation", {"citations": ["t_query_events_oql:abc"]}),
        ("a document that the hunt did not store", {"citations": [D1, "docZZZZZZZZZZZZZZZZZ"]}),
        ("a user", {"users": ["admin"]}),
        ("no category of threat", {"category": "observation"}),
    ],
)
def test_every_doubt_goes_to_investigate(why: str, over: dict[str, Any]) -> None:
    assert held(finding(**over)) is None, why


def test_a_document_after_the_last_event_is_investigated() -> None:
    assert held(finding(), documents=docs(LAST + timedelta(seconds=1))) is None
    assert held(finding(), documents=docs(None)) is None
    assert held(finding(), documents=docs(LAST)) == CAMPAIGN


def test_one_host_of_a_campaign_with_two_targets_is_investigated() -> None:
    assert held(finding(hosts=["192.0.2.30"]), campaigns=[TWO_TARGETS]) is None
    assert held(finding(hosts=[ACTOR, "192.0.2.30"]), campaigns=[TWO_TARGETS]) == TWO_TARGETS


def test_a_finding_on_machines_of_two_campaigns_is_investigated() -> None:
    other = HoldCampaign(
        id=9, title="other", stage="action", last_event=LAST, parties=CAMPAIGN.parties
    )
    assert held(finding(), campaigns=[CAMPAIGN, other], read={7, 9}) is None


def test_a_campaign_that_the_hunt_did_not_read_holds_nothing() -> None:
    assert held(finding(), read={8}) is None
    assert held(finding(), read=set()) is None


def test_a_campaign_with_no_stage_holds_nothing() -> None:
    bare = HoldCampaign(id=7, title="t", stage=None, last_event=LAST, parties=CAMPAIGN.parties)
    assert held(finding(stage="reconnaissance"), campaigns=[bare], read={7}) is None


def test_the_hosts_data_joins_a_name_to_its_machine() -> None:
    assert held(finding(hosts=[ACTOR, "web01.example.test"])) is None
    machines = {"web01.example.test": "machine:web01"}
    assert held(finding(hosts=[ACTOR, "web01.example.test"]), machines=machines) == CAMPAIGN


# ── the phase of the hunt ───────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


async def _hunt_that_read(
    maker: Any,
    settings: Settings,
    findings: list[dict[str, Any]],
    *,
    campaign_id: int,
    at: datetime,
    lead_id: int | None = None,
    synth: bool = False,
) -> tuple[str, Any]:
    """A hunt in the state the recorder leaves it, that read the block of ``campaign_id``."""
    hunt_id, plan = await _investigating_hunt(maker, settings, findings, lead_id=lead_id)
    stamp = (at - timedelta(minutes=10)).isoformat() + "Z"
    hits = [{"_id": d, "_source": {"@timestamp": stamp}} for d in (D1, D2)]
    async with maker() as db:
        await hunt_svc.append_events(
            db,
            hunt_id,
            [
                {
                    "sequence": 1,
                    "kind": "hunt_started",
                    "payload": {"objective": "o", "campaign_ids": [campaign_id]},
                },
                {
                    "sequence": 2,
                    "kind": "tool_call",
                    "payload": {"tool_name": "t_query_events_oql", "args": {}, "tool_call_id": "c"},
                },
                {
                    "sequence": 3,
                    "kind": "tool_result",
                    "payload": {
                        "tool_name": "t_query_events_oql",
                        "tool_call_id": "c",
                        "result": {"hits": hits},
                    },
                },
            ],
        )
        row = await db.get(hunt_svc.Hunt, hunt_id)
        assert row is not None
        row.is_synth_eval = synth
        await db.commit()
    return hunt_id, plan


async def _campaign(maker: Any, at: datetime) -> int:
    return await seed_campaign(
        maker,
        last=at,
        stage="access",
        parties=[
            ("actor", f"ip:{ACTOR}", None, [ACTOR]),
            ("target", "machine:web01", "web01", [TARGET]),
        ],
    )


async def test_a_held_finding_links_to_its_campaign_and_starts_no_investigation(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    at = _now()
    campaign_id = await _campaign(maker, at)
    restating = finding(stage="access")
    new = finding(title="Shell on a new host", hosts=[TARGET, OUTSIDE], stage="action")
    hunt_id, plan = await _hunt_that_read(
        maker, settings_kratos, [restating, new], campaign_id=campaign_id, at=at
    )
    mgr = FakeManager(maker, verdicts={1: "true_positive"})

    verdicts = await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)

    links = hunt_svc.finding_links(await _hunt(maker, hunt_id))
    assert links[0].state == hunt_svc.LINK_CAMPAIGN
    assert links[0].campaign_id == campaign_id
    assert links[0].investigation_id is None
    assert links[0].reason == campaign_hold.HELD_REASON
    # Negative control: the finding with a machine outside the campaign is
    # investigated as today.
    assert links[1].state == hunt_svc.LINK_ENDED
    assert [r.finding_ordinal for r in await _runs(maker)] == [1]
    # The held finding is settled. It is no new threat finding of the hunt.
    assert verdicts is not None
    assert (verdicts.held, verdicts.total, verdicts.threats, verdicts.not_judged) == (1, 1, 1, 0)
    await engine.dispose()


async def test_a_hunt_whose_only_threat_is_held_reads_no_new_threat_and_wakes_no_one(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    at = _now()
    campaign_id = await _campaign(maker, at)
    findings = [finding(stage="attempt")]
    hunt_id, plan = await _hunt_that_read(
        maker, settings_kratos, findings, campaign_id=campaign_id, at=at
    )

    verdicts = await _run_phase(settings_kratos, maker, FakeManager(maker), hunt_id, plan)

    assert verdicts is not None
    assert (verdicts.held, verdicts.total, verdicts.threat_total, verdicts.not_judged) == (
        1, 0, 0, 0,
    )  # fmt: skip
    assert outcome.public_outcome("complete", findings, "n", verdicts) == "no_threat"
    on = settings_kratos.model_copy(update={"notify_on_hunt_threat": True})
    report = {"findings": findings, "narrative": "n"}
    assert event_for_hunt(hunt_id=hunt_id, report=report, settings=on, verdicts=verdicts) is None
    # Negative control: the same report with no held finding still wakes on-call.
    assert event_for_hunt(hunt_id=hunt_id, report=report, settings=on) is not None
    await engine.dispose()


@pytest.mark.parametrize("path", ["lead", "evaluation"])
async def test_a_lead_hunt_and_an_evaluation_hunt_are_never_held(
    settings_kratos: Settings, path: str
) -> None:
    engine, maker = await _store(settings_kratos)
    at = _now()
    campaign_id = await _campaign(maker, at)
    hunt_id, plan = await _hunt_that_read(
        maker,
        settings_kratos,
        [finding(stage="access")],
        campaign_id=campaign_id,
        at=at,
        lead_id=5 if path == "lead" else None,
        synth=path == "evaluation",
    )

    await _run_phase(settings_kratos, maker, FakeManager(maker), hunt_id, plan)

    links = hunt_svc.finding_links(await _hunt(maker, hunt_id))
    assert links[0].state != hunt_svc.LINK_CAMPAIGN
    assert [r.finding_ordinal for r in await _runs(maker)] == [0]
    await engine.dispose()


async def test_a_finding_of_a_hunt_that_read_no_campaign_block_is_investigated(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    at = _now()
    await _campaign(maker, at)
    hunt_id, plan = await _hunt_that_read(
        maker, settings_kratos, [finding(stage="access")], campaign_id=999, at=at
    )

    await _run_phase(settings_kratos, maker, FakeManager(maker), hunt_id, plan)

    assert [r.finding_ordinal for r in await _runs(maker)] == [0]
    await engine.dispose()


def test_a_stored_entry_names_its_campaign_and_counts_as_settled() -> None:
    raw = {
        "0": {"state": "campaign", "campaign_id": 4, "reason": "r"},
        "1": {"state": "campaign", "campaign_id": "4"},
        "2": {"state": "ended", "investigation_id": "inv-1"},
    }
    links = hunt_svc.finding_links_from(raw)

    assert links[0].held and links[0].campaign_id == 4
    # A stored id of another shape names no campaign.
    assert not links[1].held
    assert not links[2].held
    assert hunt_svc.LINK_CAMPAIGN in hunt_svc.LINK_ENDED_STATES
    assert hunt_findings.plan_campaign_holds is not None
