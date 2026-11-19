"""The surfaces of what is new since the earlier decision (SD3).

The campaign payload and each row of ``GET /campaigns`` carry
``sinceDecision``. The Needs you item of a reopened campaign states the reopen
and the earlier decision in ``why`` and the new facts in ``newFacts``, with
the machines of the new investigations first. A campaign that never had a
decision keeps "The campaign has no decision." The words of the server are
the words of the console
(``frontend/src/components/campaign/SinceDecision.test.tsx`` holds the same lines).

The data is synthetic: placeholder addresses, names and rule names. Each
stored time is relative to now. No test calls a real grid.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui import needs_you_facts as ny_facts
from soc_ai.campaigns import since_decision as since_svc
from soc_ai.config import Settings
from soc_ai.main import create_app

from tests.test_campaign_facts import seed_hosts, seed_run

# ── The words of the server ────────────────────────────────────────────────

_CLOSED = since_svc.EarlierDecision(
    decision="closed",
    reason="test_over",
    label="Test that is over",
    by="casey",
    at=datetime(2026, 11, 15, 1, 1, 12),
)


def _since(**over: Any) -> since_svc.SinceDecision:
    """The production example of 2026-11-18, with placeholder names."""
    fields: dict[str, Any] = {
        "campaign_id": 2,
        "earlier": _CLOSED,
        "cause": "activity",
        "reopened_at": datetime(2026, 11, 18, 13, 2, 28),
        "reopened_by": None,
        "boundary": datetime(2026, 11, 15, 1, 1, 12),
        "boundary_source": "decision",
        "run_ids": ("r1", "r2", "r3", "r4", "r5", "r6"),
        "verdicts": (("true_positive", 5), ("false_positive", 1)),
        "authorized": 3,
        "actors": (since_svc.Machine("agent:a1", "actor-a", "192.0.2.10"),),
        "targets": (since_svc.Machine("ip:t1", None, "198.51.100.20"),),
        "first_event": datetime(2026, 11, 18, 12, 55, 10),
        "last_event": datetime(2026, 11, 18, 13, 12, 17),
        "stage": "attempt",
        "stage_before": "action",
        "stage_now": "action",
    }
    fields.update(over)
    return since_svc.SinceDecision(**fields)


def test_the_why_states_the_reopen_and_the_earlier_close() -> None:
    assert since_svc.why(_since()) == (
        "Opened again on 2026-11-18 13:02 UTC by new activity. "
        "casey closed it on 2026-11-15: Test that is over."
    )


@pytest.mark.parametrize(
    ("over", "reopen"),
    [
        ({"cause": "stage"}, "by a higher stage."),
        ({"cause": "party"}, "by a new machine."),
        ({"cause": "analyst", "reopened_by": "morgan"}, "by morgan."),
        ({"cause": "revoked", "reopened_by": "morgan"}, "by a revoke of the authorization."),
    ],
)
def test_the_reopen_words_follow_the_cause(over: dict[str, Any], reopen: str) -> None:
    assert (
        since_svc.reopened_sentence(_since(**over))
        == f"Opened again on 2026-11-18 13:02 UTC {reopen}"
    )


@pytest.mark.parametrize(
    ("earlier", "words"),
    [
        (
            since_svc.EarlierDecision(
                "authorized", label="Red team test", by="casey", at=_CLOSED.at
            ),
            "casey authorized it on 2026-11-15: Red team test.",
        ),
        (
            since_svc.EarlierDecision("case", by="casey", at=_CLOSED.at),
            "casey opened a case for it on 2026-11-15.",
        ),
        (
            since_svc.EarlierDecision("closed", at=_CLOSED.at),
            "The analyst closed it on 2026-11-15.",
        ),
    ],
)
def test_the_earlier_words_follow_the_decision(
    earlier: since_svc.EarlierDecision, words: str
) -> None:
    assert since_svc.earlier_sentence(_since(earlier=earlier)) == words


def test_the_new_facts_state_the_verdicts_the_actor_the_span_and_the_marks() -> None:
    assert since_svc.new_facts_sentence(_since()) == (
        "New: 5 true positive investigations and 1 false positive from actor-a, "
        "2026-11-18 12:55 to 13:12 UTC. An authorization holds 3."
    )
    risen = _since(stage_before="attempt", stage_now="access", new_machines=("web-2",))
    assert since_svc.new_facts_sentence(risen).endswith(
        "The stage rose from Attempt to Access. New machine: web-2."
    )


_HOLDING = since_svc.Holding(7, "Red team test", "active", datetime(2026, 11, 20, 22, 9), 3)


def test_the_authorization_words_name_the_true_positives_outside_it() -> None:
    """W1: "An authorization holds 3. It does not hold 2 true positives: {rule names}."."""
    outside = {
        "outside": 2,
        "outside_names": ("ET RULE A", "Unlisted rules"),
        "holding": (_HOLDING,),
    }
    # After a close, an authorization in force states its name and its end.
    assert since_svc.authorization_sentence(_since(**outside)) == (
        "The authorization Red team test holds 3. It expires 2026-11-20 22:09 UTC. "
        "It does not hold 2 true positives: ET RULE A and Unlisted rules."
    )
    assert since_svc.new_facts_sentence(_since(**outside)).endswith(
        "13:12 UTC. The authorization Red team test holds 3. It expires 2026-11-20 22:09 UTC. "
        "It does not hold 2 true positives: ET RULE A and Unlisted rules."
    )
    # After an authorization the earlier sentence names it, so this line does not.
    authorized = since_svc.EarlierDecision("authorized", label="Red team test", at=_CLOSED.at)
    assert since_svc.authorization_sentence(_since(earlier=authorized, **outside)) == (
        "An authorization holds 3. It does not hold 2 true positives: ET RULE A and Unlisted rules."
    )
    # An authorization that is not in force is not named.
    expired = since_svc.Holding(7, "Red team test", "expired", datetime(2026, 11, 16), 3)
    assert since_svc.authorization_sentence(
        _since(outside=1, outside_names=("ET RULE A",), holding=(expired,))
    ) == ("An authorization holds 3. It does not hold 1 true positive: ET RULE A.")
    # Two authorizations: no "It".
    two = (_HOLDING, since_svc.Holding(8, "Scan window", "active", datetime(2026, 11, 21), 1))
    assert since_svc.authorization_sentence(
        _since(authorized=4, outside=1, outside_names=("ET RULE A",), holding=two)
    ).endswith("No authorization holds 1 true positive: ET RULE A.")
    # More than five names: a count states the rest. No name is cut.
    many = tuple(f"rule-{n}" for n in range(7))
    assert since_svc.authorization_sentence(
        _since(outside=7, outside_names=many, holding=(_HOLDING,))
    ).endswith("7 true positives: rule-0, rule-1, rule-2, rule-3, rule-4 and 2 more.")
    # A negative control: with no mark that holds, the line names no authorization.
    assert since_svc.authorization_sentence(_since(authorized=0, outside=5)) == ""
    assert since_svc.authorization_sentence(_since()) == "An authorization holds 3."


def test_no_new_investigation_states_the_boundary() -> None:
    nothing = _since(run_ids=(), verdicts=(), authorized=0, actors=(), targets=())
    assert since_svc.new_facts_sentence(nothing) == (
        "No investigation of the campaign has an event after 2026-11-15 01:01 UTC."
    )
    assert since_svc.count_words(nothing) == "0 new investigations since the close of 2026-11-15."


def test_the_count_line_states_the_split_and_the_authorization() -> None:
    """W3: the Confirmed threats row and the bell read "6 new investigations" with no split."""
    assert since_svc.split_words(_since()) == "5 true positives and 1 false positive"
    assert since_svc.count_split_words(_since()) == (
        "6 new investigations since the close of 2026-11-15: "
        "5 true positives and 1 false positive. An authorization holds 3."
    )
    outside = _since(outside=2, outside_names=("ET RULE A",), holding=(_HOLDING,))
    assert since_svc.count_split_words(outside).endswith(
        "It does not hold 2 true positives: ET RULE A."
    )
    # A negative control: with no new investigation the line states no split.
    nothing = _since(run_ids=(), verdicts=(), authorized=0)
    assert since_svc.count_split_words(nothing) == (
        "0 new investigations since the close of 2026-11-15."
    )


def test_the_stage_and_the_count_words() -> None:
    assert since_svc.stage_sentence(_since()) == "The stage did not change."
    assert since_svc.count_words(_since()) == "6 new investigations since the close of 2026-11-15."
    window = since_svc.window(datetime(2026, 11, 17, 22, 0), datetime(2026, 11, 18, 1, 0))
    assert window == "2026-11-17 22:00 to 2026-11-18 01:00 UTC"


# ── The routes ─────────────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _seed(client: TestClient, alert_id: str, **over: Any) -> str:
    async def work(db: Any) -> str:
        return await seed_run(db, alert_id, **over)

    run_id: str = _do(client, work)
    return run_id


def _campaign(client: TestClient) -> int:
    _do(client, seed_hosts)
    for n in (1, 2):
        _seed(client, f"alert-000{n}", event_hours_ago=4 - n)
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    return int(row["id"])


def _close(client: TestClient, campaign_id: int) -> None:
    res = client.post(f"/api/v1/campaigns/{campaign_id}/close", json={"reason": "test_over"})
    assert res.status_code == 200, res.text


def _item(client: TestClient, campaign_id: int) -> dict[str, Any] | None:
    items = client.get("/api/v1/needs-you/items").json()["items"]
    found = [i for i in items if i["type"] == "campaign" and i["id"] == str(campaign_id)]
    return found[0] if found else None


def test_a_campaign_that_never_had_a_decision_keeps_its_words(client: TestClient) -> None:
    campaign_id = _campaign(client)
    assert client.get(f"/api/v1/campaigns/{campaign_id}").json()["sinceDecision"] is None
    item = _item(client, campaign_id)
    assert item is not None
    assert (item["why"], item["newFacts"]) == (ny_facts.CAMPAIGN_WHY, None)


def test_a_closed_campaign_states_no_since_and_is_no_item(client: TestClient) -> None:
    campaign_id = _campaign(client)
    _close(client, campaign_id)
    assert client.get(f"/api/v1/campaigns/{campaign_id}").json()["sinceDecision"] is None
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    assert row["sinceDecision"] is None
    assert _item(client, campaign_id) is None


def test_new_activity_states_the_earlier_close_and_the_new_facts_on_each_surface(
    client: TestClient,
) -> None:
    campaign_id = _campaign(client)
    _close(client, campaign_id)
    new = _seed(client, "alert-n", event_hours_ago=0.5)
    payload = client.get(f"/api/v1/campaigns/{campaign_id}").json()
    since = payload["sinceDecision"]
    assert since["earlier"]["decision"] == "closed"
    assert (since["earlier"]["label"], since["earlier"]["by"]) == ("Test that is over", "anonymous")
    assert (since["cause"], since["boundarySource"]) == ("activity", "basis")
    # The count of the new investigations equals the list that the console opens.
    assert since["runIds"] == [new]
    assert since["investigations"] == len(since["runIds"]) == 1
    assert since["verdicts"] == [{"verdict": "true_positive", "count": 1}]
    assert [m["name"] for m in since["actors"]] == ["actor-a"]
    assert (since["stageRose"], since["newMachines"]) == (False, [])
    # The row of the list carries the same answer.
    (row,) = client.get("/api/v1/campaigns").json()["rows"]
    assert row["sinceDecision"]["runIds"] == [new]

    item = _item(client, campaign_id)
    assert item is not None
    assert item["why"].startswith("Opened again on ")
    assert item["why"].endswith(
        " by new activity. anonymous closed it on "
        + since["earlier"]["at"][:10]
        + ": Test that is over."
    )
    assert item["newFacts"].startswith("New: 1 true positive investigation from actor-a, ")
    # The machines of the new investigations come first: the actor, then the target.
    assert [m["name"] for m in item["machines"]] == ["actor-a", "web-1"]


def test_open_again_by_the_analyst_states_the_analyst_and_no_new_event(client: TestClient) -> None:
    campaign_id = _campaign(client)
    _close(client, campaign_id)
    res = client.post(f"/api/v1/campaigns/{campaign_id}/reopen", json={"note": "Check again."})
    assert res.status_code == 200, res.text
    since = res.json()["sinceDecision"]
    assert (since["cause"], since["reopenedBy"]) == ("analyst", "anonymous")
    assert since["investigations"] == 0
    item = _item(client, campaign_id)
    assert item is not None
    assert " by anonymous. anonymous closed it on " in item["why"]
    assert item["newFacts"].startswith("No investigation of the campaign has an event after ")
    # A new event after the close is new, also after an open again by the analyst.
    new = _seed(client, "alert-n", event_hours_ago=0.5)
    since = client.get(f"/api/v1/campaigns/{campaign_id}").json()["sinceDecision"]
    assert (since["cause"], since["runIds"]) == ("analyst", [new])


def test_the_banner_links_the_hunt_that_the_reopen_started(client: TestClient) -> None:
    """W1: the campaign payload names the hunt of the reopen with the words of the hunt page."""
    from tests.test_hunt_answers import seed_hunt

    campaign_id = _campaign(client)
    _close(client, campaign_id)
    _seed(client, "alert-n", event_hours_ago=0.5)
    since = client.get(f"/api/v1/campaigns/{campaign_id}").json()["sinceDecision"]
    assert since["cause"] == "activity"
    assert since["reopenHunt"] is None

    async def hunts(db: Any) -> None:
        # A negative control: a campaign hunt before the reopen is no hunt of the reopen.
        await seed_hunt(
            db,
            "01HUNTBEFORE0000000000000A",
            findings=[],
            hours_ago=5,
            kind="campaign",
            starter="campaign",
            campaign_id=campaign_id,
        )
        await seed_hunt(
            db,
            "01HUNTREOPEN0000000000000B",
            findings=[],
            hours_ago=-0.01,
            status="running",
            kind="campaign",
            starter="campaign",
            campaign_id=campaign_id,
        )
        await db.commit()

    _do(client, hunts)
    since = client.get(f"/api/v1/campaigns/{campaign_id}").json()["sinceDecision"]
    hunt = since["reopenHunt"]
    assert (hunt["id"], hunt["status"], hunt["outcome"]) == (
        "01HUNTREOPEN0000000000000B",
        "running",
        None,
    )
    assert since["outsideTruePositives"] == 1
    assert since["outsideNames"] and since["authorizations"] == []
