"""The confirmed threats that wait and the decided campaigns (DC2, DC3, round "decide once").

On production the Dashboard at 7 days read "12 true positives on 0 hosts",
and its link opened 14 rows. Each of the 12 was in a campaign that the
analyst had closed, and 2 of the 14 were superseded. The closed campaign
stayed in the red list of the Confirmed threats panel.

One rule gives the true positives that wait
(:mod:`soc_ai.campaigns.threat_parts`). The panel, the Dashboard tile and the
Investigations list that the tile opens read it.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from fastapi.testclient import TestClient
from soc_ai.campaigns import decisions
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Campaign

from tests.test_threats_api import (  # noqa: F401
    OTHER,
    _do,
    _seed_authorization,
    _seed_campaign,
    _seed_hosts,
    _seed_run,
    _threats,
    client,
)


def _decide(
    client: TestClient,  # noqa: F811
    campaign_id: int,
    decision: str | None,
    *,
    authorization: int | None = None,
) -> None:
    """Write a decision on a campaign as the decision routes write it, or clear it."""

    async def work(db: Any) -> None:
        row = await db.get(Campaign, campaign_id)
        if decision is None:
            decisions.write_reopen(db, row, by="analyst", note="", now=utcnow())
        else:
            row.decision = decision
            row.decided_by = "analyst"
            row.decided_at = utcnow()
            row.decision_basis = {}
            row.authorization_id = authorization
        await db.commit()

    _do(client, work)


def _list(client: TestClient, href: str, **extra: str) -> dict[str, Any]:  # noqa: F811
    """GET the Investigations list that a console link names."""
    query = {k: v[0] for k, v in parse_qs(urlparse(href).query).items()}
    params = {"verdict": query["verdict"], "since": query["from"], "until": query["to"]}
    if "waits" in query:
        params["waits"] = query["waits"]
    params.update(extra)
    res = client.get("/api/v1/investigations", params=params)
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_a_closed_campaign_leaves_the_red_list_and_the_decided_line_counts_it(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    first = _seed_run(client, "d-1", minutes_ago=10)
    second = _seed_run(client, "d-2", minutes_ago=20)
    alone = _seed_run(client, "x-1", dst=OTHER, minutes_ago=30)
    campaign = _seed_campaign(client, [first, second])
    _decide(client, campaign, "closed")

    body = _threats(client)

    assert body["campaigns"] == []
    assert body["decided"] == {"campaigns": 1, "investigations": 2}
    assert [r["newestInvestigationId"] for r in body["rows"]] == [alone]
    assert (body["waiting"], body["waitingHosts"]) == (1, 1)
    # ``total`` still counts every true positive that stands.
    assert body["total"] == 3
    # The link of the tile opens exactly the counted runs.
    listed = _list(client, body["waitingHref"])
    assert [r["id"] for r in listed["rows"]] == [alone]
    assert listed["total"] == body["waiting"]


@pytest.mark.parametrize("decision", ["closed", "case"])
def test_each_decision_in_force_takes_the_campaign_out(
    client: TestClient,  # noqa: F811
    decision: str,
) -> None:
    _seed_hosts(client)
    run = _seed_run(client, "d-1", minutes_ago=10)
    _decide(client, _seed_campaign(client, [run]), decision)
    body = _threats(client)
    assert (body["campaigns"], body["waiting"], body["waitingHosts"]) == ([], 0, 0)
    assert body["decided"] == {"campaigns": 1, "investigations": 1}


def test_a_campaign_with_no_decision_stays_in_the_red_list_and_its_machines_count(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: no decision, no exit from the list."""
    _seed_hosts(client)
    first = _seed_run(client, "d-1", minutes_ago=10)
    second = _seed_run(client, "d-2", minutes_ago=20)
    _seed_run(client, "x-1", dst=OTHER, minutes_ago=30)
    campaign = _seed_campaign(client, [first, second])

    body = _threats(client)

    assert [c["id"] for c in body["campaigns"]] == [campaign]
    assert body["campaigns"][0]["state"] == "open"
    assert body["decided"] == {"campaigns": 0, "investigations": 0}
    # The machine of the campaign counts: the tile never reads "on 0 hosts"
    # above a count that is not 0.
    assert (body["waiting"], body["waitingHosts"]) == (3, 2)
    listed = _list(client, body["waitingHref"])
    assert {r["id"] for r in listed["rows"]} == {first, second} | {
        r["newestInvestigationId"] for r in body["rows"]
    }


def test_open_again_returns_the_campaign_to_the_red_list(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: "Open again" clears the decision, and the work comes back."""
    _seed_hosts(client)
    run = _seed_run(client, "d-1", minutes_ago=10)
    campaign = _seed_campaign(client, [run])
    _decide(client, campaign, "closed")
    assert _threats(client)["campaigns"] == []
    _decide(client, campaign, None)
    body = _threats(client)
    assert [c["id"] for c in body["campaigns"]] == [campaign]
    assert (body["waiting"], body["decided"]["investigations"]) == (1, 0)


@pytest.mark.parametrize("expired", [False, True])
def test_an_investigation_beyond_the_authorization_still_waits(
    client: TestClient,  # noqa: F811
    expired: bool,
) -> None:
    """NEGATIVE CONTROL: an authorization covers its marked runs only.

    A run with no mark is beyond the authorization: it waits, and the
    campaign stays in the red list with that run. An expired authorization
    marks no later run, so the work comes back.
    """
    _seed_hosts(client)
    mark = _seed_authorization(client, "exploit test", expired=expired)
    inside = _seed_run(client, "a-1", authorization=mark, minutes_ago=10)
    beyond = _seed_run(client, "a-2", minutes_ago=20)
    campaign = _seed_campaign(client, [inside, beyond])
    _decide(client, campaign, "authorized", authorization=mark)

    body = _threats(client)

    (entry,) = body["campaigns"]
    assert (entry["id"], entry["state"], entry["investigations"]) == (campaign, "authorized", 1)
    assert body["decided"] == {"campaigns": 1, "investigations": 1}
    assert body["waiting"] == 1
    assert [r["id"] for r in _list(client, body["waitingHref"])["rows"]] == [beyond]


def test_a_superseded_true_positive_is_in_no_count_that_waits(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: a verdict that a later run replaced waits on nobody."""
    _seed_hosts(client)
    _seed_run(client, "s-1", minutes_ago=60)
    newer = _seed_run(client, "s-1", minutes_ago=10)
    body = _threats(client)
    assert (body["waiting"], body["total"]) == (1, 1)
    assert [r["id"] for r in _list(client, body["waitingHref"])["rows"]] == [newer]


def test_the_true_positives_view_states_its_parts(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    first = _seed_run(client, "d-1", minutes_ago=10)
    second = _seed_run(client, "d-2", minutes_ago=20)
    _seed_run(client, "d-2", minutes_ago=40)  # superseded by ``second``
    alone = _seed_run(client, "x-1", dst=OTHER, minutes_ago=30)
    mark = _seed_authorization(client, "exploit test")
    _seed_run(client, "m-1", dst=OTHER, authorization=mark, minutes_ago=35)
    campaign = _seed_campaign(client, [first, second], title="devbox against mainsrv")
    _decide(client, campaign, "closed")
    window = _threats(client)["window"]
    href = "/investigations?" + urlencode(
        {
            "verdict": "true_positive",
            "range": "custom",
            "from": window["since"],
            "to": window["until"],
        }
    )

    body = _list(client, href, tp_parts="true")

    parts = body["truePositiveParts"]
    assert body["truePositives"] == parts["total"] == 5
    assert (parts["waiting"], parts["decided"], parts["superseded"]) == (1, 2, 1)
    assert (parts["authorized"], parts["other"]) == (1, 0)
    assert parts["campaigns"] == [
        {"id": campaign, "title": "devbox against mainsrv", "state": "closed", "investigations": 2}
    ]
    # With no ask, no parts.
    assert _list(client, href)["truePositiveParts"] is None
    # The waiting part is the run that the tile counts.
    assert _threats(client)["waiting"] == parts["waiting"]
    assert [r["id"] for r in _list(client, href, waits="true")["rows"]] == [alone]


def test_the_parts_of_a_host_cover_its_true_positives_of_all_time(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    old = _seed_run(client, "d-1", minutes_ago=60 * 24 * 20)
    recent = _seed_run(client, "d-2", minutes_ago=10)
    _seed_run(client, "fp-1", verdict="false_positive", minutes_ago=15)
    _decide(client, _seed_campaign(client, [old]), "closed")
    res = client.get(
        "/api/v1/investigations", params={"entity": "10.20.30.5", "tp_parts": "true", "limit": 3}
    )
    assert res.status_code == 200, res.text
    parts = res.json()["truePositiveParts"]
    assert (parts["total"], parts["waiting"], parts["decided"]) == (2, 1, 1)
    assert res.json()["truePositives"] == 2
    assert recent in {r["id"] for r in res.json()["rows"]}
    # A verdict filter that leaves the true positives out gives no parts.
    none = client.get(
        "/api/v1/investigations",
        params={"entity": "10.20.30.5", "tp_parts": "true", "verdict": "false_positive"},
    )
    assert none.json()["truePositiveParts"] is None


def test_the_one_rule_reads_the_rule_of_needs_you() -> None:
    """The part of a run reads ``held`` and ``in_force``, no rule of its own."""
    from soc_ai.campaigns import threat_parts
    from soc_ai.campaigns.service import CampaignLink

    def link(decision: str | None, *, differs: bool = False, beyond: bool = False) -> Any:
        return CampaignLink(
            id=1,
            title="t",
            status="open",
            stage=None,
            differs=differs,
            decision=decision,
            beyond=beyond,
        )

    class Mark:
        holds = True

    assert threat_parts.part_of(None, None) == "waits"
    assert threat_parts.part_of(link(None), None) == "waits"
    assert threat_parts.part_of(link("closed"), None) == "decided"
    assert threat_parts.part_of(link("authorized", beyond=True), None) == "waits"
    assert threat_parts.part_of(link("closed", differs=True), None) == "waits"
    assert threat_parts.part_of(None, Mark()) == "authorized"
    assert threat_parts.part_of(link(None), Mark()) == "authorized"
    # W2: ``earlier`` takes only a run that would wait.
    assert threat_parts.part_of(link(None), None, earlier=True) == "earlier"
    assert threat_parts.part_of(link(None), Mark(), earlier=True) == "authorized"
    assert threat_parts.part_of(link(None), None, handled=True, earlier=True) == "handled"
    assert threat_parts.part_of(link("closed"), None, earlier=True) == "decided"
    # NEGATIVE CONTROL: a run that no campaign holds is never ``earlier``.
    assert threat_parts.part_of(None, None, earlier=True) == "waits"
    assert threat_parts.part_of(link(None, differs=True), None, earlier=True) == "waits"


# ── A campaign that soc-ai opened again (W2, round 3 part 2) ───────────────
#
# Production, 2026-11-19: the Dashboard at 30 days read "36 true positives
# wait: 6 on their own, 30 in 1 campaign". The analyst had closed the campaign
# on 2026-11-15, and it opened again for 6 new investigations: the close
# covered 28 of the 30.


def _reopen(
    client: TestClient,  # noqa: F811
    campaign_id: int,
    *,
    old: list[str],
    new: list[str],
    cause: str = decisions.CAUSE_ACTIVITY,
) -> None:
    """Close the campaign with a basis that ends between the old and the new runs, then reopen it.

    The old runs have an event 3 hours ago, the boundary is 2 hours ago and
    the new runs have an event 1 hour ago.
    """
    from datetime import timedelta

    from soc_ai.store.models import CampaignMember
    from sqlalchemy import select

    async def work(db: Any) -> None:
        now = utcnow()
        members = (
            await db.scalars(
                select(CampaignMember).where(CampaignMember.campaign_id == campaign_id)
            )
        ).all()
        for m in members:
            m.event_time = now - timedelta(hours=3 if m.run_id in old else 1)
        row = await db.get(Campaign, campaign_id)
        row.decision = decisions.DECISION_CLOSED
        row.close_reason = "test_over"
        row.decided_by = "casey"
        row.decided_at = now - timedelta(minutes=110)
        row.decision_basis = {"last_event": (now - timedelta(hours=2)).isoformat()}
        db.add(decisions.reopen(row, cause, now - timedelta(minutes=30), by="casey"))
        await db.commit()

    assert set(old) | set(new)
    _do(client, work)


def _tp_href(window: dict[str, str]) -> str:
    return "/investigations?" + urlencode(
        {
            "verdict": "true_positive",
            "range": "custom",
            "from": window["since"],
            "to": window["until"],
        }
    )


def test_the_earlier_close_covers_the_old_true_positives_of_a_reopened_campaign(
    client: TestClient,  # noqa: F811
) -> None:
    _seed_hosts(client)
    old = [_seed_run(client, f"o-{n}", minutes_ago=200 + n) for n in (1, 2)]
    new = _seed_run(client, "n-1", minutes_ago=50)
    alone = _seed_run(client, "x-1", dst=OTHER, minutes_ago=40)
    campaign = _seed_campaign(client, [*old, new])
    _reopen(client, campaign, old=old, new=[new])

    body = _threats(client)

    # The tile: the new true positive of the campaign and the one on its own.
    assert (body["waiting"], body["waitingInCampaigns"], body["waitingCampaigns"]) == (2, 1, 1)
    assert body["earlier"]["campaigns"] == 1 and body["earlier"]["investigations"] == 2
    assert body["earlier"]["decision"] == "closed" and body["earlier"]["decidedAt"]
    assert body["decided"] == {"campaigns": 0, "investigations": 0}
    # The campaign waits on a decision, so the panel still lists it.
    assert [c["id"] for c in body["campaigns"]] == [campaign]
    assert body["total"] == 4
    # The tile equals the list that it opens.
    listed = _list(client, body["waitingHref"])
    assert {r["id"] for r in listed["rows"]} == {new, alone}
    assert listed["total"] == body["waiting"]
    # The true positives view states the same parts.
    parts = _list(client, _tp_href(body["window"]), tp_parts="true")["truePositiveParts"]
    assert (parts["total"], parts["waiting"], parts["earlier"], parts["decided"]) == (4, 2, 2, 0)
    (entry,) = parts["earlierCampaigns"]
    assert (entry["id"], entry["investigations"], entry["decision"]) == (campaign, 2, "closed")
    # The host page reads the same parts.
    host = client.get(
        "/api/v1/investigations", params={"entity": "10.20.30.5", "tp_parts": "true"}
    ).json()["truePositiveParts"]
    assert (host["waiting"], host["earlier"]) == (1, 2)


def test_after_a_new_decision_each_true_positive_of_the_campaign_is_decided(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: a decision in force outranks the part ``earlier``."""
    _seed_hosts(client)
    old = [_seed_run(client, "o-1", minutes_ago=200)]
    new = _seed_run(client, "n-1", minutes_ago=50)
    campaign = _seed_campaign(client, [*old, new])
    _reopen(client, campaign, old=old, new=[new])
    _decide(client, campaign, "closed")
    body = _threats(client)
    assert body["decided"] == {"campaigns": 1, "investigations": 2}
    assert (body["waiting"], body["earlier"]["investigations"]) == (0, 0)


@pytest.mark.parametrize("cause", [decisions.CAUSE_ANALYST, decisions.CAUSE_REVOKED])
def test_an_open_again_by_the_analyst_returns_every_true_positive_to_the_wait(
    client: TestClient,  # noqa: F811
    cause: str,
) -> None:
    """NEGATIVE CONTROL: the analyst ended the earlier decision, so it covers nothing."""
    _seed_hosts(client)
    old = [_seed_run(client, "o-1", minutes_ago=200)]
    new = _seed_run(client, "n-1", minutes_ago=50)
    campaign = _seed_campaign(client, [*old, new])
    _reopen(client, campaign, old=old, new=[new], cause=cause)
    body = _threats(client)
    assert (body["waiting"], body["waitingInCampaigns"]) == (2, 2)
    assert body["earlier"] == {
        "campaigns": 0,
        "investigations": 0,
        "decision": None,
        "decidedAt": None,
    }


def test_a_campaign_with_no_earlier_decision_keeps_its_true_positives_in_the_wait(
    client: TestClient,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: no reopen, no part ``earlier``, also for an old event."""
    _seed_hosts(client)
    old = _seed_run(client, "o-1", minutes_ago=200)
    _seed_campaign(client, [old])
    body = _threats(client)
    assert (body["waiting"], body["earlier"]["investigations"]) == (1, 0)


def test_the_needs_you_runs_hold_no_true_positive_of_a_reopened_campaign(
    client: TestClient,  # noqa: F811
) -> None:
    """Needs you lists the reopened campaign once, as a campaign item, and no run of it."""
    from soc_ai.api.webui import routes_meta

    _seed_hosts(client)
    old = [_seed_run(client, "o-1", minutes_ago=200)]
    new = _seed_run(client, "n-1", minutes_ago=50)
    alone = _seed_run(client, "x-1", dst=OTHER, minutes_ago=40)
    campaign = _seed_campaign(client, [*old, new])
    _reopen(client, campaign, old=old, new=[new])

    async def work(db: Any) -> dict[str, int]:
        return await routes_meta.needs_you_runs(db, since=None, state=client.app.state)

    assert set(_do(client, work)) == {alone}
