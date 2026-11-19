"""GET /api/v1/campaigns and GET /api/v1/campaigns/{id} (Task 9).

Both routes rebuild the campaigns first when the store changed. The list
holds the active campaigns, the newest last event first. A merged or a
withdrawn campaign answers with its status and empty sections. The detail
route reads the events of the grid. A failed read gives the events that the
investigations hold.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.campaigns import service
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store.models import Campaign

from tests.test_campaign_facts import (
    ACTOR,
    ACTOR_2,
    RULE,
    RULE_B,
    STORY,
    TARGET,
    TARGET_2,
    seed_hosts,
    seed_run,
)

ROW_KEYS = {
    "id",
    "title",
    "status",
    "stage",
    "actors",
    "targets",
    "targetsMore",
    "firstEvent",
    "lastEvent",
    "members",
    "alerts",
    "decision",
    "waitsSince",
    "state",
    "authorization",
    "beyond",
    "case",
    "sinceDecision",
    "alertsReadAt",
    "alertsBehind",
    "lastAlertAt",
    "lastActivity",
}
BRIEF_KEYS = {"machineKey", "name", "address"}
CAMPAIGN_KEYS = {
    "id",
    "title",
    "status",
    "mergedInto",
    "earlierCampaign",
    "bottomLine",
    "stage",
    "firstEvent",
    "lastEvent",
    "builtAt",
    "stale",
    "authorizations",
    "ladder",
    "parties",
    "waves",
    "members",
    "related",
    "detection",
    "graph",
    "events",
    "decision",
    "waitsSince",
    "state",
    "changes",
    "authorization",
    "beyond",
    "excluded",
    "leads",
    "hunts",
    "case",
    "answers",
    "sinceDecision",
    "lastActivity",
}
STEP_KEYS = {
    "stage",
    "reached",
    "firstAt",
    "members",
    "proofRunId",
    "proofDocumentId",
    "headline",
    "evidence",
    "heldBy",
}
STEP_EVIDENCE_KEYS = {"documentId", "label", "at"}
PARTY_KEYS = {
    "machineKey",
    "name",
    "role",
    "addresses",
    "join",
    "hasAgent",
    "firstEvent",
    "lastEvent",
    "memberRuns",
    "beyond",
}
MEMBER_KEYS = {
    "runId",
    "kind",
    "label",
    "verdict",
    "impact",
    "stage",
    "link",
    "evidence",
    "direction",
    "eventAt",
    "finishedAt",
    "tier",
    "sourceAddress",
    "targetAddress",
    "verdictDiffers",
    "huntId",
    "sourceKey",
    "targetKey",
    "authorized",
    "included",
    "nameNote",
}
EVIDENCE_KEYS = {
    "memberRunId",
    "machineKey",
    "machineName",
    "artifact",
    "communityId",
    "documentIds",
}
RELATED_KEYS = {"needsMoreInfo", "sessions", "named", "falsePositiveFromTargets"}
DETECTION_KEYS = {"stage", "tier", "runId", "eventAt", "verdictAt", "seconds"}
EDGE_KEYS = {
    "source",
    "target",
    "runs",
    "alerts",
    "stage",
    "firstAt",
    "lastAt",
    "beyond",
    "fromDocuments",
}
EVENTS_KEYS = {
    "source",
    "readAt",
    "alerts",
    "rules",
    "findings",
    "records",
    "pairs",
    "timeline",
    "behind",
    "lastAlertAt",
    "laterAlerts",
    "laterRules",
    "laterLastAt",
}
PAIR_KEYS = {
    "source",
    "target",
    "alerts",
    "otherAlerts",
    "records",
    "firstAt",
    "lastAt",
    "rules",
    "datasets",
}
RULE_KEYS = {"name", "alerts", "firstAt", "lastAt", "verdict"}


class _Grid:
    """The grid of the app: a canned answer, or an error. Counts the searches."""

    def __init__(self, answer: EsSearchResult | None = None) -> None:
        self.answer = answer
        self.calls = 0

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls += 1
        if self.answer is None:
            raise ConnectionError("the grid refused the connection")
        return self.answer


def _grid_answer(confirmed: int = 1072, other: int = 9) -> EsSearchResult:
    now = datetime.now(UTC)
    stamp = {"value": now.timestamp() * 1000, "value_as_string": now.isoformat()}
    rules = [
        {"key": RULE, "doc_count": confirmed, "first": stamp, "last": stamp},
        {"key": RULE_B, "doc_count": other, "first": stamp, "last": stamp},
    ]
    return EsSearchResult(
        total=2000,
        took_ms=3,
        aggregations={
            "pairs": {
                "buckets": {
                    "0": {
                        "doc_count": 2000,
                        "datasets": {"buckets": [{"key": "suricata.alert", "doc_count": 1081}]},
                        "alerts": {"doc_count": confirmed + other, "by_rule": {"buckets": rules}},
                    }
                }
            },
            "confirmed": {
                "buckets": {
                    "0": {
                        "doc_count": confirmed,
                        "timeline": {
                            "buckets": [
                                {"key": int(now.timestamp()) * 1000, "doc_count": confirmed}
                            ]
                        },
                    }
                }
            },
        },
    )


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            # The grid refuses each read unless a test sets an answer.
            app.state.elastic = _Grid()
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _seed_three(client: TestClient) -> list[str]:
    """The Hosts data and three true positive runs of one actor on one target."""

    async def work(db: Any) -> list[str]:
        await seed_hosts(db)
        return [
            await seed_run(db, f"alert-000{n}", event_hours_ago=4 - n, created_minutes_ago=40 - n)
            for n in (1, 2, 3)
        ]

    runs: list[str] = _do(client, work)
    return runs


def _seed(client: TestClient, alert_id: str, **over: Any) -> str:
    async def work(db: Any) -> str:
        return await seed_run(db, alert_id, **over)

    run_id: str = _do(client, work)
    return run_id


def _list(client: TestClient) -> dict[str, Any]:
    res = client.get("/api/v1/campaigns")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _campaign(client: TestClient, campaign_id: int) -> dict[str, Any]:
    res = client.get(f"/api/v1/campaigns/{campaign_id}")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_the_list_row_and_the_campaign_have_the_whole_shape(client: TestClient) -> None:
    runs = _seed_three(client)
    body = _list(client)
    assert set(body) == {"rows", "total", "stale"}
    assert (body["total"], body["stale"]) == (1, False)
    (row,) = body["rows"]
    assert set(row) == ROW_KEYS
    assert (row["title"], row["status"], row["stage"], row["members"]) == (
        "actor-a against web-1",
        "open",
        "attempt",
        3,
    )
    assert row["actors"] == [{"machineKey": "agent:a1", "name": "actor-a", "address": "192.0.2.10"}]
    assert [set(t) for t in row["targets"]] == [BRIEF_KEYS]
    assert row["targetsMore"] == 0
    assert row["firstEvent"].endswith("+00:00")
    # No grid read stored events yet.
    assert row["alerts"] is None

    campaign = _campaign(client, row["id"])
    assert set(campaign) == CAMPAIGN_KEYS
    assert (campaign["status"], campaign["mergedInto"], campaign["stale"]) == ("open", None, False)
    assert campaign["earlierCampaign"] is None
    # The period reads "on <day>" or "from <day> to <day>": the runs can cross midnight.
    assert campaign["bottomLine"].startswith("actor-a acted against web-1 ")
    assert campaign["bottomLine"].endswith("Stage reached: Attempt. No activity beyond the target.")
    assert [set(step) for step in campaign["ladder"]] == [STEP_KEYS] * 5
    assert [s["stage"] for s in campaign["ladder"] if s["reached"]] == ["attempt"]
    attempt = next(s for s in campaign["ladder"] if s["reached"])
    # What happened, in the sentence of the proof investigation, and the record that proves it.
    assert (attempt["proofRunId"], attempt["headline"]) == (runs[0], STORY)
    assert set(attempt["evidence"]) == STEP_EVIDENCE_KEYS
    assert (attempt["evidence"]["documentId"], attempt["evidence"]["label"]) == (
        "alert-0001",
        RULE,
    )
    assert attempt["evidence"]["at"] == campaign["members"][0]["eventAt"]
    # NEGATIVE CONTROL: a stage that no investigation proves has no headline and no evidence.
    assert {(s["headline"], s["evidence"]) for s in campaign["ladder"] if not s["reached"]} == {
        (None, None)
    }
    assert {p["machineKey"]: set(p) for p in campaign["parties"]} == {
        "agent:a1": PARTY_KEYS,
        "ip:t1": PARTY_KEYS,
    }
    assert {p["machineKey"]: p["hasAgent"] for p in campaign["parties"]} == {
        "agent:a1": True,
        "ip:t1": False,
    }
    (waves,) = campaign["waves"]
    assert set(waves) == {"actor", "waves"}
    assert set(waves["actor"]) == BRIEF_KEYS
    assert set(waves["waves"][0]) == {"n", "start", "end", "events"}
    assert [m["runId"] for m in campaign["members"]] == runs
    for member in campaign["members"]:
        assert set(member) == MEMBER_KEYS
        assert set(member["evidence"]) == EVIDENCE_KEYS
    second = campaign["members"][1]
    assert (second["link"], second["verdict"], second["tier"], second["kind"]) == (
        "actor",
        "true_positive",
        "alert",
        "alert",
    )
    assert second["evidence"]["machineName"] == "actor-a"
    assert set(campaign["related"]) == RELATED_KEYS
    assert campaign["related"]["falsePositiveFromTargets"] == 0
    assert campaign["authorizations"] == []
    (detection,) = campaign["detection"]
    assert set(detection) == DETECTION_KEYS
    assert detection["stage"] == "attempt"
    assert {(m["sourceKey"], m["targetKey"]) for m in campaign["members"]} == {
        ("agent:a1", "ip:t1")
    }
    assert set(campaign["graph"]) == {"edges"}
    (edge,) = campaign["graph"]["edges"]
    assert set(edge) == EDGE_KEYS
    assert (edge["source"], edge["target"], edge["runs"], edge["stage"]) == (
        "agent:a1",
        "ip:t1",
        3,
        "attempt",
    )
    # The grid refused the read: the events are the alerts that the three investigations hold.
    events = campaign["events"]
    assert set(events) == EVENTS_KEYS
    assert (events["source"], events["readAt"], events["records"]) == ("stored", None, None)
    assert (events["alerts"], events["rules"], events["findings"]) == (3, 1, 0)
    (pair,) = events["pairs"]
    assert set(pair) == PAIR_KEYS
    assert (pair["source"], pair["target"], pair["alerts"], pair["otherAlerts"]) == (
        "agent:a1",
        "ip:t1",
        3,
        0,
    )
    assert [set(r) for r in pair["rules"]] == [RULE_KEYS]
    assert (pair["rules"][0]["name"], pair["rules"][0]["verdict"]) == (RULE, "true_positive")
    assert pair["datasets"] == []
    assert events["timeline"]["bucketSeconds"] == 60
    assert [lane["machineKey"] for lane in events["timeline"]["lanes"]] == ["agent:a1"]
    assert edge["alerts"] == 3
    assert (edge["beyond"], edge["fromDocuments"]) == (False, False)
    assert edge["firstAt"].endswith("+00:00")
    assert edge["firstAt"] == campaign["members"][0]["eventAt"]
    assert edge["lastAt"] == campaign["members"][-1]["eventAt"]


def test_a_campaign_of_an_earlier_release_gives_an_empty_graph(client: TestClient) -> None:
    _seed_three(client)
    (row,) = _list(client)["rows"]

    async def strip(db: Any) -> None:
        held = await db.get(Campaign, row["id"])
        held.detail = {k: v for k, v in held.detail.items() if k != "edges"}
        await db.commit()

    _do(client, strip)
    campaign = _campaign(client, row["id"])
    assert campaign["graph"] == {"edges": []}
    # NEGATIVE CONTROL: the members still read, with their machine keys.
    assert [m["sourceKey"] for m in campaign["members"]] == ["agent:a1"] * 3


def test_a_campaign_of_an_earlier_release_has_no_evidence_and_still_reads(
    client: TestClient,
) -> None:
    """A row of the earlier release holds no events and a ladder with no proof label."""
    _seed_three(client)
    (row,) = _list(client)["rows"]

    async def strip(db: Any) -> None:
        held = await db.get(Campaign, row["id"])
        ladder = [
            {k: v for k, v in step.items() if k not in ("proof_label", "proof_at")}
            for step in held.detail["ladder"]
        ]
        held.detail = {**held.detail, "ladder": ladder}
        held.events, held.events_at, held.events_basis = None, None, None
        await db.commit()

    _do(client, strip)
    campaign = _campaign(client, row["id"])
    attempt = next(s for s in campaign["ladder"] if s["reached"])
    assert attempt["evidence"] is None
    # NEGATIVE CONTROL: the headline comes from the investigation, and it still reads.
    assert attempt["headline"] == STORY
    assert campaign["events"]["source"] == "stored"


def test_a_failing_grid_gives_200_and_the_stored_events(client: TestClient) -> None:
    _seed_three(client)
    (row,) = _list(client)["rows"]
    grid = client.app.state.elastic
    res = client.get(f"/api/v1/campaigns/{row['id']}")
    assert res.status_code == 200
    assert res.json()["events"]["source"] == "stored"
    assert grid.calls == 1
    # The list still holds no grid alerts: the failed read stored nothing.
    assert _list(client)["rows"][0]["alerts"] is None


def test_a_grid_read_gives_the_grid_events_and_the_list_row_alerts(client: TestClient) -> None:
    _seed_three(client)
    (row,) = _list(client)["rows"]
    client.app.state.elastic = _Grid(_grid_answer())
    campaign = _campaign(client, row["id"])
    events = campaign["events"]
    assert (events["source"], events["alerts"], events["rules"], events["records"]) == (
        "grid",
        1072,
        1,
        2000,
    )
    assert events["readAt"].endswith("+00:00")
    (pair,) = events["pairs"]
    assert (pair["alerts"], pair["otherAlerts"], pair["records"]) == (1072, 9, 2000)
    assert {r["name"]: r["verdict"] for r in pair["rules"]} == {
        RULE: "true_positive",
        RULE_B: "not_judged",
    }
    assert pair["datasets"] == [{"name": "suricata.alert", "records": 1081}]
    (edge,) = campaign["graph"]["edges"]
    # The arrow counts events, and the investigations stay in runs.
    assert (edge["runs"], edge["alerts"]) == (3, 1072)
    assert _list(client)["rows"][0]["alerts"] == 1072


def test_a_rule_that_is_no_confirmed_rule_takes_its_verdict_from_the_store(
    client: TestClient,
) -> None:
    _seed_three(client)
    _seed(
        client,
        "alert-fp-1",
        rule=RULE_B,
        verdict="false_positive",
        src=TARGET,
        dst=ACTOR,
        event_hours_ago=3,
    )
    (row,) = _list(client)["rows"]
    client.app.state.elastic = _Grid(_grid_answer())
    (pair,) = _campaign(client, row["id"])["events"]["pairs"]
    assert {r["name"]: r["verdict"] for r in pair["rules"]} == {
        RULE: "true_positive",
        RULE_B: "false_positive",
    }


def test_an_unknown_campaign_gives_404(client: TestClient) -> None:
    res = client.get("/api/v1/campaigns/999")
    assert res.status_code == 404
    assert res.json()["detail"]["reason"] == "campaign_not_found"


def test_a_merged_campaign_gives_its_status_and_empty_sections(client: TestClient) -> None:
    async def hosts(db: Any) -> None:
        await seed_hosts(db)

    _do(client, hosts)
    _seed(client, "alert-a", event_hours_ago=10)
    _seed(client, "alert-b", src=ACTOR_2, dst=TARGET_2, rule=RULE_B, event_hours_ago=8)
    before = _list(client)["rows"]
    assert len(before) == 2
    older, newer = sorted(row["id"] for row in before)

    # The actor of the first campaign uses the rule of the second on its target.
    _seed(client, "alert-c", dst=TARGET_2, rule=RULE_B, event_hours_ago=1)
    after = _list(client)
    assert [row["id"] for row in after["rows"]] == [older]
    merged = _campaign(client, newer)
    assert set(merged) == CAMPAIGN_KEYS
    assert (merged["status"], merged["mergedInto"]) == ("merged", older)
    for name in (
        "authorizations",
        "ladder",
        "parties",
        "waves",
        "members",
        "detection",
        "leads",
        "hunts",
    ):
        assert merged[name] == [], name
    assert merged["graph"] == {"edges": []}
    assert merged["related"] == {
        "needsMoreInfo": [],
        "sessions": [],
        "named": [],
        "falsePositiveFromTargets": 0,
    }
    assert merged["events"] == {
        "source": "none",
        "readAt": None,
        "alerts": 0,
        "rules": 0,
        "findings": 0,
        "records": None,
        "pairs": [],
        "timeline": {"bucketSeconds": 60, "lanes": []},
        "behind": False,
        "lastAlertAt": None,
        "laterAlerts": 0,
        "laterRules": 0,
        "laterLastAt": None,
    }


def test_the_list_is_newest_last_event_first(client: TestClient) -> None:
    async def hosts(db: Any) -> None:
        await seed_hosts(db)

    _do(client, hosts)
    _seed(client, "alert-a", event_hours_ago=20)
    _seed(client, "alert-b", src=ACTOR_2, dst=TARGET_2, rule=RULE_B, event_hours_ago=2)
    rows = _list(client)["rows"]
    assert [row["title"] for row in rows] == ["actor-b against web-2", "actor-a against web-1"]
    assert rows[0]["lastEvent"] > rows[1]["lastEvent"]


def test_a_second_get_with_no_store_change_runs_no_rebuild(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = service.rebuild
    calls: list[int] = []

    async def spy(db: Any, **kwargs: Any) -> service.RebuildResult:
        calls.append(1)
        return await real(db, **kwargs)

    monkeypatch.setattr(service, "rebuild", spy)
    _seed_three(client)
    (row,) = _list(client)["rows"]
    assert len(calls) == 1
    _list(client)
    _campaign(client, row["id"])
    assert len(calls) == 1


def test_a_failed_rebuild_serves_the_stored_rows_as_stale(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_three(client)
    (row,) = _list(client)["rows"]

    async def broken(db: Any, **kwargs: Any) -> service.RebuildResult:
        raise RuntimeError("the store is locked")

    monkeypatch.setattr(service, "rebuild", broken)
    _seed(client, "alert-0009", event_hours_ago=0.5, created_minutes_ago=1)
    body = _list(client)
    assert body["stale"] is True
    assert [r["id"] for r in body["rows"]] == [row["id"]]
    assert _campaign(client, row["id"])["stale"] is True
