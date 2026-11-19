"""The decision on the open false positives of a rule (round 3, RS4).

``POST /rule-decisions/{ruleKey}`` records the decision, and the background
work acknowledges the alert of each selected investigation and of its
inherited cluster. The server computes the selection again. Each investigation
gets a receipt, so no page shows an open Acknowledge after the decision. The
audit record comes first and fails closed.

The negative controls sit on the paths that the decision must not reach: an
alert with a true positive, a needs more info or an analyst verdict of its
own; the group weak when ``includeWeak`` is false; a grid that does not
answer; a rule that holds a standing true positive. The grid and the Security
Onion write are fakes, and the data is synthetic.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import investigations as inv_svc
from soc_ai.store import rule_decisions as rd_store
from soc_ai.store.models import InvestigationEvent, RuleDecision
from soc_ai.webui import rule_decisions as rd
from sqlalchemy import select

from tests.test_rule_decision_selection import RULE, seed_fp

WRITE_PATH = "soc_ai.tools.write_exec.execute_write_tool"
SRC, DST = "192.0.2.10", "203.0.113.5"
KEY = rd.rule_key(RULE)


class Audit:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any], bool]] = []

    async def log_kind(
        self, session_id: str, kind: str, payload: dict[str, Any], **kw: Any
    ) -> None:
        self.records.append((kind, payload, bool(kw.get("mutating"))))

    def kinds(self) -> list[str]:
        return [kind for kind, _p, _m in self.records]


class Down:
    async def log_kind(self, *_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("the audit index did not answer")


class Grid:
    """The grid: alert documents by id, or down. A write marks a document acknowledged."""

    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}
        self.down = False

    def add(self, es_id: str, *, src: str = SRC, dst: str = DST, acked: bool = False) -> None:
        self.docs[es_id] = {
            "@timestamp": datetime.now(UTC).isoformat(),
            "rule": {"name": RULE},
            "source": {"ip": src},
            "destination": {"ip": dst},
            "event": {
                "acknowledged": acked,
                "severity_label": "high",
                "dataset": "suricata.alert",
                "module": "suricata",
            },
        }

    def acked(self, es_id: str) -> bool:
        return bool(self.docs[es_id]["event"]["acknowledged"])

    async def search(self, index: str, query: dict[str, Any], **kw: Any) -> EsSearchResult:
        if self.down:
            raise ConnectionError("the grid refused the connection")
        if "ids" in query:
            ids = query["ids"]["values"]
            hits = [{"_id": i, "_source": self.docs[i]} for i in ids if i in self.docs]
            return EsSearchResult(total=len(hits), took_ms=1, hits=hits)
        if f'"rule.name": {json.dumps(RULE)}' not in json.dumps(query):
            return EsSearchResult(total=0, took_ms=1, hits=[])
        rows = [
            {"_id": i, "_source": d}
            for i, d in sorted(self.docs.items())
            if not d["event"]["acknowledged"]
        ]
        start = int(kw.get("from_") or 0)
        size = int(kw.get("size") or 0)
        return EsSearchResult(total=len(rows), took_ms=1, hits=rows[start : start + size])


def _client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            app.state.audit = Audit()
            app.state.elastic = Grid()
            yield test_client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    """The console API with automatic acknowledge on, as a grid that uses the feature."""
    yield from _client(settings_kratos.model_copy(update={"auto_ack_fp_enabled": True}))


@pytest.fixture
def client_auto_ack_off(settings_kratos: Settings) -> Iterator[TestClient]:
    """The console API with automatic acknowledge off, the default."""
    yield from _client(settings_kratos.model_copy(update={"auto_ack_fp_enabled": False}))


def grid(client: TestClient) -> Grid:
    found: Grid = client.app.state.elastic  # type: ignore[attr-defined]
    return found


def run(client: TestClient, work: Any) -> Any:
    return asyncio.run(work(client.app.state.db_sessionmaker))  # type: ignore[attr-defined]


def seed(client: TestClient, alert_id: str, **kw: Any) -> str:
    async def work(maker: Any) -> str:
        return await seed_fp(maker, alert_id, **kw)

    out: str = run(client, work)
    return out


def writer(client: TestClient, *, fail: frozenset[str] = frozenset()) -> AsyncMock:
    """The Security Onion write: it acknowledges the document on the fake grid."""

    async def write(tool: str, args: dict[str, Any], **_kw: Any) -> tuple[Any, str | None]:
        alert_id = args["alert_id"]
        if alert_id in fail:
            return None, "Security Onion answered 500"
        grid(client).docs[alert_id]["event"]["acknowledged"] = True
        return {"ok": True}, None

    return AsyncMock(side_effect=write)


def decide(client: TestClient, write: AsyncMock, **body: Any) -> Any:
    with patch(WRITE_PATH, write):
        return client.post(
            f"/api/v1/rule-decisions/{KEY}", json={"decision": "acknowledge", **body}
        )


def receipts(client: TestClient) -> dict[str, list[dict[str, Any]]]:
    async def work(maker: Any) -> dict[str, list[dict[str, Any]]]:
        async with maker() as db:
            rows = await db.scalars(
                select(InvestigationEvent).where(InvestigationEvent.kind == "action_executed")
            )
            out: dict[str, list[dict[str, Any]]] = {}
            for event in rows.all():
                out.setdefault(event.investigation_id, []).append(dict(event.payload))
            return out

    found: dict[str, list[dict[str, Any]]] = run(client, work)
    return found


def decision_row(client: TestClient, decision_id: int) -> RuleDecision:
    async def work(maker: Any) -> RuleDecision:
        async with maker() as db:
            row = await db.get(RuleDecision, decision_id)
            assert row is not None
            return row

    found: RuleDecision = run(client, work)
    return found


def open_ids(client: TestClient) -> set[str]:
    async def work(maker: Any) -> set[str]:
        async with maker() as db:
            return {r.id for r in await rd.open_false_positives(db, threshold=0.7)}

    found: set[str] = run(client, work)
    return found


def test_the_decision_acknowledges_the_confident_group_and_its_cluster(client: TestClient) -> None:
    g = grid(client)
    for alert in ("ev-1", "ev-2", "ev-weak", "ev-sib", "ev-far"):
        g.add(alert)
    g.docs["ev-far"]["source"]["ip"] = "198.51.100.7"
    first = seed(client, "ev-1")
    second = seed(client, "ev-2", reason=None)
    weak = seed(client, "ev-weak", reason="below_threshold", confidence=0.5)
    write = writer(client)

    answer = decide(client, write, note="Known update traffic of web-1.")

    assert answer.status_code == 202
    record = answer.json()
    assert record["ruleKey"] == KEY and record["state"] == "acknowledging"
    assert record["decision"] == "acknowledge" and record["href"] == f"/needs-you/rule/{KEY}"
    written = sorted(call.args[1]["alert_id"] for call in write.await_args_list)
    # The cluster sibling inherits the verdict of the same pair. The weak run
    # stays open (NEGATIVE CONTROL), and so does the alert of another pair.
    assert written == ["ev-1", "ev-2", "ev-sib"]
    assert not g.acked("ev-weak") and not g.acked("ev-far")
    row = decision_row(client, record["id"])
    assert (row.state, row.alerts, row.failed, row.investigations) == ("done", 3, 0, 2)
    got = receipts(client)
    assert set(got) == {first, second}
    (receipt,) = got[first]
    assert receipt["rule_decision"] == record["id"] and receipt["success"] is True
    assert receipt["tool_name"] == "ack_alert" and receipt["rule_key"] == KEY
    assert open_ids(client) == {weak}
    # The record of the intent comes first and is mutating; the result follows.
    audit: Audit = client.app.state.audit  # type: ignore[attr-defined]
    made = audit.records[0]
    assert made[0] == "rule_decision_made" and made[2] is True
    assert made[1]["selected"] == 2 and made[1]["weak"] == 1
    assert audit.kinds()[-1] == "rule_decision_result"
    assert audit.records[-1][1]["alerts"] == 3


def test_a_receipt_closes_the_acknowledge_on_the_card(client: TestClient) -> None:
    from soc_ai.api.webui._timeline import _build_actions

    grid(client).add("ev-1")
    first = seed(client, "ev-1")
    decide(client, writer(client))

    async def work(maker: Any) -> Any:
        async with maker() as db:
            return await inv_svc.get_with_events(db, first)

    inv, events = run(client, work)
    (action,) = _build_actions(events, inv.report)
    assert action.applied is True
    assert action.appliedDetail == rd.RECEIPT_DETAIL


def test_include_weak_adds_the_group_weak(client: TestClient) -> None:
    grid(client).add("ev-1")
    grid(client).add("ev-weak")
    seed(client, "ev-1")
    weak = seed(client, "ev-weak", reason="no_investigation")
    write = writer(client)

    answer = decide(client, write, includeWeak=True)

    assert answer.status_code == 202
    assert sorted(c.args[1]["alert_id"] for c in write.await_args_list) == ["ev-1", "ev-weak"]
    assert weak in receipts(client)
    assert open_ids(client) == set()


def test_the_decision_never_acknowledges_an_alert_that_a_verdict_holds(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL: the cluster holds alerts with a verdict of their own."""
    g = grid(client)
    for alert in ("ev-1", "ev-tp", "ev-nmi", "ev-analyst", "ev-open"):
        g.add(alert)
    seed(client, "ev-1")
    seed(client, "ev-tp", verdict="true_positive")
    seed(client, "ev-nmi", verdict="needs_more_info")
    decided = seed(client, "ev-analyst", reason=None)

    async def override(maker: Any) -> None:
        async with maker() as db:
            await inv_svc.resolve(
                db,
                decided,
                verdict="false_positive",
                confidence=1.0,
                rationale="Verdict set by analyst1.",
                recommended_actions=[],
                resolved_by="analyst1",
                resolved_via="manual",
            )

    run(client, override)
    write = writer(client)

    # The true positive shares the machine pair of ev-1, so the decision asks
    # for that pair: the cluster must still hold each verdict of its own.
    assert decide(client, write, includeTruePositivePairs=True).status_code == 202

    assert sorted(c.args[1]["alert_id"] for c in write.await_args_list) == ["ev-1", "ev-open"]
    assert decision_row(client, 1).detail == {
        "selected": 1,
        "held": 3,
        "cluster": 1,
        "already": 0,
        "capped": False,
        "include_true_positive_pairs": True,
    }


def test_with_the_grid_down_the_decision_acknowledges_nothing(client: TestClient) -> None:
    """NEGATIVE CONTROL: no answer from the grid is no permission to write."""
    grid(client).add("ev-1")
    first = seed(client, "ev-1")
    grid(client).down = True
    write = writer(client)

    answer = decide(client, write)

    assert answer.status_code == 202
    write.assert_not_awaited()
    assert receipts(client) == {}
    row = decision_row(client, answer.json()["id"])
    assert (row.state, row.alerts, row.failed) == ("failed", 0, 0)
    assert row.detail is not None and row.detail["unread"] is True
    assert open_ids(client) == {first}
    page = client.get("/api/v1/rule-decisions").json()
    assert page == {"standing": [], "ended": []}


def test_a_failed_write_counts_and_leaves_its_investigation_open(client: TestClient) -> None:
    grid(client).add("ev-1")
    grid(client).add("ev-2")
    first = seed(client, "ev-1")
    second = seed(client, "ev-2")

    answer = decide(client, writer(client, fail=frozenset({"ev-2"})))

    row = decision_row(client, answer.json()["id"])
    assert (row.state, row.alerts, row.failed, row.investigations) == ("done", 1, 1, 1)
    assert set(receipts(client)) == {first}
    assert open_ids(client) == {second}


def test_an_audit_failure_records_no_decision(client: TestClient) -> None:
    grid(client).add("ev-1")
    seed(client, "ev-1")
    client.app.state.audit = Down()  # type: ignore[attr-defined]
    write = writer(client)

    answer = decide(client, write)

    assert answer.status_code == 503
    assert answer.json()["detail"]["reason"] == "audit_unavailable"
    write.assert_not_awaited()

    async def work(maker: Any) -> int:
        async with maker() as db:
            return len((await db.scalars(select(RuleDecision))).all())

    assert run(client, work) == 0


def test_the_refusals(client: TestClient) -> None:
    write = writer(client)
    assert decide(client, write).json()["detail"]["reason"] == "rule_nothing_open"
    seed(client, "ev-tp", verdict="true_positive")
    answer = decide(client, write, decision="standing")
    # NEGATIVE CONTROL: a rule that holds a standing true positive takes no standing decision.
    assert answer.status_code == 409
    assert answer.json()["detail"]["reason"] == "rule_has_true_positive"
    bad = client.post("/api/v1/rule-decisions/!!", json={"decision": "acknowledge"})
    assert bad.status_code == 404
    assert client.get("/api/v1/rule-decisions/!!").status_code == 404
    write.assert_not_awaited()


def test_with_auto_ack_off_the_rule_takes_no_standing_decision(
    client_auto_ack_off: TestClient,
) -> None:
    """NEGATIVE CONTROL: a standing decision writes nothing while automatic acknowledge is off.

    The page states that, the route refuses the standing decision, and the
    decision for the open false positives of now still works.
    """
    client = client_auto_ack_off
    g = grid(client)
    g.add("ev-1")
    seed(client, "ev-1")
    write = writer(client)

    page = client.get(f"/api/v1/rule-decisions/{KEY}").json()
    assert page["canStanding"] is False
    assert "Automatic acknowledge is off" in page["canStandingWhy"]

    refused = decide(client, write, decision="standing")
    assert refused.status_code == 409
    assert refused.json()["detail"]["reason"] == "rule_auto_ack_off"
    write.assert_not_awaited()

    assert decide(client, write).status_code == 202


def test_the_page_of_a_rule_states_its_facts(client: TestClient) -> None:
    g = grid(client)
    for n in range(10):
        g.add(f"ev-{n}")
    for n in range(8):
        seed(client, f"ev-{n}", src_ip=f"192.0.2.{10 + n % 2}")
    seed(client, "ev-8", reason="below_threshold", confidence=0.5)
    seed(client, "ev-9", reason="uncited", confidence=0.6)
    tp = seed(client, "ev-tp", verdict="true_positive")

    page = client.get(f"/api/v1/rule-decisions/{KEY}").json()

    assert page["ruleName"] == RULE and page["ruleKey"] == KEY
    assert page["gridAnswered"] is True and page["readAt"] is not None
    assert page["confident"]["count"] == 8 and page["weak"]["count"] == 2
    assert page["confident"]["reasons"] == [
        {"code": "high_stakes", "label": rd.hold_label("high_stakes"), "count": 8}
    ]
    assert [r["code"] for r in page["weak"]["reasons"]] == ["below_threshold", "uncited"]
    assert page["confident"]["sources"] == 2 and page["confident"]["destinations"] == 1
    assert sum(d["confident"] + d["weak"] for d in page["histogram"]) == 10
    # At most 8 samples, and each reason has one.
    assert len(page["samples"]) == 8
    assert {s["reason"] for s in page["samples"]} == {"high_stakes", "below_threshold", "uncited"}
    assert page["machines"][0] == {
        "key": DST,
        "name": None,
        "address": DST,
        "role": "destination",
        "count": 10,
        "truePositive": True,
    }
    assert [t["id"] for t in page["truePositives"]] == [tp]
    assert page["canStanding"] is False and "true positive" in page["canStandingWhy"]
    assert page["openAlerts"] == 10
    assert page["investigationsHref"].startswith("/investigations?verdict=false_positive")


def test_an_alert_that_the_grid_states_as_acknowledged_is_in_no_count(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL: Security Onion acknowledged the alert outside soc-ai."""
    grid(client).add("ev-1")
    grid(client).add("ev-2", acked=True)
    seed(client, "ev-1")
    seed(client, "ev-2")

    page = client.get(f"/api/v1/rule-decisions/{KEY}").json()

    assert page["confident"]["count"] == 1

    async def work(maker: Any) -> dict[str, Any]:
        async with maker() as db:
            return await rd_store.states_for(db, ["ev-1", "ev-2"])

    states = run(client, work)
    assert {a: s for a, (s, _at) in states.items()} == {"ev-1": "open", "ev-2": "acknowledged"}


def test_with_the_grid_down_the_page_states_the_last_read(client: TestClient) -> None:
    grid(client).add("ev-1")
    seed(client, "ev-1")
    grid(client).down = True

    page = client.get(f"/api/v1/rule-decisions/{KEY}").json()

    assert page["gridAnswered"] is False
    assert page["readAt"] is None
    assert page["confident"]["count"] == 1
    assert page["openAlerts"] is None
