"""GET /api/v1/threats: the confirmed threats of a window, merged by target (H1).

On production the Dashboard said "TRUE POSITIVES 24H 3" beside a card that
said "True positive 0", and no element named the three. 42 of the 53 true
positive runs of 30 days had one target, from three sources, and no page
said so. The route reads the true positive verdicts of the page window and
merges them by target machine.

The data is synthetic: placeholder addresses, host names and rule names.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_threats import _what_happened
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import (
    AuthorizedActivity,
    HostDossier,
    HostDossierField,
    HostMachine,
    Investigation,
)

SERVER, SERVER_2 = "10.20.30.5", "10.20.30.6"  # two addresses of one machine
DEVBOX, LAPTOP = "10.40.50.7", "10.40.50.8"
OTHER = "10.20.30.90"  # a target the Hosts data does not hold
RULE_A = "ET EXPLOIT Example Upload Request"
RULE_B = "ET EXPLOIT Example Chunked Request"
STORY = "The source host sent exploit requests to the web server."
_ESCALATE = {
    "tool_name": "escalate_to_case",
    "tool_args": {"case_title": "Upload", "case_description": "Exploit requests."},
    "rationale": "Open a case for the exploit requests.",
}
C2 = "203.0.113.50"  # an external address: outside internal_cidrs
ROW_KEYS = {
    "target",
    "direction",
    "headline",
    "impact",
    "runs",
    "alertRuns",
    "findingRuns",
    "sources",
    "sourcesMore",
    "rules",
    "rulesMore",
    "firstSeen",
    "lastSeen",
    "waitingActions",
    "newestInvestigationId",
    "investigationsHref",
    "authorizedRuns",
    "authorizations",
}


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


def _seed_hosts(client: TestClient) -> None:
    """One server with two addresses, a name and a declared role. One agent machine."""

    async def work(db: Any) -> None:
        server = HostMachine(
            machine_key="ip:m1",
            name="mainsrv",
            names_json=[{"value": "mainsrv", "source": "dns"}],
            primary_ip=SERVER,
            address_count=2,
        )
        devbox = HostMachine(
            machine_key="agent:d1", agent_name="devbox", primary_ip=DEVBOX, address_count=1
        )
        db.add_all([server, devbox])
        await db.flush()
        first = HostDossier(
            host_key=SERVER, ip=SERVER, machine_id=server.id, address_kind="network"
        )
        second = HostDossier(
            host_key=SERVER_2, ip=SERVER_2, machine_id=server.id, address_kind="network"
        )
        agent = HostDossier(host_key=DEVBOX, ip=DEVBOX, machine_id=devbox.id, address_kind="agent")
        db.add_all([first, second, agent])
        await db.flush()
        db.add(HostDossierField(dossier_id=first.id, field="role", operator_value="server"))
        await db.commit()

    _do(client, work)


def _seed_run(
    client: TestClient,
    alert_id: str,
    *,
    src: str | None = DEVBOX,
    dst: str | None = SERVER,
    host_name: str | None = None,
    rule: str = RULE_A,
    verdict: str = "true_positive",
    minutes_ago: float = 60.0,
    started_by: str = "auto-triage",
    report: dict[str, Any] | None = None,
    actions: list[dict[str, Any]] | None = None,
    synthetic: bool = False,
    finding: tuple[str, int] | None = None,
    authorization: int | None = None,
    event_minutes_ago: float | None = None,
) -> str:
    """One finalized run. An alert run by default, a finding run with ``finding``."""
    when = datetime.now(UTC) - timedelta(minutes=minutes_ago)

    async def work(db: Any) -> str:
        extra: dict[str, Any] = {}
        if finding is not None:
            extra = {
                "kind": "hunt",
                "hunt_id": finding[0],
                "finding_ordinal": finding[1],
                "subject": {"type": "hunt", "judges": "finding", "hunt_id": finding[0]},
            }
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_id,
            started_by=started_by,
            rule_name=rule,
            src_ip=src,
            dest_ip=dst,
            is_synth_eval=synthetic,
            **extra,
        )
        if event_minutes_ago is not None:
            at = datetime.now(UTC) - timedelta(minutes=event_minutes_ago)
            await inv_svc.append_events(
                db,
                inv.id,
                [
                    {
                        "sequence": 1,
                        "kind": "enriched_alert_context",
                        "payload": {"alert": {"id": alert_id, "timestamp": at.isoformat()}},
                    }
                ],
            )
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict=verdict,
            confidence=0.85,
            summary=STORY,
            report={
                "verdict": verdict,
                "confidence": 0.85,
                "summary": STORY,
                "recommended_actions": actions if actions is not None else [],
                **(report or {}),
            },
        )
        row = await db.get(Investigation, inv.id)
        row.created_at = when.replace(tzinfo=None)
        row.host_name = host_name
        if authorization is not None:
            row.authorization_id = authorization
        await db.commit()
        return str(inv.id)

    run_id: str = _do(client, work)
    return run_id


def _seed_authorization(
    client: TestClient, label: str = "exploit test", *, expired: bool = False, revoked: bool = False
) -> int:
    async def work(db: Any) -> int:
        now = utcnow()
        row = AuthorizedActivity(
            label=label,
            sources=[{"address": DEVBOX, "machine_key": "agent:d1", "name": "devbox"}],
            target_address=SERVER,
            target_machine_key="ip:m1",
            rule_names=[RULE_A],
            rule_class="exploit_attempt",
            starts_at=now - timedelta(days=2),
            expires_at=now - timedelta(hours=1) if expired else now + timedelta(days=5),
            created_by="analyst",
            revoked_at=now if revoked else None,
        )
        db.add(row)
        await db.commit()
        return int(row.id)

    return int(_do(client, work))


def _threats(client: TestClient, **params: Any) -> dict[str, Any]:
    res = client.get("/api/v1/threats", params=params)
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _parse(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


# ── The shape ──────────────────────────────────────────────────────────────


def test_an_empty_window_has_the_whole_shape(client: TestClient) -> None:
    body = _threats(client)
    assert set(body) == {"window", "rows", "authorized", "total", "campaigns"}
    assert body["rows"] == []
    assert body["authorized"] == []
    assert body["campaigns"] == []
    assert body["total"] == 0
    # The default window is the last 24 hours.
    since, until = _parse(body["window"]["since"]), _parse(body["window"]["until"])
    assert until - since == timedelta(hours=24)
    assert since.tzinfo is not None
    assert abs((datetime.now(UTC) - until).total_seconds()) < 60


def test_two_sources_on_one_target_merge_into_one_row(client: TestClient) -> None:
    _seed_hosts(client)
    stored = f"True positive. Impact: attempted. devbox {DEVBOX} to mainsrv (server) {SERVER}."
    newest = _seed_run(
        client,
        "t-1",
        minutes_ago=10,
        report={"impact": "attempted", "first_line": stored},
        actions=[_ESCALATE],
    )
    _seed_run(client, "t-2", src=LAPTOP, rule=RULE_B, minutes_ago=30, actions=[_ESCALATE])
    _seed_run(client, "t-3", minutes_ago=50)

    body = _threats(client)

    assert body["total"] == 3
    assert body["authorized"] == []
    assert len(body["rows"]) == 1
    row = body["rows"][0]
    assert set(row) == ROW_KEYS
    assert row["target"] == {
        "address": SERVER,
        "name": "mainsrv",
        "role": "server",
        "machineKey": "ip:m1",
    }
    # What happened, in the sentence of the newest run. The row states the
    # hosts and the impact in their own fields.
    assert row["headline"] == STORY
    assert row["impact"] == "attempted"
    assert (row["runs"], row["alertRuns"], row["findingRuns"]) == (3, 3, 0)
    assert row["sources"] == [
        {"address": DEVBOX, "name": "devbox"},
        {"address": LAPTOP, "name": None},
    ]
    assert row["sourcesMore"] == 0
    assert row["rules"] == [RULE_A, RULE_B]
    assert row["rulesMore"] == 0
    assert row["waitingActions"] == 2
    assert row["newestInvestigationId"] == newest
    assert _parse(row["firstSeen"]) < _parse(row["lastSeen"])

    href = urlparse(row["investigationsHref"])
    assert href.path == "/investigations"
    query = parse_qs(href.query)
    assert query["verdict"] == ["true_positive"]
    assert query["entity"] == [SERVER]
    assert query["entity_label"] == ["mainsrv"]
    assert query["range"] == ["custom"]
    assert query["from"] == [body["window"]["since"]]
    assert query["to"] == [body["window"]["until"]]


def test_an_address_and_a_name_of_one_machine_merge(client: TestClient) -> None:
    """Three runs name one machine three ways: its first address, its second
    address, and its host name on a host log with no destination."""
    _seed_hosts(client)
    _seed_run(client, "m-1", dst=SERVER, minutes_ago=10)
    _seed_run(client, "m-2", dst=SERVER_2, minutes_ago=20)
    _seed_run(client, "m-3", src=None, dst=None, host_name="mainsrv", minutes_ago=30)
    # Negative control: an address the Hosts data does not hold stays its own row.
    _seed_run(client, "m-4", dst=OTHER, minutes_ago=40)

    rows = _threats(client)["rows"]

    assert [(r["target"]["machineKey"], r["runs"]) for r in rows] == [("ip:m1", 3), (None, 1)]
    assert rows[0]["target"]["address"] == SERVER
    assert rows[1]["target"] == {"address": OTHER, "name": None, "role": None, "machineKey": None}
    assert "()" not in rows[1]["headline"]


def test_the_rows_are_in_the_order_of_impact_then_waiting_actions_then_time(
    client: TestClient,
) -> None:
    targets = {
        "none": "10.20.31.1",
        "old": "10.20.31.2",
        "sent": "10.20.31.3",
        "worked": "10.20.31.4",
        "sent-waits": "10.20.31.5",
        "sent-new": "10.20.31.6",
    }
    _seed_run(client, "o-1", dst=targets["none"], report={"impact": "none"}, minutes_ago=1)
    _seed_run(client, "o-2", dst=targets["old"], minutes_ago=2)
    _seed_run(client, "o-3", dst=targets["sent"], report={"impact": "attempted"}, minutes_ago=30)
    _seed_run(client, "o-4", dst=targets["worked"], report={"impact": "succeeded"}, minutes_ago=50)
    _seed_run(
        client,
        "o-5",
        dst=targets["sent-waits"],
        report={"impact": "attempted"},
        actions=[_ESCALATE],
        minutes_ago=40,
    )
    _seed_run(client, "o-6", dst=targets["sent-new"], report={"impact": "attempted"}, minutes_ago=5)
    # The worst impact of a group decides: one succeeded run among none runs.
    _seed_run(client, "o-7", dst=targets["worked"], report={"impact": "none"}, minutes_ago=3)

    rows = _threats(client)["rows"]

    assert [(r["target"]["address"], r["impact"]) for r in rows] == [
        (targets["worked"], "succeeded"),
        (targets["sent-waits"], "attempted"),
        (targets["sent-new"], "attempted"),
        (targets["sent"], "attempted"),
        # A true positive that states no impact reads unknown.
        (targets["old"], "unknown"),
        (targets["none"], "none"),
    ]


def test_an_alert_run_and_a_finding_run_both_count(client: TestClient) -> None:
    _seed_run(client, "k-1", minutes_ago=20)
    finding = _seed_run(
        client,
        "k-doc-1",
        rule="Exploit requests to the web server",
        finding=("01HUNT0000000000000000000", 0),
        minutes_ago=10,
    )

    body = _threats(client)

    assert body["total"] == 2
    row = body["rows"][0]
    assert (row["runs"], row["alertRuns"], row["findingRuns"]) == (2, 1, 1)
    assert row["newestInvestigationId"] == finding
    assert row["rules"] == ["Exploit requests to the web server", RULE_A]


def test_the_sources_and_the_rules_are_capped(client: TestClient) -> None:
    for i in range(7):
        _seed_run(client, f"c-{i}", src=f"10.40.51.{i + 1}", rule=f"ET Rule {i}", minutes_ago=i + 1)

    row = _threats(client)["rows"][0]

    assert [s["address"] for s in row["sources"]] == [f"10.40.51.{i + 1}" for i in range(5)]
    assert row["sourcesMore"] == 2
    assert row["rules"] == ["ET Rule 0", "ET Rule 1", "ET Rule 2"]
    assert row["rulesMore"] == 4


def test_the_event_time_is_the_seen_time_when_the_run_has_it(client: TestClient) -> None:
    stored_at = datetime.now(UTC) - timedelta(minutes=300)
    _seed_run(
        client,
        "e-1",
        minutes_ago=10,
        report={"event_time": stored_at.isoformat()},
    )
    # A run of an older release: the time of its alert is in its context event.
    _seed_run(client, "e-2", minutes_ago=20, event_minutes_ago=200)
    # A run with no event time: the run time.
    _seed_run(client, "e-3", minutes_ago=30)

    row = _threats(client)["rows"][0]

    assert abs((_parse(row["firstSeen"]) - stored_at).total_seconds()) < 2
    last = datetime.now(UTC) - timedelta(minutes=30)
    assert abs((_parse(row["lastSeen"]) - last).total_seconds()) < 5
    assert _parse(row["lastSeen"]).tzinfo is not None


# ── What does not count ────────────────────────────────────────────────────


def test_a_replaced_run_a_replay_and_a_synthetic_run_are_not_counted(client: TestClient) -> None:
    """Negative controls. Each of these rows is a true positive in the store."""
    kept = _seed_run(client, "x-1", minutes_ago=10)
    # An older true positive of the same alert: the newer run replaced it.
    _seed_run(client, "x-1", minutes_ago=60)
    # A true positive that a newer false positive of its alert replaced.
    _seed_run(client, "x-2", minutes_ago=50)
    _seed_run(client, "x-2", verdict="false_positive", minutes_ago=5)
    # A backtest replay and a synthetic run.
    _seed_run(client, "x-3", started_by="backtest", minutes_ago=15)
    _seed_run(client, "x-4", synthetic=True, minutes_ago=15)
    # An older run of one finding, replaced by a newer run of that finding.
    _seed_run(client, "x-doc", finding=("01HUNT0000000000000000001", 2), minutes_ago=70)
    newest_finding = _seed_run(
        client, "x-doc", finding=("01HUNT0000000000000000001", 2), minutes_ago=8
    )
    # Verdicts that are no true positive.
    _seed_run(client, "x-5", verdict="false_positive", minutes_ago=12)
    _seed_run(client, "x-6", verdict="needs_more_info", minutes_ago=12)
    # A pipeline error that holds a true positive verdict.
    _seed_run(
        client,
        "x-7",
        minutes_ago=12,
        report={"resolution": {"provenance": "pipeline_fallback"}},
    )

    body = _threats(client)

    assert body["total"] == 2
    assert len(body["rows"]) == 1
    row = body["rows"][0]
    assert (row["runs"], row["alertRuns"], row["findingRuns"]) == (2, 1, 1)
    assert row["newestInvestigationId"] == newest_finding
    assert kept != newest_finding


def test_a_run_that_a_follow_up_answered_is_not_counted(client: TestClient) -> None:
    answered = _seed_run(client, "f-1", minutes_ago=30)
    answer = _seed_run(client, "f-2", verdict="false_positive", minutes_ago=5)

    async def link(db: Any) -> None:
        await inv_svc.record_follow_up(db, answered, follow_up_id=answer, requested_by="analyst")

    _do(client, link)
    assert _threats(client)["total"] == 0


# ── Authorized activity ────────────────────────────────────────────────────


def test_a_fully_authorized_group_moves_to_authorized(client: TestClient) -> None:
    _seed_hosts(client)
    active = _seed_authorization(client, "exploit test")
    expired = _seed_authorization(client, "old test", expired=True)
    _seed_run(client, "a-1", authorization=active, actions=[_ESCALATE], minutes_ago=10)
    _seed_run(client, "a-2", authorization=active, actions=[_ESCALATE], minutes_ago=20)
    _seed_run(client, "a-3", authorization=expired, minutes_ago=30)
    # Another target with one unmarked run stays a row.
    _seed_run(client, "a-4", dst=OTHER, minutes_ago=40)

    body = _threats(client)

    assert body["total"] == 4
    assert [r["target"]["address"] for r in body["rows"]] == [OTHER]
    assert [(a["authorization"]["label"], a["runs"]) for a in body["authorized"]] == [
        ("exploit test", 2),
        ("old test", 1),
    ]
    first = body["authorized"][0]
    assert set(first) == {"authorization", "target", "direction", "runs", "lastSeen", "runsHref"}
    assert first["direction"] == "inbound"
    assert set(first["authorization"]) == {"id", "label", "state", "expiresAt"}
    assert first["authorization"]["id"] == active
    assert first["authorization"]["state"] == "active"
    assert _parse(first["authorization"]["expiresAt"]).tzinfo is not None
    assert first["target"]["machineKey"] == "ip:m1"
    assert first["runsHref"] == f"/investigations?authorization={active}&range=all"
    assert body["authorized"][1]["authorization"]["state"] == "expired"


def test_a_group_with_one_unmarked_run_stays_in_rows(client: TestClient) -> None:
    """Negative control. One run of the group is outside every authorization,
    so the group needs the analyst. Only its unmarked run waits on an action."""
    mark = _seed_authorization(client)
    _seed_run(client, "u-1", authorization=mark, actions=[_ESCALATE], minutes_ago=5)
    _seed_run(client, "u-2", authorization=mark, actions=[_ESCALATE], minutes_ago=15)
    unmarked = _seed_run(client, "u-3", src=LAPTOP, actions=[_ESCALATE], minutes_ago=25)

    body = _threats(client)

    assert body["authorized"] == []
    assert body["total"] == 3
    row = body["rows"][0]
    assert row["runs"] == 3
    assert row["waitingActions"] == 1
    # The row opens on the run that needs the analyst.
    assert row["newestInvestigationId"] == unmarked
    # The row states how many of its runs an authorization holds, and which.
    assert row["authorizedRuns"] == 2
    assert len(row["authorizations"]) == 1
    entry = row["authorizations"][0]
    assert set(entry) == {"id", "label", "state", "expiresAt", "runs", "runsHref"}
    assert (entry["id"], entry["label"], entry["state"], entry["runs"]) == (
        mark,
        "exploit test",
        "active",
        2,
    )
    assert _parse(entry["expiresAt"]).tzinfo is not None
    assert entry["runsHref"] == f"/investigations?authorization={mark}&range=all"


def test_a_row_lists_at_most_three_authorizations_the_most_runs_first(
    client: TestClient,
) -> None:
    marks = [_seed_authorization(client, f"test {n}") for n in range(4)]
    minutes = 5
    for count, mark in zip((1, 3, 2, 1), marks, strict=True):
        for _ in range(count):
            _seed_run(client, f"m-{minutes}", authorization=mark, minutes_ago=minutes)
            minutes += 5
    _seed_run(client, "m-open", src=LAPTOP, minutes_ago=minutes)

    row = _threats(client)["rows"][0]

    assert row["authorizedRuns"] == 7
    assert [(a["label"], a["runs"]) for a in row["authorizations"]] == [
        ("test 1", 3),
        ("test 2", 2),
        ("test 0", 1),
    ]


def test_a_revoked_authorization_marks_nothing(client: TestClient) -> None:
    """Negative control: after a revoke the run gets normal handling."""
    revoked = _seed_authorization(client, revoked=True)
    _seed_run(client, "r-1", authorization=revoked, actions=[_ESCALATE], minutes_ago=5)

    body = _threats(client)

    assert body["authorized"] == []
    assert len(body["rows"]) == 1
    assert body["rows"][0]["waitingActions"] == 1
    assert body["rows"][0]["authorizedRuns"] == 0
    assert body["rows"][0]["authorizations"] == []


# ── The filters ────────────────────────────────────────────────────────────


def test_the_host_filter_takes_a_machine_key_an_address_or_a_name(client: TestClient) -> None:
    _seed_hosts(client)
    _seed_run(client, "h-1", dst=SERVER, minutes_ago=10)
    _seed_run(client, "h-2", dst=SERVER_2, minutes_ago=20)
    _seed_run(client, "h-3", dst=OTHER, minutes_ago=30)

    for value in ("ip:m1", SERVER, SERVER_2, "mainsrv"):
        body = _threats(client, host=value)
        assert [r["target"]["machineKey"] for r in body["rows"]] == ["ip:m1"], value
        assert body["rows"][0]["runs"] == 2
        # The total is the total of the host.
        assert body["total"] == 2

    other = _threats(client, host=OTHER)
    assert [r["target"]["address"] for r in other["rows"]] == [OTHER]
    assert other["total"] == 1

    # Negative control: a host that no run names has no row and no count.
    nobody = _threats(client, host="10.20.30.250")
    assert nobody["rows"] == []
    assert nobody["total"] == 0
    assert _threats(client)["total"] == 3


def test_the_host_filter_also_keeps_the_runs_that_the_host_is_the_source_of(
    client: TestClient,
) -> None:
    """A host that connects to a command server is the source of its true
    positive. Its page must not read as clear. An outbound run merges under
    its internal source."""
    _seed_hosts(client)
    _seed_run(client, "s-1", src=DEVBOX, dst=C2, minutes_ago=10)
    _seed_run(client, "s-2", src=LAPTOP, dst=C2, minutes_ago=20)
    _seed_run(client, "s-3", src=LAPTOP, dst=SERVER, minutes_ago=30)

    body = _threats(client, host=DEVBOX)

    assert body["total"] == 1
    assert [r["target"]["address"] for r in body["rows"]] == [DEVBOX]
    assert body["rows"][0]["direction"] == "outbound"
    assert body["rows"][0]["runs"] == 1
    assert body["rows"][0]["sources"] == [{"address": C2, "name": None}]
    # The same host by its machine key.
    assert _threats(client, host="agent:d1")["total"] == 1
    # The external end filters too: two hosts connect to it.
    assert _threats(client, host=C2)["total"] == 2
    # Negative control: the other source of that target is not this host.
    assert _threats(client, host=SERVER)["total"] == 1


def test_an_outbound_run_merges_under_its_internal_source(client: TestClient) -> None:
    """The row names the host under threat. For an internal host that
    connects to an external address, that host is the source."""
    _seed_hosts(client)
    _seed_run(client, "o-1", src=DEVBOX, dst=C2, minutes_ago=10)
    _seed_run(client, "o-2", src=DEVBOX, dst="198.51.100.9", minutes_ago=20)

    rows = _threats(client)["rows"]

    assert len(rows) == 1
    row = rows[0]
    assert row["direction"] == "outbound"
    assert row["target"]["address"] == DEVBOX
    assert row["target"]["machineKey"] == "agent:d1"
    assert [s["address"] for s in row["sources"]] == [C2, "198.51.100.9"]
    assert parse_qs(urlparse(row["investigationsHref"]).query)["entity"] == [DEVBOX]


def test_two_internal_hosts_keep_the_destination_as_the_target(client: TestClient) -> None:
    """Negative control: an internal destination stays the target, and an
    external source attacking it is inbound."""
    _seed_hosts(client)
    _seed_run(client, "i-1", src=DEVBOX, dst=SERVER, minutes_ago=10)
    _seed_run(client, "i-2", src=C2, dst=SERVER, minutes_ago=20)
    # The inbound runs and the outbound runs of one machine are two rows.
    _seed_run(client, "i-3", src=SERVER, dst="198.51.100.9", minutes_ago=30)

    rows = _threats(client)["rows"]

    by_direction = {r["direction"]: r for r in rows}
    assert set(by_direction) == {"inbound", "outbound"}
    inbound = by_direction["inbound"]
    assert inbound["target"]["address"] == SERVER
    assert [s["address"] for s in inbound["sources"]] == [DEVBOX, C2]
    assert inbound["runs"] == 2
    outbound = by_direction["outbound"]
    assert outbound["target"]["machineKey"] == "ip:m1"
    assert [s["address"] for s in outbound["sources"]] == ["198.51.100.9"]


def test_an_authorized_outbound_group_folds_with_its_direction(client: TestClient) -> None:
    _seed_hosts(client)
    active = _seed_authorization(client, "beacon test")
    _seed_run(client, "ao-1", src=DEVBOX, dst=C2, authorization=active, minutes_ago=10)

    body = _threats(client)

    assert body["rows"] == []
    assert [(a["direction"], a["target"]["address"]) for a in body["authorized"]] == [
        ("outbound", DEVBOX)
    ]


def test_the_window_bounds_are_naive_utc(client: TestClient) -> None:
    """The store holds naive UTC. A bound with an offset names the same instant."""
    inside = _seed_run(client, "w-1", minutes_ago=90)
    _seed_run(client, "w-2", dst=OTHER, minutes_ago=200)
    now = datetime.now(UTC)
    since = now - timedelta(minutes=120)
    until = now - timedelta(minutes=60)

    def ids(**params: Any) -> list[str]:
        return [r["newestInvestigationId"] for r in _threats(client, **params)["rows"]]

    aware = {"since": since.isoformat(), "until": until.isoformat()}
    naive = {
        "since": since.replace(tzinfo=None).isoformat(),
        "until": until.replace(tzinfo=None).isoformat(),
    }
    # The same instants, written with an offset of five hours.
    shifted_zone = datetime.now(UTC).astimezone().tzinfo
    plus_five = {
        "since": since.astimezone(_zone(5)).isoformat(),
        "until": until.astimezone(_zone(5)).isoformat(),
    }
    assert shifted_zone is not None
    assert ids(**aware) == [inside]
    assert ids(**naive) == [inside]
    assert ids(**plus_five) == [inside]
    body = _threats(client, **plus_five)
    assert _parse(body["window"]["since"]) == since
    assert _parse(body["window"]["until"]) == until
    assert body["window"]["since"].endswith("+00:00")
    # A window that ends before the run holds nothing.
    assert ids(since=(now - timedelta(minutes=80)).isoformat()) == []
    # No lower bound given: the window is the 24 hours before the upper bound.
    assert len(ids(until=now.isoformat())) == 2

    res = client.get(
        "/api/v1/threats", params={"since": until.isoformat(), "until": since.isoformat()}
    )
    assert res.status_code == 422


def _zone(hours: int) -> Any:
    from datetime import timezone

    return timezone(timedelta(hours=hours))


def test_the_rows_are_capped_at_fifty(client: TestClient) -> None:
    async def many(db: Any) -> None:
        now = utcnow()
        for i in range(55):
            db.add(
                Investigation(
                    id=f"01CAP{i:021d}",
                    alert_es_id=f"cap-{i}",
                    rule_name=RULE_A,
                    verdict="true_positive",
                    confidence=0.8,
                    status="complete",
                    started_by="auto-triage",
                    src_ip=DEVBOX,
                    dest_ip=f"10.20.40.{i + 1}",
                    report={"verdict": "true_positive"},
                    is_fallback=False,
                    created_at=now - timedelta(minutes=i + 1),
                    finished_at=now - timedelta(minutes=i + 1),
                )
            )
        await db.commit()

    _do(client, many)
    body = _threats(client)
    assert len(body["rows"]) == 50
    assert body["total"] == 55


# ── The headline of an older Oracle run ────────────────────────────────────


def _run_text(rationale: str | None, *, summary: str | None = None, rule: str = RULE_A) -> Any:
    return SimpleNamespace(rationale=rationale, summary=summary, rule_name=rule)


def test_the_oracle_tag_goes_from_the_start_of_the_headline() -> None:
    inv = _run_text("[Oracle adjudicated] The host ran a broad Nmap sweep across internal hosts.")
    assert _what_happened(inv, {}) == "The host ran a broad Nmap sweep across internal hosts."


@pytest.mark.parametrize(
    "said",
    [
        "[Oracle adjudicated] The claim holds: the workstation ran a broad Nmap sweep, and the "
        "local needs_more_info verdict is too weak for the records in hand",
        "The claim holds, so the local verdict stands.",
        "The model said false_positive, and the records show an exploit.",
        "The Oracle moved the run from inconclusive to a true positive.",
    ],
)
def test_a_headline_about_the_verdict_states_the_rule_name(said: str) -> None:
    assert _what_happened(_run_text(said), {}) == RULE_A
    # A finding run states its finding title, which the run keeps as its rule name.
    title = "Broad Nmap sweep from one workstation"
    assert _what_happened(_run_text(said, rule=title), {}) == title


def test_a_headline_about_the_traffic_stays() -> None:
    """Negative control: a sentence with no verdict talk and no tag stays whole."""
    said = "The captured payloads confirm real exploit attempts against the web server."
    assert _what_happened(_run_text(said), {}) == said
    # A summary with a verdict word in a plain sense stays too.
    assert _what_happened(_run_text(None, summary="The true positive rate is high. More."), {}) == (
        "The true positive rate is high."
    )
    # With no rule name, the cleaned sentence stays.
    talk = "[Oracle adjudicated] The local verdict is too weak."
    assert _what_happened(_run_text(talk, rule=""), {}) == "The local verdict is too weak."


# ── A headline that only says the claim is correct (production, 2026-11-13) ───


@pytest.mark.parametrize(
    "sentence",
    [
        "The finding's core claim is correct",
        "The finding's claim is confirmed.",
        "The claim holds: the source ran a scan.",
    ],
)
def test_a_sentence_about_the_claim_gives_way_to_the_finding_title(sentence: str) -> None:
    from types import SimpleNamespace

    from soc_ai.api.webui.routes_threats import _what_happened

    run = SimpleNamespace(rationale=sentence, summary="", rule_name="File read returns the map")
    assert _what_happened(run, {}) == "File read returns the map"


@pytest.mark.parametrize(
    "sentence",
    [
        "The 200 responses carry file-sized bodies, so the file read succeeded.",
        "The server confirmed the upload with HTTP 200.",
        "The finding documents show 23 reads of the map file.",
    ],
)
def test_a_sentence_that_states_what_happened_stays(sentence: str) -> None:
    from types import SimpleNamespace

    from soc_ai.api.webui.routes_threats import _what_happened

    run = SimpleNamespace(rationale=sentence, summary="", rule_name="File read returns the map")
    assert _what_happened(run, {}) == sentence


# ── The campaigns of the window (S5) ──────────────────────────────────────

CAMPAIGN_ROW_KEYS = {
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
    "authorization",
    "beyond",
    "case",
}
THREAT_CAMPAIGN_KEYS = CAMPAIGN_ROW_KEYS | {"investigations", "waiting", "authorized"}


def _seed_campaign(
    client: TestClient,
    run_ids: list[str],
    *,
    title: str = "devbox against mainsrv",
    stage: str | None = "access",
    hours_ago: float = 1.0,
    parties: dict[str, str] | None = None,
    status: str = "active",
) -> int:
    """One campaign row over stored runs, written as a rebuild writes it."""
    from soc_ai.store.models import Campaign, CampaignMember, CampaignParty

    async def work(db: Any) -> int:
        last = utcnow() - timedelta(hours=hours_ago)
        row = Campaign(
            status=status,
            seed_run_id=run_ids[0],
            title=title,
            bottom_line="The source host sent exploit requests to the web server.",
            stage=stage,
            first_event=last - timedelta(hours=2),
            last_event=last,
            member_count=len(run_ids),
            detail={},
            built_at=utcnow(),
        )
        db.add(row)
        await db.flush()
        for key, role in (parties or {"agent:d1": "actor", "ip:m1": "target"}).items():
            db.add(
                CampaignParty(
                    campaign_id=row.id,
                    machine_key=key,
                    role=role,
                    addresses=[],
                    member_runs=len(run_ids),
                    beyond=False,
                )
            )
        for run_id in run_ids:
            db.add(
                CampaignMember(
                    campaign_id=row.id,
                    run_id=run_id,
                    link="actor",
                    evidence={},
                    direction="inbound",
                    verdict_differs=False,
                    actor_key="agent:d1",
                    target_key="ip:m1",
                )
            )
        await db.commit()
        return int(row.id)

    return int(_do(client, work))


def test_a_campaign_leads_and_holds_its_investigations_with_three_counts(
    client: TestClient,
) -> None:
    _seed_hosts(client)
    mark = _seed_authorization(client, "exploit test")
    waits = _seed_run(client, "c-1", actions=[_ESCALATE], minutes_ago=10)
    marked = _seed_run(client, "c-2", authorization=mark, actions=[_ESCALATE], minutes_ago=20)
    quiet = _seed_run(client, "c-3", minutes_ago=30)
    # A run of the campaign outside the window counts in no number.
    old = _seed_run(client, "c-4", minutes_ago=60 * 30)
    alone = _seed_run(client, "x-1", dst=OTHER, actions=[_ESCALATE], minutes_ago=40)
    campaign = _seed_campaign(client, [waits, marked, quiet, old])

    body = _threats(client)

    assert body["total"] == 4
    (entry,) = body["campaigns"]
    assert set(entry) == THREAT_CAMPAIGN_KEYS
    assert entry["id"] == campaign
    assert entry["status"] == "open"
    assert entry["stage"] == "access"
    # No action of an investigation that the campaign holds waits: the
    # analyst decides on the campaign.
    assert (entry["investigations"], entry["waiting"], entry["authorized"]) == (3, 0, 1)
    assert [p["machineKey"] for p in entry["actors"]] == ["agent:d1"]
    assert [p["machineKey"] for p in entry["targets"]] == ["ip:m1"]
    # The rows hold only the investigations in no campaign.
    assert [r["newestInvestigationId"] for r in body["rows"]] == [alone]
    assert body["authorized"] == []


def test_the_campaigns_go_worst_stage_first_then_newest_last_event(client: TestClient) -> None:
    _seed_hosts(client)
    runs = [_seed_run(client, f"o-{n}", minutes_ago=10 + n) for n in range(4)]
    access_new = _seed_campaign(client, [runs[0]], stage="access", hours_ago=1)
    movement_old = _seed_campaign(client, [runs[1]], stage="movement", hours_ago=20)
    none_stage = _seed_campaign(client, [runs[2]], stage=None, hours_ago=0.5)
    access_old = _seed_campaign(client, [runs[3]], stage="access", hours_ago=10)

    body = _threats(client)

    assert [c["id"] for c in body["campaigns"]] == [
        movement_old,
        access_new,
        access_old,
        none_stage,
    ]
    assert body["rows"] == []
    assert body["total"] == 4


def test_a_withdrawn_or_merged_campaign_is_not_listed_and_its_runs_stay_rows(
    client: TestClient,
) -> None:
    _seed_hosts(client)
    first = _seed_run(client, "w-1", minutes_ago=10)
    second = _seed_run(client, "w-2", dst=OTHER, minutes_ago=20)
    _seed_campaign(client, [first], status="withdrawn")
    _seed_campaign(client, [second], status="merged")

    body = _threats(client)

    assert body["campaigns"] == []
    assert sorted(r["newestInvestigationId"] for r in body["rows"]) == sorted([first, second])
    assert body["total"] == 2


def test_a_campaign_with_no_true_positive_in_the_window_is_not_listed(
    client: TestClient,
) -> None:
    _seed_hosts(client)
    old = _seed_run(client, "p-1", minutes_ago=60 * 30)
    _seed_campaign(client, [old], hours_ago=29)
    body = _threats(client)
    assert body["campaigns"] == []
    assert body["total"] == 0


def test_the_host_filter_keeps_the_campaigns_where_the_machine_is_a_party(
    client: TestClient,
) -> None:
    _seed_hosts(client)
    member = _seed_run(client, "h-1", minutes_ago=10)
    campaign = _seed_campaign(client, [member])
    other = _seed_run(client, "h-2", src=LAPTOP, dst=OTHER, minutes_ago=20)
    elsewhere = _seed_campaign(
        client, [other], title="laptop against a target", parties={"ip:zz": "target"}
    )

    on_server = _threats(client, host="ip:m1")
    assert [c["id"] for c in on_server["campaigns"]] == [campaign]
    assert on_server["rows"] == []
    assert on_server["total"] == 1
    on_devbox = _threats(client, host=DEVBOX)
    assert [c["id"] for c in on_devbox["campaigns"]] == [campaign]
    # The host is no party of the other campaign. Its investigation stays a row.
    on_other = _threats(client, host=OTHER)
    assert elsewhere not in [c["id"] for c in on_other["campaigns"]]
    assert on_other["campaigns"] == []
    assert [r["newestInvestigationId"] for r in on_other["rows"]] == [other]
    assert on_other["total"] == 1


def test_a_campaign_that_the_rebuild_builds_leads_the_panel(client: TestClient) -> None:
    from soc_ai.campaigns import service as campaign_svc

    from tests.test_campaign_facts import seed_hosts, seed_run

    async def work(db: Any) -> list[str]:
        await seed_hosts(db)
        runs = [
            await seed_run(db, f"alert-000{n}", event_hours_ago=4 - n, created_minutes_ago=40 - n)
            for n in (1, 2, 3)
        ]
        await campaign_svc.rebuild(db)
        return runs

    runs = _do(client, work)
    body = _threats(client)
    (entry,) = body["campaigns"]
    assert entry["investigations"] == len(runs)
    assert entry["members"] == len(runs)
    assert body["rows"] == []
    assert body["total"] == len(runs)
