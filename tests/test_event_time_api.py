"""The investigation page and the hunt page serve an Event timeline (change D).

The detail routes read the documents the run already stores and list them in
event time, with the waves. Every time here is relative to now. Every address
is TEST-NET and every uid is synthetic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        TestClient(create_app(), client=("testclient", 50000)) as c,
    ):
        yield c


def _base() -> datetime:
    return (datetime.now(UTC) - timedelta(days=4)).replace(microsecond=0)


def _doc(doc_id: str, at: datetime, **fields: Any) -> dict[str, Any]:
    return {"id": doc_id, "timestamp": at.isoformat(), **fields}


def _seed_run(
    client: TestClient,
    *,
    events: list[dict[str, Any]],
    report: dict[str, Any],
    status: str = "complete",
    **create: Any,
) -> str:
    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(
                db, alert_es_id="subjectConn00001", started_by="tester", **create
            )
            await inv_svc.append_events(db, inv.id, events)
            if status != "running":
                await inv_svc.finalize(
                    db,
                    inv.id,
                    status=status,
                    verdict="true_positive",
                    confidence=0.8,
                    rationale="r",
                    report=report,
                )
            return inv.id

    return asyncio.run(go())


def _subject_documents(base: datetime) -> list[dict[str, Any]]:
    exploit = base + timedelta(hours=22, minutes=27)
    # Newest first, the order the subject fetch gives.
    return [
        _doc(
            "subjectFiles0001",
            exploit + timedelta(minutes=1),
            event_dataset="zeek.files",
            zeek_files_mime_type="text/x-php",
        ),
        _doc(
            "subjectAlert0002",
            exploit + timedelta(seconds=20),
            event_dataset="suricata.alert",
            rule_name="ET EXPLOIT Example upload attempt",
            source_ip="192.0.2.11",
            destination_ip="198.51.100.20",
        ),
        _doc(
            "subjectAlert0001",
            exploit,
            event_dataset="suricata.alert",
            rule_name="ET EXPLOIT Example probe",
            source_ip="192.0.2.11",
            destination_ip="198.51.100.20",
        ),
        _doc(
            "subjectSsh000001",
            base + timedelta(minutes=5),
            event_dataset="zeek.ssh",
            zeek_ssh_auth_success=True,
            source_ip="192.0.2.10",
            destination_ip="198.51.100.20",
        ),
        _doc(
            "subjectConn00001",
            base,
            event_dataset="zeek.conn",
            source_ip="192.0.2.10",
            destination_ip="198.51.100.20",
            destination_port=22,
            zeek_conn_duration=3000.0,
        ),
    ]


def test_the_investigation_page_tells_the_hunt_subject_documents_in_event_time(
    client: TestClient,
) -> None:
    base = _base()
    docs = _subject_documents(base)
    cited = ["subjectConn00001", "subjectSsh000001", "subjectAlert0001", "subjectAlert0002"]
    inv_id = _seed_run(
        client,
        events=[
            {
                "sequence": 1,
                "kind": "enriched_alert_context",
                "payload": {
                    "alert": docs[-1],
                    "subject": "hunt",
                    "subject_findings": 1,
                    "subject_documents": docs,
                },
            }
        ],
        report={"verdict": "true_positive", "citations": cited},
        kind="hunt",
        subject={"type": "hunt", "hunt_id": "01JAB3C4D5E6F7G8H9J0K1M2N3", "objective": "o"},
    )

    body = client.get(f"/api/v1/investigations/{inv_id}").json()

    timeline = body["eventTimeline"]
    assert timeline["basis"] == "hunt_subject"
    ids = [e["id"] for e in timeline["entries"]]
    assert ids == [
        "subjectConn00001",
        "subjectSsh000001",
        "subjectAlert0001",
        "subjectAlert0002",
        "subjectFiles0001",
    ]
    assert timeline["waves"][0]["start"] == timeline["entries"][0]["at"]
    assert len(timeline["waves"]) == 2
    assert timeline["gapMinutes"] == 30
    assert {e["id"] for e in timeline["entries"] if e["cited"]} == set(cited)
    assert all(e["at"].endswith("Z") for e in timeline["entries"])


def _seed_hunt_with_findings(client: TestClient, findings: list[dict[str, Any]]) -> str:
    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            hunt = await hunt_svc.create(db, objective="o", started_by="tester", kind="scheduled")
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="n",
                report={"findings": findings, "narrative": "n"},
            )
            return hunt.id

    return asyncio.run(go())


def test_a_finding_run_lists_only_the_documents_of_its_finding(client: TestClient) -> None:
    """Prod, 2026-10-30: the run of finding F1 listed, as wave 6, an SSH
    session that finding F5 of the same hunt cited. A run that judges one
    finding lists that finding's documents and the documents its verdict
    cites. A legacy run of the same hunt, which judged the whole hunt, keeps
    every subject document."""
    base = _base()
    docs = _subject_documents(base)
    other = _doc(
        "otherFindingSsh1",
        base + timedelta(hours=40),
        event_dataset="zeek.ssh",
        source_ip="192.0.2.30",
        destination_ip="203.0.113.9",
    )
    own = ["subjectAlert0001", "subjectAlert0002", "subjectFiles0001"]
    hunt_id = _seed_hunt_with_findings(
        client,
        [
            {
                "title": "Exploit of the web server",
                "category": "threat",
                "citations": [*own, "t_query_events_oql:x"],
            },
            {
                "title": "Outbound SSH to a cloud host",
                "category": "observation",
                "citations": ["otherFindingSsh1"],
            },
        ],
    )
    events = [
        {
            "sequence": 1,
            "kind": "enriched_alert_context",
            "payload": {
                "alert": docs[2],
                "subject": "hunt",
                "subject_findings": 2,
                "subject_documents": [other, *docs],
            },
        }
    ]
    subject = {"type": "hunt", "hunt_id": hunt_id, "objective": "o", "finding_ordinals": [0, 1]}
    finding_run = _seed_run(
        client,
        events=events,
        report={"verdict": "true_positive", "citations": ["subjectConn00001"]},
        kind="hunt",
        hunt_id=hunt_id,
        finding_ordinal=0,
        subject={**subject, "judges": "finding"},
    )
    legacy_run = _seed_run(
        client,
        events=events,
        report={"verdict": "true_positive", "citations": ["subjectConn00001"]},
        kind="hunt",
        hunt_id=hunt_id,
        finding_ordinal=0,
        subject=subject,
    )

    finding_tl = client.get(f"/api/v1/investigations/{finding_run}").json()["eventTimeline"]
    assert finding_tl["basis"] == "finding"
    assert [e["id"] for e in finding_tl["entries"]] == ["subjectConn00001", *own]

    legacy_tl = client.get(f"/api/v1/investigations/{legacy_run}").json()["eventTimeline"]
    assert legacy_tl["basis"] == "hunt_subject"
    assert "otherFindingSsh1" in [e["id"] for e in legacy_tl["entries"]]


def test_a_running_run_and_a_single_document_run_carry_no_event_timeline(
    client: TestClient,
) -> None:
    base = _base()
    docs = _subject_documents(base)
    running = _seed_run(
        client,
        events=[
            {
                "sequence": 1,
                "kind": "enriched_alert_context",
                "payload": {"alert": docs[-1], "subject": "hunt", "subject_documents": docs},
            }
        ],
        report={},
        status="running",
    )
    assert client.get(f"/api/v1/investigations/{running}").json()["eventTimeline"] is None

    single = _seed_run(
        client,
        events=[{"sequence": 1, "kind": "enriched_alert_context", "payload": {"alert": docs[-1]}}],
        report={"verdict": "false_positive", "citations": ["alert.rule_name"]},
    )
    assert client.get(f"/api/v1/investigations/{single}").json()["eventTimeline"] is None


def test_a_label_with_a_credential_reads_scrubbed(client: TestClient) -> None:
    base = _base()
    login = _doc(
        "httpLogin000001",
        base + timedelta(minutes=3),
        event_dataset="zeek.http",
        zeek_http_method="POST",
        zeek_http_uri="/login.php?user=admin&password=Sup3rSecretValue",
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
    )
    inv_id = _seed_run(
        client,
        events=[
            {
                "sequence": 1,
                "kind": "enriched_alert_context",
                "payload": {"alert": _doc("subjectConn00001", base), "host_events": [login]},
            }
        ],
        report={"verdict": "true_positive", "citations": ["httpLogin000001"]},
    )

    body = client.get(f"/api/v1/investigations/{inv_id}").json()

    entries = body["eventTimeline"]["entries"]
    label = next(e["label"] for e in entries if e["id"] == "httpLogin000001")
    assert "Sup3rSecretValue" not in label
    assert label.startswith("POST /login.php?user=admin&password=")


def _seed_hunt(client: TestClient, *, status: str = "complete") -> str:
    base = _base()

    def hit(doc_id: str, at: datetime, dataset: str) -> dict[str, Any]:
        return {
            "_id": doc_id,
            "_source": {
                "@timestamp": at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "event": {"dataset": dataset},
                "source": {"ip": "192.0.2.10"},
                "destination": {"ip": "198.51.100.20"},
            },
        }

    events = [
        {"sequence": 1, "kind": "hunt_started", "payload": {"objective": "o"}},
        {
            "sequence": 2,
            "kind": "tool_call",
            "payload": {"tool_name": "t_query_events_oql", "args": {}, "tool_call_id": "q1"},
        },
        {
            "sequence": 3,
            "kind": "tool_result",
            "payload": {
                "tool_name": "t_query_events_oql",
                "tool_call_id": "q1",
                "result": {
                    "total": 3,
                    "hits": [
                        hit("huntShared00001", base + timedelta(hours=6), "zeek.http"),
                        hit("huntFirst000001", base, "zeek.conn"),
                        hit("huntThird000001", base + timedelta(hours=7), "suricata.alert"),
                    ],
                },
            },
        },
        {
            "sequence": 4,
            "kind": "tool_call",
            "payload": {
                "tool_name": "t_get_event_raw",
                "args": {"event_id": "huntRawDoc00001"},
                "tool_call_id": "r1",
            },
        },
        {
            "sequence": 5,
            "kind": "tool_result",
            "payload": {
                "tool_name": "t_get_event_raw",
                "tool_call_id": "r1",
                "result": {
                    "@timestamp": (base + timedelta(minutes=10)).isoformat(),
                    "event": {"dataset": "zeek.ssh"},
                },
            },
        },
        {
            "sequence": 6,
            "kind": "tool_result",
            "payload": {
                "tool_name": "t_beacon_profile",
                "tool_call_id": "b1",
                "result": {"sample_ids": ["huntSampleOnly1"]},
            },
        },
    ]
    report = {
        "findings": [
            "a stray non-dict entry",
            {
                "title": "Setup",
                "citations": ["huntFirst000001", "huntRawDoc00001", "huntShared00001"],
            },
            {"title": "Beacon", "citations": ["huntSampleOnly1"]},
            {"title": "Exploit", "citations": ["huntShared00001", "huntThird000001"]},
        ]
    }

    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            hunt = await hunt_svc.create(db, objective="hunt the web server", started_by="t")
            await hunt_svc.append_events(db, hunt.id, events)
            if status != "running":
                await hunt_svc.finalize(db, hunt.id, status=status, narrative="n", report=report)
            await db.commit()
            return hunt.id

    return asyncio.run(go())


def test_the_hunt_page_tells_the_cited_documents_in_event_time(client: TestClient) -> None:
    hunt_id = _seed_hunt(client)

    body = client.get(f"/api/v1/hunts/{hunt_id}").json()

    timeline = body["eventTimeline"]
    assert timeline["basis"] == "hunt"
    ids = [e["id"] for e in timeline["entries"]]
    assert ids == ["huntFirst000001", "huntRawDoc00001", "huntShared00001", "huntThird000001"]
    shared = next(e for e in timeline["entries"] if e["id"] == "huntShared00001")
    # Counted over the dict-only list the page numbers: Setup is F1, Exploit F3.
    assert shared["findings"] == [0, 2]
    assert timeline["untimed"] == 1
    assert len(body["findings"]) == 3

    running = _seed_hunt(client, status="running")
    assert client.get(f"/api/v1/hunts/{running}").json()["eventTimeline"] is None
