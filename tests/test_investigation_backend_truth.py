"""Backend truth for investigations (dogfood 2026-10-01).

- RL3: the host context names each end of the alert and splits its alerts by side.
- RL5: the stored detector type follows the alert document, the same way the
  Alerts grid derives it; a row stored with the old default is corrected on read.
- D1: the bell's failed-triage half lists only primary runs, and the detail
  response names the newer run that superseded a failed one.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.recorder import InvestigationRecorder
from soc_ai.config import Settings
from soc_ai.so_client.fields import detection_kind, detection_kind_of_source
from soc_ai.so_client.models import SoAlert
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation, InvestigationEvent

# A Sigma detection in the shape Security Onion 3.x writes it: the detection
# identity at the top level, the matched event nested under event_data.
SIGMA_HIT: dict[str, Any] = {
    "_id": "sigma-doc-1",
    "_source": {
        "@timestamp": "2026-09-30T10:00:00.000Z",
        "rule": {"name": "Weak Encryption Enabled and Kerberoast", "uuid": "r-1"},
        "event": {"module": "sigma", "dataset": "sigma.alert", "severity_label": "high"},
        "sigma_level": "high",
        "event_data": {
            "source": {"ip": "192.0.2.20"},
            "destination": {"ip": "192.0.2.40"},
            "event": {"module": "windows", "dataset": "windows.security"},
        },
    },
}


def _sigma_alert_payload() -> dict[str, Any]:
    return SoAlert.from_es_hit(SIGMA_HIT).model_dump(mode="json")


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    from soc_ai.main import create_app

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        patch("soc_ai.api.webui._timeline._alert_currently_acked", AsyncMock(return_value=False)),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _seed(client: TestClient, rows: list[Investigation], events: list[InvestigationEvent]) -> None:
    async def _go() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            db.add_all(rows)
            await db.flush()
            db.add_all(events)
            await db.commit()

    asyncio.run(_go())


def _stored_kind(client: TestClient, inv_id: str) -> str:
    async def _go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            row = await db.get(Investigation, inv_id)
            assert row is not None
            return row.kind

    return asyncio.run(_go())


# ── RL5: detector type ───────────────────────────────────────────────────────


def test_the_grid_and_the_row_share_one_derivation() -> None:
    assert detection_kind_of_source(SIGMA_HIT["_source"]) == "sigma"
    assert detection_kind("sigma.alert") == "sigma"
    assert detection_kind("suricata.alert") == "suricata"
    assert detection_kind("zeek.notice") == "notice"
    # A Sigma document that lost its dataset still names its module.
    assert detection_kind(None, "sigma") == "sigma"
    assert detection_kind(None, None, sigma_marker=True) == "sigma"
    # A document that names no detector is a generic alert, never "suricata".
    assert detection_kind("system.security", "windows") == "alert"
    from soc_ai.webui.alerts_query import _kind_for

    assert _kind_for("sigma.alert") == detection_kind("sigma.alert")
    assert _kind_for(None, "sigma") == "sigma"


async def test_the_recorder_stores_sigma_for_a_sigma_document(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    rec = InvestigationRecorder(maker, alert_id="sigma-doc-1", started_by="t")
    inv_id = await rec.start()
    assert inv_id is not None
    await rec.record("enriched_alert_context", 1, {"alert": _sigma_alert_payload()})
    async with maker() as db:
        row = await db.get(Investigation, inv_id)
        assert row is not None
        assert row.kind == "sigma"
    await engine.dispose()


async def test_the_recorder_keeps_a_promoted_kind(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    rec = InvestigationRecorder(maker, alert_id="sigma-doc-1", started_by="t", kind="lead")
    inv_id = await rec.start()
    assert inv_id is not None
    await rec.record("enriched_alert_context", 1, {"alert": _sigma_alert_payload()})
    async with maker() as db:
        row = await db.get(Investigation, inv_id)
        assert row is not None
        assert row.kind == "lead"
    await engine.dispose()


def test_the_list_corrects_a_stored_default_from_the_alert_context(client: TestClient) -> None:
    now = utcnow()
    rows = [
        Investigation(
            id="01KINDSIGMA000000000000000",
            alert_es_id="sigma-doc-1",
            started_by="t",
            kind="suricata",
            status="complete",
            verdict="false_positive",
            created_at=now - timedelta(minutes=3),
            finished_at=now - timedelta(minutes=2),
        ),
        Investigation(
            id="01KINDSURI0000000000000000",
            alert_es_id="suri-doc-1",
            started_by="t",
            kind="suricata",
            status="complete",
            verdict="false_positive",
            created_at=now - timedelta(minutes=5),
            finished_at=now - timedelta(minutes=4),
        ),
        # A promoted row anchored on a Sigma document keeps its kind.
        Investigation(
            id="01KINDLEAD0000000000000000",
            alert_es_id="sigma-doc-2",
            started_by="t",
            kind="lead",
            status="complete",
            verdict="true_positive",
            created_at=now - timedelta(minutes=7),
            finished_at=now - timedelta(minutes=6),
        ),
    ]
    events = [
        InvestigationEvent(
            investigation_id="01KINDSIGMA000000000000000",
            sequence=1,
            kind="enriched_alert_context",
            payload={"alert": _sigma_alert_payload()},
        ),
        InvestigationEvent(
            investigation_id="01KINDSURI0000000000000000",
            sequence=1,
            kind="enriched_alert_context",
            payload={"alert": {"id": "suri-doc-1", "event_dataset": "suricata.alert"}},
        ),
        InvestigationEvent(
            investigation_id="01KINDLEAD0000000000000000",
            sequence=1,
            kind="enriched_alert_context",
            payload={"alert": _sigma_alert_payload()},
        ),
    ]
    _seed(client, rows, events)
    resp = client.get("/api/v1/investigations?limit=50")
    assert resp.status_code == 200
    kinds = {r["id"]: r["kind"] for r in resp.json()["rows"]}
    assert kinds["01KINDSIGMA000000000000000"] == "sigma"
    assert kinds["01KINDSURI0000000000000000"] == "suricata"
    assert kinds["01KINDLEAD0000000000000000"] == "lead"
    # The correction is written back once.
    assert _stored_kind(client, "01KINDSIGMA000000000000000") == "sigma"
    detail = client.get("/api/v1/investigations/01KINDSIGMA000000000000000").json()
    assert detail["kind"] == "sigma"


# ── RL3: host context per end ────────────────────────────────────────────────


def test_detail_names_each_end_and_splits_its_alerts_by_side(client: TestClient) -> None:
    now = utcnow()
    _seed(
        client,
        [
            Investigation(
                id="01HOSTCTX00000000000000000",
                alert_es_id="doc-host",
                started_by="t",
                status="complete",
                verdict="false_positive",
                created_at=now,
                finished_at=now,
            )
        ],
        [
            InvestigationEvent(
                investigation_id="01HOSTCTX00000000000000000",
                sequence=1,
                kind="enriched_alert_context",
                payload={
                    "alert": {"id": "doc-host", "source_ip": "192.0.2.20"},
                    "host_alert_profile": {"ET SCAN probe": 7, "ET POLICY fetch": 2},
                    "host_alert_profiles": [
                        {
                            "ip": "192.0.2.20",
                            "end": "source",
                            "as_source": {"ET POLICY fetch": 2},
                            "as_destination": {},
                        },
                        {
                            "ip": "192.0.2.40",
                            "end": "destination",
                            "as_source": {},
                            "as_destination": {"ET SCAN probe": 7},
                        },
                    ],
                },
            )
        ],
    )
    body = client.get("/api/v1/investigations/01HOSTCTX00000000000000000").json()
    ends = {h["ip"]: h for h in body["hostContexts"]}
    assert ends["192.0.2.20"]["end"] == "source"
    assert [s["label"] for s in ends["192.0.2.20"]["asSource"]] == ["ET POLICY fetch"]
    # The other host's alerts never appear under this host.
    assert ends["192.0.2.20"]["asDestination"] == []
    assert [s["label"] for s in ends["192.0.2.40"]["asDestination"]] == ["ET SCAN probe"]


# ── D1: superseded failures ──────────────────────────────────────────────────


def _run(
    inv_id: str,
    alert: str,
    *,
    minutes_ago: int,
    status: str,
    verdict: str | None = None,
    subject: dict[str, Any] | None = None,
) -> Investigation:
    now = utcnow()
    return Investigation(
        id=inv_id,
        alert_es_id=alert,
        started_by="t",
        status=status,
        verdict=verdict,
        rule_name=f"Rule {alert}",
        created_at=now - timedelta(minutes=minutes_ago + 1),
        finished_at=now - timedelta(minutes=minutes_ago),
        subject_json=subject,
    )


def test_bell_lists_only_primary_failures_and_detail_links_the_newer_run(
    client: TestClient,
) -> None:
    rows = [
        # Alert A: two failures, then a later run settled it. Neither failure
        # is a standing fault.
        _run("01D1A1000000000000000000000", "alert-a", minutes_ago=30, status="error"),
        _run("01D1A2000000000000000000000", "alert-a", minutes_ago=20, status="error"),
        _run(
            "01D1A3000000000000000000000",
            "alert-a",
            minutes_ago=10,
            status="complete",
            verdict="false_positive",
        ),
        # Alert B: one failure, nothing after it. It stays.
        _run("01D1B1000000000000000000000", "alert-b", minutes_ago=15, status="error"),
        # A hunt-subject run that names alert B's document is not a run of
        # alert B. It must not hide B's failure: the negative control on the
        # path the primacy filter could miss.
        _run(
            "01D1B2000000000000000000000",
            "alert-b",
            minutes_ago=5,
            status="complete",
            verdict="false_positive",
            subject={"type": "hunt", "hunt_id": "h-1"},
        ),
        # Alert C: two failures, no success. The newest one is primary.
        _run("01D1C1000000000000000000000", "alert-c", minutes_ago=40, status="error"),
        _run("01D1C2000000000000000000000", "alert-c", minutes_ago=35, status="error"),
    ]
    _seed(client, rows, [])
    resp = client.get("/api/v1/notifications")
    assert resp.status_code == 200
    failed = {n["id"] for n in resp.json() if n["id"].startswith("inv-failed:")}
    assert failed == {
        "inv-failed:01D1B1000000000000000000000",
        "inv-failed:01D1C2000000000000000000000",
    }

    def superseded_by(inv_id: str) -> str | None:
        body = client.get(f"/api/v1/investigations/{inv_id}").json()
        value: str | None = body["supersededBy"]
        return value

    assert superseded_by("01D1A1000000000000000000000") == "01D1A3000000000000000000000"
    assert superseded_by("01D1A2000000000000000000000") == "01D1A3000000000000000000000"
    assert superseded_by("01D1A3000000000000000000000") is None
    assert superseded_by("01D1B1000000000000000000000") is None
    assert superseded_by("01D1C1000000000000000000000") == "01D1C2000000000000000000000"
    assert superseded_by("01D1C2000000000000000000000") is None
