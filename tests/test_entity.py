"""Tests for the entity pivot page (E3.5) — read-model over investigations + hunts.

Covers the two bounded store queries (``investigations.for_entity``,
``hunts.findings_for_entity``) against a real migrated SQLite file, and the
``GET /entity/{value}`` endpoint that merges them into one newest-first timeline.
Mirrors tests/test_hunts_store.py (store) + tests/test_webui_api.py (endpoint).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


# ── store: investigations.for_entity ─────────────────────────────────────────


async def test_for_entity_matches_src_or_dst_newest_first(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # An investigation where the host is the SOURCE.
        a = await inv_svc.create(
            db, alert_es_id="ev-a", started_by="t", src_ip="10.0.0.5", dest_ip="8.8.8.8"
        )
        await inv_svc.finalize(db, a.id, status="complete", verdict="true_positive")
        # A later investigation where the SAME host is the DESTINATION.
        b = await inv_svc.create(
            db, alert_es_id="ev-b", started_by="t", src_ip="203.0.113.9", dest_ip="10.0.0.5"
        )
        await inv_svc.finalize(db, b.id, status="complete", verdict="false_positive")
        # An unrelated investigation that must NOT match.
        c = await inv_svc.create(
            db, alert_es_id="ev-c", started_by="t", src_ip="1.1.1.1", dest_ip="2.2.2.2"
        )
        await inv_svc.finalize(db, c.id, status="complete", verdict="true_positive")

        rows = await inv_svc.for_entity(db, "10.0.0.5")
        assert [r.id for r in rows] == [b.id, a.id]  # newest first, unrelated excluded

        # Bound honored.
        assert len(await inv_svc.for_entity(db, "10.0.0.5", limit=1)) == 1
        # Unknown entity → empty (not an error).
        assert await inv_svc.for_entity(db, "10.9.9.9") == []
        assert await inv_svc.for_entity(db, "") == []
    await engine.dispose()


# ── store: hunts.findings_for_entity ─────────────────────────────────────────

_REPORT = {
    "findings": [
        {
            "title": "Beaconing to rare external IP",
            "detail": "fin-ws-041 contacted 203.0.113.9 on a fixed 60s cadence.",
            "severity": "high",
            "category": "threat",
            "hosts": ["fin-ws-041"],
            "citations": ["es-abc"],
        },
        {
            "title": "Unrelated finding on another host",
            "detail": "noise",
            "severity": "low",
            "hosts": ["other-box"],
        },
    ],
    "narrative": "One host is beaconing.",
    "affected_hosts": ["fin-ws-041", "other-box"],
}


async def test_findings_for_entity_scans_reports_bounded(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="hunt for beaconing", started_by="admin")
        await hunt_svc.finalize(db, hunt.id, status="complete", report=_REPORT)

        found = await hunt_svc.findings_for_entity(db, "fin-ws-041")
        assert len(found) == 1  # only the finding naming this host
        assert found[0]["hunt_id"] == hunt.id
        assert found[0]["hunt_objective"] == "hunt for beaconing"
        assert found[0]["title"] == "Beaconing to rare external IP"
        assert found[0]["severity"] == "high"
        assert found[0]["category"] == "threat"
        assert found[0]["ts"] == hunt.created_at

        # A host named in NO finding → empty.
        assert await hunt_svc.findings_for_entity(db, "unknown-box") == []
        assert await hunt_svc.findings_for_entity(db, "") == []
        # A RUNNING hunt's (empty) report is skipped — scan is complete-only.
        running = await hunt_svc.create(db, objective="in flight", started_by="a")
        assert running.status == "running"
        assert await hunt_svc.findings_for_entity(db, "fin-ws-041") == found
    await engine.dispose()


# ── endpoint: GET /entity/{value} ────────────────────────────────────────────


def _seed_entity(client: TestClient, host: str) -> tuple[str, str, str]:
    """Seed 2 investigations touching ``host`` + 1 hunt whose finding names it.

    Returns (older_inv_id, newer_inv_id, hunt_id).
    """

    async def _seed() -> tuple[str, str, str]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            older = await inv_svc.create(
                db, alert_es_id="ev-old", started_by="t", src_ip=host, dest_ip="8.8.8.8"
            )
            older.rule_name = "ET MALWARE Beacon"
            await inv_svc.finalize(
                db, older.id, status="complete", verdict="false_positive", confidence=0.8
            )
            newer = await inv_svc.create(
                db, alert_es_id="ev-new", started_by="t", src_ip="203.0.113.9", dest_ip=host
            )
            newer.rule_name = "ET HUNTING curl UA"
            await inv_svc.finalize(
                db, newer.id, status="complete", verdict="true_positive", confidence=0.9
            )
            hunt = await hunt_svc.create(db, objective="beaconing sweep", started_by="a")
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                report={
                    "findings": [
                        {
                            "title": "Beaconing to rare IP",
                            "severity": "high",
                            "category": "threat",
                            "hosts": [host],
                        }
                    ]
                },
            )
            await db.commit()
            return older.id, newer.id, hunt.id

    return asyncio.run(_seed())


def test_entity_timeline_merges_investigations_and_findings(client: TestClient) -> None:
    host = "fin-ws-041"
    older_id, newer_id, hunt_id = _seed_entity(client, host)

    resp = client.get(f"/api/v1/entity/{host}")
    assert resp.status_code == 200
    body = resp.json()

    assert body["value"] == host
    assert body["kind"] == "host"  # not an IP
    assert body["summary"]["investigationCount"] == 2
    assert body["summary"]["huntFindingCount"] == 1
    assert body["summary"]["latestVerdict"] == "true_positive"  # newest investigation

    tl = body["timeline"]
    assert len(tl) == 3  # 2 investigations + 1 hunt finding

    # Newest-first: the two investigations + the hunt finding all carry the same
    # kinds of links, and the investigations sort by their created_at desc.
    inv_items = [i for i in tl if i["kind"] == "investigation"]
    hf_items = [i for i in tl if i["kind"] == "hunt_finding"]
    assert len(inv_items) == 2
    assert len(hf_items) == 1

    # Links point at the SPA routes.
    links = {i["link"] for i in tl}
    assert f"/app/investigation/{older_id}" in links
    assert f"/app/investigation/{newer_id}" in links
    assert f"/app/hunts/{hunt_id}" in links

    # Verdicts / severity surfaced on the right item kinds.
    assert {i["verdict"] for i in inv_items} == {"false_positive", "true_positive"}
    assert hf_items[0]["severity"] == "high"
    assert hf_items[0]["category"] == "threat"

    # Sorted newest-first by ts (ISO strings sort chronologically).
    ts_values = [i["ts"] for i in tl]
    assert ts_values == sorted(ts_values, reverse=True)


def test_entity_unknown_returns_empty_timeline_not_404(client: TestClient) -> None:
    resp = client.get("/api/v1/entity/never-seen-host")
    assert resp.status_code == 200
    body = resp.json()
    assert body["value"] == "never-seen-host"
    assert body["kind"] == "host"
    assert body["timeline"] == []
    assert body["summary"]["investigationCount"] == 0
    assert body["summary"]["huntFindingCount"] == 0
    assert body["summary"]["latestVerdict"] is None


def test_entity_kind_classifies_ip_vs_host(client: TestClient) -> None:
    # An IP value (with dots) is captured whole by the path param and classified.
    ip_resp = client.get("/api/v1/entity/10.0.0.5")
    assert ip_resp.status_code == 200
    assert ip_resp.json()["kind"] == "ip"
    assert ip_resp.json()["value"] == "10.0.0.5"

    host_resp = client.get("/api/v1/entity/web-server-01")
    assert host_resp.status_code == 200
    assert host_resp.json()["kind"] == "host"
