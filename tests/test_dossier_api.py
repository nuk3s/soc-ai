"""Tests for the host-dossier REST surface (``soc_ai/api/webui/routes_dossier.py``).

The load-bearing test here is :func:`test_override_survives_a_rebuild`: it sets an
operator value *through the API*, runs the builder's own write path again, and
re-reads *through the API*. That is the two-lane invariant proven end to end —
the store-level test proves the columns are disjoint, this one proves nothing on
the read path quietly re-collapses them.

Everything else is the contract around it: server-side paging and filtering, the
404-vs-409 split on "accept the inference", and a refresh trigger that cannot be
double-started.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, SecretStr
from soc_ai.config import Settings
from soc_ai.dossier.types import DOSSIER_FIELDS, Fact
from soc_ai.main import create_app
from soc_ai.store import host_dossier as dossier_store
from sqlalchemy.exc import SQLAlchemyError


def _client(settings: Settings, *, es_search: Any | None = None) -> Iterator[TestClient]:
    """The app on a scratch DB with a stubbed grid.

    ``es_search`` replaces ``AsyncElasticsearch.search`` — a raw ES response (or
    an exception) per call. Stubbing at THAT seam rather than at the query module
    keeps the real ElasticClient, the real aggregation folding, and the real
    route in the test, so a wire-shape change cannot pass unnoticed.
    """
    fake_es = AsyncMock()
    if es_search is not None:
        fake_es.search.side_effect = es_search
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


# ---------------------------------------------------------------------------
# Seeding helpers — the builder's own write path, so a test can never seed a
# shape the real sweep cannot produce.
# ---------------------------------------------------------------------------


def _fact(
    field: str,
    value: str | None,
    *,
    value_json: Any | None = None,
    source: str = "behaviour",
    strength: str = "strong",
    confidence: float = 0.9,
    evidence: Iterable[str] = (),
    observed_at: datetime | None = None,
) -> Fact:
    return Fact(
        field=field,
        value=value,
        value_json=value_json,
        confidence=confidence,
        strength=strength,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        evidence=list(evidence),
        observed_at=observed_at or datetime(2026, 8, 1, 12, 0),
    )


def _seed_host(
    client: TestClient,
    ip: str,
    *,
    facts: Iterable[Fact] = (),
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    event_count: int = 0,
    built_at: datetime | None = None,
) -> None:
    """Insert one host header plus its inference lane, as a build would."""

    async def _run() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            host = await dossier_store.upsert_host(
                db,
                ip,
                first_seen=first_seen or datetime(2026, 7, 1, 0, 0),
                last_seen=last_seen or datetime(2026, 8, 5, 0, 0),
                event_count=event_count,
                last_built_at=built_at or datetime.now(UTC).replace(tzinfo=None),
            )
            for fact in facts:
                await dossier_store.upsert_inferred(db, host, fact, now=built_at)
            await db.commit()

    asyncio.run(_run())


def _rebuild(client: TestClient, ip: str, facts: Iterable[Fact]) -> None:
    """Re-run the builder's write path for one host — an inference sweep."""

    async def _run() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            host = await dossier_store.upsert_host(db, ip)
            for fact in facts:
                await dossier_store.upsert_inferred(db, host, fact)
            await db.commit()

    asyncio.run(_run())


def _field(body: dict[str, Any], name: str) -> dict[str, Any]:
    return next(f for f in body["fields"] if f["field"] == name)


# ---------------------------------------------------------------------------
# GET /dossiers — paging + filtering
# ---------------------------------------------------------------------------


def test_list_is_empty_before_the_first_sweep(client: TestClient) -> None:
    body = client.get("/api/v1/dossiers").json()
    assert body["rows"] == []
    assert body["total"] == 0
    assert body["limit"] == 50


def test_list_pages_server_side_and_reports_the_total(client: TestClient) -> None:
    """The page is cut in SQL, and `total` describes the whole match set — a
    5,000-host table must never be shipped whole the way the identifier list is."""
    for n in (1, 2, 3):
        _seed_host(client, f"192.168.10.{n}", last_seen=datetime(2026, 8, n, 0, 0))

    first = client.get("/api/v1/dossiers", params={"limit": 2, "sort": "ip"}).json()
    assert [row["ip"] for row in first["rows"]] == ["192.168.10.1", "192.168.10.2"]
    assert first["total"] == 3
    assert first["limit"] == 2 and first["offset"] == 0

    second = client.get("/api/v1/dossiers", params={"limit": 2, "offset": 2, "sort": "ip"}).json()
    assert [row["ip"] for row in second["rows"]] == ["192.168.10.3"]
    assert second["total"] == 3


def test_list_rows_carry_every_field_resolved(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "hypervisor")])
    row = client.get("/api/v1/dossiers").json()["rows"][0]
    assert [f["field"] for f in row["fields"]] == list(DOSSIER_FIELDS)
    role = _field(row, "role")
    assert role["value"] == "hypervisor"
    assert role["source"] == "behaviour"
    assert role["reason"] is None
    # A field the classifier never emitted is still present, and says why.
    assert _field(row, "criticality")["reason"] == "no_signal"


def test_list_filters_by_role(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "hypervisor")])
    _seed_host(client, "192.168.10.50", facts=[_fact("role", "workstation")])

    body = client.get("/api/v1/dossiers", params={"role": "hypervisor"}).json()
    assert [row["ip"] for row in body["rows"]] == ["192.168.10.202"]
    assert body["total"] == 1


def test_list_filters_by_q_over_ip_and_hostname(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("hostname", "pve01", source="banner")])
    _seed_host(client, "172.16.4.9", facts=[_fact("hostname", "kiosk", source="banner")])

    by_name = client.get("/api/v1/dossiers", params={"q": "pve"}).json()
    assert [row["ip"] for row in by_name["rows"]] == ["192.168.10.202"]

    by_ip = client.get("/api/v1/dossiers", params={"q": "172.16"}).json()
    assert [row["ip"] for row in by_ip["rows"]] == ["172.16.4.9"]


def test_list_filters_by_source_lane(client: TestClient) -> None:
    """`source` splits the network by whether a human has touched it at all."""
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "hypervisor")])
    _seed_host(client, "192.168.10.50", facts=[_fact("role", "workstation")])
    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override",
        json={"field": "criticality", "value": "high"},
    )
    assert resp.status_code == 200

    touched = client.get("/api/v1/dossiers", params={"source": "operator"}).json()
    assert [row["ip"] for row in touched["rows"]] == ["192.168.10.202"]
    assert touched["rows"][0]["override_count"] == 1

    untouched = client.get("/api/v1/dossiers", params={"source": "inferred"}).json()
    assert [row["ip"] for row in untouched["rows"]] == ["192.168.10.50"]


def test_rows_and_detail_carry_the_agent_reporting_flag(client: TestClient) -> None:
    """``reporting``: an agent ON the machine is currently telling us about it.

    The host page's headline says "No agent — network-only visibility" off this
    flag. It cannot be derived from per-field ``source``: an override masks the
    hostlog provenance on the field it wins (a renamed host reads as agentless),
    and the staleness window is a server knob the client does not hold. A false
    "no agent" sends someone to install an agent that is already running.
    """
    _seed_host(client, "192.168.10.1", facts=[_fact("hostname", "self", source="hostlog")])
    _seed_host(client, "192.168.10.2", facts=[_fact("hostname", "heard", source="banner")])
    # An agent report the operator has overruled — the box still ships logs.
    _seed_host(client, "192.168.10.3", facts=[_fact("hostname", "pve01", source="hostlog")])
    resp = client.post(
        "/api/v1/dossiers/192.168.10.3/override", json={"field": "hostname", "value": "blue"}
    )
    assert resp.status_code == 200
    # An agent that stopped reporting weeks ago is not coverage now.
    old = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=10)
    _seed_host(
        client,
        "192.168.10.4",
        facts=[_fact("hostname", "gone", source="hostlog")],
        built_at=old,
    )

    rows = {row["ip"]: row for row in client.get("/api/v1/dossiers").json()["rows"]}
    assert rows["192.168.10.1"]["reporting"] is True
    assert rows["192.168.10.2"]["reporting"] is False
    assert rows["192.168.10.3"]["reporting"] is True  # override hides the value, not the agent
    assert rows["192.168.10.4"]["reporting"] is False

    # The detail card answers the same, and the flags sum to the KPI: the strip
    # and the rows beneath it describe the same machines.
    assert client.get("/api/v1/dossiers/192.168.10.3").json()["reporting"] is True
    assert client.get("/api/v1/dossiers/192.168.10.99").json()["reporting"] is False
    kpi = client.get("/api/v1/dossiers/summary").json()["reporting"]
    assert sum(1 for row in rows.values() if row["reporting"]) == kpi == 2


def test_list_health_broken_is_the_kpi_click_through(client: TestClient) -> None:
    """``?health=broken`` returns exactly the hosts ``never_built`` counted.

    Before this filter existed the KPI said "2 never built or errored" and
    clicking it could go nowhere: a broken host's row was indistinguishable from
    a healthy sparse one.
    """
    _seed_host(client, "192.168.10.1")  # built clean

    async def _seed_unbuilt_and_errored() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            # Never built: a census row with no build stamp at all.
            await dossier_store.upsert_host(db, "192.168.10.2", last_seen=datetime(2026, 8, 5))
            # Built, and the build failed.
            await dossier_store.upsert_host(
                db,
                "192.168.10.3",
                last_seen=datetime(2026, 8, 5),
                last_built_at=datetime(2026, 8, 5),
                build_error="grid timeout",
            )
            await db.commit()

    asyncio.run(_seed_unbuilt_and_errored())

    kpi = client.get("/api/v1/dossiers/summary").json()["never_built"]
    body = client.get("/api/v1/dossiers", params={"health": "broken"}).json()
    assert body["total"] == kpi == 2
    assert {row["ip"] for row in body["rows"]} == {"192.168.10.2", "192.168.10.3"}

    # A typo is a 422 with the legal set in the schema, not a silently ignored
    # filter that shows every host as "broken matches".
    assert client.get("/api/v1/dossiers", params={"health": "meh"}).status_code == 422


def test_list_defaults_to_attention_order(client: TestClient) -> None:
    """The landing screen ranks what needs the operator, not what talked last.

    The dogfood finding this pins: sorted by last_seen, the one named, critical,
    conflicted host was the last row of 41 — the page answered "who spoke
    recently" when the operator was asking "who needs me".
    """
    # The anonymous tail: seen most recently, nothing else to say.
    _seed_host(client, "192.168.10.50", last_seen=datetime(2026, 8, 6, 0, 0))
    # Named, declared critical — and QUIET.
    _seed_host(
        client,
        "192.168.10.20",
        facts=[_fact("hostname", "blue", source="banner")],
        last_seen=datetime(2026, 8, 1, 0, 0),
    )
    resp = client.post(
        "/api/v1/dossiers/192.168.10.20/override",
        json={"field": "criticality", "value": "critical"},
    )
    assert resp.status_code == 200

    default = client.get("/api/v1/dossiers").json()
    assert [row["ip"] for row in default["rows"]] == ["192.168.10.20", "192.168.10.50"]

    explicit = client.get("/api/v1/dossiers", params={"sort": "attention"}).json()
    assert [row["ip"] for row in explicit["rows"]] == ["192.168.10.20", "192.168.10.50"]

    # The old default is still a legal, working option.
    recent = client.get("/api/v1/dossiers", params={"sort": "last_seen"}).json()
    assert [row["ip"] for row in recent["rows"]] == ["192.168.10.50", "192.168.10.20"]


def test_importance_sort_leads_with_the_graded_over_the_unbuilt(client: TestClient) -> None:
    """The Hosts screen's landing order, over the wire (dogfood B2a).

    An estate where nothing has been built is the normal case, and there
    ``attention`` puts every anonymous row first. ``importance`` puts the
    operator's own grading first, and needs-attention stays one query away.
    """
    # Never built and anonymous — leads under `attention`, sinks under `importance`.
    _seed_host(client, "192.168.11.50", last_seen=datetime(2026, 8, 6, 0, 0))
    # Named and graded critical, and the quietest host on the network.
    _seed_host(
        client,
        "192.168.11.20",
        facts=[_fact("hostname", "dc01", source="dns")],
        last_seen=datetime(2026, 8, 1, 0, 0),
    )
    assert (
        client.post(
            "/api/v1/dossiers/192.168.11.20/override",
            json={"field": "criticality", "value": "critical"},
        ).status_code
        == 200
    )

    ranked = client.get("/api/v1/dossiers", params={"sort": "importance"}).json()
    assert [row["ip"] for row in ranked["rows"]] == ["192.168.11.20", "192.168.11.50"]

    # A typo is a 422 naming the legal set, not a silent fall back.
    assert client.get("/api/v1/dossiers", params={"sort": "importants"}).status_code == 422


# ---------------------------------------------------------------------------
# GET /dossiers/{ip} — every answer comes out of resolve.py
# ---------------------------------------------------------------------------


def test_get_dossier_reports_operator_and_inference_lanes(client: TestClient) -> None:
    _seed_host(
        client,
        "192.168.10.202",
        facts=[_fact("role", "server", evidence=["responds on tcp/22 (from behaviour)"])],
        event_count=3412,
    )
    client.post(
        "/api/v1/dossiers/192.168.10.202/override",
        json={"field": "role", "value": "hypervisor", "note": "Proxmox node"},
    )

    body = client.get("/api/v1/dossiers/192.168.10.202").json()
    assert body["found"] is True
    assert body["event_count"] == 3412
    role = _field(body, "role")
    assert role["value"] == "hypervisor"
    assert role["source"] == "operator"
    assert role["confidence"] == 1.0
    assert role["overridden"] is True
    assert role["operator_note"] == "Proxmox node"
    # The suppressed belief is still readable — an override hides EFFECT, not
    # observation, and the conflict UI argues from exactly this.
    assert role["inferred_value"] == "server"
    assert role["evidence"]["behaviour"]["strings"] == ["responds on tcp/22 (from behaviour)"]


def test_get_dossier_reports_a_stale_belief_as_stale(client: TestClient) -> None:
    """The API cannot assert a fact nobody has re-confirmed — proof the response
    is resolved rather than read straight off the column."""
    old = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=10)
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")], built_at=old)

    role = _field(client.get("/api/v1/dossiers/192.168.10.202").json(), "role")
    assert role["value"] is None
    assert role["reason"] == "stale"
    assert role["inferred_value"] == "server"  # the belief underneath is still shown


def test_get_dossier_below_the_confidence_floor(client: TestClient) -> None:
    _seed_host(
        client,
        "192.168.10.202",
        facts=[_fact("role", "iot", strength="weak", confidence=0.5)],
    )
    role = _field(client.get("/api/v1/dossiers/192.168.10.202").json(), "role")
    assert role["value"] is None
    assert role["reason"] == "low_confidence"


def test_get_dossier_for_an_unswept_host_is_found_false(client: TestClient) -> None:
    """Absence is a reportable answer, not a 404 — the entity card has to render
    "no dossier for this host" instead of an error."""
    body = client.get("/api/v1/dossiers/192.168.10.77").json()
    assert body["found"] is False
    assert body["ip"] == "192.168.10.77"
    assert [f["field"] for f in body["fields"]] == list(DOSSIER_FIELDS)
    assert all(f["reason"] == "no_signal" for f in body["fields"])


def test_get_dossier_for_a_non_address_is_404(client: TestClient) -> None:
    resp = client.get("/api/v1/dossiers/not-an-ip")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_an_ip"


# ---------------------------------------------------------------------------
# The two-lane invariant, end to end through the API
# ---------------------------------------------------------------------------


def test_override_survives_a_rebuild(client: TestClient) -> None:
    """Set an override through the API, run the builder again, re-read: the
    operator value stands, the inference lane underneath is refreshed, and the
    disagreement has started counting."""
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])

    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override",
        json={"field": "role", "value": "hypervisor", "note": "Proxmox VE node"},
    )
    assert resp.status_code == 200
    assert _field(resp.json(), "role")["value"] == "hypervisor"

    _rebuild(client, "192.168.10.202", [_fact("role", "workstation")])

    role = _field(client.get("/api/v1/dossiers/192.168.10.202").json(), "role")
    assert role["value"] == "hypervisor"  # NOT clobbered
    assert role["source"] == "operator"
    assert role["inferred_value"] == "workstation"  # the build kept observing
    assert role["conflict"]["kind"] == "mismatch"
    assert role["conflict"]["observations"] == 1


def test_override_unknown_host_is_404(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/dossiers/192.168.10.77/override", json={"field": "role", "value": "server"}
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


def test_override_unknown_field_is_400(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202")
    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override", json={"field": "vibes", "value": "good"}
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "unknown_field"


def test_override_without_a_value_is_400(client: TestClient) -> None:
    """An empty override would silently resolve to nothing; the caller means
    "accept the inference", which is the DELETE."""
    _seed_host(client, "192.168.10.202")
    resp = client.post("/api/v1/dossiers/192.168.10.202/override", json={"field": "role"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "empty_override"


@pytest.mark.parametrize("blank", ["", "   ", "\n\t "])
def test_override_with_a_blank_value_is_400(client: TestClient, blank: str) -> None:
    """A blank string is not a decision.

    Stored as a real override it would win in the resolver — pinning the field to
    empty and permanently suppressing the inference underneath it, which is the
    one thing an operator cannot undo by rebuilding.
    """
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])
    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override", json={"field": "role", "value": blank}
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "empty_override"

    # The field is still the builder's.
    role = _field(client.get("/api/v1/dossiers/192.168.10.202").json(), "role")
    assert role["value"] == "server"
    assert role["source"] == "behaviour"
    assert role["overridden"] is False


def test_override_value_is_stripped(client: TestClient) -> None:
    """Surrounding whitespace is a paste artefact, not part of the operator's word."""
    _seed_host(client, "192.168.10.202")
    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override",
        json={"field": "role", "value": "  hypervisor \n"},
    )
    assert resp.status_code == 200
    assert _field(resp.json(), "role")["value"] == "hypervisor"


def test_a_blank_value_beside_a_structured_one_is_accepted(client: TestClient) -> None:
    """A UI that always sends both fields must not be able to pin an empty scalar
    over a structured override."""
    _seed_host(client, "192.168.10.202")
    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override",
        json={"field": "services_offered", "value": "", "value_json": [{"port": 8006}]},
    )
    assert resp.status_code == 200
    services = _field(resp.json(), "services_offered")
    assert services["value"] is None
    assert services["value_json"] == [{"port": 8006}]


def test_override_accepts_a_structured_value(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202")
    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override",
        json={"field": "services_offered", "value_json": [{"port": 8006, "proto": "tcp"}]},
    )
    assert resp.status_code == 200
    services = _field(resp.json(), "services_offered")
    assert services["value_json"] == [{"port": 8006, "proto": "tcp"}]
    assert services["source"] == "operator"


# ---------------------------------------------------------------------------
# DELETE /dossiers/{ip}/override/{field} — accept the inference
# ---------------------------------------------------------------------------


def test_clear_override_returns_the_field_to_the_inference(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])
    client.post(
        "/api/v1/dossiers/192.168.10.202/override", json={"field": "role", "value": "hypervisor"}
    )
    _rebuild(client, "192.168.10.202", [_fact("role", "server")])

    resp = client.delete("/api/v1/dossiers/192.168.10.202/override/role")
    assert resp.status_code == 200
    role = _field(resp.json(), "role")
    assert role["value"] == "server"
    assert role["source"] == "behaviour"
    assert role["conflict"] is None


def test_clear_override_unknown_host_is_404(client: TestClient) -> None:
    resp = client.delete("/api/v1/dossiers/192.168.10.77/override/role")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


def test_clear_override_unknown_field_is_400(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202")
    resp = client.delete("/api/v1/dossiers/192.168.10.202/override/vibes")
    assert resp.status_code == 400


def test_clear_override_with_no_override_is_409(client: TestClient) -> None:
    """An inferred value cannot be deleted — the next build would just write it
    back. 409 says so instead of pretending the DELETE did something."""
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])
    resp = client.delete("/api/v1/dossiers/192.168.10.202/override/role")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "no_operator_override"
    assert "recomputed on every build" in resp.json()["detail"]["hint"]


# ---------------------------------------------------------------------------
# Conflicts: the list, and "keep mine"
# ---------------------------------------------------------------------------


def _drive_conflict(client: TestClient, ip: str, builds: int = 3) -> None:
    for _ in range(builds):
        _rebuild(client, ip, [_fact("role", "workstation")])


def test_conflicts_lists_rows_past_the_prompt_gate(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])
    client.post(
        "/api/v1/dossiers/192.168.10.202/override", json={"field": "role", "value": "hypervisor"}
    )

    _drive_conflict(client, "192.168.10.202", builds=2)
    assert client.get("/api/v1/dossiers/conflicts").json()["pending"] == 0

    _drive_conflict(client, "192.168.10.202", builds=1)
    body = client.get("/api/v1/dossiers/conflicts").json()
    assert body["pending"] == 1
    row = body["rows"][0]
    assert row["ip"] == "192.168.10.202"
    assert row["field"] == "role"
    assert row["kind"] == "mismatch"
    assert row["observations"] == 3
    assert row["operator_value"] == "hypervisor"
    assert row["inferred_value"] == "workstation"


def test_a_structured_conflict_reaches_the_list_with_both_lanes(client: TestClient) -> None:
    """``services_offered`` is overridden through ``value_json`` with the scalar
    left null — the documented path for the three structured fields.

    Those disagreements have to reach this list like any other, and they have to
    be readable when they do: a row carrying only the scalar lanes would render
    the operator's claim and the builder's evidence as two blanks.
    """
    _seed_host(
        client,
        "192.168.10.202",
        facts=[_fact("services_offered", "tcp/22", value_json=[{"port": 22, "proto": "tcp"}])],
    )
    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override",
        json={"field": "services_offered", "value_json": [{"port": 8006, "proto": "tcp"}]},
    )
    assert resp.status_code == 200

    for _ in range(3):
        _rebuild(
            client,
            "192.168.10.202",
            [
                _fact(
                    "services_offered",
                    "tcp/22",
                    value_json=[{"port": 22, "proto": "tcp", "count": 91}],
                )
            ],
        )

    body = client.get("/api/v1/dossiers/conflicts").json()
    assert body["pending"] == 1
    row = body["rows"][0]
    assert row["field"] == "services_offered"
    assert row["kind"] == "mismatch"
    assert row["observations"] == 3
    assert row["operator_value"] is None  # the claim lives in the JSON lane
    assert row["operator_value_json"] == [{"port": 8006, "proto": "tcp"}]
    assert row["inferred_value_json"] == [{"port": 22, "proto": "tcp", "count": 91}]


def test_snooze_takes_a_conflict_off_the_list(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])
    client.post(
        "/api/v1/dossiers/192.168.10.202/override", json={"field": "role", "value": "hypervisor"}
    )
    _drive_conflict(client, "192.168.10.202")

    resp = client.post("/api/v1/dossiers/192.168.10.202/conflicts/role/snooze")
    assert resp.status_code == 200
    role = _field(resp.json(), "role")
    assert role["conflict"]["snoozed_until"] is not None
    assert role["conflict"]["observations"] == 0
    assert role["value"] == "hypervisor"  # "keep mine" changes nothing else

    assert client.get("/api/v1/dossiers/conflicts").json()["pending"] == 0


def test_snooze_unknown_host_is_404(client: TestClient) -> None:
    resp = client.post("/api/v1/dossiers/192.168.10.77/conflicts/role/snooze")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


def test_snooze_without_an_open_conflict_is_409(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])
    resp = client.post("/api/v1/dossiers/192.168.10.202/conflicts/role/snooze")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "no_open_conflict"


# ---------------------------------------------------------------------------
# GET /dossiers/summary — the host list's KPI strip
#
# Every number here is the WHOLE table. The screen it feeds is paged in SQL at
# 50 rows, and this project has twice shipped a headline count taken off a page
# and presented as the network's.
# ---------------------------------------------------------------------------


def test_summary_describes_the_network_not_the_page(client: TestClient) -> None:
    for n in (1, 2, 3):
        _seed_host(client, f"192.168.10.{n}")

    page = client.get("/api/v1/dossiers", params={"limit": 1}).json()
    assert len(page["rows"]) == 1  # one row on screen...

    body = client.get("/api/v1/dossiers/summary").json()
    assert body["hosts"] == 3  # ...three in the answer above it
    assert body["never_built"] == 0


def test_summary_carries_the_classifier_role_vocabulary(client: TestClient) -> None:
    """The closed role vocabulary travels on the wire so the host filter and the
    declare datalist offer every role the classifier can emit, not just the ones
    a host on the current page happens to carry."""
    from soc_ai.dossier.infer import ROLE_VOCABULARY

    body = client.get("/api/v1/dossiers/summary").json()
    assert body["role_vocabulary"] == list(ROLE_VOCABULARY)
    # The roles a reader expects are actually there — a guard against an empty or
    # truncated list shipping unnoticed.
    assert {"hypervisor", "domain_controller", "workstation", "unknown"} <= set(
        body["role_vocabulary"]
    )


def test_summary_named_agrees_with_the_rows_underneath_it(client: TestClient) -> None:
    """A name the resolver withholds must not be counted.

    The KPI sits directly above a table that renders an em-dash for exactly this
    host. A count reading the stored column instead of the resolved value would
    claim a name the row beneath it does not show.
    """
    _seed_host(client, "192.168.10.1", facts=[_fact("hostname", "known", source="banner")])
    _seed_host(
        client,
        "192.168.10.2",
        facts=[_fact("hostname", "guess", source="banner", strength="weak", confidence=0.5)],
    )

    rows = {row["ip"]: row for row in client.get("/api/v1/dossiers").json()["rows"]}
    assert _field(rows["192.168.10.1"], "hostname")["value"] == "known"
    assert _field(rows["192.168.10.2"], "hostname")["value"] is None

    assert client.get("/api/v1/dossiers/summary").json()["named"] == 1


def test_summary_counts_hosts_reporting_at_the_hostlog_rung(client: TestClient) -> None:
    """The agent-rollout number: an agent ON the machine reporting about itself.

    The one card that answers "is host-log shipping reaching the network?", which
    nothing else in the app can currently say.
    """
    _seed_host(client, "192.168.10.1", facts=[_fact("hostname", "self", source="hostlog")])
    _seed_host(client, "192.168.10.2", facts=[_fact("hostname", "heard", source="banner")])

    body = client.get("/api/v1/dossiers/summary").json()
    assert body["hosts"] == 2
    assert body["reporting"] == 1


def test_summary_counts_hosts_with_no_clean_build(client: TestClient) -> None:
    _seed_host(client, "192.168.10.1")

    async def _break_one() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            await dossier_store.upsert_host(
                db,
                "192.168.10.2",
                last_built_at=datetime(2026, 8, 1, 12, 0),
                build_error="grid timeout",
            )
            await db.commit()

    asyncio.run(_break_one())

    body = client.get("/api/v1/dossiers/summary").json()
    assert body["hosts"] == 2
    assert body["never_built"] == 1


def test_summary_carries_the_resolved_role_mix(client: TestClient) -> None:
    """The distribution bar's segments: effective role per host, operator lane
    first, the resolver's gates on the inferred lane — never the raw column."""
    _seed_host(client, "192.168.10.1", facts=[_fact("role", "server", source="behaviour")])
    _seed_host(client, "192.168.10.2", facts=[_fact("role", "server", source="behaviour")])
    _seed_host(client, "192.168.10.3", facts=[_fact("role", "workstation", source="behaviour")])
    # The operator relabels one server; the bar must follow the declaration.
    client.post(
        "/api/v1/dossiers/192.168.10.2/override", json={"field": "role", "value": "hypervisor"}
    )
    # A role too weak to resolve joins no bucket — the row under it shows a dash.
    _seed_host(
        client,
        "192.168.10.4",
        facts=[_fact("role", "server", source="behaviour", strength="weak", confidence=0.4)],
    )

    body = client.get("/api/v1/dossiers/summary").json()
    assert body["hosts"] == 4
    assert body["roles"] == {"server": 1, "hypervisor": 1, "workstation": 1}


def test_summary_dates_itself_and_reports_the_schedule(client: TestClient) -> None:
    """The counts are only as fresh as the last sweep, and the schedule is OFF by
    default — so the strip has to be able to say both, or an operator trusts a
    stale number for as long as they leave the schedule alone."""
    empty = client.get("/api/v1/dossiers/summary").json()
    assert empty["last_built_at"] is None
    assert empty["schedule_enabled"] is False

    _seed_host(client, "192.168.10.1", built_at=datetime(2026, 8, 1, 9, 0))
    _seed_host(client, "192.168.10.2", built_at=datetime(2026, 8, 1, 12, 0))
    body = client.get("/api/v1/dossiers/summary").json()
    # The NEWEST stamp: how old the freshest number in the strip is.
    assert body["last_built_at"].startswith("2026-08-01T12:00:00")


def test_summary_reports_an_enabled_schedule(settings_kratos: Settings) -> None:
    scheduled = settings_kratos.model_copy(update={"dossier_schedule_enabled": True})
    for scheduled_client in _client(scheduled):
        body = scheduled_client.get("/api/v1/dossiers/summary").json()
        assert body["schedule_enabled"] is True


def test_summary_conflicts_matches_the_queue_beside_it(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])
    client.post(
        "/api/v1/dossiers/192.168.10.202/override", json={"field": "role", "value": "hypervisor"}
    )
    _drive_conflict(client, "192.168.10.202")

    pending = client.get("/api/v1/dossiers/conflicts").json()["pending"]
    assert pending == 1
    assert client.get("/api/v1/dossiers/summary").json()["conflicts"] == pending


def test_summary_is_not_swallowed_by_the_ip_path(client: TestClient) -> None:
    """FastAPI matches in declaration order. Declared after ``/dossiers/{ip}``,
    this path would be read as an address, and "summary" is not one — so the
    strip would 404 with ``not_an_ip`` on every load."""
    resp = client.get("/api/v1/dossiers/summary")
    assert resp.status_code == 200
    assert "hosts" in resp.json()
    # ...and the literal path has not stolen a real address either.
    assert client.get("/api/v1/dossiers/192.168.10.77").json()["found"] is False


# ---------------------------------------------------------------------------
# POST/GET /dossiers/refresh — single-flight
# ---------------------------------------------------------------------------


def test_refresh_starts_and_status_settles(client: TestClient) -> None:
    async def _instant(state: Any) -> None:
        from soc_ai.api.webui.routes_dossier import _get_dossier_status

        status = _get_dossier_status(state)
        status.last_summary = {"hosts_built": 2}
        status.running = False
        status.last_run = datetime.now(UTC).isoformat()

    with patch("soc_ai.api.webui.routes_dossier._run_dossier_task", _instant):
        resp = client.post("/api/v1/dossiers/refresh")
        assert resp.status_code == 200
        assert resp.json()["note"] in ("started", "already running")

        deadline = time.time() + 5.0
        data: dict[str, Any] = {}
        while time.time() < deadline:
            data = client.get("/api/v1/dossiers/refresh").json()
            if not data["running"] and data.get("last_run"):
                break
            time.sleep(0.05)

    assert data["running"] is False
    assert data["last_summary"] == {"hosts_built": 2}


def test_refresh_is_single_flight(client: TestClient) -> None:
    """A second POST while a sweep is in flight reports it instead of starting a
    second one — 200 network hosts x 7 round trips must not run twice at once."""
    from soc_ai.api.webui.routes_dossier import _get_dossier_status

    status = _get_dossier_status(client.app.state)  # type: ignore[attr-defined]
    status.running = True
    try:
        body = client.post("/api/v1/dossiers/refresh").json()
        assert body["note"] == "already running"
        assert body["running"] is True
    finally:
        status.running = False


def test_refresh_reports_the_master_switch(client: TestClient) -> None:
    from soc_ai.api.webui.routes_dossier import _get_dossier_status

    state = client.app.state  # type: ignore[attr-defined]
    state.settings.dossier_enabled = False
    _get_dossier_status(state).running = False
    try:
        body = client.post("/api/v1/dossiers/refresh").json()
        assert body["note"] == "dossier disabled"
        assert body["running"] is False
    finally:
        state.settings.dossier_enabled = True


def test_refresh_worker_never_raises() -> None:
    """The background sweep releases the single-flight slot whatever happens —
    a task that died holding it would wedge the Rebuild button until a restart.

    The state here is deliberately broken (no clients on it at all), which is the
    cheapest stand-in for "the sweep exploded".
    """
    from soc_ai.api.webui.routes_dossier import _get_dossier_status, _run_dossier_task

    state = SimpleNamespace()
    asyncio.run(_run_dossier_task(state))
    status = _get_dossier_status(state)
    assert status.running is False
    assert status.last_run is not None
    assert status.last_summary == {"errors": ["refresh failed; see server logs"]}


# ---------------------------------------------------------------------------
# Audit + auth
# ---------------------------------------------------------------------------


def test_mutations_emit_audit_events(client: TestClient) -> None:
    _seed_host(client, "192.168.10.202", facts=[_fact("role", "server")])
    audit = AsyncMock()
    client.app.state.audit = audit  # type: ignore[attr-defined]

    client.post(
        "/api/v1/dossiers/192.168.10.202/override", json={"field": "role", "value": "hypervisor"}
    )
    _drive_conflict(client, "192.168.10.202")
    client.post("/api/v1/dossiers/192.168.10.202/conflicts/role/snooze")
    client.delete("/api/v1/dossiers/192.168.10.202/override/role")

    kinds = [call.kwargs["kind"] for call in audit.log_kind.await_args_list]
    assert kinds == ["dossier_override", "dossier_conflict_nudge", "dossier_override"]
    actions = [call.kwargs["payload"]["action"] for call in audit.log_kind.await_args_list]
    assert actions == ["set", "snooze", "clear"]


def test_a_failed_audit_write_does_not_lose_the_override(client: TestClient) -> None:
    """The kinds are string literals against an enum another module owns; an
    unknown kind raises inside the logger. A mutation the operator asked for
    must not be lost to that."""
    _seed_host(client, "192.168.10.202")
    audit = AsyncMock()
    audit.log_kind.side_effect = RuntimeError("audit index down")
    client.app.state.audit = audit  # type: ignore[attr-defined]

    resp = client.post(
        "/api/v1/dossiers/192.168.10.202/override", json={"field": "criticality", "value": "high"}
    )
    assert resp.status_code == 200
    assert _field(resp.json(), "criticality")["value"] == "high"


ADMIN_PW = "dossier-admin-pw"


def _auth_client(settings: Settings) -> Iterator[TestClient]:
    secured = settings.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr(ADMIN_PW)}
    )
    yield from _client(secured)


def test_dossier_routes_require_auth(settings_kratos: Settings) -> None:
    for client in _auth_client(settings_kratos):
        assert client.get("/api/v1/dossiers").status_code in (401, 403)
        assert client.get("/api/v1/dossiers/refresh").status_code in (401, 403)
        # A host's peer list, its logged-in accounts and its alert count are
        # exactly the reconnaissance an unauthenticated caller must not get.
        activity = client.get("/api/v1/dossiers/192.168.10.202/activity")
        assert activity.status_code in (401, 403)


def test_analyst_reads_but_cannot_override(settings_kratos: Settings) -> None:
    """Read is the analyst default (router-level auth); the mutations are admin.
    An analyst who could relabel a host as low-criticality could bury it."""
    from soc_ai.store import auth as auth_svc
    from soc_ai.store.auth import SESSION_COOKIE

    async def _session(maker: Any) -> str:
        async with maker() as db:
            user = await auth_svc.create_user(db, "analyst-dossier", "longpassword1")
            return await auth_svc.create_session(db, user, ttl_hours=24)

    for client in _auth_client(settings_kratos):
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        client.cookies.set(SESSION_COOKIE, asyncio.run(_session(maker)))
        headers = {"Origin": "http://testserver"}

        assert client.get("/api/v1/dossiers", headers=headers).status_code == 200
        assert client.get("/api/v1/dossiers/conflicts", headers=headers).status_code == 200
        assert client.get("/api/v1/dossiers/summary", headers=headers).status_code == 200

        blocked = client.post(
            "/api/v1/dossiers/192.168.10.202/override",
            json={"field": "role", "value": "server"},
            headers=headers,
        )
        assert blocked.status_code == 403
        assert blocked.json()["detail"]["reason"] == "admin_required"


# ---------------------------------------------------------------------------
# GET /dossiers/{ip}/activity — the LIVE half of the host page
# ---------------------------------------------------------------------------

_ACTIVITY_IP = "192.168.10.202"


def _es_response(total: int, aggregations: dict[str, Any] | None = None) -> dict[str, Any]:
    """A raw Elasticsearch search response, as the transport hands it back."""
    return {
        "took": 3,
        "hits": {"total": {"value": total, "relation": "eq"}, "hits": []},
        "aggregations": aggregations or {},
    }


def _grid_responder() -> Any:
    """Answer each of the activity endpoint's sub-queries by its agg names."""

    async def _search(**kwargs: Any) -> dict[str, Any]:
        aggs = set((kwargs.get("body") or {}).get("aggs") or {})
        if "volume" in aggs:
            return _es_response(
                930,
                {
                    "out": {
                        "peers": {
                            "buckets": [
                                {
                                    "key": "192.168.10.40",
                                    "doc_count": 900,
                                    "ports": {"buckets": [{"key": 445, "doc_count": 900}]},
                                },
                                {
                                    "key": "192.168.20.226",
                                    "doc_count": 2,
                                    "ports": {"buckets": [{"key": 4444, "doc_count": 2}]},
                                },
                            ]
                        }
                    },
                    "in": {"peers": {"buckets": []}},
                    "volume": {
                        "buckets": [{"key_as_string": "2026-08-08T11:00:00.000Z", "doc_count": 902}]
                    },
                },
            )
        if "recent" in aggs:
            return _es_response(
                2,
                {
                    "recent": {
                        "src": {"buckets": [{"key": _ACTIVITY_IP, "doc_count": 2}]},
                        "dst": {"buckets": [{"key": "192.168.20.226", "doc_count": 2}]},
                    }
                },
            )
        if "users" in aggs:
            return _es_response(0, {})
        return _es_response(0, {})

    return _search


@pytest.fixture
def activity_client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos, es_search=_grid_responder())


def test_activity_returns_peers_volume_users_and_alert_count(
    activity_client: TestClient,
) -> None:
    body = activity_client.get(f"/api/v1/dossiers/{_ACTIVITY_IP}/activity", params={"range": "24h"})
    assert body.status_code == 200
    data = body.json()
    assert [p["ip"] for p in data["peers"]] == ["192.168.10.40", "192.168.20.226"]
    assert data["peers"][0]["direction"] == "out"
    assert data["peers"][0]["ports"] == [445]
    assert data["peers"][1]["alerted"] is True
    assert data["volume"] == [{"ts": "2026-08-08T11:00:00.000Z", "events": 902}]
    # No auth documents for this address at all — "needs host logs", not "nobody".
    assert data["users"] is None
    assert data["alerts_7d"] == 2
    assert data["latest_investigation"] is None
    # The truncation flags ride the wire so the page's "the N busiest…"
    # footnotes state a cut that happened instead of re-inferring one from a
    # copied cap constant. Two peers, no cut.
    assert data["peers_truncated"] is False
    assert data["users_truncated"] is False


def test_activity_names_peers_from_the_dossier(activity_client: TestClient) -> None:
    """A peer row names the same machine the host list does — through the
    resolver, so an operator override on the peer's hostname shows up here too."""
    _seed_host(activity_client, "192.168.10.40", facts=[_fact("hostname", "nas-1")])

    data = activity_client.get(f"/api/v1/dossiers/{_ACTIVITY_IP}/activity").json()
    named = next(p for p in data["peers"] if p["ip"] == "192.168.10.40")
    assert named["hostname"] == "nas-1"
    # A peer with no dossier row is null, not the empty string.
    assert next(p for p in data["peers"] if p["ip"] == "192.168.20.226")["hostname"] is None


def test_activity_rejects_a_range_it_cannot_bucket(activity_client: TestClient) -> None:
    """422, not a silent fall back to 24h: the chart's interval comes from the
    range, and a window quietly swapped under the analyst is a lying chart."""
    resp = activity_client.get(f"/api/v1/dossiers/{_ACTIVITY_IP}/activity", params={"range": "90d"})
    assert resp.status_code == 422


def test_activity_for_a_non_address_is_404(activity_client: TestClient) -> None:
    resp = activity_client.get("/api/v1/dossiers/not-an-ip/activity")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_an_ip"


def test_activity_degrades_when_the_grid_is_down(settings_kratos: Settings) -> None:
    """The console's standard grid-unavailable signal, not an empty panel: a
    silent [] here would tell the analyst the host did nothing."""
    from elastic_transport import TransportError

    async def _down(**kwargs: Any) -> dict[str, Any]:
        raise TransportError("connection refused")

    for client in _client(settings_kratos, es_search=_down):
        resp = client.get(f"/api/v1/dossiers/{_ACTIVITY_IP}/activity")
        assert resp.status_code == 503
        assert resp.json()["detail"]["reason"] == "grid_unavailable"


def test_activity_does_not_blame_the_grid_for_a_database_failure(
    activity_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A broken DB costs the peer NAMES and the investigation link. Nothing else.

    Both injected lookups read the database, and the route can only translate
    Elasticsearch failures — so an exception out of either used to answer 500,
    which the page renders as its grid-unavailable card ("Everything below comes
    from the network sweep and is unaffected"). Pointing an operator at Security
    Onion while their database is the thing that is down is worse than the
    missing hostname it was reporting.
    """
    from soc_ai.api.webui import routes_dossier

    async def _boom(*args: Any, **kwargs: Any) -> Any:
        raise SQLAlchemyError("connection pool exhausted")

    monkeypatch.setattr(routes_dossier.dossier_store, "get_dossiers", _boom)
    monkeypatch.setattr(routes_dossier.inv_svc, "for_entity", _boom)

    resp = activity_client.get(f"/api/v1/dossiers/{_ACTIVITY_IP}/activity")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert [p["ip"] for p in data["peers"]] == ["192.168.10.40", "192.168.20.226"]
    assert all(peer["hostname"] is None for peer in data["peers"])
    assert data["latest_investigation"] is None
    # The whole grid read survived the database failure.
    assert data["alerts_7d"] == 2
    assert data["volume"] == [{"ts": "2026-08-08T11:00:00.000Z", "events": 902}]


def test_activity_does_not_shadow_the_literal_dossier_routes(
    activity_client: TestClient,
) -> None:
    """FastAPI matches in declaration order, and this module already carries two
    literal paths that had to be declared ahead of ``/dossiers/{ip}``. Prove the
    two-segment activity route neither swallows them nor is swallowed by them."""
    assert activity_client.get("/api/v1/dossiers/conflicts").status_code == 200
    assert activity_client.get("/api/v1/dossiers/refresh").status_code == 200
    # ...and the single-segment detail route still answers its own shape.
    detail = activity_client.get(f"/api/v1/dossiers/{_ACTIVITY_IP}")
    assert detail.status_code == 200
    assert "fields" in detail.json()


def test_activity_reports_a_misconfigured_alerts_query_as_bad_oql(
    settings_kratos: Settings,
) -> None:
    """A broken ``webui_alerts_query`` is a 400 here, exactly as on the console.

    The alert count is scoped by the SAME ``build_filter`` the alerts console
    uses, so the same misconfiguration reaches both surfaces. Without this the
    operator gets a 400 with the offending fragment on one screen and an
    unexplained 500 on the other, for one setting they typed wrong once.
    """
    broken = settings_kratos.model_copy(update={"webui_alerts_query": 'bogus_field:"x"'})
    for client in _client(broken, es_search=_grid_responder()):
        resp = client.get(f"/api/v1/dossiers/{_ACTIVITY_IP}/activity")
        assert resp.status_code == 400
        assert resp.json()["detail"]["reason"] == "bad_oql"


def test_activity_wire_models_reject_unknown_fields() -> None:
    """A field added to the dataclass must not vanish silently on the way out.

    The route builds these with ``**asdict(...)``. Pydantic's default is
    ``extra="ignore"``, so a new dataclass field would compile, typecheck, pass
    every existing test and never reach the wire — the same silent-drop class
    that once cost the agent its prefetched evidence. Forbidding extras turns
    that drift into a loud failure here instead of a missing column on the page.
    """
    from pydantic import ValidationError
    from soc_ai.api.webui.routes_dossier import (
        HostActivityOut,
        HostPeerOut,
        LatestInvestigationOut,
        UserSeenOut,
        VolumePointOut,
    )

    cases: list[tuple[type[BaseModel], dict[str, Any]]] = [
        (HostPeerOut, {"ip": "192.168.10.40"}),
        (VolumePointOut, {"ts": "2026-08-08T11:00:00.000Z", "events": 1}),
        (UserSeenOut, {"name": "svc-backup", "events": 1, "last_seen": "2026-08-08T11:00:00Z"}),
        (LatestInvestigationOut, {"id": "inv-1", "ts": "2026-08-08T11:00:00Z"}),
        (HostActivityOut, {}),
    ]
    for model, kwargs in cases:
        model(**kwargs)  # the real shape still constructs
        with pytest.raises(ValidationError):
            model(**kwargs, field_the_dataclass_grew=1)


def test_activity_names_a_peer_the_grid_spelled_differently(
    settings_kratos: Settings,
) -> None:
    """A peer name survives the two normalizers disagreeing about spelling.

    Elasticsearch hands back whatever text it stored; the dossier is keyed on
    the ``ipaddress``-canonical form. For IPv6 those differ, and the name lookup
    has to canonicalize on the way IN (to find the row) and map back on the way
    OUT (to key the response by the address the peer list actually carries).
    Get either half wrong and the row silently renders unnamed.
    """
    expanded = "2001:0db8:0000:0000:0000:0000:0000:0040"
    canonical = "2001:db8::40"

    async def _search(**kwargs: Any) -> dict[str, Any]:
        aggs = set((kwargs.get("body") or {}).get("aggs") or {})
        if "volume" in aggs:
            return _es_response(
                7,
                {
                    "out": {
                        "peers": {
                            "buckets": [{"key": expanded, "doc_count": 7, "ports": {"buckets": []}}]
                        }
                    },
                    "in": {"peers": {"buckets": []}},
                    "volume": {"buckets": []},
                },
            )
        return _es_response(0, {})

    for client in _client(settings_kratos, es_search=_search):
        _seed_host(client, canonical, facts=[_fact("hostname", "nas-v6")])
        data = client.get(f"/api/v1/dossiers/{_ACTIVITY_IP}/activity").json()
        assert [p["ip"] for p in data["peers"]] == [expanded]
        assert data["peers"][0]["hostname"] == "nas-v6"


# ---------------------------------------------------------------------------
# POST /dossiers/bulk-override — declare one field across many hosts (A4)
# ---------------------------------------------------------------------------


def _bulk(client: TestClient, ips: list[str], field: str, value: str, **extra: Any) -> Any:
    return client.post(
        "/api/v1/dossiers/bulk-override",
        json={"ips": ips, "field": field, "value": value, **extra},
    )


def test_bulk_override_writes_the_operator_lane_for_every_host(client: TestClient) -> None:
    """The whole point of the Hosts bulk action: tagging a subnet is one pass,
    and every host in it ends up with a real operator declaration — the same
    lane, written by the same store path, as the single-host declare."""
    ips = ["10.0.0.11", "10.0.0.12", "10.0.0.13"]
    for ip in ips:
        _seed_host(client, ip, facts=[_fact("role", "workstation", confidence=0.9)])

    resp = _bulk(client, ips, "criticality", "low", note="printer VLAN")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["updated"] == ips
    assert body["not_found"] == []

    for ip in ips:
        got = client.get(f"/api/v1/dossiers/{ip}").json()
        crit = _field(got, "criticality")
        assert crit["value"] == "low"
        assert crit["source"] == "operator"


def test_bulk_override_beats_the_inference_on_every_host(client: TestClient) -> None:
    # The two-lane rule is not weakened by doing it in bulk.
    ips = ["10.0.0.21", "10.0.0.22"]
    for ip in ips:
        _seed_host(client, ip, facts=[_fact("role", "workstation", confidence=0.95)])
    assert _bulk(client, ips, "role", "hypervisor").status_code == 200
    for ip in ips:
        role = _field(client.get(f"/api/v1/dossiers/{ip}").json(), "role")
        assert role["value"] == "hypervisor"
        assert role["source"] == "operator"
        # The inference is suppressed, not erased.
        assert role["inferred_value"] == "workstation"


def test_bulk_override_partitions_hosts_it_has_never_seen(client: TestClient) -> None:
    """A selection can outlive a sweep. Unknown hosts are reported, not fatal —
    the known ones are still declared."""
    _seed_host(client, "10.0.0.31")
    resp = _bulk(client, ["10.0.0.31", "10.0.0.99"], "criticality", "high")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["updated"] == ["10.0.0.31"]
    assert body["not_found"] == ["10.0.0.99"]


def test_bulk_override_survives_a_rebuild(client: TestClient) -> None:
    ips = ["10.0.0.41", "10.0.0.42"]
    for ip in ips:
        _seed_host(client, ip, facts=[_fact("role", "workstation")])
    _bulk(client, ips, "role", "server")
    for ip in ips:
        _rebuild(client, ip, [_fact("role", "workstation", confidence=0.99)])
    for ip in ips:
        assert _field(client.get(f"/api/v1/dossiers/{ip}").json(), "role")["value"] == "server"


def test_bulk_override_rejects_an_unknown_field(client: TestClient) -> None:
    _seed_host(client, "10.0.0.51")
    resp = _bulk(client, ["10.0.0.51"], "vibes", "good")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "unknown_field"


def test_bulk_override_rejects_a_blank_value(client: TestClient) -> None:
    _seed_host(client, "10.0.0.52")
    resp = _bulk(client, ["10.0.0.52"], "role", "   ")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "empty_override"


def test_bulk_override_rejects_a_role_outside_the_vocabulary(client: TestClient) -> None:
    """A typo declared in bulk is a typo on N hosts, and it does not stop there:
    an invented role becomes a bucket in the ROLES distribution and an entry in
    the role facet, for every user of the deployment. One mistyped word in a
    text box is not an acceptable way to extend a shared vocabulary."""
    ips = ["10.0.0.53", "10.0.0.54"]
    for ip in ips:
        _seed_host(client, ip, facts=[_fact("role", "workstation", confidence=0.9)])

    resp = _bulk(client, ips, "role", "srever-typo-role")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "unknown_role"

    # All-or-nothing, as with every other bulk refusal: not one host was written.
    for ip in ips:
        role = _field(client.get(f"/api/v1/dossiers/{ip}").json(), "role")
        assert role["source"] != "operator"
        assert role["value"] == "workstation"


def test_bulk_override_accepts_every_role_the_classifier_can_emit(client: TestClient) -> None:
    """The constraint is the classifier's own vocabulary, so nothing the sweep
    can assert is refused when an operator asserts the same thing in bulk."""
    from soc_ai.dossier.infer import ROLE_VOCABULARY

    for i, role in enumerate(ROLE_VOCABULARY):
        ip = f"10.0.1.{i + 1}"
        _seed_host(client, ip)
        resp = _bulk(client, [ip], "role", role)
        assert resp.status_code == 200, f"{role}: {resp.text}"
        assert resp.json()["updated"] == [ip]
        got = _field(client.get(f"/api/v1/dossiers/{ip}").json(), "role")
        assert got["value"] == role
        assert got["source"] == "operator"


def test_single_host_override_still_takes_a_role_the_classifier_has_never_heard_of(
    client: TestClient,
) -> None:
    """The single-host declare is DELIBERATELY free text and stays that way.

    An operator who knows a machine is a `jump_host` is telling the truth about
    one host they looked at, and refusing that would make the product argue with
    someone who knows more than it does. The blast radius is one row, and the
    distribution bar reads it as one row. Bulk is the different case: the same
    keystroke lands on every selected host at once."""
    _seed_host(client, "10.0.2.1", facts=[_fact("role", "server", confidence=0.9)])
    resp = client.post(
        "/api/v1/dossiers/10.0.2.1/override",
        json={"field": "role", "value": "jump_host"},
    )
    assert resp.status_code == 200, resp.text
    role = _field(resp.json(), "role")
    assert role["value"] == "jump_host"
    assert role["source"] == "operator"


def test_bulk_override_rejects_a_criticality_outside_the_vocabulary(client: TestClient) -> None:
    """Criticality is an ORDER, not a label: the four grades are the four rungs
    the importance sort ranks on. A fifth word is unrankable by construction, so
    a bulk declare of it drops N hosts out of the grading they were selected to
    be given — silently, because the word still renders on every row."""
    ips = ["10.0.3.1", "10.0.3.2"]
    for ip in ips:
        _seed_host(client, ip)

    resp = _bulk(client, ips, "criticality", "super-important")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "unknown_criticality"

    # All-or-nothing, as with every other bulk refusal: not one host was written.
    for ip in ips:
        crit = _field(client.get(f"/api/v1/dossiers/{ip}").json(), "criticality")
        assert crit["source"] != "operator"
        assert crit["value"] is None


def test_the_criticality_grades_are_the_four_the_hosts_screen_offers() -> None:
    """The vocabulary is derived from the rank map, and the OTHER half of this
    contract is hand-written in TypeScript (frontend/src/screens/Hosts.tsx,
    `CRITICALITIES`) — it is not shipped over the wire the way `role_vocabulary`
    is. So a rename in _CRITICALITY_RANK would carry the gate along with it and
    leave the screen's own <select> posting a grade the gate now answers 400 to,
    with every test still green because they all iterate the constant. Pinned to
    the literal words, so that rename fails HERE and names the file to change."""
    from soc_ai.store.host_dossier import CRITICALITY_VOCABULARY

    assert CRITICALITY_VOCABULARY == ("critical", "high", "medium", "low")


def test_bulk_override_refuses_a_json_shaped_role_or_criticality(client: TestClient) -> None:
    """The vocabulary gates read the scalar, so a crafted request drove the same
    arbitrary word in through ``value_json`` and the gate never saw it.

    Worse than the scalar hole it was meant to close: the resolver takes the
    operator lane whichever half holds the value, so the page renders
    `super-important` — while the importance sort (which reads the SCALAR) ranks
    the host UNRANKED and the Hosts table's flags cell, which also reads the
    scalar, shows no grade at all. Neither field is JSON-shaped in the first
    place: ``value_json`` exists for services_offered, activity_profile and
    management_plane."""
    for field, junk in (("criticality", "super-important"), ("role", "srever")):
        ip = "10.0.7.1"
        _seed_host(client, ip)
        resp = client.post(
            "/api/v1/dossiers/bulk-override",
            json={"ips": [ip], "field": field, "value_json": junk},
        )
        assert resp.status_code == 400, f"{field}: {resp.text}"
        assert resp.json()["detail"]["reason"] == "not_a_json_field"
        got = _field(client.get(f"/api/v1/dossiers/{ip}").json(), field)
        assert got["source"] != "operator"
        assert got["value"] is None

    # Even a grade the gate WOULD accept as a scalar: sent as JSON it lands in
    # the column the order cannot read, so it is the same silent unranking.
    _seed_host(client, "10.0.7.2")
    resp = client.post(
        "/api/v1/dossiers/bulk-override",
        json={"ips": ["10.0.7.2"], "field": "criticality", "value_json": "critical"},
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["reason"] == "not_a_json_field"

    # The three fields a scalar cannot carry are untouched by the refusal.
    _seed_host(client, "10.0.7.3")
    resp = client.post(
        "/api/v1/dossiers/bulk-override",
        json={
            "ips": ["10.0.7.3"],
            "field": "services_offered",
            "value_json": [{"port": 8006, "proto": "tcp"}],
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["updated"] == ["10.0.7.3"]


def test_bulk_override_accepts_every_canonical_criticality_grade(client: TestClient) -> None:
    """The constraint is the importance sort's own rank map, so every grade the
    order can read is a grade an operator may declare in bulk."""
    from soc_ai.store.host_dossier import CRITICALITY_VOCABULARY

    for i, grade in enumerate(CRITICALITY_VOCABULARY):
        ip = f"10.0.4.{i + 1}"
        _seed_host(client, ip)
        resp = _bulk(client, [ip], "criticality", grade)
        assert resp.status_code == 200, f"{grade}: {resp.text}"
        assert resp.json()["updated"] == [ip]
        got = _field(client.get(f"/api/v1/dossiers/{ip}").json(), "criticality")
        assert got["value"] == grade
        assert got["source"] == "operator"


def test_bulk_override_folds_criticality_case_the_way_the_sort_does(client: TestClient) -> None:
    """The rank map compares lower(trim())-folded, so "Critical" and "critical"
    are one claim there. The gate folds the same way, or it would refuse a grade
    the order ranks perfectly well."""
    _seed_host(client, "10.0.5.1")
    resp = _bulk(client, ["10.0.5.1"], "criticality", "Critical")
    assert resp.status_code == 200, resp.text
    got = _field(client.get("/api/v1/dossiers/10.0.5.1").json(), "criticality")
    assert got["value"] == "Critical"


def test_single_host_override_still_takes_free_text_criticality(client: TestClient) -> None:
    """Unchanged, and deliberately so — the same asymmetry the role gate keeps.

    One host graded `regulated` by someone who knows that host is one row, and an
    ungradeable word is left where it was found (_CRITICALITY_UNRANKED ranks with
    "not stated": it neither sinks nor floats the host). In bulk the same word
    lands on every selected host at once, which is how a whole selection drops
    out of the order it was selected in."""
    _seed_host(client, "10.0.6.1")
    resp = client.post(
        "/api/v1/dossiers/10.0.6.1/override",
        json={"field": "criticality", "value": "regulated"},
    )
    assert resp.status_code == 200, resp.text
    crit = _field(resp.json(), "criticality")
    assert crit["value"] == "regulated"
    assert crit["source"] == "operator"


def test_bulk_override_rejects_an_empty_selection(client: TestClient) -> None:
    resp = _bulk(client, [], "role", "server")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "no_hosts"


def test_bulk_override_caps_the_batch(client: TestClient) -> None:
    resp = _bulk(client, [f"10.0.{i // 250}.{i % 250}" for i in range(600)], "role", "server")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "too_many_hosts"


def test_bulk_override_rejects_a_selection_that_is_not_addresses(client: TestClient) -> None:
    resp = _bulk(client, ["not-an-ip"], "role", "server")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "not_an_ip"


def test_bulk_low_criticality_does_not_jump_the_importance_order(client: TestClient) -> None:
    """THE guard on this feature.

    The landing sort leads with hosts graded critical/high, THEN named hosts,
    and only then the rest of the grading. Tagging a subnet of anonymous
    printers `low` is exactly the pass that would otherwise put 200 rows of
    `HOST — ROLE —` in front of the domain controller — the first-screen-of-
    nothing the order exists to prevent. Declaring `low` must not promote a
    single one of them above a named host.
    """
    _seed_host(client, "10.0.0.5", facts=[_fact("hostname", "dc-01.example.internal")])
    printers = [f"10.0.0.{n}" for n in range(100, 112)]
    for ip in printers:
        _seed_host(client, ip)

    before = [
        r["ip"]
        for r in client.get("/api/v1/dossiers", params={"sort": "importance"}).json()["rows"]
    ]
    assert before[0] == "10.0.0.5"

    assert _bulk(client, printers, "criticality", "low").status_code == 200

    after = [
        r["ip"]
        for r in client.get("/api/v1/dossiers", params={"sort": "importance"}).json()["rows"]
    ]
    assert after[0] == "10.0.0.5", "a bulk `low` tag must not outrank a named host"
    assert after == before, "declaring `low` must not reshuffle the landing screen at all"


def test_bulk_critical_does_lead_the_importance_order(client: TestClient) -> None:
    """The other half: `critical` and `high` are the two grades that SAY the
    host matters, and they are meant to lead — including over a named host."""
    _seed_host(client, "10.0.0.5", facts=[_fact("hostname", "dc-01.example.internal")])
    _seed_host(client, "10.0.0.200")

    assert _bulk(client, ["10.0.0.200"], "criticality", "critical").status_code == 200
    rows = [
        r["ip"]
        for r in client.get("/api/v1/dossiers", params={"sort": "importance"}).json()["rows"]
    ]
    assert rows[0] == "10.0.0.200"


def test_bulk_override_reports_a_host_that_failed_on_its_own(client: TestClient) -> None:
    """A mid-batch exception used to escape the loop: HTTP 500, the hosts BEFORE
    it left declared, and the audit line — which sits after the loop — never
    written. A partial write that denies being one. Now the batch completes, the
    failure is named, and what landed is still reported."""
    ips = ["10.0.0.61", "10.0.0.62", "10.0.0.63"]
    for ip in ips:
        _seed_host(client, ip)

    real = dossier_store.set_override
    calls: list[str] = []

    async def flaky(db: Any, ip: str, field: str, value: Any, **kw: Any) -> Any:
        calls.append(ip)
        if ip == "10.0.0.62":
            raise SQLAlchemyError("disk I/O error")
        return await real(db, ip, field, value, **kw)

    with patch.object(dossier_store, "set_override", new=flaky):
        resp = _bulk(client, ips, "criticality", "low")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["updated"] == ["10.0.0.61", "10.0.0.63"]
    assert [f["ip"] for f in body["failed"]] == ["10.0.0.62"]
    assert body["not_found"] == []
    # The batch did not stop at the bad host.
    assert calls == ips

    # And the two that landed really landed.
    for ip in ("10.0.0.61", "10.0.0.63"):
        assert _field(client.get(f"/api/v1/dossiers/{ip}").json(), "criticality")["value"] == "low"
    assert _field(client.get("/api/v1/dossiers/10.0.0.62").json(), "criticality")["value"] is None


def test_bulk_override_audits_what_landed_even_when_part_of_the_batch_failed(
    client: TestClient,
) -> None:
    """The audit line is the record of an operator action. Skipping it precisely
    when the batch went wrong is losing the record when it matters most."""
    ips = ["10.0.0.71", "10.0.0.72"]
    for ip in ips:
        _seed_host(client, ip)

    real = dossier_store.set_override

    async def flaky(db: Any, ip: str, field: str, value: Any, **kw: Any) -> Any:
        if ip == "10.0.0.72":
            raise SQLAlchemyError("disk I/O error")
        return await real(db, ip, field, value, **kw)

    audit = AsyncMock()
    client.app.state.audit = audit  # type: ignore[attr-defined]
    with patch.object(dossier_store, "set_override", new=flaky):
        assert _bulk(client, ips, "role", "iot").status_code == 200

    assert audit.log_kind.await_count == 1
    payload = audit.log_kind.await_args.kwargs["payload"]
    assert payload["action"] == "bulk_set"
    assert payload["ips"] == ["10.0.0.71"]
    assert payload["failed"] == ["10.0.0.72"]
