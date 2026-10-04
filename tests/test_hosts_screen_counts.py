"""The Hosts screen's counts and the filters behind them read one source.

The ROLES bar counted through the resolver's gates and the role filter matched
the stored lanes with none, so "server 1" on the bar listed four hosts. The
"low confidence" filter ran on the client over the first 200 rows of 336. A
stale sweep read as "needs attention 0", and an agent seen at the last build
read as "reporting 0". These tests pin each count to the rows behind it.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings

from tests.test_dossier_api import _client, _fact, _seed_host

FRESH = "198.51.100.1"
STALE = "198.51.100.2"
THIN = "198.51.100.3"
NOTHING = "198.51.100.4"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _seed_estate(client: TestClient) -> None:
    old = _now() - timedelta(days=8)
    _seed_host(client, FRESH, facts=[_fact("role", "server")], event_count=5)
    _seed_host(client, STALE, facts=[_fact("role", "server")], event_count=5, built_at=old)
    _seed_host(
        client,
        THIN,
        facts=[_fact("role", "workstation", strength="weak", confidence=0.5)],
        event_count=5,
    )
    _seed_host(
        client,
        NOTHING,
        facts=[_fact("role", "unknown", strength="weak", confidence=0.5)],
        event_count=5,
    )


def _listed(client: TestClient, role: str) -> set[str]:
    body = client.get("/api/v1/dossiers", params={"role": role, "limit": 200}).json()
    return {row["ip"] for row in body["rows"]}


def test_each_role_bucket_and_its_filter_list_one_set(client: TestClient) -> None:
    _seed_estate(client)
    summary = client.get("/api/v1/dossiers/summary").json()

    assert summary["roles"] == {"server": 1}
    assert _listed(client, "server") == {FRESH}
    assert summary["roles_low_confidence"] == 1
    assert _listed(client, "__low_confidence__") == {THIN}
    assert summary["roles_stale"] == 1
    assert _listed(client, "__stale__") == {STALE}


def test_a_guess_spelled_unknown_is_in_no_withheld_bucket(client: TestClient) -> None:
    """Negative control: the classifier's "unknown" is no guess to withhold."""
    _seed_estate(client)
    assert NOTHING not in _listed(client, "__low_confidence__")
    assert NOTHING not in _listed(client, "__stale__")


def test_the_low_confidence_filter_reads_past_the_first_page(client: TestClient) -> None:
    """The filter ran over the first 200 rows. The server now counts them all."""
    _seed_estate(client)
    body = client.get(
        "/api/v1/dossiers", params={"role": "__low_confidence__", "limit": 1, "offset": 0}
    ).json()
    assert body["total"] == 1


def test_the_brief_row_names_the_guess_and_its_age(client: TestClient) -> None:
    _seed_estate(client)
    body = client.get("/api/v1/dossiers", params={"limit": 200}).json()
    by_ip = {row["ip"]: row for row in body["rows"]}
    role = next(f for f in by_ip[STALE]["fields"] if f["field"] == "role")
    assert role["reason"] == "stale"
    assert role["inferred_value"] == "server"
    assert role["last_run_at"] is not None


def test_a_stale_sweep_is_counted_and_an_old_agent_is_still_named(client: TestClient) -> None:
    old = _now() - timedelta(days=8)
    _seed_host(
        client,
        STALE,
        facts=[_fact("hostname", "dc01.example.test", source="hostlog")],
        event_count=5,
        built_at=old,
    )
    _seed_host(client, FRESH, facts=[_fact("role", "server")], event_count=5)

    summary = client.get("/api/v1/dossiers/summary").json()
    assert summary["stale_hosts"] == 1
    assert summary["reporting"] == 0
    assert summary["reporting_stale"] == 1
    assert summary["staleness_hours"] > 0


def test_a_fresh_agent_is_not_counted_twice(client: TestClient) -> None:
    """Negative control: a fresh agent is in ``reporting`` and not in the stale part."""
    _seed_host(
        client,
        FRESH,
        facts=[_fact("hostname", "dc01.example.test", source="hostlog")],
        event_count=5,
    )
    summary = client.get("/api/v1/dossiers/summary").json()
    assert summary["reporting"] == 1
    assert summary["reporting_stale"] == 0
    assert summary["stale_hosts"] == 0


def test_a_declared_field_says_what_removing_it_leaves(client: TestClient) -> None:
    """The remove button said "the sweep's answer then stands" over a 0.50 guess."""
    _seed_host(
        client,
        THIN,
        facts=[_fact("role", "server", strength="weak", confidence=0.5)],
        event_count=5,
    )
    _seed_host(client, FRESH, facts=[_fact("role", "server")], event_count=5)
    for ip in (THIN, FRESH):
        res = client.post(
            f"/api/v1/dossiers/{ip}/override", json={"field": "role", "value": "hypervisor"}
        )
        assert res.status_code == 200, res.text

    def role(ip: str) -> dict:
        body = client.get(f"/api/v1/dossiers/{ip}").json()
        return next(f for f in body["fields"] if f["field"] == "role")

    assert role(THIN)["inference_reason"] == "low_confidence"
    # Negative control: a strong answer underneath does stand.
    assert role(FRESH)["inference_reason"] is None
