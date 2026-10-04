"""The demo host estate behind the published Hosts screenshots.

``scripts/demo/seed_demo.py`` writes 16 machines the way a sweep does, and
``scripts/demo/mock_es.py`` answers the host page's grid reads for the proxy.
docs/img/screenshot-hosts.png and screenshot-host.png show what these produce,
and docs/WEBUI_GUIDE.md describes those pictures. These tests pin the numbers
the pictures show, and keep every seeded identifier inside the documentation
ranges, because the images ship publicly.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from scripts.demo import demo_dataset as dd
from scripts.demo import mock_es, seed_demo
from soc_ai.config import Settings
from soc_ai.main import create_app

_TEST_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


@pytest.fixture
def estate(settings_kratos: Settings) -> Iterator[tuple[TestClient, dict[str, str]]]:
    fake_es = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as client:
            maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
            keys = asyncio.run(seed_demo.seed_hosts(maker, actor="admin"))
            yield client, keys


def _get(client: TestClient, path: str, **params: Any) -> dict[str, Any]:
    response = client.get(path, params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def test_the_cards_count_the_estate_the_screenshot_shows(
    estate: tuple[TestClient, dict[str, str]],
) -> None:
    client, _ = estate
    summary = _get(client, "/api/v1/hosts/summary")

    assert summary["machines"] == 16
    assert summary["addresses"] == 19
    assert summary["with_agent"] == 11
    assert summary["without_agent"] == 5
    assert summary["new_7d"] == 1
    assert summary["named"] == 14
    assert summary["unnamed"] == 2
    # Every primary address has a clean, fresh build, and no declaration
    # disagrees with the sweep: the cards read 0, not a dash.
    assert summary["needs_attention"] == 0
    assert summary["never_built"] == 0
    assert summary["conflicts"] == 0
    assert summary["last_sweep_at"] is not None
    roles = summary["roles"]
    assert roles["workstation"] == 6
    assert roles["server"] == 4
    assert roles["domain_controller"] == 1
    assert roles["security_appliance"] == 1
    assert roles["hypervisor"] == 1
    assert roles["low_confidence"] == 1
    assert roles["unknown"] == 2


def test_the_default_list_opens_on_the_newest_machine(
    estate: tuple[TestClient, dict[str, str]],
) -> None:
    client, _ = estate
    body = _get(client, "/api/v1/hosts")

    assert body["total"] == 16
    assert (body["sort"], body["dir"]) == ("last_seen", "desc")
    names = [row["name"] for row in body["rows"]]
    assert names[:3] == ["dc-01", "web-proxy-01", "intranet-01"]
    dc = body["rows"][0]
    assert dc["role"]["state"] == "declared"
    assert dc["role"]["value"] == "domain_controller"
    display = next(row for row in body["rows"] if row["name"] == "conf-b-display")
    assert display["key"].startswith("mac:")
    assert display["role"]["state"] == "low_confidence"
    assert display["role"]["guess"] == "iot"


def test_the_proxy_page_holds_four_addresses_and_three_containers(
    estate: tuple[TestClient, dict[str, str]],
) -> None:
    client, keys = estate
    detail = _get(client, f"/api/v1/hosts/{quote(keys['host_proxy'], safe='')}")

    assert detail["name"] == "web-proxy-01"
    assert detail["primary_ip"] == keys["host_proxy_ip"] == dd.PROXY_IP
    kinds = {a["ip"]: a["kind"] for a in detail["addresses"]}
    assert kinds == {
        "198.51.100.5": "agent",
        "198.51.100.6": "agent",
        "198.51.100.7": "agent",
        "198.51.100.8": "name",
    }
    assert [c["ip"] for c in detail["containers"]] == ["192.0.2.2", "192.0.2.3", "192.0.2.4"]
    assert detail["agent"]["os"] == "Ubuntu 24.04 LTS"


def test_every_seeded_identifier_is_documentation_only() -> None:
    for machine in seed_demo.DEMO_MACHINES:
        ips = [a.ip for a in machine.addresses + machine.containers]
        if machine.bridge is not None:
            ips.append(machine.bridge)
        for ip in ips:
            parsed = ipaddress.ip_address(ip)
            assert any(parsed in net for net in _TEST_NETS), ip
        mac = machine.mac_address
        assert mac is None or mac.startswith("00:00:5e:00:53:"), mac
        for address in machine.addresses:
            assert address.dns is None or address.dns.endswith(f".{dd.ORG_DOMAIN}")
    for host, peers in dd.HOST_PEERS.items():
        for ip in [host, *(peer for peer, _, _, _ in peers)]:
            assert any(ipaddress.ip_address(ip) in net for net in _TEST_NETS), ip


def _conn_body(ip: str, interval: str = "hour") -> dict[str, Any]:
    return {
        "aggs": {
            "by_dataset": {"terms": {"field": "event.dataset"}},
            "by_stream_dataset": {"terms": {"field": "data_stream.dataset"}},
            "out": {"filter": {"term": {"source.ip": ip}}, "aggs": {}},
            "in": {"filter": {"term": {"destination.ip": ip}}, "aggs": {}},
            "volume": {"date_histogram": {"field": "@timestamp", "calendar_interval": interval}},
        }
    }


@pytest.mark.parametrize("interval", ["hour", "day"])
def test_the_mock_answers_the_proxy_conversations(interval: str) -> None:
    aggs = mock_es._search_response(_conn_body(dd.PROXY_IP, interval))["aggregations"]

    peers_in = [b["key"] for b in aggs["in"]["peers"]["buckets"]]
    peers_out = [b["key"] for b in aggs["out"]["peers"]["buckets"]]
    assert len(peers_in) + len(peers_out) == len(dd.HOST_PEERS[dd.PROXY_IP])
    assert "198.51.100.23" in peers_in
    assert "203.0.113.80" in peers_out
    records = sum(b["doc_count"] for side in ("in", "out") for b in aggs[side]["peers"]["buckets"])
    assert sum(b["doc_count"] for b in aggs["volume"]["buckets"]) == records
    assert len(aggs["volume"]["buckets"]) == (24 if interval == "hour" else 7)


def test_the_mock_keeps_every_other_host_quiet() -> None:
    body = mock_es._search_response(_conn_body("198.51.100.23"))

    assert body["hits"]["total"]["value"] == 0
    assert "aggregations" not in body


def test_the_mock_names_the_accounts_on_the_proxy() -> None:
    query = {"bool": {"filter": [{"term": {"host.ip": dd.PROXY_IP}}]}}
    body = mock_es._search_response(
        {"query": query, "aggs": {"agents": {}, "users": {}}},
    )

    assert [b["key"] for b in body["aggregations"]["agents"]["buckets"]] == ["web-proxy-01"]
    assert [b["key"] for b in body["aggregations"]["users"]["buckets"]] == [
        "svc-deploy",
        "ops-admin",
    ]
