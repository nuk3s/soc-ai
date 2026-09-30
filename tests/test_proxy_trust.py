"""One trust rule for forwarded headers, with CIDR blocks for a proxy in a container."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from soc_ai.api.webui._shared import _request_is_https, client_ip, peer_is_trusted_proxy
from soc_ai.config import Settings
from soc_ai.main import create_app
from starlette.requests import Request

from tests.conftest import _base_settings_kwargs


def _req(peer: str, *, scheme: str = "http", headers: dict[str, str] | None = None) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "scheme": scheme,
        "headers": raw,
        "client": (peer, 40000),
        "server": ("203.0.113.10", 8443),
        "query_string": b"",
    }
    return Request(scope)


def test_a_cidr_block_trusts_every_address_in_it() -> None:
    settings = SimpleNamespace(proxy_trusted_ips=["172.16.0.0/12", "203.0.113.5"])
    assert peer_is_trusted_proxy("172.18.0.7", settings) is True
    assert peer_is_trusted_proxy("203.0.113.5", settings) is True
    assert peer_is_trusted_proxy("203.0.113.6", settings) is False
    assert peer_is_trusted_proxy("198.51.100.1", settings) is False


def test_an_ipv4_mapped_ipv6_peer_matches_its_ipv4_block() -> None:
    """A dual-stack listener reports a v4 peer as ::ffff:a.b.c.d. The block still matches."""
    settings = SimpleNamespace(proxy_trusted_ips=["172.16.0.0/12"])
    assert peer_is_trusted_proxy("::ffff:172.18.0.7", settings) is True
    assert peer_is_trusted_proxy("::ffff:198.51.100.1", settings) is False


def test_a_bad_entry_trusts_nothing_and_does_not_raise() -> None:
    settings = SimpleNamespace(proxy_trusted_ips=["not-an-address", "10.0.0.0/8"])
    assert peer_is_trusted_proxy("10.1.2.3", settings) is True
    assert peer_is_trusted_proxy("not-an-address", settings) is False
    assert peer_is_trusted_proxy("?", settings) is False


def test_forwarded_proto_is_trusted_only_from_the_block() -> None:
    settings = SimpleNamespace(proxy_trusted_ips=["172.16.0.0/12"])
    assert (
        _request_is_https(_req("172.18.0.7", headers={"x-forwarded-proto": "https"}), settings)
        is True
    )
    assert (
        _request_is_https(_req("198.51.100.1", headers={"x-forwarded-proto": "https"}), settings)
        is False
    )


def test_client_ip_walks_past_every_trusted_hop_in_the_block() -> None:
    settings = SimpleNamespace(proxy_trusted_ips=["172.16.0.0/12"])
    req = _req("172.18.0.7", headers={"x-forwarded-for": "198.51.100.9, 172.18.0.3"})
    assert client_ip(req, settings) == "198.51.100.9"
    assert (
        client_ip(_req("203.0.113.9", headers={"x-forwarded-for": "198.51.100.9"}), settings)
        == "203.0.113.9"
    )


def _app_client(settings: Settings, peer: str) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app, client=(peer, 40000)) as client:
            yield client


def test_hsts_follows_the_same_trust_rule() -> None:
    """The HSTS header follows forwarded-proto only from a peer in the block."""
    settings = Settings(**_base_settings_kwargs(), proxy_trusted_ips=["172.16.0.0/12"])
    for client in _app_client(settings, "172.18.0.7"):
        resp = client.get("/healthz", headers={"X-Forwarded-Proto": "https"})
        assert resp.status_code == 200
        assert "Strict-Transport-Security" in resp.headers
    for client in _app_client(settings, "198.51.100.1"):
        resp = client.get("/healthz", headers={"X-Forwarded-Proto": "https"})
        assert resp.status_code == 200
        assert "Strict-Transport-Security" not in resp.headers
