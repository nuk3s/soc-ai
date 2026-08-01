"""Regression tests for the 2026-07-30 review — integrations bucket (B08).

Each test fails on the pre-fix code and passes after the fix:

- F08 zeek_parser: TLS `cipher` / conn `service` must NOT be rolled up as
  Kerberos evidence for non-kerberos zeek datasets.
- F09 enrichment: MISP IP/domain lookups must query the full attribute-type set
  (ip-dst / hostname), not only ip-src / domain.
- F30 shodan_internetdb: an operator-declared internal_cidrs host (globally
  routable) must be refused, matching shodan_host / greynoise.
- F31 rule_prevalence: a model-supplied lookback_days beyond the ceiling is
  rejected without touching Elasticsearch.
- F57 oql: `head` / `count` bind to the aggregation regardless of pipe order.
"""

from __future__ import annotations

import ipaddress
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from soc_ai.config import Settings
from soc_ai.enrichment.zeek_parser import parse_typed_zeek_fields
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.so_client.models import SoAlert
from soc_ai.so_client.oql import ast_to_es_dsl, parse_oql
from soc_ai.tools.enrichment import MispClient, enrich_domain, enrich_ip
from soc_ai.tools.rule_prevalence import rule_prevalence
from soc_ai.tools.shodan_internetdb import shodan_internetdb

# ---------------------------------------------------------------------------
# F08 — zeek_parser: no cross-dataset Kerberos roll-up
# ---------------------------------------------------------------------------


def test_ssl_cipher_service_not_rolled_up_as_kerberos() -> None:
    """A zeek.ssl record's TLS `cipher` and conn `service` must never land in the
    kerberos_* lists — otherwise a benign legacy-TLS session reads as Kerberoasting."""
    pivots = [
        SoAlert(
            id="ssl1",
            event_dataset="zeek.ssl",
            event_module="zeek",
            message=json.dumps(
                {
                    "server_name": "legacy.example.com",
                    "cipher": "TLS_RSA_WITH_RC4_128_SHA",
                    "service": "ssl",
                    "ja3": "deadbeef",
                }
            ),
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert typed.kerberos_ciphers == []
    assert typed.kerberos_services == []
    # The legitimately-parsed fields are unaffected by the gating.
    assert "legacy.example.com" in typed.sni_servers


def test_real_kerberos_cipher_service_still_captured() -> None:
    """A genuine zeek.kerberos record still surfaces its cipher/service via the
    raw-message fallback (typed attrs absent on a directly-built SoAlert)."""
    pivots = [
        SoAlert(
            id="krb1",
            event_dataset="zeek.kerberos",
            event_module="zeek",
            message=json.dumps({"cipher": "rc4-hmac", "service": "HTTP/dc01.corp"}),
        )
    ]
    typed = parse_typed_zeek_fields(pivots)
    assert "rc4-hmac" in typed.kerberos_ciphers
    assert "HTTP/dc01.corp" in typed.kerberos_services


# ---------------------------------------------------------------------------
# F09 — enrichment: MISP queries the full attribute-type set
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_ip_queries_ip_dst_types(settings_kratos: Settings) -> None:
    misp = AsyncMock(spec=MispClient)
    misp.search_ioc.return_value = []

    await enrich_ip("203.0.113.10", settings=settings_kratos, misp=misp)

    misp.search_ioc.assert_awaited_once()
    ioc_type = misp.search_ioc.await_args.kwargs["ioc_type"]
    assert isinstance(ioc_type, list)
    # The destination-C2 attribute type MUST be queried.
    assert "ip-dst" in ioc_type
    assert "ip-src" in ioc_type


@pytest.mark.asyncio
async def test_enrich_domain_queries_hostname_type(settings_kratos: Settings) -> None:
    misp = AsyncMock(spec=MispClient)
    misp.search_ioc.return_value = []

    await enrich_domain("evil.example.com", settings=settings_kratos, misp=misp)

    misp.search_ioc.assert_awaited_once()
    ioc_type = misp.search_ioc.await_args.kwargs["ioc_type"]
    assert isinstance(ioc_type, list)
    assert "hostname" in ioc_type
    assert "domain" in ioc_type


# ---------------------------------------------------------------------------
# F30 — shodan_internetdb: honours operator internal_cidrs
# ---------------------------------------------------------------------------


_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _shodan_settings(**over: Any) -> Any:
    base: dict[str, Any] = dict(
        allow_online_enrichment=True,
        online_enrichment_timeout_s=8,
        online_enrichment_verify_ssl=True,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _patch_httpx(handler: Any) -> Any:
    transport = httpx.MockTransport(handler)

    def _factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k["transport"] = transport
        return _REAL_ASYNC_CLIENT(*a, **k)

    return patch("soc_ai.tools.online.httpx.AsyncClient", _factory)


@pytest.mark.asyncio
async def test_shodan_internetdb_refuses_internal_cidr_host() -> None:
    """A globally-routable IP declared in internal_cidrs must be refused (never
    sent off-box) — same posture as shodan_host / greynoise."""
    calls = {"n": 0}

    def h(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    settings = _shodan_settings(internal_cidrs=[ipaddress.ip_network("45.55.0.0/16")])
    with _patch_httpx(h):
        out = await shodan_internetdb("45.55.1.7", settings=settings)

    assert out["available"] is False
    assert out["reason"] == "private_ip"
    assert calls["n"] == 0  # internal-but-routable IP never leaves the box


@pytest.mark.asyncio
async def test_shodan_internetdb_allows_true_public_ip() -> None:
    """An IP outside internal_cidrs still proceeds to the lookup (guard is scoped
    to internal hosts, not all public IPs)."""

    def h(req: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    settings = _shodan_settings(internal_cidrs=[ipaddress.ip_network("45.55.0.0/16")])
    with _patch_httpx(h):
        out = await shodan_internetdb("8.8.8.8", settings=settings)

    assert out["observed"] is False


# ---------------------------------------------------------------------------
# F31 — rule_prevalence: bounded lookback_days
# ---------------------------------------------------------------------------


def _elastic(settings: Settings, search: AsyncMock) -> ElasticClient:
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()):
        client = ElasticClient(settings)
    client.search = search  # type: ignore[method-assign]
    return client


@pytest.mark.asyncio
async def test_rule_prevalence_rejects_oversized_lookback(settings_kratos: Settings) -> None:
    search = AsyncMock()
    client = _elastic(settings_kratos, search)

    out = await rule_prevalence(
        "ET INFO Observed", elastic=client, settings=settings_kratos, lookback_days=3_650_000
    )

    assert out["error"] is True
    assert out["type"] == "ValueError"
    search.assert_not_called()  # no full-history ES scan issued


@pytest.mark.asyncio
async def test_rule_prevalence_accepts_max_lookback(settings_kratos: Settings) -> None:
    search = AsyncMock(return_value=EsSearchResult(total=0, took_ms=1, hits=[], aggregations=None))
    client = _elastic(settings_kratos, search)

    out = await rule_prevalence(
        "ET INFO Observed", elastic=client, settings=settings_kratos, lookback_days=365
    )

    assert out["observed"] is False
    search.assert_called_once()


# ---------------------------------------------------------------------------
# F57 — oql: head/count bind to the aggregation regardless of pipe order
# ---------------------------------------------------------------------------


def test_head_before_groupby_sets_bucket_size() -> None:
    ast = parse_oql("source.ip:10.0.0.1 | head 5 | groupby destination.ip")
    body = ast_to_es_dsl(ast)
    assert body["size"] == 0
    assert body["aggs"]["by_destination_ip"]["terms"]["size"] == 5


def test_head_after_groupby_unchanged() -> None:
    ast = parse_oql("source.ip:10.0.0.1 | groupby destination.ip | head 5")
    body = ast_to_es_dsl(ast)
    assert body["aggs"]["by_destination_ip"]["terms"]["size"] == 5


def test_count_before_head_forces_size_zero() -> None:
    ast = parse_oql("source.ip:10.0.0.1 | count | head 5")
    body = ast_to_es_dsl(ast)
    assert body["size"] == 0
    assert body["track_total_hits"] == 10_000
