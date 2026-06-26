"""Tests for :mod:`soc_ai.tools.enrichment` - MISP client + enrich_*."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from soc_ai.config import Settings
from soc_ai.tools.enrichment import (
    Finding,
    IndicatorEnrichment,
    MispClient,
    enrich_domain,
    enrich_hash,
    enrich_ip,
)


@pytest.fixture
def settings_no_misp() -> Settings:
    from pydantic import SecretStr

    return Settings(
        so_host="https://so.test",
        so_username="x",
        so_password=SecretStr("x"),
        es_hosts=["https://es.test:9200"],
        litellm_base_url="http://localhost:4000",
    )


@pytest.fixture
def settings_with_internal_cidrs(settings_no_misp: Settings) -> Settings:
    import ipaddress

    settings_no_misp.internal_cidrs = [ipaddress.ip_network("10.0.0.0/8")]
    return settings_no_misp


_MISP_HIT: dict[str, Any] = {
    "id": "12345",
    "type": "ip-src",
    "category": "Network activity",
    "value": "203.0.113.10",
    "comment": "Known C2 server",
    "to_ids": True,
}

_MISP_RESPONSE: dict[str, Any] = {"response": {"Attribute": [_MISP_HIT]}}


# =====================================================================
# MispClient
# =====================================================================


@pytest.mark.asyncio
async def test_misp_client_search_ioc(settings_with_misp: Settings) -> None:
    client = MispClient(settings_with_misp)
    try:
        with respx.mock(base_url="https://misp.example.com") as mock:
            route = mock.post("/attributes/restSearch").mock(
                return_value=httpx.Response(200, json=_MISP_RESPONSE)
            )
            results = await client.search_ioc("203.0.113.10", ioc_type="ip-src")
        assert len(results) == 1
        assert results[0]["value"] == "203.0.113.10"
        body = route.calls[0].request.read()
        assert b"203.0.113.10" in body
        assert b"ip-src" in body
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_misp_client_swallows_5xx(settings_with_misp: Settings) -> None:
    """An unreachable MISP must not crash enrichment - return ``[]``."""
    client = MispClient(settings_with_misp)
    try:
        with respx.mock(base_url="https://misp.example.com") as mock:
            mock.post("/attributes/restSearch").mock(
                return_value=httpx.Response(503, text="service unavailable")
            )
            results = await client.search_ioc("anything")
        assert results == []
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_misp_client_handles_malformed_response(
    settings_with_misp: Settings,
) -> None:
    client = MispClient(settings_with_misp)
    try:
        with respx.mock(base_url="https://misp.example.com") as mock:
            mock.post("/attributes/restSearch").mock(
                return_value=httpx.Response(200, json={"unexpected": "shape"})
            )
            results = await client.search_ioc("anything")
        assert results == []
    finally:
        await client.aclose()


def test_misp_client_requires_url(settings_kratos: Settings) -> None:
    """settings_kratos has no MISP_URL configured."""
    with pytest.raises(ValueError, match="MISP_URL"):
        MispClient(settings_kratos)


def test_misp_client_verifies_tls_by_default(settings_with_misp: Settings) -> None:
    """Default secure: the MISP httpx client is constructed with verify=True
    (the API key transits this channel, so an unverified default is a leak risk)."""
    from unittest.mock import patch

    with patch("soc_ai.tools.enrichment.httpx.AsyncClient") as mock_client:
        MispClient(settings_with_misp)
    _, kwargs = mock_client.call_args
    assert kwargs["verify"] is True


def test_misp_client_verify_can_be_disabled(settings_with_misp: Settings) -> None:
    """MISP_VERIFY_SSL=false is honoured (homelab self-signed opt-out)."""
    from unittest.mock import patch

    settings_with_misp.misp_verify_ssl = False
    with patch("soc_ai.tools.enrichment.httpx.AsyncClient") as mock_client:
        MispClient(settings_with_misp)
    _, kwargs = mock_client.call_args
    assert kwargs["verify"] is False


def test_misp_client_uses_ca_bundle_when_set(settings_with_misp: Settings) -> None:
    """A pinned CA bundle path takes precedence over the boolean toggle."""
    from pathlib import Path
    from unittest.mock import patch

    settings_with_misp.misp_ca_bundle = Path("/etc/ssl/misp-ca.pem")
    with patch("soc_ai.tools.enrichment.httpx.AsyncClient") as mock_client:
        MispClient(settings_with_misp)
    _, kwargs = mock_client.call_args
    assert kwargs["verify"] == "/etc/ssl/misp-ca.pem"


# =====================================================================
# enrich_ip
# =====================================================================


@pytest.mark.asyncio
async def test_enrich_ip_internal_no_misp(settings_kratos: Settings) -> None:
    # enrich_ip now returns IndicatorEnrichment; internal flag replaces the
    # legacy "internal_network" Finding.
    result = await enrich_ip("192.168.1.50", settings=settings_kratos)
    assert isinstance(result, IndicatorEnrichment)
    assert result.indicator_type == "ip"
    assert result.internal is True


@pytest.mark.asyncio
async def test_enrich_ip_external_no_misp(settings_kratos: Settings) -> None:
    # No blocklist/maxmind/cloud passed → all hits fields are empty.
    result = await enrich_ip("8.8.8.8", settings=settings_kratos)
    assert result.blocklist_hits == []
    assert result.misp_hits == []
    assert result.internal is False


@pytest.mark.asyncio
async def test_enrich_ip_external_with_misp_match(
    settings_with_misp: Settings,
) -> None:
    # misp_hits replaces the old result.findings list for MISP results.
    misp = AsyncMock(spec=MispClient)
    misp.search_ioc.return_value = [_MISP_HIT]

    result = await enrich_ip("203.0.113.10", settings=settings_with_misp, misp=misp)

    assert any(f.source == "misp" for f in result.misp_hits)
    misp_finding = next(f for f in result.misp_hits if f.source == "misp")
    assert "Known C2 server" in misp_finding.description


@pytest.mark.asyncio
async def test_enrich_ip_internal_and_misp(settings_with_misp: Settings) -> None:
    # Internal IPs now short-circuit MISP (external-only). The internal flag
    # is set but misp_hits stays empty — this is intentional per the new design.
    misp = AsyncMock(spec=MispClient)
    misp.search_ioc.return_value = [_MISP_HIT]

    result = await enrich_ip("10.0.0.5", settings=settings_with_misp, misp=misp)

    assert result.internal is True
    # MISP is skipped for internal IPs; misp.search_ioc should NOT have been called.
    misp.search_ioc.assert_not_awaited()


@pytest.mark.asyncio
async def test_enrich_ip_internal_cidrs_override_marks_internal(
    settings_no_misp: Settings,
) -> None:
    """An active 'cidr' identifier (threaded as ``internal_cidrs``) overlays the
    settings-only set so a host inside an operator-activated CIDR is classified
    internal in Phase-A enrichment — matching the ICMP-downgrade classifier.

    203.0.113.0/24 is TEST-NET-3 (not in the default RFC1918 internal_cidrs), so
    settings-only marks it external; the effective override marks it internal.
    """
    import ipaddress

    ip = "203.0.113.10"

    # Settings-only (no override): the IP is OUTSIDE settings.internal_cidrs.
    baseline = await enrich_ip(ip, settings=settings_no_misp)
    assert baseline.internal is False

    # Effective override (active 'cidr' row covering the IP): now internal.
    effective_cidrs = [ipaddress.ip_network("203.0.113.0/24")]
    overridden = await enrich_ip(ip, settings=settings_no_misp, internal_cidrs=effective_cidrs)
    assert overridden.internal is True


@pytest.mark.asyncio
async def test_enrich_ip_internal_cidrs_none_uses_settings(
    settings_with_internal_cidrs: Settings,
) -> None:
    """With no override (``internal_cidrs=None``) the internal flag is unchanged:
    classification falls back to ``settings.internal_cidrs`` (backward-compat)."""
    # settings_with_internal_cidrs has internal_cidrs = [10.0.0.0/8].
    inside = await enrich_ip("10.0.0.5", settings=settings_with_internal_cidrs)
    assert inside.internal is True
    outside = await enrich_ip("8.8.8.8", settings=settings_with_internal_cidrs)
    assert outside.internal is False


# =====================================================================
# enrich_domain
# =====================================================================


@pytest.mark.asyncio
async def test_enrich_domain_no_misp(settings_kratos: Settings) -> None:
    result = await enrich_domain("evil.example.com", settings=settings_kratos)
    assert result.indicator == "evil.example.com"
    assert result.indicator_type == "domain"
    assert result.misp_hits == []


@pytest.mark.asyncio
async def test_enrich_domain_with_misp(settings_with_misp: Settings) -> None:
    misp = AsyncMock(spec=MispClient)
    misp.search_ioc.return_value = [
        {
            "type": "domain",
            "value": "evil.example.com",
            "category": "Network activity",
            "comment": "DGA",
        }
    ]

    result = await enrich_domain("evil.example.com", settings=settings_with_misp, misp=misp)

    misp.search_ioc.assert_awaited_once()
    assert misp.search_ioc.await_args.kwargs.get("ioc_type") == "domain" or (
        misp.search_ioc.await_args.args and "evil.example.com" in misp.search_ioc.await_args.args
    )
    assert len(result.misp_hits) == 1


# =====================================================================
# enrich_hash
# =====================================================================


@pytest.mark.asyncio
async def test_enrich_hash_known_algo(settings_with_misp: Settings) -> None:
    # misp_hits replaces the old result.findings list for MISP results.
    misp = AsyncMock(spec=MispClient)
    misp.search_ioc.return_value = [
        {
            "type": "sha256",
            "value": "deadbeef",
            "category": "Payload delivery",
            "comment": "Known dropper",
        }
    ]

    result = await enrich_hash("deadbeef", "SHA256", settings=settings_with_misp, misp=misp)

    # indicator_type is now "sha256" (not "hash:sha256") — new IndicatorEnrichment shape.
    assert result.indicator_type == "sha256"
    assert len(result.misp_hits) == 1
    assert isinstance(result.misp_hits[0], Finding)


@pytest.mark.asyncio
async def test_enrich_hash_unknown_algo_skips_misp(
    settings_with_misp: Settings,
) -> None:
    """Unknown algo - no MISP call, empty hits."""
    misp = AsyncMock(spec=MispClient)

    result = await enrich_hash("abc", "blake3", settings=settings_with_misp, misp=misp)

    misp.search_ioc.assert_not_awaited()
    assert result.misp_hits == []
    # indicator_type now reflects the algo (blake3 for unknown algos).
    assert result.indicator_type == "blake3"


@pytest.mark.asyncio
async def test_enrich_hash_no_misp(settings_kratos: Settings) -> None:
    result = await enrich_hash("abc", "sha256", settings=settings_kratos)
    assert result.misp_hits == []


# =====================================================================
# IndicatorEnrichment new shape tests
# =====================================================================


def test_indicator_enrichment_default_shape() -> None:
    """IndicatorEnrichment is a Pydantic model with sane defaults."""
    from soc_ai.tools.enrichment import IndicatorEnrichment

    e = IndicatorEnrichment(indicator="8.8.8.8", indicator_type="ip")
    assert e.indicator == "8.8.8.8"
    assert e.indicator_type == "ip"
    assert e.internal is False
    assert e.blocklist_hits == []
    assert e.asn is None
    assert e.geoip is None
    assert e.cloud_provider is None


@pytest.mark.asyncio
async def test_enrich_ip_with_blocklist_hit_no_maxmind(
    monkeypatch: pytest.MonkeyPatch, settings_no_misp: Settings
) -> None:
    """enrich_ip with a BlocklistDB hit + no MaxMind/cloud — populates blocklist_hits."""
    from soc_ai.enrichment.blocklists import BlocklistDB, BlocklistHit
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import enrich_ip

    blocklist = BlocklistDB()
    blocklist.ips["198.51.100.5"] = [
        BlocklistHit(
            indicator="198.51.100.5",
            indicator_type="ip",
            source="abuse.ch URLhaus",
            tags=("emotet",),
        )
    ]
    result = await enrich_ip(
        "198.51.100.5",
        settings=settings_no_misp,
        misp=None,
        blocklist=blocklist,
        maxmind=MaxmindReader(),  # both readers None → unavailable
        cloud=CloudPrefixDB(),
    )
    assert result.indicator == "198.51.100.5"
    assert result.indicator_type == "ip"
    assert result.internal is False
    assert len(result.blocklist_hits) == 1
    assert result.blocklist_hits[0].source == "abuse.ch URLhaus"
    assert result.asn is None  # no MaxMind data
    assert result.cloud_provider is None  # no CloudPrefixDB data


@pytest.mark.asyncio
async def test_enrich_ip_with_cloud_tag(
    monkeypatch: pytest.MonkeyPatch, settings_no_misp: Settings
) -> None:
    """enrich_ip resolves cloud_provider when CloudPrefixDB has a hit."""
    from ipaddress import ip_network

    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB, CloudTag
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import enrich_ip

    cloud = CloudPrefixDB()
    cloud.aws_prefixes.append(
        (ip_network("198.51.100.0/24"), CloudTag(provider="AWS", region="us-east-1"))
    )
    result = await enrich_ip(
        "198.51.100.5",
        settings=settings_no_misp,
        misp=None,
        blocklist=BlocklistDB(),
        maxmind=MaxmindReader(),
        cloud=cloud,
    )
    assert result.cloud_provider == "AWS"


@pytest.mark.asyncio
async def test_enrich_ip_ipv6_cloud_tag_marked_incomplete(
    settings_no_misp: Settings,
) -> None:
    """IPv6 cloud-tag lookup reports incompleteness instead of silently None (C2)."""
    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import enrich_ip

    result = await enrich_ip(
        "2001:db8::1",
        settings=settings_no_misp,
        misp=None,
        blocklist=BlocklistDB(),
        maxmind=MaxmindReader(),
        cloud=CloudPrefixDB(),
    )
    assert result.cloud_provider is None
    assert any("cloud_tag: IPv6 not supported" in e for e in result.errors)


@pytest.mark.asyncio
async def test_enrich_ip_ipv4_cloud_tag_path_unchanged(
    settings_no_misp: Settings,
) -> None:
    """IPv4 no-match leaves errors empty — C2 change does not affect IPv4 path."""
    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import enrich_ip

    result = await enrich_ip(
        "203.0.113.1",
        settings=settings_no_misp,
        misp=None,
        blocklist=BlocklistDB(),
        maxmind=MaxmindReader(),
        cloud=CloudPrefixDB(),
    )
    assert result.cloud_provider is None
    # No IPv6 error on an IPv4 address
    assert not any("IPv6" in e for e in result.errors)


@pytest.mark.asyncio
async def test_enrich_ip_internal_skips_external_only_lookups(
    settings_with_internal_cidrs: Settings,
) -> None:
    """Internal IPs skip MaxMind/cloud/MISP lookups — only internal flag is set."""
    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import enrich_ip

    result = await enrich_ip(
        "10.0.0.1",
        settings=settings_with_internal_cidrs,
        misp=None,
        blocklist=BlocklistDB(),
        maxmind=MaxmindReader(),
        cloud=CloudPrefixDB(),
    )
    assert result.internal is True
    assert result.asn is None
    assert result.cloud_provider is None
