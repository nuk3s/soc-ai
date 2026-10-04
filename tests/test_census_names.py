"""The census lists machines, and a hostname names one.

The census listed mDNS service names (``_uscan._tcp.local``) and reverse names
(``…in-addr.arpa``) as strong hostnames, and a broadcast address as a host with
3,733 events. Each test plants the needle and a negative control beside it: a
plain ``.local`` name, an underscore inside a label, and the address one below
the broadcast address.
"""

from __future__ import annotations

from ipaddress import IPv4Network
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.dossier.infer import _clean_hostname
from soc_ai.dossier.observe import _dns_claim
from soc_ai.dossier.types import is_service_or_reverse_name
from soc_ai.enrichment import host_dossier as job
from soc_ai.store.models import HostDossier
from sqlalchemy import select

from tests.test_host_dossier_job import _db, _FakeES, _settings


@pytest.mark.parametrize(
    "name",
    [
        "_uscan._tcp.local",
        "Living Room._amzn-alexa._tcp.local.",
        "_services._dns-sd._udp.local",
        "10.2.0.192.in-addr.arpa",
        "1.0.0.0.ip6.arpa",
        "IN-ADDR.ARPA",
    ],
)
def test_a_service_or_reverse_name_names_no_machine(name: str) -> None:
    assert is_service_or_reverse_name(name)
    assert _clean_hostname(name) is None


@pytest.mark.parametrize("name", ["nas01.local", "my_host.example.test", "dc01.example.test"])
def test_an_ordinary_name_is_kept(name: str) -> None:
    """Negative control: ``.local`` and an inner underscore are ordinary names."""
    assert not is_service_or_reverse_name(name)
    assert _clean_hostname(name) == name


def test_a_service_name_makes_no_dns_claim() -> None:
    nets = [IPv4Network("192.168.10.0/24")]
    bucket: dict[str, Any] = {"key": "192.168.10.40", "doc_count": 12}
    assert _dns_claim("_uscan._tcp.local", bucket, nets) is None
    assert _dns_claim("40.10.168.192.in-addr.arpa", bucket, nets) is None
    claim = _dns_claim("printer01.example.test", bucket, nets)
    assert claim is not None and claim.ip == "192.168.10.40"


async def test_the_census_lists_no_broadcast_address(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos, internal_cidrs=[IPv4Network("192.168.10.0/24")])
    engine, maker = await _db(settings)
    es = _FakeES(
        src={"192.168.10.254": 40, "192.168.10.255": 3733},
        dst={"255.255.255.255": 900, "192.168.10.20": 12},
    )

    await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        ips = set((await db.scalars(select(HostDossier.ip))).all())
    assert ips == {"192.168.10.254", "192.168.10.20"}
    await engine.dispose()


def test_only_an_ipv4_network_of_four_or_more_has_a_broadcast_address() -> None:
    nets = [IPv4Network("192.168.10.0/24"), IPv4Network("192.168.20.0/31")]
    assert job._broadcast_addresses(nets) == frozenset({"192.168.10.255", "255.255.255.255"})
