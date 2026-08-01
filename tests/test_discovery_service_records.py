"""DNS-SD / SRV service records must never become internal identifiers.

Dogfood 2026-07-31: the auto-detected "internal domain suffixes" list was
polluted with mDNS service types (``_dns-sd._udp.local``, ``_printer._tcp.local``)
and a doubled suffix (``_https.hermes.hq.lan.hq.lan``). These are DNS-SD
(RFC 6763) / SRV (RFC 2782) service records — underscore-prefixed labels — never
a host's own domain.
"""

from __future__ import annotations

from soc_ai.enrichment.discovery import _Candidate, _ingest_buckets, _is_service_record_name


def test_is_service_record_name() -> None:
    assert _is_service_record_name("_dns-sd._udp.local")
    assert _is_service_record_name("_printer._tcp.local")
    assert _is_service_record_name("_ipp._tcp.local")
    assert _is_service_record_name("_https.hermes.hq.lan")
    # a real host FQDN is NOT a service record
    assert not _is_service_record_name("dc01.corp.hq.lan")
    assert not _is_service_record_name("host.lan")
    assert not _is_service_record_name("hermes.hq.lan")


def test_ingest_drops_service_records_but_keeps_real_hosts() -> None:
    suffixes: dict[str, _Candidate] = {}
    hosts: dict[str, _Candidate] = {}
    buckets = [
        {"key": "_dns-sd._udp.local", "doc_count": 25200, "distinct_hosts": {"value": 9}},
        {"key": "_https.hermes.hq.lan", "doc_count": 32, "distinct_hosts": {"value": 2}},
        {"key": "dc01.corp.hq.lan", "doc_count": 10, "distinct_hosts": {"value": 3}},
    ]
    _ingest_buckets(buckets, [], suffixes, hosts, associated=False)

    # No service record leaks into either the suffix or the bare-host set.
    assert not any(label.startswith("_") for s in suffixes for label in s.split("."))
    assert not any(label.startswith("_") for h in hosts for label in h.split("."))
    assert "_udp.local" not in suffixes
    assert "_dns-sd._udp.local" not in hosts

    # The genuine host still contributes its registrable parent suffix.
    assert "corp.hq.lan" in suffixes
