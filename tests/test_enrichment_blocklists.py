"""Tests for soc_ai.enrichment.blocklists."""

from __future__ import annotations

from pathlib import Path

import pytest
from soc_ai.enrichment.blocklists import BlocklistDB


def test_blocklistdb_loads_urlhaus_csv(tmp_path: Path) -> None:
    """BlocklistDB.from_dir loads URLhaus CSV and matches a known IP."""
    src = tmp_path / "urlhaus.csv"
    src.write_text(
        "# URLhaus sample\n"
        '"id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"\n'
        '"1","2026-04-01 12:00:00","http://198.51.100.5/payload.exe","online","malware_download","emotet","https://urlhaus.abuse.ch/url/1/","abuse_ch"\n'
        '"2","2026-04-01 12:00:00","http://evil.example.com/payload.exe","online","malware_download","trickbot","https://urlhaus.abuse.ch/url/2/","abuse_ch"\n',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["urlhaus"])
    hits = db.lookup_ip("198.51.100.5")
    assert len(hits) == 1
    assert hits[0].source == "abuse.ch URLhaus"
    assert "emotet" in hits[0].tags


def test_blocklistdb_lookup_ip_no_hits(tmp_path: Path) -> None:
    """Unknown IP returns empty list (not None, not raise)."""
    src = tmp_path / "urlhaus.csv"
    src.write_text(
        '"id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"\n',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["urlhaus"])
    assert db.lookup_ip("8.8.8.8") == []


def test_blocklistdb_lookup_domain_from_urlhaus(tmp_path: Path) -> None:
    """URLhaus URLs resolved to the hostname for domain lookups."""
    src = tmp_path / "urlhaus.csv"
    src.write_text(
        '"id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"\n'
        '"1","2026-04-01 12:00:00","http://evil.example.com/x","online","malware_download","trickbot","https://urlhaus.abuse.ch/url/1/","abuse_ch"\n',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["urlhaus"])
    hits = db.lookup_domain("evil.example.com")
    assert len(hits) == 1
    assert hits[0].source == "abuse.ch URLhaus"


def test_blocklistdb_missing_source_file_skips_silently(tmp_path: Path) -> None:
    """If a configured source's file is absent, BlocklistDB skips it (fail-open)."""
    db = BlocklistDB.from_dir(tmp_path, sources=["urlhaus"])
    assert db.lookup_ip("198.51.100.5") == []
    assert "urlhaus" in db.missing_sources


def test_blocklistdb_urlhaus_filters_offline_rows(tmp_path: Path) -> None:
    """URLhaus offline-status rows are not indexed (avoid FP noise)."""
    src = tmp_path / "urlhaus.csv"
    src.write_text(
        '"id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"\n'
        '"1","2026-04-01 12:00:00","http://198.51.100.5/x","offline","malware_download","emotet","https://urlhaus.abuse.ch/url/1/","abuse_ch"\n'
        '"2","2026-04-01 12:00:00","http://198.51.100.6/x","online","malware_download","trickbot","https://urlhaus.abuse.ch/url/2/","abuse_ch"\n',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["urlhaus"])
    assert db.lookup_ip("198.51.100.5") == []  # offline → not indexed
    assert len(db.lookup_ip("198.51.100.6")) == 1  # online → indexed


def test_blocklistdb_unknown_source_skips_silently(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Unknown source name lands in missing_sources without raising."""
    caplog.set_level("WARNING")
    db = BlocklistDB.from_dir(tmp_path, sources=["nonexistent_source"])
    assert "nonexistent_source" in db.missing_sources
    assert any("unknown blocklist source" in rec.message for rec in caplog.records)
    assert db.lookup_ip("8.8.8.8") == []


def test_blocklistdb_urlhaus_malformed_date_falls_back_to_none(tmp_path: Path) -> None:
    """Garbage in `dateadded` column doesn't crash; first_seen is None."""
    src = tmp_path / "urlhaus.csv"
    src.write_text(
        '"id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"\n'
        '"1","not-a-date","http://198.51.100.7/x","online","malware_download","emotet","https://urlhaus.abuse.ch/url/1/","abuse_ch"\n',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["urlhaus"])
    hits = db.lookup_ip("198.51.100.7")
    assert len(hits) == 1
    assert hits[0].first_seen is None


def test_blocklistdb_loads_threatfox_json(tmp_path: Path) -> None:
    """ThreatFox JSON dump populates ips/domains/hashes."""
    src = tmp_path / "threatfox.json"
    sample_hash = "deadbeef" + "0" * 56
    src.write_text(
        '{"1": [{"ioc_value": "203.0.113.10", "ioc_type": "ip:port", '
        '"threat_type": "botnet_cc", "malware": "trickbot", '
        '"first_seen": "2026-04-01 12:00:00", "tags": "trickbot,c2"}],'
        '"2": [{"ioc_value": "evil2.example.com", "ioc_type": "domain", '
        '"threat_type": "malware_download", "malware": "emotet", '
        '"first_seen": "2026-04-02 12:00:00", "tags": "emotet"}],'
        '"3": [{"ioc_value": "' + sample_hash + '", "ioc_type": "sha256_hash", '
        '"threat_type": "payload", "malware": "qakbot", '
        '"first_seen": "2026-04-03 12:00:00", "tags": "qakbot"}]}',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["threatfox"])
    assert len(db.lookup_ip("203.0.113.10")) == 1
    assert "trickbot" in db.lookup_ip("203.0.113.10")[0].tags
    assert len(db.lookup_domain("evil2.example.com")) == 1
    assert len(db.lookup_hash(sample_hash)) == 1


def test_blocklistdb_loads_feodo_csv(tmp_path: Path) -> None:
    """Feodo Tracker IP blocklist populates ips."""
    src = tmp_path / "feodo.csv"
    src.write_text(
        "# Feodo Tracker IP Blocklist\n"
        "# first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n"
        "2026-04-01 00:00:00,192.0.2.50,443,online,2026-04-30 12:00:00,Emotet\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["feodo"])
    hits = db.lookup_ip("192.0.2.50")
    assert len(hits) == 1
    assert hits[0].source == "abuse.ch Feodo Tracker"
    assert "emotet" in [t.lower() for t in hits[0].tags]


def test_blocklistdb_loads_tor_exit_list(tmp_path: Path) -> None:
    """Tor exit-node list (one IP per line, # comments) populates ips with tag=tor_exit."""
    src = tmp_path / "tor_exits.txt"
    src.write_text(
        "# Tor exit nodes (snapshot)\n198.51.100.99\n203.0.113.99\n\n# end\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["tor"])
    hits = db.lookup_ip("198.51.100.99")
    assert len(hits) == 1
    assert hits[0].source == "Tor Project exit list"
    assert "tor_exit" in hits[0].tags


def test_blocklistdb_loads_internal_seed_yaml(tmp_path: Path) -> None:
    """Operator-curated YAML seed list with mixed IOC types."""
    src = tmp_path / "internal_seed.yaml"
    src.write_text(
        "# Operator's local known-bad seed list.\n"
        "ips:\n"
        "  - indicator: 198.51.100.123\n"
        "    tags: [past_incident_2026-q1, c2]\n"
        "    note: 'Phishing C2 from incident #INC-1234'\n"
        "domains:\n"
        "  - indicator: known-bad.example.org\n"
        "    tags: [internal_blocklist]\n"
        "hashes: []\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["internal_seed"])
    assert len(db.lookup_ip("198.51.100.123")) == 1
    assert "past_incident_2026-q1" in db.lookup_ip("198.51.100.123")[0].tags
    assert len(db.lookup_domain("known-bad.example.org")) == 1


def test_threatfox_handles_malformed_json_shape(tmp_path: Path) -> None:
    """Non-list values + non-dict entries don't crash; just get skipped."""
    src = tmp_path / "threatfox.json"
    src.write_text(
        '{"1": null, "2": [{"ioc_value": "203.0.113.99", "ioc_type": "ip", '
        '"first_seen": "2026-04-01 12:00:00", "tags": "test"}], '
        '"3": "not a list", "4": [42, {"ioc_value": "203.0.113.100", "ioc_type": "ip", '
        '"first_seen": "2026-04-01 12:00:00", "tags": "test"}]}',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["threatfox"])
    # Both valid IPs were indexed; null/non-list/non-dict were skipped silently.
    assert len(db.lookup_ip("203.0.113.99")) == 1
    assert len(db.lookup_ip("203.0.113.100")) == 1


def test_threatfox_handles_ipv6_with_port(tmp_path: Path) -> None:
    """IPv6 addresses (bracketed + bare) are correctly extracted."""
    src = tmp_path / "threatfox.json"
    src.write_text(
        '{"1": [{"ioc_value": "[2001:db8::1]:443", "ioc_type": "ip:port", '
        '"first_seen": "2026-04-01 12:00:00", "tags": "test"}], '
        '"2": [{"ioc_value": "2001:db8::2", "ioc_type": "ip", '
        '"first_seen": "2026-04-01 12:00:00", "tags": "test"}]}',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["threatfox"])
    assert len(db.lookup_ip("2001:db8::1")) == 1
    assert len(db.lookup_ip("2001:db8::2")) == 1


def test_feodo_skips_empty_ip_rows(tmp_path: Path) -> None:
    """Feodo rows with empty IP column don't get indexed under '' key."""
    src = tmp_path / "feodo.csv"
    src.write_text(
        "# header\n"
        "first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n"
        "2026-04-01 00:00:00,,443,online,2026-04-30 12:00:00,Emotet\n"
        "2026-04-01 00:00:00,192.0.2.51,443,online,2026-04-30 12:00:00,Emotet\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["feodo"])
    assert db.lookup_ip("") == []
    assert len(db.lookup_ip("192.0.2.51")) == 1


def test_tor_skips_non_ip_lines(tmp_path: Path) -> None:
    """Tor exit list rows that aren't valid IPs are skipped (no junk keys)."""
    src = tmp_path / "tor_exits.txt"
    src.write_text(
        "# header\ngarbage-not-ip\n198.51.100.50\nanother-non-ip-line\n203.0.113.50\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["tor"])
    assert db.lookup_ip("garbage-not-ip") == []
    assert len(db.lookup_ip("198.51.100.50")) == 1
    assert len(db.lookup_ip("203.0.113.50")) == 1


def test_internal_seed_handles_scalar_tags(tmp_path: Path) -> None:
    """Operator writing `tags: foo` (scalar instead of list) gets a single-tag tuple."""
    src = tmp_path / "internal_seed.yaml"
    src.write_text(
        "ips:\n  - indicator: 198.51.100.200\n    tags: active_c2\ndomains: []\nhashes: []\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["internal_seed"])
    hits = db.lookup_ip("198.51.100.200")
    assert len(hits) == 1
    assert hits[0].tags == ("active_c2",)


def test_blocklistdb_spamhaus_requires_license_ack(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Spamhaus loader refuses to load if license_acknowledged=False."""
    src = tmp_path / "spamhaus_drop.txt"
    src.write_text("# Spamhaus DROP\n192.0.2.0/24 ; SBL12345\n", encoding="utf-8")
    caplog.set_level("WARNING")
    db = BlocklistDB.from_dir(
        tmp_path, sources=["spamhaus_drop"], spamhaus_license_acknowledged=False
    )
    assert "spamhaus_drop" in db.missing_sources
    assert any("Spamhaus license" in rec.message for rec in caplog.records)
    assert db.lookup_ip("192.0.2.5") == []


def test_blocklistdb_loads_spamhaus_drop_when_acknowledged(tmp_path: Path) -> None:
    """Spamhaus DROP loader populates ips for any IP inside the listed CIDRs."""
    src = tmp_path / "spamhaus_drop.txt"
    src.write_text(
        "; Spamhaus DROP List\n192.0.2.0/24 ; SBL12345\n203.0.113.0/24 ; SBL67890\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(
        tmp_path, sources=["spamhaus_drop"], spamhaus_license_acknowledged=True
    )
    hits = db.lookup_ip("192.0.2.5")
    assert len(hits) == 1
    assert hits[0].source == "Spamhaus DROP"
    assert "SBL12345" in hits[0].tags
    # Outside the CIDR — no hit.
    assert db.lookup_ip("198.51.100.1") == []


def test_blocklistdb_spamhaus_skips_malformed_cidrs(tmp_path: Path) -> None:
    """Spamhaus DROP rows with malformed CIDRs are silently skipped (fail-open)."""
    src = tmp_path / "spamhaus_drop.txt"
    src.write_text(
        "; Spamhaus DROP List\n"
        "not-a-cidr ; SBL00000\n"
        "192.0.2.0/24 ; SBL12345\n"
        "999.999.999.0/24 ; SBL00001\n"
        "203.0.113.0/24 ; SBL67890\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(
        tmp_path, sources=["spamhaus_drop"], spamhaus_license_acknowledged=True
    )
    # Two valid CIDRs loaded, two malformed skipped.
    assert len(db.spamhaus_networks) == 2
    assert len(db.lookup_ip("192.0.2.5")) == 1
    assert len(db.lookup_ip("203.0.113.5")) == 1


# =====================================================================
# C4: IP normalisation — zero-padded octets match canonical form
# =====================================================================


def test_norm_ip_strips_leading_zeros_in_octets() -> None:
    """_norm_ip canonicalises zero-padded IPv4 octets."""
    from soc_ai.enrichment.blocklists import _norm_ip

    assert _norm_ip("192.168.001.005") == "192.168.1.5"
    assert _norm_ip("010.000.000.001") == "10.0.0.1"
    assert _norm_ip("192.168.1.5") == "192.168.1.5"  # already canonical
    assert _norm_ip("2001:db8::1") == "2001:db8::1"  # IPv6 unchanged
    assert _norm_ip("not-an-ip") is None  # non-IP returns None
    assert _norm_ip("hostname.example.com") is None  # domain returns None


def test_blocklistdb_zero_padded_source_found_by_canonical_lookup(tmp_path: Path) -> None:
    """A blocklist source using zero-padded IPs is found via canonical lookup."""
    src = tmp_path / "urlhaus.csv"
    # The source file has zero-padded octets in the URL host.
    src.write_text(
        '"id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"\n'
        '"1","2026-04-01 12:00:00","http://192.168.001.005/payload.exe","online","malware_download","emotet","https://urlhaus.abuse.ch/url/1/","abuse_ch"\n',
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["urlhaus"])
    # Canonical form must match
    hits = db.lookup_ip("192.168.1.5")
    assert len(hits) == 1
    # Zero-padded lookup must also match (lookup normalises too)
    hits2 = db.lookup_ip("192.168.001.005")
    assert len(hits2) == 1


def test_blocklistdb_canonical_source_found_by_padded_lookup(tmp_path: Path) -> None:
    """A lookup with zero-padded octets finds a canonically-stored entry."""
    src = tmp_path / "feodo.csv"
    src.write_text(
        "2026-04-01 00:00:00,198.51.100.5,443,0,0,Dridex\n",
        encoding="utf-8",
    )
    db = BlocklistDB.from_dir(tmp_path, sources=["feodo"])
    # Zero-padded lookup must find the canonically stored IP
    hits = db.lookup_ip("198.051.100.005")
    assert len(hits) == 1
    assert hits[0].source == "abuse.ch Feodo Tracker"


def test_empty_blocklist_dir_warns_at_build(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """build_local_enrichment_context emits ONE high-signal warning naming the
    remediation when no blocklist source loads (e.g. the Docker volume was never
    seeded), instead of only per-source 'file missing' lines. Regression for the
    silent-degradation gap: an unseeded deploy loses local IOC reputation.
    """
    from types import SimpleNamespace

    from soc_ai.tools.enrichment import build_local_enrichment_context

    settings = SimpleNamespace(
        blocklist_data_dir=tmp_path,  # empty dir → nothing loads
        blocklist_sources=["urlhaus", "feodo"],
        spamhaus_license_acknowledged=False,
        maxmind_data_dir=tmp_path,
        cloud_prefix_data_dir=tmp_path,
    )
    caplog.set_level("WARNING")
    ctx = build_local_enrichment_context(settings)  # type: ignore[arg-type]
    assert ctx.blocklist.loaded_sources == []
    assert any(
        "local IOC reputation is DISABLED" in rec.message and "blocklists refresh" in rec.message
        for rec in caplog.records
    )
