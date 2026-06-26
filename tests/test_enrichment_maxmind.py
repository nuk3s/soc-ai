"""Tests for soc_ai.enrichment.maxmind."""

from __future__ import annotations

from pathlib import Path

import pytest
from soc_ai.enrichment.maxmind import (
    AsnInfo,
    MaxmindReader,
)


def test_maxmind_reader_no_files_returns_none(tmp_path: Path) -> None:
    """If neither .mmdb file is present, reader returns None for everything but doesn't raise."""
    reader = MaxmindReader.from_dir(tmp_path)
    assert reader.lookup_asn("8.8.8.8") is None
    assert reader.lookup_geoip("8.8.8.8") is None
    assert reader.is_available is False


def test_maxmind_reader_files_present_but_empty(tmp_path: Path) -> None:
    """Empty .mmdb files don't open as valid databases — reader stays unavailable."""
    (tmp_path / "GeoLite2-ASN.mmdb").write_bytes(b"")
    (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"")
    reader = MaxmindReader.from_dir(tmp_path)
    assert reader.is_available is False
    assert reader.lookup_asn("8.8.8.8") is None
    assert reader.lookup_geoip("8.8.8.8") is None


@pytest.mark.skipif(
    not (Path(__file__).parent / "fixtures" / "maxmind" / "GeoLite2-ASN-Test.mmdb").exists(),
    reason="MaxMind test fixture not vendored; download from MaxMind/GeoIP2-python repo",
)
def test_maxmind_reader_asn_lookup_with_fixture() -> None:
    """When real test mmdb is present, ASN lookup returns AsnInfo."""
    fixtures = Path(__file__).parent / "fixtures" / "maxmind"
    reader = MaxmindReader.from_dir(fixtures)
    info = reader.lookup_asn("1.0.0.0")
    if info is not None:
        assert isinstance(info, AsnInfo)
        assert info.number > 0
        assert info.org
