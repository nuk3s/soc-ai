"""Tests for soc_ai.enrichment.cloud_tags."""

from __future__ import annotations

import json
from pathlib import Path

from soc_ai.enrichment.cloud_tags import CloudPrefixDB


def test_cloud_prefix_db_aws_lookup(tmp_path: Path) -> None:
    """AWS prefix JSON in canonical AWS format is parsed correctly."""
    aws_data = {
        "syncToken": "1234567890",
        "createDate": "2026-04-01-00-00-00",
        "prefixes": [
            {"ip_prefix": "52.0.0.0/15", "region": "us-east-1", "service": "AMAZON"},
            {"ip_prefix": "52.0.0.0/15", "region": "us-east-1", "service": "EC2"},
        ],
        "ipv6_prefixes": [],
    }
    (tmp_path / "aws.json").write_text(json.dumps(aws_data), encoding="utf-8")
    db = CloudPrefixDB.from_dir(tmp_path)
    tag = db.lookup_ip("52.0.0.5")
    assert tag is not None
    assert tag.provider == "AWS"
    assert tag.region == "us-east-1"


def test_cloud_prefix_db_no_match(tmp_path: Path) -> None:
    """Non-cloud IP returns None."""
    aws_data = {"prefixes": [], "ipv6_prefixes": []}
    (tmp_path / "aws.json").write_text(json.dumps(aws_data), encoding="utf-8")
    db = CloudPrefixDB.from_dir(tmp_path)
    assert db.lookup_ip("198.51.100.1") is None


def test_cloud_prefix_db_missing_files_no_error(tmp_path: Path) -> None:
    """Empty data dir is fine; everything returns None."""
    db = CloudPrefixDB.from_dir(tmp_path)
    assert db.lookup_ip("8.8.8.8") is None


def test_cloud_prefix_db_cloudflare_envelope_format(tmp_path: Path) -> None:
    """Cloudflare's wrapped JSON envelope (refresh CLI converts TXT to {prefixes: [...]}) parses."""
    cf_data = {"prefixes": ["1.1.1.0/24", "104.16.0.0/13"]}
    (tmp_path / "cloudflare.json").write_text(json.dumps(cf_data), encoding="utf-8")
    db = CloudPrefixDB.from_dir(tmp_path)
    tag = db.lookup_ip("1.1.1.50")
    assert tag is not None
    assert tag.provider == "Cloudflare"
