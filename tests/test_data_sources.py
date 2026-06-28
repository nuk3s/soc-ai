"""Tests for the Data Sources config panel introspection."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from pydantic import SecretStr
from soc_ai.api.data_sources import collect_data_sources


def _settings(tmp_path: Path, **over: Any) -> Any:
    base: dict[str, Any] = dict(
        blocklist_data_dir=tmp_path,
        maxmind_data_dir=tmp_path,
        cloud_prefix_data_dir=tmp_path,
        maxmind_license_key=None,
        misp_url="",
        misp_api_key=None,
        allow_online_enrichment=False,
        greynoise_api_key=None,
        shodan_api_key=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_catalog_covers_local_and_online(tmp_path: Path) -> None:
    ids = {s.id for s in collect_data_sources(_settings(tmp_path))}
    assert {
        "blocklists",
        "maxmind",
        "cloud_prefixes",
        "misp",
        "shodan_internetdb",
        "greynoise",
        "shodan_host",
        "cvedb",
    } <= ids


def test_online_tools_default_off_and_need_config(tmp_path: Path) -> None:
    srcs = {s.id: s for s in collect_data_sources(_settings(tmp_path))}
    gn = srcs["greynoise"]
    assert gn.enabled is False
    assert gn.needs_key is True
    assert gn.key_configured is False
    assert srcs["shodan_internetdb"].enabled is False  # gated by the master flag
    assert srcs["cvedb"].enabled is False  # free but still master-flag gated
    assert srcs["cvedb"].needs_key is False
    assert srcs["shodan_host"].needs_key is True  # paid, key-gated
    assert srcs["shodan_host"].enabled is False


def test_freshness_reads_local_file_mtime(tmp_path: Path) -> None:
    (tmp_path / "tor_exits.txt").write_text("1.2.3.4\n")
    bl = {s.id: s for s in collect_data_sources(_settings(tmp_path))}["blocklists"]
    assert bl.present is True
    assert bl.last_refreshed is not None  # ISO mtime of the freshest feed file


def test_online_enabled_when_flag_and_key_present(tmp_path: Path) -> None:
    srcs = {
        s.id: s
        for s in collect_data_sources(
            _settings(tmp_path, allow_online_enrichment=True, greynoise_api_key=SecretStr("k"))
        )
    }
    assert srcs["greynoise"].enabled is True
    assert srcs["greynoise"].key_configured is True
    assert srcs["shodan_internetdb"].enabled is True  # no key required
