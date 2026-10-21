"""Tests for the Data Sources config panel introspection."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from pydantic import SecretStr
from soc_ai import doctor
from soc_ai.api.data_sources import (
    BLOCKLIST_FEED_FILES,
    blocklist_feed_files,
    collect_data_sources,
    local_feed_health,
)
from soc_ai.config import Settings

_DEFAULT_SOURCES = ["urlhaus", "threatfox", "feodo", "tor", "internal_seed"]
DASH = re.compile("[\u2013\u2014]")


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
        blocklist_sources=list(_DEFAULT_SOURCES),
        blocklist_stale_threshold_days=7,
        cloud_prefix_stale_threshold_days=45,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _write(path: Path, *, days_old: float = 0.0) -> None:
    """Write a feed file whose mtime is *days_old* days before now."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n")
    stamp = time.time() - days_old * 86400
    os.utime(path, (stamp, stamp))


def _write_all_feeds(d: Path, *, days_old: float = 0.0) -> None:
    for name in ("urlhaus.csv", "threatfox.json", "feodo.csv", "tor_exits.txt"):
        _write(d / name, days_old=days_old)


def _source(sources: list[Any], sid: str) -> Any:
    return next(s for s in sources if s.id == sid)


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
    assert srcs["maxmind"].needs_key is False  # nothing downloads with the key
    assert srcs["shodan_host"].needs_key is True  # paid, key-gated
    assert srcs["shodan_host"].enabled is False

    # A blank key (the bare `KEY=` line in .env.example) is not a configured key:
    # the lookup tools refuse with not_configured, so the catalog must agree.
    blank = {
        s.id: s
        for s in collect_data_sources(
            _settings(
                tmp_path,
                allow_online_enrichment=True,
                greynoise_api_key=SecretStr(""),
                shodan_api_key=SecretStr(""),
                maxmind_license_key=SecretStr(""),
            )
        )
    }
    for sid in ("greynoise", "shodan_host"):
        assert blank[sid].key_configured is False, sid
        assert blank[sid].enabled is False, sid
    assert blank["maxmind"].key_configured is False


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


# ---------------------------------------------------------------------------
# H1-D11: a stale or absent local feed is not "Active" (dogfood 2026-10-19)
# ---------------------------------------------------------------------------


def test_a_stale_feed_reads_stale_and_names_each_feed(tmp_path: Path) -> None:
    """The fresh install of H1: tor at 88 days, three feeds never fetched.

    The panel showed a green "Active" because one file existed. The doctor
    said "never refreshed: urlhaus, threatfox, feodo. stale after 7 days: tor".
    """
    _write(tmp_path / "tor_exits.txt", days_old=88)
    bl = _source(collect_data_sources(_settings(tmp_path)), "blocklists")
    assert bl.state == "stale"
    assert bl.present is True
    assert "soc-ai finds no file for urlhaus, threatfox and feodo." in bl.note
    assert "The tor feed is 88 days old." in bl.note
    assert "A feed is stale after 7 days." in bl.note


def test_no_feed_file_reads_missing(tmp_path: Path) -> None:
    bl = _source(collect_data_sources(_settings(tmp_path)), "blocklists")
    assert bl.state == "missing"
    assert bl.present is False


def test_fresh_feeds_read_active(tmp_path: Path) -> None:
    _write_all_feeds(tmp_path, days_old=1)
    bl = _source(collect_data_sources(_settings(tmp_path)), "blocklists")
    assert bl.state == "active"
    assert "finds no file" not in bl.note and "days old" not in bl.note


def test_a_fresh_feed_beside_an_absent_feed_reads_partial(tmp_path: Path) -> None:
    _write(tmp_path / "tor_exits.txt", days_old=1)
    bl = _source(collect_data_sources(_settings(tmp_path)), "blocklists")
    assert bl.state == "partial"
    assert "soc-ai finds no file for urlhaus, threatfox and feodo." in bl.note


def test_the_threshold_is_the_setting(tmp_path: Path) -> None:
    """Negative control: the same file is fresh under a wider threshold."""
    _write_all_feeds(tmp_path, days_old=10)
    assert local_feed_health(_settings(tmp_path))["blocklists"].state == "stale"
    wide = _settings(tmp_path, blocklist_stale_threshold_days=30)
    assert local_feed_health(wide)["blocklists"].state == "active"


def test_an_unconfigured_feed_is_not_judged(tmp_path: Path) -> None:
    """A feed absent from blocklist_sources is not missing. internal_seed is
    operator data with no refresh, so the rule skips it, as the doctor does."""
    _write(tmp_path / "tor_exits.txt", days_old=1)
    s = _settings(tmp_path, blocklist_sources=["tor", "internal_seed"])
    assert local_feed_health(s)["blocklists"].state == "active"
    assert [f.source for f in blocklist_feed_files(s)] == ["tor"]


def test_maxmind_reads_missing_partial_and_active(tmp_path: Path) -> None:
    """H1 STE item 33: an absent MaxMind file reads "Missing"."""
    mm = tmp_path / "mm"
    mm.mkdir()
    s = _settings(tmp_path, maxmind_data_dir=mm)
    assert _source(collect_data_sources(s), "maxmind").state == "missing"
    _write(mm / "GeoLite2-City.mmdb")
    row = _source(collect_data_sources(s), "maxmind")
    assert row.state == "partial"
    assert "GeoLite2-ASN.mmdb" in row.note
    _write(mm / "GeoLite2-ASN.mmdb")
    assert _source(collect_data_sources(s), "maxmind").state == "active"


def test_cloud_prefixes_use_the_enrichment_staleness_rule(tmp_path: Path) -> None:
    cloud = tmp_path / "cloud"
    cloud.mkdir()
    s = _settings(tmp_path, cloud_prefix_data_dir=cloud)
    assert _source(collect_data_sources(s), "cloud_prefixes").state == "missing"
    _write(cloud / "aws.json")
    assert _source(collect_data_sources(s), "cloud_prefixes").state == "active"
    old = (datetime.now(UTC) - timedelta(days=60)).isoformat()
    (cloud / "cloud_refresh_status.json").write_text(
        json.dumps({"azure": {"last_success": old}}), encoding="utf-8"
    )
    row = _source(collect_data_sources(s), "cloud_prefixes")
    assert row.state == "stale"
    assert "60 days old" in row.note


def test_the_rule_matches_the_doctor(tmp_path: Path) -> None:
    """One rule for the console and the doctor: the same feed map, and the
    same verdict on the same files."""
    assert dict(doctor._BLOCKLIST_FEED_FILES) == dict(BLOCKLIST_FEED_FILES)
    real = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        soc_ai_data_dir=tmp_path / "data",
        blocklist_data_dir=tmp_path / "blocklists",
        blocklist_sources=list(_DEFAULT_SOURCES),
    )
    _write(tmp_path / "blocklists" / "tor_exits.txt", days_old=88)
    _write(tmp_path / "blocklists" / "feodo.csv", days_old=1)
    files = {f.source: f.state for f in blocklist_feed_files(real)}
    assert files == {"urlhaus": "missing", "threatfox": "missing", "feodo": "fresh", "tor": "stale"}
    detail = next(r for r in doctor.check_blocklists(real) if r.name == "blocklists").detail
    assert "never refreshed: urlhaus, threatfox." in detail
    assert "tor at 88 days old" in detail
    assert "feodo" not in detail


# ---------------------------------------------------------------------------
# R5-D21, R5 STE item 36: notes name the console path and read in STE
# ---------------------------------------------------------------------------


def test_online_lookup_notes_name_the_settings_sections(tmp_path: Path) -> None:
    srcs = collect_data_sources(_settings(tmp_path))
    for sid in ("greynoise", "shodan_host"):
        note = _source(srcs, sid).note
        assert ".env" not in note, note
        assert "Settings > API keys" in note, note
        assert "Settings > Online enrichment" in note, note
    misp = _source(srcs, "misp").note
    assert "Settings > Online enrichment" in misp and "Settings > API keys" in misp


def test_the_shodan_host_name_reads_in_words(tmp_path: Path) -> None:
    name = _source(collect_data_sources(_settings(tmp_path)), "shodan_host").name
    assert "/shodan/host" not in name
    assert "vulns" not in name


def test_online_and_service_rows_carry_a_state(tmp_path: Path) -> None:
    srcs = collect_data_sources(_settings(tmp_path))
    assert _source(srcs, "greynoise").state == "needs_key"
    assert _source(srcs, "shodan_internetdb").state == "off"
    assert _source(srcs, "misp").state == "off"
    on = collect_data_sources(
        _settings(tmp_path, allow_online_enrichment=True, greynoise_api_key=SecretStr("k"))
    )
    assert _source(on, "greynoise").state == "active"
    assert _source(on, "cvedb").state == "active"
    url_only = collect_data_sources(_settings(tmp_path, misp_url="https://misp.example.com"))
    assert _source(url_only, "misp").state == "needs_key"
    both = collect_data_sources(
        _settings(tmp_path, misp_url="https://misp.example.com", misp_api_key=SecretStr("k"))
    )
    assert _source(both, "misp").state == "active"


# Dogfood round 2: the grid row (R5-D30) and the blocklist title (V2-8)
# ---------------------------------------------------------------------------


def _grid(es: dict[str, Any], so: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    return {"es": es, "so": so or {"ok": True, "state": "ok", "detail": "ok"}}


def test_the_grid_row_comes_first_and_reads_the_health_probe(tmp_path: Path) -> None:
    """Data sources listed every enrichment feed and no row for the grid itself."""
    s = _settings(tmp_path, events_index_pattern="logs-*")
    up = collect_data_sources(s, grid=_grid({"ok": True, "state": "ok", "detail": "ok"}))
    grid = up[0]
    assert grid.id == "grid"
    assert grid.name == "Grid (Security Onion and Elasticsearch)"
    assert grid.category == "Grid"
    assert grid.state == "active"
    assert "`logs-*`" in grid.note
    assert "Settings > Connections" in grid.note
    assert not DASH.search(grid.name + grid.note)

    down = _source(
        collect_data_sources(
            s, grid=_grid({"ok": False, "state": "down", "kind": "refused", "detail": "x"})
        ),
        "grid",
    )
    assert down.state == "down"
    assert down.present is False
    assert down.note.startswith("The health probe cannot read Elasticsearch.")
    slow = _source(
        collect_data_sources(s, grid=_grid({"ok": False, "state": "slow", "detail": "x"})),
        "grid",
    )
    assert slow.state == "slow"
    so_down = _source(
        collect_data_sources(
            s,
            grid=_grid(
                {"ok": True, "state": "ok", "detail": "ok"},
                {"ok": False, "state": "down", "detail": "x"},
            ),
        ),
        "grid",
    )
    assert so_down.state == "partial"
    assert "Acknowledgements and cases fail." in so_down.note
    # No probe result yet: the row says so and claims nothing.
    unknown = _source(collect_data_sources(s), "grid")
    assert unknown.state == "unknown"


def test_the_blocklist_title_names_the_configured_feeds(tmp_path: Path) -> None:
    """The title named Spamhaus, which is off by default, and not ThreatFox."""
    name = _source(collect_data_sources(_settings(tmp_path)), "blocklists").name
    assert name == "Blocklists (URLhaus, ThreatFox, Feodo and Tor)"
    with_drop = _settings(tmp_path, blocklist_sources=["tor", "spamhaus_drop"])
    assert _source(collect_data_sources(with_drop), "blocklists").name == (
        "Blocklists (Tor and Spamhaus DROP)"
    )
    none = _settings(tmp_path, blocklist_sources=["internal_seed"])
    assert _source(collect_data_sources(none), "blocklists").name == "Blocklists"


def test_the_route_puts_the_probe_result_on_the_grid_row(settings_kratos: Settings) -> None:
    from unittest.mock import AsyncMock, patch

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    probed = _grid(
        {"ok": True, "state": "ok", "detail": "ok"}, {"ok": False, "state": "down", "detail": "x"}
    )
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        patch(
            "soc_ai.api.webui.routes_meta._cached_health_probes",
            AsyncMock(return_value=probed),
        ),
        TestClient(create_app()) as client,
    ):
        body = client.get("/api/v1/config/data-sources").json()
    grid = body["sources"][0]
    assert grid["id"] == "grid"
    assert grid["state"] == "partial"
    assert f"`{settings_kratos.events_index_pattern}`" in grid["note"]


def test_the_feed_names_match_the_doctor() -> None:
    from soc_ai.api.data_sources import BLOCKLIST_FEED_NAMES

    assert doctor._BLOCKLIST_FEED_NAMES == BLOCKLIST_FEED_NAMES
    assert set(BLOCKLIST_FEED_NAMES) == set(BLOCKLIST_FEED_FILES)
