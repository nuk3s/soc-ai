"""Tests for soc_ai.enrichment.blocklist_refresh.

Network is fully mocked with respx — these tests never hit the live internet.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import ClassVar

import httpx
import pytest
import respx
from soc_ai.demo.guard import DemoEgressBlocked
from soc_ai.enrichment.blocklist_refresh import (
    BLOCKLIST_FEEDS,
    _atomic_write_bytes,
    _refresh_cli,
    refresh_blocklists,
    register_subparser,
)
from soc_ai.enrichment.blocklists import BlocklistDB

# ---------------------------------------------------------------------------
# Realistic feed bodies — each is in the EXACT format the matching loader parses.
# ---------------------------------------------------------------------------

_URLHAUS_BODY = (
    "# URLhaus dump\n"
    '"id","dateadded","url","url_status","threat","tags","urlhaus_link","reporter"\n'
    '"1","2026-05-13 12:00:00","http://198.51.100.5/payload.exe","online",'
    '"malware_download","emotet","https://urlhaus.abuse.ch/url/1/","abuse_ch"\n'
)
_THREATFOX_BODY = (
    '{"1": [{"ioc_value": "203.0.113.10", "ioc_type": "ip:port", '
    '"first_seen": "2026-05-13 12:00:00", "tags": "trickbot,c2"}]}'
)
_FEODO_BODY = (
    "# Feodo Tracker IP Blocklist\n"
    "# first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n"
    "2026-05-13 00:00:00,192.0.2.50,443,online,2026-05-13 12:00:00,Emotet\n"
)
_TOR_BODY = "# Tor exit nodes\n198.51.100.99\n203.0.113.99\n"

_AUTH_KEY = "test-secret-auth-key"


def _mock_all_feeds(mock: respx.MockRouter) -> None:
    mock.get(BLOCKLIST_FEEDS["urlhaus"].url).mock(
        return_value=httpx.Response(200, text=_URLHAUS_BODY)
    )
    mock.get(BLOCKLIST_FEEDS["threatfox"].url).mock(
        return_value=httpx.Response(200, text=_THREATFOX_BODY)
    )
    mock.get(BLOCKLIST_FEEDS["feodo"].url).mock(return_value=httpx.Response(200, text=_FEODO_BODY))
    mock.get(BLOCKLIST_FEEDS["tor"].url).mock(return_value=httpx.Response(200, text=_TOR_BODY))


# ---------------------------------------------------------------------------
# 1. Right filename + format the matching loader parses.
# ---------------------------------------------------------------------------


async def test_refresh_writes_filenames_loaders_can_parse(tmp_path: Path) -> None:
    """Each feed is written under the loader's exact filename and round-trips."""
    with respx.mock(assert_all_called=False) as mock:
        _mock_all_feeds(mock)
        results = await refresh_blocklists(
            tmp_path,
            sources=["urlhaus", "threatfox", "feodo", "tor"],
            abuse_ch_auth_key=_AUTH_KEY,
        )

    # Exact filenames the loaders read.
    assert (tmp_path / "urlhaus.csv").exists()
    assert (tmp_path / "threatfox.json").exists()
    assert (tmp_path / "feodo.csv").exists()
    assert (tmp_path / "tor_exits.txt").exists()
    assert all(r.success for r in results)
    assert all(not r.skipped for r in results)

    # The real BlocklistDB loaders parse what we wrote → IOCs are queryable.
    db = BlocklistDB.from_dir(tmp_path, sources=["urlhaus", "threatfox", "feodo", "tor"])
    assert db.missing_sources == []
    assert len(db.lookup_ip("198.51.100.5")) == 1  # urlhaus
    assert len(db.lookup_ip("203.0.113.10")) == 1  # threatfox ip:port
    assert len(db.lookup_ip("192.0.2.50")) == 1  # feodo
    tor_hits = db.lookup_ip("198.51.100.99")  # tor
    assert len(tor_hits) == 1
    assert "tor_exit" in tor_hits[0].tags


async def test_refresh_filename_matches_feed_registry(tmp_path: Path) -> None:
    """The registry filenames are exactly what blocklists.py loaders expect."""
    assert BLOCKLIST_FEEDS["urlhaus"].filename == "urlhaus.csv"
    assert BLOCKLIST_FEEDS["threatfox"].filename == "threatfox.json"
    assert BLOCKLIST_FEEDS["feodo"].filename == "feodo.csv"
    assert BLOCKLIST_FEEDS["tor"].filename == "tor_exits.txt"


# ---------------------------------------------------------------------------
# 2. abuse.ch Auth-Key handling.
# ---------------------------------------------------------------------------


async def test_auth_key_sent_as_header_to_abuse_ch_feeds(tmp_path: Path) -> None:
    """The Auth-Key header is sent to abuse.ch feeds and NOT to Tor."""
    with respx.mock(assert_all_called=True) as mock:
        urlhaus_route = mock.get(BLOCKLIST_FEEDS["urlhaus"].url).mock(
            return_value=httpx.Response(200, text=_URLHAUS_BODY)
        )
        tor_route = mock.get(BLOCKLIST_FEEDS["tor"].url).mock(
            return_value=httpx.Response(200, text=_TOR_BODY)
        )
        await refresh_blocklists(tmp_path, sources=["urlhaus", "tor"], abuse_ch_auth_key=_AUTH_KEY)

    abuse_req = urlhaus_route.calls.last.request
    assert abuse_req.headers.get("Auth-Key") == _AUTH_KEY
    tor_req = tor_route.calls.last.request
    assert "Auth-Key" not in tor_req.headers


async def test_missing_auth_key_skips_abuse_ch_but_refreshes_tor(tmp_path: Path) -> None:
    """No Auth-Key → abuse.ch feeds skipped gracefully; Tor still refreshes."""
    with respx.mock(assert_all_called=False) as mock:
        # abuse.ch routes are mocked but must NOT be called when the key is absent.
        urlhaus_route = mock.get(BLOCKLIST_FEEDS["urlhaus"].url).mock(
            return_value=httpx.Response(200, text=_URLHAUS_BODY)
        )
        threatfox_route = mock.get(BLOCKLIST_FEEDS["threatfox"].url).mock(
            return_value=httpx.Response(200, text=_THREATFOX_BODY)
        )
        feodo_route = mock.get(BLOCKLIST_FEEDS["feodo"].url).mock(
            return_value=httpx.Response(200, text=_FEODO_BODY)
        )
        mock.get(BLOCKLIST_FEEDS["tor"].url).mock(return_value=httpx.Response(200, text=_TOR_BODY))
        results = await refresh_blocklists(
            tmp_path,
            sources=["urlhaus", "threatfox", "feodo", "tor"],
            abuse_ch_auth_key=None,
        )

    by_src = {r.source: r for r in results}
    for src in ("urlhaus", "threatfox", "feodo"):
        assert by_src[src].skipped is True
        assert by_src[src].success is False
        assert "Auth-Key" in (by_src[src].error or "")
    # Skipped feeds were never fetched.
    assert not urlhaus_route.called
    assert not threatfox_route.called
    assert not feodo_route.called
    # No abuse.ch files were written (live files not clobbered).
    assert not (tmp_path / "urlhaus.csv").exists()
    assert not (tmp_path / "threatfox.json").exists()
    assert not (tmp_path / "feodo.csv").exists()
    # Tor still refreshed.
    assert by_src["tor"].success is True
    assert (tmp_path / "tor_exits.txt").exists()


async def test_auth_key_not_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The secret Auth-Key never appears in log output (even on failure)."""
    caplog.set_level("DEBUG")
    with respx.mock(assert_all_called=False) as mock:
        # Force a failure so the warning/error path also runs.
        mock.get(BLOCKLIST_FEEDS["urlhaus"].url).mock(return_value=httpx.Response(403))
        await refresh_blocklists(tmp_path, sources=["urlhaus"], abuse_ch_auth_key=_AUTH_KEY)
    assert _AUTH_KEY not in caplog.text


# ---------------------------------------------------------------------------
# 3. Atomic write (temp-then-move) behaviour.
# ---------------------------------------------------------------------------


def test_atomic_write_replaces_in_place(tmp_path: Path) -> None:
    """_atomic_write_bytes overwrites the live file and leaves no temp turds."""
    dest = tmp_path / "feed.csv"
    dest.write_bytes(b"OLD CONTENT")
    _atomic_write_bytes(dest, b"NEW CONTENT")
    assert dest.read_bytes() == b"NEW CONTENT"
    # No leftover temp files in the dir.
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "feed.csv"]
    assert leftovers == []


def test_atomic_write_uses_temp_then_move(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The write goes through a temp file in the SAME dir, then os.replace.

    A partial download therefore can't corrupt the live file: capture the
    (src, dst) os.replace is called with and prove src is a sibling temp file
    of dst (so the rename is atomic, not a cross-device copy).
    """
    import os as _os

    dest = tmp_path / "feed.csv"
    dest.write_bytes(b"LIVE")
    seen: dict[str, str] = {}
    real_replace = _os.replace

    def _spy_replace(src: object, dst: object, *a: object, **k: object) -> None:
        seen["src"] = str(src)
        seen["dst"] = str(dst)
        real_replace(src, dst, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr("soc_ai.enrichment.blocklist_refresh.os.replace", _spy_replace)
    _atomic_write_bytes(dest, b"FRESH")

    assert seen["dst"] == str(dest)
    src_path = Path(seen["src"])
    assert src_path.parent == dest.parent  # same dir → atomic rename
    assert src_path.name != dest.name  # it was a temp file
    assert dest.read_bytes() == b"FRESH"


def test_atomic_write_failure_does_not_corrupt_live_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If os.replace fails mid-write, the live file is untouched and no temp leaks."""

    def _boom(*_a: object, **_k: object) -> None:
        raise OSError("simulated replace failure")

    dest = tmp_path / "feed.csv"
    dest.write_bytes(b"LIVE-GOOD")
    monkeypatch.setattr("soc_ai.enrichment.blocklist_refresh.os.replace", _boom)

    with pytest.raises(OSError, match="simulated replace failure"):
        _atomic_write_bytes(dest, b"PARTIAL")

    # Live file unchanged; temp file cleaned up.
    assert dest.read_bytes() == b"LIVE-GOOD"
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "feed.csv"]
    assert leftovers == []


async def test_refresh_http_failure_keeps_old_file(tmp_path: Path) -> None:
    """A feed 500ing leaves any existing live file intact (fail-open)."""
    live = tmp_path / "tor_exits.txt"
    live.write_text("# stale-but-valid\n198.51.100.1\n", encoding="utf-8")
    with respx.mock(assert_all_called=False) as mock:
        mock.get(BLOCKLIST_FEEDS["tor"].url).mock(return_value=httpx.Response(500))
        results = await refresh_blocklists(tmp_path, sources=["tor"], abuse_ch_auth_key=None)
    assert results[0].success is False
    assert results[0].skipped is False
    # Old file still there and unchanged.
    assert live.read_text(encoding="utf-8") == "# stale-but-valid\n198.51.100.1\n"


# ---------------------------------------------------------------------------
# 4. --source single-feed filtering.
# ---------------------------------------------------------------------------


async def test_single_source_only_fetches_that_feed(tmp_path: Path) -> None:
    with respx.mock(assert_all_called=False) as mock:
        tor_route = mock.get(BLOCKLIST_FEEDS["tor"].url).mock(
            return_value=httpx.Response(200, text=_TOR_BODY)
        )
        results = await refresh_blocklists(tmp_path, sources=["tor"], abuse_ch_auth_key=None)
    assert [r.source for r in results] == ["tor"]
    assert tor_route.called
    assert (tmp_path / "tor_exits.txt").exists()


async def test_non_refreshable_sources_ignored(tmp_path: Path) -> None:
    """internal_seed / spamhaus_drop are not network-fetched by this job."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(BLOCKLIST_FEEDS["tor"].url).mock(return_value=httpx.Response(200, text=_TOR_BODY))
        results = await refresh_blocklists(
            tmp_path,
            sources=["internal_seed", "spamhaus_drop", "tor"],
            abuse_ch_auth_key=None,
        )
    # Only tor was fetched; the curated/license sources are skipped entirely.
    assert [r.source for r in results] == ["tor"]


# ---------------------------------------------------------------------------
# 5. CLI subcommand dispatch.
# ---------------------------------------------------------------------------


def test_register_subparser_dispatches_to_refresh() -> None:
    """`blocklists refresh` parses and binds the refresh handler."""
    parser = argparse.ArgumentParser(prog="soc-ai")
    sub = parser.add_subparsers(dest="cmd")
    register_subparser(sub)

    args = parser.parse_args(["blocklists", "refresh"])
    assert args.func is _refresh_cli
    assert args.source is None

    args2 = parser.parse_args(["blocklists", "refresh", "--source", "tor"])
    assert args2.source == "tor"


def test_cli_refresh_single_source_invokes_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_refresh_cli wires Settings → refresh_blocklists for a single --source.

    Settings is patched so the test needs no .env and no real fields, and the
    cloud-prefix half is skipped (single --source). Network is mocked.
    """
    from pydantic import SecretStr

    class _FakeSettings:
        blocklist_data_dir = tmp_path
        blocklist_sources: ClassVar[list[str]] = ["urlhaus", "threatfox", "feodo", "tor"]
        abuse_ch_auth_key = SecretStr(_AUTH_KEY)

    monkeypatch.setattr("soc_ai.config.Settings", lambda *a, **k: _FakeSettings())

    args = argparse.Namespace(source="tor")
    with respx.mock(assert_all_called=True) as mock:
        mock.get(BLOCKLIST_FEEDS["tor"].url).mock(return_value=httpx.Response(200, text=_TOR_BODY))
        rc = _refresh_cli(args)

    assert rc == 0
    assert (tmp_path / "tor_exits.txt").exists()


def test_cli_refresh_unknown_single_source_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unknown --source returns exit code 2 without any network I/O."""
    from pydantic import SecretStr

    class _FakeSettings:
        blocklist_data_dir = tmp_path
        blocklist_sources: ClassVar[list[str]] = ["tor"]
        abuse_ch_auth_key = SecretStr(_AUTH_KEY)

    monkeypatch.setattr("soc_ai.config.Settings", lambda *a, **k: _FakeSettings())
    args = argparse.Namespace(source="not-a-feed")
    rc = _refresh_cli(args)
    assert rc == 2


def test_cli_refresh_missing_auth_key_still_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Skipped abuse.ch feeds (no key) don't flip the exit code to failure."""

    class _FakeSettings:
        blocklist_data_dir = tmp_path
        blocklist_sources: ClassVar[list[str]] = ["urlhaus", "tor"]
        abuse_ch_auth_key = None

    monkeypatch.setattr("soc_ai.config.Settings", lambda *a, **k: _FakeSettings())
    args = argparse.Namespace(source="urlhaus")  # single → skip cloud half
    rc = _refresh_cli(args)
    # urlhaus skipped (no key) is not a failure → exit 0.
    assert rc == 0
    assert not (tmp_path / "urlhaus.csv").exists()


@pytest.mark.asyncio
async def test_refresh_blocklists_blocked_in_demo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SOC_AI_DEMO refuses the feed refresh before any HTTP client exists."""
    monkeypatch.setenv("SOC_AI_DEMO", "true")
    with pytest.raises(DemoEgressBlocked):
        await refresh_blocklists(tmp_path, sources=["tor"], abuse_ch_auth_key=None)
