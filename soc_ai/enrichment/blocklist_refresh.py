"""Blocklist feed refresh — fetch public IOC feeds into ``blocklist_data_dir``.

Run via ``soc-ai blocklists refresh``. Wired to a daily systemd timer
(see ``scripts/systemd/soc-ai-blocklists.{service,timer}`` and
``docs/BLOCKLISTS.md``).

Privacy posture: this is one of the only places soc-ai talks to the public
internet. It is triggered by the operator on a schedule, NEVER during triage.
Each feed is written into ``blocklist_data_dir`` under the EXACT filename the
matching :mod:`soc_ai.enrichment.blocklists` loader reads, in the format that
loader already parses.

abuse.ch Auth-Key (2024+ policy)
--------------------------------
abuse.ch (URLhaus, ThreatFox, Feodo Tracker) gates its CSV/JSON exports behind
a free ``Auth-Key`` HTTP header (register at https://auth.abuse.ch/). The key is
read from ``Settings.abuse_ch_auth_key`` and sent ONLY to abuse.ch feeds. If it
is unset, those feeds are SKIPPED with a clear message — the refresh does not
fail hard, and the Tor exit list (which needs no key) still refreshes. The key
is never logged.

Atomic writes
-------------
Each feed is downloaded to a temp file in the same directory and then
``os.replace``-d into place, so a partial or failed download can never corrupt
a live feed file that triage is reading.

Synth-eval reproducibility
---------------------------
The synth-eval catalogue was built against a PINNED feed snapshot. Refresh ONLY
ever writes to the configured live ``blocklist_data_dir``; the eval harness must
point ``blocklist_data_dir`` at its own frozen snapshot dir so a live refresh
cannot silently change synth results. See ``docs/BLOCKLISTS.md``.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from soc_ai.demo.guard import assert_ambient_egress_allowed

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class BlocklistFeed:
    """One refreshable blocklist feed.

    Attributes:
        name: The blocklist source key (matches ``Settings.blocklist_sources``
            and the ``_LOADERS`` registry in :mod:`soc_ai.enrichment.blocklists`).
        url: Upstream download URL.
        filename: Exact on-disk filename the matching loader reads from
            ``blocklist_data_dir``.
        requires_abuse_ch_auth: True for abuse.ch feeds that need the
            ``Auth-Key`` HTTP header (2024+ policy). The Tor exit list is False.
    """

    name: str
    url: str
    filename: str
    requires_abuse_ch_auth: bool


# Feed registry. The ``filename`` MUST match the path each loader in
# soc_ai/enrichment/blocklists.py reads:
#   _load_urlhaus   -> urlhaus.csv
#   _load_threatfox -> threatfox.json
#   _load_feodo     -> feodo.csv
#   _load_tor       -> tor_exits.txt
BLOCKLIST_FEEDS: dict[str, BlocklistFeed] = {
    "urlhaus": BlocklistFeed(
        name="urlhaus",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        filename="urlhaus.csv",
        requires_abuse_ch_auth=True,
    ),
    "threatfox": BlocklistFeed(
        name="threatfox",
        url="https://threatfox.abuse.ch/export/json/recent/",
        filename="threatfox.json",
        requires_abuse_ch_auth=True,
    ),
    "feodo": BlocklistFeed(
        name="feodo",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        filename="feodo.csv",
        requires_abuse_ch_auth=True,
    ),
    "tor": BlocklistFeed(
        name="tor",
        url="https://check.torproject.org/torbulkexitlist",
        filename="tor_exits.txt",
        requires_abuse_ch_auth=False,
    ),
}

# Sources that can be refreshed by this job. Other configured sources
# (internal_seed.yaml = operator-curated; spamhaus_drop = license-gated,
# handled out-of-band) are intentionally not auto-fetched here.
REFRESHABLE_SOURCES: tuple[str, ...] = tuple(BLOCKLIST_FEEDS)


@dataclass
class RefreshResult:
    """Outcome of one feed refresh attempt."""

    source: str
    success: bool
    bytes_written: int = 0
    skipped: bool = False
    error: str | None = None


def _atomic_write_bytes(dest: Path, content: bytes) -> None:
    """Write ``content`` to ``dest`` atomically (temp file in same dir + replace).

    A partial or interrupted download therefore never leaves a half-written or
    truncated live feed file: the live file flips from old to new in a single
    ``os.replace``, which is atomic on the same filesystem.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    # NamedTemporaryFile in the SAME directory so os.replace is a rename, not a
    # cross-device copy (which would not be atomic).
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, dest)
    except BaseException:
        # Clean up the temp file on any failure so we don't leave stray .tmp files behind.
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


async def refresh_blocklists(
    data_dir: Path,
    *,
    sources: list[str],
    abuse_ch_auth_key: str | None = None,
) -> list[RefreshResult]:
    """Fetch each enabled blocklist feed and write it atomically into ``data_dir``.

    Args:
        data_dir: The live ``blocklist_data_dir``. Refresh writes ONLY here.
        sources: Which feed keys to refresh. Non-refreshable sources (e.g.
            ``internal_seed``, ``spamhaus_drop``) are silently ignored — they
            are not network-fetched by this job.
        abuse_ch_auth_key: The abuse.ch Auth-Key. When ``None``/empty, abuse.ch
            feeds are SKIPPED (result.skipped=True) with a clear message; the
            Tor feed still refreshes. NEVER logged.

    Returns:
        One :class:`RefreshResult` per attempted feed. A single feed failing
        (HTTP error) does not abort the others (fail-open).
    """
    # No Settings parameter in this signature (the CLI handler owns that), so
    # the ambient guard resolves the demo flag itself.
    assert_ambient_egress_allowed("blocklist refresh")
    data_dir.mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240 — httpx uses asyncio
    results: list[RefreshResult] = []

    # Resolve the requested feeds, preserving config order, ignoring unknown /
    # non-refreshable source names.
    feeds = [BLOCKLIST_FEEDS[s] for s in sources if s in BLOCKLIST_FEEDS]
    if not feeds:
        return results

    has_auth = bool(abuse_ch_auth_key)
    if not has_auth and any(f.requires_abuse_ch_auth for f in feeds):
        _LOGGER.warning(
            "abuse.ch Auth-Key not configured (set ABUSE_CH_AUTH_KEY in .env; "
            "register free at https://auth.abuse.ch/) — skipping abuse.ch feeds "
            "(urlhaus/threatfox/feodo). The Tor exit list still refreshes."
        )

    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=15.0)) as client:
        for feed in feeds:
            if feed.requires_abuse_ch_auth and not has_auth:
                results.append(
                    RefreshResult(
                        source=feed.name,
                        success=False,
                        skipped=True,
                        error="abuse.ch Auth-Key not configured (set ABUSE_CH_AUTH_KEY)",
                    )
                )
                continue

            headers: dict[str, str] = {}
            if feed.requires_abuse_ch_auth:
                # Sent only to abuse.ch feeds; the value is never logged.
                headers["Auth-Key"] = abuse_ch_auth_key or ""

            try:
                resp = await client.get(feed.url, headers=headers, follow_redirects=True)
                resp.raise_for_status()
            except httpx.HTTPError as e:
                # str(e) is the httpx message (URL + status), never the auth key.
                _LOGGER.warning("blocklist refresh %s failed: %s", feed.name, e)
                results.append(RefreshResult(source=feed.name, success=False, error=str(e)))
                continue

            content = resp.content
            try:
                _atomic_write_bytes(data_dir / feed.filename, content)
            except OSError as e:
                _LOGGER.warning("blocklist refresh %s write failed: %s", feed.name, e)
                results.append(RefreshResult(source=feed.name, success=False, error=str(e)))
                continue

            results.append(
                RefreshResult(source=feed.name, success=True, bytes_written=len(content))
            )

    return results


def _refresh_cli(args: argparse.Namespace) -> int:
    """argparse handler for ``soc-ai blocklists refresh``.

    Refreshes the network-fetchable blocklist feeds (urlhaus/threatfox/feodo/tor)
    plus the cloud-prefix lists (delegated to
    :mod:`soc_ai.enrichment.refresh`, which owns that data dir + status file).

    ``--source <name>`` restricts to a single blocklist feed; the cloud-prefix
    refresh is then skipped (the operator asked for one feed).
    """
    from soc_ai.config import Settings  # noqa: PLC0415

    # pydantic-settings populates fields from .env/env at runtime, which mypy
    # can't see (same documented limitation as config.get_settings()).
    settings = Settings()  # type: ignore[call-arg]

    single = getattr(args, "source", None)
    if single:
        if single not in BLOCKLIST_FEEDS:
            known = ", ".join(sorted(BLOCKLIST_FEEDS))
            print(f"unknown --source {single!r}; known feeds: {known}")
            return 2
        requested = [single]
    else:
        # Only the network-fetchable feeds among the configured sources.
        requested = [s for s in settings.blocklist_sources if s in BLOCKLIST_FEEDS]

    auth_key = (
        settings.abuse_ch_auth_key.get_secret_value()
        if settings.abuse_ch_auth_key is not None
        else None
    )

    blocklist_results = asyncio.run(
        refresh_blocklists(
            settings.blocklist_data_dir,
            sources=requested,
            abuse_ch_auth_key=auth_key,
        )
    )

    print("Blocklist refresh:")
    for r in blocklist_results:
        if r.skipped:
            flag = "skip"
        elif r.success:
            flag = "ok"
        else:
            flag = "FAIL"
        suffix = f" — {r.error}" if r.error else ""
        print(f"  {flag} {r.source}: {r.bytes_written} bytes{suffix}")

    cloud_failed: list[object] = []
    if not single:
        # Delegate the cloud-prefix refresh to the existing module so its status
        # file + Azure URL override behaviour stay in one place.
        from soc_ai.enrichment.refresh import refresh_cloud_prefixes  # noqa: PLC0415

        cloud_results = asyncio.run(
            refresh_cloud_prefixes(
                settings.cloud_prefix_data_dir,
                sources=["aws", "gcp", "azure", "cloudflare"],
                url_overrides={"azure_prefixes": str(settings.azure_service_tags_url)},
            )
        )
        print("Cloud prefix refresh:")
        for cr in cloud_results:
            cflag = "ok" if cr.success else "FAIL"
            csuffix = f" — {cr.error}" if cr.error else ""
            print(f"  {cflag} {cr.source}: {cr.bytes_written} bytes{csuffix}")
        cloud_failed = [cr for cr in cloud_results if not cr.success]

    # MaxMind is downloaded separately (license key + ZIP — different shape),
    # covered in the deployment runbook, not in this CLI for v1.
    #
    # Exit non-zero if any feed genuinely FAILED. A SKIPPED abuse.ch feed
    # (no auth key) is an expected, operator-driven state, not a failure, so
    # it does not flip the exit code (the timer keeps the Tor feed fresh).
    blocklist_failed = [r for r in blocklist_results if not r.success and not r.skipped]
    return 0 if not (blocklist_failed or cloud_failed) else 1


def register_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``blocklists refresh`` (called from :func:`soc_ai.cli.main`)."""
    p_bl = sub.add_parser("blocklists", help="Refresh local IOC + cloud-prefix data files")
    bl_sub = p_bl.add_subparsers(dest="bl_cmd", required=True)
    p_refresh = bl_sub.add_parser(
        "refresh",
        help="Fetch configured blocklist feeds (+ cloud prefixes) into the data dir",
    )
    p_refresh.add_argument(
        "--source",
        default=None,
        choices=sorted(BLOCKLIST_FEEDS),
        help="Refresh only this single blocklist feed (default: all enabled "
        "feeds + cloud prefixes)",
    )
    p_refresh.set_defaults(func=_refresh_cli)


__all__ = [
    "BLOCKLIST_FEEDS",
    "REFRESHABLE_SOURCES",
    "BlocklistFeed",
    "RefreshResult",
    "refresh_blocklists",
    "register_subparser",
]
