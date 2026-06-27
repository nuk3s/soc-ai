"""Refresh CLI subcommand — fetches blocklist + cloud-prefix data files.

Run via `soc-ai blocklists refresh`. Wired to a systemd timer in the
deployment runbook (see docs/SAFETY_MODEL.md).

Privacy posture: this is the ONE place soc-ai talks to the public
internet. Triggered by the operator on a schedule, never during triage.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import httpx

_LOGGER = logging.getLogger(__name__)

# Name of the JSON file written alongside the cloud-prefix data files
# to record last-success / last-attempt timestamps for each provider.
_CLOUD_STATUS_FILE = "cloud_refresh_status.json"


REFRESH_URLS: dict[str, str] = {
    # Blocklists
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "tor": "https://check.torproject.org/torbulkexitlist",
    # Spamhaus is opt-in; URL still recorded so refresh can pick it up if enabled.
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    # Cloud prefixes
    "aws_prefixes": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp_prefixes": "https://www.gstatic.com/ipranges/cloud.json",
    # Azure URL encodes a publish date in the filename; override via
    # Settings.azure_service_tags_url to point at a newer snapshot.
    "azure_prefixes": (
        "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/"
        "ServiceTags_Public_20241125.json"
    ),
    "cloudflare_v4": "https://www.cloudflare.com/ips-v4",
}

_BLOCKLIST_FILENAMES = {
    "urlhaus": "urlhaus.csv",
    "threatfox": "threatfox.json",
    "feodo": "feodo.csv",
    "tor": "tor_exits.txt",
    "spamhaus_drop": "spamhaus_drop.txt",
}

_CLOUD_FILENAMES = {
    "aws": ("aws_prefixes", "aws.json"),
    "gcp": ("gcp_prefixes", "gcp.json"),
    "azure": ("azure_prefixes", "azure.json"),
    "cloudflare": ("cloudflare_v4", "cloudflare.json"),
}


@dataclass
class RefreshResult:
    source: str
    success: bool
    bytes_written: int = 0
    error: str | None = None


def _load_cloud_status(data_dir: Path) -> dict[str, dict[str, str]]:
    """Load the cloud refresh status file; return empty dict if absent/corrupt."""
    path = data_dir / _CLOUD_STATUS_FILE
    if not path.exists():
        return {}
    try:
        return cast("dict[str, dict[str, str]]", json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, OSError):
        return {}


def _save_cloud_status(data_dir: Path, status: dict[str, dict[str, str]]) -> None:
    """Write the cloud refresh status file (best-effort; errors are logged)."""
    path = data_dir / _CLOUD_STATUS_FILE
    try:
        path.write_text(json.dumps(status, indent=2), encoding="utf-8")
    except OSError as e:
        _LOGGER.warning("could not write cloud refresh status file: %s", e)


def cloud_prefix_staleness_days(data_dir: Path, source: str = "azure") -> float | None:
    """Return how many days since the last *successful* cloud-prefix refresh.

    Returns ``None`` when no status is recorded (never refreshed or status
    file absent). A successful refresh resets the counter to 0.

    Used by ``enrich_ip`` to append a staleness warning to
    ``IndicatorEnrichment.errors`` when the data is older than
    ``Settings.cloud_prefix_stale_threshold_days``.
    """
    status = _load_cloud_status(data_dir)
    entry = status.get(source, {})
    last_success_raw = entry.get("last_success")
    if not last_success_raw:
        return None
    try:
        last_success = datetime.fromisoformat(last_success_raw)
    except (ValueError, TypeError):
        return None
    if last_success.tzinfo is None:
        last_success = last_success.replace(tzinfo=UTC)
    delta = datetime.now(UTC) - last_success
    return delta.total_seconds() / 86400.0


async def _fetch_validated(
    client: httpx.AsyncClient, url: str, *, as_json: bool = False, retries: int = 3
) -> bytes:
    """GET ``url`` with retries + integrity checks; return the body bytes.

    Guards against the silent truncation that left a partial AWS
    ``ip-ranges.json`` on disk (received 720283, expected 2517145): a short
    read versus ``Content-Length`` and — for JSON feeds — a body that doesn't
    parse both fail the attempt and retry. A 4xx is permanent (no retry);
    transient transport/5xx/truncation errors back off and retry.
    """
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = await client.get(url, follow_redirects=True)
            resp.raise_for_status()
            content = resp.content
            clen = resp.headers.get("content-length")
            # Content-Length is the WIRE size; when the body was transfer-compressed
            # (gzip/br) httpx returns the larger decompressed bytes, so the header
            # only matches len(content) for an un-encoded response. Skip the check
            # when encoded — the JSON-parse guard below still catches truncation.
            encoded = bool(resp.headers.get("content-encoding"))
            if clen is not None and clen.isdigit() and not encoded and len(content) != int(clen):
                raise ValueError(f"truncated download: got {len(content)} bytes, expected {clen}")
            if as_json:
                json.loads(content)  # raises on a truncated/garbage body
            return content
        except httpx.HTTPStatusError as e:
            if 400 <= e.response.status_code < 500:
                raise  # permanent (e.g. 404) — don't burn retries
            last_err = e
        except (httpx.HTTPError, ValueError) as e:
            last_err = e
        if attempt < retries:
            await asyncio.sleep(min(2**attempt, 8))  # 2s, 4s, 8s backoff
    assert last_err is not None
    raise last_err


_AZURE_DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
_AZURE_FILE_RE = re.compile(
    r"https://download\.microsoft\.com/download/[^\"'\s]+?/ServiceTags_Public_\d{8}\.json"
)


async def _resolve_azure_service_tags_url(client: httpx.AsyncClient) -> str | None:
    """Resolve the CURRENT Azure Service Tags JSON URL from Microsoft's download
    page. MS rotates both the dated filename AND the GUID path ~weekly, so a
    hardcoded URL eventually 404s. Returns ``None`` if the page can't be scraped
    (the caller then falls back to the configured/override URL).
    """
    try:
        resp = await client.get(_AZURE_DOWNLOAD_PAGE, follow_redirects=True)
        resp.raise_for_status()
    except Exception as e:  # best-effort: resolution must never break the refresh
        _LOGGER.warning("azure service-tags URL resolution failed: %s", e)
        return None
    m = _AZURE_FILE_RE.search(resp.text)
    if m:
        _LOGGER.info("resolved current azure service-tags URL: %s", m.group(0))
        return m.group(0)
    return None


async def refresh_blocklists(data_dir: Path, *, sources: list[str]) -> list[RefreshResult]:
    """Fetch each blocklist source and write to ``data_dir``."""
    data_dir.mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240 — httpx uses asyncio, not trio/anyio
    results: list[RefreshResult] = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=15.0)) as client:
        for source in sources:
            url = REFRESH_URLS.get(source)
            fname = _BLOCKLIST_FILENAMES.get(source)
            if url is None or fname is None:
                results.append(RefreshResult(source=source, success=False, error="unknown source"))
                continue
            try:
                content = await _fetch_validated(client, url)
            except (httpx.HTTPError, ValueError) as e:
                _LOGGER.warning("refresh %s failed: %s", source, e)
                results.append(RefreshResult(source=source, success=False, error=str(e)))
                continue
            (data_dir / fname).write_bytes(content)
            results.append(RefreshResult(source=source, success=True, bytes_written=len(content)))
    return results


async def refresh_cloud_prefixes(
    data_dir: Path,
    *,
    sources: list[str],
    url_overrides: dict[str, str] | None = None,
) -> list[RefreshResult]:
    """Fetch cloud prefix lists and write to ``data_dir``.

    Args:
        data_dir: Directory to write prefix JSON files and the status file.
        sources: Which providers to fetch (``"aws"``, ``"gcp"``, ``"azure"``,
            ``"cloudflare"``).
        url_overrides: Optional mapping from the ``REFRESH_URLS`` key (e.g.
            ``"azure_prefixes"``) to a replacement URL.  Used by
            ``_refresh_cli`` to honour ``Settings.azure_service_tags_url``
            without hardcoding the setting here.

    Cloudflare publishes a plain-text list of prefixes; we wrap them in
    a JSON envelope ``{"prefixes": [...]}`` so the CloudPrefixDB loader
    can parse uniformly.

    After each source attempt (success or failure) the status is written
    to ``cloud_refresh_status.json`` in ``data_dir`` so that
    ``cloud_prefix_staleness_days`` can report how fresh the data is.
    """
    data_dir.mkdir(parents=True, exist_ok=True)  # noqa: ASYNC240 — httpx uses asyncio, not trio/anyio
    effective_urls = dict(REFRESH_URLS)
    if url_overrides:
        effective_urls.update(url_overrides)

    status = _load_cloud_status(data_dir)
    results: list[RefreshResult] = []
    now_iso = datetime.now(UTC).isoformat()

    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=15.0)) as client:
        for source in sources:
            spec = _CLOUD_FILENAMES.get(source)
            if spec is None:
                results.append(RefreshResult(source=source, success=False, error="unknown source"))
                continue
            url_key, fname = spec
            url = effective_urls.get(url_key)
            if url is None:
                results.append(RefreshResult(source=source, success=False, error="no URL"))
                continue

            entry: dict[str, str] = status.get(source, {})
            entry["last_attempt"] = now_iso

            content: bytes | None = None
            try:
                content = await _fetch_validated(client, url, as_json=(source != "cloudflare"))
            except (httpx.HTTPError, ValueError) as e:
                # Azure rotates its dated filename + GUID path weekly, so the
                # configured URL eventually 404s. On failure, resolve the current
                # URL from MS's download page and retry once (honors an explicit
                # operator override by trying it FIRST, above).
                if source == "azure":
                    resolved = await _resolve_azure_service_tags_url(client)
                    if resolved and resolved != url:
                        try:
                            content = await _fetch_validated(client, resolved, as_json=True)
                        except (httpx.HTTPError, ValueError) as e2:
                            e = e2
                if content is None:
                    _LOGGER.warning("refresh cloud %s failed: %s", source, e)
                    entry["last_error"] = str(e)
                    status[source] = entry
                    _save_cloud_status(data_dir, status)
                    results.append(RefreshResult(source=source, success=False, error=str(e)))
                    continue

            if source == "cloudflare":
                # Convert TXT prefix list → JSON envelope.
                lines = [
                    line.strip()
                    for line in content.decode("utf-8", "replace").splitlines()
                    if line.strip() and not line.startswith("#")
                ]
                content = json.dumps({"prefixes": lines}).encode("utf-8")
            (data_dir / fname).write_bytes(content)
            entry["last_success"] = now_iso
            entry.pop("last_error", None)
            status[source] = entry
            _save_cloud_status(data_dir, status)
            results.append(RefreshResult(source=source, success=True, bytes_written=len(content)))

    return results


def _refresh_cli(args: argparse.Namespace) -> int:
    """argparse handler for `soc-ai blocklists refresh`."""
    from soc_ai.config import Settings  # noqa: PLC0415

    # reads from .env; pydantic-settings populates fields from env, which mypy
    # can't see (same documented limitation as config.get_settings()).
    settings = Settings()  # type: ignore[call-arg]
    blocklist_results = asyncio.run(
        refresh_blocklists(settings.blocklist_data_dir, sources=settings.blocklist_sources)
    )
    cloud_results = asyncio.run(
        refresh_cloud_prefixes(
            settings.cloud_prefix_data_dir,
            sources=["aws", "gcp", "azure", "cloudflare"],
            # Honour the operator-configured Azure URL (e.g. a newer snapshot).
            url_overrides={"azure_prefixes": str(settings.azure_service_tags_url)},
        )
    )
    print("Blocklist refresh:")
    for r in blocklist_results:
        flag = "ok" if r.success else "FAIL"
        suffix = f" — {r.error}" if r.error else ""
        print(f"  {flag} {r.source}: {r.bytes_written} bytes{suffix}")
    print("Cloud prefix refresh:")
    for r in cloud_results:
        flag = "ok" if r.success else "FAIL"
        suffix = f" — {r.error}" if r.error else ""
        print(f"  {flag} {r.source}: {r.bytes_written} bytes{suffix}")
    # MaxMind is downloaded separately (license key + ZIP — different shape)
    # — covered in deployment runbook, not in this CLI for v1.
    failed = [r for r in (blocklist_results + cloud_results) if not r.success]
    return 0 if not failed else 1


def register_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Called from soc_ai/cli.py main() to register `blocklists refresh`."""
    p_bl = sub.add_parser("blocklists", help="Refresh local IOC + cloud-prefix data files")
    bl_sub = p_bl.add_subparsers(dest="bl_cmd", required=True)
    p_refresh = bl_sub.add_parser(
        "refresh", help="Fetch all configured blocklist + cloud-prefix sources"
    )
    p_refresh.set_defaults(func=_refresh_cli)


__all__ = [
    "REFRESH_URLS",
    "RefreshResult",
    "cloud_prefix_staleness_days",
    "refresh_blocklists",
    "refresh_cloud_prefixes",
    "register_subparser",
]
