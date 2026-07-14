"""Cloud-prefix refresh + staleness helpers.

Owns fetching the cloud provider prefix lists (AWS/GCP/Azure/Cloudflare) and
the ``cloud_refresh_status.json`` staleness bookkeeping that ``enrich_ip``
reads. The `soc-ai blocklists refresh` CLI subcommand lives in
:mod:`soc_ai.enrichment.blocklist_refresh`, which delegates the cloud-prefix
half to :func:`refresh_cloud_prefixes` here.

Privacy posture: this module only talks to the public internet when the
operator-triggered refresh runs — never during triage.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import httpx

from soc_ai.demo.guard import assert_ambient_egress_allowed

_LOGGER = logging.getLogger(__name__)

# Name of the JSON file written alongside the cloud-prefix data files
# to record last-success / last-attempt timestamps for each provider.
_CLOUD_STATUS_FILE = "cloud_refresh_status.json"


REFRESH_URLS: dict[str, str] = {
    # Cloud prefixes (blocklist feed URLs live in blocklist_refresh.BLOCKLIST_FEEDS)
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
            ``"azure_prefixes"``) to a replacement URL.  Used by the
            ``blocklist_refresh`` CLI handler to honour
            ``Settings.azure_service_tags_url`` without hardcoding the
            setting here.

    Cloudflare publishes a plain-text list of prefixes; we wrap them in
    a JSON envelope ``{"prefixes": [...]}`` so the CloudPrefixDB loader
    can parse uniformly.

    After each source attempt (success or failure) the status is written
    to ``cloud_refresh_status.json`` in ``data_dir`` so that
    ``cloud_prefix_staleness_days`` can report how fresh the data is.
    """
    # No Settings parameter in this signature (the CLI handler owns that), so
    # the ambient guard resolves the demo flag itself.
    assert_ambient_egress_allowed("geo/cloud refresh")
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
            except (httpx.HTTPError, ValueError) as err:
                # Azure rotates its dated filename + GUID path weekly, so the
                # configured URL eventually 404s. On failure, resolve the current
                # URL from MS's download page and retry once (honors an explicit
                # operator override by trying it FIRST, above).
                fail_err: Exception = err
                if source == "azure":
                    resolved = await _resolve_azure_service_tags_url(client)
                    if resolved and resolved != url:
                        try:
                            content = await _fetch_validated(client, resolved, as_json=True)
                        except (httpx.HTTPError, ValueError) as err2:
                            fail_err = err2
                if content is None:
                    _LOGGER.warning("refresh cloud %s failed: %s", source, fail_err)
                    entry["last_error"] = str(fail_err)
                    status[source] = entry
                    _save_cloud_status(data_dir, status)
                    results.append(RefreshResult(source=source, success=False, error=str(fail_err)))
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


__all__ = [
    "REFRESH_URLS",
    "RefreshResult",
    "cloud_prefix_staleness_days",
    "refresh_cloud_prefixes",
]
