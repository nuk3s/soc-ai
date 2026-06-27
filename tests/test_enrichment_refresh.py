"""Tests for soc_ai.enrichment.refresh."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from soc_ai.enrichment.refresh import (
    REFRESH_URLS,
    cloud_prefix_staleness_days,
    refresh_blocklists,
    refresh_cloud_prefixes,
)


@pytest.mark.asyncio
async def test_refresh_blocklists_writes_files(tmp_path: Path) -> None:
    """refresh_blocklists fetches each source URL and writes the local file."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(REFRESH_URLS["urlhaus"]).mock(
            return_value=httpx.Response(200, text='"id","dateadded","url"\n"1","2026-04-01","x"\n')
        )
        mock.get(REFRESH_URLS["threatfox"]).mock(return_value=httpx.Response(200, text='{"1": []}'))
        mock.get(REFRESH_URLS["feodo"]).mock(return_value=httpx.Response(200, text="# header\n"))
        mock.get(REFRESH_URLS["tor"]).mock(return_value=httpx.Response(200, text="# header\n"))

        results = await refresh_blocklists(
            tmp_path,
            sources=["urlhaus", "threatfox", "feodo", "tor"],
        )

    assert (tmp_path / "urlhaus.csv").exists()
    assert (tmp_path / "threatfox.json").exists()
    assert (tmp_path / "feodo.csv").exists()
    assert (tmp_path / "tor_exits.txt").exists()
    assert all(r.success for r in results)


@pytest.mark.asyncio
async def test_refresh_blocklists_failure_logs_but_continues(tmp_path: Path) -> None:
    """One source 500ing doesn't kill the whole refresh; result.success=False for that one."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(REFRESH_URLS["urlhaus"]).mock(return_value=httpx.Response(500))
        mock.get(REFRESH_URLS["tor"]).mock(
            return_value=httpx.Response(200, text="# tor exits\n198.51.100.1\n")
        )
        results = await refresh_blocklists(tmp_path, sources=["urlhaus", "tor"])
    by_src = {r.source: r for r in results}
    assert by_src["urlhaus"].success is False
    assert by_src["tor"].success is True
    assert (tmp_path / "tor_exits.txt").exists()


@pytest.mark.asyncio
async def test_refresh_cloud_prefixes_writes_aws_json(tmp_path: Path) -> None:
    with respx.mock(assert_all_called=False) as mock:
        mock.get(REFRESH_URLS["aws_prefixes"]).mock(
            return_value=httpx.Response(200, text='{"prefixes":[]}')
        )
        results = await refresh_cloud_prefixes(tmp_path, sources=["aws"])
    assert (tmp_path / "aws.json").exists()
    assert all(r.success for r in results)


@pytest.mark.asyncio
async def test_refresh_cloud_azure_url_override_used(tmp_path: Path) -> None:
    """Azure URL can be overridden via url_overrides (Settings.azure_service_tags_url)."""
    custom_url = "https://custom.example.com/ServiceTags_Public_NEWER.json"
    with respx.mock(assert_all_called=True) as mock:
        mock.get(custom_url).mock(return_value=httpx.Response(200, text='{"values":[]}'))
        results = await refresh_cloud_prefixes(
            tmp_path,
            sources=["azure"],
            url_overrides={"azure_prefixes": custom_url},
        )
    assert all(r.success for r in results)
    assert (tmp_path / "azure.json").exists()


@pytest.mark.asyncio
async def test_refresh_cloud_failure_records_last_attempt(tmp_path: Path) -> None:
    """A failed cloud refresh records last_attempt in the status file."""
    import json as _json

    with respx.mock(assert_all_called=False) as mock:
        mock.get(REFRESH_URLS["aws_prefixes"]).mock(return_value=httpx.Response(500))
        results = await refresh_cloud_prefixes(tmp_path, sources=["aws"])
    by_src = {r.source: r for r in results}
    assert by_src["aws"].success is False
    status_path = tmp_path / "cloud_refresh_status.json"
    assert status_path.exists()
    status = _json.loads(status_path.read_text())
    assert "last_attempt" in status.get("aws", {})
    assert "last_success" not in status.get("aws", {})


@pytest.mark.asyncio
async def test_cloud_prefix_staleness_days_no_status(tmp_path: Path) -> None:
    """Returns None when no status file exists."""
    assert cloud_prefix_staleness_days(tmp_path) is None


@pytest.mark.asyncio
async def test_cloud_prefix_staleness_days_after_success(tmp_path: Path) -> None:
    """Returns ~0 days right after a successful refresh."""
    with respx.mock(assert_all_called=False) as mock:
        mock.get(REFRESH_URLS["aws_prefixes"]).mock(
            return_value=httpx.Response(200, text='{"prefixes":[]}')
        )
        await refresh_cloud_prefixes(tmp_path, sources=["aws"])
    age = cloud_prefix_staleness_days(tmp_path, source="aws")
    assert age is not None
    assert 0.0 <= age < 1.0  # just refreshed — well under 1 day


@pytest.mark.asyncio
async def test_enrich_ip_warns_when_cloud_data_stale(tmp_path: Path) -> None:
    """enrich_ip appends staleness warning when cloud data exceeds threshold."""
    import json as _json
    from datetime import UTC, datetime, timedelta

    from pydantic import SecretStr
    from soc_ai.config import Settings
    from soc_ai.enrichment.blocklists import BlocklistDB
    from soc_ai.enrichment.cloud_tags import CloudPrefixDB
    from soc_ai.enrichment.maxmind import MaxmindReader
    from soc_ai.tools.enrichment import enrich_ip

    # Write a status file recording a last_success 60 days ago (> 45-day default)
    sixty_days_ago = (datetime.now(UTC) - timedelta(days=60)).isoformat()
    status_data = {"azure": {"last_success": sixty_days_ago, "last_attempt": sixty_days_ago}}
    (tmp_path / "cloud_refresh_status.json").write_text(_json.dumps(status_data), encoding="utf-8")

    settings = Settings(
        so_host="https://so.test",
        so_username="x",
        so_password=SecretStr("x"),
        es_hosts=["https://es.test:9200"],
        litellm_base_url="http://localhost:4000",
        cloud_prefix_data_dir=tmp_path,
    )
    result = await enrich_ip(
        "203.0.113.1",
        settings=settings,
        misp=None,
        blocklist=BlocklistDB(),
        maxmind=MaxmindReader(),
        cloud=CloudPrefixDB(),
    )
    assert any("stale" in e for e in result.errors)


def test_cloud_prefix_staleness_days_naive_timestamp(tmp_path: Path) -> None:
    """cloud_prefix_staleness_days coerces a naive last_success timestamp to UTC.

    Status files written by an older version (or a third-party tool) may lack a
    timezone offset.  The function must still compute the staleness delta instead
    of raising a TypeError from datetime-aware minus datetime-naive subtraction.
    """
    import json as _json

    # Write a naive ISO timestamp (no +00:00 / Z suffix) that is ~2 days old.
    from datetime import UTC, datetime, timedelta

    two_days_ago_naive = (datetime.now(UTC) - timedelta(days=2)).replace(tzinfo=None).isoformat()
    assert "+" not in two_days_ago_naive
    assert two_days_ago_naive[-1] != "Z"

    status_data = {"azure": {"last_success": two_days_ago_naive}}
    (tmp_path / "cloud_refresh_status.json").write_text(_json.dumps(status_data), encoding="utf-8")

    age = cloud_prefix_staleness_days(tmp_path, source="azure")

    assert age is not None, "should return a day count, not None"
    assert 1.5 < age < 3.0, f"expected ~2 days old, got {age}"


@pytest.mark.asyncio
async def test_refresh_cloud_prefixes_cloudflare_wraps_txt_in_json_envelope(tmp_path: Path) -> None:
    """Cloudflare publishes plain TXT; the refresh job wraps it in JSON for CloudPrefixDB."""
    import json

    with respx.mock(assert_all_called=False) as mock:
        mock.get(REFRESH_URLS["cloudflare_v4"]).mock(
            return_value=httpx.Response(200, text="1.1.1.0/24\n104.16.0.0/13\n# comment\n")
        )
        results = await refresh_cloud_prefixes(tmp_path, sources=["cloudflare"])
    assert all(r.success for r in results)
    written = json.loads((tmp_path / "cloudflare.json").read_text())
    assert "prefixes" in written
    assert "1.1.1.0/24" in written["prefixes"]
    assert "104.16.0.0/13" in written["prefixes"]
    # Comment lines are stripped from the JSON envelope.
    assert "# comment" not in written["prefixes"]


@pytest.mark.asyncio
async def test_refresh_cloud_azure_resolves_rotated_url_on_404(tmp_path: Path) -> None:
    """A4: when the configured Azure URL 404s, the refresh scrapes MS's download
    page for the CURRENT ServiceTags URL and retries."""
    from soc_ai.enrichment.refresh import _AZURE_DOWNLOAD_PAGE

    current = "https://download.microsoft.com/download/a/b/c/ServiceTags_Public_20260601.json"
    page_html = f'<html><body><a href="{current}">download</a></body></html>'
    with respx.mock(assert_all_called=False) as mock:
        mock.get(REFRESH_URLS["azure_prefixes"]).mock(return_value=httpx.Response(404))
        mock.get(_AZURE_DOWNLOAD_PAGE).mock(return_value=httpx.Response(200, text=page_html))
        mock.get(current).mock(return_value=httpx.Response(200, text='{"values":[]}'))
        results = await refresh_cloud_prefixes(tmp_path, sources=["azure"])
    assert all(r.success for r in results)
    assert (tmp_path / "azure.json").exists()


@pytest.mark.asyncio
async def test_fetch_validated_rejects_truncated_body() -> None:
    """A5: a body shorter than Content-Length is a truncated transfer → reject."""
    from soc_ai.enrichment.refresh import _fetch_validated

    url = "https://example.com/big.json"
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url).mock(
            return_value=httpx.Response(
                200, content=b'{"x":1}', headers={"content-length": "99999"}
            )
        )
        async with httpx.AsyncClient() as client:
            with pytest.raises(ValueError, match="truncated"):
                await _fetch_validated(client, url, as_json=True, retries=1)


@pytest.mark.asyncio
async def test_fetch_validated_rejects_unparseable_json() -> None:
    """A5: a JSON feed whose body doesn't parse (truncated) → reject, not write."""
    from soc_ai.enrichment.refresh import _fetch_validated

    url = "https://example.com/x.json"
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url).mock(return_value=httpx.Response(200, content=b'{"truncated'))
        async with httpx.AsyncClient() as client:
            with pytest.raises(ValueError):
                await _fetch_validated(client, url, as_json=True, retries=1)


@pytest.mark.asyncio
async def test_fetch_validated_allows_compressed_body() -> None:
    """A5 regression: a gzip-encoded body is LARGER than Content-Length (which is
    the compressed wire size). Don't mis-flag it as truncated (the GCP feed)."""
    import gzip

    from soc_ai.enrichment.refresh import _fetch_validated

    raw = b'{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"}]}'
    body = gzip.compress(raw)
    url = "https://example.com/gcp.json"
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url).mock(
            return_value=httpx.Response(
                200, content=body,
                headers={"content-length": str(len(body)), "content-encoding": "gzip"},
            )
        )
        async with httpx.AsyncClient() as client:
            out = await _fetch_validated(client, url, as_json=True, retries=1)
    assert out == raw  # decompressed body returned, no false truncation error
