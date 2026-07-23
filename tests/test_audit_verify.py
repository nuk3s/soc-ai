"""Tests for the operator-facing audit-chain verification surface.

Two layers, both hermetic (no live ES):

- :func:`soc_ai.audit.verify.verify_audit_chain` — the shared fetch-and-verify
  helper. A fake ElasticClient (mocking at the ``_client.search`` boundary the
  helper actually calls) serves an intact chain / a tampered record / an empty
  index, and we assert the :class:`ChainVerifyResult`.
- ``GET /api/v1/config/audit/verify-chain`` — the admin endpoint. We assert it
  requires admin (401/403 with API auth on) and returns the JSON shape on an
  intact chain (helper mocked, ES untouched).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.audit.chain import GENESIS_PREV_HASH, GENESIS_SEQ, compute_hash
from soc_ai.audit.verify import ChainVerifyResult, verify_audit_chain
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient

# ── chain builder (mirrors AuditLogger.log's hash stamping) ────────────────────


def _build_chain(n: int, *, start_seq: int = GENESIS_SEQ) -> list[dict[str, Any]]:
    """Build ``n`` valid, correctly-linked audit records (as ES ``_source`` bodies).

    Mirrors :meth:`soc_ai.audit.logger.AuditLogger.log`: the hash is computed over
    the content (every field but ``hash``) plus the previous record's hash.
    """
    records: list[dict[str, Any]] = []
    prev_hash = GENESIS_PREV_HASH
    for i in range(n):
        seq = start_seq + i
        content: dict[str, Any] = {
            "session_id": f"s{seq}",
            "kind": "tool_call",
            "payload": {"i": seq},
            "seq": seq,
            "prev_hash": prev_hash,
            "timestamp": f"2026-07-11T00:00:{seq:02d}+00:00",
        }
        digest = compute_hash(content, prev_hash)
        record = {**content, "hash": digest}
        records.append(record)
        prev_hash = digest
    return records


# ── fake ES that serves records with search_after paging + sort cursors ────────


class _FakeES:
    """Minimal ES double honoring the helper's ``search_after`` seq paging.

    Serves a fixed list of records (in seq order) as ``hits`` with a per-hit
    ``sort`` cursor of ``[seq, _id]`` — exactly what ``_search_page`` reads to
    advance. Empty index → no hits.
    """

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = sorted(records, key=lambda r: r["seq"])

    async def search(self, *, index: str, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        size = int(body.get("size", 1000))
        after = body.get("search_after")
        start = 0
        if after is not None:
            after_seq = after[0]
            # First record whose seq is strictly greater than the cursor seq.
            start = next(
                (i for i, r in enumerate(self._records) if r["seq"] > after_seq),
                len(self._records),
            )
        page = self._records[start : start + size]
        hits = [
            {"_source": r, "_id": f"id-{r['seq']}", "sort": [r["seq"], f"id-{r['seq']}"]}
            for r in page
        ]
        return {"hits": {"hits": hits}}


def _elastic_with(records: list[dict[str, Any]]) -> ElasticClient:
    """An ElasticClient whose ``_client`` is a :class:`_FakeES` (no real transport)."""
    settings = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
    )
    fake = _FakeES(records)
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake):
        return ElasticClient(settings)


# ── helper: intact / tampered / empty ──────────────────────────────────────────


async def test_verify_intact_chain() -> None:
    records = _build_chain(5)
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert isinstance(result, ChainVerifyResult)
    assert result.ok is True
    assert result.first_broken_seq is None
    assert result.records_verified == 5
    assert result.first_seq == 0
    assert result.last_seq == 4
    assert result.capped is False


async def test_verify_tampered_record() -> None:
    records = _build_chain(5)
    # Edit a stored record's payload WITHOUT re-stamping its hash → recompute fails
    # at that seq (an edit is exactly what verify_chain must catch).
    records[2]["payload"] = {"i": 999}
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is False
    assert result.first_broken_seq == 2


async def test_verify_deleted_record_breaks_chain() -> None:
    """Deleting a middle record leaves a seq gap → tamper detected at the gap."""
    records = _build_chain(5)
    del records[2]  # seq 2 removed; 3 no longer follows 1 contiguously
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is False
    assert result.first_broken_seq == 3


async def test_verify_windowed_slice_is_not_tamper() -> None:
    """A ``days=`` window that legitimately starts mid-stream (the record before the
    window was rotated out / filtered) must NOT be reported as tampered. Regression
    for the windowed false-positive: verify_chain forced the genesis prev_hash onto
    the first in-window record regardless of its real seq."""
    full = _build_chain(10)
    window = full[6:]  # seqs 6..9 — exactly what a days= filter hands back on an old deploy
    elastic = _elastic_with(window)
    result = await verify_audit_chain(elastic, "soc-ai-audit", days=7)
    assert result.ok is True
    assert result.first_broken_seq is None
    assert result.records_verified == 4
    assert result.first_seq == 6
    assert result.last_seq == 9


async def test_verify_full_scan_still_flags_missing_head() -> None:
    """No-regression guard: a full (non-windowed) scan whose oldest records are gone
    is still a tamper. With no ``days`` window to excuse it, expect_genesis stays on,
    so a first record with seq>0 and a non-genesis prev_hash is caught, not accepted."""
    full = _build_chain(10)
    missing_head = full[3:]  # head deleted, no days= window
    elastic = _elastic_with(missing_head)
    result = await verify_audit_chain(elastic, "soc-ai-audit")  # days=None
    assert result.ok is False
    assert result.first_broken_seq == 3


async def test_verify_empty_index_is_intact() -> None:
    elastic = _elastic_with([])
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is True
    assert result.first_broken_seq is None
    assert result.records_verified == 0
    assert result.first_seq is None
    assert result.last_seq is None
    assert result.capped is False


async def test_verify_pages_past_page_size() -> None:
    """A chain larger than one page is fully fetched via search_after (no truncation)."""
    records = _build_chain(2500)  # > _PAGE_SIZE (1000)
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is True
    assert result.records_verified == 2500
    assert result.last_seq == 2499
    assert result.capped is False


async def test_verify_respects_max_records_cap() -> None:
    """Hitting the record cap sets capped=True (never a silent truncation)."""
    records = _build_chain(50)
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit", max_records=10)
    assert result.capped is True
    assert result.records_verified == 10


async def test_verify_es_error_propagates() -> None:
    """A transport/ES error is raised, NOT swallowed as an intact chain — the
    caller (CLI exit-2 / endpoint 5xx) must be able to tell 'could not run' apart
    from 'intact'."""
    elastic = _elastic_with([])
    with (
        patch.object(elastic._client, "search", AsyncMock(side_effect=RuntimeError("ES down"))),
        pytest.raises(RuntimeError, match="ES down"),
    ):
        await verify_audit_chain(elastic, "soc-ai-audit")


# ── endpoint: GET /config/audit/verify-chain ───────────────────────────────────


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "api_auth_required": False,
    }
    base.update(overrides)
    return Settings(**base)


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client() -> Iterator[TestClient]:
    yield from _client(_settings())


def test_endpoint_returns_shape_on_intact_chain(client: TestClient) -> None:
    """The endpoint returns the documented JSON on an intact chain (helper mocked)."""
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=True,
            records_verified=7,
            first_broken_seq=None,
            first_seq=0,
            last_seq=6,
            capped=False,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["records_verified"] == 7
    assert body["first_broken_seq"] is None
    assert body["first_seq"] == 0
    assert body["last_seq"] == 6
    assert body["capped"] is False
    assert isinstance(body["checked_at"], str) and body["checked_at"]


def test_endpoint_reports_tamper(client: TestClient) -> None:
    """A broken chain surfaces ok=false + first_broken_seq (still HTTP 200 — the
    verification RAN and its answer is 'tampered')."""
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=False,
            records_verified=3,
            first_broken_seq=3,
            first_seq=0,
            last_seq=4,
            capped=False,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is False
    assert body["first_broken_seq"] == 3


def test_endpoint_passes_days_param(client: TestClient) -> None:
    """``?days=N`` is threaded into the helper."""
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=True,
            records_verified=1,
            first_broken_seq=None,
            first_seq=0,
            last_seq=0,
            capped=False,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain?days=7")
    assert resp.status_code == 200, resp.text
    _args, kwargs = fake.call_args
    assert kwargs["days"] == 7


def test_endpoint_es_error_is_not_reported_as_intact(client: TestClient) -> None:
    """An ES/transport error must surface as 'could not run' (5xx), never ok=true."""
    fake = AsyncMock(side_effect=RuntimeError("ES down"))
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code >= 500
    # The body must not read as an intact chain.
    assert '"ok":true' not in resp.text.replace(" ", "")


def test_endpoint_admin_gated() -> None:
    """With API auth ON, an unauthenticated request is refused; an admin gets through."""
    settings = _settings(
        api_auth_required=True,
        bootstrap_admin_password=SecretStr("admin-pw"),
    )
    for c in _client(settings):
        resp = c.get("/api/v1/config/audit/verify-chain")
        assert resp.status_code in (401, 403)

        login = c.post("/api/v1/login", json={"username": "admin", "password": "admin-pw"})
        assert login.status_code == 200, login.text
        fake = AsyncMock(
            return_value=ChainVerifyResult(
                ok=True,
                records_verified=0,
                first_broken_seq=None,
                first_seq=None,
                last_seq=None,
                capped=False,
            )
        )
        with patch("soc_ai.audit.verify.verify_audit_chain", fake):
            ok = c.get("/api/v1/config/audit/verify-chain")
        assert ok.status_code == 200
        assert ok.json()["ok"] is True
