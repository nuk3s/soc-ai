"""Tests for the ECS-first Zeek/ECS field-resolution layer.

Covers:
- :func:`first_present` coalescing: ECS-present -> ECS; only ``zeek.*`` present
  -> ``zeek.*``; ``0`` is a value (not absent); ``""`` / ``[]`` / ``None`` are
  absent; nested *and* flat-dotted document layouts.
- :func:`resolve_agg_field` against a fake ES client returning canned counts:
  picks the first populated candidate, caches the result, and falls back to
  ``candidates[0]`` on all-zero counts or on a probe error.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.so_client.fields import (
    CONN_ORIG_BYTES,
    DNS_QUERY,
    SSL_JA3S,
    _clear_agg_field_cache,
    first_present,
    get_dotted,
    resolve_agg_field,
)

# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------


class FakeES:
    """Fake ElasticClient whose `exists` count per field comes from `counts`.

    A `raise_on` field name forces the probe for that field to raise, letting us
    exercise the error-path fallback to ``candidates[0]``.
    """

    def __init__(self, counts: dict[str, int], *, raise_on: str | None = None) -> None:
        self._counts = counts
        self._raise_on = raise_on
        self.probed: list[str] = []

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        sort: list[dict[str, Any]] | None = None,
        source: list[str] | bool | None = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
    ) -> EsSearchResult:
        # The resolver probes with {"exists": {"field": <name>}}, size=0.
        field = query["exists"]["field"]
        self.probed.append(field)
        if self._raise_on is not None and field == self._raise_on:
            raise RuntimeError(f"mapping missing for {field}")
        return EsSearchResult(total=self._counts.get(field, 0), took_ms=1, hits=[])


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    """Each test starts with an empty resolver cache."""
    _clear_agg_field_cache()


# ---------------------------------------------------------------------------
# first_present — coalescing
# ---------------------------------------------------------------------------


def test_first_present_prefers_ecs_when_present() -> None:
    # Both ECS and zeek.* present -> ECS (first candidate) wins.
    source = {"dns.query.name": "evil.example.com", "zeek.dns.query": "stale.zeek"}
    assert first_present(source, DNS_QUERY) == "evil.example.com"


def test_first_present_falls_through_to_zeek_when_only_zeek_present() -> None:
    # Only the legacy zeek.* field is populated (synth fixture shape).
    source = {"zeek.dns.query": "synth.lab.lan"}
    assert first_present(source, DNS_QUERY) == "synth.lab.lan"


def test_first_present_skips_empty_ecs_and_uses_next_candidate() -> None:
    # ECS present but empty-string -> treated as absent, fall through to zeek.*.
    source = {"dns.query.name": "", "zeek.dns.query": "fallback.lan"}
    assert first_present(source, DNS_QUERY) == "fallback.lan"


def test_first_present_zero_is_a_real_value() -> None:
    # A 0 byte-count is a REAL value: must be returned, not skipped.
    source = {"client.bytes": 0, "zeek.conn.orig_bytes": 999}
    assert first_present(source, CONN_ORIG_BYTES) == 0


def test_first_present_empty_list_is_absent() -> None:
    source = {"dns.query.name": [], "dns.question.name": "next.example.com"}
    assert first_present(source, DNS_QUERY) == "next.example.com"


def test_first_present_none_everywhere_returns_none() -> None:
    source: dict[str, Any] = {"unrelated.field": "x"}
    assert first_present(source, SSL_JA3S) is None


def test_first_present_explicit_none_value_is_absent() -> None:
    source = {"dns.query.name": None, "zeek.dns.query": "real.lan"}
    assert first_present(source, DNS_QUERY) == "real.lan"


def test_first_present_nested_dotted_path() -> None:
    # Nested document layout: dns -> query -> name.
    source = {"dns": {"query": {"name": "nested.example.com"}}}
    assert first_present(source, DNS_QUERY) == "nested.example.com"


def test_first_present_mixed_nested_and_flat() -> None:
    # ECS nested empty -> fall through to a flat-dotted zeek.* candidate.
    source = {"dns": {"query": {"name": ""}}, "zeek.dns.query": "flat.lan"}
    assert first_present(source, DNS_QUERY) == "flat.lan"


def test_get_dotted_flat_and_nested() -> None:
    assert get_dotted({"a.b": 1}, "a.b") == 1
    assert get_dotted({"a": {"b": 2}}, "a.b") == 2
    assert get_dotted({"a": {"b": 2}}, "a.c") is None
    assert get_dotted({"a": 5}, "a.b") is None  # non-dict mid-path


# ---------------------------------------------------------------------------
# resolve_agg_field — probe + cache + fallback
# ---------------------------------------------------------------------------


async def test_resolve_agg_field_picks_first_populated() -> None:
    # ECS candidate populated -> returned, and probing stops there.
    es = FakeES({"dns.query.name": 11_900_000, "zeek.dns.query": 9})
    field = await resolve_agg_field(es, "logs-*", DNS_QUERY)
    assert field == "dns.query.name"
    assert es.probed == ["dns.query.name"]  # stopped at first hit


async def test_resolve_agg_field_falls_through_to_populated_zeek() -> None:
    # ECS candidates empty on this deployment; only zeek.* has data.
    es = FakeES({"dns.query.name": 0, "dns.question.name": 0, "zeek.dns.query": 9})
    field = await resolve_agg_field(es, "logs-*", DNS_QUERY)
    assert field == "zeek.dns.query"
    assert es.probed == ["dns.query.name", "dns.question.name", "zeek.dns.query"]


async def test_resolve_agg_field_caches_result() -> None:
    es = FakeES({"client.bytes": 42})
    first = await resolve_agg_field(es, "logs-*", CONN_ORIG_BYTES)
    assert first == "client.bytes"
    assert es.probed == ["client.bytes"]
    # Second call: served from cache, no further probing.
    second = await resolve_agg_field(es, "logs-*", CONN_ORIG_BYTES)
    assert second == "client.bytes"
    assert es.probed == ["client.bytes"]  # unchanged


async def test_resolve_agg_field_cache_expires_after_ttl() -> None:
    """F71: an unbounded cache silently goes stale forever if the deployment's
    schema migrates mid-process (e.g. an Elastic-Agent upgrade moving data onto
    a different field). A TTL of 0 means "already expired" -> the second call
    must re-probe rather than serve the stale cached name."""
    es = FakeES({"client.bytes": 42})
    first = await resolve_agg_field(es, "logs-*", CONN_ORIG_BYTES, ttl_seconds=0)
    assert first == "client.bytes"
    assert es.probed == ["client.bytes"]
    second = await resolve_agg_field(es, "logs-*", CONN_ORIG_BYTES, ttl_seconds=0)
    assert second == "client.bytes"
    assert es.probed == ["client.bytes", "client.bytes"]  # re-probed, not cached


async def test_resolve_agg_field_cache_keyed_on_index() -> None:
    es = FakeES({"client.bytes": 7})
    await resolve_agg_field(es, "logs-a", CONN_ORIG_BYTES)
    await resolve_agg_field(es, "logs-b", CONN_ORIG_BYTES)
    # Different index pattern -> separate cache entry -> probed twice.
    assert es.probed == ["client.bytes", "client.bytes"]


async def test_resolve_agg_field_all_zero_falls_back_to_first_candidate() -> None:
    es = FakeES({})  # every candidate has 0 docs
    field = await resolve_agg_field(es, "logs-*", SSL_JA3S)
    assert field == SSL_JA3S[0] == "hash.ja3s"
    # All candidates were probed before giving up.
    assert es.probed == list(SSL_JA3S)


async def test_resolve_agg_field_error_falls_back_to_first_candidate() -> None:
    # First probe raises -> immediate ECS-first fallback, no crash.
    es = FakeES({"dns.query.name": 5}, raise_on="dns.query.name")
    field = await resolve_agg_field(es, "logs-*", DNS_QUERY)
    assert field == DNS_QUERY[0] == "dns.query.name"


async def test_resolve_agg_field_error_does_not_cache() -> None:
    # An error path returns the default WITHOUT caching, so a later healthy
    # call can still resolve correctly.
    es_err = FakeES({"dns.query.name": 5}, raise_on="dns.query.name")
    assert await resolve_agg_field(es_err, "logs-*", DNS_QUERY) == "dns.query.name"
    es_ok = FakeES({"dns.query.name": 0, "zeek.dns.query": 9})
    assert await resolve_agg_field(es_ok, "logs-*", DNS_QUERY) == "zeek.dns.query"


def test_resolve_agg_field_accepts_sequence_not_just_tuple() -> None:
    # Candidates may arrive as a list; cache key normalizes to a tuple.
    async def _run() -> str:
        es = FakeES({"client.bytes": 3})
        cands: Sequence[str] = list(CONN_ORIG_BYTES)
        return await resolve_agg_field(es, "logs-*", cands)

    import asyncio

    assert asyncio.run(_run()) == "client.bytes"
