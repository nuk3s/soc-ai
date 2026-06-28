"""Tests for internal-identifier discovery (Increment 2b).

The ES layer is MOCKED throughout — a fake ``ElasticClient`` whose ``search``
returns canned terms+cardinality aggregation buckets. No real ES is touched.

Coverage:
* registrable-suffix derivation + public/internal classification (pure helpers).
* THE safety test: a public registrable domain is NEVER auto-activated, even
  with a huge distinct-host count; a reserved/internal suffix at/above threshold
  IS active; below threshold → muted.
* bare-hostname active/muted; already-reserved suffix dropped.
* distinct-internal-host counting from the cardinality sub-agg.
* graceful degradation: one sub-query raising still returns a summary with the
  error recorded and the other signal processed.
* upsert wiring: rows land via upsert_detected with correct kind/state/evidence;
  a re-run preserves an operator-muted row (not flipped back to active).
* endpoint: POST starts a scan, GET returns status, single-flight rejects a
  concurrent start, admin gate enforced.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.enrichment import discovery as disc
from soc_ai.enrichment.discovery import (
    _PUBLIC_TLDS_FALLBACK,
    DiscoverySummary,
    _Candidate,
    _CidrCandidate,
    _ingest_ip_buckets,
    _is_rfc1918,
    _load_public_tlds,
    _slash24,
    classify_host,
    classify_suffix,
    derive_suffix,
    is_clearly_internal_suffix,
    is_public_registrable,
    registrable_form,
    run_discovery,
)
from soc_ai.main import create_app
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import internal_identifiers as ids
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_agg_cache() -> Iterator[None]:
    """Reset the per-deployment field-resolution cache between tests.

    ``resolve_agg_field`` caches on (index, candidates); tests reuse the same
    index pattern with different grid flavours, so the cache must be cleared.
    """
    from soc_ai.so_client.fields import _clear_agg_field_cache

    _clear_agg_field_cache()
    yield
    _clear_agg_field_cache()


def _settings() -> Settings:
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        internal_cidrs=["10.0.0.0/8", "192.168.0.0/16"],
        discovery_min_hosts=3,
        discovery_lookback_days=7,
        api_auth_required=False,  # dev-open; secure default is True
    )


async def _sessionmaker(settings: Settings) -> async_sessionmaker[AsyncSession]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return make_sessionmaker(engine)


def _bucket(key: str, doc_count: int, distinct: int) -> dict[str, Any]:
    return {"key": key, "doc_count": doc_count, "distinct_hosts": {"value": distinct}}


def _ip_bucket(ip: str, doc_count: int = 1) -> dict[str, Any]:
    """A plain terms bucket (no cardinality sub-agg) for an IP-field aggregation."""
    return {"key": ip, "doc_count": doc_count}


def _agg_result(buckets: list[dict[str, Any]], total: int = 100) -> EsSearchResult:
    return EsSearchResult(
        total=total,
        took_ms=1,
        hits=[],
        aggregations={"candidates": {"buckets": buckets}},
    )


def _exists_probe_field(query: dict[str, Any]) -> str | None:
    """Return the field of an ``{"exists": {"field": ...}}`` probe, or None.

    ``resolve_agg_field`` probes each candidate with a ``size=0`` search whose
    query is ``{"exists": {"field": <name>}}`` and ``aggs=None``. We detect that
    shape so the fake can answer "does this field carry data?" per candidate.
    """
    exists = query.get("exists") if isinstance(query, dict) else None
    if isinstance(exists, dict):
        field = exists.get("field")
        return field if isinstance(field, str) else None
    return None


class FakeES:
    """Fake ElasticClient routing host.name vs the DNS agg field.

    Defaults to a LEGACY/synth grid: the ECS exists-probes report no data, so
    ``resolve_agg_field`` resolves the DNS query/answer fields to their
    ``zeek.*`` forms (matching the existing buckets). Set ``ecs=True`` to model a
    modern grid where the ECS names carry the data instead. ``resolved_buckets``
    feeds the new resolved-internal (forward-record) aggregation;
    ``local_orig_ip_buckets`` / ``local_resp_ip_buckets`` feed the
    connection.local.* CIDR corroboration.
    """

    def __init__(
        self,
        host_buckets: list[dict[str, Any]] | None = None,
        dns_buckets: list[dict[str, Any]] | None = None,
        ptr_buckets: list[dict[str, Any]] | None = None,
        src_ip_buckets: list[dict[str, Any]] | None = None,
        dst_ip_buckets: list[dict[str, Any]] | None = None,
        resolved_buckets: list[dict[str, Any]] | None = None,
        local_orig_ip_buckets: list[dict[str, Any]] | None = None,
        local_resp_ip_buckets: list[dict[str, Any]] | None = None,
        raise_on: str | None = None,
        ecs: bool = False,
    ) -> None:
        self._host = host_buckets or []
        self._dns = dns_buckets or []
        self._ptr = ptr_buckets or []
        self._src_ip = src_ip_buckets or []
        self._dst_ip = dst_ip_buckets or []
        self._resolved = resolved_buckets or []
        self._local_orig_ip = local_orig_ip_buckets or []
        self._local_resp_ip = local_resp_ip_buckets or []
        self._raise_on = raise_on
        self._ecs = ecs
        self.calls: list[str] = []
        # The fields that "have data" for exists-probes. Legacy grid → zeek.*;
        # ECS grid → the ECS-first candidate name.
        self._dns_query_field = "dns.query.name" if ecs else "zeek.dns.query"
        self._dns_resolved_field = "dns.resolved_ip" if ecs else "zeek.dns.answers"

    def _has_data(self, field: str) -> bool:
        # Stable identity fields always have data; otherwise only the resolved
        # DNS/answer/local fields for this grid flavour report data.
        if field in ("host.name", "source.ip", "destination.ip"):
            return True
        return field in (
            self._dns_query_field,
            self._dns_resolved_field,
            "connection.local.originator" if self._ecs else "zeek.conn.local_orig",
            "connection.local.responder" if self._ecs else "zeek.conn.local_resp",
        )

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
        **_: Any,
    ) -> EsSearchResult:
        # 1. resolve_agg_field exists-probe (aggs is None, query is an exists).
        probe_field = _exists_probe_field(query)
        if aggs is None and probe_field is not None:
            return EsSearchResult(
                total=1 if self._has_data(probe_field) else 0,
                took_ms=1,
                hits=[],
                aggregations=None,
            )

        field_name = ""
        if aggs:
            field_name = aggs["candidates"]["terms"]["field"]
        self.calls.append(field_name)
        if self._raise_on is not None and field_name == self._raise_on:
            raise RuntimeError(f"mapping missing for {field_name}")
        # The resolved-internal (forward-record) aggregation carries a
        # resolved_ips sub-agg — route it by that shape.
        sub = aggs["candidates"].get("aggs", {}) if aggs else {}
        if "resolved_ips" in sub:
            return _agg_result(self._resolved)
        if field_name == "host.name":
            return _agg_result(self._host)
        if field_name == self._dns_query_field:
            return _agg_result(self._dns)
        if field_name == self._dns_resolved_field:
            return _agg_result(self._ptr)
        if field_name == "source.ip":
            # connection.local.originator-scoped agg vs the window-wide agg.
            local_flag = self._local_flag_in(query, "originator")
            return _agg_result(self._local_orig_ip if local_flag else self._src_ip)
        if field_name == "destination.ip":
            local_flag = self._local_flag_in(query, "responder")
            return _agg_result(self._local_resp_ip if local_flag else self._dst_ip)
        return _agg_result([])

    @staticmethod
    def _local_flag_in(query: dict[str, Any], side: str) -> bool:
        """True iff this query filters on connection.local.<side>/local_<side>."""
        filters = query.get("bool", {}).get("filter", [])
        for clause in filters:
            term = clause.get("term", {}) if isinstance(clause, dict) else {}
            for key in term:
                if side[:4] in key and ("local" in key or "local_" in key):
                    return True
        return False

    async def aclose(self) -> None:  # pragma: no cover - cleanup no-op
        return None


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_derive_suffix_parent_domain() -> None:
    assert derive_suffix("dc01.corp.acme.com") == "corp.acme.com"
    assert derive_suffix("host.lan") == "lan"
    assert derive_suffix("a.b.c.d") == "b.c.d"


def test_derive_suffix_single_label_is_none() -> None:
    assert derive_suffix("WIN11-01") is None
    assert derive_suffix("") is None


def test_derive_suffix_strips_trailing_dot_and_lowercases() -> None:
    assert derive_suffix("WEB.Corp.Acme.Com.") == "corp.acme.com"


def test_registrable_form_two_label() -> None:
    assert registrable_form("corp.acme.com") == "acme.com"
    assert registrable_form("acme.com") == "acme.com"
    assert registrable_form("lan") == "lan"


def test_is_public_registrable() -> None:
    assert is_public_registrable("acme.com") is True
    assert is_public_registrable("corp.acme.com") is True  # via 2-label form
    assert is_public_registrable("evil.io") is True
    # reserved / internal
    assert is_public_registrable("corp.acme.local") is False
    assert is_public_registrable("lan") is False
    assert is_public_registrable("home.arpa") is False


def test_is_clearly_internal_suffix() -> None:
    assert is_clearly_internal_suffix("corp.acme.local") is True
    assert is_clearly_internal_suffix("lan") is True  # single-label
    assert is_clearly_internal_suffix("ad.contoso.internal") is True
    assert is_clearly_internal_suffix("home.arpa") is True
    assert is_clearly_internal_suffix("acme.com") is False


# ---------------------------------------------------------------------------
# Vendored IANA TLD list — the public-domain gate (the regression)
# ---------------------------------------------------------------------------


def test_update_cdn_click_is_public_via_iana_list() -> None:
    # .click is a real gTLD absent from the old hardcoded set — now caught.
    assert is_public_registrable("update-cdn.click") is True
    assert is_clearly_internal_suffix("update-cdn.click") is False


def test_iana_list_covers_new_gtlds() -> None:
    for d in ("foo.xyz", "foo.top", "foo.online", "foo.app", "foo.shop", "foo.live"):
        assert is_public_registrable(d) is True


def test_iana_loader_strips_comments_and_lowercases() -> None:
    tlds = _load_public_tlds()
    assert "click" in tlds and "com" in tlds
    assert not any(t.startswith("#") for t in tlds)
    assert all(t == t.lower() for t in tlds)


def test_iana_loader_falls_back_when_file_missing(tmp_path: Any) -> None:
    missing = tmp_path / "nope.txt"
    assert _load_public_tlds(missing) == _PUBLIC_TLDS_FALLBACK


# ---------------------------------------------------------------------------
# Classification — the safety-critical rule
# ---------------------------------------------------------------------------


def test_classify_internal_suffix_active_at_threshold() -> None:
    # Associated (host.name / PTR of internal hosts) → eligible to activate.
    cand = _Candidate(value="corp.acme.local", host_count=3, associated=True)
    assert classify_suffix(cand, min_hosts=3) == "active"


def test_classify_internal_suffix_below_threshold_muted() -> None:
    cand = _Candidate(value="corp.acme.local", host_count=2, associated=True)
    assert classify_suffix(cand, min_hosts=3) == "muted"


def test_classify_public_domain_never_active_even_huge_count() -> None:
    """THE safety test: a query-only public registrable domain is never active —
    and now dropped entirely (not even suggested), to kill FP noise."""
    cand = _Candidate(value="evil.com", host_count=10_000, associated=False)
    assert classify_suffix(cand, min_hosts=3) is None
    # multi-label public form too
    cand2 = _Candidate(value="cdn.cloudflare.com", host_count=99_999, associated=False)
    assert classify_suffix(cand2, min_hosts=3) is None
    # the real-world FP the operator reported: a common external domain looked up
    # by internal hosts must NOT be surfaced as an internal identifier.
    assert classify_suffix(_Candidate(value="apple.com", associated=False), min_hosts=3) is None


def test_classify_reserved_default_suffix_dropped() -> None:
    for reserved in ("lan", "local", "internal", "corp"):
        cand = _Candidate(value=reserved, host_count=50)
        assert classify_suffix(cand, min_hosts=3) is None


def test_classify_associated_public_domain_active() -> None:
    """An associated public domain (org's own AD domain via host.name) activates."""
    cand = _Candidate(value="evil.com", host_count=10_000, associated=True)
    # associated public registrable → eligible to activate (it IS the org's name)
    assert classify_suffix(cand, min_hosts=3) == "active"


# ---------------------------------------------------------------------------
# Signal-quality / association gate
# ---------------------------------------------------------------------------


def test_classify_query_only_public_domain_dropped() -> None:
    # update-cdn.click seen ONLY as an outbound DNS query → dropped (public,
    # lookup-only). New gTLDs are recognised as public via the IANA snapshot.
    cand = _Candidate(value="update-cdn.click", host_count=50, associated=False)
    assert classify_suffix(cand, min_hosts=3) is None


def test_classify_query_only_internal_suffix_demoted_to_muted() -> None:
    # Even a reserved-TLD suffix is only a low-confidence suggestion if it was
    # never a host.name/PTR of an internal host.
    cand = _Candidate(value="weird.local", host_count=99, associated=False)
    assert classify_suffix(cand, min_hosts=3) == "muted"


def test_classify_hostname_associated_corp_public_domain_active() -> None:
    # corp.acme.com appears as host.name of AD-joined internal hosts → capturable
    # despite the public .com TLD (discriminator is association, not the TLD).
    cand = _Candidate(value="corp.acme.com", host_count=5, associated=True)
    assert classify_suffix(cand, min_hosts=3) == "active"


def test_classify_associated_internal_suffix_active() -> None:
    cand = _Candidate(value="corp.acme.local", host_count=3, associated=True)
    assert classify_suffix(cand, min_hosts=3) == "active"


def test_classify_host_query_only_muted() -> None:
    assert classify_host(_Candidate(value="WIN11-01", host_count=9, associated=False), 3) == "muted"
    assert classify_host(_Candidate(value="WIN11-01", host_count=9, associated=True), 3) == "active"


def test_classify_host_active_and_muted() -> None:
    assert (
        classify_host(_Candidate(value="WIN11-01", host_count=3, associated=True), min_hosts=3)
        == "active"
    )
    assert (
        classify_host(_Candidate(value="lonely", host_count=1, associated=True), min_hosts=3)
        == "muted"
    )


# ---------------------------------------------------------------------------
# run_discovery — end-to-end with mocked ES
# ---------------------------------------------------------------------------


async def test_run_discovery_extracts_and_classifies() -> None:
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(
        host_buckets=[
            _bucket("dc01.corp.acme.local", 200, 5),  # internal suffix, 5 hosts → active
            _bucket("WIN11-01", 30, 4),  # bare host, 4 → active
            _bucket("lonely-box", 2, 1),  # bare host, 1 → muted
        ],
        dns_buckets=[
            _bucket("www.evil.com", 5000, 8),  # PUBLIC, lookup-only → dropped (FP noise)
            _bucket("printer.corp.acme.local", 12, 1),  # same suffix, +1 host
        ],
    )

    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]

    assert isinstance(summary, DiscoverySummary)
    assert summary.started_at is not None and summary.finished_at is not None
    assert summary.errors == []

    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}

    # internal suffix: host counts accumulate across the two FQDN buckets (5+1=6)
    corp = rows[("suffix", ".corp.acme.local")]
    assert corp.state == "active"
    assert corp.source == "detected"
    assert corp.evidence is not None
    assert corp.evidence["host_count"] == 6
    assert "dc01.corp.acme.local" in corp.evidence["sample"]

    # public domain seen ONLY as a lookup → dropped entirely (not even a muted
    # suggestion), despite 8 hosts — it's an external service, not our domain.
    assert ("suffix", ".evil.com") not in rows

    # bare hosts
    assert rows[("host", "WIN11-01")].state == "active"
    assert rows[("host", "lonely-box")].state == "muted"

    assert summary.suffixes_active == 1  # corp.acme.local only
    assert summary.suffixes_muted == 0  # evil.com (public, lookup-only) dropped, not muted


async def test_run_discovery_query_only_public_domain_never_active() -> None:
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(
        host_buckets=[_bucket("dc01.corp.acme.local", 200, 5)],  # associated internal → active
        dns_buckets=[_bucket("cdn-12.update-cdn.click", 9000, 40)],  # query-only public → dropped
    )
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    assert rows[("suffix", ".corp.acme.local")].state == "active"
    # query-only public domain is dropped entirely — never an internal identifier
    assert ("suffix", ".update-cdn.click") not in rows


async def test_run_discovery_hostname_corp_public_domain_active() -> None:
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(
        host_buckets=[_bucket(f"ws{i}.corp.acme.com", 100, 1) for i in range(5)],  # 5 distinct
    )
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    assert rows[("suffix", ".corp.acme.com")].state == "active"  # public TLD but host.name-assoc


async def test_run_discovery_ptr_answer_marks_association() -> None:
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(
        ptr_buckets=[_bucket("dc01.corp.acme.local", 10, 4)],  # PTR answer for an internal IP
    )
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    assert rows[("suffix", ".corp.acme.local")].state == "active"


async def test_run_discovery_skips_reverse_zone_names() -> None:
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(dns_buckets=[_bucket("7.0.10.10.in-addr.arpa", 50, 9)])
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        rows = await ids.list_identifiers(db, kind="suffix")
    assert not any("arpa" in r.value for r in rows)  # reverse-zone names never become identifiers


async def test_run_discovery_graceful_degradation_on_subquery_error() -> None:
    """One sub-query raising is recorded; the other signal still processes."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(
        host_buckets=[_bucket("dc01.corp.acme.local", 50, 5)],
        dns_buckets=[_bucket("printer.corp.acme.local", 3, 3)],
        raise_on="host.name",  # the host.name aggregation blows up
    )

    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]

    # error recorded, scan did not crash
    assert any("host.name" in e for e in summary.errors)
    # the zeek.dns.query signal still landed a row
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    assert ("suffix", ".corp.acme.local") in rows


async def test_run_discovery_preserves_operator_mute_on_rerun() -> None:
    """A muted detected row stays muted across a re-scan (tombstone)."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(host_buckets=[_bucket("dc01.corp.acme.local", 50, 9)])

    # First scan → active (9 hosts ≥ 3)
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        rows = await ids.list_identifiers(db, kind="suffix")
        row = next(r for r in rows if r.value == ".corp.acme.local")
        assert row.state == "active"
        # operator mutes it
        await ids.set_state(db, row.id, "muted")

    # Second scan with the same strong signal must NOT flip it back to active
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        rows = await ids.list_identifiers(db, kind="suffix")
        row = next(r for r in rows if r.value == ".corp.acme.local")
        assert row.state == "muted"  # operator mute preserved


async def test_run_discovery_no_cidrs_returns_error_summary() -> None:
    settings = _settings()
    settings.internal_cidrs = []  # type: ignore[assignment]
    maker = await _sessionmaker(settings)
    fake = FakeES(host_buckets=[_bucket("dc01.corp.acme.local", 50, 9)])
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    assert summary.errors  # no CIDRs → recorded, zero yield
    assert summary.suffixes_found == 0


# ---------------------------------------------------------------------------
# ECS field resolution + the internal-resolution / local-flag signals
# ---------------------------------------------------------------------------


def _resolved_bucket(
    query_name: str,
    resolved_ips: list[str],
    doc_count: int = 10,
    distinct: int = 1,
    registered_domain: str | None = None,
) -> dict[str, Any]:
    """A DNS-query bucket carrying a resolved-IP sub-terms (+ optional reg-dom)."""
    bucket: dict[str, Any] = {
        "key": query_name,
        "doc_count": doc_count,
        "distinct_hosts": {"value": distinct},
        "resolved_ips": {"buckets": [{"key": ip, "doc_count": 1} for ip in resolved_ips]},
    }
    if registered_domain is not None:
        bucket["registered_domain"] = {"buckets": [{"key": registered_domain, "doc_count": 1}]}
    return bucket


async def test_run_discovery_resolves_ecs_dns_field_on_modern_grid() -> None:
    """On an ECS grid the DNS aggregation must run on dns.query.name, not zeek.*."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(
        ecs=True,
        host_buckets=[_bucket("dc01.corp.acme.local", 200, 5)],
        # The fake routes the DNS-query agg to _dns when the agg field is the
        # RESOLVED field; on ecs=True that's dns.query.name.
        dns_buckets=[_bucket("printer.corp.acme.local", 12, 2)],
    )
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    assert summary.errors == []
    # The DNS aggregation ran on the ECS field, not zeek.dns.query.
    assert "dns.query.name" in fake.calls
    assert "zeek.dns.query" not in fake.calls
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    assert rows[("suffix", ".corp.acme.local")].state == "active"


async def test_run_discovery_domain_resolving_to_internal_ip_is_active() -> None:
    """A domain whose resolved IP is internal is association=True → active.

    This is the STRONGEST signal: a forward record pointing at an internal
    address is the host's own name, even though the same name seen only as an
    outbound query would be muted.
    """
    settings = _settings()
    maker = await _sessionmaker(settings)
    # 3 distinct internal hosts all resolve names under app.corp.acme.com to
    # internal 10.x addresses → the suffix is internal-associated and active.
    resolved = [
        _resolved_bucket(f"svc{i}.app.acme.com", ["10.50.0.7"], distinct=1) for i in range(3)
    ]
    fake = FakeES(ecs=True, resolved_buckets=resolved)
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    assert summary.errors == []
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    # acme.com is a PUBLIC registrable domain, yet because it RESOLVES to an
    # internal IP (associated) it is eligible to activate at/above min_hosts.
    suffix = rows[("suffix", ".app.acme.com")]
    assert suffix.state == "active"
    assert suffix.evidence is not None
    assert suffix.evidence["host_count"] >= 3


async def test_run_discovery_domain_resolving_external_not_associated() -> None:
    """A domain resolving only to EXTERNAL IPs is NOT marked associated here.

    It is still picked up by the weak query-only aggregation, but a public domain
    seen only as a lookup is now dropped entirely (the tightened safety contract).
    """
    settings = _settings()
    maker = await _sessionmaker(settings)
    resolved = [_resolved_bucket("www.evil.com", ["93.184.216.34"], distinct=40)]
    fake = FakeES(
        ecs=True,
        resolved_buckets=resolved,
        dns_buckets=[_bucket("www.evil.com", 9000, 40)],  # weak query-only signal
    )
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    # Resolved external → not associated; only the query-only signal applies →
    # public domain is dropped, not surfaced at all.
    assert ("suffix", ".evil.com") not in rows


async def test_run_discovery_prefers_highest_registered_domain() -> None:
    """SO's computed dns.highest_registered_domain wins over derive_suffix."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    resolved = [
        _resolved_bucket(
            f"a.b.svc{i}.corp.example.com",
            ["10.10.10.10"],
            distinct=1,
            registered_domain="example.com",
        )
        for i in range(3)
    ]
    fake = FakeES(ecs=True, resolved_buckets=resolved)
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    # The suffix is the SO-computed registrable domain, not the label-stripped
    # parent (which would be b.svc0.corp.example.com).
    assert ("suffix", ".example.com") in rows
    assert rows[("suffix", ".example.com")].state == "active"


async def test_run_discovery_local_flag_corroborates_cidr_suggestion() -> None:
    """connection.local.originator-flagged IPs feed the /24 CIDR clustering."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    # A NEW RFC1918 /24 (172.16.5.0/24) NOT in the effective CIDRs, seen only via
    # the connection.local.originator flag → still suggested (always muted).
    local_orig = [_ip_bucket(f"172.16.5.{i}") for i in range(1, 5)]
    fake = FakeES(ecs=True, local_orig_ip_buckets=local_orig)
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    assert summary.cidrs_suggested >= 1
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db, kind="cidr")}
    cidr = rows[("cidr", "172.16.5.0/24")]
    assert cidr.state == "muted"  # CIDR is two-directional → never auto-active


async def test_run_discovery_legacy_grid_still_uses_zeek_fields() -> None:
    """Old SO / synth fixtures (ecs=False) resolve to zeek.* and still work."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(host_buckets=[_bucket("dc01.corp.acme.local", 50, 5)])
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    # DNS aggregation fell back to zeek.dns.query on this legacy grid.
    assert "zeek.dns.query" in fake.calls
    assert "dns.query.name" not in fake.calls


def test_distinct_host_counting_sums_cardinality() -> None:
    """Distinct-host count accumulates the cardinality sub-agg per suffix."""
    cidrs = [__import__("ipaddress").ip_network("10.0.0.0/8")]
    suffixes: dict[str, _Candidate] = {}
    hosts: dict[str, _Candidate] = {}
    disc._ingest_buckets(
        [
            _bucket("a.corp.acme.local", 10, 4),
            _bucket("b.corp.acme.local", 20, 3),
        ],
        cidrs,  # type: ignore[arg-type]
        suffixes,
        hosts,
        associated=True,
    )
    assert suffixes["corp.acme.local"].host_count == 7
    assert suffixes["corp.acme.local"].event_count == 30


def test_ingest_skips_ip_keys() -> None:
    cidrs = [__import__("ipaddress").ip_network("10.0.0.0/8")]
    suffixes: dict[str, _Candidate] = {}
    hosts: dict[str, _Candidate] = {}
    disc._ingest_buckets(
        [_bucket("10.1.2.3", 5, 2)],
        cidrs,  # type: ignore[arg-type]
        suffixes,
        hosts,
        associated=True,
    )
    assert suffixes == {}
    assert hosts == {}


# ---------------------------------------------------------------------------
# CIDR discovery (Increment 3 — SUGGEST-FIRST)
# ---------------------------------------------------------------------------


def test_is_rfc1918_accepts_private_rejects_public() -> None:
    assert _is_rfc1918("10.50.0.7") is not None
    assert _is_rfc1918("172.16.4.1") is not None
    assert _is_rfc1918("192.168.1.1") is not None
    # public / loopback / link-local / non-v4 / garbage → None
    assert _is_rfc1918("8.8.8.8") is None
    assert _is_rfc1918("127.0.0.1") is None
    assert _is_rfc1918("169.254.1.1") is None
    assert _is_rfc1918("::1") is None
    assert _is_rfc1918("not-an-ip") is None


def test_slash24_clusters_to_network() -> None:
    import ipaddress

    assert str(_slash24(ipaddress.IPv4Address("10.50.0.7"))) == "10.50.0.0/24"
    assert str(_slash24(ipaddress.IPv4Address("172.16.4.200"))) == "172.16.4.0/24"


def test_ingest_ip_buckets_clusters_rfc1918_not_covered() -> None:
    """RFC1918 IPs outside the covered set cluster into /24s; covered+public skip."""
    import ipaddress

    covered = [ipaddress.ip_network("192.168.0.0/16")]
    candidates: dict[str, _CidrCandidate] = {}
    _ingest_ip_buckets(
        [
            _ip_bucket("10.50.0.7", 5),
            _ip_bucket("10.50.0.8", 3),
            _ip_bucket("10.50.0.7", 2),  # dup IP — counts once toward host_count
            _ip_bucket("192.168.1.1", 9),  # already covered → skipped
            _ip_bucket("8.8.8.8", 99),  # public → skipped
            _ip_bucket("not-an-ip", 1),  # garbage → skipped
            _ip_bucket("10.99.0.1", 1),  # different /24
        ],
        covered,  # type: ignore[arg-type]
        candidates,
    )
    assert set(candidates) == {"10.50.0.0/24", "10.99.0.0/24"}
    c = candidates["10.50.0.0/24"]
    assert c.host_count == 2  # distinct IPs: .7 and .8
    assert c.event_count == 10  # 5 + 3 + 2
    assert c.sample() == ["10.50.0.7", "10.50.0.8"]


async def test_run_discovery_suggests_new_24_always_muted() -> None:
    """A new /24 with ≥ min_hosts distinct private IPs is suggested — and MUTED."""
    settings = _settings()  # internal_cidrs = 10/8 + 192.168/16
    maker = await _sessionmaker(settings)
    # 172.16.x is RFC1918 but NOT in the configured internal_cidrs → a candidate.
    fake = FakeES(
        src_ip_buckets=[
            _ip_bucket("172.16.5.1", 100),
            _ip_bucket("172.16.5.2", 50),
            _ip_bucket("172.16.5.3", 10),  # 3 distinct → at threshold
        ],
        dst_ip_buckets=[_ip_bucket("8.8.8.8", 9999)],  # public → ignored
    )
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]

    assert summary.cidrs_found == 1
    assert summary.cidrs_suggested == 1
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    row = rows[("cidr", "172.16.5.0/24")]
    assert row.state == "muted"  # SUGGEST-FIRST — never auto-active
    assert row.source == "detected"
    assert row.evidence is not None
    assert row.evidence["host_count"] == 3


async def test_run_discovery_cidr_always_muted_regardless_of_count() -> None:
    """THE safety test: no count/volume makes a discovered CIDR active."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(
        src_ip_buckets=[_ip_bucket(f"172.20.7.{i}", 1_000_000) for i in range(1, 60)],
    )
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    assert summary.cidrs_found == 1
    async with maker() as db:
        rows = await ids.list_identifiers(db, kind="cidr")
    detected = [r for r in rows if r.source == "detected"]
    assert detected, "expected a detected CIDR row"
    assert all(r.state == "muted" for r in detected), (
        "a discovered CIDR must ALWAYS be muted — never auto-active"
    )


async def test_run_discovery_cidr_below_min_hosts_not_suggested() -> None:
    """A /24 with fewer than min_hosts distinct private IPs is dropped."""
    settings = _settings()  # discovery_min_hosts = 3
    maker = await _sessionmaker(settings)
    fake = FakeES(
        src_ip_buckets=[_ip_bucket("172.16.9.1", 5), _ip_bucket("172.16.9.2", 5)],  # only 2
    )
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    assert summary.cidrs_found == 0
    async with maker() as db:
        rows = await ids.list_identifiers(db, kind="cidr")
    assert [r for r in rows if r.source == "detected"] == []


async def test_run_discovery_cidr_excludes_already_covered() -> None:
    """IPs inside the configured internal_cidrs never become a suggestion."""
    settings = _settings()  # 10/8 covered
    maker = await _sessionmaker(settings)
    fake = FakeES(
        src_ip_buckets=[_ip_bucket(f"10.1.2.{i}", 100) for i in range(1, 30)],
    )
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    assert summary.cidrs_found == 0
    async with maker() as db:
        rows = await ids.list_identifiers(db, kind="cidr")
    assert [r for r in rows if r.source == "detected"] == []


async def test_run_discovery_cidr_graceful_degradation_on_ip_agg_error() -> None:
    """A source.ip agg error is recorded; destination.ip signal still processes."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(
        dst_ip_buckets=[_ip_bucket(f"172.16.8.{i}", 10) for i in range(1, 5)],
        raise_on="source.ip",
    )
    summary = await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    assert any("source.ip" in e for e in summary.errors)
    # destination.ip signal still landed a muted suggestion
    async with maker() as db:
        rows = {(r.kind, r.value): r for r in await ids.list_identifiers(db)}
    assert rows[("cidr", "172.16.8.0/24")].state == "muted"


async def test_run_discovery_cidr_preserves_operator_unmute_on_rerun() -> None:
    """An operator-unmuted (activated) detected CIDR stays active across re-scan."""
    settings = _settings()
    maker = await _sessionmaker(settings)
    fake = FakeES(src_ip_buckets=[_ip_bucket(f"172.16.6.{i}", 100) for i in range(1, 6)])

    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        row = next(
            r for r in await ids.list_identifiers(db, kind="cidr") if r.value == "172.16.6.0/24"
        )
        assert row.state == "muted"  # suggested muted on first scan
        await ids.set_state(db, row.id, "active")  # operator un-mutes (activates)

    # Re-scan: upsert must NOT flip the operator-activated row back to muted.
    await run_discovery(fake, maker, settings)  # type: ignore[arg-type]
    async with maker() as db:
        row = next(
            r for r in await ids.list_identifiers(db, kind="cidr") if r.value == "172.16.6.0/24"
        )
        assert row.state == "active"  # operator activation preserved (tombstone is mute-only)


# ---------------------------------------------------------------------------
# Endpoint: POST/GET /api/v1/discovery/scan
# ---------------------------------------------------------------------------


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


def test_discovery_scan_post_starts_and_get_reports(client: TestClient) -> None:
    async def _instant(es: Any, maker: Any, settings: Any) -> DiscoverySummary:
        return DiscoverySummary(
            started_at="t0", finished_at="t1", suffixes_found=2, suffixes_active=1
        )

    with patch("soc_ai.enrichment.discovery.run_discovery", _instant):
        resp = client.post("/api/v1/discovery/scan")
        assert resp.status_code == 200
        assert resp.json()["note"] in ("started", "already running")

        # Poll GET until the background task settles.
        import time

        deadline = time.time() + 5.0
        data: dict[str, Any] = {}
        while time.time() < deadline:
            data = client.get("/api/v1/discovery/scan").json()
            if not data["running"] and data.get("last_scan"):
                break
            time.sleep(0.05)

    assert data["running"] is False
    assert data["last_scan"] is not None
    assert data["last_summary"]["suffixes_found"] == 2


def test_discovery_scan_single_flight(client: TestClient) -> None:
    """A second POST while a scan is running returns the running status."""
    import soc_ai.api.webui_api as api

    # Pre-mark the in-memory status as running (no task) so the second POST is rejected.
    app_state = client.app.state  # type: ignore[attr-defined]
    status = api._get_discovery_status(app_state)
    status.running = True
    try:
        resp = client.post("/api/v1/discovery/scan")
        assert resp.status_code == 200
        assert resp.json()["note"] == "already running"
        assert resp.json()["running"] is True
    finally:
        status.running = False


def test_discovery_scan_disabled_note(client: TestClient) -> None:
    import soc_ai.api.webui_api as api

    app_state = client.app.state  # type: ignore[attr-defined]
    app_state.settings.discovery_enabled = False
    # ensure idle
    api._get_discovery_status(app_state).running = False
    try:
        resp = client.post("/api/v1/discovery/scan")
        assert resp.status_code == 200
        assert resp.json()["note"] == "discovery disabled"
        assert resp.json()["running"] is False
    finally:
        app_state.settings.discovery_enabled = True


def test_discovery_scan_admin_gated() -> None:
    """With api_auth_required on and no session, the route is auth-gated."""
    gated = _settings().model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw")}
    )
    for client in _client(gated):
        resp = client.get("/api/v1/discovery/scan")
        assert resp.status_code in (401, 403)
        resp_post = client.post("/api/v1/discovery/scan")
        assert resp_post.status_code in (401, 403)
