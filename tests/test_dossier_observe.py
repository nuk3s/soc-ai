"""Tests for the host-dossier collector (``soc_ai.dossier.observe``).

Every case runs against a fake Elasticsearch that routes on the SHAPE of the
request, because the collector issues six *kinds* of search and the guarantees
differ per kind:

* ``exists`` probes  — :func:`soc_ai.so_client.fields.resolve_agg_field` deciding
  which of a dual-mapped field's names actually carries data here.
* the dataset inventory — what telemetry this grid has AT ALL.
* the network agent inventory — every machine that self-reports through a host
  log agent, and which addresses each one claims. Once per SWEEP, not per host.
* the network DNS-name pass — what the network's own DNS answers call each
  internal address. Once per SWEEP too, and for the same reason.
* the one multi-agg pass — volume, ports, peers, bytes, hours.
* the targeted identity searches — DHCP / SSH / Windows / software / UA / PTR.

The defects these tests exist to prevent are all silent ones: a ``terms`` agg on
``zeek.dns.query`` returns zero buckets on a modern SO grid rather than an
error, so a dossier built without the ECS-first resolver concludes "this host
makes no DNS queries" and is confidently wrong; a missing ``zeek.dhcp`` dataset
looks exactly like "no lease seen", which reads as "statically addressed" for
the whole network; and a synth fixture leaking past the kill-switch would put
eval data into a production asset record.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from soc_ai.dossier.observe import (
    collect_agent_inventory,
    collect_dns_names,
    collect_host_observations,
    reverse_zone,
)
from soc_ai.dossier.types import (
    AgentInventory,
    DnsNameClaim,
    DnsNameInventory,
    HostObservations,
)
from soc_ai.so_client import fields, inventory
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.tools.host_summary import _base_host_query

_IP = "192.168.10.202"
_INDEX = "logs-*"

# The dual-mapped fields the multi-agg pass aggregates on. Hard-coding either
# spelling in observe.py is the bug; these two sets are what the resolver must
# choose between.
_ECS_POPULATED = frozenset(
    {
        "network.protocol",
        "client.bytes",
        "server.bytes",
        "hash.ja3",
        "dns.highest_registered_domain",
        "dns.query.name",
        "dns.resolved_ip",
        "ssl.server_name",
    }
)
_LEGACY_POPULATED = frozenset(
    {
        "zeek.conn.service",
        "zeek.conn.orig_bytes",
        "zeek.conn.resp_bytes",
        "zeek.ssl.ja3",
        "zeek.dns.query",
        "zeek.dns.answers",
        "zeek.ssl.server_name",
    }
)

_ALL_DATASETS = (
    "zeek.conn",
    "zeek.dns",
    "zeek.dhcp",
    "zeek.ssh",
    "zeek.ntlm",
    "zeek.kerberos",
    "zeek.smb_mapping",
    "zeek.dce_rpc",
    "zeek.software",
    "zeek.http",
    "zeek.ssl",
)


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


_FIRST_SEEN = datetime(2026, 7, 24, 3, 15, tzinfo=UTC)
_LAST_SEEN = datetime(2026, 8, 6, 17, 42, tzinfo=UTC)

# A Proxmox-shaped responder: management-plane ports, a handful of peers, all
# day long. The classifier's rules read every one of these numbers.
_MAIN_AGGS: dict[str, Any] = {
    "first_seen": {"value": float(_ms(_FIRST_SEEN)), "value_as_string": "2026-07-24T03:15:00.000Z"},
    "last_seen": {"value": float(_ms(_LAST_SEEN)), "value_as_string": "2026-08-06T17:42:00.000Z"},
    "datasets": {
        "buckets": [
            {"key": "zeek.conn", "doc_count": 3412},
            {"key": "zeek.dns", "doc_count": 88},
        ]
    },
    "responder": {
        "doc_count": 3412,
        "ports": {
            "buckets": [
                {"key": 8006, "doc_count": 900},
                {"key": 22, "doc_count": 41},
                {"key": 9999, "doc_count": 1},
            ]
        },
        "peers": {"value": 4},
        "hours": {
            "buckets": [
                {"key": _ms(datetime(2026, 8, 6, 9, tzinfo=UTC)), "doc_count": 300},
                {"key": _ms(datetime(2026, 8, 6, 10, tzinfo=UTC)), "doc_count": 120},
            ]
        },
        "services": {"buckets": [{"key": "http", "doc_count": 900}]},
        "bytes": {"values": {"50.0": 1200.0, "95.0": 98000.0}},
    },
    "originator": {
        "doc_count": 500,
        "ports": {
            "buckets": [
                {"key": 443, "doc_count": 400},
                {"key": 53, "doc_count": 88},
            ]
        },
        "peers": {"value": 12},
        "bytes": {"values": {"50.0": 300.0, "95.0": 4000.0}},
        "ja3": {"value": 3},
    },
    "activity": {
        "buckets": [
            {"key": _ms(datetime(2026, 8, 5, 9, tzinfo=UTC)), "doc_count": 40},
            {"key": _ms(datetime(2026, 8, 6, 9, tzinfo=UTC)), "doc_count": 60},
            {"key": _ms(datetime(2026, 8, 6, 22, tzinfo=UTC)), "doc_count": 5},
        ]
    },
    "reg_domains": {"buckets": [{"key": "proxmox.com", "doc_count": 12}]},
    "dns_queries": {"buckets": [{"key": "enterprise.proxmox.com", "doc_count": 12}]},
    "sni": {"buckets": [{"key": "enterprise.proxmox.com", "doc_count": 7}]},
}


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    """Both resolvers are process-cached; a stale entry would hide a regression."""
    fields._clear_agg_field_cache()
    inventory._clear_cache()
    yield
    fields._clear_agg_field_cache()
    inventory._clear_cache()


def _settings() -> Any:
    class _S:
        events_index_pattern = _INDEX

    return _S()


def _result(
    *,
    hits: list[dict[str, Any]] | None = None,
    total: int | None = None,
    aggregations: dict[str, Any] | None = None,
) -> EsSearchResult:
    wrapped = [{"_id": f"e{i}", "_source": src} for i, src in enumerate(hits or [])]
    return EsSearchResult(
        total=total if total is not None else len(wrapped),
        took_ms=2,
        hits=wrapped,
        aggregations=aggregations,
    )


def _call_kind(query: dict[str, Any], aggs: dict[str, Any] | None) -> str:
    """Which of the collector's six search kinds this request is."""
    if "exists" in query:
        return "probe"
    if aggs and "responder" in aggs:
        return "main"
    if aggs and set(aggs) == {"datasets"}:
        return "inventory"
    if aggs and "hosts" in aggs:
        return "agent"
    if aggs and "names" in aggs:
        return "dns"
    return "targeted"


def _datasets_in(query: dict[str, Any]) -> tuple[str, ...]:
    """The ``event.dataset`` values a targeted query filters on (``()`` for PTR)."""
    for clause in query.get("bool", {}).get("must", []):
        if not isinstance(clause, dict):
            continue
        term = clause.get("term") or {}
        if "event.dataset" in term:
            return (str(term["event.dataset"]),)
        terms = clause.get("terms") or {}
        if "event.dataset" in terms:
            return tuple(str(d) for d in terms["event.dataset"])
    return ()


def _targeted_key(query: dict[str, Any]) -> str:
    datasets = _datasets_in(query)
    return "|".join(datasets) if datasets else "ptr"


class _FakeES:
    """Routes on request shape and records every call for assertion."""

    def __init__(
        self,
        *,
        populated: frozenset[str] = _ECS_POPULATED,
        grid_datasets: tuple[str, ...] = _ALL_DATASETS,
        main_aggs: dict[str, Any] | None = None,
        main_total: int = 0,
        main_errors: tuple[str, ...] = (),
        targeted_hits: dict[str, list[dict[str, Any]]] | None = None,
        targeted_errors: frozenset[str] = frozenset(),
        inventory_error: bool = False,
        agent_buckets: list[dict[str, Any]] | None = None,
        agent_error: bool = False,
        dns_buckets: list[dict[str, Any]] | None = None,
        dns_error: bool = False,
        dns_other: int = 0,
    ) -> None:
        self.populated = populated
        self.grid_datasets = grid_datasets
        self.main_aggs = main_aggs
        self.main_total = main_total
        self.main_errors = list(main_errors)
        self.targeted_hits = dict(targeted_hits or {})
        self.targeted_errors = targeted_errors
        self.inventory_error = inventory_error
        self.agent_buckets = list(agent_buckets or [])
        self.agent_error = agent_error
        self.dns_buckets = list(dns_buckets or [])
        self.dns_error = dns_error
        # `sum_other_doc_count` on the name terms agg: ES's only signal that
        # buckets fell off the end of `size`. The inner (per-name address) agg
        # carries its own, set per bucket by `_dns_bucket(other=...)`.
        self.dns_other = dns_other
        self.calls: list[dict[str, Any]] = []

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: list[dict[str, Any]] | None = None,
        source: list[str] | bool | None = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
    ) -> EsSearchResult:
        kind = _call_kind(query, aggs)
        call: dict[str, Any] = {
            "kind": kind,
            "index": index,
            "query": query,
            "size": size,
            "sort": sort,
            "source": source,
            "aggs": aggs,
            "track_total_hits": track_total_hits,
            "key": kind,
        }
        self.calls.append(call)

        if kind == "probe":
            field = query["exists"]["field"]
            return _result(total=1 if field in self.populated else 0)
        if kind == "inventory":
            if self.inventory_error:
                raise RuntimeError("inventory down")
            return _result(
                total=100,
                aggregations={
                    "datasets": {
                        "buckets": [
                            {"key": d, "doc_count": 10, "categories": {"buckets": []}}
                            for d in self.grid_datasets
                        ]
                    }
                },
            )
        if kind == "main":
            if self.main_errors:
                raise RuntimeError(self.main_errors.pop(0))
            return _result(total=self.main_total, aggregations=self.main_aggs)
        if kind == "agent":
            if self.agent_error:
                raise RuntimeError("circuit_breaking_exception on host.name terms")
            return _result(total=999, aggregations={"hosts": {"buckets": self.agent_buckets}})
        if kind == "dns":
            if self.dns_error:
                raise RuntimeError("circuit_breaking_exception on dns.query.name terms")
            return _result(
                total=38471,
                aggregations={
                    "names": {
                        "sum_other_doc_count": self.dns_other,
                        "buckets": self.dns_buckets,
                    }
                },
            )

        key = _targeted_key(query)
        call["key"] = key
        if key in self.targeted_errors:
            raise RuntimeError(f"search_phase_execution_exception on {key}")
        return _result(hits=self.targeted_hits.get(key, []))


async def _collect(
    es: Any,
    *,
    ip: str = _IP,
    window_hours: int = 24,
    time_anchor: datetime | None = None,
) -> HostObservations:
    return await collect_host_observations(
        ip,
        elastic=es,
        settings=_settings(),
        window_hours=window_hours,
        time_anchor=time_anchor,
    )


def _calls(es: _FakeES, kind: str) -> list[dict[str, Any]]:
    return [c for c in es.calls if c["kind"] == kind]


def _one(es: _FakeES, key: str) -> dict[str, Any]:
    matches = [c for c in es.calls if c["key"] == key]
    assert len(matches) == 1, f"expected exactly one {key!r} search, got {len(matches)}"
    return matches[0]


# ---------------------------------------------------------------------------
# ECS-first field resolution — the silent-zero-buckets defect.
# ---------------------------------------------------------------------------


async def test_dual_mapped_agg_fields_resolve_ecs_first_on_a_modern_grid() -> None:
    es = _FakeES(populated=_ECS_POPULATED, main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es)

    aggs = _one(es, "main")["aggs"]
    assert aggs["responder"]["aggs"]["services"]["terms"]["field"] == "network.protocol"
    assert aggs["responder"]["aggs"]["bytes"]["percentiles"]["field"] == "server.bytes"
    assert aggs["originator"]["aggs"]["bytes"]["percentiles"]["field"] == "client.bytes"
    assert aggs["originator"]["aggs"]["ja3"]["cardinality"]["field"] == "hash.ja3"
    assert aggs["reg_domains"]["terms"]["field"] == "dns.highest_registered_domain"
    assert aggs["dns_queries"]["terms"]["field"] == "dns.query.name"
    assert aggs["sni"]["terms"]["field"] == "ssl.server_name"


async def test_dual_mapped_agg_fields_resolve_to_zeek_on_a_legacy_grid() -> None:
    # The synth fixtures and older SO write zeek.*; the ECS names are mapped but
    # empty, so an ECS-hardcoded agg silently returns nothing.
    es = _FakeES(populated=_LEGACY_POPULATED, main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es)

    aggs = _one(es, "main")["aggs"]
    assert aggs["responder"]["aggs"]["services"]["terms"]["field"] == "zeek.conn.service"
    assert aggs["responder"]["aggs"]["bytes"]["percentiles"]["field"] == "zeek.conn.resp_bytes"
    assert aggs["originator"]["aggs"]["bytes"]["percentiles"]["field"] == "zeek.conn.orig_bytes"
    assert aggs["originator"]["aggs"]["ja3"]["cardinality"]["field"] == "zeek.ssl.ja3"
    assert aggs["dns_queries"]["terms"]["field"] == "zeek.dns.query"
    assert aggs["sni"]["terms"]["field"] == "zeek.ssl.server_name"


async def test_every_dual_mapped_field_is_probed_through_the_resolver() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es)

    probed = {c["query"]["exists"]["field"] for c in _calls(es, "probe")}
    # The ECS head of each of the seven dual-mapped candidate lists.
    for candidates in (
        fields.CONN_SERVICE,
        fields.CONN_RESP_BYTES,
        fields.CONN_ORIG_BYTES,
        fields.SSL_JA3,
        fields.DNS_REGISTERED_DOMAIN,
        fields.DNS_QUERY,
        fields.SSL_SNI,
    ):
        assert candidates[0] in probed, f"{candidates[0]} never went through resolve_agg_field"


async def test_canonical_ecs_fields_are_not_probed() -> None:
    # destination.port / source.ip / @timestamp / event.dataset are canonical ECS
    # on every grid — probing them would be three wasted round trips per host.
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es)

    probed = {c["query"]["exists"]["field"] for c in _calls(es, "probe")}
    assert probed.isdisjoint({"@timestamp", "event.dataset", "source.ip", "destination.port"})


# ---------------------------------------------------------------------------
# The base query: either-endpoint predicate + the synthetic-eval kill-switch.
# ---------------------------------------------------------------------------


async def test_main_query_is_the_host_summary_base_query() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es, window_hours=336)

    assert _one(es, "main")["query"] == _base_host_query(_IP, 336 * 60, None)


async def test_every_search_carries_the_synth_kill_switch() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es)

    kill_switch = [{"exists": {"field": "synth.scenario_id"}}]
    for call in es.calls:
        if call["kind"] in ("probe", "inventory"):
            continue
        assert call["query"]["bool"]["must_not"] == kill_switch, (
            f"{call['key']} search would let synth fixtures into a real dossier"
        )


async def test_time_anchor_is_threaded_into_every_window() -> None:
    anchor = datetime(2026, 7, 1, 12, tzinfo=UTC)
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es, window_hours=24, time_anchor=anchor)

    expected = _base_host_query(_IP, 24 * 60, anchor)["bool"]["filter"]
    for call in es.calls:
        if call["kind"] in ("probe", "inventory"):
            continue
        assert call["query"]["bool"]["filter"] == expected


async def test_main_pass_is_a_single_size_zero_round_trip() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es)

    main = _one(es, "main")
    assert main["size"] == 0
    assert main["track_total_hits"] is True
    assert main["index"] == _INDEX


# ---------------------------------------------------------------------------
# Aggregation -> observation mapping.
# ---------------------------------------------------------------------------


async def test_aggregations_populate_the_observation_set() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    obs = await _collect(es)

    assert obs.ip == _IP
    assert obs.total_events == 3412
    assert obs.first_seen == _FIRST_SEEN
    assert obs.last_seen == _LAST_SEEN
    assert obs.resp_ports == [
        {"value": 8006, "count": 900},
        {"value": 22, "count": 41},
        {"value": 9999, "count": 1},
    ]
    assert obs.orig_ports == [{"value": 443, "count": 400}, {"value": 53, "count": 88}]
    assert obs.resp_peer_count == 4
    assert obs.orig_peer_count == 12
    assert obs.resp_hours == 2
    assert obs.services == [{"value": "http", "count": 900}]
    assert obs.datasets == [
        {"value": "zeek.conn", "count": 3412},
        {"value": "zeek.dns", "count": 88},
    ]
    assert obs.resp_bytes_p50 == 1200.0
    assert obs.resp_bytes_p95 == 98000.0
    assert obs.orig_bytes_p50 == 300.0
    assert obs.orig_bytes_p95 == 4000.0
    assert obs.ja3_distinct == 3
    assert obs.registered_domains == [{"value": "proxmox.com", "count": 12}]
    assert obs.dns_queries == [{"value": "enterprise.proxmox.com", "count": 12}]
    assert obs.sni == [{"value": "enterprise.proxmox.com", "count": 7}]
    assert obs.errors == ()


async def test_hour_of_day_is_folded_client_side() -> None:
    # No painless script — scripting is disabled on hardened grids — so the
    # hourly histogram is folded here. Two 09:00 buckets on different days sum.
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    obs = await _collect(es)

    assert obs.hour_of_day == {9: 100, 22: 5}


# ---------------------------------------------------------------------------
# Dataset gating — "signal unavailable" is not "signal absent".
# ---------------------------------------------------------------------------


async def test_absent_dataset_skips_its_targeted_search() -> None:
    es = _FakeES(
        grid_datasets=("zeek.conn", "zeek.dns", "zeek.http"),
        main_aggs=_MAIN_AGGS,
        main_total=3412,
    )

    obs = await _collect(es)

    searched = {ds for c in es.calls if c["kind"] == "targeted" for ds in _datasets_in(c["query"])}
    assert "zeek.dhcp" not in searched
    assert "zeek.ssh" not in searched
    assert "zeek.software" not in searched
    assert searched.isdisjoint({"zeek.ntlm", "zeek.kerberos", "zeek.smb_mapping", "zeek.dce_rpc"})
    assert "zeek.http" in searched
    assert obs.available_datasets == frozenset({"zeek.conn", "zeek.dns", "zeek.http"})
    assert obs.dhcp == ()


async def test_multi_dataset_search_narrows_to_what_the_grid_has() -> None:
    es = _FakeES(
        grid_datasets=("zeek.conn", "zeek.ntlm", "zeek.dce_rpc", "zeek.http"),
        main_aggs=_MAIN_AGGS,
        main_total=3412,
    )

    await _collect(es)

    windows = _one(es, "zeek.ntlm|zeek.dce_rpc")
    assert _datasets_in(windows["query"]) == ("zeek.ntlm", "zeek.dce_rpc")
    assert _datasets_in(_one(es, "zeek.http")["query"]) == ("zeek.http",)


async def test_empty_inventory_does_not_gate_the_targeted_searches() -> None:
    # A discovery failure must not look like "this grid has no DHCP": that would
    # retract every previously-held hostname across the network on one bad sweep.
    es = _FakeES(inventory_error=True, main_aggs=_MAIN_AGGS, main_total=3412)

    obs = await _collect(es)

    searched = {ds for c in es.calls if c["kind"] == "targeted" for ds in _datasets_in(c["query"])}
    assert "zeek.dhcp" in searched
    assert "zeek.ssh" in searched
    assert obs.available_datasets == frozenset()


# ---------------------------------------------------------------------------
# The reduced-agg retry: a terms agg on a text-mapped field 400s the WHOLE pass.
# ---------------------------------------------------------------------------


async def test_reduced_agg_retry_fires_on_a_400() -> None:
    es = _FakeES(
        main_aggs=_MAIN_AGGS,
        main_total=3412,
        main_errors=(
            "BadRequestError(400, 'search_phase_execution_exception', 'Fielddata is "
            "disabled on [dns.query.name]')",
        ),
    )

    obs = await _collect(es)

    main_calls = _calls(es, "main")
    assert len(main_calls) == 2, "expected exactly one retry"
    retry_aggs = main_calls[1]["aggs"]
    for optional in ("reg_domains", "dns_queries", "sni"):
        assert optional not in retry_aggs
    assert "services" not in retry_aggs["responder"]["aggs"]
    assert "bytes" not in retry_aggs["responder"]["aggs"]
    assert "bytes" not in retry_aggs["originator"]["aggs"]
    assert "ja3" not in retry_aggs["originator"]["aggs"]
    # The mandatory half survives — this is what the role rules run on.
    assert retry_aggs["responder"]["aggs"]["ports"]["terms"]["field"] == "destination.port"
    assert retry_aggs["responder"]["aggs"]["peers"]["cardinality"]["field"] == "source.ip"
    assert "first_seen" in retry_aggs
    assert "activity" in retry_aggs
    assert obs.total_events == 3412
    assert obs.resp_peer_count == 4
    assert any("reduced-agg fallback" in e for e in obs.errors)


async def test_reduced_agg_retry_failure_is_a_clean_result() -> None:
    es = _FakeES(main_errors=("boom", "boom again"))

    obs = await _collect(es)

    assert len(_calls(es, "main")) == 2
    assert obs.total_events == 0
    assert obs.resp_ports == []
    assert any("boom again" in e for e in obs.errors)


# ---------------------------------------------------------------------------
# Targeted identity searches.
# ---------------------------------------------------------------------------

_TARGETED_HITS: dict[str, list[dict[str, Any]]] = {
    "zeek.dhcp": [
        {
            "@timestamp": "2026-08-06T17:00:00.000Z",
            "event": {"dataset": "zeek.dhcp"},
            "source": {"ip": _IP},
            "destination": {"ip": "192.168.10.1"},
            "dhcp": {
                "hostname": "pve01",
                "client": {"mac": "AA:BB:CC:11:22:33"},
                "client_fqdn": "pve01.lab.example",
                "domain": "lab.example",
            },
        }
    ],
    "zeek.ssh": [
        {
            "@timestamp": "2026-08-06T16:00:00.000Z",
            "event": {"dataset": "zeek.ssh"},
            "source": {"ip": "192.168.10.50"},
            "destination": {"ip": _IP},
            "ssh": {
                "client": "SSH-2.0-OpenSSH_9.2p1",
                "server": "SSH-2.0-OpenSSH_9.6p1 Debian-3",
                "version": 2,
                "direction": "INBOUND",
            },
        }
    ],
    "zeek.ntlm|zeek.kerberos|zeek.smb_mapping|zeek.dce_rpc": [
        {
            "@timestamp": "2026-08-06T15:00:00.000Z",
            "event": {"dataset": "zeek.ntlm"},
            "source": {"ip": _IP},
            "destination": {"ip": "192.168.10.10"},
            "ntlm": {"hostname": "PVE01", "domainname": "LAB"},
        },
        {
            "@timestamp": "2026-08-06T14:00:00.000Z",
            "event": {"dataset": "zeek.dce_rpc"},
            "source": {"ip": "192.168.10.50"},
            "destination": {"ip": _IP},
            "dce_rpc": {"endpoint": "drsuapi"},
        },
    ],
    "zeek.software": [
        {
            "@timestamp": "2026-08-06T13:00:00.000Z",
            "event": {"dataset": "zeek.software"},
            "source": {"ip": _IP},
            "destination": {"ip": "192.168.10.9"},
            "software": {
                "name": "Apache",
                "unparsed_version": "Apache/2.4.58 (Debian)",
                "software_type": "HTTP::SERVER",
            },
        }
    ],
    "zeek.http|zeek.ssl": [
        {
            "@timestamp": "2026-08-06T12:00:00.000Z",
            "event": {"dataset": "zeek.http"},
            "source": {"ip": _IP},
            "destination": {"ip": "192.168.10.9"},
            "user_agent": {"original": "curl/8.4.0"},
            "host": {"name": "pve01", "mac": "aa:bb:cc:11:22:33"},
        },
        {
            "@timestamp": "2026-08-06T11:00:00.000Z",
            "event": {"dataset": "zeek.http"},
            "source": {"ip": _IP},
            "destination": {"ip": "192.168.10.9"},
            "user_agent": {"original": "curl/8.4.0"},
            "host": {"name": "pve01"},
        },
    ],
    "ptr": [
        {
            "@timestamp": "2026-08-06T10:00:00.000Z",
            "event": {"dataset": "zeek.dns"},
            "dns": {"resolved_ip": ["pve01.lab.example"]},
        }
    ],
}


async def test_targeted_searches_sort_newest_first() -> None:
    # The opposite of host_summary's oldest-first 200-doc sample: a dossier
    # reports what a host IS now, so the newest announcement wins.
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412, targeted_hits=_TARGETED_HITS)

    await _collect(es)

    targeted = _calls(es, "targeted")
    assert targeted, "no targeted searches ran"
    for call in targeted:
        assert call["sort"] == [{"@timestamp": {"order": "desc"}}]
        assert call["size"] == 20


async def test_dhcp_lease_is_collected() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412, targeted_hits=_TARGETED_HITS)

    obs = await _collect(es)

    assert len(obs.dhcp) == 1
    lease = obs.dhcp[0]
    assert lease["hostname"] == "pve01"
    assert lease["mac"] == "AA:BB:CC:11:22:33"
    assert lease["client_fqdn"] == "pve01.lab.example"
    assert lease["domain"] == "lab.example"
    assert lease["source_ip"] == _IP
    assert lease["timestamp"] == datetime(2026, 8, 6, 17, 0, tzinfo=UTC)


async def test_ssh_banner_keeps_its_direction_and_endpoints() -> None:
    # A client banner identifies the ORIGINATOR and a server banner the
    # RESPONDER; without the endpoints the banner's OS lands on the wrong host.
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412, targeted_hits=_TARGETED_HITS)

    obs = await _collect(es)

    assert len(obs.ssh_banners) == 1
    banner = obs.ssh_banners[0]
    assert banner["server"] == "SSH-2.0-OpenSSH_9.6p1 Debian-3"
    assert banner["client"] == "SSH-2.0-OpenSSH_9.2p1"
    assert banner["destination_ip"] == _IP
    assert banner["source_ip"] == "192.168.10.50"


async def test_windows_identity_records_carry_dataset_and_direction() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412, targeted_hits=_TARGETED_HITS)

    obs = await _collect(es)

    assert len(obs.windows_identity) == 2
    ntlm, dce = obs.windows_identity
    assert ntlm["hostname"] == "PVE01"
    assert ntlm["domain"] == "LAB"
    assert ntlm["dataset"] == "zeek.ntlm"
    # The DC rule needs "host is the RESPONDER on a drsuapi endpoint".
    assert dce["dce_rpc_endpoint"] == "drsuapi"
    assert dce["destination_ip"] == _IP


async def test_software_and_user_agents_are_collected_deduped() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412, targeted_hits=_TARGETED_HITS)

    obs = await _collect(es)

    assert obs.software[0]["version"] == "Apache/2.4.58 (Debian)"
    assert obs.software[0]["name"] == "Apache"
    assert obs.user_agents == ("curl/8.4.0",)
    assert obs.host_names == ("pve01",)


async def test_ptr_query_uses_the_reverse_zone_and_no_host_filter() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412, targeted_hits=_TARGETED_HITS)

    obs = await _collect(es)

    ptr = _one(es, "ptr")
    must = ptr["query"]["bool"]["must"]
    assert must == [{"term": {"dns.query.name": "202.10.168.192.in-addr.arpa"}}]
    assert obs.ptr_name == "pve01.lab.example"


async def test_ptr_query_uses_the_resolved_dns_field_on_a_legacy_grid() -> None:
    es = _FakeES(populated=_LEGACY_POPULATED, main_aggs=_MAIN_AGGS, main_total=3412)

    await _collect(es)

    assert _one(es, "ptr")["query"]["bool"]["must"] == [
        {"term": {"zeek.dns.query": "202.10.168.192.in-addr.arpa"}}
    ]


async def test_identity_record_keys_are_the_classifier_vocabulary() -> None:
    # These key names are the seam between the collector and the pure
    # classifier: `soc_ai.dossier.infer` reads them by name off these records.
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412, targeted_hits=_TARGETED_HITS)

    obs = await _collect(es)

    envelope = {"timestamp", "dataset", "source_ip", "destination_ip"}
    assert envelope <= set(obs.dhcp[0])
    assert envelope <= set(obs.ssh_banners[0])
    assert set(obs.windows_identity[0]) == envelope | {"hostname", "domain"}
    assert set(obs.software[0]) == envelope | {"name", "version", "software_type"}


async def test_mac_is_read_from_this_hosts_own_side_of_the_connection() -> None:
    # source.mac / destination.mac are per-ENDPOINT. Coalescing them blindly
    # stamps the peer's hardware address onto this host every time the host is
    # on the other side — a silently wrong identity field, which is the whole
    # failure class the dossier exists to remove.
    es = _FakeES(
        main_aggs=_MAIN_AGGS,
        main_total=3412,
        targeted_hits={
            "zeek.ssh": [
                {
                    "@timestamp": "2026-08-06T16:00:00.000Z",
                    "event": {"dataset": "zeek.ssh"},
                    "source": {"ip": "192.168.10.50", "mac": "de:ad:be:ef:00:01"},
                    "destination": {"ip": _IP, "mac": "aa:bb:cc:11:22:33"},
                    "ssh": {"server": "SSH-2.0-OpenSSH_9.6p1 Debian-3"},
                }
            ],
            "zeek.software": [
                {
                    "@timestamp": "2026-08-06T13:00:00.000Z",
                    "event": {"dataset": "zeek.software"},
                    "source": {"ip": _IP, "mac": "aa:bb:cc:11:22:33"},
                    "destination": {"ip": "192.168.10.9", "mac": "de:ad:be:ef:00:02"},
                    "software": {"name": "Apache"},
                }
            ],
        },
    )

    obs = await _collect(es)

    assert obs.ssh_banners[0]["mac"] == "aa:bb:cc:11:22:33"
    assert obs.software[0]["mac"] == "aa:bb:cc:11:22:33"


async def test_ptr_answer_that_is_an_ip_is_rejected() -> None:
    # `dns.resolved_ip` on a PTR response sometimes carries the address back
    # rather than the name; an IP is not a hostname.
    es = _FakeES(
        main_aggs=_MAIN_AGGS,
        main_total=3412,
        targeted_hits={
            "ptr": [
                {
                    "@timestamp": "2026-08-06T10:00:00.000Z",
                    "dns": {"resolved_ip": ["192.168.10.202"]},
                },
                {"@timestamp": "2026-08-06T09:00:00.000Z", "dns": {"resolved_ip": ["pve01."]}},
            ]
        },
    )

    obs = await _collect(es)

    assert obs.ptr_name == "pve01"


async def test_multi_valued_identity_field_collapses_to_its_first_value() -> None:
    # ES returns an array for any field that was indexed more than once in a
    # document; a record holding ["pve01", "pve01.lab"] would render as a list.
    es = _FakeES(
        main_aggs=_MAIN_AGGS,
        main_total=3412,
        targeted_hits={
            "zeek.dhcp": [
                {
                    "@timestamp": "2026-08-06T17:00:00.000Z",
                    "event": {"dataset": "zeek.dhcp"},
                    "source": {"ip": _IP},
                    "dhcp": {"hostname": ["pve01", "pve01.lab.example"]},
                }
            ]
        },
    )

    obs = await _collect(es)

    assert obs.dhcp[0]["hostname"] == "pve01"
    assert obs.dhcp[0]["destination_ip"] is None


async def test_epoch_millis_min_max_aggs_still_yield_datetimes() -> None:
    # Not every grid returns `value_as_string` on a min/max date agg.
    aggs = dict(_MAIN_AGGS)
    aggs["first_seen"] = {"value": float(_ms(_FIRST_SEEN))}
    aggs["last_seen"] = {"value": float(_ms(_LAST_SEEN))}
    es = _FakeES(main_aggs=aggs, main_total=3412)

    obs = await _collect(es)

    assert obs.first_seen == _FIRST_SEEN
    assert obs.last_seen == _LAST_SEEN


async def test_empty_percentile_buckets_are_none_not_zero() -> None:
    # A host with no byte volume must not report a p50 of 0 — the baseline is
    # then "unknown", and "this host never transfers data" is a different claim.
    aggs = dict(_MAIN_AGGS)
    aggs["responder"] = {**_MAIN_AGGS["responder"], "bytes": {"values": {"50.0": None}}}
    es = _FakeES(main_aggs=aggs, main_total=3412)

    obs = await _collect(es)

    assert obs.resp_bytes_p50 is None
    assert obs.resp_bytes_p95 is None


def test_reverse_zone_ipv4() -> None:
    assert reverse_zone("192.168.10.202") == "202.10.168.192.in-addr.arpa"


def test_reverse_zone_ipv6() -> None:
    assert reverse_zone("2001:db8::1") == (
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    )


def test_reverse_zone_rejects_a_non_ip() -> None:
    assert reverse_zone("pve01.lab.example") is None


# ---------------------------------------------------------------------------
# Robustness: empty is a clean result, every failure returns rather than raises.
# ---------------------------------------------------------------------------


async def test_targeted_failure_records_an_error_and_keeps_the_rest() -> None:
    es = _FakeES(
        main_aggs=_MAIN_AGGS,
        main_total=3412,
        targeted_hits=_TARGETED_HITS,
        targeted_errors=frozenset({"zeek.dhcp"}),
    )

    obs = await _collect(es)

    assert obs.dhcp == ()
    assert any("zeek.dhcp" in e for e in obs.errors)
    assert obs.ssh_banners  # the other searches still ran
    assert obs.total_events == 3412


async def test_no_events_is_a_clean_empty_result() -> None:
    es = _FakeES(grid_datasets=(), main_aggs=None, main_total=0)

    obs = await _collect(es)

    assert obs == HostObservations(ip=_IP)


async def test_invalid_ip_never_raises_and_never_queries() -> None:
    es = _FakeES(main_aggs=_MAIN_AGGS, main_total=3412)

    obs = await _collect(es, ip="not-an-ip")

    assert obs.total_events == 0
    assert any("invalid IP" in e for e in obs.errors)
    assert es.calls == []


async def test_total_es_outage_never_raises() -> None:
    class _DeadES:
        async def search(self, *args: Any, **kwargs: Any) -> EsSearchResult:
            raise RuntimeError("connection refused")

    obs = await _collect(_DeadES())

    assert obs.ip == _IP
    assert obs.total_events == 0
    assert obs.errors


# ---------------------------------------------------------------------------
# The network agent inventory — the hostlog lane's pre-pass.
#
# Every shape below was read off the live network (11 hosts shipping
# `system.auth` + `system.syslog` through one filebeat release), with the names
# and addresses substituted. Three of them are the whole reason the attribution
# rule is a unique-claim rule and not a subnet rule:
#
# * `172.17.0.1` is claimed by FOUR different machines — it is Docker's default
#   bridge gateway, so every host running Docker reports it as its own. The
#   172.18-31.x gateways recur the same way.
# * `172.16.20.5` is a REAL second interface on one host, which is why "172.16/12
#   is bridge noise" is wrong in the other direction. No subnet predicate can
#   separate these two cases; only "how many machines claim this address" can.
# * every host also claims a pile of `fe80::` addresses. A link-local address
#   names an interface on a link, not a machine on the network, and the same one
#   can legitimately exist on two links — so a unique claim on one is not
#   evidence of anything.
# ---------------------------------------------------------------------------

_PVE_IP = _IP  # 192.168.10.202 — the host the pivot incident ran through
_QUIET_IP = "192.168.60.226"  # a VM with a handful of auth events and no service
_BRIDGE_IP = "172.17.0.1"  # claimed by four machines
_PROXY_SECOND_IP = "172.16.20.5"  # a real second interface, in the "noisy" range

_AGENT_FIRST = datetime(2026, 7, 25, 6, 0, tzinfo=UTC)
_AGENT_LAST = datetime(2026, 8, 8, 12, 24, 35, tzinfo=UTC)

_DEBIAN_OS = {
    "name": "Debian GNU/Linux",
    "family": "debian",
    "version": "13 (trixie)",
    "kernel": "7.0.12-1-pve",
    "platform": "debian",
    "type": "linux",
}
_FEDORA_OS = {
    "name": "Fedora Linux",
    "family": "redhat",
    "version": "43 (Server Edition)",
    "kernel": "7.1.4-104.fc43.x86_64",
    "platform": "fedora",
    "type": "linux",
}


def _agent_bucket(
    name: str,
    ips: list[str],
    *,
    os: dict[str, str] | None = None,
    macs: list[str] | None = None,
    docs: int = 14024,
    version: str = "9.3.7",
    last: datetime = _AGENT_LAST,
) -> dict[str, Any]:
    """One `host.name` bucket as Elasticsearch returns it.

    The identity fields come out of a size-1 `top_hits`, not out of terms aggs:
    one document is one moment, so the name, the kernel and the agent version in
    it are mutually consistent — and none of those fields has to be provable
    aggregatable for the pass to work.
    """
    return {
        "key": name,
        "doc_count": docs,
        "ips": {"buckets": [{"key": ip, "doc_count": docs} for ip in ips]},
        "first_report": {
            "value": float(_ms(_AGENT_FIRST)),
            "value_as_string": _AGENT_FIRST.isoformat(),
        },
        "last_report": {"value": float(_ms(last)), "value_as_string": last.isoformat()},
        "latest": {
            "hits": {
                "hits": [
                    {
                        "_id": f"a-{name}",
                        "_source": {
                            "@timestamp": last.isoformat(),
                            "agent": {"name": name, "type": "filebeat", "version": version},
                            "host": {
                                "name": name,
                                "ip": ips,
                                "mac": macs if macs is not None else ["52-54-00-12-34-56"],
                                "architecture": "x86_64",
                                "os": dict(os or _DEBIAN_OS),
                            },
                        },
                    }
                ]
            }
        },
    }


# The network as the aggregation returns it. `pve-a` is the hypervisor the pivot
# ran through; `quiet-vm` is the machine that pivoted through it — six thousand
# host-log documents and almost nothing on the wire, which is exactly the asset
# soc-ai could not name.
_NETWORK_BUCKETS: list[dict[str, Any]] = [
    _agent_bucket(
        "pve-a",
        [_PVE_IP, "fe80::5054:ff:fe12:3456", "fe80::5054:ff:fe98:7654"],
        macs=["52-54-00-12-34-56", "52-54-00-98-76-54", "0A-11-22-33-44-55"],
    ),
    _agent_bucket("quiet-vm", [_QUIET_IP, "fe80::5054:ff:feaa:0001"], os=_FEDORA_OS, docs=6175),
    # Four machines, one bridge gateway. None of them may claim it.
    _agent_bucket("buildbox", ["192.168.10.172", _BRIDGE_IP], docs=269998),
    _agent_bucket("registry-a", ["192.168.10.75", _BRIDGE_IP, "172.18.0.1"], docs=52085),
    _agent_bucket("sensor", ["192.168.10.253", _BRIDGE_IP, "172.17.1.1"], docs=5752897),
    _agent_bucket("workbench", ["192.168.10.220", _BRIDGE_IP, "172.18.0.1"], docs=369188),
    # A real second interface inside the range the bridges live in.
    _agent_bucket("edge-proxy", ["192.168.10.119", _PROXY_SECOND_IP], docs=216274),
]

_HOSTLOG_DATASETS = ("system.auth", "system.syslog")
_GRID_WITH_HOST_LOGS = (*_ALL_DATASETS, *_HOSTLOG_DATASETS)


async def _agent_inventory(es: Any, *, window_hours: int = 336) -> AgentInventory:
    return await collect_agent_inventory(
        elastic=es, settings=_settings(), window_hours=window_hours
    )


def _network_es(**overrides: Any) -> _FakeES:
    kwargs: dict[str, Any] = {
        "grid_datasets": _GRID_WITH_HOST_LOGS,
        "agent_buckets": _NETWORK_BUCKETS,
        "main_aggs": _MAIN_AGGS,
        "main_total": 3412,
    }
    kwargs.update(overrides)
    return _FakeES(**kwargs)


async def test_the_agent_inventory_is_one_aggregation_for_the_whole_network() -> None:
    """Once per sweep, not once per host — the entire cost model of the lane.

    A per-host version of this query would be one extra aggregation per address
    in the network, for an answer that is identical for all of them.
    """
    es = _network_es()

    await _agent_inventory(es)

    agent = _calls(es, "agent")
    assert len(agent) == 1, "the agent inventory is one round trip for the network"
    call = agent[0]
    assert call["size"] == 0, "an aggregation pass must pull no documents"
    assert call["index"] == _INDEX
    hosts = call["aggs"]["hosts"]
    assert hosts["terms"]["field"] == "host.name"
    assert hosts["aggs"]["ips"]["terms"]["field"] == "host.ip"
    # Size 1, newest-first: the freshest self-report, as one coherent document.
    assert hosts["aggs"]["latest"]["top_hits"]["size"] == 1
    assert hosts["aggs"]["latest"]["top_hits"]["sort"] == [{"@timestamp": {"order": "desc"}}]
    datasets = [c for c in call["query"]["bool"]["filter"] if "terms" in c]
    assert datasets[0]["terms"]["event.dataset"] == list(_HOSTLOG_DATASETS)
    assert call["query"]["bool"]["must_not"] == [{"exists": {"field": "synth.scenario_id"}}]


async def test_a_uniquely_claimed_address_carries_the_agents_self_report() -> None:
    es = _network_es()

    inventory_ = await _agent_inventory(es)
    report, claimants = inventory_.for_ip(_PVE_IP)

    assert claimants == ()
    assert report is not None
    assert report.host_name == "pve-a"
    assert report.os["name"] == "Debian GNU/Linux"
    assert report.os["kernel"] == "7.0.12-1-pve"
    assert report.os["type"] == "linux"
    assert report.architecture == "x86_64"
    assert report.agent_type == "filebeat"
    assert report.agent_version == "9.3.7"
    assert report.last_report == _AGENT_LAST
    assert report.first_report == _AGENT_FIRST
    assert report.doc_count == 14024


async def test_an_address_four_agents_claim_yields_no_identity_at_all() -> None:
    """The rule the lane stands on: a contended address names nobody.

    Without it the dossier for a Docker bridge gateway would flap between four
    identities from one sweep to the next — the fingerprint-flap failure class,
    with the operator prodded about a machine swap that never happened.
    """
    es = _network_es()

    inventory_ = await _agent_inventory(es)
    report, claimants = inventory_.for_ip(_BRIDGE_IP)

    assert report is None
    assert set(claimants) == {"buildbox", "registry-a", "sensor", "workbench"}
    assert _BRIDGE_IP not in inventory_.unique_claims()


async def test_a_second_interface_in_the_bridge_range_is_still_an_identity() -> None:
    """172.16/12 is not categorically noise, so the rule cannot be about subnets."""
    es = _network_es()

    inventory_ = await _agent_inventory(es)
    report, claimants = inventory_.for_ip(_PROXY_SECOND_IP)

    assert claimants == ()
    assert report is not None and report.host_name == "edge-proxy"


async def test_link_local_addresses_never_claim_an_identity() -> None:
    """A uniquely-claimed fe80:: address is still not a machine on the network.

    Link-local scope is per-LINK: the same address can exist on two of them, so
    a single claim inside one window is not evidence of a unique holder.
    """
    es = _network_es()

    inventory_ = await _agent_inventory(es)
    report, claimants = inventory_.for_ip("fe80::5054:ff:fe12:3456")

    assert (report, claimants) == (None, ())
    assert not [ip for ip in inventory_.unique_claims() if ip.startswith("fe80")]


async def test_the_grids_own_host_names_are_all_discovered() -> None:
    es = _network_es()

    inventory_ = await _agent_inventory(es)

    assert {host.host_name for host in inventory_.hosts} == {
        "pve-a",
        "quiet-vm",
        "buildbox",
        "registry-a",
        "sensor",
        "workbench",
        "edge-proxy",
    }
    # Every machine's own primary address resolves to it, contended or not.
    assert inventory_.unique_claims()[_QUIET_IP].host_name == "quiet-vm"


async def test_no_host_log_datasets_on_the_grid_means_no_query_and_no_signal() -> None:
    """A missing dataset reads as "no signal", and costs nothing to find out.

    The dossier's dataset inventory already knows what this grid carries; when
    neither host-log dataset is on it, the lane contributes nothing and issues no
    aggregation at all.
    """
    es = _FakeES(grid_datasets=_ALL_DATASETS, agent_buckets=_NETWORK_BUCKETS)

    inventory_ = await _agent_inventory(es)

    assert inventory_.hosts == ()
    assert inventory_.claims == {}
    assert _calls(es, "agent") == []


async def test_an_unknown_dataset_inventory_still_runs_the_agent_pass() -> None:
    """An inventory outage must not retract the network's self-reported names.

    An EMPTY inventory is "unknown", not "nothing" — the same rule
    `_present_datasets` applies to the targeted identity searches.
    """
    es = _network_es(inventory_error=True)

    inventory_ = await _agent_inventory(es)

    assert len(_calls(es, "agent")) == 1
    assert inventory_.unique_claims()[_PVE_IP].host_name == "pve-a"


async def test_an_agent_inventory_failure_is_recorded_not_raised() -> None:
    es = _network_es(agent_error=True)

    inventory_ = await _agent_inventory(es)

    assert inventory_.hosts == ()
    assert any("circuit_breaking_exception" in e for e in inventory_.errors)


async def test_the_collector_threads_this_hosts_slice_into_the_observations() -> None:
    es = _network_es()
    inventory_ = await _agent_inventory(es)

    obs = await collect_host_observations(
        _PVE_IP,
        elastic=es,
        settings=_settings(),
        window_hours=336,
        agent_inventory=inventory_,
    )

    assert obs.agent_report is not None
    assert obs.agent_report.host_name == "pve-a"
    assert obs.agent_ip_claimants == ()
    # The network-wide pass is NOT re-run per host: the sweep hands the same inventory
    # to every host it builds.
    assert len(_calls(es, "agent")) == 1


async def test_a_contended_address_reaches_the_classifier_as_a_claimant_list() -> None:
    es = _network_es()
    inventory_ = await _agent_inventory(es)

    obs = await collect_host_observations(
        _BRIDGE_IP,
        elastic=es,
        settings=_settings(),
        window_hours=336,
        agent_inventory=inventory_,
    )

    assert obs.agent_report is None
    assert set(obs.agent_ip_claimants) == {"buildbox", "registry-a", "sensor", "workbench"}


async def test_without_an_inventory_the_observations_carry_no_agent_lane() -> None:
    es = _network_es()

    obs = await _collect(es)

    assert obs.agent_report is None
    assert obs.agent_ip_claimants == ()


# ---------------------------------------------------------------------------
# The DNS-name lane — consensus over the network's own answers.
# ---------------------------------------------------------------------------


def test_dns_inventory_for_ip_returns_majority_name_and_withholds_on_tie() -> None:
    """A DNS name is a claim about an address, and a tie is contention.

    The claim list is per (name, address) pair because one aggregation bucket is
    one pair; the consensus is per ADDRESS, which is what makes a name that
    leads on one host irrelevant to another.
    """
    inv = DnsNameInventory(
        claims=(
            DnsNameClaim(ip="192.168.10.202", name="pve-a", answers=214),
            DnsNameClaim(ip="192.168.10.202", name="pve-a", answers=3),
            DnsNameClaim(ip="192.168.10.50", name="ws-1", answers=40),
            DnsNameClaim(ip="192.168.10.50", name="ws-alias", answers=40),  # tie
        ),
    )

    name, evidence = inv.for_ip("192.168.10.202")

    assert name == "pve-a"
    assert "217" in evidence  # total answers
    assert inv.for_ip("192.168.10.50") == (None, "2 names tie for 192.168.10.50")
    assert inv.for_ip("192.168.10.99") == (None, "")


def test_a_claim_normalises_its_address_so_a_hand_built_inventory_matches_a_collected_one() -> None:
    """The claim is the boundary: everything past it speaks one spelling.

    ``2001:db8:0:0:0:0:0:5`` and ``2001:db8::5`` are one address. With the
    normalisation only in the collector, a claim carrying the long form could not
    even be found by its OWN key — and `consensus()` is the census entry point,
    so the host silently vanished from adoption rather than failing loudly.
    """
    inv = DnsNameInventory(
        claims=(DnsNameClaim(ip="2001:db8:0:0:0:0:0:5", name="nas.lab.internal", answers=100),),
    )

    assert inv.for_ip("2001:db8::5")[0] == "nas.lab.internal"
    assert inv.for_ip("2001:db8:0:0:0:0:0:5")[0] == "nas.lab.internal"
    assert set(inv.consensus()) == {"2001:db8::5"}


def test_a_claim_folds_its_name_so_case_variants_do_not_split_the_vote() -> None:
    """DNS is case-insensitive and resolvers randomise query case (0x20 encoding).

    Counting the spellings separately splits a host's own vote and turns its
    clear majority into a tie, so the lane goes silent on precisely its
    best-attested hosts. The fold belongs to the claim, not to the collector:
    the majority rule lives in the type and cannot depend on who built it.
    """
    inv = DnsNameInventory(
        claims=(
            DnsNameClaim(ip="192.168.10.5", name="WeB-1.lab.internal", answers=30),
            DnsNameClaim(ip="192.168.10.5", name="web-1.lab.internal.", answers=25),
            DnsNameClaim(ip="192.168.10.5", name="other.lab.internal", answers=40),
        ),
    )

    name, evidence = inv.for_ip("192.168.10.5")

    assert name == "web-1.lab.internal"
    assert "55" in evidence


def test_the_family_rule_message_counts_addresses_not_claims() -> None:
    """The rule decides on distinct ADDRESSES, so the reason has to say addresses.

    One name split across two buckets for the same address is still one address;
    counting claims would tell the reader "3 addresses" about a name on two.
    """
    inv = DnsNameInventory(
        claims=(
            DnsNameClaim(ip="192.168.10.10", name="vpn.lab.internal", answers=900),
            DnsNameClaim(ip="192.168.10.10", name="vpn.lab.internal", answers=50),
            DnsNameClaim(ip="192.168.10.11", name="vpn.lab.internal", answers=880),
        ),
    )

    assert "2 addresses" in inv.for_ip("192.168.10.10")[1]


def test_a_name_round_robining_over_two_addresses_names_neither() -> None:
    """One name over several addresses of ONE family is a service record.

    Per-address consensus does NOT cover this on its own: when the round-robin
    name is the only name either address carries, it wins both — and two hosts
    end up wearing the same hostname at strong confidence, which is worse than
    the blank the lane was built to fill. The names have to be counted per
    family before the majority is taken.
    """
    inv = DnsNameInventory(
        claims=(
            DnsNameClaim(ip="192.168.10.10", name="vpn.lab.internal", answers=900),
            DnsNameClaim(ip="192.168.10.11", name="vpn.lab.internal", answers=880),
        ),
    )

    assert inv.for_ip("192.168.10.10")[0] is None
    assert inv.for_ip("192.168.10.11")[0] is None
    # And neither becomes a census member off the back of it.
    assert inv.consensus() == {}
    # Withheld, not missing — the reason travels with the silence.
    assert "2 addresses" in inv.for_ip("192.168.10.10")[1]


def test_one_address_per_family_is_a_dual_stack_host_not_a_round_robin() -> None:
    """The counterpart the family rule exists to protect.

    An A and an AAAA record for the same name are one machine on two addresses.
    Skipping every name that answers for more than one address would blind the
    lane to every dual-stack host on the network.
    """
    inv = DnsNameInventory(
        claims=(
            DnsNameClaim(ip="192.168.10.70", name="nas.lab.internal", answers=340),
            DnsNameClaim(ip="2001:db8:10::5", name="nas.lab.internal", answers=128),
        ),
    )

    assert inv.for_ip("192.168.10.70")[0] == "nas.lab.internal"
    assert inv.for_ip("2001:db8:10::5")[0] == "nas.lab.internal"


def test_the_family_rule_is_applied_per_family_not_to_the_whole_name() -> None:
    """Two A records and one AAAA: only the crowded family loses its claims.

    The single v6 address IS that name's address, one-for-one, and there is
    nothing ambiguous about naming it — the ambiguity is entirely on the v4
    side, and it should not spread.
    """
    inv = DnsNameInventory(
        claims=(
            DnsNameClaim(ip="192.168.10.10", name="vpn.lab.internal", answers=900),
            DnsNameClaim(ip="192.168.10.11", name="vpn.lab.internal", answers=880),
            DnsNameClaim(ip="2001:db8:10::9", name="vpn.lab.internal", answers=210),
        ),
    )

    assert inv.for_ip("192.168.10.10")[0] is None
    assert inv.for_ip("192.168.10.11")[0] is None
    assert inv.for_ip("2001:db8:10::9")[0] == "vpn.lab.internal"


def test_a_round_robin_name_loses_to_a_real_name_on_the_same_address() -> None:
    """Dropping the spread name must not drop the address with it.

    A VIP parked on a host that DNS also knows by its own name is common, and
    the host's own name is the answer — the spread name simply stops competing.
    """
    inv = DnsNameInventory(
        claims=(
            DnsNameClaim(ip="192.168.10.10", name="vpn.lab.internal", answers=900),
            DnsNameClaim(ip="192.168.10.11", name="vpn.lab.internal", answers=880),
            DnsNameClaim(ip="192.168.10.10", name="app-1.lab.internal", answers=12),
        ),
    )

    assert inv.for_ip("192.168.10.10")[0] == "app-1.lab.internal"
    assert inv.for_ip("192.168.10.11")[0] is None


def test_consensus_over_a_mixed_claim_set_matches_the_per_address_semantics() -> None:
    """One pass over the address index yields exactly the per-address answers.

    ``consensus()`` walks the ``_by_ip`` index built in ``__post_init__`` — the
    linear path that replaced the full claim scan per address — and it is the
    census's entry point, so a divergence here is a host silently gaining or
    losing its name at adoption time. This pins the indexed path against one
    mixed set exercising every rule at once: a split bucket that merges, a
    majority over a minority, a clean tie, a round-robin VIP, a VIP parked
    beside a real name, and a dual-stack host.
    """
    early = datetime(2019, 3, 2, 9, 0, tzinfo=UTC)
    late = datetime(2019, 3, 14, 18, 30, tzinfo=UTC)
    claims = (
        # Split bucket + majority: pve-a merges 214+3 (case fold included)
        # and beats pve-b's 100.
        DnsNameClaim(
            ip="192.168.10.202",
            name="pve-a.lab.internal",
            answers=214,
            first_answer=early,
            last_answer=early,
        ),
        DnsNameClaim(
            ip="192.168.10.202",
            name="PVE-A.lab.internal.",
            answers=3,
            first_answer=late,
            last_answer=late,
        ),
        DnsNameClaim(ip="192.168.10.202", name="pve-b.lab.internal", answers=100),
        # A clean tie: withheld, so absent from the consensus.
        DnsNameClaim(ip="192.168.10.50", name="ws-1.lab.internal", answers=40),
        DnsNameClaim(ip="192.168.10.50", name="ws-alias.lab.internal", answers=40),
        # Round-robin VIP over two v4 addresses names neither of them...
        DnsNameClaim(ip="192.168.10.10", name="vpn.lab.internal", answers=900),
        DnsNameClaim(ip="192.168.10.11", name="vpn.lab.internal", answers=880),
        # ...but the address DNS also knows by a real name keeps that name.
        DnsNameClaim(ip="192.168.10.10", name="app-1.lab.internal", answers=12),
        # Dual-stack: one name, one address per family — both keep it.
        DnsNameClaim(ip="192.168.10.70", name="nas.lab.internal", answers=340),
        DnsNameClaim(ip="2001:db8:10::5", name="nas.lab.internal", answers=128),
    )
    inv = DnsNameInventory(claims=claims)

    winners = inv.consensus()

    assert {ip: (claim.name, claim.answers) for ip, claim in winners.items()} == {
        "192.168.10.202": ("pve-a.lab.internal", 217),
        "192.168.10.10": ("app-1.lab.internal", 12),
        "192.168.10.70": ("nas.lab.internal", 340),
        "2001:db8:10::5": ("nas.lab.internal", 128),
    }
    # The merged claim's span widens to cover both buckets.
    merged = winners["192.168.10.202"]
    assert (merged.first_answer, merged.last_answer) == (early, late)
    # And the one-pass answer agrees with the per-address answer everywhere.
    for ip in {claim.ip for claim in claims}:
        winner = winners.get(ip)
        assert inv.resolve(ip).name == (winner.name if winner is not None else None)


# The query-name buckets as the aggregation returns them, read off the live grid on
# 2026-08-08 with the names and addresses substituted: `zeek.dns` carried
# ~38,000 answer documents every 6 hours there, and 553 distinct names resolved
# INTO the internal ranges over a 14-day window — against 13 machines running a
# log agent. DNS is where the rest of the network's names are.
#
# Three of the shapes below are why the rules are the rules:
#
# * `_PVE_IP` answers to THREE names — one box fronting three services — so
#   "the name for this address" is a majority question, not a lookup.
# * `_DUAL_STACK_NAME` answers for an IPv4 AND an IPv6 address: one machine on
#   two addresses, which must keep its name on both.
# * `_VIP_NAME` answers for two IPv4 addresses. A per-address majority alone
#   would hand BOTH hosts that one name — it is the only name either carries, so
#   it wins both uncontested — which is why the names are counted per address
#   family before the majority is taken.
_GATEWAY_IP = "192.168.10.1"
_PRINTER_IP = "192.168.10.61"
_DUAL_STACK_V6 = "2001:db8:10::5"
_DUAL_STACK_NAME = "nas.lab.internal"
_VIP_NAME = "vpn.lab.internal"
_VIP_A = "192.168.10.10"
_VIP_B = "192.168.10.11"


def _dns_bucket(
    name: str, answers: dict[str, int], *, last: datetime = _AGENT_LAST, other: int = 0
) -> dict[str, Any]:
    """One query-name bucket: the answer addresses it resolved to, and how often."""
    return {
        "key": name,
        "doc_count": sum(answers.values()),
        "ips": {
            "sum_other_doc_count": other,
            "buckets": [
                {
                    "key": ip,
                    "doc_count": count,
                    "first_answer": {
                        "value": float(_ms(_AGENT_FIRST)),
                        "value_as_string": _AGENT_FIRST.isoformat(),
                    },
                    "last_answer": {
                        "value": float(_ms(last)),
                        "value_as_string": last.isoformat(),
                    },
                }
                for ip, count in answers.items()
            ],
        },
    }


_DNS_BUCKETS: list[dict[str, Any]] = [
    _dns_bucket("pve-a.lab.internal", {_PVE_IP: 214}),
    _dns_bucket("backup.lab.internal", {_PVE_IP: 96}),
    _dns_bucket("console.lab.internal", {_PVE_IP: 71}),
    _dns_bucket("gw.lab.internal", {_GATEWAY_IP: 7636}),
    # The quiet machine the network census cannot see, named 12 times all window.
    _dns_bucket("printer-1.lab.internal", {_PRINTER_IP: 12}),
    _dns_bucket(_DUAL_STACK_NAME, {"192.168.10.70": 340, _DUAL_STACK_V6: 128}),
    _dns_bucket(_VIP_NAME, {_VIP_A: 900, _VIP_B: 880}),
    # Public answers dwarf the internal ones on a real grid; none of them may
    # name anything, however many times they were resolved.
    _dns_bucket("cdn.example.net", {"8.8.8.8": 9001, "203.0.113.20": 4400}),
]

_CIDRS = [ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("2001:db8::/32")]


async def _dns_names(es: Any, *, window_hours: int = 336, cidrs: Any = None) -> DnsNameInventory:
    return await collect_dns_names(
        elastic=es,
        settings=_settings(),
        window_hours=window_hours,
        cidrs=_CIDRS if cidrs is None else cidrs,
    )


def _dns_es(**overrides: Any) -> _FakeES:
    kwargs: dict[str, Any] = {"grid_datasets": _ALL_DATASETS, "dns_buckets": _DNS_BUCKETS}
    kwargs.update(overrides)
    return _FakeES(**kwargs)


async def test_collect_dns_names_builds_consensus_over_internal_answers() -> None:
    """The majority name per address, and nothing at all for a public one."""
    es = _dns_es()

    inv = await _dns_names(es)

    assert inv.for_ip(_PVE_IP)[0] == "pve-a.lab.internal"
    assert "214" in inv.for_ip(_PVE_IP)[1]
    assert inv.for_ip(_GATEWAY_IP)[0] == "gw.lab.internal"
    assert inv.for_ip(_PRINTER_IP)[0] == "printer-1.lab.internal"
    # A public answer target is never named, whatever its volume.
    assert inv.for_ip("8.8.8.8") == (None, "")
    assert inv.for_ip("203.0.113.20") == (None, "")
    assert inv.errors == ()


async def test_a_name_answering_for_two_addresses_names_both_of_them() -> None:
    """One machine, an A and an AAAA record: one address per family, so both keep it.

    A rule that discarded every name resolving to several addresses would drop
    every dual-stack host on the network — and both of these addresses genuinely
    are that host.
    """
    es = _dns_es()

    inv = await _dns_names(es)

    assert inv.for_ip("192.168.10.70")[0] == _DUAL_STACK_NAME
    assert inv.for_ip(_DUAL_STACK_V6)[0] == _DUAL_STACK_NAME


async def test_a_round_robin_vip_names_neither_of_its_addresses() -> None:
    """The collector keeps the spread claims; the family rule is what withholds.

    Two hosts wearing one hostname at strong confidence is worse than the blank
    this lane was built to fill, and the census must not adopt either address on
    the strength of a name that belongs to a service.
    """
    es = _dns_es()

    inv = await _dns_names(es)

    assert inv.for_ip(_VIP_A)[0] is None
    assert inv.for_ip(_VIP_B)[0] is None
    assert _VIP_A not in inv.consensus()
    assert _VIP_B not in inv.consensus()
    # The raw claims survive the collection — the rule lives in the inventory, so
    # a hand-built one behaves identically to a collected one.
    assert {claim.ip for claim in inv.claims if claim.name == _VIP_NAME} == {_VIP_A, _VIP_B}


async def test_the_dns_pass_is_one_size_zero_aggregation_over_the_dns_dataset() -> None:
    """One round trip for the whole network, and it pulls no documents.

    Per-host it would be an extra aggregation per address for an answer that is
    identical for all of them — the same cost model as the agent inventory.
    """
    es = _dns_es()

    await _dns_names(es)

    dns = _calls(es, "dns")
    assert len(dns) == 1, "the DNS name pass is one round trip for the network"
    call = dns[0]
    assert call["size"] == 0
    assert call["index"] == _INDEX
    names = call["aggs"]["names"]
    assert names["terms"]["field"] == "dns.query.name"
    assert names["aggs"]["ips"]["terms"]["field"] == "dns.resolved_ip"
    datasets = [c for c in call["query"]["bool"]["filter"] if "terms" in c]
    assert {"event.dataset": ["zeek.dns"]} in [c["terms"] for c in datasets]
    assert call["query"]["bool"]["must_not"] == [{"exists": {"field": "synth.scenario_id"}}]


async def test_the_dns_pass_narrows_to_internal_answers_when_the_field_allows_it() -> None:
    """`dns.resolved_ip` is ECS-typed `ip`, so the CIDRs are a matchable term.

    Without this the aggregation buckets every name the network resolved — 4,221
    of them over 14 days on the grid this was measured against, against 553 that
    point inside — and terms fall off the end of `size` by DOC COUNT, so the ones
    dropped are the least-queried names. That is the quiet printer, which is
    exactly the host this lane exists to name.
    """
    es = _dns_es()

    await _dns_names(es)

    clauses = _calls(es, "dns")[0]["query"]["bool"]["filter"]
    assert {"terms": {"dns.resolved_ip": ["192.168.0.0/16", "2001:db8::/32"]}} in clauses


async def test_a_legacy_answer_field_is_not_narrowed_by_cidr() -> None:
    """`zeek.dns.answers` is a KEYWORD of raw answer strings.

    A CIDR term against it matches nothing at all, silently — the whole network's
    names would vanish and look like a grid with no DNS. So that grid gets the
    wide pass, and the internal gate does its whole job client-side.
    """
    es = _dns_es(populated=_LEGACY_POPULATED)

    inv = await _dns_names(es)

    call = _calls(es, "dns")[0]
    assert call["aggs"]["names"]["aggs"]["ips"]["terms"]["field"] == "zeek.dns.answers"
    assert {"exists": {"field": "zeek.dns.answers"}} in call["query"]["bool"]["filter"]
    assert inv.for_ip(_PVE_IP)[0] == "pve-a.lab.internal"
    assert inv.for_ip("8.8.8.8") == (None, "")


async def test_no_dns_dataset_on_the_grid_means_no_query_and_no_signal() -> None:
    """A missing dataset reads as "no signal", and costs nothing to find out."""
    es = _dns_es(grid_datasets=("zeek.conn", "zeek.http"))

    inv = await _dns_names(es)

    assert inv.claims == ()
    assert _calls(es, "dns") == []


async def test_without_internal_cidrs_the_dns_pass_does_not_run() -> None:
    """ "Internal" is the operator's definition; without one there is nothing to scope.

    A name lane scoped to the whole internet would write CDN edge names into
    asset records — the sweep abandons for the same reason.
    """
    es = _dns_es()

    inv = await _dns_names(es, cidrs=[])

    assert inv.claims == ()
    assert _calls(es, "dns") == []


async def test_a_dns_pass_failure_is_recorded_not_raised() -> None:
    es = _dns_es(dns_error=True)

    inv = await _dns_names(es)

    assert inv.claims == ()
    assert any("circuit_breaking_exception" in detail for detail in inv.errors)


async def test_a_truncated_name_agg_says_so_instead_of_dropping_names_quietly() -> None:
    """`sum_other_doc_count` is the only signal that terms fell off `size`.

    A short answer is indistinguishable from a host DNS never named, so the cap
    has to be something the operator can see on the run row.
    """
    es = _dns_es(dns_other=41_000)

    inv = await _dns_names(es)

    assert inv.for_ip(_PVE_IP)[0] == "pve-a.lab.internal"
    # A truncation is a NOTE, not a failure: it lands in `notes`, and `errors`
    # stays empty so a healthy-but-capped pass never inflates the error count.
    assert inv.errors == ()
    detail = next(d for d in inv.notes if "truncated" in d)
    assert "41000" in detail
    # The narrowed pass only ever bucketed internal answers, so what fell off the
    # end really was internal and the note can say so.
    assert "least-queried" in detail
    assert "impact unknown" not in detail


async def test_the_wide_pass_does_not_claim_an_internal_impact_it_cannot_see() -> None:
    """On the legacy field the cap counts PUBLIC names too, so it overflows always.

    4,221 names against a 2,000 cap on the grid this was measured against — the
    note would fire every single sweep whether or not one internal name was lost,
    and a run-row warning that is always on stops being read. The wide pass says
    what it actually knows instead.
    """
    es = _dns_es(populated=_LEGACY_POPULATED, dns_other=41_000)

    inv = await _dns_names(es)

    assert inv.errors == ()
    detail = next(d for d in inv.notes if "truncated" in d)
    assert "ran wide" in detail
    assert "impact unknown" in detail
    assert "41000" in detail
    # It is a caveat on a working pass, not a failure: the names that DID fit are
    # still claimed.
    assert inv.for_ip(_PVE_IP)[0] == "pve-a.lab.internal"


async def test_a_truncated_answer_agg_says_so_too() -> None:
    """The INNER cap can hide an address just as silently as the outer one.

    On the legacy answer field the pass cannot be narrowed to internal answers
    server-side, so a name whose public answers fill the top buckets pushes its
    internal one out of the result entirely — and the host it would have named
    simply never appears.
    """
    # Truncation on ONE name among several: the note sums across name buckets,
    # so a per-bucket signal is what proves it is not just reading the first.
    es = _dns_es(
        dns_buckets=[
            _dns_bucket("crowded.lab.internal", {_PRINTER_IP: 12}, other=615),
            _dns_bucket("roomy.lab.internal", {_GATEWAY_IP: 40}),
        ]
    )

    inv = await _dns_names(es)

    assert inv.errors == ()
    assert any("addresses per name" in detail and "615" in detail for detail in inv.notes)
    # The addresses that DID come back are still claimed: a truncated inner agg
    # is a short answer, not a failed one.
    assert inv.for_ip(_PRINTER_IP)[0] == "crowded.lab.internal"
    assert inv.for_ip(_GATEWAY_IP)[0] == "roomy.lab.internal"


async def test_a_dropped_answer_count_survives_a_bucket_with_no_usable_name() -> None:
    """A bucket this collector cannot use still lost addresses off its inner agg.

    Tallying after the name check silently drops that count, which is how "both
    caps have to account for it" stops being true without any test noticing.
    """
    es = _dns_es(
        dns_buckets=[
            _dns_bucket("", {_PRINTER_IP: 5}, other=77),
            _dns_bucket("ok.lab.internal", {_GATEWAY_IP: 40}),
        ]
    )

    inv = await _dns_names(es)

    assert inv.errors == ()
    assert any("addresses per name" in detail and "77" in detail for detail in inv.notes)
    assert inv.for_ip(_GATEWAY_IP)[0] == "ok.lab.internal"


async def test_the_collector_threads_this_addresss_dns_name_into_the_observations() -> None:
    es = _dns_es(main_aggs=_MAIN_AGGS, main_total=3412)
    inv = await _dns_names(es)

    obs = await collect_host_observations(
        _PVE_IP,
        elastic=es,
        settings=_settings(),
        window_hours=336,
        dns_names=inv,
    )

    assert obs.dns_name == "pve-a.lab.internal"
    assert "214" in obs.dns_name_evidence
    assert obs.dns_name_observed_at == _AGENT_LAST
    # The network-wide pass is NOT re-run per host: the sweep hands the same inventory
    # to every host it builds.
    assert len(_calls(es, "dns")) == 1


async def test_an_address_whose_dns_names_tie_reaches_the_classifier_unnamed() -> None:
    """Withheld, and the reason travels with the silence.

    Two names equally attested is contention, not a coin flip — the classifier
    must see no name at all rather than whichever bucket happened to sort first.
    """
    es = _dns_es(
        main_aggs=_MAIN_AGGS,
        main_total=3412,
        dns_buckets=[
            _dns_bucket("a.lab.internal", {_PRINTER_IP: 30}),
            _dns_bucket("b.lab.internal", {_PRINTER_IP: 30}),
        ],
    )
    inv = await _dns_names(es)

    obs = await collect_host_observations(
        _PRINTER_IP,
        elastic=es,
        settings=_settings(),
        window_hours=336,
        dns_names=inv,
    )

    assert obs.dns_name is None
    assert obs.dns_name_evidence == "", "there is no name, so nothing was attested"
    assert "2 names tie" in obs.dns_name_withheld


async def test_without_an_inventory_the_observations_carry_no_dns_name() -> None:
    es = _dns_es(main_aggs=_MAIN_AGGS, main_total=3412)

    obs = await _collect(es)

    assert obs.dns_name is None
    assert obs.dns_name_evidence == ""
    assert obs.dns_name_withheld == ""
    assert obs.dns_name_observed_at is None
