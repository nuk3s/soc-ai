"""The profile lane: building a model of normal from the grid's own history.

The test that matters most here is plane selection. On the measured range,
``zeek.conn`` held 885,000 documents for two weeks that carried no
``destination.ip`` at all — Zeek was writing TSV into a pipeline that parses
JSON with failures ignored. A builder that picks its flow plane by document
count, or by dataset name, builds every profile on this grid out of nothing and
reports the result as measured.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from soc_ai.dossier.profile import (
    EPHEMERAL_PORT_FLOOR,
    FLOW_CANDIDATES,
    collect_entity_profiles,
    resolve_plane,
)
from soc_ai.so_client.elastic import EsSearchResult

pytestmark = pytest.mark.asyncio

_INDEX = "logs-*"
_ANCHOR = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)

# A flow plane that carries every field the flow dimensions probe. Ports matter
# as much as addresses: served_ports and consumed_ports probe destination.port,
# and a fixture that only declares the addresses sends both dimensions blind.
_FLOW_FIELDS = {"destination.ip": 100, "source.ip": 100, "destination.port": 100}
_FLOW_OK = {"network_traffic.flow": _FLOW_FIELDS}


def _settings() -> Any:
    class _S:
        events_index_pattern = _INDEX
        so_timezone = "UTC"

    return _S()


def _result(*, total: int = 0, aggregations: dict[str, Any] | None = None) -> EsSearchResult:
    return EsSearchResult(
        total=total,
        took_ms=1,
        hits=[],
        aggregations=aggregations,
        total_is_lower_bound=False,
    )


class _FakeES:
    """Routes on request shape, like tests/test_dossier_observe.py's fake.

    ``field_presence`` maps dataset -> {field: doc_count}, which is what the
    plane probe reads. ``agg_payloads`` maps an agg key to a canned response.
    """

    def __init__(
        self,
        *,
        field_presence: dict[str, dict[str, int]] | None = None,
        agg_payloads: dict[str, dict[str, Any]] | None = None,
        error_on: str | None = None,
    ) -> None:
        self.field_presence = field_presence or {}
        self.agg_payloads = agg_payloads or {}
        self.error_on = error_on
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
        self.calls.append({"index": index, "query": query, "aggs": aggs, "size": size})
        keys = set(aggs or {})

        if self.error_on and self.error_on in keys:
            raise RuntimeError("elasticsearch said no")

        # The plane probe: one filters agg, one bucket per (dataset, field).
        if "plane_probe" in keys:
            buckets = {}
            probe = (aggs or {})["plane_probe"]["filters"]["filters"]
            for key in probe:
                dataset, _, field = key.partition("|")
                buckets[key] = {"doc_count": self.field_presence.get(dataset, {}).get(field, 0)}
            return _result(aggregations={"plane_probe": {"buckets": buckets}})

        for key in keys:
            if key in self.agg_payloads:
                return _result(aggregations={key: self.agg_payloads[key]})

        return _result(aggregations={})


def _entity_bucket(
    key: str, members: list[tuple[str, int, str, str]], *, days: int = 30
) -> dict[str, Any]:
    """One entity bucket: members with count and first/last, days at the top.

    ``active_days`` sits on the ENTITY, matching the aggregation: support is a
    property of the entity's own history, not of each member of it.
    """
    return {
        "key": key,
        "doc_count": sum(m[1] for m in members),
        "active_days": {
            "buckets": [
                {"key_as_string": f"2026-08-{d:02d}", "doc_count": 1} for d in range(1, days + 1)
            ]
        },
        "members": {
            "buckets": [
                {
                    "key": name,
                    "doc_count": count,
                    "first": {"value_as_string": first},
                    "last": {"value_as_string": last},
                }
                for name, count, first, last in members
            ]
        },
    }


# ---------------------------------------------------------------------------
# Plane resolution — the lesson the range taught
# ---------------------------------------------------------------------------


async def test_a_plane_with_documents_but_no_usable_field_is_not_selected() -> None:
    # zeek.conn: 885,000 documents, none of them carrying destination.ip.
    # network_traffic.flow: fewer documents, all of them usable.
    es = _FakeES(
        field_presence={
            "zeek.conn": {"destination.ip": 0},
            "network_traffic.flow": {"destination.ip": 3_798_780},
        }
    )
    planes = await resolve_plane(
        es, _settings(), candidates=FLOW_CANDIDATES, field="destination.ip", minutes=60
    )
    assert "zeek.conn" not in planes
    assert "network_traffic.flow" in planes


async def test_a_plane_is_selected_on_field_presence_not_document_count() -> None:
    # Same shape, but the empty plane is the larger one. Selecting by volume
    # picks the plane that can answer nothing.
    es = _FakeES(
        field_presence={
            "zeek.conn": {"destination.ip": 0},
            "network_traffic.flow": {"destination.ip": 12},
        }
    )
    planes = await resolve_plane(
        es, _settings(), candidates=FLOW_CANDIDATES, field="destination.ip", minutes=60
    )
    assert planes == ("network_traffic.flow",)


async def test_every_usable_plane_is_returned_not_just_the_first() -> None:
    # Once Zeek is healthy both planes carry the field, and a membership seen
    # only by one sensor is still a membership.
    es = _FakeES(
        field_presence={
            "zeek.conn": {"destination.ip": 500},
            "network_traffic.flow": {"destination.ip": 900},
        }
    )
    planes = await resolve_plane(
        es, _settings(), candidates=FLOW_CANDIDATES, field="destination.ip", minutes=60
    )
    assert set(planes) == {"zeek.conn", "network_traffic.flow"}


async def test_no_usable_plane_returns_empty_rather_than_every_candidate() -> None:
    # Fail-CLOSED here, unlike _present_datasets. Searching every candidate
    # when none can answer produces an empty result that reads as "measured,
    # nothing there" — the false all-clear this whole layer exists to avoid.
    es = _FakeES(field_presence={"zeek.conn": {"destination.ip": 0}})
    planes = await resolve_plane(
        es, _settings(), candidates=FLOW_CANDIDATES, field="destination.ip", minutes=60
    )
    assert planes == ()


async def test_a_probe_failure_is_unknown_not_empty() -> None:
    # None, not (). Collapsing the two made a grid outage render as "no plane
    # on this grid carries destination.ip", which an operator reads as a fact
    # about their estate rather than as a broken query. A dead grid must never
    # be reportable as a quiet network.
    es = _FakeES(error_on="plane_probe")
    planes = await resolve_plane(
        es, _settings(), candidates=FLOW_CANDIDATES, field="destination.ip", minutes=60
    )
    assert planes is None


async def test_a_probe_failure_produces_an_error_not_a_blind_row() -> None:
    # A blind row claims "we looked and could not see". A failed probe means
    # we never looked, and the sweep has to say which of those happened.
    es = _FakeES(error_on="plane_probe")
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    assert sweep.errors
    assert all(p.coverage != "blind" for p in sweep.profiles)


# ---------------------------------------------------------------------------
# Building profiles
# ---------------------------------------------------------------------------


async def test_both_endpoints_of_a_connection_are_updated() -> None:
    # A switch never initiates anything, so a source-keyed sweep alone gives it
    # no history at all and every port it serves reads as novel forever.
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "served_ports": {
                "buckets": [
                    _entity_bucket(
                        "10.1.10.254",
                        [("22", 40, "2026-08-20T00:00:00Z", "2026-09-14T00:00:00Z")],
                    )
                ]
            },
            "consumed_ports": {
                "buckets": [
                    _entity_bucket(
                        "10.1.10.21",
                        [("443", 90, "2026-08-20T00:00:00Z", "2026-09-14T00:00:00Z")],
                    )
                ]
            },
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    by_key = {(p.entity_key, p.dimension): p for p in sweep.profiles}
    assert ("10.1.10.254", "served_ports") in by_key
    assert ("10.1.10.21", "consumed_ports") in by_key
    assert by_key[("10.1.10.254", "served_ports")].vector["22"]["count"] == 40


async def test_a_membership_carries_first_seen_last_seen_and_count() -> None:
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "peers_out": {
                "buckets": [
                    _entity_bucket(
                        "10.1.10.21",
                        [("140.82.121.4", 7, "2026-09-01T10:00:00Z", "2026-09-14T19:00:00Z")],
                    )
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    peers = next(p for p in sweep.profiles if p.dimension == "peers_out")
    member = peers.vector["140.82.121.4"]
    assert member["count"] == 7
    assert member["first_seen"].startswith("2026-09-01")
    assert member["last_seen"].startswith("2026-09-14")


async def test_a_dimension_with_no_usable_plane_reads_blind_not_empty() -> None:
    # THE distinction the coverage column exists for. A host that ships no
    # process telemetry has no unusual processes in exactly the way a quiet
    # host does, and only one of those is a finding.
    es = _FakeES(
        field_presence={
            "network_traffic.flow": _FLOW_FIELDS,
            "endpoint.events.process": {"process.name": 0},
        },
        agg_payloads={
            "peers_out": {
                "buckets": [
                    _entity_bucket(
                        "10.1.10.21",
                        [("1.1.1.1", 3, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z")],
                    )
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    process = [p for p in sweep.profiles if p.dimension == "process_names"]
    assert process, "a blind dimension must still produce a row"
    assert all(p.coverage == "blind" for p in process)
    assert all(p.vector is None for p in process)


async def test_below_the_support_floor_reads_learning() -> None:
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "peers_out": {
                "buckets": [
                    _entity_bucket(
                        "10.1.10.99",
                        [("1.1.1.1", 3, "2026-09-14T00:00:00Z", "2026-09-15T00:00:00Z")],
                        days=2,
                    )
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    peers = next(p for p in sweep.profiles if p.dimension == "peers_out")
    assert peers.coverage == "learning"
    assert peers.support_days == 2


async def test_the_lane_never_raises_and_reports_its_errors() -> None:
    # House rule for every dossier lane: a failure is a note on the sweep, not
    # an exception that takes the whole build down.
    es = _FakeES(
        field_presence=_FLOW_OK,
        error_on="peers_out",
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    assert sweep.errors
    assert any("peers_out" in e for e in sweep.errors)


async def test_the_planes_it_chose_are_reported_for_the_run_summary() -> None:
    # An operator has to be able to see WHY a dimension is blind, and "no plane
    # on this grid carries destination.ip" is a different problem from "the
    # host is quiet".
    es = _FakeES(
        field_presence={
            "zeek.conn": {"destination.ip": 0},
            "network_traffic.flow": _FLOW_FIELDS,
        }
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    assert sweep.planes.get("flow") == ("network_traffic.flow",)


async def test_support_days_are_days_not_distinct_timestamps() -> None:
    # Found by running the lane against the live range: a host reported
    # support=98517d over a 30-day window. `cardinality` on @timestamp counts
    # distinct millisecond values, not distinct days, so the support floor was
    # being cleared by volume rather than by persistence -- a host that made a
    # thousand connections in one afternoon read as a thousand days of history.
    #
    # Support is an ENTITY-level property ("7 days of the entity's own data"),
    # so it is measured once per entity with a daily date_histogram, not once
    # per member.
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "peers_out": {
                "buckets": [
                    {
                        "key": "10.1.10.21",
                        "doc_count": 50_000,
                        # Three daily buckets: three days of support, whatever
                        # the document count inside them.
                        "active_days": {
                            "buckets": [
                                {"key_as_string": "2026-09-12", "doc_count": 20_000},
                                {"key_as_string": "2026-09-13", "doc_count": 20_000},
                                {"key_as_string": "2026-09-14", "doc_count": 10_000},
                            ]
                        },
                        "members": {
                            "buckets": [
                                {
                                    "key": "1.1.1.1",
                                    "doc_count": 50_000,
                                    "first": {"value_as_string": "2026-09-12T00:00:00Z"},
                                    "last": {"value_as_string": "2026-09-14T00:00:00Z"},
                                }
                            ]
                        },
                    }
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    peers = next(p for p in sweep.profiles if p.dimension == "peers_out")
    assert peers.support_days == 3, "three daily buckets is three days, not 50,000"
    assert peers.coverage == "learning", "three days is below the seven-day floor"


async def test_support_days_cannot_exceed_the_window() -> None:
    # A belt-and-braces bound on the same defect: whatever the aggregation
    # returns, an entity cannot have more days of history than the window holds.
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "peers_out": {
                "buckets": [
                    {
                        "key": "10.1.10.21",
                        "doc_count": 1,
                        "active_days": {
                            "buckets": [
                                {"key_as_string": f"2026-{m:02d}-{d:02d}", "doc_count": 1}
                                for m in (7, 8, 9)
                                for d in range(1, 29)
                            ]
                        },
                        "members": {
                            "buckets": [
                                {
                                    "key": "1.1.1.1",
                                    "doc_count": 1,
                                    "first": {"value_as_string": "2026-07-01T00:00:00Z"},
                                    "last": {"value_as_string": "2026-09-14T00:00:00Z"},
                                }
                            ]
                        },
                    }
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    peers = next(p for p in sweep.profiles if p.dimension == "peers_out")
    assert peers.support_days <= 30


async def test_the_baseline_excludes_the_recent_window_it_is_compared_against() -> None:
    """A baseline that contains the present cannot be departed from.

    Found on the range: the profile was built over now-30d, the prior sweep
    read the last 24h, and 30 days INCLUDES those 24 hours. Every member the
    sweep observed was therefore already in the baseline built from it, and
    novel_for was structurally incapable of firing -- 656 evaluations, zero
    findings, no bug visible anywhere.

    The baseline window must END where the recent window BEGINS, which is the
    same shape soc_ai.tools.analytics._first_seen_windows already uses.
    """
    es = _FakeES(field_presence=_FLOW_OK)
    await collect_entity_profiles(
        elastic=es,
        settings=_settings(),
        window_hours=24 * 30,
        lag_hours=24,
        time_anchor=_ANCHOR,
    )

    ranges = [
        clause["range"]["@timestamp"]
        for call in es.calls
        for clause in call["query"].get("bool", {}).get("filter", [])
        if "range" in clause and "@timestamp" in clause["range"]
    ]
    assert ranges, "the lane made no windowed read"
    for window in ranges:
        assert "lte" in window, f"baseline window has no upper bound: {window}"
        # The upper bound must be the lag, not the anchor: an upper bound of
        # "now" is the defect restated.
        assert "-24h" in str(window["lte"]) or "-1440m" in str(window["lte"]), (
            f"baseline window still runs up to the present: {window}"
        )


async def test_no_lag_leaves_the_window_flush_for_callers_that_want_it() -> None:
    # The host page renders a profile of what a machine does, including today.
    # Only the novelty comparison needs the gap, so the lag is a parameter
    # rather than a constant baked into the lane.
    es = _FakeES(field_presence=_FLOW_OK)
    await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    ranges = [
        clause["range"]["@timestamp"]
        for call in es.calls
        for clause in call["query"].get("bool", {}).get("filter", [])
        if "range" in clause and "@timestamp" in clause["range"]
    ]
    assert all(str(w.get("lte", "")).endswith(_ANCHOR.isoformat()) for w in ranges)


async def test_ephemeral_ports_are_excluded_from_port_dimensions() -> None:
    """A randomly assigned port is novel by construction and means nothing.

    The first live run of the prior sweep produced exactly four findings, and
    all four were ephemeral ports: 58348, 60292, 60474, 49669. Those are the
    far end of dynamically negotiated channels -- RPC, NFS, passive FTP -- and
    a new one appears on every connection. Including them in a novelty baseline
    is an unbounded false-positive generator, which is the one failure mode
    this layer was not allowed to have.

    The signal for dynamic-port abuse is the endpoint mapper plus the operation,
    never the port number, so nothing is lost by dropping them.
    """
    es = _FakeES(field_presence=_FLOW_OK)
    await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )

    port_calls = [c for c in es.calls if set(c["aggs"] or {}) & {"served_ports", "consumed_ports"}]
    assert port_calls, "no port aggregation was issued"
    for call in port_calls:
        filters = call["query"]["bool"]["filter"]
        ranges = [
            f["range"]["destination.port"]
            for f in filters
            if "range" in f and "destination.port" in f["range"]
        ]
        assert ranges, f"port aggregation has no ephemeral bound: {filters}"
        assert ranges[0]["lt"] == EPHEMERAL_PORT_FLOOR


def _keeps_flow(call: dict[str, Any], *, dest_ip: str, dest_port: int) -> bool:
    """Whether one flow document survives the clauses this call carries.

    Reads the two clauses the outbound-port dimension relies on: the range
    bound on the port, and the estate exclusion on the destination address.
    """
    import ipaddress

    bools = call["query"]["bool"]
    for clause in bools.get("filter", []):
        bound = (clause.get("range") or {}).get("destination.port")
        if bound and dest_port >= int(bound["lt"]):
            return False
    for clause in bools.get("must_not", []):
        nets = (clause.get("terms") or {}).get("destination.ip")
        if not nets:
            continue
        addr = ipaddress.ip_address(dest_ip)
        if any(addr in ipaddress.ip_network(n) for n in nets):
            return False
    return True


async def test_the_outbound_port_dimension_counts_only_what_leaves_the_estate() -> None:
    """The analytic says "connects to the internet". The dimension did not.

    consumed_ports took every destination port on every flow, so the range's
    first lead was 9 ports to internal hosts, all of them the far end of a
    dynamically negotiated channel. A server talking to its own domain
    controller on a fresh RPC port is not a server reaching the internet.
    """
    import ipaddress

    es = _FakeES(field_presence=_FLOW_OK)
    await collect_entity_profiles(
        elastic=es,
        settings=_settings(),
        window_hours=24 * 30,
        time_anchor=_ANCHOR,
        cidrs=[ipaddress.ip_network("10.1.0.0/16")],
    )
    calls = [c for c in es.calls if "consumed_ports" in set(c["aggs"] or {})]
    assert calls, "no outbound port aggregation was issued"
    call = calls[0]
    # An internal destination on a dynamically assigned port: both reasons to
    # drop it, and the range's first lead was 9 of these.
    assert not _keeps_flow(call, dest_ip="10.1.10.9", dest_port=47948)
    # An outside destination on a port a server has no business using.
    assert _keeps_flow(call, dest_ip="203.0.113.9", dest_port=8220)
    # An outside destination on a dynamic port stays out: the port number
    # carries nothing, whichever way the flow went.
    assert not _keeps_flow(call, dest_ip="203.0.113.9", dest_port=51000)


async def test_the_served_port_dimension_still_counts_internal_traffic() -> None:
    # A server SERVES the estate. Dropping internal destinations there would
    # empty the dimension, because the destination is the server itself.
    import ipaddress

    es = _FakeES(field_presence=_FLOW_OK)
    await collect_entity_profiles(
        elastic=es,
        settings=_settings(),
        window_hours=24 * 30,
        time_anchor=_ANCHOR,
        cidrs=[ipaddress.ip_network("10.1.0.0/16")],
    )
    for call in es.calls:
        if "served_ports" not in set(call["aggs"] or {}):
            continue
        assert _keeps_flow(call, dest_ip="10.1.10.9", dest_port=445)


async def test_non_port_dimensions_carry_no_port_bound() -> None:
    # peers_out and process_names have nothing to do with ports; adding the
    # clause there would silently drop every document with no destination.port.
    es = _FakeES(field_presence=_FLOW_OK)
    await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    for call in es.calls:
        keys = set(call["aggs"] or {})
        if not keys & {"peers_out", "dns_names"}:
            continue
        filters = call["query"]["bool"]["filter"]
        assert not [f for f in filters if "range" in f and "destination.port" in f["range"]], (
            f"a non-port dimension bounded destination.port: {keys}"
        )


# ---------------------------------------------------------------------------
# Active hours and rates — the dimensions that give a lead its second kind
# ---------------------------------------------------------------------------


async def test_active_hours_is_built_as_a_168_bin_set() -> None:
    """Without this dimension the off-hours clause cannot fire at all.

    On the range that left exactly one observation kind available, and a lead
    needs two -- so the whole chaining half of the design was inert while every
    surface reported it healthy.

    A set test, not a rate: "was this host ever active in this hour of the
    week" needs no dispersion, which is why it is the one dimension that does
    not go through the three-cell summary.
    """
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "active_hours": {
                "buckets": [
                    {
                        "key": "10.1.10.21",
                        "doc_count": 400,
                        "active_days": {
                            "buckets": [
                                {"key_as_string": f"2026-08-{d:02d}", "doc_count": 1}
                                for d in range(1, 31)
                            ]
                        },
                        "hours": {
                            "buckets": [{"key": h, "doc_count": 50} for h in (9, 10, 11, 14)]
                        },
                    }
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    hours = [p for p in sweep.profiles if p.dimension == "active_hours"]
    assert hours, "the lane built no active_hours dimension"
    profile = hours[0]
    assert profile.shape == "active_hours"
    assert set(profile.vector) == {"9", "10", "11", "14"}


async def test_a_numeric_dimension_is_summarised_into_three_cells() -> None:
    """profile_math exists to be used. It was written, tested, and then never
    called by anything, so no rate dimension was ever built."""
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "connection_rate": {
                "buckets": [
                    {
                        "key": "10.1.10.21",
                        "doc_count": 900,
                        "active_days": {
                            "buckets": [
                                {"key_as_string": f"2026-08-{d:02d}", "doc_count": 1}
                                for d in range(1, 31)
                            ]
                        },
                        "per_hour": {
                            "buckets": [
                                # Tuesday 2026-09-15, working hours and night.
                                {
                                    "key_as_string": "2026-09-15T10:00:00.000Z",
                                    "doc_count": 40,
                                },
                                {
                                    "key_as_string": "2026-09-16T11:00:00.000Z",
                                    "doc_count": 44,
                                },
                                {
                                    "key_as_string": "2026-09-16T23:00:00.000Z",
                                    "doc_count": 2,
                                },
                            ]
                        },
                    }
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    rate = next((p for p in sweep.profiles if p.dimension == "connection_rate"), None)
    assert rate is not None, "the lane built no numeric dimension"
    assert rate.shape == "numeric"
    # Every cell present even when empty, so "no weekend activity observed" is
    # a statement the profile can make.
    assert set(rate.vector) == {"work", "off", "weekend"}
    assert rate.vector["work"]["median"] == 42.0
    assert rate.vector["weekend"]["samples"] == 0


async def test_an_empty_cell_is_recorded_rather_than_omitted() -> None:
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "connection_rate": {
                "buckets": [
                    {
                        "key": "10.1.10.21",
                        "doc_count": 1,
                        "active_days": {"buckets": []},
                        "per_hour": {
                            "buckets": [
                                {"key_as_string": "2026-09-15T10:00:00.000Z", "doc_count": 7}
                            ]
                        },
                    }
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    rate = next(p for p in sweep.profiles if p.dimension == "connection_rate")
    assert rate.vector["off"]["median"] is None
    assert rate.vector["off"]["samples"] == 0


async def test_only_internal_addresses_become_host_entities() -> None:
    """A remote endpoint is not one of our hosts.

    The first live run profiled 52.123.129.14 (a Microsoft server), 127.0.0.1
    and 192.0.2.254 as though they were machines on this estate, and then
    reported findings about their behaviour. Three costs, all real: the
    500-entity aggregation cap gets spent on the internet, the findings are
    about somebody else's infrastructure, and "this host has never used this
    port" is meaningless for an endpoint we only ever see one side of.
    """
    import ipaddress

    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "peers_out": {
                "buckets": [
                    _entity_bucket(
                        "10.1.10.21",
                        [("1.1.1.1", 9, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z")],
                    ),
                    _entity_bucket(
                        "52.123.129.14",
                        [("8.8.8.8", 9, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z")],
                    ),
                    _entity_bucket(
                        "127.0.0.1",
                        [("127.0.0.1", 9, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z")],
                    ),
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es,
        settings=_settings(),
        window_hours=24 * 30,
        time_anchor=_ANCHOR,
        cidrs=[ipaddress.ip_network("10.1.0.0/16")],
    )
    keys = {p.entity_key for p in sweep.profiles if p.dimension == "peers_out"}
    assert keys == {"10.1.10.21"}


async def test_with_no_cidrs_configured_every_address_is_still_profiled() -> None:
    """Fail OPEN on an unconfigured estate.

    An empty CIDR list means nobody has told this deployment what its own
    network is. Treating that as "nothing is internal" would build no profiles
    at all and report a perfectly healthy grid as having no entities -- which
    is the false all-clear again, this time about the estate itself.
    """
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "peers_out": {
                "buckets": [
                    _entity_bucket(
                        "52.123.129.14",
                        [("8.8.8.8", 9, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z")],
                    )
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    assert any(p.entity_key == "52.123.129.14" for p in sweep.profiles)


async def test_multicast_and_link_local_are_not_peers() -> None:
    """mDNS to 224.0.0.251 and LLMNR to 224.0.0.252 are the host talking to
    the LAN, not to a peer. Left in, every host's peer set carried the same
    three multicast groups (seen on the DC's profile, 2026-09-16), and a
    novel-destination prior would fire on the first one a host ever sent."""
    es = _FakeES(
        field_presence=_FLOW_OK,
        agg_payloads={
            "peers_out": {
                "buckets": [
                    _entity_bucket(
                        "10.1.10.21",
                        [
                            ("8.8.8.8", 9, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z"),
                            ("224.0.0.251", 900, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z"),
                            ("224.0.0.252", 800, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z"),
                            ("169.254.1.1", 5, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z"),
                            ("255.255.255.255", 5, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z"),
                            # A directed broadcast is a real destination the
                            # host chose; dropping it would need a mask guess.
                            ("10.1.10.255", 30, "2026-09-01T00:00:00Z", "2026-09-14T00:00:00Z"),
                        ],
                    )
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    peers = next(p for p in sweep.profiles if p.dimension == "peers_out")
    assert set(peers.vector) == {"8.8.8.8", "10.1.10.255"}
