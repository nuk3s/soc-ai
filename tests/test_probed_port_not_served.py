"""A probed port is not a served port.

Measured defect (production review 2026-11-12, found by the A4 work). One Nmap
sweep sent SYN packets to seven ports of 1,672 addresses. A Zeek conn record is
written for a connection ATTEMPT, so each address gained seven responder ports.
594 of 600 sampled rows read "management-plane responder on tcp/22" at 0.9. No
record showed a packet from those addresses.

The inference already separates an answered port from an attempted port, and
its host-wide test reads the responder byte percentile. The probe records hold
no responder byte field, so the percentile was not measured and the test said
nothing. The collector never gave the inference a count for each port.

The rule. A TCP flow record is a probe when it carries a responder counter and
no counter is above zero, or when its connection state is a refusal. A port is
probed when each record to it is a probe. A probed port is not a served port.
A record of a different transport, and a record with no responder counter,
keeps the behavior it had: a UDP log sink answers nothing and is a real
service.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from scripts.demo import mock_es
from soc_ai.config import Settings
from soc_ai.dossier import observe
from soc_ai.dossier.infer import infer_host_facts
from soc_ai.dossier.profile import _direction_for, served_direction_clauses
from soc_ai.dossier.types import HostObservations
from soc_ai.enrichment import host_dossier as job
from soc_ai.so_client import fields
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.tools.host_summary import host_summary

from tests.test_host_dossier_job import _MAIN_AGGS, _db, _FakeES, _field, _settings

_NOW = datetime(2026, 11, 13, tzinfo=UTC)
_HOST = "192.168.10.202"


# ---------------------------------------------------------------------------
# One flow record: probe or not
# ---------------------------------------------------------------------------


def _conn(state: str, packets: int | None, payload: int | None, proto: str = "tcp") -> dict:
    """A zeek.conn document in the shape that a Security Onion 3.x grid stores."""
    source: dict[str, Any] = {
        "event": {"dataset": "zeek.conn"},
        "network": {"transport": proto},
        "connection": {"state": state},
        "destination": {"ip": _HOST, "port": 22},
        "server": {},
    }
    if packets is not None:
        source["server"]["packets"] = packets
    if payload is not None:
        source["server"]["bytes"] = payload
    return {"_source": source}


def _is_probe(doc: dict) -> bool:
    return bool(mock_es._matches(fields.probe_record_clause(), doc, _NOW))


def _is_evidence(doc: dict) -> bool:
    return bool(mock_es._matches(fields.served_evidence_clause(), doc, _NOW))


def test_a_syn_that_nothing_answered_is_a_probe() -> None:
    """The measured record: state S0, zero responder packets, no responder byte field."""
    assert _is_probe(_conn("S0", 0, None))
    assert not _is_evidence(_conn("S0", 0, None))


def test_a_refused_connection_is_a_probe() -> None:
    """A closed port answers a SYN with one RST. The port is not served."""
    refused = _conn("REJ", 1, 0)
    assert _is_probe(refused)
    assert not _is_evidence(refused)


def test_one_syn_ack_is_evidence() -> None:
    """Negative control: a half-open scan of an open port. One packet, no payload."""
    half_open = _conn("RSTO", 1, 0)
    assert _is_evidence(half_open)
    assert not _is_probe(half_open)


def test_a_session_with_payload_is_evidence() -> None:
    """Negative control."""
    session = _conn("SF", 24, 4096)
    assert _is_evidence(session)
    assert not _is_probe(session)


def test_a_udp_record_with_no_answer_is_not_a_probe() -> None:
    """Negative control: a UDP log sink answers nothing and is a real service."""
    assert not _is_probe(_conn("S0", 0, 0, proto="udp"))


def test_a_record_with_no_responder_counter_is_not_a_probe() -> None:
    """Negative control: a grid with no responder counter keeps its behavior."""
    assert not _is_probe(_conn("S0", None, None))
    endpoint = {
        "_source": {
            "event": {"dataset": "endpoint.events.network", "action": "connection_accepted"},
            "network": {"transport": "tcp"},
            "destination": {"ip": _HOST, "port": 22},
        }
    }
    assert not _is_probe(endpoint)


def test_a_record_with_no_transport_is_not_a_probe() -> None:
    """Negative control: the rule needs proof that the record is TCP."""
    record = _conn("S0", 0, None)
    del record["_source"]["network"]
    assert not _is_probe(record)


def test_the_older_field_names_give_the_same_answer() -> None:
    def legacy(state: str, packets: int) -> dict:
        return {
            "_source": {
                "zeek.conn.proto": "tcp",
                "zeek.conn.conn_state": state,
                "zeek.conn.resp_pkts": packets,
            }
        }

    assert _is_probe(legacy("S0", 0))
    assert _is_probe(legacy("REJ", 1))
    assert not _is_probe(legacy("SF", 9))


def test_the_host_rule_and_the_port_rule_read_the_same_counters() -> None:
    """The A4 rule and this rule agree on what a responder packet is."""
    census = job._responder_aggs()
    assert census["judged"]["filter"] == fields.judged_record_clause()
    assert census["answered"]["filter"] == fields.responder_answered_clause()
    assert fields.responder_answered_clause() in fields.served_evidence_clause()["bool"]["filter"]
    # The host rule keeps a refusal: one RST proves that a machine is there.
    assert mock_es._matches(fields.responder_answered_clause(), _conn("REJ", 1, 0), _NOW)


# ---------------------------------------------------------------------------
# The dossier collector
# ---------------------------------------------------------------------------


def _agg_fields() -> Any:
    return observe._AggFields(
        service="network.protocol",
        orig_bytes="client.bytes",
        resp_bytes="server.bytes",
        ja3="hash.ja3",
        reg_domain="dns.highest_registered_domain",
        dns_query="dns.query.name",
        sni="ssl.server_name",
        transport="network.transport",
    )


@pytest.mark.parametrize("optional", [True, False])
def test_the_collector_asks_each_responder_port_for_its_evidence(optional: bool) -> None:
    """Both counts survive the reduced retry: the role rules read them."""
    ports = observe._build_aggs(_HOST, _agg_fields(), optional=optional)["responder"]["aggs"][
        "ports"
    ]
    assert ports["aggs"]["served"]["filter"] == fields.served_evidence_clause()
    assert ports["aggs"]["unjudged"]["filter"] == {
        "bool": {"must_not": [fields.judged_record_clause()]}
    }
    assert ("transport" in ports["aggs"]) is optional


def _port_agg(*buckets: dict[str, Any]) -> dict[str, Any]:
    return {"buckets": list(buckets)}


def _bucket(port: int, count: int, *, served: int | None, unjudged: int | None) -> dict[str, Any]:
    bucket: dict[str, Any] = {"key": port, "doc_count": count}
    if served is not None:
        bucket["served"] = {"doc_count": served}
    if unjudged is not None:
        bucket["unjudged"] = {"doc_count": unjudged}
    return bucket


def test_a_port_with_no_evidence_reads_zero_answered() -> None:
    (pair,) = observe._port_pairs(_port_agg(_bucket(222, 2, served=0, unjudged=0)))
    assert pair == {"value": 222, "count": 2, "answered": 0}


def test_a_port_with_one_answer_keeps_its_count() -> None:
    """Negative control: one SYN-ACK among the records is enough."""
    (pair,) = observe._port_pairs(_port_agg(_bucket(22, 2, served=1, unjudged=0)))
    assert "answered" not in pair
    assert pair["count"] == 2


def test_a_port_with_a_record_that_cannot_be_judged_keeps_its_count() -> None:
    """Negative control: UDP, or a record with no responder counter."""
    (pair,) = observe._port_pairs(_port_agg(_bucket(514, 900, served=0, unjudged=900)))
    assert "answered" not in pair


def test_a_grid_that_returns_no_evidence_counts_keeps_its_ports() -> None:
    """Negative control: the bucket shape from before this change."""
    (pair,) = observe._port_pairs(_port_agg(_bucket(22, 40, served=None, unjudged=None)))
    assert pair == {"value": 22, "count": 40}


# ---------------------------------------------------------------------------
# The inference
# ---------------------------------------------------------------------------


def _obs(resp_ports: list[dict[str, Any]], **over: Any) -> HostObservations:
    base: dict[str, Any] = {
        "ip": _HOST,
        "total_events": 500,
        "first_seen": datetime(2026, 11, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 11, 7, 1, 55, tzinfo=UTC),
        "resp_ports": resp_ports,
        "resp_peer_count": 1,
        "resp_hours": 1,
    }
    base.update(over)
    return HostObservations(**base)


def _served(facts: dict[str, Any]) -> list[int]:
    return [entry["port"] for entry in facts["services_offered"].value_json or []]


def _scan_ports(*ports: int) -> list[dict[str, Any]]:
    """Two SYN packets for each port, as the measured sweep sent, and no answer."""
    return observe._port_pairs(_port_agg(*(_bucket(p, 2, served=0, unjudged=0) for p in ports)))


def test_a_scanned_host_with_no_responder_evidence_loses_the_ports_and_the_role() -> None:
    """The measured row, above the event floor so that the floor does not hide the result."""
    facts = infer_host_facts(
        _obs(_scan_ports(22, 222, 2022, 2200, 2222, 8022, 8006)), min_events=20
    )
    assert _served(facts) == []
    assert facts["management_plane"].value != "yes"
    assert facts["role"].value == "unknown"
    assert "responds on" not in " ".join(facts["role"].evidence)


def test_the_same_host_reads_as_a_responder_without_the_evidence_counts() -> None:
    """The defect, kept as a control: with no count for each port the scan reads as service."""
    ports = [{"value": p, "count": 2} for p in (22, 222, 2022, 2200, 2222, 8022, 8006)]
    facts = infer_host_facts(_obs(ports), min_events=20)
    assert 22 in _served(facts)
    assert facts["management_plane"].value == "yes"


def test_a_real_ssh_server_that_was_also_scanned_keeps_tcp_22() -> None:
    """Negative control."""
    ports = observe._port_pairs(
        _port_agg(
            _bucket(22, 61, served=59, unjudged=0),
            _bucket(222, 2, served=0, unjudged=0),
            _bucket(2222, 2, served=0, unjudged=0),
        )
    )
    facts = infer_host_facts(_obs(ports, resp_peer_count=5, resp_hours=30), min_events=20)
    assert _served(facts) == [22]
    assert facts["management_plane"].value == "yes"
    assert facts["management_plane"].value_json == [22]


def test_a_host_that_answered_one_syn_ack_keeps_the_port() -> None:
    """Negative control: two records to tcp/22, and one of them shows a SYN-ACK."""
    ports = observe._port_pairs(
        _port_agg(_bucket(22, 2, served=1, unjudged=0), _bucket(222, 2, served=0, unjudged=0))
    )
    facts = infer_host_facts(_obs(ports), min_events=20)
    assert _served(facts) == [22]


# ---------------------------------------------------------------------------
# The profile baseline, the prior sweep and the host summary
# ---------------------------------------------------------------------------


def test_the_served_port_profile_read_leaves_out_probe_records() -> None:
    """The baseline and the recent read spread the same clauses, so both agree."""
    clauses = _direction_for("served_ports", planes=["zeek.conn"])
    assert fields.probe_record_clause() in clauses["must_not"]


def test_the_direction_clauses_of_the_earlier_fix_are_unchanged() -> None:
    """The direction rule of 2026-09-25 stays as it was, with the probe rule beside it."""
    direction = served_direction_clauses(["zeek.conn", "endpoint.events.network"])
    served = _direction_for("served_ports", planes=["zeek.conn", "endpoint.events.network"])
    assert fields.probe_record_clause() not in direction["must_not"]
    assert served["filter"] == direction["filter"]
    assert served["must_not"][: len(direction["must_not"])] == direction["must_not"]


def test_a_dimension_that_is_not_a_served_port_carries_no_probe_clause() -> None:
    """Negative control: the ports a host consumes are not judged by the answer of the host."""
    assert _direction_for("consumed_ports", planes=["zeek.conn"]) == {"filter": [], "must_not": []}


class _SummaryES:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"query": query, **kwargs})
        return EsSearchResult(total=0, took_ms=1, aggregations={})


async def test_the_host_summary_leaves_probe_records_out_of_its_ports(
    settings_kratos: Settings,
) -> None:
    es = _SummaryES()
    await host_summary(_HOST, elastic=es, settings=settings_kratos)  # type: ignore[arg-type]
    ports = next(c["aggs"]["resp_ports"] for c in es.calls if "resp_ports" in (c.get("aggs") or {}))
    assert ports["filter"]["bool"]["must_not"] == [fields.probe_record_clause()]
    assert {"term": {"destination.ip": _HOST}} in ports["filter"]["bool"]["must"]


# ---------------------------------------------------------------------------
# The sweep: a rebuild corrects a stored false port
# ---------------------------------------------------------------------------


class _PortsES(_FakeES):
    """The job fake, with the responder ports of the main pass under test control."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.port_buckets: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        aggs = kwargs.get("aggs") or {}
        if "responder" not in aggs:
            return await super().search(index, query, **kwargs)
        self.calls.append(
            {"kind": "main", "index": index, "query": query, "aggs": aggs, "ip": None}
        )
        responder = {
            **_MAIN_AGGS["responder"],
            "ports": {"buckets": self.port_buckets},
            "services": {"buckets": []},
            # The probe records hold no responder byte field, so the grid
            # returns no percentile.
            "bytes": {"values": {"50.0": None, "95.0": None}},
        }
        return EsSearchResult(
            total=self.main_total, took_ms=2, aggregations={**_MAIN_AGGS, "responder": responder}
        )


_SCAN = (22, 222, 2022, 2200, 2222, 8022, 22222)


async def test_a_rebuild_corrects_the_false_ports_that_the_store_holds(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        es = _PortsES(src={_HOST: 500}, main_total=60)
        # The first build is the build from before the change: no count for each port.
        es.port_buckets = [_bucket(port, 2, served=None, unjudged=None) for port in _SCAN]
        await job.run_dossier_refresh(es, maker, settings)
        before = await _field(maker, _HOST, "services_offered")
        assert [e["port"] for e in before.inferred_value_json] == sorted(_SCAN)
        assert (await _field(maker, _HOST, "management_plane")).inferred_value == "yes"

        # The next build reads the same records, and each port shows no answer.
        es.port_buckets = [_bucket(port, 2, served=0, unjudged=0) for port in _SCAN]
        await job.run_dossier_refresh(es, maker, settings)
        after = await _field(maker, _HOST, "services_offered")
        assert after.inferred_value is None
        assert after.inferred_value_json == []
        plane = await _field(maker, _HOST, "management_plane")
        assert plane.inferred_value != "yes"
        assert not plane.inferred_value_json
    finally:
        await engine.dispose()


async def test_a_rebuild_keeps_the_real_port_of_a_scanned_server(
    settings_kratos: Settings,
) -> None:
    """Negative control, through the sweep."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        es = _PortsES(src={_HOST: 500}, main_total=600)
        es.port_buckets = [
            _bucket(22, 61, served=59, unjudged=0),
            *(_bucket(port, 2, served=0, unjudged=0) for port in _SCAN[1:]),
        ]
        await job.run_dossier_refresh(es, maker, settings)
        offered = await _field(maker, _HOST, "services_offered")
        assert [e["port"] for e in offered.inferred_value_json] == [22]
        assert (await _field(maker, _HOST, "management_plane")).inferred_value == "yes"
    finally:
        await engine.dispose()


async def test_a_short_read_still_keeps_the_previous_ports(settings_kratos: Settings) -> None:
    """Negative control: probed ports that the previous build did not hold explain nothing.

    The previous build held eight served ports. This read returns two of them
    and ten probed ports of a scan. That is a short read of the served ports,
    and the build keeps the previous answer.
    """
    real = (22, 80, 443, 3306, 5432, 8080, 8443, 9090)
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        es = _PortsES(src={_HOST: 500}, main_total=900)
        es.port_buckets = [_bucket(port, 40, served=40, unjudged=0) for port in real]
        await job.run_dossier_refresh(es, maker, settings)
        es.port_buckets = [
            *(_bucket(port, 40, served=40, unjudged=0) for port in real[:2]),
            *(_bucket(port, 2, served=0, unjudged=0) for port in range(7000, 7010)),
        ]
        summary = await job.run_dossier_refresh(es, maker, settings)
        offered = await _field(maker, _HOST, "services_offered")
        assert sorted(e["port"] for e in offered.inferred_value_json) == sorted(real)
        assert summary.partial_reads == 1
    finally:
        await engine.dispose()
