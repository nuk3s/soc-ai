"""Host coverage: which telemetry planes one host ships, stated as a fact.

Production held twelve false "no host telemetry" claims about one Linux
server. Each probe named the Elastic Defend datasets, which the host never
shipped. The host shipped system.syslog, system.auth and osquery results
through Elastic Agent, and no tool said so. These tests pin the read that
says so, and the sentences the tools hand to the model.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.dossier.coverage import (
    HostCoverage,
    describe,
    host_coverage,
    host_identity,
    name_variants,
    planes_of,
)
from soc_ai.so_client.elastic import EsSearchResult

pytestmark = pytest.mark.asyncio

_UNTIL = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
_SINCE = _UNTIL - timedelta(hours=24)
_ADDR = "192.0.2.41"
_AGENT_ID = "a1b2c3d4-0000-4000-8000-000000000001"


class _Settings:
    events_index_pattern = "logs-*"


def _dataset_buckets(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {
            "key": name,
            "doc_count": count,
            "newest": {"value_as_string": "2026-09-20T11:59:00.000Z"},
        }
        for name, count in counts.items()
    ]


def host_logs_only_aggs() -> dict[str, Any]:
    """A Linux host with Elastic Agent: host logs and osquery, no Elastic Defend."""
    return {
        "host_datasets": {
            "buckets": _dataset_buckets(
                {
                    "system.syslog": 62713,
                    "system.auth": 11309,
                    "osquery_manager.result": 2623,
                }
            )
        },
        "host_agents": {
            "buckets": [
                {
                    "key": _AGENT_ID,
                    "doc_count": 76645,
                    "names": {"buckets": [{"key": "app-01", "doc_count": 76645}]},
                    "os": {"buckets": [{"key": "Fedora Linux", "doc_count": 76645}]},
                }
            ]
        },
        "host_agent_names": {"buckets": []},
    }


class _FakeES:
    def __init__(
        self, aggregations: dict[str, Any] | None = None, error: Exception | None = None
    ) -> None:
        self.aggregations = aggregations or {}
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        if self.error is not None:
            raise self.error
        total = sum(
            int(b.get("doc_count") or 0)
            for b in (self.aggregations.get("host_datasets") or {}).get("buckets", [])
        )
        return EsSearchResult(total=total, took_ms=1, aggregations=self.aggregations)


# ---------------------------------------------------------------------------
# Plane grouping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("dataset", "planes"),
    [
        ("system.syslog", ("host_logs",)),
        ("system.auth", ("host_logs",)),
        ("journald", ("host_logs",)),
        ("linux.memory", ("host_logs",)),
        ("auditd.log", ("host_logs", "process")),
        ("endpoint.events.process", ("process",)),
        ("windows.sysmon_operational", ("process",)),
        ("endpoint.events.network", ("endpoint_network",)),
        ("system.security", ("host_logs", "windows_security")),
        ("windows.security", ("windows_security",)),
        ("winlog", ("windows_security",)),
        ("osquery_manager.result", ("osquery",)),
        ("elastic_agent.filebeat", ("agent_self",)),
        ("elastic_agent", ("agent_self",)),
        ("zeek.conn", ()),
        ("suricata.alert", ()),
    ],
)
async def test_planes_of_groups_each_dataset(dataset: str, planes: tuple[str, ...]) -> None:
    assert planes_of(dataset) == planes


async def test_name_variants_add_the_short_and_the_full_form() -> None:
    out = name_variants(["app-01.example.test", "app-01", "192.0.2.41"])
    assert "app-01" in out
    assert "app-01.example.test" in out
    # An address is not a name and never reaches host.name.
    assert "192.0.2.41" not in out


# ---------------------------------------------------------------------------
# The read
# ---------------------------------------------------------------------------


async def test_the_read_is_one_bounded_query_over_every_identifier() -> None:
    es = _FakeES(host_logs_only_aggs())
    await host_coverage(
        es,
        _Settings(),
        addresses=[_ADDR, "not-an-address"],
        names=["app-01.example.test"],
        agent_ids=[_AGENT_ID],
        since=_SINCE,
        until=_UNTIL,
    )
    assert len(es.calls) == 1
    call = es.calls[0]
    assert call["size"] == 0
    # A partial read must raise, so it can never read as an absence.
    assert call["require_complete"] is True
    should = call["query"]["bool"]["should"]
    fields = {next(iter(c["terms"])) for c in should}
    assert fields == {"agent.id", "host.name", "host.hostname", "host.ip"}
    names = next(c["terms"]["host.name"] for c in should if "host.name" in c["terms"])
    assert "app-01" in names and "app-01.example.test" in names
    ips = next(c["terms"]["host.ip"] for c in should if "host.ip" in c["terms"])
    assert ips == [_ADDR]
    assert call["aggs"]["host_datasets"]["terms"] == {"field": "event.dataset", "size": 100}
    rng = call["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert rng == {"gte": _SINCE.isoformat(), "lte": _UNTIL.isoformat()}
    must_not = call["query"]["bool"]["must_not"]
    assert {"exists": {"field": "synth.scenario_id"}} in must_not


async def test_a_host_logs_only_host_is_covered_in_two_planes() -> None:
    cov = await host_coverage(
        _FakeES(host_logs_only_aggs()),
        _Settings(),
        addresses=[_ADDR],
        since=_SINCE,
        until=_UNTIL,
    )
    assert cov.read_ok
    assert cov.present == ["host_logs", "osquery"]
    assert cov.ships("host_logs") and cov.ships("osquery")
    assert not cov.ships("process")
    assert cov.absent() == ["process", "endpoint_network"]
    agent = cov.agent
    assert agent is not None
    assert (agent.id, agent.name, agent.os) == (_AGENT_ID, "app-01", "Fedora Linux")
    assert describe(cov) == [
        "This host ships host logs (system.syslog 62,713, system.auth 11,309) and osquery "
        "(osquery_manager.result 2,623).",
        "It ships no process events and no endpoint network events.",
    ]


async def test_a_plane_absence_never_reads_as_no_host_telemetry() -> None:
    """Negative control on the path that produced the false claims.

    Every Elastic Defend probe on this host returns zero. The sentences must
    name the absent planes and must not say the host has no host telemetry.
    """
    cov = await host_coverage(
        _FakeES(host_logs_only_aggs()), _Settings(), addresses=[_ADDR], since=_SINCE, until=_UNTIL
    )
    text = " ".join(describe(cov)).lower()
    assert "ships no process events" in text
    for false_claim in ("no host telemetry", "no host-level", "no host logs", "no telemetry"):
        assert false_claim not in text


async def test_unknown_datasets_go_to_other_with_their_name() -> None:
    aggs = host_logs_only_aggs()
    aggs["host_datasets"]["buckets"] += _dataset_buckets({"custom.app": 12})
    cov = await host_coverage(
        _FakeES(aggs), _Settings(), addresses=[_ADDR], since=_SINCE, until=_UNTIL
    )
    assert [d.dataset for d in cov.other] == ["custom.app"]
    assert describe(cov)[-1] == "It also ships custom.app 12."


async def test_a_failed_read_reports_unknown_never_absence() -> None:
    cov = await host_coverage(
        _FakeES(error=TimeoutError("read timed out")),
        _Settings(),
        addresses=[_ADDR],
        since=_SINCE,
        until=_UNTIL,
    )
    assert cov.read_ok is False
    assert cov.reason is not None and "TimeoutError" in cov.reason
    assert cov.present == []
    assert cov.absent() == []  # unknown, so no plane is reported absent
    sentences = describe(cov)
    assert sentences[0].startswith("soc-ai could not read the host's coverage.")
    assert not any("ships no" in s for s in sentences)


async def test_no_identifier_is_unknown_and_spends_no_query() -> None:
    es = _FakeES(host_logs_only_aggs())
    cov = await host_coverage(es, _Settings(), since=_SINCE, until=_UNTIL)
    assert es.calls == []
    assert cov.read_ok is False


async def test_a_host_with_no_document_is_absent_in_every_core_plane() -> None:
    cov = await host_coverage(
        _FakeES({"host_datasets": {"buckets": []}}),
        _Settings(),
        addresses=[_ADDR],
        since=_SINCE,
        until=_UNTIL,
    )
    assert cov.read_ok and not cov.covered
    assert describe(cov, subject=_ADDR) == [
        f"soc-ai found no host document for {_ADDR} in the window. {_ADDR} ships no host "
        "logs, no process events and no endpoint network events."
    ]


async def test_coverage_serialises_for_a_tool_result() -> None:
    cov = await host_coverage(
        _FakeES(host_logs_only_aggs()), _Settings(), addresses=[_ADDR], since=_SINCE, until=_UNTIL
    )
    again = HostCoverage.model_validate(cov.model_dump(mode="json"))
    assert again.present == ["host_logs", "osquery"]


# ---------------------------------------------------------------------------
# Identity input
# ---------------------------------------------------------------------------


async def test_host_identity_reads_the_agent_name_from_the_dossier_evidence(
    settings_kratos: Settings,
) -> None:
    """The agent's own name sits in the evidence even when the hostname field is null.

    On production the agent name was rejected as a top-level domain, so the
    hostname value was null and the only name the model saw was the DNS form.
    The agent name still sat in the host-agent evidence of another field.
    """
    from soc_ai.store import host_dossier as store
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
    from soc_ai.store.models import HostDossierField

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    try:
        async with maker() as db:
            host = await store.upsert_host(db, _ADDR, event_count=10)
            db.add(
                HostDossierField(
                    dossier_id=host.id,
                    field="hostname",
                    inferred_value=None,
                    inferred_evidence={
                        "telemetry": {
                            "strings": ["app-01.example.test (from dns, 63 A/AAAA answers)"],
                            "value": "app-01.example.test",
                            "strength": "strong",
                        }
                    },
                )
            )
            db.add(
                HostDossierField(
                    dossier_id=host.id,
                    field="mac",
                    inferred_value=None,
                    inferred_evidence={
                        "banner": {
                            "strings": [
                                "app-01 reported 5 hardware addresses (bridges and virtual "
                                "interfaces); none can be singled out as the machine's own "
                                "(from host-agent)"
                            ],
                            "value": None,
                            "strength": "none",
                        }
                    },
                )
            )
            await db.commit()
        async with maker() as db:
            ident = await host_identity(db, _ADDR)
        assert ident.addresses == [_ADDR]
        assert "app-01" in ident.names
        assert "app-01.example.test" in ident.names
        async with maker() as db:
            unknown = await host_identity(db, "198.51.100.77")
        assert unknown.addresses == ["198.51.100.77"]
        assert unknown.names == []
    finally:
        await engine.dispose()
