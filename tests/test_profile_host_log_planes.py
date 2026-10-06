"""The profile planes read what Linux agents and Security Onion 3.x ship.

Two dimensions read nothing on a production grid:

* ``logon_users`` read ``system.security`` only. A Linux agent ships its
  logons as ``system.auth``, so every Linux host was blind with thousands of
  accepted logons a day on the grid.
* ``dns_names`` probed ``dns.question.name``. Security Onion 3.x ``zeek.dns``
  writes ``dns.query.name``, so every host was blind.

A dimension that becomes measurable starts in learning. Its first week raises
no departure.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from soc_ai.dossier.profile import collect_entity_profiles
from soc_ai.hunting.prior_sweep import _recent_members
from soc_ai.hunting.priors import evaluate_prior
from soc_ai.hunting.spec import load_spec
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store.entity_profiles import ProfileRow

from tests.es_doubles import composite_page

pytestmark = pytest.mark.asyncio

_ANCHOR = datetime(2026, 9, 15, 12, 0, tzinfo=UTC)
_CATALOG = Path(__file__).resolve().parents[1] / "soc_ai" / "hunting" / "catalog"


class _Settings:
    events_index_pattern = "logs-*"
    so_timezone = "UTC"


def _member(name: str, count: int) -> dict[str, Any]:
    return {
        "key": name,
        "doc_count": count,
        "first": {"value_as_string": "2026-09-01T00:00:00.000Z"},
        "last": {"value_as_string": "2026-09-14T00:00:00.000Z"},
    }


def _entity(key: str, *, days: int, members: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "key": key,
        "doc_count": 1,
        "active_days": {
            "buckets": [
                {"key_as_string": f"2026-09-{d:02d}", "doc_count": 1} for d in range(1, days + 1)
            ]
        },
    }
    for agg, buckets in members.items():
        out[agg] = {"buckets": buckets}
    return out


class _FakeES:
    """Answers the plane probe from ``presence`` and each dimension from ``payloads``."""

    def __init__(
        self,
        presence: dict[str, dict[str, int]],
        payloads: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.presence = presence
        self.payloads = payloads or {}
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        aggs = kwargs.get("aggs") or {}
        self.calls.append({"query": query, "aggs": aggs})
        if "plane_probe" in aggs:
            buckets = {}
            for key in aggs["plane_probe"]["filters"]["filters"]:
                dataset, _, field = key.partition("|")
                buckets[key] = {"doc_count": self.presence.get(dataset, {}).get(field, 0)}
            return EsSearchResult(
                total=0, took_ms=1, aggregations={"plane_probe": {"buckets": buckets}}
            )
        for key in aggs:
            if key in self.payloads:
                # The sweep's recent read pages a composite aggregation.
                answer = (
                    composite_page(aggs[key], self.payloads[key].get("buckets") or [])
                    if "composite" in aggs[key]
                    else self.payloads[key]
                )
                return EsSearchResult(total=1, took_ms=1, aggregations={key: answer})
        return EsSearchResult(total=0, took_ms=1, aggregations={})


def _query_for(es: _FakeES, dimension: str) -> dict[str, Any]:
    return next(c["query"] for c in es.calls if dimension in c["aggs"])


async def test_logon_users_reads_accepted_system_auth_logons() -> None:
    es = _FakeES(
        {"system.auth": {"user.name": 11309, "host.name": 11309}},
        {
            "logon_users": {
                "buckets": [
                    _entity(
                        "app-01",
                        days=30,
                        members={"members": [_member("alice", 400), _member("root", 90)]},
                    )
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_Settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    logon = next(
        p for p in sweep.profiles if p.dimension == "logon_users" and p.entity_key == "app-01"
    )
    assert logon.coverage == "measured"
    assert set(logon.vector) == {"alice", "root"}
    assert sweep.planes.get("logon") == ("system.auth",)

    # Negative control: a failed logon is not a known user. A plane that read
    # every system.auth line would put a brute-force username list in the
    # baseline, and the next real logon by one of those names would never fire.
    query = _query_for(es, "logon_users")
    planes = next(
        f["bool"]["should"] for f in query["bool"]["filter"] if "should" in f.get("bool", {})
    )
    text = repr(planes)
    assert "'event.outcome': 'success'" in text
    assert "'system.auth.ssh.event': 'Accepted'" in text


async def test_a_newly_measurable_logon_plane_raises_no_departure_in_its_first_week() -> None:
    spec = load_spec(_CATALOG / "prior-workstation-account-first-logon-to-dc.yaml")

    async def _profile(days: int) -> ProfileRow:
        es = _FakeES(
            {"system.auth": {"user.name": 300}},
            {
                "logon_users": {
                    "buckets": [
                        _entity("dc-01", days=days, members={"members": [_member("alice", 40)]})
                    ]
                }
            },
        )
        sweep = await collect_entity_profiles(
            elastic=es, settings=_Settings(), window_hours=24 * 30, time_anchor=_ANCHOR
        )
        built = next(p for p in sweep.profiles if p.dimension == "logon_users")
        return ProfileRow(
            entity_kind="host",
            entity_key=built.entity_key,
            dimension=built.dimension,
            shape=built.shape,
            vector=built.vector,
            coverage=built.coverage,
            coverage_reason=None,
            support_days=built.support_days,
            role="domain_controller",
            role_confidence=0.95,
            identity_fingerprint=None,
            window_days=30,
            first_seen=None,
            last_seen=None,
            built_at=None,
        )

    observed = {"mallory": {"count": 5}}
    first_week = await _profile(days=3)
    assert first_week.coverage == "learning"
    quiet = evaluate_prior(
        spec,
        profile=first_week,
        observed=observed,
        role="domain_controller",
        role_confidence=0.95,
    )
    assert quiet.coverage == "learning"
    assert not quiet.fired

    # The same novel account against a measured baseline does fire, so the
    # silence above is the learning floor and not a dead test.
    measured = await _profile(days=30)
    loud = evaluate_prior(
        spec,
        profile=measured,
        observed=observed,
        role="domain_controller",
        role_confidence=0.95,
    )
    assert loud.fired


async def test_dns_names_reads_dns_query_name_beside_dns_question_name() -> None:
    es = _FakeES(
        # Security Onion 3.x: zeek.dns carries dns.query.name and no dns.question.name.
        {"zeek.dns": {"dns.query.name": 112831, "source.ip": 112831}},
        {
            "dns_names": {
                "buckets": [
                    _entity(
                        "192.0.2.41",
                        days=30,
                        members={
                            "members": [],
                            "members_alt_0": [
                                _member("pkg.example.test", 300),
                                _member("time.example.test", 40),
                            ],
                        },
                    )
                ]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_Settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    dns = next(p for p in sweep.profiles if p.dimension == "dns_names" and p.entity_key != "*")
    assert dns.coverage == "measured"
    assert set(dns.vector) == {"pkg.example.test", "time.example.test"}
    assert "dns_names" not in sweep.unanswered

    query = _query_for(es, "dns_names")
    assert {
        "bool": {
            "should": [
                {"exists": {"field": "dns.question.name"}},
                {"exists": {"field": "dns.query.name"}},
            ],
            "minimum_should_match": 1,
        }
    } in query["bool"]["filter"]
    aggs = next(c["aggs"] for c in es.calls if "dns_names" in c["aggs"])["dns_names"]["aggs"]
    assert aggs["members"]["terms"]["field"] == "dns.question.name"
    assert aggs["members_alt_0"]["terms"]["field"] == "dns.query.name"


async def test_the_recent_dns_read_reads_the_same_two_fields() -> None:
    """The recent read and the baseline must agree, or every name reads as novel."""
    es = _FakeES(
        {"zeek.dns": {"dns.query.name": 900}},
        {
            "dns_names": {
                "buckets": [
                    _entity(
                        "192.0.2.41",
                        days=1,
                        members={"members": [], "members_alt_0": [_member("pkg.example.test", 9)]},
                    )
                ]
            }
        },
    )
    out = await _recent_members(es, _Settings(), dimension="dns_names", hours=24, cidrs=())
    assert out is not None
    assert set(out["192.0.2.41"]) == {"pkg.example.test"}
    aggs = next(c["aggs"] for c in es.calls if "dns_names" in c["aggs"])["dns_names"]["aggs"]
    assert aggs["members_alt_0"]["terms"]["field"] == "dns.query.name"
    assert "samples" in aggs["members_alt_0"]["aggs"]


async def test_the_process_plane_reads_auditd_execve_records_only() -> None:
    es = _FakeES(
        {"auditd_manager.auditd": {"process.name": 70, "host.name": 70}},
        {
            "process_names": {
                "buckets": [_entity("app-01", days=30, members={"members": [_member("rpm", 70)]})]
            }
        },
    )
    sweep = await collect_entity_profiles(
        elastic=es, settings=_Settings(), window_hours=24 * 30, time_anchor=_ANCHOR
    )
    proc = next(
        p for p in sweep.profiles if p.dimension == "process_names" and p.entity_key == "app-01"
    )
    assert proc.coverage == "measured"
    query = _query_for(es, "process_names")
    assert "'event.action': 'executed'" in repr(query)
