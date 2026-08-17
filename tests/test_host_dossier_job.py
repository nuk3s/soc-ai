"""Tests for the host-dossier network sweep (``soc_ai.enrichment.host_dossier``).

The sweep is what makes the dossier hold a *current* idea of what a host is, so
these tests are about the properties that decide whether it can be left running
unattended against a live grid:

* **The census is aggregations only.** Enumerating the network by pulling
  documents is the difference between a cheap nightly sweep and a job that
  hammers Elasticsearch, and the shape of that one query is the whole cost model.
* **A run is stamped even when it did nothing.** A stable network finds nothing
  new almost every sweep; gating the durable stamp on "found something" is the
  bug that had auto-triage re-running full ES planning every 60 seconds, and
  here it would re-sweep the whole network on every restart.
* **One bad host cannot abort the sweep.** The failure is recorded on that
  host's row and the sweep carries on.
* **The prod is rate-limited end to end.** Three disagreeing builds earn exactly
  one prod, a fourth inside the interval earns none, agreement clears the
  disagreement while keeping the history, and "keep mine" buys a doubling
  silence. The state machine lives in the store; what is tested here is that the
  sweep actually drives it, with the operator's configured knobs.

Everything runs against a fake Elasticsearch that routes on the SHAPE of the
request (the recipe from ``tests/test_dossier_observe.py``, extended with the
census pass) and a scratch SQLite DB migrated to head (the recipe from
``tests/test_hunts_store.py``).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.enrichment import host_dossier as job
from soc_ai.so_client import fields, inventory
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import host_dossier as store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.internal_identifiers import list_identifiers, set_state
from soc_ai.store.models import DossierRun, HostDossier, HostDossierField
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

_HYPERVISOR = "192.168.10.202"
_LAPTOP = "192.168.10.77"
_EXTERNAL = "203.0.113.9"

_FIRST_SEEN = datetime(2026, 7, 24, 3, 15, tzinfo=UTC)
_LAST_SEEN = datetime(2026, 8, 6, 17, 42, tzinfo=UTC)

_LINUX_BANNER = "SSH-2.0-OpenSSH_9.6p1 Debian-3"
_WINDOWS_BANNER = "SSH-2.0-OpenSSH_for_Windows_9.5"

_GRID_DATASETS = (
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


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


# A management-plane responder: enough volume and spread that the classifier
# reaches a behavioural verdict rather than the insufficient-telemetry floor.
_MAIN_AGGS: dict[str, Any] = {
    "first_seen": {"value": float(_ms(_FIRST_SEEN)), "value_as_string": _iso(_FIRST_SEEN)},
    "last_seen": {"value": float(_ms(_LAST_SEEN)), "value_as_string": _iso(_LAST_SEEN)},
    "datasets": {"buckets": [{"key": "zeek.conn", "doc_count": 3412}]},
    "responder": {
        "doc_count": 3412,
        "ports": {"buckets": [{"key": 8006, "doc_count": 900}, {"key": 22, "doc_count": 41}]},
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
        "ports": {"buckets": [{"key": 443, "doc_count": 400}]},
        "peers": {"value": 12},
        "bytes": {"values": {"50.0": 300.0, "95.0": 4000.0}},
        "ja3": {"value": 3},
    },
    "activity": {"buckets": [{"key": _ms(datetime(2026, 8, 6, 9, tzinfo=UTC)), "doc_count": 60}]},
    "reg_domains": {"buckets": []},
    "dns_queries": {"buckets": []},
    "sni": {"buckets": []},
}


def _ssh_hit(ip: str, banner: str) -> dict[str, Any]:
    """A Zeek SSH record where *ip* is the SERVER — its own banner, not its peer's."""
    return {
        "@timestamp": _iso(_LAST_SEEN),
        "event.dataset": "zeek.ssh",
        "source.ip": "192.168.10.50",
        "destination.ip": ip,
        "ssh.server": banner,
    }


def _dhcp_hit(ip: str, hostname: str, *, mac: str | None = "aa:bb:cc:dd:ee:01") -> dict[str, Any]:
    """A DHCP lease where *ip* is the client — the strongest first-party name.

    ``mac=None`` omits the field entirely, which is what a shorter DHCP window
    (or a lease renewal Zeek only partially parsed) looks like: the name is
    still announced, the hardware address simply is not in this window.
    """
    hit: dict[str, Any] = {
        "@timestamp": _iso(_LAST_SEEN),
        "event.dataset": "zeek.dhcp",
        "source.ip": ip,
        "destination.ip": "192.168.10.1",
        "dhcp.hostname": hostname,
    }
    if mac is not None:
        hit["dhcp.client.mac"] = mac
    return hit


class _RecordingAudit:
    """The one :class:`AuditLogger` method the sweep uses, plus a failure switch.

    The sweep must emit exactly one ``dossier_conflict_nudge`` per fired prod —
    without it the state machine burns its 14-day rate limit on prompts nobody
    ever saw — and it must survive an audit index that is down, because the
    field write it describes has already been committed.
    """

    def __init__(self, *, fail: bool = False) -> None:
        self.events: list[dict[str, Any]] = []
        self.fail = fail

    async def log_kind(
        self, session_id: str, kind: str, payload: dict[str, Any], **kwargs: Any
    ) -> None:
        if self.fail:
            raise RuntimeError("audit index is down")
        self.events.append({"session_id": session_id, "kind": kind, "payload": payload, **kwargs})


# ---------------------------------------------------------------------------
# Fake Elasticsearch
# ---------------------------------------------------------------------------


def _call_kind(query: dict[str, Any], aggs: dict[str, Any] | None) -> str:
    """Which of the sweep's seven search kinds this request is."""
    if aggs and {"src", "dst"} <= set(aggs):
        return "census"
    if aggs and "hosts" in aggs:
        return "agent"
    if aggs and "names" in aggs:
        return "dns"
    if "exists" in query:
        return "probe"
    if aggs and "responder" in aggs:
        return "main"
    if aggs and set(aggs) == {"datasets"}:
        return "inventory"
    return "targeted"


def _host_ip(query: dict[str, Any]) -> str | None:
    """The IP a per-host query is about (``None`` for the resolver-side PTR search)."""
    for clause in query.get("bool", {}).get("must", []):
        if not isinstance(clause, dict):
            continue
        for should in clause.get("bool", {}).get("should", []):
            term = should.get("term") or {}
            if "source.ip" in term:
                return str(term["source.ip"])
    return None


def _ptr_ip(query: dict[str, Any]) -> str | None:
    """The IP behind a reverse-zone term, so a PTR search routes like the rest."""
    for clause in query.get("bool", {}).get("must", []):
        if not isinstance(clause, dict):
            continue
        for value in (clause.get("term") or {}).values():
            zone = str(value)
            if zone.endswith(".in-addr.arpa"):
                return ".".join(reversed(zone[: -len(".in-addr.arpa")].split(".")))
    return None


def _datasets_in(query: dict[str, Any]) -> tuple[str, ...]:
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


class _FakeES:
    """Routes on request shape, records every call, and can fail on demand."""

    def __init__(
        self,
        *,
        src: dict[str, int] | None = None,
        dst: dict[str, int] | None = None,
        targeted: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
        main_total: int = 3412,
        grid_datasets: tuple[str, ...] = _GRID_DATASETS,
        census_error: str | None = None,
        search_error: str | None = None,
        census_other: int = 0,
        agents: list[dict[str, Any]] | None = None,
        dns: list[dict[str, Any]] | None = None,
    ) -> None:
        self.src = dict(src or {})
        self.dst = dict(dst or {})
        self.targeted = dict(targeted or {})
        self.main_total = main_total
        self.grid_datasets = grid_datasets
        # `host.name` buckets for the network agent inventory — the hostlog lane.
        self.agents = list(agents or [])
        # Query-name buckets for the network DNS pass — the telemetry lane.
        self.dns = list(dns or [])
        self.census_error = census_error
        # Every search raises — a grid-wide outage, as opposed to one bad agg.
        self.search_error = search_error
        # `sum_other_doc_count` on the census terms aggs: ES's only signal that
        # buckets fell off the end of `size`.
        self.census_other = census_other
        self.calls: list[dict[str, Any]] = []

    def _buckets(self, counts: dict[str, int]) -> dict[str, Any]:
        return {
            "sum_other_doc_count": self.census_other,
            "buckets": [
                {
                    "key": ip,
                    "doc_count": n,
                    "first_seen": {
                        "value": float(_ms(_FIRST_SEEN)),
                        "value_as_string": _iso(_FIRST_SEEN),
                    },
                    "last_seen": {
                        "value": float(_ms(_LAST_SEEN)),
                        "value_as_string": _iso(_LAST_SEEN),
                    },
                }
                for ip, n in counts.items()
            ],
        }

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
        if self.search_error:
            raise RuntimeError(self.search_error)
        kind = _call_kind(query, aggs)
        self.calls.append(
            {
                "kind": kind,
                "index": index,
                "query": query,
                "size": size,
                "sort": sort,
                "aggs": aggs,
                "ip": _host_ip(query) or _ptr_ip(query),
            }
        )

        if kind == "census":
            if self.census_error:
                raise RuntimeError(self.census_error)
            return EsSearchResult(
                total=sum(self.src.values()) + sum(self.dst.values()),
                took_ms=3,
                aggregations={"src": self._buckets(self.src), "dst": self._buckets(self.dst)},
            )
        if kind == "agent":
            return EsSearchResult(
                total=sum(int(b["doc_count"]) for b in self.agents),
                took_ms=2,
                aggregations={"hosts": {"buckets": self.agents}},
            )
        if kind == "dns":
            return EsSearchResult(
                total=sum(int(b["doc_count"]) for b in self.dns),
                took_ms=2,
                aggregations={"names": {"buckets": self.dns}},
            )
        if kind == "probe":
            # Only the ECS spellings carry data on this (modern) grid.
            populated = {
                "network.protocol",
                "client.bytes",
                "server.bytes",
                "hash.ja3",
                "dns.highest_registered_domain",
                "dns.query.name",
                "ssl.server_name",
            }
            hit = 1 if query["exists"]["field"] in populated else 0
            return EsSearchResult(total=hit, took_ms=1)
        if kind == "inventory":
            return EsSearchResult(
                total=100,
                took_ms=1,
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
            return EsSearchResult(total=self.main_total, took_ms=2, aggregations=_MAIN_AGGS)

        ip = _host_ip(query) or _ptr_ip(query) or ""
        datasets = _datasets_in(query)
        key = datasets[0] if datasets else "ptr"
        hits = self.targeted.get((ip, key), [])
        return EsSearchResult(
            total=len(hits),
            took_ms=1,
            hits=[{"_id": f"e{i}", "_source": src} for i, src in enumerate(hits)],
        )


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_caches() -> Iterator[None]:
    """Both resolvers are process-cached; a stale entry would hide a regression."""
    fields._clear_agg_field_cache()
    inventory._clear_cache()
    yield
    fields._clear_agg_field_cache()
    inventory._clear_cache()


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[Any]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _settings(settings_kratos: Settings, **overrides: Any) -> Settings:
    """Settings with the dossier knobs the sweep reads set explicitly."""
    settings_kratos.dossier_enabled = True
    settings_kratos.dossier_lookback_days = 14
    settings_kratos.dossier_max_hosts_per_run = 200
    settings_kratos.dossier_max_hosts = 5000
    settings_kratos.dossier_min_events = 20
    settings_kratos.dossier_min_confidence = 0.6
    settings_kratos.dossier_conflict_min_observations = 3
    settings_kratos.dossier_conflict_prompt_interval_hours = 336
    for key, value in overrides.items():
        setattr(settings_kratos, key, value)
    return settings_kratos


async def _field(maker: async_sessionmaker[Any], ip: str, name: str) -> HostDossierField:
    async with maker() as db:
        row = await store.get_field(db, ip, name)
        assert row is not None, f"no {name!r} row for {ip}"
        return row


async def _host_row(maker: async_sessionmaker[Any], ip: str) -> HostDossier | None:
    async with maker() as db:
        got = await store.get_dossier(db, ip)
        return got[0] if got else None


async def _runs(maker: async_sessionmaker[Any]) -> list[DossierRun]:
    async with maker() as db:
        rows = await db.scalars(select(DossierRun).order_by(DossierRun.id.asc()))
        return list(rows.all())


# ---------------------------------------------------------------------------
# The census pass: aggregations only
# ---------------------------------------------------------------------------


async def test_the_census_pass_is_size_zero_aggregations_only(settings_kratos: Settings) -> None:
    """The census must never pull documents — that is the whole cost model.

    One terms agg per endpoint over the lookback window. Pulling hits to
    enumerate hosts would scan the network's entire event volume every sweep.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412}, dst={_EXTERNAL: 900})

    await job.run_dossier_refresh(es, maker, settings)

    census = [c for c in es.calls if c["kind"] == "census"]
    assert len(census) == 1, "the census is one round trip"
    call = census[0]
    assert call["size"] == 0
    assert call["index"] == settings.events_index_pattern
    assert call["aggs"]["src"]["terms"]["field"] == "source.ip"
    assert call["aggs"]["dst"]["terms"]["field"] == "destination.ip"
    # The synthetic-eval kill-switch: an eval fixture must never become a
    # durable asset record.
    assert call["query"]["bool"]["must_not"] == [{"exists": {"field": "synth.scenario_id"}}]
    ranges = [c for c in call["query"]["bool"]["filter"] if "range" in c]
    assert ranges[0]["range"]["@timestamp"]["gte"] == "now-14d"
    await engine.dispose()


async def test_only_internal_addresses_become_dossiers(settings_kratos: Settings) -> None:
    """External peers are in the buckets by construction; they are not assets."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412, _EXTERNAL: 12}, dst={_LAPTOP: 40, _EXTERNAL: 900})

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_seen == 2
    async with maker() as db:
        ips = set((await db.scalars(select(HostDossier.ip))).all())
    assert ips == {_HYPERVISOR, _LAPTOP}
    await engine.dispose()


async def test_a_failed_census_pass_is_recorded_not_raised(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 1}, census_error="search_phase_execution_exception")

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_seen == 0
    assert any("search_phase_execution_exception" in e for e in summary.errors)
    # Still stamped: a broken sweep that left no trace would be re-run on the
    # next wake, five minutes later, forever.
    assert len(await _runs(maker)) == 1
    await engine.dispose()


# ---------------------------------------------------------------------------
# The durable run stamp
# ---------------------------------------------------------------------------


async def test_a_zero_work_sweep_still_stamps_a_run(settings_kratos: Settings) -> None:
    """A stable network finds nothing new; the stamp is what stops a re-sweep loop."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES()

    summary = await job.run_dossier_refresh(es, maker, settings, trigger="manual")

    assert summary.hosts_seen == 0
    assert summary.hosts_built == 0
    runs = await _runs(maker)
    assert len(runs) == 1
    assert runs[0].trigger == "manual"
    assert runs[0].started_at is not None
    assert runs[0].finished_at is not None
    assert runs[0].errors is None
    stamp = await job.latest_run_started_at(maker)
    assert stamp is not None and stamp.tzinfo is not None
    await engine.dispose()


async def test_the_run_row_carries_the_sweeps_counters(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.ssh"): [_ssh_hit(_HYPERVISOR, _LINUX_BANNER)]},
    )

    summary = await job.run_dossier_refresh(es, maker, settings)

    runs = await _runs(maker)
    assert len(runs) == 1
    assert runs[0].hosts_seen == summary.hosts_seen == 1
    assert runs[0].hosts_built == summary.hosts_built == 1
    assert runs[0].fields_written == summary.fields_written > 0
    assert runs[0].conflicts_detected == 0
    assert runs[0].conflicts_prompted == 0
    await engine.dispose()


async def test_a_sweep_that_cannot_stamp_its_run_never_touches_es(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A database that will not take one insert will not take 2,400 of them.

    Discovering that after spending hundreds of Elasticsearch aggregations is
    the wrong order to find out, so the run row is claimed first.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412})

    async def _no_row(*args: Any, **kwargs: Any) -> int | None:
        return None

    monkeypatch.setattr(job, "_open_run", _no_row)

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert es.calls == []
    assert summary.errors == ["could not open a dossier_run row; sweep abandoned"]
    await engine.dispose()


async def test_the_recorded_errors_are_bounded(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A network-wide outage is one error repeated, not 200 rows of JSON."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={f"192.168.10.{n}": 40 for n in range(1, 61)})

    async def _explode(ip: str, **kwargs: Any) -> Any:
        raise RuntimeError("the grid is gone")

    monkeypatch.setattr(job, "collect_host_observations", _explode)

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_seen == 60
    assert summary.hosts_built == 0
    assert len(summary.errors) == 51
    assert summary.errors[-1].startswith("... further failures suppressed")
    # Every host still carries its own reason on its own row.
    assert (await _host_row(maker, "192.168.10.60")).build_error is not None
    await engine.dispose()


async def test_run_history_is_pruned_to_the_newest_fifty(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    base = datetime(2026, 1, 1, 12, 0)
    async with maker() as db:
        for i in range(60):
            db.add(DossierRun(started_at=base + timedelta(hours=i), trigger="schedule"))
        await db.commit()

    await job.run_dossier_refresh(_FakeES(), maker, settings)

    async with maker() as db:
        total = await db.scalar(select(func.count(DossierRun.id)))
        oldest = await db.scalar(select(func.min(DossierRun.started_at)))
    assert total == 50
    # The 11 oldest went; an operations trail, not an archive.
    assert oldest == base + timedelta(hours=11)
    await engine.dispose()


async def test_latest_run_started_at_is_none_before_the_first_sweep(
    settings_kratos: Settings,
) -> None:
    """``None`` means "never swept", which the scheduler reads as due."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    assert await job.latest_run_started_at(maker) is None
    await engine.dispose()


# ---------------------------------------------------------------------------
# Settings are read on every wake
# ---------------------------------------------------------------------------


async def test_the_master_switch_stops_the_sweep_before_it_touches_es(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos, dossier_enabled=False)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412})

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert es.calls == []
    assert summary.errors
    assert await _runs(maker) == []
    await engine.dispose()


async def test_no_internal_cidrs_is_an_error_not_a_network_wide_sweep(
    settings_kratos: Settings,
) -> None:
    """Without CIDRs "internal" is undefined; sweeping everything would be wrong."""
    settings = _settings(settings_kratos, internal_cidrs=[])
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412})

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert es.calls == []
    assert any("internal CIDR" in e for e in summary.errors)
    assert len(await _runs(maker)) == 1
    await engine.dispose()


async def test_the_batch_cap_bounds_one_sweep_and_the_rest_wait_for_the_next(
    settings_kratos: Settings,
) -> None:
    """Overflow is picked up next sweep because priority is recomputed from the
    durable ``last_built_at``, not from a cursor a restart would lose."""
    settings = _settings(settings_kratos, dossier_max_hosts_per_run=1)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412, _LAPTOP: 40})

    first = await job.run_dossier_refresh(es, maker, settings)
    assert first.hosts_seen == 2
    assert first.hosts_built == 1

    built_first = [
        ip for ip in (_HYPERVISOR, _LAPTOP) if (await _host_row(maker, ip)).last_built_at
    ]
    assert len(built_first) == 1

    second = await job.run_dossier_refresh(es, maker, settings)
    assert second.hosts_built == 1
    # Staleness-first: the never-built host goes before the one built seconds ago.
    for ip in (_HYPERVISOR, _LAPTOP):
        row = await _host_row(maker, ip)
        assert row is not None and row.last_built_at is not None
    await engine.dispose()


# ---------------------------------------------------------------------------
# One bad host cannot abort the sweep
# ---------------------------------------------------------------------------


async def test_a_per_host_failure_writes_build_error_and_the_sweep_continues(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412, _LAPTOP: 40},
        targeted={(_LAPTOP, "zeek.ssh"): [_ssh_hit(_LAPTOP, _LINUX_BANNER)]},
    )
    real = job.collect_host_observations

    async def _explode(ip: str, **kwargs: Any) -> Any:
        if ip == _HYPERVISOR:
            raise RuntimeError("elasticsearch closed the connection")
        return await real(ip, **kwargs)

    monkeypatch.setattr(job, "collect_host_observations", _explode)

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_seen == 2
    assert summary.hosts_built == 1
    assert any("elasticsearch closed the connection" in e for e in summary.errors)

    failed = await _host_row(maker, _HYPERVISOR)
    assert failed is not None
    assert failed.build_error is not None
    assert "elasticsearch closed the connection" in failed.build_error
    # A failed build still advances the staleness stamp, or this host would be
    # retried first on every sweep forever, spending the per-run host budget on
    # it while the rest of the table goes unrebuilt.
    assert failed.last_built_at is not None

    survived = await _host_row(maker, _LAPTOP)
    assert survived is not None and survived.build_error is None
    assert (await _field(maker, _LAPTOP, "os_family")).inferred_value == "linux"

    runs = await _runs(maker)
    assert runs[0].errors and len(runs[0].errors) == 1
    await engine.dispose()


async def test_a_later_clean_build_clears_the_error(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412})
    real = job.collect_host_observations

    async def _explode(ip: str, **kwargs: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(job, "collect_host_observations", _explode)
    await job.run_dossier_refresh(es, maker, settings)
    assert (await _host_row(maker, _HYPERVISOR)).build_error is not None

    monkeypatch.setattr(job, "collect_host_observations", real)
    await job.run_dossier_refresh(es, maker, settings)
    assert (await _host_row(maker, _HYPERVISOR)).build_error is None
    await engine.dispose()


# ---------------------------------------------------------------------------
# The prod: rate-limited, end to end
# ---------------------------------------------------------------------------


async def _sweep_with_override(
    settings: Settings, maker: async_sessionmaker[Any], es: _FakeES
) -> None:
    """First build, then an operator who disagrees with it about the OS."""
    await job.run_dossier_refresh(es, maker, settings)
    assert (await _field(maker, _HYPERVISOR, "os_family")).inferred_value == "linux"
    async with maker() as db:
        await store.set_override(db, _HYPERVISOR, "os_family", "windows", actor="analyst")


def _conflict_es() -> _FakeES:
    return _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.ssh"): [_ssh_hit(_HYPERVISOR, _LINUX_BANNER)]},
    )


async def test_three_disagreeing_builds_fire_exactly_one_prod(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _conflict_es()
    await _sweep_with_override(settings, maker, es)

    prompted = [(await job.run_dossier_refresh(es, maker, settings)).conflicts_prompted]
    prompted.append((await job.run_dossier_refresh(es, maker, settings)).conflicts_prompted)
    third = await job.run_dossier_refresh(es, maker, settings)
    prompted.append(third.conflicts_prompted)

    assert prompted == [0, 0, 1], "continued evidence, not the first disagreement"
    assert third.conflicts_detected == 1
    row = await _field(maker, _HYPERVISOR, "os_family")
    assert row.conflict_kind == "mismatch"
    assert row.conflict_observations == 3
    assert row.conflict_prompt_count == 1
    assert row.conflict_last_prompted_at is not None
    # The override still decides the value; the build only records what it saw.
    assert row.operator_value == "windows"
    assert row.inferred_value == "linux"
    await engine.dispose()


async def test_a_fourth_build_inside_the_interval_does_not_reprompt(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _conflict_es()
    await _sweep_with_override(settings, maker, es)
    for _ in range(3):
        await job.run_dossier_refresh(es, maker, settings)

    fourth = await job.run_dossier_refresh(es, maker, settings)

    assert fourth.conflicts_detected == 1
    assert fourth.conflicts_prompted == 0
    row = await _field(maker, _HYPERVISOR, "os_family")
    assert row.conflict_observations == 4
    assert row.conflict_prompt_count == 1
    await engine.dispose()


async def test_agreement_resets_the_conflict_but_keeps_the_prompt_history(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _conflict_es()
    await _sweep_with_override(settings, maker, es)
    for _ in range(3):
        await job.run_dossier_refresh(es, maker, settings)
    assert (await _field(maker, _HYPERVISOR, "os_family")).conflict_prompt_count == 1

    # The network changed under the override: the host now answers with a Windows
    # SSH banner, which is what the operator said all along.
    es.targeted[(_HYPERVISOR, "zeek.ssh")] = [_ssh_hit(_HYPERVISOR, _WINDOWS_BANNER)]
    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.conflicts_detected == 0
    row = await _field(maker, _HYPERVISOR, "os_family")
    assert row.inferred_value == "windows"
    assert row.conflict_first_seen_at is None
    assert row.conflict_observations == 0
    assert row.conflict_kind is None
    # History is kept: a second disagreement backs off from where the first
    # ended rather than nagging from scratch.
    assert row.conflict_prompt_count == 1
    await engine.dispose()


async def test_a_snooze_doubles_per_prompt_and_keeps_the_sweep_quiet(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _conflict_es()
    await _sweep_with_override(settings, maker, es)
    for _ in range(3):
        await job.run_dossier_refresh(es, maker, settings)

    when = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    async with maker() as db:
        row = await store.snooze_conflict(
            db,
            _HYPERVISOR,
            "os_family",
            now=when,
            interval_hours=settings.dossier_conflict_prompt_interval_hours,
        )
    assert row is not None and row.conflict_snoozed_until is not None
    # One prod so far → 336h * 2**1 = 28 days.
    assert row.conflict_snoozed_until - when.replace(tzinfo=None) == timedelta(days=28)

    summary = await job.run_dossier_refresh(es, maker, settings)
    assert summary.conflicts_detected == 1, "the disagreement is still real"
    assert summary.conflicts_prompted == 0, "but the operator bought silence"
    after = await _field(maker, _HYPERVISOR, "os_family")
    assert after.conflict_prompt_count == 1
    await engine.dispose()


async def test_the_snooze_backoff_caps_at_ninety_days(settings_kratos: Settings) -> None:
    """The nag decays, but a standing disagreement is re-raised within a quarter."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _conflict_es()
    await _sweep_with_override(settings, maker, es)
    for _ in range(3):
        await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        row = await store.get_field(db, _HYPERVISOR, "os_family")
        assert row is not None
        row.conflict_prompt_count = 6  # answered the same question six times
        await db.commit()
    when = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)
    async with maker() as db:
        snoozed = await store.snooze_conflict(
            db,
            _HYPERVISOR,
            "os_family",
            now=when,
            interval_hours=settings.dossier_conflict_prompt_interval_hours,
        )
    assert snoozed is not None and snoozed.conflict_snoozed_until is not None
    # 336h * 2**min(6, 4) is 224 days uncapped; the ceiling brings it back to 90.
    assert snoozed.conflict_snoozed_until - when.replace(tzinfo=None) == timedelta(days=90)
    await engine.dispose()


async def test_the_operators_thresholds_are_read_on_every_sweep(
    settings_kratos: Settings,
) -> None:
    """Hot settings are only hot if the job re-reads them; a cached knob is a lie."""
    settings = _settings(settings_kratos, dossier_conflict_min_observations=1)
    engine, maker = await _db(settings)
    es = _conflict_es()
    await _sweep_with_override(settings, maker, es)

    first = await job.run_dossier_refresh(es, maker, settings)
    assert first.conflicts_prompted == 1

    # Prodding turned off mid-life: the disagreement is still counted, but the
    # operator is not asked again.
    settings.dossier_conflict_prompt_interval_hours = 0
    second = await job.run_dossier_refresh(es, maker, settings)
    assert second.conflicts_detected == 1
    assert second.conflicts_prompted == 0
    assert (await _field(maker, _HYPERVISOR, "os_family")).conflict_prompt_count == 1
    await engine.dispose()


# ---------------------------------------------------------------------------
# What a build writes on the host row
# ---------------------------------------------------------------------------


async def test_a_build_stamps_identity_and_lifetime_on_the_host_row(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )

    await job.run_dossier_refresh(es, maker, settings)

    row = await _host_row(maker, _HYPERVISOR)
    assert row is not None
    assert row.first_seen == _FIRST_SEEN.replace(tzinfo=None)
    assert row.last_seen == _LAST_SEEN.replace(tzinfo=None)
    assert row.last_observed_at == _LAST_SEEN.replace(tzinfo=None)
    assert row.event_count == 3412
    # Per-component digests joined, NOT one hash over both: the two halves have
    # to stay independently comparable or a component ageing out reads as a
    # different machine (see the rebind tests below).
    expected = ":".join(
        hashlib.sha256(part).hexdigest()[:16] for part in (b"pve01", b"aa:bb:cc:dd:ee:01")
    )
    assert row.identity_fingerprint == expected
    assert row.identity_rebound_at is None
    await engine.dispose()


async def test_a_host_with_no_identity_signal_never_looks_rebound(
    settings_kratos: Settings,
) -> None:
    """Silence is not evidence that the machine behind the address changed.

    A fingerprint over two empty strings would be identical for every headless
    host on the grid, and the first DHCP lease one of them ever emitted would
    read as "a different machine now holds this address".
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412})

    await job.run_dossier_refresh(es, maker, settings)
    assert (await _host_row(maker, _HYPERVISOR)).identity_fingerprint is None

    es.targeted[(_HYPERVISOR, "zeek.dhcp")] = [_dhcp_hit(_HYPERVISOR, "pve01")]
    await job.run_dossier_refresh(es, maker, settings)

    row = await _host_row(maker, _HYPERVISOR)
    assert row is not None and row.identity_fingerprint is not None
    assert row.identity_rebound_at is None
    await engine.dispose()


async def test_a_different_machine_on_the_address_stamps_the_rebind(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )
    await job.run_dossier_refresh(es, maker, settings)

    es.targeted[(_HYPERVISOR, "zeek.dhcp")] = [
        _dhcp_hit(_HYPERVISOR, "laptop-7", mac="aa:bb:cc:dd:ee:99")
    ]
    await job.run_dossier_refresh(es, maker, settings)

    row = await _host_row(maker, _HYPERVISOR)
    assert row is not None and row.identity_rebound_at is not None
    await engine.dispose()


# ---------------------------------------------------------------------------
# Feeding the egress sanitizer
# ---------------------------------------------------------------------------


async def test_first_party_hostnames_are_proposed_not_activated(
    settings_kratos: Settings,
) -> None:
    """A DHCP hostname is ATTACKER-CHOSEN input, so it is suggested, never applied.

    Internal identifiers drive egress redaction. Upserting a name the sweep read
    out of a DHCP request as ``active`` makes redaction policy writable by
    anyone who can pick their own lease hostname — the same suggest-first rule
    discovery already applies to every candidate it cannot corroborate.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )

    await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        rows = await list_identifiers(db)
    hosts = {r.value: r for r in rows if r.kind == "host"}
    assert "pve01" in hosts
    assert hosts["pve01"].state == "muted", "a proposal awaiting review, not live policy"
    assert hosts["pve01"].source == "detected"
    assert hosts["pve01"].evidence["source"] == "host_dossier"
    assert hosts["pve01"].evidence["ip"] == _HYPERVISOR
    await engine.dispose()


async def test_an_operators_activation_survives_the_next_sweep(
    settings_kratos: Settings,
) -> None:
    """Suggest-first only works if accepting the suggestion sticks."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )
    await job.run_dossier_refresh(es, maker, settings)
    async with maker() as db:
        proposed = next(r for r in await list_identifiers(db) if r.kind == "host")
        await set_state(db, proposed.id, "active")

    await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        rows = await list_identifiers(db)
    assert {r.value: r.state for r in rows if r.kind == "host"}["pve01"] == "active"
    await engine.dispose()


async def test_a_name_the_host_did_not_announce_is_not_pushed(
    settings_kratos: Settings,
) -> None:
    """A PTR answer is a WEAK telemetry name, and weak names reach no prompt.

    The boundary inside the telemetry rung, not around it: the DNS consensus is
    proposed (see the muted-suggestion test below) because it is strong enough
    for the resolver to show and therefore reaches the model. A PTR answer
    resolves at 0.5, under the 0.6 confidence floor, so it renders nowhere —
    there is no egress gap to close, and it stays out of the review queue.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={
            (_HYPERVISOR, "ptr"): [
                {
                    "@timestamp": _iso(_LAST_SEEN),
                    "event.dataset": "zeek.dns",
                    "dns.resolved_ip": "reverse-name.example",
                }
            ]
        },
    )

    await job.run_dossier_refresh(es, maker, settings)

    assert (await _field(maker, _HYPERVISOR, "hostname")).inferred_value == "reverse-name.example"
    async with maker() as db:
        rows = await list_identifiers(db)
    assert [r for r in rows if r.kind == "host"] == []
    await engine.dispose()


async def test_a_protocol_artifact_never_becomes_a_redaction_rule(
    settings_kratos: Settings,
) -> None:
    """``WORKGROUP`` as a redaction rule would rewrite unrelated prose."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "WORKGROUP")]},
    )

    await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        rows = await list_identifiers(db)
    assert [r for r in rows if r.kind == "host"] == []
    await engine.dispose()


# ---------------------------------------------------------------------------
# Table cap
# ---------------------------------------------------------------------------


async def test_the_sweep_prunes_the_table_to_the_configured_cap(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos, dossier_max_hosts=1)
    engine, maker = await _db(settings)
    async with maker() as db:
        await store.upsert_host(db, "192.168.10.5", last_seen=datetime(2026, 1, 1))
        await db.commit()
    es = _FakeES(src={_HYPERVISOR: 3412})

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_pruned == 1
    async with maker() as db:
        ips = set((await db.scalars(select(HostDossier.ip))).all())
    assert ips == {_HYPERVISOR}
    await engine.dispose()


# ---------------------------------------------------------------------------
# The prod has to be DELIVERED, not just counted
# ---------------------------------------------------------------------------


async def test_the_prod_that_fires_reaches_the_audit_log(settings_kratos: Settings) -> None:
    """A prod that only increments a counter is not a prod.

    ``conflict_last_prompted_at`` and ``conflict_prompt_count`` advance on the
    build that fires, which burns the 14-day rate limit and escalates the "keep
    mine" backoff. If nothing is emitted, the first question the operator is
    ever actually asked already carries a 90-day snooze.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _conflict_es()
    audit = _RecordingAudit()
    await _sweep_with_override(settings, maker, es)

    for _ in range(2):
        await job.run_dossier_refresh(es, maker, settings, audit=audit)
    assert audit.events == [], "the first two disagreements are not yet a prod"

    third = await job.run_dossier_refresh(es, maker, settings, audit=audit)

    assert third.conflicts_prompted == 1
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event["kind"] == "dossier_conflict_nudge"
    assert event["session_id"] == f"dossier:{_HYPERVISOR}"
    payload = event["payload"]
    assert payload["ip"] == _HYPERVISOR
    assert payload["field"] == "os_family"
    assert payload["action"] == "raised"
    assert payload["conflict_kind"] == "mismatch"
    assert payload["operator_value"] == "windows"
    assert payload["inferred_value"] == "linux"
    assert payload["observations"] == 3
    assert payload["prompt_count"] == 1

    # A fourth build inside the interval fires no prod, so it emits nothing.
    await job.run_dossier_refresh(es, maker, settings, audit=audit)
    assert len(audit.events) == 1
    await engine.dispose()


async def test_a_broken_audit_index_does_not_break_the_sweep(settings_kratos: Settings) -> None:
    """The field write is already committed; losing the audit line is the lesser loss."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _conflict_es()
    audit = _RecordingAudit(fail=True)
    await _sweep_with_override(settings, maker, es)
    for _ in range(2):
        await job.run_dossier_refresh(es, maker, settings, audit=audit)

    third = await job.run_dossier_refresh(es, maker, settings, audit=audit)

    assert third.conflicts_prompted == 1
    assert (await _field(maker, _HYPERVISOR, "os_family")).conflict_prompt_count == 1
    await engine.dispose()


# ---------------------------------------------------------------------------
# An outage is not evidence of absence
# ---------------------------------------------------------------------------


async def test_an_es_outage_does_not_retract_what_the_dossier_knows(
    settings_kratos: Settings,
) -> None:
    """A build that could not QUERY must not look like one that found nothing.

    Every search failing fast is indistinguishable from a silent host unless the
    sweep says so, and the inference write would then stamp
    ``inferred_retracted_at`` across the whole network — one bad night wiping
    what the system knew about every asset.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )
    await job.run_dossier_refresh(es, maker, settings)
    assert (await _field(maker, _HYPERVISOR, "hostname")).inferred_value == "pve01"

    es.search_error = "connection_error: [Errno 111] Connection refused"
    summary = await job.run_dossier_refresh(es, maker, settings)

    row = await _field(maker, _HYPERVISOR, "hostname")
    assert row.inferred_value == "pve01", "the name is not gone; the grid is"
    assert row.inferred_retracted_at is None
    assert summary.hosts_built == 0
    host = await _host_row(maker, _HYPERVISOR)
    assert host is not None and host.build_error is not None
    assert "could not observe" in host.build_error
    # The stamp still advances, or this host is retried first on every sweep
    # for as long as the outage lasts, starving every host still waiting.
    assert host.last_built_at is not None
    await engine.dispose()


async def test_a_host_that_genuinely_went_quiet_is_still_retracted(
    settings_kratos: Settings,
) -> None:
    """The guard must not become a licence to keep stale beliefs forever.

    A sweep whose searches all SUCCEED and return nothing is evidence of
    absence, and the belief is retracted exactly as before.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )
    await job.run_dossier_refresh(es, maker, settings)
    assert (await _field(maker, _HYPERVISOR, "hostname")).inferred_value == "pve01"

    es.targeted.clear()
    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_built == 1
    row = await _field(maker, _HYPERVISOR, "hostname")
    assert row.inferred_value is None
    assert row.inferred_retracted_at is not None
    await engine.dispose()


# ---------------------------------------------------------------------------
# The identity fingerprint must not flap
# ---------------------------------------------------------------------------


async def test_a_signal_ageing_out_of_the_window_is_not_a_rebind(
    settings_kratos: Settings,
) -> None:
    """THE flap: a 30-day DHCP lease against a 14-day window.

    Hashing ``hostname|mac`` as one string made either half dropping to "" a
    whole-fingerprint change, so the value oscillated between two non-null
    hashes and ``identity_rebound_at`` was re-stamped on every flap — a
    perpetual "different machine" prod an operator can never settle.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )
    await job.run_dossier_refresh(es, maker, settings)
    first = await _host_row(maker, _HYPERVISOR)
    assert first is not None and first.identity_fingerprint is not None

    # The MAC ages out of the window; the name is still announced.
    es.targeted[(_HYPERVISOR, "zeek.dhcp")] = [_dhcp_hit(_HYPERVISOR, "pve01", mac=None)]
    await job.run_dossier_refresh(es, maker, settings)
    faded = await _host_row(maker, _HYPERVISOR)
    assert faded is not None
    assert faded.identity_rebound_at is None, "absence of a signal is not a rebind"
    assert faded.identity_fingerprint == first.identity_fingerprint

    # …and it comes back on the next lease renewal.
    es.targeted[(_HYPERVISOR, "zeek.dhcp")] = [_dhcp_hit(_HYPERVISOR, "pve01")]
    await job.run_dossier_refresh(es, maker, settings)
    back = await _host_row(maker, _HYPERVISOR)
    assert back is not None and back.identity_rebound_at is None
    await engine.dispose()


async def test_a_hostname_that_only_changed_case_is_not_a_rebind(
    settings_kratos: Settings,
) -> None:
    """``PVE01`` and ``pve01`` are one machine; the classifier does not fold case."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )
    await job.run_dossier_refresh(es, maker, settings)

    es.targeted[(_HYPERVISOR, "zeek.dhcp")] = [
        _dhcp_hit(_HYPERVISOR, "PVE01", mac="AA:BB:CC:DD:EE:01")
    ]
    await job.run_dossier_refresh(es, maker, settings)

    row = await _host_row(maker, _HYPERVISOR)
    assert row is not None and row.identity_rebound_at is None
    await engine.dispose()


async def test_a_spent_rebind_stamp_ages_out(settings_kratos: Settings) -> None:
    """Nothing ever cleared ``identity_rebound_at``, so one address reuse left
    "a different machine may hold this address" on the entity card forever."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )
    await job.run_dossier_refresh(es, maker, settings)
    es.targeted[(_HYPERVISOR, "zeek.dhcp")] = [
        _dhcp_hit(_HYPERVISOR, "laptop-7", mac="aa:bb:cc:dd:ee:99")
    ]
    await job.run_dossier_refresh(es, maker, settings)
    assert (await _host_row(maker, _HYPERVISOR)).identity_rebound_at is not None

    # Push the stamp past the observation window: no query the builder makes
    # can still see the evidence that raised it.
    async with maker() as db:
        row = await db.scalar(select(HostDossier).where(HostDossier.ip == _HYPERVISOR))
        row.identity_rebound_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=40)
        await db.commit()

    await job.run_dossier_refresh(es, maker, settings)

    assert (await _host_row(maker, _HYPERVISOR)).identity_rebound_at is None
    await engine.dispose()


async def test_an_unanswered_rebind_is_never_aged_out(settings_kratos: Settings) -> None:
    """Ageing out a rebind the operator has not answered would lose the question."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )
    await job.run_dossier_refresh(es, maker, settings)
    async with maker() as db:
        await store.set_override(db, _HYPERVISOR, "os_family", "windows", actor="analyst")
    es.targeted[(_HYPERVISOR, "zeek.dhcp")] = [
        _dhcp_hit(_HYPERVISOR, "laptop-7", mac="aa:bb:cc:dd:ee:99")
    ]
    await job.run_dossier_refresh(es, maker, settings)

    # Both stamps backdated, keeping the override OLDER than the rebind — the
    # shape that makes `_conflict_kind` answer "rebound".
    stale = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=40)
    async with maker() as db:
        host = await db.scalar(select(HostDossier).where(HostDossier.ip == _HYPERVISOR))
        host.identity_rebound_at = stale
        field_row = await store.get_field(db, _HYPERVISOR, "os_family")
        field_row.operator_set_at = stale - timedelta(days=10)
        await db.commit()

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.conflicts_detected >= 1
    assert (await _host_row(maker, _HYPERVISOR)).identity_rebound_at == stale
    await engine.dispose()


# ---------------------------------------------------------------------------
# Census reach: what the sweep can and cannot see
# ---------------------------------------------------------------------------


async def test_the_census_bucket_cap_follows_the_host_cap(settings_kratos: Settings) -> None:
    """A fixed 2,000 buckets silently capped the census under a 5,000-host table."""
    settings = _settings(settings_kratos, dossier_max_hosts=5000)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412})

    await job.run_dossier_refresh(es, maker, settings)

    census = next(c for c in es.calls if c["kind"] == "census")
    assert census["aggs"]["src"]["terms"]["size"] == 5000
    assert census["aggs"]["dst"]["terms"]["size"] == 5000
    await engine.dispose()


async def test_a_truncated_census_is_reported_not_silent(settings_kratos: Settings) -> None:
    """ES drops the overflow buckets silently, and they are the QUIETEST hosts —
    the ones an analyst has no other context for."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412}, census_other=41_000)

    summary = await job.run_dossier_refresh(es, maker, settings)

    # A truncated cap is a NOTE, not a failure: it lands in the notes channel and
    # never in errors, so a healthy-but-capped sweep does not report an error
    # count every night (the level-triggered-noise class fixed for alarms).
    assert summary.errors == []
    assert any("census truncated" in n for n in summary.notes)
    runs = await _runs(maker)
    assert runs[0].errors is None
    assert runs[0].notes and any("census truncated" in n for n in runs[0].notes)
    await engine.dispose()


async def test_a_network_the_cadence_cannot_keep_fresh_says_so(
    settings_kratos: Settings,
) -> None:
    """Past ``max_hosts_per_run x sweeps-per-staleness-window`` some host is
    always outside the gate, and its dossier resolves to "stale" while every
    screen still says the feature is on."""
    settings = _settings(
        settings_kratos,
        dossier_max_hosts_per_run=1,
        dossier_schedule_interval_hours=24,
        dossier_staleness_hours=72,
    )
    engine, maker = await _db(settings)
    es = _FakeES(src={f"192.168.10.{n}": 40 for n in range(1, 8)})

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_seen == 7
    # A throughput ceiling is an advisory, not a failure — it belongs in notes.
    assert not any("cannot keep" in e for e in summary.errors)
    assert any("cannot keep" in n for n in summary.notes)
    await engine.dispose()


# ---------------------------------------------------------------------------
# The hostlog lane: the network's agents, once per sweep.
#
# The shapes here are the live network's, scrubbed: every machine self-reports a
# pile of addresses, and the container bridge gateway is claimed by more than
# one of them. Two properties decide whether the lane is safe to leave running:
# the inventory is fetched ONCE for the network (not once per host), and a
# machine that self-reports gets a dossier even when the wire has nothing to say
# about it — which is the entire point, because the quiet machine is the one
# nobody could name.
# ---------------------------------------------------------------------------

_QUIET_VM = "192.168.60.226"  # a handful of auth events, no services, no chatter
_BRIDGE = "172.17.0.1"  # every container host reports this one as its own

_HOSTLOG_DATASETS = ("system.auth", "system.syslog")
_GRID_WITH_HOST_LOGS = (*_GRID_DATASETS, *_HOSTLOG_DATASETS)

_AGENT_FIRST = datetime(2026, 7, 25, 6, 0, tzinfo=UTC)
_AGENT_LAST = datetime(2026, 8, 8, 12, 24, 35, tzinfo=UTC)


def _agent_bucket(
    name: str,
    ips: list[str],
    *,
    macs: list[str] | None = None,
    docs: int = 6175,
) -> dict[str, Any]:
    """One `host.name` bucket: the claim list plus the newest self-report."""
    return {
        "key": name,
        "doc_count": docs,
        "ips": {"buckets": [{"key": ip, "doc_count": docs} for ip in ips]},
        "first_report": {"value": float(_ms(_AGENT_FIRST)), "value_as_string": _iso(_AGENT_FIRST)},
        "last_report": {"value": float(_ms(_AGENT_LAST)), "value_as_string": _iso(_AGENT_LAST)},
        "latest": {
            "hits": {
                "hits": [
                    {
                        "_id": f"a-{name}",
                        "_source": {
                            "@timestamp": _iso(_AGENT_LAST),
                            "agent": {"type": "filebeat", "version": "9.3.7"},
                            "host": {
                                "name": name,
                                "ip": ips,
                                "mac": macs if macs is not None else ["52-54-00-12-34-56"],
                                "architecture": "x86_64",
                                "os": {
                                    "name": "Debian GNU/Linux",
                                    "family": "debian",
                                    "version": "13 (trixie)",
                                    "kernel": "7.0.12-1-pve",
                                    "platform": "debian",
                                    "type": "linux",
                                },
                            },
                        },
                    }
                ]
            }
        },
    }


_NETWORK_AGENTS = [
    _agent_bucket("pve-a", [_HYPERVISOR, _BRIDGE, "fe80::5054:ff:fe12:3456"], docs=14024),
    _agent_bucket("quiet-vm", [_QUIET_VM, "fe80::5054:ff:feaa:1"]),
    _agent_bucket("buildbox", ["192.168.10.172", _BRIDGE], docs=269998),
]


async def test_the_agent_inventory_is_one_aggregation_for_the_whole_sweep(
    settings_kratos: Settings,
) -> None:
    """Once per sweep, not once per host — every host gets the same slice.

    A per-host version would add one network-wide aggregation per address built,
    for an answer that does not vary by address.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412, _LAPTOP: 40},
        grid_datasets=_GRID_WITH_HOST_LOGS,
        agents=_NETWORK_AGENTS,
    )

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_built >= 2
    assert len([c for c in es.calls if c["kind"] == "agent"]) == 1
    await engine.dispose()


async def test_a_machine_that_only_self_reports_still_gets_a_dossier(
    settings_kratos: Settings,
) -> None:
    """The pivot-incident payoff: the QUIET machine is the one worth naming.

    `quiet-vm` never appears in the network census — it answers nothing and
    initiates almost nothing — so before the hostlog lane it had no dossier row
    at all, and an investigation naming its address had nothing to resolve.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        grid_datasets=_GRID_WITH_HOST_LOGS,
        agents=_NETWORK_AGENTS,
    )

    summary = await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        ips = set((await db.scalars(select(HostDossier.ip))).all())
    assert _QUIET_VM in ips, "a self-reporting host is a network member"
    assert summary.hosts_seen == 3  # the hypervisor, the build box, the quiet VM
    hostname = await _field(maker, _QUIET_VM, "hostname")
    assert hostname.inferred_value == "quiet-vm"
    assert hostname.inferred_source == "hostlog"
    # Its lifetime comes from its own reports, not from a network sighting it
    # never made — and that is also what keeps it out of the prune's sights.
    row = await _host_row(maker, _QUIET_VM)
    assert row is not None and row.last_seen == _AGENT_LAST.replace(tzinfo=None)
    await engine.dispose()


async def test_a_self_reported_hostname_outranks_the_wire_and_reaches_the_store(
    settings_kratos: Settings,
) -> None:
    """The disagreement live on the incident host: DHCP says one name, the agent another."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        grid_datasets=_GRID_WITH_HOST_LOGS,
        agents=_NETWORK_AGENTS,
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )

    await job.run_dossier_refresh(es, maker, settings)

    row = await _field(maker, _HYPERVISOR, "hostname")
    assert row.inferred_value == "pve-a"
    assert row.inferred_source == "hostlog"
    # The loser is kept, under its own key: the evidence map is source-keyed.
    assert "pve01 (from dhcp)" in row.inferred_evidence["hostlog"]["strings"]
    os_family = await _field(maker, _HYPERVISOR, "os_family")
    assert (os_family.inferred_value, os_family.inferred_source) == ("linux", "hostlog")
    await engine.dispose()


async def test_a_self_reported_hostname_is_proposed_to_the_identifier_store(
    settings_kratos: Settings,
) -> None:
    """An agent's name is a first-party claim, so it feeds redaction policy too.

    Muted, like every other first-party name: these become egress-redaction
    rules, and a name is a name whether a DHCP client or an agent supplied it.
    Without this the lane would silently REMOVE the proposal on any host where
    it outranks the DHCP name — the newly-named machines are exactly the ones
    whose names most need redacting.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        grid_datasets=_GRID_WITH_HOST_LOGS,
        agents=_NETWORK_AGENTS,
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )

    await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        hosts = {r.value: r for r in await list_identifiers(db) if r.kind == "host"}
    assert "pve-a" in hosts
    assert hosts["pve-a"].state == "muted"
    assert hosts["pve-a"].evidence["ip"] == _HYPERVISOR
    await engine.dispose()


async def test_an_address_two_agents_claim_is_named_by_neither(
    settings_kratos: Settings,
) -> None:
    """The container bridge gateway: two machines report it, so it gets no name.

    Believing either one would make this dossier flap between two identities
    from sweep to sweep — and every flap re-stamps `identity_rebound_at` and
    prods the operator about a machine swap that never happened.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_BRIDGE: 3412},
        grid_datasets=_GRID_WITH_HOST_LOGS,
        agents=_NETWORK_AGENTS,
    )

    await job.run_dossier_refresh(es, maker, settings)

    row = await _field(maker, _BRIDGE, "hostname")
    assert row.inferred_value is None
    # …and the dossier says WHY, rather than looking like an address nobody has
    # ever reported.
    strings = row.inferred_evidence["banner"]["strings"]
    assert any("2 host-log agents claim" in line for line in strings)
    # Neither claimant's name became a redaction rule ATTRIBUTED to the shared
    # address (both machines are still named on their own rows).
    async with maker() as db:
        named = [r for r in await list_identifiers(db) if r.kind == "host"]
    assert [r.value for r in named if r.evidence.get("ip") == _BRIDGE] == []
    await engine.dispose()


async def test_a_grid_without_host_logs_sweeps_exactly_as_it_did_before(
    settings_kratos: Settings,
) -> None:
    """A network-only deployment must not pay for the lane, or notice it.

    No aggregation is issued, no host-log evidence appears, and the wire keeps
    the field: the dataset inventory already knows the datasets are absent, and
    absent reads as "no signal".
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        agents=_NETWORK_AGENTS,  # present, but this grid carries no host logs
        targeted={(_HYPERVISOR, "zeek.dhcp"): [_dhcp_hit(_HYPERVISOR, "pve01")]},
    )

    await job.run_dossier_refresh(es, maker, settings)

    assert [c for c in es.calls if c["kind"] == "agent"] == []
    row = await _field(maker, _HYPERVISOR, "hostname")
    assert (row.inferred_value, row.inferred_source) == ("pve01", "banner")
    assert set(row.inferred_evidence) == {"banner"}
    await engine.dispose()


# ---------------------------------------------------------------------------
# The DNS-name lane — naming the hosts no other lane can see.
# ---------------------------------------------------------------------------

_PRINTER = "192.168.10.61"  # answers nothing, ships nothing, but DNS knows it

# Deliberately WIDER than the network census window on both ends, so a lifetime
# that did not take the answer span into account is visible as a failure rather
# than as a coincidence.
_DNS_FIRST = datetime(2026, 7, 20, 4, 30, tzinfo=UTC)
_DNS_LAST = datetime(2026, 8, 8, 11, 5, tzinfo=UTC)


def _dns_bucket(name: str, answers: dict[str, int]) -> dict[str, Any]:
    """One query-name bucket: the answer addresses it resolved to, and how often."""
    return {
        "key": name,
        "doc_count": sum(answers.values()),
        "ips": {
            "buckets": [
                {
                    "key": ip,
                    "doc_count": count,
                    "first_answer": {
                        "value": float(_ms(_DNS_FIRST)),
                        "value_as_string": _iso(_DNS_FIRST),
                    },
                    "last_answer": {
                        "value": float(_ms(_DNS_LAST)),
                        "value_as_string": _iso(_DNS_LAST),
                    },
                }
                for ip, count in answers.items()
            ]
        },
    }


_NETWORK_DNS = [
    _dns_bucket("pve-a-dns.lab.internal", {_HYPERVISOR: 214}),
    _dns_bucket("printer-1.lab.internal", {_PRINTER: 12}),
    # Public answers dwarf internal ones on a real grid and must name nothing.
    _dns_bucket("cdn.example.net", {"203.0.113.20": 9001}),
]


async def test_a_host_only_dns_can_name_still_gets_a_dossier_row(
    settings_kratos: Settings,
) -> None:
    """The complaint this lane was built for: hostname blank almost everywhere.

    A printer answers nothing, initiates almost nothing and ships no logs, so
    neither the network census nor the hostlog lane produces a name for it — or,
    before this, a row. The network's own DNS knows exactly what it is called.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412}, dns=_NETWORK_DNS)

    summary = await job.run_dossier_refresh(es, maker, settings, trigger="manual")

    async with maker() as db:
        ips = set((await db.scalars(select(HostDossier.ip))).all())
    assert _PRINTER in ips, "a host the network's DNS names is a network member"
    assert summary.hosts_seen == 2  # the hypervisor, and the printer DNS found
    hostname = await _field(maker, _PRINTER, "hostname")
    assert hostname.inferred_value == "printer-1.lab.internal"
    assert hostname.inferred_source == "telemetry"
    # Its lifetime comes from the answers that named it, not from a network
    # sighting it never made — which is also what keeps it out of the prune.
    row = await _host_row(maker, _PRINTER)
    assert row is not None and row.last_seen == _DNS_LAST.replace(tzinfo=None)
    assert row.first_seen == _DNS_FIRST.replace(tzinfo=None)
    # A public answer target is never adopted, whatever its volume.
    assert "203.0.113.20" not in ips
    await engine.dispose()


async def test_the_dns_name_pass_is_one_aggregation_for_the_whole_sweep(
    settings_kratos: Settings,
) -> None:
    """Once per sweep, not once per host — the cost model of the lane."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412, _LAPTOP: 40}, dns=_NETWORK_DNS)

    summary = await job.run_dossier_refresh(es, maker, settings)

    assert summary.hosts_built >= 2
    assert len([c for c in es.calls if c["kind"] == "dns"]) == 1
    await engine.dispose()


async def test_a_self_reported_name_outranks_the_dns_name_in_the_store(
    settings_kratos: Settings,
) -> None:
    """Both lanes name the hypervisor; the machine's own account wins the field.

    An address can be re-pointed at a different machine without that machine
    knowing, so the ladder — not a tiebreak — settles this.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        grid_datasets=_GRID_WITH_HOST_LOGS,
        agents=_NETWORK_AGENTS,
        dns=_NETWORK_DNS,
    )

    await job.run_dossier_refresh(es, maker, settings)

    row = await _field(maker, _HYPERVISOR, "hostname")
    assert row.inferred_value == "pve-a"
    assert row.inferred_source == "hostlog"
    # The loser is kept, under the winning rung's key: the map is source-keyed.
    assert any(
        "pve-a-dns.lab.internal" in line for line in row.inferred_evidence["hostlog"]["strings"]
    )
    await engine.dispose()


async def test_a_dns_name_is_proposed_as_a_muted_redaction_suggestion(
    settings_kratos: Settings,
) -> None:
    """A name the model will be told has to be a name the guard can be taught.

    Whether DNS names the HOST or only the ADDRESS is a question about identity
    correctness, and the ladder already answers it — `telemetry` sits under
    `banner` and `hostlog`, and a machine's own claim wins the field. REDACTION
    is a different question, and it has a different answer: this lane names
    roughly the whole previously-nameless population, those names go into
    investigations, both chats, the hunt planner and the hunt console seed, and
    `guard.sanitize_text` can only redact what the identifier store knows about.
    A name nobody ever proposed cannot be accepted, so on a cloud-egress
    deployment it leaves in the clear.

    Muted, exactly like a DHCP name: a suggestion an operator can accept, never
    an active rule the sweep wrote by itself.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(src={_HYPERVISOR: 3412}, dns=_NETWORK_DNS)

    await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        rows = {r.value: r for r in await list_identifiers(db) if r.kind == "host"}
    assert rows["pve-a-dns.lab.internal"].state == "muted"
    assert rows["pve-a-dns.lab.internal"].evidence["ip"] == _HYPERVISOR
    assert rows["printer-1.lab.internal"].state == "muted"
    # A public answer target names nothing and reaches no prompt: the lane never
    # adopted it as a host, so it has nothing to propose either.
    assert not [value for value in rows if value.startswith("cdn.")]
    await engine.dispose()


async def test_a_first_party_name_still_beats_the_dns_name_into_the_store(
    settings_kratos: Settings,
) -> None:
    """The proposal follows the WINNER, not every name the window offered.

    The identifier store is a review queue an operator reads. Filing every
    candidate for a host would make it a list of guesses; the dossier's own
    answer for the host is the one worth asking about.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    es = _FakeES(
        src={_HYPERVISOR: 3412},
        grid_datasets=_GRID_WITH_HOST_LOGS,
        agents=_NETWORK_AGENTS,
        dns=_NETWORK_DNS,
    )

    await job.run_dossier_refresh(es, maker, settings)

    async with maker() as db:
        named = {r.value for r in await list_identifiers(db) if r.evidence.get("ip") == _HYPERVISOR}
    assert named == {"pve-a"}
    await engine.dispose()
