"""The host sweep builds active hosts first, and a probed address is not a host.

Measured defect (production review 2026-11-12, ops finding 1, hunts finding 8,
triage finding 9). One Nmap sweep on 2026-11-07 named 1,672 addresses of seven
/24 networks as responders. The census made a host row and a machine record
for each one. The stored facts of those rows read "14 events in window across
0 outbound and 1 inbound peers", a responder byte count of 0, no name and no
agent: no machine was at those addresses.

The nightly sweep builds 200 rows, and it took the rows that no sweep had
built first. For six nights each build went to a scan row. The hosts with
alerts were last built on 2026-11-06, and from 11-10 the model read
``role: unknown [stale]`` for them.

Two changes. The census gives no row to an address that only received probes.
The build queue takes the active hosts first.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.dossier.types import DhcpLease, DhcpLeaseInventory
from soc_ai.enrichment import host_dossier as job
from soc_ai.so_client import fields
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store.auth import utcnow
from soc_ai.store.models import HostDossier, HostMachine, Investigation
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from tests.test_host_dossier_job import _db, _FakeES, _iso, _ms, _settings

_SCANNER = "192.168.10.58"
_WORKSTATION = "192.168.10.77"
_PRINTER = "192.168.10.40"
_DEAD_A = "192.168.10.201"
_DEAD_B = "192.168.10.202"


_SENSOR = "sensor-1"


class _ScanES(_FakeES):
    """The census of a grid where a scanner probed addresses with no machine.

    ``answered`` holds the responder records that show a packet from the
    address. An address absent from it never answered. ``counters`` False
    models a grid whose flow records carry no responder counter. ``non_tcp``
    holds the UDP and ICMP records that an address received. ``sensor`` is the
    sensor that wrote the records of each address, and ``answering`` holds the
    sensors that show responder traffic in the window. ``hidden_src`` holds
    addresses that originated documents which a truncated source list left
    out, and ``originator_error`` makes the targeted read of them fail.
    """

    def __init__(
        self,
        *,
        answered: dict[str, int] | None = None,
        counters: bool = True,
        recent: tuple[str, ...] = (),
        non_tcp: dict[str, int] | None = None,
        sensor: str | None = _SENSOR,
        sensors: dict[str, str] | None = None,
        answering: tuple[str, ...] = (_SENSOR,),
        hidden_src: dict[str, int] | None = None,
        originator_error: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.answered = dict(answered or {})
        self.counters = counters
        self.recent = set(recent)
        self.non_tcp = dict(non_tcp or {})
        self.sensor = sensor
        self.sensors = dict(sensors or {})
        self.answering = answering
        self.hidden_src = dict(hidden_src or {})
        self.originator_error = originator_error
        self.originator_calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        aggs = kwargs.get("aggs") or {}
        if "originators" in aggs:
            self.originator_calls.append({"query": query, "aggs": aggs})
            if self.originator_error:
                raise RuntimeError(self.originator_error)
            return EsSearchResult(
                total=0,
                took_ms=1,
                aggregations={
                    "originators": {
                        "buckets": [
                            {"key": ip, "doc_count": n} for ip, n in self.hidden_src.items()
                        ]
                    }
                },
            )
        result = await super().search(index, query, **kwargs)
        if not {"src", "dst"} <= set(aggs):
            return result
        assert result.aggregations is not None
        now = datetime.now(UTC) - timedelta(hours=2)
        for bucket in result.aggregations["src"]["buckets"]:
            if bucket["key"] in self.recent:
                bucket["last_seen"] = {"value": float(_ms(now)), "value_as_string": _iso(now)}
        for bucket in result.aggregations["dst"]["buckets"]:
            judged = bucket["doc_count"] if self.counters else 0
            sensor = self.sensors.get(bucket["key"], self.sensor)
            named = [{"key": sensor, "doc_count": judged}] if sensor and judged else []
            bucket["judged"] = {
                "doc_count": judged,
                "sensors": {"buckets": named, "sum_other_doc_count": 0},
            }
            bucket["answered"] = {"doc_count": self.answered.get(bucket["key"], 0)}
            bucket["non_tcp"] = {"doc_count": self.non_tcp.get(bucket["key"], 0)}
        result.aggregations["answering"] = {
            "doc_count": 900 if self.answering else 0,
            "sensors": {"buckets": [{"key": name, "doc_count": 450} for name in self.answering]},
        }
        return result


async def _ips(maker: async_sessionmaker[Any]) -> set[str]:
    async with maker() as db:
        return {str(ip) for ip in (await db.scalars(select(HostDossier.ip))).all()}


async def _machine_ips(maker: async_sessionmaker[Any]) -> set[str]:
    async with maker() as db:
        rows = (await db.scalars(select(HostMachine))).all()
        return {str(row.primary_ip) for row in rows if row.primary_ip}


def _scan_grid(**kwargs: Any) -> _ScanES:
    """A scanner, a workstation, a printer that only answers, and two dead addresses."""
    return _ScanES(
        src={_SCANNER: 500, _WORKSTATION: 120},
        dst={_PRINTER: 40, _DEAD_A: 14, _DEAD_B: 18},
        answered={_PRINTER: 40},
        **kwargs,
    )


# ---------------------------------------------------------------------------
# The census: a probed address is not a host
# ---------------------------------------------------------------------------


async def test_an_address_that_only_received_probes_gets_no_row_and_no_machine(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        summary = await job.run_dossier_refresh(_scan_grid(), maker, settings)
        rows = await _ips(maker)
        assert _DEAD_A not in rows and _DEAD_B not in rows
        assert {_SCANNER, _WORKSTATION, _PRINTER} <= rows
        machines = await _machine_ips(maker)
        assert _DEAD_A not in machines and _DEAD_B not in machines
        assert summary.hosts_seen == 3
        assert any(
            note.startswith("2 address(es) only received probes and got no host record.")
            for note in summary.notes
        ), summary.notes
    finally:
        await engine.dispose()


async def test_a_host_that_only_answers_keeps_its_row(settings_kratos: Settings) -> None:
    """Negative control: a printer never originates, and it is a real host."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        await job.run_dossier_refresh(_scan_grid(), maker, settings)
        assert _PRINTER in await _ips(maker)
        assert _PRINTER in await _machine_ips(maker)
    finally:
        await engine.dispose()


async def test_an_address_that_cannot_be_measured_keeps_its_row(
    settings_kratos: Settings,
) -> None:
    """Negative control: no responder counter on the grid means no claim of silence."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        summary = await job.run_dossier_refresh(_scan_grid(counters=False), maker, settings)
        assert {_DEAD_A, _DEAD_B, _PRINTER} <= await _ips(maker)
        assert not [note for note in summary.notes if "only received probes" in note]
    finally:
        await engine.dispose()


async def test_an_existing_row_of_a_probed_address_stays(settings_kratos: Settings) -> None:
    """The change creates no row for a probed address. It deletes none."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        async with maker() as db:
            db.add(HostDossier(host_key=_DEAD_A, ip=_DEAD_A, event_count=14))
            await db.commit()
        summary = await job.run_dossier_refresh(_scan_grid(), maker, settings)
        rows = await _ips(maker)
        assert _DEAD_A in rows
        assert _DEAD_B not in rows
        assert any(note.startswith("1 address(es) only received probes") for note in summary.notes)
    finally:
        await engine.dispose()


def test_the_census_asks_the_responder_side_whether_the_address_answered() -> None:
    dst = job._endpoint_agg("destination.ip", 100, responder=True)["aggs"]
    src = job._endpoint_agg("source.ip", 100)["aggs"]
    assert {"judged", "answered", "non_tcp"} <= set(dst)
    assert not {"judged", "answered", "non_tcp"} & set(src)
    answered = dst["answered"]["filter"]["bool"]["should"]
    assert {"range": {"server.packets": {"gt": 0}}} in answered
    assert {"range": {"server.bytes": {"gt": 0}}} in answered
    # The clauses of the served-port rule: a TCP record with a responder counter.
    assert dst["judged"]["filter"] == fields.judged_record_clause()
    assert dst["judged"]["aggs"]["sensors"]["terms"]["field"] == "observer.name"
    assert dst["non_tcp"]["filter"] == {"bool": {"must_not": [fields.tcp_record_clause()]}}


def _candidate(**over: Any) -> Any:
    base: dict[str, Any] = {
        "ip": _DEAD_A,
        "events": 14,
        "judged": 14,
        "sensors": {_SENSOR},
        "sensor_answers": True,
    }
    base.update(over)
    return job._Candidate(**base)


def test_the_probe_only_rule_needs_every_test_to_hold() -> None:
    """Each kind of evidence that a machine is at the address keeps the record."""
    assert _candidate().probe_only is True
    # It sent a packet as the originator.
    assert _candidate(originated=1).probe_only is False
    # It sent a packet as the responder. One RST is enough.
    assert _candidate(answered=1).probe_only is False
    # An agent reports it.
    assert _candidate(agent=True).probe_only is False
    # A DNS answer or a DHCP lease names it.
    assert _candidate(named=True).probe_only is False
    # No record carries a responder counter, so the silence is not measured.
    assert _candidate(judged=0).probe_only is False
    # It received a UDP or an ICMP record. A UDP service can serve with no answer.
    assert _candidate(non_tcp=1).probe_only is False
    # Its sensor shows no responder traffic for any host: a one-direction capture.
    assert _candidate(sensor_answers=False).probe_only is False


def test_a_dhcp_lease_names_its_address() -> None:
    candidates = {_DEAD_A: _candidate(), _DEAD_B: _candidate(ip=_DEAD_B)}
    leases = DhcpLeaseInventory(leases=(DhcpLease(ip=_DEAD_A, mac="aa:bb:cc:dd:ee:01"),))
    job._mark_leases(leases, candidates)
    assert candidates[_DEAD_A].probe_only is False
    assert candidates[_DEAD_B].probe_only is True


# ---------------------------------------------------------------------------
# The build queue: active hosts first
# ---------------------------------------------------------------------------


async def _seed(maker: async_sessionmaker[Any], rows: list[tuple[str, datetime | None]]) -> None:
    async with maker() as db:
        for ip, built in rows:
            db.add(HostDossier(host_key=ip, ip=ip, event_count=14, last_built_at=built))
        await db.commit()


def _scan_rows(count: int) -> list[tuple[str, datetime | None]]:
    """Rows that no sweep has built: the front of a staleness-first queue."""
    return [(f"10.40.40.{n}", None) for n in range(1, count + 1)]


async def test_active_hosts_are_built_before_rows_that_no_sweep_has_built(
    settings_kratos: Settings,
) -> None:
    """The measured queue: scan rows first in staleness order, real hosts behind them."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        week_old = utcnow() - timedelta(days=6)
        real = [(f"10.20.30.{n}", week_old + timedelta(minutes=n)) for n in range(1, 6)]
        await _seed(maker, _scan_rows(30) + real)
        staleness_only = await job._due_hosts(maker, 10)
        assert not set(staleness_only) & {ip for ip, _built in real}
        due = await job._due_hosts(maker, 10, {ip for ip, _built in real})
        # The five active hosts lead, the stalest of them first.
        assert due[:5] == [ip for ip, _built in real]
        # The rest of the budget goes to the other rows, stalest first.
        assert due[5:] == [ip for ip, _built in _scan_rows(5)]
    finally:
        await engine.dispose()


async def test_quiet_hosts_keep_a_share_when_active_hosts_fill_the_sweep(
    settings_kratos: Settings,
) -> None:
    """Negative control: activity first must not starve a new quiet host for ever."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        built = utcnow() - timedelta(days=2)
        active = [(f"10.20.30.{n}", built + timedelta(minutes=n)) for n in range(1, 41)]
        await _seed(maker, active + _scan_rows(30))
        due = await job._due_hosts(maker, 20, {ip for ip, _built in active})
        assert len(due) == 20
        assert due[:18] == [ip for ip, _built in active[:18]]
        assert due[18:] == ["10.40.40.1", "10.40.40.2"]
    finally:
        await engine.dispose()


async def test_the_queue_is_staleness_first_when_no_host_is_active(
    settings_kratos: Settings,
) -> None:
    """Negative control: with no signal the order is the order it was."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        old = utcnow() - timedelta(days=9)
        await _seed(maker, [("10.20.30.1", old), ("10.20.30.2", None), ("10.20.30.3", old)])
        assert await job._due_hosts(maker, 2) == ["10.20.30.2", "10.20.30.1"]
        assert await job._due_hosts(maker, 2, set()) == ["10.20.30.2", "10.20.30.1"]
    finally:
        await engine.dispose()


async def test_a_quiet_host_with_evidence_is_built_before_a_probed_row(
    settings_kratos: Settings,
) -> None:
    """The rows of probed addresses and the rows that the census did not see go last."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        old = utcnow() - timedelta(days=8)
        quiet_real = [("10.20.30.201", old), ("10.20.30.202", old + timedelta(minutes=1))]
        await _seed(maker, _scan_rows(30) + quiet_real + [("10.20.30.1", old)])
        due = await job._due_hosts(
            maker,
            4,
            active={"10.20.30.1"},
            evidenced={"10.20.30.1", "10.20.30.201", "10.20.30.202"},
        )
        assert due == ["10.20.30.1", "10.20.30.201", "10.20.30.202", "10.40.40.1"]
    finally:
        await engine.dispose()


async def test_the_three_activity_signals(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        now = utcnow()
        async with maker() as db:
            db.add(
                Investigation(
                    id="01RECENT0000000000000000000",
                    alert_es_id="a1",
                    status="complete",
                    started_by="test",
                    src_ip="10.20.30.10",
                    dest_ip="10.20.30.11",
                    created_at=now - timedelta(days=2),
                )
            )
            db.add(
                Investigation(
                    id="01OLD00000000000000000000000",
                    alert_es_id="a2",
                    status="complete",
                    started_by="test",
                    src_ip="10.20.30.12",
                    dest_ip=None,
                    created_at=now - timedelta(days=9),
                )
            )
            db.add(
                Investigation(
                    id="01SYNTH000000000000000000000",
                    alert_es_id="a3",
                    status="complete",
                    started_by="test",
                    src_ip="10.20.30.13",
                    dest_ip=None,
                    is_synth_eval=True,
                    created_at=now - timedelta(days=1),
                )
            )
            db.add(HostDossier(host_key="10.20.30.14", ip="10.20.30.14", address_kind="agent"))
            await db.commit()
        aware_now = datetime.now(UTC)
        candidates = {
            "10.20.30.20": job._Candidate(ip="10.20.30.20", agent=True),
            "10.20.30.21": job._Candidate(
                ip="10.20.30.21", originated=5, last_originated=aware_now - timedelta(days=1)
            ),
            "10.20.30.22": job._Candidate(
                ip="10.20.30.22", originated=5, last_originated=aware_now - timedelta(days=10)
            ),
            "10.20.30.23": job._Candidate(ip="10.20.30.23", judged=14),
        }
        active = await job._active_addresses(maker, candidates, job.DossierSummary(started_at=""))
        assert active == {
            "10.20.30.10",  # an investigation in the last 7 days, as the source
            "10.20.30.11",  # and as the destination
            "10.20.30.14",  # an agent address from the last machine build
            "10.20.30.20",  # an agent address from this census
            "10.20.30.21",  # an originated event in the last 7 days
        }
    finally:
        await engine.dispose()


async def test_the_sweep_builds_the_active_host_before_the_unbuilt_rows(
    settings_kratos: Settings,
) -> None:
    """End to end, with a budget of two builds and three unbuilt rows ahead in the queue."""
    settings = _settings(settings_kratos, dossier_max_hosts_per_run=2)
    engine, maker = await _db(settings)
    try:
        await _seed(maker, [(_DEAD_A, None), (_DEAD_B, None), (_PRINTER, None)])
        es = _ScanES(
            src={_WORKSTATION: 120},
            dst={_PRINTER: 40, _DEAD_A: 14, _DEAD_B: 18},
            answered={_PRINTER: 40},
            recent=(_WORKSTATION,),
        )
        summary = await job.run_dossier_refresh(es, maker, settings)
        assert summary.hosts_built == 2
        async with maker() as db:
            built = {
                str(row.ip)
                for row in (await db.scalars(select(HostDossier))).all()
                if row.last_built_at is not None
            }
        # The workstation is the newest row, and it is the active host.
        assert _WORKSTATION in built
        assert len(built) == 2
    finally:
        await engine.dispose()


async def _simulate(
    maker: async_sessionmaker[Any],
    limit: int,
    active: set[str],
    evidenced: set[str],
    sweeps: int,
) -> dict[str, int]:
    """Run sweeps of the queue. Returns the first sweep that built each row."""
    from sqlalchemy import update

    first_built: dict[str, int] = {}
    for sweep in range(1, sweeps + 1):
        due = await job._due_hosts(maker, limit, active, evidenced)
        assert len(due) == len(set(due)) <= limit
        for ip in due:
            first_built.setdefault(ip, sweep)
        async with maker() as db:
            for start in range(0, len(due), 500):
                await db.execute(
                    update(HostDossier)
                    .where(HostDossier.ip.in_(due[start : start + 500]))
                    .values(last_built_at=utcnow() + timedelta(seconds=sweep))
                )
            await db.commit()
    return first_built


def _bound(limit: int, active: int, others: int) -> int:
    """The sweeps within which each row builds, from the two shares of the queue."""
    reserved = max(1, limit // 10)
    return max(-(-others // reserved), -(-active // (limit - reserved)))


@pytest.mark.parametrize(
    ("limit", "active", "quiet", "unseen"),
    [(200, 400, 30, 10), (200, 150, 600, 1200), (2000, 3000, 600, 400)],
)
async def test_each_row_builds_within_a_bounded_number_of_sweeps(
    settings_kratos: Settings, limit: int, active: int, quiet: int, unseen: int
) -> None:
    """A row outside the census evidence never built while 20 quiet rows had evidence.

    The reserved share went to the rows with evidence first, and they refilled
    it on each sweep. The share now goes to the stalest rows of every class.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        old = utcnow() - timedelta(days=3)
        active_rows = [(f"10.20.{n // 250}.{n % 250 + 1}", old) for n in range(active)]
        quiet_rows = [(f"10.30.{n // 250}.{n % 250 + 1}", old) for n in range(quiet)]
        unseen_rows: list[tuple[str, datetime | None]] = [
            (f"10.40.{n // 250}.{n % 250 + 1}", None) for n in range(unseen)
        ]
        await _seed(maker, active_rows + quiet_rows + unseen_rows)
        active_ips = {ip for ip, _built in active_rows}
        evidenced = active_ips | {ip for ip, _built in quiet_rows}
        bound = _bound(limit, active, quiet + unseen)
        first_built = await _simulate(maker, limit, active_ips, evidenced, bound)
        every = active_ips | {ip for ip, _b in quiet_rows} | {ip for ip, _b in unseen_rows}
        assert set(first_built) == every, f"{len(every - set(first_built))} rows never built"
        assert max(first_built.values()) <= bound
    finally:
        await engine.dispose()


async def test_the_reserved_share_takes_the_stalest_row_of_every_class(
    settings_kratos: Settings,
) -> None:
    """The measured case: active rows fill 180 and 30 quiet rows have evidence."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        old = utcnow() - timedelta(days=1)
        active_rows = [(f"10.20.{n // 250}.{n % 250 + 1}", old) for n in range(400)]
        quiet_rows = [(f"10.30.0.{n}", old) for n in range(1, 31)]
        unseen_rows: list[tuple[str, datetime | None]] = [
            (f"10.40.40.{n}", None) for n in range(1, 11)
        ]
        await _seed(maker, active_rows + quiet_rows + unseen_rows)
        active_ips = {ip for ip, _built in active_rows}
        evidenced = active_ips | {ip for ip, _built in quiet_rows}
        due = await job._due_hosts(maker, 200, active_ips, evidenced)
        assert {ip for ip, _built in unseen_rows} <= set(due)
        assert len(set(due) & active_ips) == 180
    finally:
        await engine.dispose()


@pytest.mark.parametrize("limit", [2, 5, 9])
async def test_a_small_budget_keeps_one_build_for_the_other_rows(
    settings_kratos: Settings, limit: int
) -> None:
    """A budget below ten still reserves one build, so each row has a bound."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        built = utcnow() - timedelta(days=2)
        active = [(f"10.20.30.{n}", built + timedelta(minutes=n)) for n in range(1, 21)]
        await _seed(maker, _scan_rows(10) + active)
        due = await job._due_hosts(maker, limit, {ip for ip, _built in active})
        assert due == [*(ip for ip, _built in active[: limit - 1]), "10.40.40.1"]
    finally:
        await engine.dispose()


async def test_a_budget_of_one_build_takes_the_stalest_row(settings_kratos: Settings) -> None:
    """One build cannot serve two shares. Staleness alone gives each row a bound."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        built = utcnow() - timedelta(days=2)
        await _seed(maker, [("10.20.30.1", built), ("10.40.40.1", None)])
        assert await job._due_hosts(maker, 1, {"10.20.30.1"}) == ["10.40.40.1"]
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Review of 2026-11-13: defects 3 and 4
# ---------------------------------------------------------------------------

_QUIET = "192.168.10.90"


def _truncated_grid(**kwargs: Any) -> _ScanES:
    """The source list is truncated: the documents of the quiet host did not fit."""
    return _ScanES(src={_SCANNER: 500}, dst={_QUIET: 14}, census_other=7000, **kwargs)


async def test_a_truncated_census_reads_the_candidates_as_originators_first(
    settings_kratos: Settings,
) -> None:
    """The quiet host did send documents. The truncated source list did not show them."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        grid = _truncated_grid(hidden_src={_QUIET: 3})
        summary = await job.run_dossier_refresh(grid, maker, settings)
        assert _QUIET in await _ips(maker)
        assert not [note for note in summary.notes if "only received probes" in note]
        (call,) = grid.originator_calls
        assert {"terms": {"source.ip": [_QUIET]}} in call["query"]["bool"]["filter"]
    finally:
        await engine.dispose()


async def test_a_truncated_census_still_drops_an_address_that_sent_nothing(
    settings_kratos: Settings,
) -> None:
    """Negative control: the targeted read ran and found no document from the address."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        grid = _truncated_grid()
        summary = await job.run_dossier_refresh(grid, maker, settings)
        assert _QUIET not in await _ips(maker)
        assert len(grid.originator_calls) == 1
        assert any("only received probes" in note for note in summary.notes)
    finally:
        await engine.dispose()


async def test_a_truncated_census_keeps_each_record_when_the_check_cannot_run(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        grid = _truncated_grid(originator_error="grid refused")
        summary = await job.run_dossier_refresh(grid, maker, settings)
        assert _QUIET in await _ips(maker)
        assert not [note for note in summary.notes if "only received probes" in note]
    finally:
        await engine.dispose()


async def test_a_whole_census_runs_no_targeted_read(settings_kratos: Settings) -> None:
    """Negative control: the extra search runs only for a truncated source list."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        grid = _scan_grid()
        await job.run_dossier_refresh(grid, maker, settings)
        assert grid.originator_calls == []
    finally:
        await engine.dispose()


async def test_an_address_that_received_a_udp_record_keeps_its_row(
    settings_kratos: Settings,
) -> None:
    """A syslog collector receives UDP and answers nothing. It is a real host."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        await job.run_dossier_refresh(_scan_grid(non_tcp={_DEAD_A: 3}), maker, settings)
        rows = await _ips(maker)
        assert _DEAD_A in rows
        assert _DEAD_B not in rows
    finally:
        await engine.dispose()


async def test_a_one_direction_capture_keeps_every_record(settings_kratos: Settings) -> None:
    """No sensor shows a responder packet for any host, so zero answers prove nothing."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        grid = _ScanES(src={_SCANNER: 500}, dst={_PRINTER: 40, _DEAD_A: 14}, answering=())
        summary = await job.run_dossier_refresh(grid, maker, settings)
        assert {_PRINTER, _DEAD_A} <= await _ips(maker)
        assert not [note for note in summary.notes if "only received probes" in note]
    finally:
        await engine.dispose()


async def test_the_rule_needs_responder_traffic_at_the_same_sensor(
    settings_kratos: Settings,
) -> None:
    """Two sensors. The one that saw the address shows no responder traffic at all."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        grid = _ScanES(
            src={_SCANNER: 500},
            dst={_DEAD_A: 14, _DEAD_B: 18},
            sensors={_DEAD_A: "sensor-one-way", _DEAD_B: _SENSOR},
            answering=(_SENSOR,),
        )
        await job.run_dossier_refresh(grid, maker, settings)
        rows = await _ips(maker)
        assert _DEAD_A in rows
        assert _DEAD_B not in rows
    finally:
        await engine.dispose()


async def test_records_with_no_sensor_name_keep_the_record(settings_kratos: Settings) -> None:
    """The rule cannot find the sensor of the records, so it does not apply."""
    settings = _settings(settings_kratos)
    engine, maker = await _db(settings)
    try:
        grid = _ScanES(src={_SCANNER: 500}, dst={_DEAD_A: 14}, sensor=None)
        await job.run_dossier_refresh(grid, maker, settings)
        assert _DEAD_A in await _ips(maker)
    finally:
        await engine.dispose()
