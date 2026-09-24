"""The audit hash chain under concurrent writers.

Measured on a live deployment, 2026-09-06: ``soc-ai audit verify --days 3``
reported TAMPER in the current epoch, and a composite aggregation over the
audit index found 41 duplicated ``seq`` values across 51 extra documents in
seven days. The duplicates share a ``prev_hash`` — two writers continued the
chain from the same head:

    109667  19:07:01Z  enriched_alert_context  prev=88b058b2a2ee
    109667  19:07:04Z  host_dossier            prev=88b058b2a2ee

Reproduced on a test grid against a real Elasticsearch: three OS processes
writing 60 records each through :class:`~soc_ai.audit.logger.AuditLogger`
produced 60 duplicated seq values and 120 extra documents, and the same load
in ONE process produced none. That is the shape of the defect. The in-process
``asyncio.Lock`` works; it just does not span an OS process, a second logger
instance in the same process (the nightly quality alarm builds one), or the
window between "the head was read" and "the record landed".

So the tests here race writers that do NOT share a lock and assert on what
survives in the index, not on what the logger believed. The fake grid models
the three Elasticsearch behaviours the fix depends on:

- ``op_type=create`` refuses a second document at an ``_id`` that already
  exists (this is the atomic claim),
- ``search`` is near-real-time and cannot see the newest writes (which is why
  re-reading the head is not, on its own, a fix),
- a multi-get by ``_id`` IS realtime (which is why the loser of a race can
  find out who won without waiting for a refresh).

:func:`test_negative_control_a_grid_without_create_semantics_still_collides`
is the control: the same racing harness against a grid that ignores
``op_type`` still produces duplicates, so a green result above is the claim
being enforced, not the race failing to happen.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.audit.chain import (
    GENESIS_PREV_HASH,
    compute_hash,
    verify_chain,
    verify_chain_detail,
)
from soc_ai.audit.logger import AuditLogger
from soc_ai.audit.schemas import AuditEvent
from soc_ai.audit.verify import _partition_epochs
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient

from tests.es_doubles import conflict_error


class _RacyES:
    """In-memory Elasticsearch double with create semantics and refresh lag.

    ``refresh_lag`` is how many of the newest documents ``search`` cannot see
    yet — the near-real-time window a head re-read falls into. ``mget`` ignores
    it, like the real realtime multi-get. Every call yields to the event loop,
    so tasks genuinely interleave rather than running to completion one at a
    time.
    """

    def __init__(
        self,
        *,
        enforce_create: bool = True,
        refresh_lag: int = 0,
        hang_first_write: bool = False,
    ) -> None:
        self.docs: dict[tuple[str, str], dict[str, Any]] = {}
        self.order: list[tuple[str, str]] = []
        self.enforce_create = enforce_create
        self.refresh_lag = refresh_lag
        self.hang_first_write = hang_first_write
        self.conflicts = 0
        self.writes_started = 0
        self.indices = AsyncMock()

    async def index(
        self,
        *,
        index: str,
        body: dict[str, Any],
        id: str | None = None,
        op_type: str | None = None,
    ) -> dict[str, Any]:
        await asyncio.sleep(0)
        self.writes_started += 1
        key = (index, id if id is not None else f"auto-{self.writes_started}")
        if op_type == "create" and self.enforce_create and key in self.docs:
            self.conflicts += 1
            raise conflict_error()
        # Apply BEFORE any stall: a write whose acknowledgement never arrives
        # is still a write the grid performed. That ambiguity is the whole
        # problem, so the double has to reproduce it.
        self.docs[key] = dict(body)
        self.order.append(key)
        if self.hang_first_write and self.writes_started == 1:
            await asyncio.sleep(3600)
        return {"result": "created"}

    async def mget(self, *, index: str, ids: list[str]) -> dict[str, Any]:
        await asyncio.sleep(0)
        docs: list[dict[str, Any]] = []
        for doc_id in ids:
            key = (index, doc_id)
            if key in self.docs:
                docs.append({"_id": doc_id, "found": True, "_source": dict(self.docs[key])})
            else:
                docs.append({"_id": doc_id, "found": False})
        return {"docs": docs}

    async def search(self, *, index: str, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        await asyncio.sleep(0)
        visible = self.order[: max(0, len(self.order) - self.refresh_lag)]
        chained = [self.docs[k] for k in visible if self.docs[k].get("seq") is not None]
        if not chained:
            return {"hits": {"hits": []}}
        top = max(chained, key=lambda d: int(d["seq"]))
        return {"hits": {"hits": [{"_source": top}]}}

    def stored(self) -> list[dict[str, Any]]:
        return [self.docs[k] for k in self.order]


def _logger(es: _RacyES, settings: Settings) -> AuditLogger:
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es):
        elastic = ElasticClient(settings)
    return AuditLogger(settings, elastic)


async def _write_burst(audit: AuditLogger, tag: str, count: int) -> None:
    for i in range(count):
        await audit.log_kind(session_id=tag, kind="tool_call", payload={"i": i, "w": tag})


def _duplicate_seqs(docs: list[dict[str, Any]]) -> list[int]:
    seen: dict[int, int] = {}
    for d in docs:
        seq = d.get("seq")
        if isinstance(seq, int):
            seen[seq] = seen.get(seq, 0) + 1
    return sorted(s for s, n in seen.items() if n > 1)


@pytest.mark.asyncio
async def test_two_logger_instances_racing_never_reuse_a_seq(settings_kratos: Settings) -> None:
    """Two loggers, one grid, no shared lock — the index must still hold one
    record per seq and a chain that verifies.

    This is the production shape: the API process's shared logger and a second
    logger (the nightly quality alarm's, or a CLI process's) writing at the
    same time. ``es.conflicts`` proves the race actually happened rather than
    the tasks politely queueing.
    """
    es = _RacyES(refresh_lag=3)
    a = _logger(es, settings_kratos)
    b = _logger(es, settings_kratos)

    await asyncio.gather(
        _write_burst(a, "alpha", 12),
        _write_burst(b, "bravo", 12),
        _write_burst(a, "charlie", 12),
    )

    docs = es.stored()
    assert len(docs) == 36
    assert _duplicate_seqs(docs) == []
    assert es.conflicts > 0, "the writers never actually collided; the test proves nothing"
    ok, broken = verify_chain(docs)
    assert ok, f"chain broken at seq {broken}"


@pytest.mark.asyncio
async def test_negative_control_a_grid_without_create_semantics_still_collides(
    settings_kratos: Settings,
) -> None:
    """The control for the test above.

    Same racing harness, against a grid that accepts a second document at an
    ``_id`` that already exists. Duplicates must appear — otherwise the green
    result above would be telling us nothing about the fix.
    """
    es = _RacyES(enforce_create=False, refresh_lag=3)
    a = _logger(es, settings_kratos)
    b = _logger(es, settings_kratos)

    await asyncio.gather(
        _write_burst(a, "alpha", 12),
        _write_burst(b, "bravo", 12),
        _write_burst(a, "charlie", 12),
    )

    docs = es.stored()
    assert _duplicate_seqs(docs), "the harness did not race; every other assertion here is void"
    ok, _broken = verify_chain(docs)
    assert not ok


@pytest.mark.asyncio
async def test_expired_write_does_not_hand_its_seq_to_the_next_record(
    settings_kratos: Settings,
) -> None:
    """A write whose acknowledgement never arrives must not have its seq reused.

    The grid applies the first record and then stalls past the write budget,
    so the logger cannot classify the outcome; the head re-read then lands in
    the near-real-time window and cannot see the record either. Re-reading the
    head is not enough here — only the grid can settle it, and it does, by
    refusing the second claim on that seq.
    """
    settings = settings_kratos.model_copy(update={"webui_grid_timeout_s": 1})
    es = _RacyES(refresh_lag=5, hang_first_write=True)
    audit = _logger(es, settings)

    await audit.log_kind(session_id="stalled", kind="tool_call", payload={"n": 1})
    await audit.log_kind(session_id="after", kind="tool_call", payload={"n": 2})

    docs = es.stored()
    assert len(docs) == 2
    assert [d["seq"] for d in docs] == [0, 1]
    ok, broken = verify_chain(docs)
    assert ok, f"chain broken at seq {broken}"


@pytest.mark.asyncio
async def test_first_write_does_not_lose_seq_zero_to_the_template_install(
    settings_kratos: Settings,
) -> None:
    """The earliest-timestamped record must carry the lowest seq.

    The index-template install runs once per process, and the writer that pays
    for it must not be overtaken by the writers that skip it: the verifier
    fetches timestamp-ascending and starts a new epoch at every ``seq == 0``,
    so a record stamped seq 0 AFTER a record with a higher seq splits one
    healthy chain into two and reports a break that never happened. Found on a
    test grid: with twelve concurrent first writes, the earliest record carried
    seq 11 and ``verify`` reported two epochs, both broken, on 180 records with
    no duplicates at all.
    """
    es = _RacyES()

    async def slow_template(**_kw: Any) -> None:
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    es.indices.put_index_template = AsyncMock(side_effect=slow_template)
    audit = _logger(es, settings_kratos)

    await asyncio.gather(*(_write_burst(audit, f"w{i}", 3) for i in range(6)))

    docs = es.stored()
    assert len(docs) == 18
    by_time = sorted(docs, key=lambda d: str(d["timestamp"]))
    assert by_time[0]["seq"] == 0, "the earliest record did not start the chain"
    epochs = _partition_epochs(by_time)
    assert len(epochs) == 1, f"one process incarnation split into {len(epochs)} epochs"
    ok, broken = verify_chain(epochs[0])
    assert ok, f"chain broken at seq {broken}"


@pytest.mark.asyncio
async def test_a_record_the_grid_refuses_outright_is_not_silently_renumbered(
    settings_kratos: Settings,
) -> None:
    """A create that keeps conflicting is dropped, never written at a guessed seq.

    The retry budget is finite. When it runs out the record is lost — which is
    the documented best-effort policy for a write that fails — but the chain it
    could not join is left intact, because a record forced in at a seq someone
    else holds is what "tamper detected" is made of.
    """
    es = _RacyES()
    audit = _logger(es, settings_kratos)
    await audit.log_kind(session_id="first", kind="tool_call", payload={"n": 1})

    # Every subsequent claim conflicts, whatever seq it picks.
    real_index = es.index

    async def always_conflict(**kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(0)
        es.conflicts += 1
        raise conflict_error()

    es.index = always_conflict  # type: ignore[method-assign]
    await audit.log_kind(session_id="second", kind="tool_call", payload={"n": 2})
    es.index = real_index  # type: ignore[method-assign]

    docs = es.stored()
    assert len(docs) == 1
    ok, broken = verify_chain(docs)
    assert ok, f"chain broken at seq {broken}"


@pytest.mark.asyncio
async def test_conflicting_mutating_write_aborts_the_action_when_fail_closed(
    settings_kratos: Settings,
) -> None:
    """A mutating write that cannot claim a seq must abort its state change.

    Same bargain the existing fail-closed policy strikes for a failed index
    call: no acknowledged alert without an audit record. A claim the grid never
    granted is a record that does not exist.
    """
    from soc_ai.audit.logger import AuditWriteError

    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    es = _RacyES()
    audit = _logger(es, settings)

    async def always_conflict(**_kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(0)
        es.conflicts += 1
        raise conflict_error()

    es.index = always_conflict  # type: ignore[method-assign]
    event = AuditEvent(
        session_id="ack",
        user="analyst",
        timestamp=datetime.now(UTC),
        kind="tool_call",
        payload={"tool": "acknowledge_alert"},
    )
    with pytest.raises(AuditWriteError):
        await audit.log(event, mutating=True)
    assert es.stored() == []


# =====================================================================
# Telling a fork apart from an edit
# =====================================================================


def _chained(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Re-chain *records* into a valid run so a test can then damage one thing."""
    out: list[dict[str, Any]] = []
    prev = GENESIS_PREV_HASH
    for seq, rec in enumerate(records):
        body = dict(rec)
        body["seq"] = seq
        body["prev_hash"] = prev
        body.pop("hash", None)
        digest = compute_hash(body, prev)
        body["hash"] = digest
        prev = digest
        out.append(body)
    return out


def _record(i: int) -> dict[str, Any]:
    return {"session_id": f"s{i}", "kind": "tool_call", "payload": {"i": i}}


def test_a_forked_position_is_reported_as_a_fork_not_an_edit() -> None:
    """Two records at one seq, each still matching its own hash, is concurrency.

    The operator has to be able to act on the difference: this shape is two
    writers appending at the same moment, and an intruder rewriting a decision
    record is a different emergency. Before this, both printed the same
    sentence.
    """
    records = _chained([_record(i) for i in range(4)])
    # A second writer that continued from the same head: same seq, same
    # prev_hash, its own content, its own (valid) hash.
    fork = dict(records[2])
    fork["session_id"] = "second-writer"
    fork.pop("hash")
    fork["hash"] = compute_hash(fork, fork["prev_hash"])
    brk = verify_chain_detail([*records, fork])
    assert brk is not None
    assert brk.kind == "duplicate_seq"
    assert brk.seq == 2
    assert "were not altered" in brk.detail
    assert "two writers" in brk.detail


def test_an_edited_record_is_reported_as_an_edit() -> None:
    """A record whose content no longer matches its own hash is an alteration."""
    records = _chained([_record(i) for i in range(4)])
    records[2]["payload"] = {"i": "changed after the fact"}
    brk = verify_chain_detail(records)
    assert brk is not None
    assert brk.kind == "content_altered"
    assert brk.seq == 2


def test_a_deleted_record_is_reported_as_a_gap() -> None:
    """A dropped record leaves a hole, and the hole is named as one."""
    records = _chained([_record(i) for i in range(4)])
    del records[2]
    brk = verify_chain_detail(records)
    assert brk is not None
    assert brk.kind == "missing_seq"
    assert brk.seq == 3


def test_a_fork_whose_copy_was_also_edited_says_so() -> None:
    """A duplicated position is not a licence to ignore a bad hash inside it."""
    records = _chained([_record(i) for i in range(4)])
    fork = dict(records[2])
    fork["session_id"] = "second-writer"  # hash left stale on purpose
    brk = verify_chain_detail([*records, fork])
    assert brk is not None
    assert brk.kind == "duplicate_seq"
    assert "content was altered" in brk.detail


def test_a_run_that_does_not_start_a_chain_is_reported_as_a_missing_head() -> None:
    """A full scan whose oldest record is not a genesis has lost its head."""
    records = _chained([_record(i) for i in range(4)])
    brk = verify_chain_detail(records[2:], expect_genesis=True)
    assert brk is not None
    assert brk.kind == "orphan_head"
    assert brk.seq == 2


# =====================================================================
# How widespread, not just where it starts
# =====================================================================
#
# The daily verification named a single sequence number. The window it scanned
# held 41 distinct duplicated sequence numbers across 51 extra records, some
# positions claimed by four writers. An operator cannot act on that difference:
# a single collision and a forked stretch of a whole afternoon read identically.
# They also cannot see the fact that matters most here, which is that all 41
# fall before the fix that stopped the forking, so the honest reading is
# "historical and bounded".


def _stamped(n: int) -> list[dict[str, Any]]:
    """A valid chain of *n* records carrying real timestamps."""
    records = _chained([_record(i) for i in range(n)])
    for i, rec in enumerate(records):
        rec["timestamp"] = datetime(2026, 9, 1, 12, 0, i, tzinfo=UTC).isoformat()
        rec.pop("hash")
        rec["hash"] = compute_hash(rec, rec["prev_hash"])
    return records


def _fork(rec: dict[str, Any], writer: str) -> dict[str, Any]:
    """A second writer's record at the same position, sound in itself."""
    copy = dict(rec)
    copy["session_id"] = writer
    copy.pop("hash")
    copy["hash"] = compute_hash(copy, copy["prev_hash"])
    return copy


def test_the_census_counts_every_fork_not_just_the_first() -> None:
    """Three forked positions, one of them claimed four ways."""
    from soc_ai.audit.chain import census_chain

    records = _stamped(8)
    forks = [
        _fork(records[2], "writer-b"),
        _fork(records[5], "writer-b"),
        _fork(records[6], "writer-b"),
        _fork(records[6], "writer-c"),
        _fork(records[6], "writer-d"),
    ]
    census = census_chain([*records, *forks])

    assert census.duplicate_seqs == 3
    assert census.extra_records == 5
    assert census.max_claimants == 4
    assert census.altered_records == 0
    assert census.missing_seqs == 0


def test_the_census_bounds_the_damage_in_time() -> None:
    """The oldest and newest record involved in a break.

    This is what lets an operator read a standing alarm as historical: if the
    newest affected record predates the fix, nothing has forked since.
    """
    from soc_ai.audit.chain import census_chain

    records = _stamped(8)
    census = census_chain([*records, _fork(records[2], "writer-b"), _fork(records[5], "writer-b")])

    assert census.oldest_break_at == records[2]["timestamp"]
    assert census.newest_break_at == records[5]["timestamp"]


def test_the_census_separates_an_alteration_from_a_fork() -> None:
    """A copy that no longer matches its own hash is counted apart.

    A duplicated position is what a second writer leaves behind. A record whose
    content no longer matches its own hash is someone changing the record of a
    decision, and the two must never be reported as one number.
    """
    from soc_ai.audit.chain import census_chain

    records = _stamped(6)
    records[3]["payload"] = {"i": "changed after the fact"}  # hash left stale
    census = census_chain(records)

    assert census.altered_records == 1
    assert census.duplicate_seqs == 0
    assert census.newest_break_at == records[3]["timestamp"]


def test_the_census_counts_absent_positions() -> None:
    from soc_ai.audit.chain import census_chain

    records = _stamped(8)
    del records[5]
    del records[2]
    census = census_chain(records)

    assert census.missing_seqs == 2
    assert census.duplicate_seqs == 0


def test_an_intact_chain_censuses_to_nothing() -> None:
    """NEGATIVE CONTROL. The census must not invent damage in a sound chain."""
    from soc_ai.audit.chain import census_chain

    census = census_chain(_stamped(20))

    assert census.duplicate_seqs == 0
    assert census.extra_records == 0
    assert census.max_claimants == 0
    assert census.altered_records == 0
    assert census.missing_seqs == 0
    assert census.oldest_break_at is None
    assert census.newest_break_at is None
    assert census_chain([]).newest_break_at is None
