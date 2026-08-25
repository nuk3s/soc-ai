"""Tests for the operator-facing audit-chain verification surface.

Two layers, both hermetic (no live ES):

- :func:`soc_ai.audit.verify.verify_audit_chain` — the shared fetch-and-verify
  helper. A fake ElasticClient (mocking at the ``_client.search`` boundary the
  helper actually calls) serves an intact chain / a tampered record / an empty
  index, and we assert the :class:`ChainVerifyResult`.
- ``GET /api/v1/config/audit/verify-chain`` — the admin endpoint. We assert it
  requires admin (401/403 with API auth on) and returns the JSON shape on an
  intact chain (helper mocked, ES untouched).
"""

from __future__ import annotations

import functools
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.audit.chain import GENESIS_PREV_HASH, GENESIS_SEQ, compute_hash
from soc_ai.audit.verify import ChainVerifyResult, verify_audit_chain
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient, GridPartialResultsError

# ── chain builder (mirrors AuditLogger.log's hash stamping) ────────────────────

# Arbitrary fixed instant. Epoch-boundary tests offset from this by whole hours
# so two epochs' timestamp ranges never accidentally overlap.
_BASE_TS = datetime(2026, 7, 11, 0, 0, 0, tzinfo=UTC)


def _build_chain(
    n: int,
    *,
    start_seq: int = GENESIS_SEQ,
    start_time: datetime = _BASE_TS,
    step: timedelta = timedelta(seconds=1),
) -> list[dict[str, Any]]:
    """Build ``n`` valid, correctly-linked audit records (as ES ``_source`` bodies).

    Mirrors :meth:`soc_ai.audit.logger.AuditLogger.log`: the hash is computed over
    the content (every field but ``hash``) plus the previous record's hash.

    ``timestamp`` advances by ``step`` per record using real ``datetime`` math —
    not the old zero-padded-seconds string trick, which silently produced
    unparseable/non-monotonic strings past 60 records (e.g. ``"...:00:99..."``).
    That was harmless while the fetch sort was seq-major (seq alone was unique
    and monotonic; timestamp was only ever a tiebreak), but the fetch sort is now
    timestamp-major (see ``soc_ai/audit/verify.py``'s ``_fetch_audit_records``),
    so a builder used by a 2 500-record test has to hand back real, ordered
    timestamps. ``step=timedelta(0)`` builds an epoch where every record shares
    one timestamp, for the same-millisecond-write tests.
    """
    records: list[dict[str, Any]] = []
    prev_hash = GENESIS_PREV_HASH
    for i in range(n):
        seq = start_seq + i
        ts = start_time + step * i
        content: dict[str, Any] = {
            "session_id": f"s{seq}",
            "kind": "tool_call",
            "payload": {"i": seq},
            "seq": seq,
            "prev_hash": prev_hash,
            "timestamp": ts.isoformat(),
        }
        digest = compute_hash(content, prev_hash)
        record = {**content, "hash": digest}
        records.append(record)
        prev_hash = digest
    return records


# ── fake ES that serves records with search_after paging + sort cursors ────────


def _es9_shard_failure_if_id_sort(sort: Any) -> dict[str, Any] | None:
    """Mirror real ES 9's refusal to sort on ``_id``, or None if the sort is fine.

    Stock ES 9 ships ``indices.id_field_data.enabled=false``: sorting on ``_id``
    needs fielddata, so every data-bearing shard fails with
    ``illegal_argument_exception``. Pre-fix, every fake in this suite accepted any
    sort — including the ``_id`` tiebreak ``_fetch_audit_records`` used to send —
    so CI never saw what a real 93M-doc ES 9 grid did: ``58 of 76 shards failed``
    (the exact shape reproduced below) on every ``soc-ai audit verify`` run. This
    check makes the fake refuse the same way, so a sort that reintroduces ``_id``
    fails here again instead of only on a live upgrade.
    """
    if not isinstance(sort, list) or not any(
        isinstance(clause, dict) and "_id" in clause for clause in sort
    ):
        return None
    return {
        "took": 4,
        "timed_out": False,
        "_shards": {
            "total": 76,
            "successful": 18,
            "skipped": 0,
            "failed": 58,
            "failures": [
                {
                    "shard": 0,
                    "index": "soc-ai-audit-000001",
                    "reason": {
                        "type": "illegal_argument_exception",
                        "reason": (
                            "Fielddata access on the _id field is disallowed, you can "
                            "re-enable it by updating the dynamic cluster setting: "
                            "indices.id_field_data.enabled"
                        ),
                    },
                }
            ],
        },
        "hits": {"hits": []},
    }


def _sort_fields_from_request(sort_spec: Any) -> list[tuple[str, str]]:
    """Extract ``(field, order)`` pairs from an ES ``sort`` clause, in priority order.

    Mirrors what a real ES node does with the ``sort`` array — apply each field
    in order, tie-breaking with the next — reading the request the same way
    :func:`_es9_shard_failure_if_id_sort` already does for the ``_id`` check.

    This is what makes :class:`_FakeES` actually serve whatever order
    ``_fetch_audit_records`` asked for, rather than a hardcoded guess at what it
    SHOULD ask for. The earlier version of this fake pre-sorted every response
    to ``(timestamp, seq)`` in its constructor, independent of the request body
    — so reverting the production sort back to the old seq-major order
    (``[{"seq": ...}, {"timestamp": ...}]``) changed nothing about what the fake
    served, and every multi-epoch behavioral test (``epochs``, ``ok``,
    ``first_broken_seq``) stayed green. Only the one test that inspects
    ``body["sort"]`` directly would have caught it, and only as a body-shape
    diff with no visible consequence — exactly the kind of regression this
    module exists to catch with a legible failure, not a silent pass.
    """
    fields: list[tuple[str, str]] = []
    if isinstance(sort_spec, list):
        for clause in sort_spec:
            if not isinstance(clause, dict):
                continue
            for field, spec in clause.items():
                order = spec.get("order", "asc") if isinstance(spec, dict) else "asc"
                fields.append((field, str(order)))
    return fields


def _record_sort_values(record: dict[str, Any], fields: list[tuple[str, str]]) -> list[Any]:
    """A record's values for ``fields``, in order — the shape ES's own ``sort``
    cursor takes, so this doubles as both a sort key's input and a cursor."""
    return [record.get(field) for field, _order in fields]


def _compare_sort_values(a: list[Any], b: list[Any], fields: list[tuple[str, str]]) -> int:
    """-1 if ``a`` sorts before ``b``, 1 if after, 0 if tied — per each field's
    own ``asc``/``desc``, first field wins, later fields only break ties."""
    for (_field, order), av, bv in zip(fields, a, b, strict=True):
        if av == bv:
            continue
        ascending = -1 if av < bv else 1
        return ascending if order != "desc" else -ascending
    return 0


class _FakeES:
    """Minimal ES double honoring the helper's ``search_after`` paging.

    Serves records ordered by whatever ``sort`` clause the REQUEST carries —
    derived per call via :func:`_sort_fields_from_request` /
    :func:`_compare_sort_values`, never a hardcoded field order — so a
    regression in ``_fetch_audit_records``'s own sort changes what this fake
    actually hands back, and the multi-epoch tests fail BEHAVIORALLY (wrong
    ``epochs``/``ok``/``first_broken_seq``, with a legible assertion message)
    instead of silently staying green. See :func:`_sort_fields_from_request`
    for why that distinction matters. Empty index → no hits.

    Enforces the ES 9 ``_id``-sort restriction (see
    :func:`_es9_shard_failure_if_id_sort`) BEFORE serving anything, exactly
    where a real cluster would refuse — every test in this file that reaches
    ``verify_audit_chain`` through this fake doubles as a regression guard for
    the ``_id`` tiebreak.
    """

    def __init__(self, records: list[dict[str, Any]]) -> None:
        # Kept in whatever order the caller built them in — the actual serving
        # order is derived per-request in `search()`, from that request's own
        # `sort`, not fixed here.
        self._records = list(records)

    async def search(self, *, index: str, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        failure = _es9_shard_failure_if_id_sort(body.get("sort"))
        if failure is not None:
            return failure
        fields = _sort_fields_from_request(body.get("sort"))
        ordered = sorted(
            self._records,
            key=functools.cmp_to_key(
                lambda a, b: _compare_sort_values(
                    _record_sort_values(a, fields), _record_sort_values(b, fields), fields
                )
            ),
        )
        size = int(body.get("size", 1000))
        after = body.get("search_after")
        start = 0
        if after is not None:
            # First record that sorts strictly after the cursor, per the SAME
            # per-field ordering `ordered` was just built with.
            start = next(
                (
                    i
                    for i, r in enumerate(ordered)
                    if _compare_sort_values(_record_sort_values(r, fields), after, fields) > 0
                ),
                len(ordered),
            )
        page = ordered[start : start + size]
        hits = [
            {"_source": r, "_id": f"id-{r.get('seq')}", "sort": _record_sort_values(r, fields)}
            for r in page
        ]
        return {"hits": {"hits": hits}}


class _HalfReadES(_FakeES):
    """The grid that answers 200 having read only half its shards.

    Serves whatever records the surviving shards held (possibly none) exactly as
    :class:`_FakeES` would, plus the ``_shards``/``timed_out`` metadata that says
    the read was partial — which is all ES itself says under its default
    ``allow_partial_search_results=true``. Nothing raises; the evidence is in
    the envelope, and a reader that only looks at ``hits`` cannot see it.
    """

    def __init__(self, records: list[dict[str, Any]], *, timed_out: bool = True) -> None:
        super().__init__(records)
        self._timed_out = timed_out

    async def search(self, *, index: str, body: dict[str, Any], **kw: Any) -> dict[str, Any]:
        resp = await super().search(index=index, body=body, **kw)
        resp["timed_out"] = self._timed_out
        resp["_shards"] = {
            "total": 4,
            "successful": 2,
            "skipped": 0,
            "failed": 2,
            "failures": [
                {
                    "shard": 0,
                    "index": "soc-ai-audit-000001",
                    "reason": {"type": "no_shard_available_action_exception"},
                }
            ],
        }
        return resp


def _elastic_with(
    records: list[dict[str, Any]],
    *,
    fake: Any | None = None,
    settings_overrides: dict[str, Any] | None = None,
) -> ElasticClient:
    """An ElasticClient whose ``_client`` is a :class:`_FakeES` (no real transport)."""
    settings = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
        **(settings_overrides or {}),
    )
    if fake is None:
        fake = _FakeES(records)
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake):
        return ElasticClient(settings)


# ── helper: intact / tampered / empty ──────────────────────────────────────────


def test_es9_fake_rejects_id_sort_and_accepts_timestamp_sort() -> None:
    """Direct pin of the enforcement contract in :func:`_es9_shard_failure_if_id_sort`.

    Regression for the ES 9 ``id_field_data`` restriction (found 2026-08-20 against
    a real 93M-doc grid): ``_fetch_audit_records`` used to tiebreak ``search_after``
    on ``_id``, which stock ES 9 refuses (``indices.id_field_data.enabled=false``),
    failing every data-bearing shard and turning the (correct) partial-read guard
    into a permanent couldn't-verify. Every other test in this file proves
    ``verify_audit_chain`` no longer sends that sort (all pass through this same
    enforcing fake); this test pins the fake's contract in isolation so the shape it
    rejects/accepts is obvious without reading the paging logic.
    """
    id_sort = [{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}]
    failure = _es9_shard_failure_if_id_sort(id_sort)
    assert failure is not None
    assert failure["_shards"]["failed"] == 58
    assert failure["_shards"]["total"] == 76
    assert failure["_shards"]["failures"][0]["reason"]["type"] == "illegal_argument_exception"

    # Real shape sent by `_fetch_audit_records` since the epoch partition landed:
    # timestamp-major, seq tiebreak (neither is `_id`).
    ts_sort = [{"timestamp": {"order": "asc"}}, {"seq": {"order": "asc"}}]
    assert _es9_shard_failure_if_id_sort(ts_sort) is None
    assert _es9_shard_failure_if_id_sort(None) is None
    assert _es9_shard_failure_if_id_sort([{"seq": {"order": "asc"}}]) is None


async def test_verify_intact_chain() -> None:
    records = _build_chain(5)
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert isinstance(result, ChainVerifyResult)
    assert result.ok is True
    assert result.first_broken_seq is None
    assert result.records_verified == 5
    assert result.first_seq == 0
    assert result.last_seq == 4
    assert result.capped is False
    # One unbroken chain is one epoch — the common case, and the ONLY case
    # before the chain-head recovery bug (fixed 2026-08-17) started fragmenting
    # prod's chain into 134 of them.
    assert result.epochs == 1
    assert result.first_broken_epoch_start is None


async def test_verify_tampered_record() -> None:
    records = _build_chain(5)
    # Edit a stored record's payload WITHOUT re-stamping its hash → recompute fails
    # at that seq (an edit is exactly what verify_chain must catch).
    records[2]["payload"] = {"i": 999}
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is False
    assert result.first_broken_seq == 2
    assert result.epochs == 1
    assert result.first_broken_epoch_start == records[0]["timestamp"]
    # A single-epoch scan: the one broken epoch is trivially both the oldest
    # AND the newest (and only) broken one, and — being the only epoch at
    # all — trivially the latest too.
    assert result.epochs_broken == 1
    assert result.newest_broken_epoch_start == records[0]["timestamp"]
    assert result.latest_epoch_broken is True


async def test_verify_deleted_record_breaks_chain() -> None:
    """Deleting a middle record leaves a seq gap → tamper detected at the gap."""
    records = _build_chain(5)
    del records[2]  # seq 2 removed; 3 no longer follows 1 contiguously
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is False
    assert result.first_broken_seq == 3
    assert result.epochs == 1
    assert result.first_broken_epoch_start == records[0]["timestamp"]
    assert result.epochs_broken == 1
    assert result.newest_broken_epoch_start == records[0]["timestamp"]
    assert result.latest_epoch_broken is True


async def test_verify_windowed_slice_is_not_tamper() -> None:
    """A ``days=`` window that legitimately starts mid-stream (the record before the
    window was rotated out / filtered) must NOT be reported as tampered. Regression
    for the windowed false-positive: verify_chain forced the genesis prev_hash onto
    the first in-window record regardless of its real seq."""
    full = _build_chain(10)
    window = full[6:]  # seqs 6..9 — exactly what a days= filter hands back on an old deploy
    elastic = _elastic_with(window)
    result = await verify_audit_chain(elastic, "soc-ai-audit", days=7)
    assert result.ok is True
    assert result.first_broken_seq is None
    assert result.records_verified == 4
    assert result.first_seq == 6
    assert result.last_seq == 9
    # No seq=0 anywhere in the window, so it is one (legitimately headless)
    # epoch, not zero — `epochs` counts groups actually present in the fetch.
    assert result.epochs == 1
    assert result.first_broken_epoch_start is None
    assert result.epochs_broken == 0
    assert result.newest_broken_epoch_start is None
    assert result.latest_epoch_broken is False


async def test_verify_full_scan_still_flags_missing_head() -> None:
    """No-regression guard: a full (non-windowed) scan whose oldest records are gone
    is still a tamper. With no ``days`` window to excuse it, expect_genesis stays on,
    so a first record with seq>0 and a non-genesis prev_hash is caught, not accepted."""
    full = _build_chain(10)
    missing_head = full[3:]  # head deleted, no days= window
    elastic = _elastic_with(missing_head)
    result = await verify_audit_chain(elastic, "soc-ai-audit")  # days=None
    assert result.ok is False
    assert result.first_broken_seq == 3
    assert result.epochs == 1
    assert result.first_broken_epoch_start == missing_head[0]["timestamp"]
    assert result.epochs_broken == 1
    assert result.newest_broken_epoch_start == missing_head[0]["timestamp"]
    assert result.latest_epoch_broken is True


async def test_verify_empty_index_is_intact() -> None:
    elastic = _elastic_with([])
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is True
    assert result.first_broken_seq is None
    assert result.records_verified == 0
    assert result.first_seq is None
    assert result.last_seq is None
    assert result.capped is False
    # Nothing to partition — zero epochs, not one. The verdict tri-state (CLI,
    # API consumers, Config.tsx) treats epochs<=1 as the green/unchanged path,
    # so 0 must land there beside 1, not in the amber multi-epoch branch.
    assert result.epochs == 0
    assert result.first_broken_epoch_start is None
    # Vacuously true: no epochs at all means nothing can be "the broken latest
    # epoch" either.
    assert result.epochs_broken == 0
    assert result.newest_broken_epoch_start is None
    assert result.latest_epoch_broken is False


async def test_verify_pages_past_page_size() -> None:
    """A chain larger than one page is fully fetched via search_after (no truncation)."""
    records = _build_chain(2500)  # > _PAGE_SIZE (1000)
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is True
    assert result.records_verified == 2500
    assert result.last_seq == 2499
    assert result.capped is False
    assert result.epochs == 1
    assert result.epochs_broken == 0


async def test_verify_respects_max_records_cap() -> None:
    """Hitting the record cap sets capped=True (never a silent truncation)."""
    records = _build_chain(50)
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit", max_records=10)
    assert result.capped is True
    assert result.records_verified == 10
    # A capped scan mid-way through a single long-running epoch: still 1 epoch,
    # same amber "partial" branch as before the epoch feature existed (the
    # multi-epoch amber branch is a distinct state — see the epochs>1 tests
    # below).
    assert result.epochs == 1
    assert result.epochs_broken == 0


# ── epoch partition: restart boundaries are history, not tamper ────────────────
#
# Prod's audit chain carries 134 genesis (seq=0) records, 2026-06-24 →
# 2026-08-16: `_top_source`'s `isinstance(resp, dict)` never matched the real
# ES client's `ObjectApiResponse` (fixed 2026-08-17, commit 8032258), so
# `_ensure_chain_head` "recovered" an empty head and restarted the chain from
# genesis on every process restart for ~8 weeks. Zero new genesis records since
# the fix. Every test below builds that exact shape — multiple independently-
# intact chains, back to back in time — and pins that the verifier reports it
# as what it is (N intact epochs), not as one chain broken 133 times.


async def test_verify_multi_epoch_all_intact_reports_epoch_count() -> None:
    """Three restarts, each internally intact: epochs=3, ok=True, not tampered.

    This is prod's actual shape. Before the epoch partition,
    ``verify_audit_chain`` ran ONE ``verify_chain(records)`` pass over
    everything fetched; sorted seq-major (the old sort), every epoch after the
    first interleaved its seq=0 in among every other epoch's low seqs, and
    sorted timestamp-major without partitioning, the second epoch's seq=0
    simply looks like seq going backwards after the first epoch's seq=1 — a
    "duplicate/out-of-order seq" that reports TAMPER at the second epoch's
    genesis, permanently, for a grid that was never tampered with.
    """
    e0 = _build_chain(3, start_time=_BASE_TS)
    e1 = _build_chain(4, start_time=_BASE_TS + timedelta(hours=1))
    e2 = _build_chain(2, start_time=_BASE_TS + timedelta(hours=2))
    elastic = _elastic_with(e0 + e1 + e2)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is True
    assert result.epochs == 3
    assert result.records_verified == 9
    assert result.first_broken_seq is None
    assert result.first_broken_epoch_start is None
    assert result.epochs_broken == 0
    assert result.newest_broken_epoch_start is None
    assert result.latest_epoch_broken is False


async def test_verify_break_inside_a_later_epoch_locates_that_epoch() -> None:
    """A break in epoch 2 (not epoch 1) is located by EPOCH 2's own genesis.

    ``first_broken_seq`` is LOCAL to the broken epoch (every epoch renumbers
    from 0 — seq 2 here means the third record of epoch 2, not the ninth
    record overall), and ``first_broken_epoch_start`` names epoch 2's genesis
    timestamp specifically, not epoch 1's and not a global record count. An
    operator locating a real tamper needs to know WHICH restart it happened in.
    """
    e0 = _build_chain(4, start_time=_BASE_TS)
    e1 = _build_chain(5, start_time=_BASE_TS + timedelta(hours=1))
    e1[2]["payload"] = {"i": "tampered"}  # edit inside epoch 2, local seq 2, no re-stamp
    e2 = _build_chain(3, start_time=_BASE_TS + timedelta(hours=2))
    elastic = _elastic_with(e0 + e1 + e2)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is False
    assert result.first_broken_seq == 2
    assert result.first_broken_epoch_start == e1[0]["timestamp"]
    # The full shape is still reported even though the break is in the middle —
    # records_verified counts everything FETCHED (the existing, pre-epoch
    # convention: it is not "records checked before the break"), and epochs
    # mirrors that same convention for the partition.
    assert result.epochs == 3
    assert result.records_verified == 4 + 5 + 3
    # Exactly ONE epoch is broken (epoch 2) — epoch 3, which comes AFTER it and
    # is perfectly intact, must not be swept into the tally just because the
    # scan continues past the break to see it.
    assert result.epochs_broken == 1
    assert result.newest_broken_epoch_start == e1[0]["timestamp"]
    # Epoch 3 (intact) is the last epoch fetched, so the break is NOT in the
    # latest epoch — this is the "broken, then clean since" shape.
    assert result.latest_epoch_broken is False


async def test_verify_break_in_the_first_epoch_of_a_multi_epoch_fetch() -> None:
    """A break in epoch 1 must not be masked by later, perfectly intact epochs."""
    e0 = _build_chain(4, start_time=_BASE_TS)
    del e0[1]  # seq gap inside epoch 1 (local seq 1 missing; seq 2 breaks)
    e1 = _build_chain(3, start_time=_BASE_TS + timedelta(hours=1))
    elastic = _elastic_with(e0 + e1)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is False
    assert result.first_broken_seq == 2
    assert result.first_broken_epoch_start == e0[0]["timestamp"]
    assert result.epochs_broken == 1
    assert result.newest_broken_epoch_start == e0[0]["timestamp"]
    # e1 (intact) is the last epoch fetched — the operator's real question,
    # "am I sound NOW", is answered here: yes, the most recent epoch is clean.
    assert result.latest_epoch_broken is False


# ── verify EVERY epoch: a break reports its blast radius, not just its
# existence ──────────────────────────────────────────────────────────────────
#
# Live prod, 2026-08-21: ``soc-ai audit verify`` reported "TAMPER — chain broke
# at seq 38 in the epoch starting 2026-06-26T21:55:52Z". Verified by hand: a
# REAL duplicate-seq artifact — two interleaved series both claiming seq
# 38/39/40, one starting 2026-06-26T22:17 and the other 2026-06-27T02:13 —
# from the historic pre-1.2.8 write-side stale-head seq-reuse bug (a stalled
# write left the in-memory chain head stale; the next write reused its seq).
# Not a false positive — the chain genuinely IS broken there — but the OLD
# code stopped at the first broken epoch it found, leaving prod's operator
# unable to tell whether that June scar was the ONLY damage or whether
# anything more recent (possibly the live, current epoch) was also broken.
# The tests below build chains with breaks BEFORE and/or AFTER other breaks
# and pin that every epoch gets checked, every break gets tallied, and the
# NEWEST break is named specifically — the field an operator actually needs
# to answer "am I sound right now".


async def test_verify_two_epochs_broken_tallies_both_oldest_and_newest_kept() -> None:
    """Two independent breaks, an intact epoch between AND after them.

    Five epochs: intact, BROKEN, intact, BROKEN, intact. This is the general
    shape of prod's actual finding — the chain-head recovery bug (fixed
    2026-08-17) created 134 restart boundaries, and separately, at least one
    of those pre-1.2.8 epochs carries a REAL duplicate-seq artifact from the
    historic write-side stale-head seq-reuse bug (a stalled write left the
    head stale; the next write reused its seq — two interleaved series both
    claiming the same seq numbers). Stopping at the first break (the old
    behavior) would report ONE broken epoch and go silent about whether
    anything since is also broken — unable to answer "am I sound NOW".
    Verifying every epoch answers it: ``epochs_broken`` counts BOTH breaks,
    ``first_broken_*`` keeps the OLDEST (compat with the single-break era),
    and ``newest_broken_epoch_start`` names the most recent one specifically.
    """
    e0 = _build_chain(3, start_time=_BASE_TS)
    e1 = _build_chain(4, start_time=_BASE_TS + timedelta(hours=1))
    e1[1]["payload"] = {"i": "tampered"}  # break epoch 1 (local seq 1)
    e2 = _build_chain(2, start_time=_BASE_TS + timedelta(hours=2))
    e3 = _build_chain(5, start_time=_BASE_TS + timedelta(hours=3))
    e3[3]["payload"] = {"i": "also tampered"}  # break epoch 3 (local seq 3)
    e4 = _build_chain(3, start_time=_BASE_TS + timedelta(hours=4))
    elastic = _elastic_with(e0 + e1 + e2 + e3 + e4)
    result = await verify_audit_chain(elastic, "soc-ai-audit")

    assert result.ok is False
    assert result.epochs == 5
    assert result.epochs_broken == 2
    # Oldest break kept for compat — this is epoch 1's, not epoch 3's.
    assert result.first_broken_seq == 1
    assert result.first_broken_epoch_start == e1[0]["timestamp"]
    # Newest broken epoch is epoch 3's, specifically — not epoch 1's (the
    # oldest) and not epoch 4's (which is intact and comes after it).
    assert result.newest_broken_epoch_start == e3[0]["timestamp"]
    # Epoch 4, intact, is the last epoch fetched — "every epoch after the
    # newest broken one" (epoch 3) is genuinely, verifiably clean.
    assert result.latest_epoch_broken is False


async def test_verify_latest_epoch_broken_is_flagged() -> None:
    """When the MOST RECENT epoch itself is the broken one, say so distinctly.

    Two clean restarts, then the current (most recent) epoch is tampered —
    there is nothing intact "after" the newest break to reassure the operator
    with, because the newest break IS the latest thing on record.
    """
    e0 = _build_chain(3, start_time=_BASE_TS)
    e1 = _build_chain(3, start_time=_BASE_TS + timedelta(hours=1))
    e2 = _build_chain(4, start_time=_BASE_TS + timedelta(hours=2))
    e2[2]["payload"] = {"i": "tampered"}  # break the LAST (most recent) epoch
    elastic = _elastic_with(e0 + e1 + e2)
    result = await verify_audit_chain(elastic, "soc-ai-audit")

    assert result.ok is False
    assert result.epochs == 3
    assert result.epochs_broken == 1
    assert result.first_broken_epoch_start == e2[0]["timestamp"]
    assert result.newest_broken_epoch_start == e2[0]["timestamp"]
    assert result.latest_epoch_broken is True


async def test_verify_cap_tallies_only_scanned_epochs() -> None:
    """A capped scan's tally covers what it actually scanned — nothing more.

    Epoch 0 broken, epoch 1 intact, epoch 2 (never fetched — the cap fires
    right after epoch 1) would-be intact. The tally must reflect exactly the
    TWO epochs the scan reached: ``epochs_broken=1`` (only epoch 0),
    ``newest_broken_epoch_start`` is epoch 0's own start (the only break), and
    ``latest_epoch_broken`` is False because epoch 1 — the last epoch this
    capped scan actually fetched — verified intact. This is a data-layer pin:
    the CAVEAT that a capped scan cannot vouch for anything beyond its own
    prefix (so a consumer must not present ``latest_epoch_broken=False`` here
    as "the chain is currently sound" — there may be a real epoch 2 this scan
    never saw) is a RENDERING decision, tested at the CLI/Config.tsx layer,
    not something this function computes differently based on ``capped``.
    """
    e0 = _build_chain(3, start_time=_BASE_TS)
    e0[1]["payload"] = {"i": "tampered"}
    e1 = _build_chain(3, start_time=_BASE_TS + timedelta(hours=1))
    e2 = _build_chain(3, start_time=_BASE_TS + timedelta(hours=2))  # never fetched
    elastic = _elastic_with(e0 + e1 + e2)
    result = await verify_audit_chain(elastic, "soc-ai-audit", max_records=6)

    assert result.capped is True
    assert result.records_verified == 6
    assert result.epochs == 2
    assert result.epochs_broken == 1
    assert result.first_broken_epoch_start == e0[0]["timestamp"]
    assert result.newest_broken_epoch_start == e0[0]["timestamp"]
    assert result.latest_epoch_broken is False


async def test_verify_tolerates_identical_timestamps_within_an_epoch() -> None:
    """Same-millisecond writes within one epoch must not scramble the chain.

    ``_fetch_audit_records``'s sort is timestamp-major with a ``seq`` tiebreak
    specifically so a burst of records landing in the same ES-visible
    millisecond still comes back seq-ascending — the ordering the epoch
    partition (cut at seq==0) and ``verify_chain``'s own per-epoch seq check
    both depend on. Real clock granularity is coarser than write rate under
    load, so this is not a hypothetical.
    """
    records = _build_chain(6, step=timedelta(0))  # every record: identical timestamp
    elastic = _elastic_with(records)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is True
    assert result.epochs == 1
    assert result.records_verified == 6
    assert result.epochs_broken == 0


async def test_verify_identical_timestamp_at_an_epoch_boundary_still_resolves() -> None:
    """The one collision the compound sort cannot fully absorb: a break, not a lie.

    If a dying process's last write and the next incarnation's genesis write
    ever landed in the exact same ES-visible millisecond, the seq tiebreak would
    sort the new genesis (seq=0) ahead of the old epoch's tail (a high seq) —
    the old epoch's tail record would then be read as arriving mid-epoch-2,
    where its seq does not fit, and ``verify_chain`` reports a break there. That
    is the conservative failure mode this module always wants for an ambiguous
    ordering: a break, never a silent "intact". In practice a process must fully
    exit before the next one starts and recovers a fresh chain head (see
    ``AuditLogger._ensure_chain_head``), so the two writes are never truly
    concurrent — this test pins the fallback behavior anyway, in case that
    assumption is ever wrong.
    """
    e0 = _build_chain(3, start_time=_BASE_TS)
    e1 = _build_chain(3, start_time=_BASE_TS)  # same timestamps as e0 (worst case)
    elastic = _elastic_with(e0 + e1)
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    # Whatever the outcome, it must be a definitive break, never a false
    # "intact" — an ambiguous ordering is never allowed to read as a clean bill
    # of health.
    assert result.ok is False
    assert result.first_broken_seq is not None
    assert result.epochs_broken >= 1


async def test_verify_cap_can_stop_mid_epoch_after_earlier_epochs_completed() -> None:
    """A capped scan's LAST epoch can be a genuine partial — never itself a break.

    Three epochs of 5 records each; the cap (8) lands 3 records into epoch 2.
    ``verify_chain`` never requires a group to end on any particular record — a
    forward-only prefix is intact by construction — so this must report
    ``ok=True``, ``capped=True``, and ``epochs=2``: epoch 3 was never fetched at
    all (the cap fired before reaching it), so it does not exist in the
    returned records and is not counted. Mirrors the pre-epoch capped
    contract (a capped scan verifies the OLDEST records) one level up: now the
    oldest EPOCHS.
    """
    e0 = _build_chain(5, start_time=_BASE_TS)
    e1 = _build_chain(5, start_time=_BASE_TS + timedelta(hours=1))
    e2 = _build_chain(5, start_time=_BASE_TS + timedelta(hours=2))
    elastic = _elastic_with(e0 + e1 + e2)
    result = await verify_audit_chain(elastic, "soc-ai-audit", max_records=8)
    assert result.capped is True
    assert result.records_verified == 8
    assert result.ok is True
    assert result.epochs == 2
    assert result.first_broken_epoch_start is None
    assert result.epochs_broken == 0
    assert result.newest_broken_epoch_start is None
    assert result.latest_epoch_broken is False


async def test_fetch_requests_timestamp_major_sort_and_excludes_legacy_docs() -> None:
    """Pins the two structural facts the epoch partition depends on.

    1. The fetch sort is timestamp-major (``[{timestamp: asc}, {seq: asc}]``) —
       epochs were written sequentially in time, and the OLD seq-major sort
       interleaves every epoch's seq=0 first, making partition on seq alone
       impossible (see the multi-epoch tests above for what that did to the
       verdict).
    2. The query still filters ``exists: seq``, so legacy pre-chain docs
       (written before the hash chain existed — no ``seq`` at all) can never
       reach the partition logic. Nothing downstream has to guess what a
       seq-less record means; it structurally cannot appear.
    """
    captured: dict[str, Any] = {}

    class _CapturingES(_FakeES):
        async def search(self, *, index: str, body: dict[str, Any], **kw: Any) -> dict[str, Any]:
            captured["sort"] = body.get("sort")
            captured["query"] = body.get("query")
            return await super().search(index=index, body=body, **kw)

    elastic = _elastic_with([], fake=_CapturingES(_build_chain(3)))
    await verify_audit_chain(elastic, "soc-ai-audit")

    assert captured["sort"] == [
        {"timestamp": {"order": "asc"}},
        {"seq": {"order": "asc"}},
    ]
    assert {"exists": {"field": "seq"}} in captured["query"]["bool"]["filter"]


async def test_verify_half_read_index_raises_not_intact() -> None:
    """A half-read index is 'could not run', never 'intact — 0 records'.

    ES answers 200 with only the surviving shards' records (here: none), and the
    partiality is visible only in ``_shards``/``timed_out``. Before the per-page
    check this paged to zero records and 'an empty chain is intact by definition'
    turned a blind read into a clean bill of health on the one surface whose
    whole job is to be believed about integrity.
    """
    elastic = _elastic_with([], fake=_HalfReadES([]))
    with pytest.raises(GridPartialResultsError) as excinfo:
        await verify_audit_chain(elastic, "soc-ai-audit")
    err = excinfo.value
    assert err.shards_failed == 2
    assert err.shards_total == 4
    message = str(err)
    assert "2 of 4 shards failed" in message
    assert "cannot be verified" in message


async def test_verify_half_read_mid_chain_is_unverifiable_not_tamper() -> None:
    """The bucket-separation control: a partial read must not be scored as tamper.

    The dead shards held seq 2, so the surviving shards serve 0,1,3,4 — to
    ``verify_chain`` that seq gap is indistinguishable from a deleted record, and
    without the per-page raise this exact input reports ``ok=False,
    first_broken_seq=3``: an outage published as the most expensive false alarm
    the product can raise, telling the operator their audit trail was tampered
    with because a node restarted. The raise has to happen before a single hit
    is hashed, so neither verdict bucket can be reached from a partial read.
    """
    records = _build_chain(5)
    del records[2]  # the record the dead shards held
    elastic = _elastic_with([], fake=_HalfReadES(records))
    with pytest.raises(GridPartialResultsError):
        await verify_audit_chain(elastic, "soc-ai-audit")


async def test_verify_partial_read_ignores_the_partial_results_opt_out() -> None:
    """``es_fail_on_partial_results=false`` must not reach the tamper-evidence check.

    The opt-out exists so a console with a chronically red shard stays usable:
    a degraded panel is better than no panel. Verification is not a panel — a
    partial read here fakes either an intact chain or a tampered one — so the
    audit scan raises regardless of the opt-out.
    """
    elastic = _elastic_with(
        [],
        fake=_HalfReadES(_build_chain(3)),
        settings_overrides={"es_fail_on_partial_results": False},
    )
    with pytest.raises(GridPartialResultsError):
        await verify_audit_chain(elastic, "soc-ai-audit")


async def test_verify_search_timeout_with_no_failed_shards_still_raises() -> None:
    """``timed_out: true`` with zero failed shards is still a read that never finished."""

    class _TimedOutES(_FakeES):
        async def search(self, *, index: str, body: dict[str, Any], **kw: Any) -> dict[str, Any]:
            resp = await super().search(index=index, body=body, **kw)
            resp["timed_out"] = True
            resp["_shards"] = {"total": 4, "successful": 4, "skipped": 0, "failed": 0}
            return resp

    elastic = _elastic_with([], fake=_TimedOutES(_build_chain(3)))
    with pytest.raises(GridPartialResultsError, match="timed out"):
        await verify_audit_chain(elastic, "soc-ai-audit")


async def test_verify_clean_shard_metadata_still_verifies() -> None:
    """The over-correction control: the guard keys on failure, not on ``_shards``.

    A response that says all shards answered — and one that says nothing at all,
    which every other test in this file exercises via the bare :class:`_FakeES` —
    must verify exactly as before, or the fix is 'always unverifiable' and the
    operator stops running the check.
    """

    class _CleanShardsES(_FakeES):
        async def search(self, *, index: str, body: dict[str, Any], **kw: Any) -> dict[str, Any]:
            resp = await super().search(index=index, body=body, **kw)
            resp["timed_out"] = False
            resp["_shards"] = {"total": 4, "successful": 4, "skipped": 0, "failed": 0}
            return resp

    records = _build_chain(5)
    elastic = _elastic_with([], fake=_CleanShardsES(records))
    result = await verify_audit_chain(elastic, "soc-ai-audit")
    assert result.ok is True
    assert result.records_verified == 5


async def test_verify_es_error_propagates() -> None:
    """A transport/ES error is raised, NOT swallowed as an intact chain — the
    caller (CLI exit-2 / endpoint 5xx) must be able to tell 'could not run' apart
    from 'intact'."""
    elastic = _elastic_with([])
    with (
        patch.object(elastic._client, "search", AsyncMock(side_effect=RuntimeError("ES down"))),
        pytest.raises(RuntimeError, match="ES down"),
    ):
        await verify_audit_chain(elastic, "soc-ai-audit")


# ── endpoint: GET /config/audit/verify-chain ───────────────────────────────────


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "api_auth_required": False,
    }
    base.update(overrides)
    return Settings(**base)


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


def test_endpoint_returns_shape_on_intact_chain(client: TestClient) -> None:
    """The endpoint returns the documented JSON on an intact chain (helper mocked)."""
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=True,
            records_verified=7,
            first_broken_seq=None,
            first_seq=0,
            last_seq=6,
            capped=False,
            epochs=1,
            first_broken_epoch_start=None,
            epochs_broken=0,
            newest_broken_epoch_start=None,
            latest_epoch_broken=False,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["records_verified"] == 7
    assert body["first_broken_seq"] is None
    assert body["first_seq"] == 0
    assert body["last_seq"] == 6
    assert body["capped"] is False
    assert body["epochs"] == 1
    assert body["first_broken_epoch_start"] is None
    assert body["epochs_broken"] == 0
    assert body["newest_broken_epoch_start"] is None
    assert body["latest_epoch_broken"] is False
    assert isinstance(body["checked_at"], str) and body["checked_at"]


def test_endpoint_reports_tamper(client: TestClient) -> None:
    """A broken chain surfaces ok=false + first_broken_seq (still HTTP 200 — the
    verification RAN and its answer is 'tampered')."""
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=False,
            records_verified=3,
            first_broken_seq=3,
            first_seq=0,
            last_seq=4,
            capped=False,
            epochs=1,
            first_broken_epoch_start="2026-08-01T00:00:00+00:00",
            epochs_broken=1,
            newest_broken_epoch_start="2026-08-01T00:00:00+00:00",
            latest_epoch_broken=True,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is False
    assert body["first_broken_seq"] == 3


def test_endpoint_surfaces_epoch_fields_on_a_multi_epoch_intact_scan(
    client: TestClient,
) -> None:
    """``epochs`` passes through exactly like the seq fields already do.

    This is the field the tri-state verdict (CLI / this endpoint's consumers /
    Config.tsx) keys the amber "intact within N epochs" branch on, so the raw
    count reaching the wire is what makes that branch reachable at all.
    """
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=True,
            records_verified=9,
            first_broken_seq=None,
            first_seq=0,
            last_seq=4,
            capped=False,
            epochs=3,
            first_broken_epoch_start=None,
            epochs_broken=0,
            newest_broken_epoch_start=None,
            latest_epoch_broken=False,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["epochs"] == 3
    assert body["first_broken_epoch_start"] is None


def test_endpoint_surfaces_which_epoch_broke(client: TestClient) -> None:
    """A tampered multi-epoch chain surfaces WHICH epoch broke, not just which seq.

    ``first_broken_seq`` alone is ambiguous once more than one epoch exists (it
    resets to 0 at every genesis) — ``first_broken_epoch_start`` is what lets an
    operator find the right restart.
    """
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=False,
            records_verified=7,
            first_broken_seq=2,
            first_seq=0,
            last_seq=3,
            capped=False,
            epochs=2,
            first_broken_epoch_start="2026-08-01T00:00:00+00:00",
            epochs_broken=1,
            newest_broken_epoch_start="2026-08-01T00:00:00+00:00",
            latest_epoch_broken=False,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is False
    assert body["epochs"] == 2
    assert body["first_broken_epoch_start"] == "2026-08-01T00:00:00+00:00"


def test_endpoint_surfaces_the_broken_epoch_tally(client: TestClient) -> None:
    """The blast-radius fields — ``epochs_broken``, ``newest_broken_epoch_start``,
    ``latest_epoch_broken`` — pass through exactly like the seq/epoch fields do.

    This is the shape prod's June finding actually has once every epoch is
    checked instead of stopping at the first break: a scar in old history,
    nothing broken since.
    """
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=False,
            records_verified=134,
            first_broken_seq=38,
            first_seq=0,
            last_seq=40,
            capped=False,
            epochs=134,
            first_broken_epoch_start="2026-06-26T21:55:52+00:00",
            epochs_broken=1,
            newest_broken_epoch_start="2026-06-26T21:55:52+00:00",
            latest_epoch_broken=False,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is False
    assert body["epochs_broken"] == 1
    assert body["newest_broken_epoch_start"] == "2026-06-26T21:55:52+00:00"
    assert body["latest_epoch_broken"] is False


def test_endpoint_surfaces_latest_epoch_broken(client: TestClient) -> None:
    """``latest_epoch_broken=True`` is a distinct, real shape from the reassuring
    one above — the endpoint must not collapse the two."""
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=False,
            records_verified=10,
            first_broken_seq=1,
            first_seq=0,
            last_seq=3,
            capped=False,
            epochs=3,
            first_broken_epoch_start="2026-08-19T00:00:00+00:00",
            epochs_broken=1,
            newest_broken_epoch_start="2026-08-19T00:00:00+00:00",
            latest_epoch_broken=True,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["latest_epoch_broken"] is True


def test_endpoint_passes_days_param(client: TestClient) -> None:
    """``?days=N`` is threaded into the helper."""
    fake = AsyncMock(
        return_value=ChainVerifyResult(
            ok=True,
            records_verified=1,
            first_broken_seq=None,
            first_seq=0,
            last_seq=0,
            capped=False,
            epochs=1,
            first_broken_epoch_start=None,
            epochs_broken=0,
            newest_broken_epoch_start=None,
            latest_epoch_broken=False,
        )
    )
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain?days=7")
    assert resp.status_code == 200, resp.text
    _args, kwargs = fake.call_args
    assert kwargs["days"] == 7


def test_endpoint_es_error_is_not_reported_as_intact(client: TestClient) -> None:
    """An ES/transport error must surface as 'could not run' (5xx), never ok=true."""
    fake = AsyncMock(side_effect=RuntimeError("ES down"))
    with patch("soc_ai.audit.verify.verify_audit_chain", fake):
        resp = client.get("/api/v1/config/audit/verify-chain")
    assert resp.status_code >= 500
    # The body must not read as an intact chain.
    assert '"ok":true' not in resp.text.replace(" ", "")


def test_endpoint_admin_gated() -> None:
    """With API auth ON, an unauthenticated request is refused; an admin gets through."""
    settings = _settings(
        api_auth_required=True,
        bootstrap_admin_password=SecretStr("admin-pw"),
    )
    for c in _client(settings):
        resp = c.get("/api/v1/config/audit/verify-chain")
        assert resp.status_code in (401, 403)

        login = c.post("/api/v1/login", json={"username": "admin", "password": "admin-pw"})
        assert login.status_code == 200, login.text
        fake = AsyncMock(
            return_value=ChainVerifyResult(
                ok=True,
                records_verified=0,
                first_broken_seq=None,
                first_seq=None,
                last_seq=None,
                capped=False,
                epochs=0,
                first_broken_epoch_start=None,
                epochs_broken=0,
                newest_broken_epoch_start=None,
                latest_epoch_broken=False,
            )
        )
        with patch("soc_ai.audit.verify.verify_audit_chain", fake):
            ok = c.get("/api/v1/config/audit/verify-chain")
        assert ok.status_code == 200
        assert ok.json()["ok"] is True
