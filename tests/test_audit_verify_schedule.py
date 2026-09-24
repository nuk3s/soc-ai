"""The scheduled audit-chain verification in ``soc_ai.main``.

The chain has been checkable since v1 and, in practice, nobody ever checked
it: a live deployment carried a broken current epoch for weeks and the only
thing that would have said so was a button in a diagnostics panel. This loop
is what makes the tamper-evidence a claim the product tests on itself.

Driven the same way the other scheduler suites are: ``soc_ai.main.asyncio.
sleep`` is patched so the first wake returns and the next raises
``CancelledError``, bounding the ``while True`` to exactly one body iteration.
Nothing here touches a real index — ``verify_audit_chain`` is patched at its
source.

What each test pins:
* runs when enabled and due, and stays quiet when disabled or not yet due;
* a break reaches a human on all three channels (audit record, webhook, bell);
* the break is NOT suppressed on the next run — an unfixed chain reports every
  time, which is the honest state;
* a clean run clears a standing alarm, so the bell entry goes away by itself;
* "could not run" is never rendered as tamper;
* a failing iteration is logged and the loop survives;
* cancellation at shutdown is clean.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai import main as main_mod
from soc_ai.api.webui.routes_config import _AuditVerifyStatus, _get_audit_verify_status
from soc_ai.audit.verify import ChainVerifyResult
from soc_ai.main import _audit_verify_due, _audit_verify_loop


def _result(**overrides: Any) -> ChainVerifyResult:
    base: dict[str, Any] = {
        "ok": True,
        "records_verified": 120,
        "first_broken_seq": None,
        "first_seq": 0,
        "last_seq": 119,
        "capped": False,
        "epochs": 1,
        "first_broken_epoch_start": None,
        "epochs_broken": 0,
        "newest_broken_epoch_start": None,
        "latest_epoch_broken": False,
    }
    base.update(overrides)
    return ChainVerifyResult(**base)


def _broken(**overrides: Any) -> ChainVerifyResult:
    base: dict[str, Any] = {
        "ok": False,
        "first_broken_seq": 109667,
        "epochs_broken": 1,
        "first_broken_epoch_start": "2026-09-04T02:32:07Z",
        "newest_broken_epoch_start": "2026-09-04T02:32:07Z",
        "latest_epoch_broken": True,
        "first_break_kind": "duplicate_seq",
        "first_break_detail": "2 records claim sequence 109667",
        "newest_break_kind": "duplicate_seq",
        "newest_break_detail": "2 records claim sequence 109667",
        "duplicate_seqs": 41,
        "extra_records": 51,
        "max_claimants": 4,
        "altered_records": 0,
        "missing_seqs": 0,
        "oldest_break_at": "2026-09-04T02:32:07Z",
        "newest_break_at": "2026-09-04T19:07:04Z",
        "break_kinds": ("duplicate_seq",),
    }
    base.update(overrides)
    return _result(**base)


class _RecordingAudit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    async def log_kind(self, session_id: str, kind: str, payload: dict[str, Any]) -> None:
        self.records.append({"session_id": session_id, "kind": kind, "payload": payload})


def _app(audit: Any = None) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(elastic=object(), audit=audit, settings=None))


def _settings(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "audit_verify_schedule_enabled": True,
        "audit_verify_schedule_interval_hours": 24,
        "audit_verify_days": 7,
        "audit_index_alias": "soc-ai-audit",
        "notify_on_audit_chain_break": True,
        "notify_enabled": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


async def _run_iterations(
    monkeypatch: pytest.MonkeyPatch,
    app: SimpleNamespace,
    settings: Any,
    n: int = 1,
) -> None:
    """Run the loop for exactly *n* body iterations, then unwind."""
    real_sleep = asyncio.sleep
    calls = {"n": 0}

    async def _sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] <= n:
            return None
        raise asyncio.CancelledError()

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)
    try:
        with contextlib.suppress(asyncio.CancelledError):
            await _audit_verify_loop(app, settings)
    finally:
        monkeypatch.setattr(main_mod.asyncio, "sleep", real_sleep)


def _patch_verify(
    monkeypatch: pytest.MonkeyPatch, results: list[Any]
) -> dict[str, list[dict[str, Any]]]:
    """Serve *results* (a value to return, or an exception to raise) in order."""
    seen: dict[str, list[dict[str, Any]]] = {"calls": []}

    async def _verify(_elastic: Any, alias: str, *, days: int | None = None) -> Any:
        seen["calls"].append({"alias": alias, "days": days})
        outcome = results.pop(0) if results else _result()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr("soc_ai.audit.verify.verify_audit_chain", _verify)
    return seen


# --------------------------------------------------------------------------- #
# the pure due-helper
# --------------------------------------------------------------------------- #


def test_never_run_is_due() -> None:
    assert _audit_verify_due(None, 24) is True


def test_elapsed_is_due() -> None:
    stamp = (datetime.now(UTC) - timedelta(hours=25)).isoformat()
    assert _audit_verify_due(stamp, 24) is True


def test_not_elapsed_is_not_due() -> None:
    stamp = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    assert _audit_verify_due(stamp, 24) is False


def test_unparseable_stamp_errs_toward_checking() -> None:
    assert _audit_verify_due("not a timestamp", 24) is True


# --------------------------------------------------------------------------- #
# the loop
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_runs_when_enabled_and_due(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    seen = _patch_verify(monkeypatch, [_result()])
    await _run_iterations(monkeypatch, app, _settings())
    assert seen["calls"] == [{"alias": "soc-ai-audit", "days": 7}]
    assert _get_audit_verify_status(app.state).last_run is not None


@pytest.mark.asyncio
async def test_disabled_never_reads_the_index(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    seen = _patch_verify(monkeypatch, [_result()])
    await _run_iterations(monkeypatch, app, _settings(audit_verify_schedule_enabled=False))
    assert seen["calls"] == []


@pytest.mark.asyncio
async def test_not_due_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    status = _AuditVerifyStatus(last_run=datetime.now(UTC).isoformat())
    app.state._audit_verify_status = status
    seen = _patch_verify(monkeypatch, [_result()])
    await _run_iterations(monkeypatch, app, _settings())
    assert seen["calls"] == []


@pytest.mark.asyncio
async def test_a_break_reaches_a_human_on_every_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Audit record, webhook, and the in-app bell.

    Three channels because two of them can be absent: notifications are off by
    default, and the audit index is exactly the thing that may be unwell. The
    bell entry is held in memory and needs neither.
    """
    audit = _RecordingAudit()
    app = _app(audit)
    _patch_verify(monkeypatch, [_broken()])
    fired: list[Any] = []

    async def _fire_safe(event: Any, _settings: Any, _audit: Any = None) -> None:
        fired.append(event)

    monkeypatch.setattr("soc_ai.notify.fire_safe", _fire_safe)

    await _run_iterations(monkeypatch, app, _settings())

    assert [r["kind"] for r in audit.records] == ["audit_chain_verification"]
    assert audit.records[0]["payload"]["break_kind"] == "duplicate_seq"
    assert audit.records[0]["payload"]["break_seq"] == 109667
    assert len(fired) == 1
    assert fired[0].kind == "audit_chain_break"
    assert fired[0].severity == "critical"
    alarm = _get_audit_verify_status(app.state).alarm
    assert alarm is not None
    assert alarm["break_kind"] == "duplicate_seq"


@pytest.mark.asyncio
async def test_an_unfixed_break_is_reported_every_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No transition gate here, deliberately.

    A quality regression pages once because a standing regression is one
    problem the operator has already seen. A standing break in the audit trail
    is a standing claim that the decision record cannot be trusted, and going
    quiet about it would read as "resolved".
    """
    audit = _RecordingAudit()
    app = _app(audit)
    _patch_verify(monkeypatch, [_broken(), _broken()])
    monkeypatch.setattr("soc_ai.notify.fire_safe", _noop_fire)

    settings = _settings(audit_verify_schedule_interval_hours=0)
    await _run_iterations(monkeypatch, app, settings, n=2)

    assert len(audit.records) == 2


async def _noop_fire(_event: Any, _settings: Any, _audit: Any = None) -> None:
    return None


# --------------------------------------------------------------------------- #
# what a dismissal means for a tamper alarm
# --------------------------------------------------------------------------- #
#
# The alarm lived only in application state and the bell entry's id embedded
# the detection timestamp, so every run minted a new identity and the entry
# could not be cleared. On the deployed instance that meant an undismissable
# danger notification every day until a forked stretch of history aged out of
# the seven-day window.
#
# The bell's dismissal mechanism is the one every other standing alarm here
# uses: a stable id the client remembers. So the identity has to be the
# FINDING, not the moment it was noticed. What goes into it, and what
# deliberately does not, is the whole of the safety argument:
#
# * the break kinds present, so dismissing a known historical fork can never
#   suppress a record being edited, because that is a different key;
# * the newest record involved in any break, so anything that breaks after a
#   dismissal moves this forward and re-raises;
# * how many records no longer match their own hash, so a further alteration
#   re-raises even when the kind is already showing;
# * NOT the duplicate or extra-record counts, because a rolling window sheds
#   old records every day and a key that moved on that would re-raise the same
#   historical scar every morning, which is the defect being fixed.


def _run_alarm(monkeypatch: pytest.MonkeyPatch, app: Any, results: list[Any]) -> Any:
    """Run one iteration per result, returning the final alarm dict."""
    _patch_verify(monkeypatch, results)
    monkeypatch.setattr("soc_ai.notify.fire_safe", _noop_fire)
    return _get_audit_verify_status(app.state)


@pytest.mark.asyncio
async def test_the_same_finding_keeps_one_identity_across_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two runs, one scar, one identity, so a dismissal holds overnight."""
    app = _app(_RecordingAudit())
    status = _run_alarm(monkeypatch, app, [_broken(), _broken()])
    settings = _settings(audit_verify_schedule_interval_hours=0)

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    first_key, first_since = status.alarm["alarm_key"], status.alarm["alarm_since"]

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    assert status.alarm["alarm_key"] == first_key
    # The clock the bell renders stays put too, so the entry reads as the
    # standing thing it is rather than "just now" every morning.
    assert status.alarm["alarm_since"] == first_since
    # The verification itself still ran and still recorded: the identity is
    # stable, the reporting is not suppressed. `detected_at` is the last time
    # the finding was seen, and it moves.
    assert status.alarm["detected_at"] >= first_since


@pytest.mark.asyncio
async def test_the_window_shedding_old_records_does_not_re_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scar shrinks as it ages out. That is not a new finding.

    All 41 duplicated positions fall before the fix that stopped the forking,
    so as the seven-day window rolls the counts fall day by day. Keying on them
    would mint a new identity every morning and defeat the dismissal.
    """
    app = _app(_RecordingAudit())
    status = _run_alarm(
        monkeypatch,
        app,
        [_broken(), _broken(duplicate_seqs=38, extra_records=46, max_claimants=3)],
    )
    settings = _settings(audit_verify_schedule_interval_hours=0)

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    first_key = status.alarm["alarm_key"]

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    assert status.alarm["alarm_key"] == first_key
    # The counts themselves still move, so the operator sees the scar shrinking.
    assert status.alarm["duplicate_seqs"] == 38


@pytest.mark.asyncio
async def test_a_break_after_a_dismissal_mints_a_new_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Anything that forks after the dismissal moves the newest affected record."""
    app = _app(_RecordingAudit())
    status = _run_alarm(
        monkeypatch,
        app,
        [
            _broken(),
            _broken(duplicate_seqs=42, extra_records=52, newest_break_at="2026-09-06T08:00:00Z"),
        ],
    )
    settings = _settings(audit_verify_schedule_interval_hours=0)

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    first_key, first_since = status.alarm["alarm_key"], status.alarm["alarm_since"]

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    assert status.alarm["alarm_key"] != first_key
    assert status.alarm["alarm_since"] != first_since


@pytest.mark.asyncio
async def test_dismissing_a_fork_cannot_suppress_an_alteration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lever the verifier already gives us.

    A duplicated position is what a second writer leaves behind and an operator
    can reasonably acknowledge it as the known, bounded, historical thing it
    is. A record whose content no longer matches its own hash is someone
    changing the record of a decision. The second must never inherit the
    first's dismissal, so the kind is part of the identity, and a finding that
    includes an alteration is not offered as dismissible at all.
    """
    app = _app(_RecordingAudit())
    status = _run_alarm(
        monkeypatch,
        app,
        [
            _broken(),
            _broken(
                altered_records=1,
                break_kinds=("content_altered", "duplicate_seq"),
                newest_break_kind="content_altered",
            ),
        ],
    )
    settings = _settings(audit_verify_schedule_interval_hours=0)

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    fork_key = status.alarm["alarm_key"]
    assert status.alarm["dismissible"] is True

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    assert status.alarm["alarm_key"] != fork_key
    assert status.alarm["dismissible"] is False


@pytest.mark.asyncio
async def test_a_further_alteration_re_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A second edited record, same kind, same timestamps, still a new finding."""
    app = _app(_RecordingAudit())
    one = _broken(
        duplicate_seqs=0,
        extra_records=0,
        max_claimants=0,
        altered_records=1,
        break_kinds=("content_altered",),
        newest_break_kind="content_altered",
    )
    two = _broken(
        duplicate_seqs=0,
        extra_records=0,
        max_claimants=0,
        altered_records=2,
        break_kinds=("content_altered",),
        newest_break_kind="content_altered",
    )
    status = _run_alarm(monkeypatch, app, [one, two])
    settings = _settings(audit_verify_schedule_interval_hours=0)

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    first_key = status.alarm["alarm_key"]

    await _run_iterations(monkeypatch, app, settings, n=1)
    assert status.alarm is not None
    assert status.alarm["alarm_key"] != first_key


@pytest.mark.asyncio
async def test_the_alarm_carries_the_blast_radius_not_one_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The audit record, the webhook and the bell all get the scale."""
    audit = _RecordingAudit()
    app = _app(audit)
    _patch_verify(monkeypatch, [_broken()])
    fired: list[Any] = []

    async def _fire_safe(event: Any, _settings: Any, _audit: Any = None) -> None:
        fired.append(event)

    monkeypatch.setattr("soc_ai.notify.fire_safe", _fire_safe)
    await _run_iterations(monkeypatch, app, _settings())

    payload = audit.records[0]["payload"]
    assert payload["duplicate_seqs"] == 41
    assert payload["extra_records"] == 51
    assert payload["max_claimants"] == 4
    assert payload["altered_records"] == 0
    assert "41 sequence numbers" in payload["blast_radius"]
    assert "41 sequence numbers" in fired[0].body
    alarm = _get_audit_verify_status(app.state).alarm
    assert alarm is not None
    assert "no record was altered" in alarm["blast_radius"].lower()


@pytest.mark.asyncio
async def test_a_clean_run_clears_a_standing_alarm(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(_RecordingAudit())
    status = _get_audit_verify_status(app.state)
    status.alarm = {"break_kind": "duplicate_seq", "detected_at": "2026-09-06T00:00:00Z"}
    _patch_verify(monkeypatch, [_result()])
    await _run_iterations(monkeypatch, app, _settings())
    assert status.alarm is None


@pytest.mark.asyncio
async def test_an_unreadable_index_is_not_reported_as_tamper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "Could not run" is not a verdict. Alarming on it teaches the operator to
    ignore the alarm that matters."""
    audit = _RecordingAudit()
    app = _app(audit)
    _patch_verify(monkeypatch, [RuntimeError("audit index unreachable")])
    fired: list[Any] = []

    async def _fire_safe(event: Any, _settings: Any, _audit: Any = None) -> None:
        fired.append(event)

    monkeypatch.setattr("soc_ai.notify.fire_safe", _fire_safe)

    await _run_iterations(monkeypatch, app, _settings())

    assert audit.records == []
    assert fired == []
    assert _get_audit_verify_status(app.state).alarm is None


@pytest.mark.asyncio
async def test_a_failing_iteration_does_not_kill_the_loop(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app()

    # No elastic on state and a settings object that raises on the toggle read:
    # the widest failure the loop can meet inside its own body.
    class _Boom:
        def __getattr__(self, _name: str) -> Any:
            raise RuntimeError("settings exploded")

    with caplog.at_level(logging.ERROR):
        await _run_iterations(monkeypatch, app, _Boom(), n=2)
    assert "audit chain verification scheduler iteration failed" in caplog.text


@pytest.mark.asyncio
async def test_cancellation_is_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    _patch_verify(monkeypatch, [])
    task = asyncio.create_task(_audit_verify_loop(app, _settings()))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
