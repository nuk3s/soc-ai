"""The retry wait, the alarm and the pause of Auto-Investigate.

Pure tests of :mod:`soc_ai.webui.autotriage_health`. The clock is an argument
or the patched ``_now()``, and every base time is relative to now, so no test
here rots with the calendar.

The two replays model the 2026-10-27 gateway refusal and the 2026-10-28
timeouts. Each replay runs the planner's rule (retry_hold, then take_probe)
over 5-minute cycles against a model of the store's failed-run count.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from soc_ai.store.investigations import FailedRuns
from soc_ai.webui import autotriage_health as ah

SYNTH = ("synth_first_round1", "ModelHTTPError")


def _naive(at: datetime) -> datetime:
    return at.astimezone(UTC).replace(tzinfo=None)


def _hold(count: int, limit: int, ago: timedelta) -> str | None:
    now = _naive(datetime.now(UTC))
    return ah.retry_hold(limit, FailedRuns(count=count, last_at=now - ago), now=now)


# ---------------------------------------------------------------------------
# The retry wait
# ---------------------------------------------------------------------------


def test_the_wait_doubles_after_each_failure() -> None:
    assert _hold(1, 2, timedelta(minutes=14)) == "retry_wait"
    assert _hold(1, 2, timedelta(minutes=16)) is None
    assert _hold(2, 2, timedelta(minutes=29)) == "retry_wait"
    assert _hold(2, 2, timedelta(minutes=31)) is None


def test_an_alert_past_the_limit_waits_six_hours() -> None:
    assert _hold(3, 2, timedelta(hours=5, minutes=59)) == "retry_limit"
    assert _hold(3, 2, timedelta(hours=6, minutes=1)) is None
    assert _hold(1, 0, timedelta(hours=2)) == "retry_limit"


def test_an_alert_with_no_failure_is_never_held() -> None:
    assert ah.retry_hold(2, None, now=_naive(datetime.now(UTC))) is None


def test_the_wait_never_passes_the_slow_wait() -> None:
    assert ah.retry_wait(10, 10) == ah.RETRY_SLOW_WAIT
    assert ah.retry_wait(6, 10) == ah.RETRY_SLOW_WAIT
    assert ah.retry_wait(3, 10) == timedelta(hours=1)


# ---------------------------------------------------------------------------
# The alarm
# ---------------------------------------------------------------------------


def test_five_failures_of_one_error_in_two_hours_open_one_alarm() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(hours=1)
    opened = []
    for i in range(5):
        at = t0 + timedelta(minutes=10 * i)
        opened.append(health.record_failure(f"a{i}", *SYNTH, at=at)[0])
        health.record_verdict(f"other{i}", at=at + timedelta(minutes=1))
    assert opened == [False, False, False, False, True]
    alarm = health.newest_alarm()
    assert alarm is not None
    since = alarm.since

    assert health.record_failure("a5", *SYNTH, at=t0 + timedelta(minutes=50)) == (False, False)
    alarm = health.newest_alarm()
    assert alarm is not None
    assert alarm.since == since
    assert alarm.failures == 6
    assert ah.describe(alarm.phase, alarm.error_type) == "ModelHTTPError in synth_first_round1"


def test_failures_spread_over_two_hours_open_no_alarm() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(hours=3)
    for i in range(5):
        at = t0 + timedelta(minutes=35 * i)
        assert health.record_failure(f"a{i}", *SYNTH, at=at)[0] is False
        health.record_verdict(f"other{i}", at=at + timedelta(minutes=1))
    assert health.newest_alarm() is None


@pytest.mark.parametrize("limit", [2, 10])
def test_one_alert_alone_cannot_open_the_alarm(limit: int) -> None:
    health = ah.TriageHealth()
    store = _Store()
    t0 = datetime.now(UTC) - timedelta(days=1)
    runs = 0
    for cycle in range(24 * 12):
        at = t0 + timedelta(minutes=5 * cycle)
        for alert in _plan(health, store, ["solo"], at=at, limit=limit):
            runs += 1
            store.fail(alert, at)
            assert health.record_failure(alert, *SYNTH, at=at)[0] is False
        health.record_verdict(f"std{cycle}", at=at + timedelta(seconds=30))
    assert health.newest_alarm() is None
    assert runs >= 4


def test_timeout_shapes_count_as_one_error() -> None:
    keys = {
        ah.error_key("whole_run_backstop", "TimeoutError"),
        ah.error_key("run_cancelled", "CancelledError"),
        ah.error_key("per_target_cap", "TimeoutError"),
        ah.error_key("investigation_loop_timeout", "TimeoutError"),
    }
    assert keys == {"timeout"}
    assert ah.error_key("investigation_loop", "ModelHTTPError") != "timeout"
    assert ah.error_key("investigation_loop", "ModelHTTPError") != ah.error_key(*SYNTH)
    assert ah.describe("", "ModelHTTPError") == "ModelHTTPError"


def _open_alarm(health: ah.TriageHealth, at: datetime, prefix: str = "a") -> None:
    """Five failures of SYNTH on five alerts, a verdict on another alert between."""
    for i in range(1, 6):
        health.record_failure(f"{prefix}{i}", *SYNTH, at=at + timedelta(minutes=i))
        health.record_verdict(f"between{prefix}{i}", at=at + timedelta(minutes=i, seconds=30))
    assert health.newest_alarm() is not None


def test_a_verdict_on_a_failed_alert_closes_its_alarm_and_gives_retries_back() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("b1", "investigation_loop", "ModelHTTPError", at=t0)
    _open_alarm(health, t0)

    health.record_verdict("other", at=t0 + timedelta(minutes=10))
    assert health.newest_alarm() is not None

    healed_at = t0 + timedelta(minutes=11)
    health.record_verdict("a3", at=healed_at)
    assert health.newest_alarm() is None
    for alert in ("a1", "a2", "a4", "a5"):
        assert health.heal_since(alert) == healed_at
    assert health.heal_since("b1") is None


def test_a_stale_alarm_closes_on_the_next_verdict() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(hours=4)
    _open_alarm(health, t0)
    alarm = health.newest_alarm()
    assert alarm is not None

    health.record_verdict("other", at=alarm.last_at + timedelta(hours=2, minutes=1))
    assert health.newest_alarm() is None
    for i in range(1, 6):
        assert health.heal_since(f"a{i}") is None


def test_a_second_error_opens_its_own_alarm() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=40)
    _open_alarm(health, t0)
    other = ("investigation_loop", "ModelHTTPError")
    opened = []
    for i in range(1, 6):
        at = t0 + timedelta(minutes=10 + i)
        opened.append(health.record_failure(f"l{i}", *other, at=at)[0])
        health.record_verdict(f"betweenl{i}", at=at + timedelta(seconds=30))
    assert opened[-1] is True
    newest = health.newest_alarm()
    assert newest is not None
    assert newest.key == ah.error_key(*other)
    row = health.bell_row(at=t0 + timedelta(minutes=20))
    assert row is not None
    assert row[0] == f"auto-triage-failing:{ah.breaker.iso(newest.since)}"


# ---------------------------------------------------------------------------
# The pause
# ---------------------------------------------------------------------------


def test_five_failures_in_a_row_with_no_verdict_pause_the_runs() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(hours=2)
    errors = [SYNTH, ("investigation_loop", "ModelHTTPError"), ("worker", "RuntimeError")]
    opened = []
    for i in range(5):
        opened.append(
            health.record_failure(f"p{i}", *errors[i % 3], at=t0 + timedelta(minutes=i))[1]
        )
    t = t0 + timedelta(minutes=4)
    assert opened == [False, False, False, False, True]
    assert health.paused_until == t + timedelta(minutes=15)
    assert health.is_paused(at=t + timedelta(minutes=14))
    assert not health.is_paused(at=t + timedelta(minutes=16))
    since = health.pause_since

    for minutes, wait in ((20, 30), (60, 60), (130, 60)):
        at = t0 + timedelta(minutes=minutes)
        assert health.record_failure("p0", *SYNTH, at=at)[1] is False
        assert health.paused_until == at + timedelta(minutes=wait)
        assert health.pause_since == since

    health.record_verdict("fresh", at=t0 + timedelta(minutes=131))
    assert health.paused_until is None
    assert health.pause_since is None
    assert not health.is_paused(at=t0 + timedelta(minutes=132))
    assert all(health.heal_since(f"p{i}") is None for i in range(5))


def test_a_long_pause_stays_at_one_hour() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(days=1)
    for i in range(400):
        health.record_failure(f"x{i % 7}", *SYNTH, at=t0 + timedelta(minutes=i))
    last = t0 + timedelta(minutes=399)
    assert health.paused_until == last + ah.PAUSE_MAX


def test_a_verdict_between_failures_keeps_the_runs_going() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(hours=1)
    for i in range(8):
        at = t0 + timedelta(minutes=2 * i)
        assert health.record_failure(f"v{i}", "worker", "RuntimeError", at=at)[1] is False
        health.record_verdict(f"ok{i}", at=at + timedelta(minutes=1))
    assert health.paused_until is None
    assert not health.is_paused(at=t0 + timedelta(minutes=20))


# ---------------------------------------------------------------------------
# The probe
# ---------------------------------------------------------------------------


def test_the_probe_runs_one_failed_alert_each_hour() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(hours=3)
    health.record_failure("b1", "investigation_loop", "ModelHTTPError", at=t0)
    _open_alarm(health, t0)
    alarm = health.newest_alarm()
    assert alarm is not None
    last = alarm.last_at

    assert health.take_probe("a1", at=last + timedelta(minutes=59)) is False
    assert health.take_probe("a1", at=last + timedelta(hours=1)) is True
    assert health.take_probe("a2", at=last + timedelta(hours=1, minutes=5)) is False
    assert health.take_probe("b1", at=last + timedelta(hours=2)) is False
    assert health.take_probe("never-failed", at=last + timedelta(hours=2)) is False
    assert health.take_probe("a2", at=last + timedelta(hours=2)) is True


# ---------------------------------------------------------------------------
# The texts
# ---------------------------------------------------------------------------


def test_the_texts_name_the_error() -> None:
    until = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=15)
    stamp = until.strftime("%Y-%m-%d %H:%M:%S")
    error = "ModelHTTPError in synth_first_round1"
    pause = ah.pause_text(until, 5, error)
    alarm = ah.alarm_text(7, error)
    assert pause == (
        f"Continuous Auto-Investigate is paused until {stamp} UTC. The last 5 runs failed, "
        "and no run reached a verdict. The last error is ModelHTTPError in "
        "synth_first_round1. A run that reaches a verdict ends the pause."
    )
    assert alarm == (
        "7 Auto-Investigate runs failed with the same error: ModelHTTPError in "
        "synth_first_round1. A failed alert waits longer before each retry. A verdict on "
        "one of these alerts closes this alarm."
    )
    for text in (pause, alarm):
        assert "—" not in text
        assert "–" not in text

    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=50)
    assert health.bell_row(at=t0) is None
    _open_alarm(health, t0)
    row = health.bell_row(at=t0 + timedelta(minutes=6))
    assert row is not None
    first_id = row[0]
    assert row[1].startswith("5 Auto-Investigate runs failed")

    for i in range(5):
        health.record_failure(f"a{i + 1}", *SYNTH, at=t0 + timedelta(minutes=10 + i))
    paused = health.bell_row(at=t0 + timedelta(minutes=15))
    assert paused is not None
    assert paused[0] == first_id
    assert paused[1].startswith("Continuous Auto-Investigate is paused until")

    health.record_verdict("fresh", at=t0 + timedelta(minutes=16))
    closed = health.bell_row(at=t0 + timedelta(minutes=17))
    assert closed is not None
    assert closed[0] == first_id
    assert closed[1].startswith("10 Auto-Investigate runs failed")


def test_the_status_fields_name_the_pause_and_the_alarm() -> None:
    health = ah.TriageHealth()
    assert health.status_fields() == {
        "paused_until": None,
        "pause_ends": None,
        "failed_in_a_row": 0,
        "gateway_paused": False,
        "alarm_error": None,
        "alarm_failures": 0,
    }
    at = datetime.now(UTC) - timedelta(minutes=5)
    for i in range(5):
        health.record_failure(f"s{i}", *SYNTH, at=at)
    fields = health.status_fields()
    assert fields["paused_until"] == ah.breaker.iso(at + timedelta(minutes=15))
    assert fields["pause_ends"] == fields["paused_until"]
    assert fields["failed_in_a_row"] == 5
    assert fields["alarm_error"] == "ModelHTTPError in synth_first_round1"
    assert fields["alarm_failures"] == 5


def test_the_status_fields_keep_the_end_of_a_pause_that_ran_out() -> None:
    # The pause ran out, and no run reached a verdict yet. The next scheduled
    # run comes up to one interval later. The Status page measures an overdue
    # run from the end of the pause, so it needs that moment.
    health = ah.TriageHealth()
    at = datetime.now(UTC) - timedelta(minutes=17)
    for i in range(5):
        health.record_failure(f"r{i}", *SYNTH, at=at)
    fields = health.status_fields()
    assert fields["paused_until"] is None
    assert fields["failed_in_a_row"] == 0
    assert fields["pause_ends"] == ah.breaker.iso(at + timedelta(minutes=15))
    health.record_verdict("other")
    assert health.status_fields()["pause_ends"] is None


def test_the_patched_clock_drives_the_default_time(monkeypatch: pytest.MonkeyPatch) -> None:
    fixed = datetime.now(UTC) - timedelta(hours=1)
    monkeypatch.setattr(ah, "_now", lambda: fixed)
    health = ah.TriageHealth()
    for i in range(5):
        health.record_failure(f"c{i}", *SYNTH)
    assert health.paused_until == fixed + timedelta(minutes=15)
    assert health.is_paused()


# ---------------------------------------------------------------------------
# The replays
# ---------------------------------------------------------------------------


class _Store:
    """The store's failed-run count, as failed_runs_for_alerts reads it."""

    def __init__(self) -> None:
        self.failures: dict[str, list[datetime]] = {}
        self.verdicts: dict[str, datetime] = {}

    def fail(self, alert: str, at: datetime) -> None:
        self.failures.setdefault(alert, []).append(_naive(at))

    def verdict(self, alert: str, at: datetime) -> None:
        self.verdicts[alert] = _naive(at)

    def failed(self, alert: str, healed: datetime | None) -> FailedRuns | None:
        floors = [self.verdicts.get(alert)]
        if healed is not None:
            floors.append(_naive(healed))
        floor = max((f for f in floors if f is not None), default=None)
        counted = [t for t in self.failures.get(alert, []) if floor is None or t > floor]
        return FailedRuns(count=len(counted), last_at=max(counted)) if counted else None


def _plan(
    health: ah.TriageHealth, store: _Store, alerts: list[str], *, at: datetime, limit: int
) -> list[str]:
    """The planner's order: the probe, then fresh alerts, then retries."""
    probe: str | None = None
    fresh: list[str] = []
    retries: list[str] = []
    for alert in alerts:
        failed = store.failed(alert, health.heal_since(alert))
        hold = ah.retry_hold(limit, failed, now=_naive(at))
        if hold and probe is None and health.take_probe(alert, at=at):
            probe = alert
            continue
        if hold:
            continue
        (retries if failed else fresh).append(alert)
    return ([probe] if probe else []) + fresh + retries


def test_the_2026_10_27_replay_raises_one_alarm_and_recovers() -> None:
    base = datetime.now(UTC) - timedelta(days=1)
    fault_ends = base + timedelta(minutes=689)
    health = ah.TriageHealth()
    store = _Store()
    runs_in_fault = 0
    failures = 0
    alarm_opened_on: str | None = None
    verdict_at: dict[str, datetime] = {}
    for cycle in range(12 * 15):
        at = base + timedelta(minutes=5 * cycle)
        cluster = ["A", "B"] if at < base + timedelta(minutes=26) else ["C", "D"]
        # A settled alert blocks its own rehunt (blocks_rehunt).
        alerts = [a for a in cluster if a not in verdict_at]
        ran = False
        for alert in _plan(health, store, alerts, at=at, limit=2):
            ran = True
            if at < fault_ends:
                runs_in_fault += 1
                failures += 1
                store.fail(alert, at)
                if health.record_failure(alert, *SYNTH, at=at)[0]:
                    assert failures == 5
                    alarm_opened_on = alert
                    alarm = health.newest_alarm()
                    assert alarm is not None
                    assert ah.describe(alarm.phase, alarm.error_type) == (
                        "ModelHTTPError in synth_first_round1"
                    )
            else:
                store.verdict(alert, at)
                health.record_verdict(alert, at=at)
                verdict_at.setdefault(alert, at)
            assert not health.is_paused(at=at)
        if ran:
            health.record_verdict(f"standard-{cycle}", at=at + timedelta(minutes=3))
        assert health.pause_since is None
    assert alarm_opened_on == "C"
    assert runs_in_fault <= 24
    for alert in ("C", "D"):
        assert alert in verdict_at
        assert verdict_at[alert] - fault_ends <= timedelta(minutes=75)
    assert health.newest_alarm() is None


def test_the_2026_10_28_replay_lets_one_alert_recover() -> None:
    errors = [
        ("whole_run_backstop", "TimeoutError"),
        ("run_cancelled", "CancelledError"),
        ("investigation_loop", "ModelHTTPError"),
    ]
    durations = [timedelta(minutes=15), timedelta(minutes=12), timedelta(minutes=10)]
    base = datetime.now(UTC) - timedelta(days=1)
    health = ah.TriageHealth()
    store = _Store()
    first_failure: datetime | None = None
    fault_ends: datetime | None = None
    failed_at: list[datetime] = []
    # The start of the run that reaches a verdict.
    verdict: datetime | None = None
    busy_until = base
    runs = 0
    cycle = 0
    while verdict is None and cycle < 12 * 12:
        at = base + timedelta(minutes=5 * cycle)
        cycle += 1
        if at < busy_until:
            continue
        for alert in _plan(health, store, ["E"], at=at, limit=2):
            end = at + durations[min(runs, 2)]
            busy_until = end
            if fault_ends is None or end < fault_ends:
                store.fail(alert, end)
                phase, kind = errors[min(runs, 2)]
                opened = health.record_failure(alert, phase, kind, at=end)
                assert opened == (False, False)
                failed_at.append(end)
                if first_failure is None:
                    first_failure = end
                    fault_ends = end + timedelta(minutes=98)
            else:
                store.verdict(alert, end)
                health.record_verdict(alert, at=end)
                verdict = at
            runs += 1
        health.record_verdict(f"other-{cycle}", at=at + timedelta(minutes=1))
    assert fault_ends is not None
    assert health.newest_alarm() is None
    assert health.pause_since is None
    assert len([t for t in failed_at if t < fault_ends]) <= 3
    # The run that reaches the verdict starts at most one cycle after the slow
    # wait ends.
    assert verdict is not None
    assert len(failed_at) == 3
    assert verdict - failed_at[2] <= timedelta(hours=6, minutes=5)


# ---------------------------------------------------------------------------
# The gateway pause (B5, 2026-11-13)
# ---------------------------------------------------------------------------
#
# From 2026-11-01 to 2026-11-12 the gateway could not reach the model engine in
# eight windows. 62 runs failed, each in 5 to 12 seconds, and the sweep started
# the next alert at once. The pause of five failures in a row opened six times,
# after it burned five alerts each time. 33 alerts kept an error and no verdict.

GATEWAY_500 = (
    "status_code: 500, model_name: analyst, body: {'message': 'litellm.InternalServerError: "
    "Hosted_vllmException - Cannot connect to host 10.0.0.9:8888', 'type': None}"
)
GATEWAY_502 = "status_code: 502, model_name: analyst, body: Bad Gateway"
LOOP = ("investigation_loop", "ModelHTTPError")


@pytest.mark.parametrize(
    ("error_type", "message"),
    [
        ("ModelHTTPError", GATEWAY_500),
        ("ModelHTTPError", GATEWAY_502),
        ("ModelHTTPError", "status_code: 503, model_name: analyst, body: no healthy deployment"),
        ("ModelAPIError", "Connection error."),
        ("APIConnectionError", "Connection error."),
        ("ConnectError", "All connection attempts failed"),
    ],
)
def test_a_gateway_connection_error_is_recognized(error_type: str, message: str) -> None:
    assert ah.is_gateway_connection_error(error_type, message)


@pytest.mark.parametrize(
    ("error_type", "message"),
    [
        # The 2026-10-27 failure: the gateway answered, and refused the schema.
        ("ModelHTTPError", "status_code: 400, model_name: analyst, body: schema refused"),
        ("ModelHTTPError", "status_code: 500, model_name: analyst, body: internal error"),
        ("ModelHTTPError", "status_code: 429, model_name: analyst, body: rate limit"),
        ("UnexpectedModelBehavior", "Model token limit (32000) exceeded before any response"),
        ("ModelAPIError", "Request timed out."),
        ("TimeoutError", ""),
        ("CancelledError", ""),
        ("RuntimeError", "Cannot connect to host"),
    ],
)
def test_another_failure_is_not_a_gateway_connection_error(error_type: str, message: str) -> None:
    """Negative controls: an answer of the gateway, a timeout and a fault of
    the worker keep the rule of five failures in a row."""
    assert not ah.is_gateway_connection_error(error_type, message)


def test_two_gateway_connection_errors_in_sequence_pause_the_sweep() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("a0", *LOOP, message=GATEWAY_500, at=t0)
    assert not health.gateway_paused
    assert not health.blocks_sweep(at=t0)
    health.record_failure("a1", *LOOP, message=GATEWAY_500, at=t0 + timedelta(seconds=8))
    assert health.gateway_paused
    assert health.blocks_sweep(at=t0 + timedelta(seconds=9))
    # The pause has no end time. Only a test of the gateway that passes ends it.
    assert health.blocks_sweep(at=t0 + timedelta(days=2))
    assert health.paused_until is None


def test_another_failure_between_two_gateway_errors_opens_no_pause() -> None:
    """Negative control: the two errors must be in sequence."""
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("a0", *LOOP, message=GATEWAY_500, at=t0)
    health.record_failure("a1", "synth_first_round1", "UnexpectedModelBehavior", at=t0)
    health.record_failure("a2", *LOOP, message=GATEWAY_500, at=t0)
    assert not health.gateway_paused


def test_a_verdict_between_two_gateway_errors_opens_no_pause() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("a0", *LOOP, message=GATEWAY_502, at=t0)
    health.record_verdict("ok", at=t0)
    health.record_failure("a1", *LOOP, message=GATEWAY_502, at=t0)
    assert not health.gateway_paused


def test_two_failures_of_another_class_do_not_open_the_gateway_pause() -> None:
    """Negative control: the rule of five failures in a row did not change."""
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    for i in range(4):
        health.record_failure(f"a{i}", *SYNTH, message="status_code: 400, body: refused", at=t0)
    assert not health.gateway_paused
    assert not health.blocks_sweep(at=t0)
    assert health.record_failure("a4", *SYNTH, message="status_code: 400", at=t0)[1] is True
    assert health.is_paused(at=t0)


def test_a_recovery_closes_the_pause_and_gives_the_failed_alerts_their_runs_back() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("a0", *LOOP, message=GATEWAY_500, at=t0)
    health.record_failure("a1", *LOOP, message=GATEWAY_500, at=t0)
    health.record_failure("other", *SYNTH, message="status_code: 400", at=t0)
    t1 = t0 + timedelta(minutes=10)
    healed = health.record_gateway_recovered(["stored-alert"], at=t1)
    assert not health.gateway_paused
    assert not health.blocks_sweep(at=t1)
    # The alerts that failed on the gateway run again at once: the two that
    # this process saw, and the one that the store named.
    assert sorted(healed) == ["a0", "a1", "stored-alert"]
    assert health.heal_since("a0") == t1
    assert health.heal_since("a1") == t1
    assert health.heal_since("stored-alert") == t1
    # Negative control: an alert that failed with another error keeps its wait.
    assert health.heal_since("other") is None
    # The next gateway error starts a new count.
    health.record_failure("a2", *LOOP, message=GATEWAY_500, at=t1)
    assert not health.gateway_paused


def test_the_bell_and_the_status_name_the_gateway_pause() -> None:
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("a0", *LOOP, message=GATEWAY_500, at=t0)
    health.record_failure("a1", *LOOP, message=GATEWAY_500, at=t0)
    row = health.bell_row(at=t0 + timedelta(minutes=1))
    assert row is not None
    assert row[1] == (
        "Continuous Auto-Investigate is paused. The model gateway failed 2 runs in a row "
        "with a connection error. The last error is ModelHTTPError in investigation_loop. "
        "soc-ai tests the gateway before each scheduled run. A test that passes ends the pause."
    )
    fields = health.status_fields(at=t0 + timedelta(minutes=1))
    assert fields["gateway_paused"] is True
    assert fields["failed_in_a_row"] == 2
    assert fields["alarm_error"] == "ModelHTTPError in investigation_loop"
    health.record_gateway_recovered([], at=t0 + timedelta(minutes=5))
    assert health.bell_row(at=t0 + timedelta(minutes=6)) is None
    assert health.status_fields(at=t0 + timedelta(minutes=6))["gateway_paused"] is False


def test_the_gateway_pause_text_reads_in_ste() -> None:
    text = ah.gateway_pause_text(2, "ModelHTTPError in investigation_loop")
    assert "—" not in text and "–" not in text and "(" not in text
    for sentence in text.split(". "):
        assert len(sentence.split()) <= 25, sentence


def test_a_verdict_from_any_run_closes_the_gateway_pause() -> None:
    """Review defect 5. A press reached a verdict while the gateway pause was
    open, so the gateway answers. The pause stayed open, the sweep stayed
    blocked, and the bell read "failed 0 runs in a row"."""
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("a1", *LOOP, message=GATEWAY_502, at=t0)
    health.record_failure("a2", *LOOP, message=GATEWAY_502, at=t0)
    assert health.gateway_paused
    t1 = t0 + timedelta(minutes=3)
    health.record_verdict("a3", at=t1)
    assert not health.gateway_paused
    assert not health.blocks_sweep(at=t1)
    assert health.bell_row(at=t1) is None
    assert health.status_fields(at=t1)["gateway_paused"] is False
    # The alerts that failed on the gateway have their runs back.
    assert health.heal_since("a1") == t1
    assert health.heal_since("a2") == t1


def test_the_bell_keeps_the_count_of_the_gateway_errors() -> None:
    """The bell text must match the real state. Another failure during the
    pause set the count of the text to zero."""
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("a1", *LOOP, message=GATEWAY_502, at=t0)
    health.record_failure("a2", *LOOP, message=GATEWAY_502, at=t0)
    health.record_failure("a3", "worker", "RuntimeError", message="another fault", at=t0)
    assert health.gateway_paused
    row = health.bell_row(at=t0 + timedelta(minutes=1))
    assert row is not None
    assert "failed 2 runs in a row with a connection error" in row[1]
    assert health.status_fields(at=t0 + timedelta(minutes=1))["failed_in_a_row"] == 2
    # A third gateway error during the pause counts.
    health.record_failure("a4", *LOOP, message=GATEWAY_502, at=t0)
    row = health.bell_row(at=t0 + timedelta(minutes=1))
    assert row is not None
    assert "failed 3 runs in a row with a connection error" in row[1]


def test_a_failure_does_not_close_the_gateway_pause() -> None:
    """Negative control: only a verdict or a gateway test that passes closes it."""
    health = ah.TriageHealth()
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    health.record_failure("a1", *LOOP, message=GATEWAY_502, at=t0)
    health.record_failure("a2", *LOOP, message=GATEWAY_502, at=t0)
    health.record_failure("a3", *SYNTH, message="status_code: 400, body: refused", at=t0)
    assert health.gateway_paused
    assert health.blocks_sweep(at=t0 + timedelta(days=1))
