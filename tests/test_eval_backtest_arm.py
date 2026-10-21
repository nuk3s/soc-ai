"""scripts/eval/backtest_arm.py: the HTTP steps of one backtest arm, against a fake transport.

No network: every test injects an ``opener`` that returns a canned response
instead of calling :func:`urllib.request.urlopen`, and asserts on the
request it was handed (method, URL, body) and the value the helper
returns.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "eval" / "backtest_arm.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("backtest_arm", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["backtest_arm"] = module
    spec.loader.exec_module(module)
    return module


backtest_arm = _load()


class _FakeResponse:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = json.dumps(body).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _RecordingOpener:
    """An opener that records every request and answers from a fixed queue."""

    def __init__(self, *responses: dict[str, Any]) -> None:
        self._responses = list(responses)
        self.requests: list[Request] = []

    def __call__(self, request: Request) -> _FakeResponse:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError("the fake transport ran out of canned responses")
        return _FakeResponse(self._responses.pop(0))


def test_set_strategy_posts_the_investigator_strategy_key() -> None:
    opener = _RecordingOpener({"ok": True, "restart_required": False})

    result = backtest_arm.set_strategy("https://host", "tok", "ensemble", opener=opener)

    assert result == {"ok": True, "restart_required": False}
    assert len(opener.requests) == 1
    request = opener.requests[0]
    assert request.full_url == "https://host/api/v1/config/setting"
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer tok"
    assert json.loads(request.data) == {"key": "investigator_strategy", "value": "ensemble"}


def test_start_backtest_posts_the_window_and_sample_size() -> None:
    opener = _RecordingOpener({"active": True, "backtest_id": None, "total": 0})

    result = backtest_arm.start_backtest(
        "https://host", "tok", window_days=30, sample_size=40, opener=opener
    )

    assert result["active"] is True
    request = opener.requests[0]
    assert request.full_url == "https://host/api/v1/backtest"
    assert json.loads(request.data) == {"window_days": 30, "sample_size": 40}


def test_start_backtest_carries_min_severity_only_when_given() -> None:
    opener = _RecordingOpener({"active": True})

    backtest_arm.start_backtest(
        "https://host",
        "tok",
        window_days=7,
        sample_size=10,
        min_severity="high",
        opener=opener,
    )

    assert json.loads(opener.requests[0].data) == {
        "window_days": 7,
        "sample_size": 10,
        "min_severity": "high",
    }


def test_start_backtest_carries_alert_ids_and_omits_sample_size() -> None:
    """A fixed sample pins the request: alert_ids rides, sample_size drops even when given."""
    opener = _RecordingOpener({"active": True})

    backtest_arm.start_backtest(
        "https://host",
        "tok",
        window_days=30,
        sample_size=40,
        alert_ids=["alert-1", "alert-2"],
        opener=opener,
    )

    assert json.loads(opener.requests[0].data) == {
        "window_days": 30,
        "alert_ids": ["alert-1", "alert-2"],
    }


def test_read_alert_ids_file_skips_blank_lines_and_caps_at_200(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ids_file = tmp_path / "ids.txt"
    ids_file.write_text("\n".join([f"alert-{i}" for i in range(250)] + ["", "  "]) + "\n")

    ids = backtest_arm.read_alert_ids_file(ids_file)
    err = capsys.readouterr().err

    assert len(ids) == 200
    assert ids[0] == "alert-0"
    assert ids[-1] == "alert-199"
    assert "250 alert ids" in err


def test_extract_replayed_alert_ids_prefers_the_dedicated_field() -> None:
    result = {"results": {"replayed_alert_ids": ["a", "b"], "rows": [{"alert_id": "c"}]}}

    assert backtest_arm.extract_replayed_alert_ids(result) == ["a", "b"]


def test_extract_replayed_alert_ids_falls_back_to_rows() -> None:
    result = {
        "results": {
            "rows": [
                {"alert_id": "a", "soc_ai_verdict": "true_positive"},
                {"alert_id": None, "error": "timeout"},
                {"alert_id": "c", "soc_ai_verdict": "false_positive"},
            ]
        }
    }

    assert backtest_arm.extract_replayed_alert_ids(result) == ["a", "c"]


def test_extract_replayed_alert_ids_is_empty_with_no_results() -> None:
    assert backtest_arm.extract_replayed_alert_ids({}) == []


def test_get_backtest_reads_one_run_by_id() -> None:
    opener = _RecordingOpener({"backtest_id": "bt-1", "status": "complete"})

    result = backtest_arm.get_backtest("https://host", "tok", "bt-1", opener=opener)

    assert result["status"] == "complete"
    request = opener.requests[0]
    assert request.full_url == "https://host/api/v1/backtest/bt-1"
    assert request.get_method() == "GET"


def test_poll_until_done_stops_once_active_is_false_and_an_id_is_set() -> None:
    opener = _RecordingOpener(
        {"active": True, "backtest_id": None},  # still sampling
        {"active": True, "backtest_id": "bt-1"},  # replaying
        {"active": False, "backtest_id": "bt-1", "status": "complete"},  # done
    )
    sleeps: list[float] = []

    result = backtest_arm.poll_until_done(
        "https://host",
        "tok",
        interval_s=5,
        opener=opener,
        sleep=sleeps.append,
        now=lambda: 0.0,
    )

    assert result == {"active": False, "backtest_id": "bt-1", "status": "complete"}
    assert sleeps == [5, 5]


def test_poll_until_done_raises_at_once_on_a_refusal_with_no_id() -> None:
    opener = _RecordingOpener({"active": False, "backtest_id": None, "refused": {"reason": "x"}})

    with pytest.raises(backtest_arm.PollTimeout, match="refused"):
        backtest_arm.poll_until_done("https://host", "tok", opener=opener, sleep=lambda _s: None)


def test_poll_until_done_raises_past_the_timeout() -> None:
    opener = _RecordingOpener(
        {"active": True, "backtest_id": "bt-1"}, {"active": True, "backtest_id": "bt-1"}
    )
    clock = iter([0.0, 0.0, 11.0])

    with pytest.raises(backtest_arm.PollTimeout, match="did not finish"):
        backtest_arm.poll_until_done(
            "https://host",
            "tok",
            interval_s=5,
            timeout_s=10,
            opener=opener,
            sleep=lambda _s: None,
            now=lambda: next(clock),
        )


def test_a_non_2xx_response_raises_http_error_with_no_header_in_the_message() -> None:
    def opener(request: Request) -> _FakeResponse:
        raise HTTPError(request.full_url, 401, "unauthorized", {}, None)

    with pytest.raises(backtest_arm.HttpError) as excinfo:
        backtest_arm.set_strategy("https://host", "secret-token", "single", opener=opener)

    assert "401" in str(excinfo.value)
    assert "secret-token" not in str(excinfo.value)


def test_main_requires_base_url_and_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("BASE_URL", raising=False)
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)

    code = backtest_arm.main(["set-strategy", "single"])
    err = capsys.readouterr().err

    assert code == 2
    assert "BASE_URL" in err


def test_main_set_strategy_prints_the_response_json_and_never_the_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASE_URL", "https://host")
    monkeypatch.setenv("SOC_AI_API_TOKEN", "super-secret")
    opener = _RecordingOpener({"ok": True, "restart_required": False})

    code = backtest_arm.main(["set-strategy", "advocates"], opener=opener)
    out = capsys.readouterr().out

    assert code == 0
    assert json.loads(out) == {"ok": True, "restart_required": False}
    assert "super-secret" not in out
    assert opener.requests[0].get_header("Authorization") == "Bearer super-secret"


def test_main_get_prints_a_1_exit_on_an_http_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASE_URL", "https://host")
    monkeypatch.setenv("SOC_AI_API_TOKEN", "tok")

    def opener(request: Request) -> _FakeResponse:
        raise HTTPError(request.full_url, 404, "not found", {}, None)

    code = backtest_arm.main(["get", "bt-missing"], opener=opener)
    err = capsys.readouterr().err

    assert code == 1
    assert "404" in err


def test_main_start_with_alert_ids_file_omits_sample_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASE_URL", "https://host")
    monkeypatch.setenv("SOC_AI_API_TOKEN", "tok")
    ids_file = tmp_path / "ids.txt"
    ids_file.write_text("alert-1\nalert-2\n")
    opener = _RecordingOpener({"active": True})

    code = backtest_arm.main(
        ["start", "30", "40", "--alert-ids-file", str(ids_file)], opener=opener
    )
    out = capsys.readouterr().out

    assert code == 0
    assert json.loads(opener.requests[0].data) == {
        "window_days": 30,
        "alert_ids": ["alert-1", "alert-2"],
    }
    assert json.loads(out) == {"active": True}


def test_main_start_with_no_alert_ids_file_keeps_sample_size(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("BASE_URL", "https://host")
    monkeypatch.setenv("SOC_AI_API_TOKEN", "tok")
    opener = _RecordingOpener({"active": True})

    backtest_arm.main(["start", "30", "40"], opener=opener)
    capsys.readouterr()

    assert json.loads(opener.requests[0].data) == {"window_days": 30, "sample_size": 40}


def test_main_ids_prints_the_replayed_ids_from_stdin_with_no_base_url_or_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("BASE_URL", raising=False)
    monkeypatch.delenv("SOC_AI_API_TOKEN", raising=False)
    result = {"results": {"replayed_alert_ids": ["alert-1", "alert-2"]}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(result)))

    code = backtest_arm.main(["ids"])
    out = capsys.readouterr().out

    assert code == 0
    assert out.splitlines() == ["alert-1", "alert-2"]


def test_main_ids_exits_2_on_bad_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))

    code = backtest_arm.main(["ids"])
    err = capsys.readouterr().err

    assert code == 2
    assert "not a JSON result" in err
