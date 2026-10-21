#!/usr/bin/env python3
"""scripts/eval/backtest_arm.py: the HTTP steps of one backtest arm.

Called by ``scripts/eval/backtest-arm.sh``, one subcommand per step, so each
step is a plain HTTP call this module can test with a fake transport and no
network. Standard library only. See ``docs/dev/eval-arms.md`` for the
runbook and the design record
``docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md`` for why the
backtest arm exists.

Five calls on a running soc-ai, against its admin API:

- ``set-strategy <value>``: ``POST /api/v1/config/setting`` with
  ``{"key": "investigator_strategy", "value": <value>}``. Hot-apply or not
  is a property of that setting, not of this script.
- ``start <window-days> <sample-size> [min-severity] [--alert-ids-file <path>]``:
  ``POST /api/v1/backtest``. With ``--alert-ids-file``, the request carries
  ``alert_ids`` (read from the file, one id per line) and omits
  ``sample_size``: the backtest replays exactly those alerts.
- ``poll [interval-s] [timeout-s]``: repeats ``GET /api/v1/backtest`` until
  the run is no longer active and carries a ``backtest_id``.
- ``get <backtest-id>``: ``GET /api/v1/backtest/<backtest-id>``, the scored
  result.
- ``ids``: reads a result from stdin (the JSON ``get`` prints) and prints
  the alert ids it replayed, one per line. This is the file arm A's run
  writes for arms B to E to read back as ``ALERT_IDS_FILE``.

``POST /api/v1/backtest`` without ``alert_ids`` carries a window and a
sample size alone, never a seed. Two such calls can sample a different
window of alerts. ``--alert-ids-file`` pins the sample across arms instead:
run one arm with a sampled window, write its replayed ids with ``ids``, and
pass that file to every later arm.

BASE_URL and SOC_AI_API_TOKEN come from the environment only. This module
never logs, prints or returns either of them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

Opener = Callable[[urllib.request.Request], Any]

# The backtest route's own cap on alert_ids (soc_ai.api.webui.routes_backtest).
# A longer file is truncated here, so the failure a caller sees is this
# truncation, never a surprise 422 from the server.
MAX_ALERT_IDS = 200


def _default_opener(request: urllib.request.Request) -> Any:
    return urllib.request.urlopen(request, timeout=30)


class HttpError(Exception):
    """A non-2xx response. The message carries the status and the body, never a header."""


class PollTimeout(Exception):
    """A backtest did not finish inside the poll budget."""


def _as_dict(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def read_alert_ids_file(path: Path) -> list[str]:
    """One alert id per line of ``path``. A blank line is skipped.

    A file longer than :data:`MAX_ALERT_IDS` is truncated to the first
    :data:`MAX_ALERT_IDS` ids, with a warning on stderr.
    """
    ids = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(ids) > MAX_ALERT_IDS:
        print(
            f"backtest_arm: {path} carries {len(ids)} alert ids. Using the first {MAX_ALERT_IDS}.",
            file=sys.stderr,
        )
        ids = ids[:MAX_ALERT_IDS]
    return ids


def extract_replayed_alert_ids(result: dict[str, Any]) -> list[str]:
    """The alert ids one backtest result replayed, read from ``get_backtest``'s payload.

    The ids ride a dedicated field of ``results`` when the backtest route
    carries one (``replayed_alert_ids``, or ``alert_ids`` echoing the
    request), checked in that order. With neither, they are read off each
    row's own ``alert_id`` instead. Order is preserved; a row with no
    ``alert_id`` is skipped.
    """
    results = _as_dict(result.get("results"))
    for key in ("replayed_alert_ids", "alert_ids"):
        candidate = results.get(key)
        if isinstance(candidate, list) and all(isinstance(i, str) for i in candidate):
            return list(candidate)
    rows = results.get("rows")
    if isinstance(rows, list):
        return [
            str(row["alert_id"]) for row in rows if isinstance(row, Mapping) and row.get("alert_id")
        ]
    return []


def _request(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None,
    *,
    opener: Opener = _default_opener,
) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with opener(request) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        raise HttpError(f"{method} {url}: HTTP {exc.code} {detail}".strip()) from exc
    except urllib.error.URLError as exc:
        raise HttpError(f"{method} {url}: {exc.reason}") from exc
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HttpError(f"{method} {url}: the response was not JSON") from exc
    return value if isinstance(value, dict) else {"value": value}


def set_strategy(
    base_url: str, token: str, strategy: str, *, opener: Opener = _default_opener
) -> dict[str, Any]:
    """``POST /api/v1/config/setting`` for ``investigator_strategy``."""
    return _request(
        "POST",
        f"{base_url}/api/v1/config/setting",
        token,
        {"key": "investigator_strategy", "value": strategy},
        opener=opener,
    )


def start_backtest(
    base_url: str,
    token: str,
    *,
    window_days: int,
    sample_size: int | None = None,
    alert_ids: list[str] | None = None,
    min_severity: str | None = None,
    opener: Opener = _default_opener,
) -> dict[str, Any]:
    """``POST /api/v1/backtest``.

    ``alert_ids``, when given, pins the exact sample: the body carries
    ``alert_ids`` and omits ``sample_size`` even when a value was passed.
    With no ``alert_ids``, the backtest route samples by window and
    ``sample_size`` alone, with no seed to pin it across calls.
    """
    body: dict[str, Any] = {"window_days": window_days}
    if alert_ids:
        body["alert_ids"] = list(alert_ids)
    elif sample_size is not None:
        body["sample_size"] = sample_size
    if min_severity:
        body["min_severity"] = min_severity
    return _request("POST", f"{base_url}/api/v1/backtest", token, body, opener=opener)


def get_status(base_url: str, token: str, *, opener: Opener = _default_opener) -> dict[str, Any]:
    """``GET /api/v1/backtest``: the current or last run's state."""
    return _request("GET", f"{base_url}/api/v1/backtest", token, None, opener=opener)


def get_backtest(
    base_url: str, token: str, backtest_id: str, *, opener: Opener = _default_opener
) -> dict[str, Any]:
    """``GET /api/v1/backtest/<id>``: one run's scored result."""
    return _request("GET", f"{base_url}/api/v1/backtest/{backtest_id}", token, None, opener=opener)


def poll_until_done(
    base_url: str,
    token: str,
    *,
    interval_s: float = 10.0,
    timeout_s: float = 3600.0,
    opener: Opener = _default_opener,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Poll ``GET /api/v1/backtest`` until the run ends, or raise :class:`PollTimeout`.

    The run has ended when the status carries a ``backtest_id`` and is no
    longer ``active``. A status that is refused before it ever got a
    ``backtest_id`` (no alert in the window to replay, or the grid was
    unreachable) raises immediately rather than spinning for the full
    timeout.
    """
    deadline = now() + timeout_s
    while True:
        status = get_status(base_url, token, opener=opener)
        if status.get("refused") and not status.get("backtest_id"):
            raise PollTimeout(f"backtest refused before it started: {status['refused']}")
        if status.get("backtest_id") and not status.get("active"):
            return status
        if now() >= deadline:
            raise PollTimeout(f"backtest did not finish within {timeout_s:.0f}s")
        sleep(interval_s)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="One HTTP step of a swarm-triage backtest arm. "
        "BASE_URL and SOC_AI_API_TOKEN come from the environment."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    strategy_p = sub.add_parser("set-strategy", help="set investigator_strategy")
    strategy_p.add_argument("strategy")

    start_p = sub.add_parser("start", help="start a backtest")
    start_p.add_argument("window_days", type=int)
    start_p.add_argument("sample_size", type=int)
    start_p.add_argument("min_severity", nargs="?", default="")
    start_p.add_argument(
        "--alert-ids-file",
        type=Path,
        default=None,
        help="one alert id per line; pins the sample and drops sample_size",
    )

    poll_p = sub.add_parser("poll", help="poll until the backtest ends")
    poll_p.add_argument("--interval", type=float, default=10.0)
    poll_p.add_argument("--timeout", type=float, default=3600.0)

    get_p = sub.add_parser("get", help="fetch one backtest's result")
    get_p.add_argument("backtest_id")

    sub.add_parser("ids", help="print a result's replayed alert ids, one per line")

    return parser


def main(argv: list[str] | None = None, *, opener: Opener | None = None) -> int:
    opener = opener or _default_opener
    args = _build_parser().parse_args(argv)

    if args.command == "ids":
        # Local JSON processing only. No BASE_URL and no token needed.
        try:
            result = json.load(sys.stdin)
        except json.JSONDecodeError as exc:
            print(f"backtest_arm: stdin was not a JSON result: {exc}", file=sys.stderr)
            return 2
        for alert_id in extract_replayed_alert_ids(result if isinstance(result, dict) else {}):
            print(alert_id)
        return 0

    base_url = os.environ.get("BASE_URL", "").rstrip("/")
    token = os.environ.get("SOC_AI_API_TOKEN", "")
    if not base_url or not token:
        print(
            "backtest_arm: set BASE_URL and SOC_AI_API_TOKEN in the environment.",
            file=sys.stderr,
        )
        return 2

    try:
        if args.command == "set-strategy":
            result = set_strategy(base_url, token, args.strategy, opener=opener)
        elif args.command == "start":
            alert_ids = read_alert_ids_file(args.alert_ids_file) if args.alert_ids_file else None
            result = start_backtest(
                base_url,
                token,
                window_days=args.window_days,
                sample_size=args.sample_size,
                alert_ids=alert_ids,
                min_severity=args.min_severity or None,
                opener=opener,
            )
        elif args.command == "poll":
            result = poll_until_done(
                base_url,
                token,
                interval_s=args.interval,
                timeout_s=args.timeout,
                opener=opener,
            )
        else:
            result = get_backtest(base_url, token, args.backtest_id, opener=opener)
    except (HttpError, PollTimeout) as exc:
        print(f"backtest_arm: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
