"""``soc-ai usage``: the per-entry-point cost table, computed from the store.

The report reads stamped counters where a row has them and the stored events
where it does not, and it never prints a zero for a number the store does not
hold. A false zero would read as "this cost nothing".
"""

from __future__ import annotations

import sys
from datetime import timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt, HuntEvent, Investigation, InvestigationEvent
from soc_ai.store.run_usage import format_usage, percentile, usage_report


def _inv(inv_id: str, **kw: Any) -> Investigation:
    now = utcnow()
    base: dict[str, Any] = {
        "id": inv_id,
        "alert_es_id": f"alert-{inv_id}",
        "started_by": "auto-triage:scheduler",
        "status": "complete",
        "verdict": "false_positive",
        "created_at": now - timedelta(hours=1),
        "finished_at": now - timedelta(hours=1) + timedelta(seconds=40),
        "is_fallback": False,
    }
    base.update(kw)
    return Investigation(**base)


async def _seed(settings: Settings) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    now = utcnow()
    async with maker() as db:
        # Two scheduler runs with stamped counters.
        db.add(
            _inv(
                "s1",
                run_class="standard",
                model_requests=2,
                input_tokens=50_000,
                output_tokens=1_000,
                tool_calls=1,
                es_searches=12,
                wall_ms=40_000,
            )
        )
        db.add(
            _inv(
                "s2",
                run_class="cheap",
                model_requests=1,
                input_tokens=8_000,
                output_tokens=200,
                tool_calls=0,
                es_searches=9,
                wall_ms=8_000,
            )
        )
        # One scheduler run from before the counters: usage and tools from events.
        db.add(_inv("s3", verdict="needs_more_info"))
        db.add_all(
            [
                InvestigationEvent(
                    investigation_id="s3",
                    sequence=1,
                    kind="usage",
                    payload={"requests": 3, "input_tokens": 70_000, "output_tokens": 2_000},
                ),
                InvestigationEvent(
                    investigation_id="s3",
                    sequence=2,
                    kind="tool_call",
                    payload={"tool_name": "t_web_search"},
                ),
                InvestigationEvent(
                    investigation_id="s3",
                    sequence=3,
                    kind="tool_call",
                    payload={"tool_name": "final_result"},
                ),
            ]
        )
        # An analyst's first run and a re-run of the same alert.
        db.add(_inv("a1", started_by="analyst", alert_es_id="alert-x", wall_ms=None))
        db.add(
            _inv(
                "a2",
                started_by="analyst",
                alert_es_id="alert-x",
                created_at=now - timedelta(minutes=30),
                finished_at=now - timedelta(minutes=29),
            )
        )
        # A run older than the window is left out.
        long_ago = now - timedelta(days=40)
        db.add(_inv("old", created_at=long_ago, finished_at=long_ago))
        # A legacy hunt: tool calls are known, model usage is not.
        db.add(
            Hunt(
                id="h1",
                objective="look",
                kind="chat",
                starter="analyst",
                status="complete",
                created_at=now - timedelta(hours=2),
                finished_at=now - timedelta(hours=2) + timedelta(seconds=300),
                threat_findings_count=0,
            )
        )
        db.add(HuntEvent(hunt_id="h1", sequence=1, kind="tool_call", payload={"tool_name": "t_x"}))
        await db.commit()
    return engine, maker


async def test_the_report_splits_runs_by_entry_point(settings_kratos: Settings) -> None:
    engine, maker = await _seed(settings_kratos)
    async with maker() as db:
        report = await usage_report(db, days=7)
    await engine.dispose()
    by_entry = {e.entry: e for e in report.entries}
    assert set(by_entry) == {
        "Auto-triage, scheduler",
        "Analyst first run",
        "Analyst re-run",
        "Hunt, analyst",
    }
    sched = by_entry["Auto-triage, scheduler"]
    assert sched.runs == 3
    assert sched.with_counters == 2
    # Tokens: 51.0K, 8.2K and 72.0K from the legacy events.
    assert sched.tokens.known == 3
    assert sched.tokens.p50 == 51_000
    assert sched.tokens.p90 == 72_000
    # The legacy run counts one tool call: final_result is the output tool.
    assert sorted([sched.tool_calls.p50 or 0, sched.tool_calls.p90 or 0]) == [1, 1]
    # Searches exist only on the two stamped rows.
    assert sched.searches.known == 2
    assert sched.outcomes == {"fp": 2, "nmi": 1}


async def test_a_hunt_with_no_usage_record_reports_unknown_tokens(
    settings_kratos: Settings,
) -> None:
    """A dash, never a zero, for a number the store does not hold."""
    engine, maker = await _seed(settings_kratos)
    async with maker() as db:
        report = await usage_report(db, days=7)
    await engine.dispose()
    hunt = next(e for e in report.entries if e.entry == "Hunt, analyst")
    assert hunt.tokens.known == 0
    assert hunt.requests.known == 0
    assert hunt.searches.known == 0
    assert hunt.tool_calls.p50 == 1
    assert hunt.wall_s.p50 == 300
    text = format_usage(report)
    hunt_line = next(line for line in text.splitlines() if line.startswith("Hunt, analyst"))
    assert " - " in hunt_line
    assert "0 / 0" not in hunt_line


def test_percentile_is_nearest_rank() -> None:
    assert percentile([], 0.5) is None
    assert percentile([5.0], 0.9) == 5.0
    assert percentile([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0], 0.9) == 9.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0


async def test_an_empty_window_says_so(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with make_sessionmaker(engine)() as db:
        report = await usage_report(db, days=1)
    await engine.dispose()
    assert report.entries == []
    assert "No run in this window." in format_usage(report)


def test_the_cli_prints_the_table(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio

    from soc_ai import cli

    engine, _maker = asyncio.run(_seed(settings_kratos))
    asyncio.run(engine.dispose())
    monkeypatch.setattr("soc_ai.config.get_settings", lambda: settings_kratos)
    monkeypatch.setattr(sys, "argv", ["soc-ai", "usage", "--days", "7"])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert "Auto-triage, scheduler" in out
    assert "tokens p50/p90" in out
    assert "Counters on 2 of 6 runs" in out
