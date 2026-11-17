"""``soc-ai needs-you``: list the investigations that wait, clear the old ones, restore one.

The command works on the store of the install, as ``soc-ai campaigns`` does.
A clear needs a date and a reason, and asks for a typed "yes" without
``--yes``. ``--dry-run`` writes nothing.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.audit.logger import AuditWriteError
from soc_ai.config import Settings
from soc_ai.store.models import Investigation, InvestigationEvent
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_campaign_facts import OUTSIDE, seed_run
from tests.test_cli_campaigns import _settings, _with_db

REASON = "Old work from before the new rules."
_ESCALATE = {
    "recommended_actions": [
        {
            "tool_name": "escalate_to_case",
            "tool_args": {"alert_id": "alert-tp", "case_title": "t", "case_description": "d"},
            "rationale": "Open a case for the upload.",
        }
    ]
}


async def _seed(db: AsyncSession) -> dict[str, str]:
    """An old true positive with an action, an old and a new verdict that needs more info."""
    return {
        "tp": await seed_run(
            db, "alert-tp", src=OUTSIDE, dst=OUTSIDE, event_hours_ago=90 * 24, report=_ESCALATE
        ),
        "nmi_old": await seed_run(
            db,
            "alert-nmi-old",
            src=OUTSIDE,
            dst=OUTSIDE,
            verdict="needs_more_info",
            event_hours_ago=60 * 24,
        ),
        "nmi_new": await seed_run(
            db,
            "alert-nmi-new",
            src=OUTSIDE,
            dst=OUTSIDE,
            verdict="needs_more_info",
            event_hours_ago=2,
        ),
    }


async def _state(db: AsyncSession) -> dict[str, Any]:
    rows = (await db.scalars(select(Investigation).order_by(Investigation.id))).all()
    dismissals = await db.scalar(
        select(func.count())
        .select_from(InvestigationEvent)
        .where(InvestigationEvent.kind.in_(("action_dismissed", "action_restored")))
    )
    return {
        "reports": {r.id: dict(r.report or {}) for r in rows},
        "verdicts": {r.id: (r.verdict, r.confidence) for r in rows},
        "dismissals": int(dismissals or 0),
    }


@pytest.fixture
def env(
    settings_kratos: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Settings, AsyncMock]:
    """The settings of a scratch store, and the audit logger of the command."""
    settings = _settings(settings_kratos, tmp_path)
    audit = AsyncMock()
    monkeypatch.setattr("soc_ai.cli_needs_you._audit_logger", lambda _s, _e: audit)
    monkeypatch.setattr("soc_ai.config.get_settings", lambda: settings)
    return settings, audit


def _cli(monkeypatch: pytest.MonkeyPatch, *argv: str, stdin: str = "") -> int:
    from soc_ai import cli

    monkeypatch.setattr(sys, "argv", ["soc-ai", *argv])
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        pytest.raises(SystemExit) as exit_info,
    ):
        cli.main()
    return int(exit_info.value.code or 0)


def _before() -> str:
    from datetime import UTC, datetime, timedelta

    return (datetime.now(UTC) - timedelta(days=30)).date().isoformat()


def test_list_prints_each_investigation_that_waits(
    env: tuple[Settings, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings, _audit = env
    runs = _with_db(settings, _seed)
    assert _cli(monkeypatch, "needs-you", "list") == 0
    out = capsys.readouterr().out
    for inv_id in runs.values():
        assert inv_id in out
    assert "true positive" in out
    assert "needs more info" in out
    assert out.strip().endswith("3 investigations wait.")
    assert _cli(monkeypatch, "needs-you", "list", "--before", _before(), "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert {row["id"] for row in rows} == {runs["tp"], runs["nmi_old"]}
    tp = next(row for row in rows if row["id"] == runs["tp"])
    assert tp["verdict"] == "true_positive"
    assert tp["waiting_actions"] == 1
    assert tp["source"] == OUTSIDE
    assert set(tp) >= {"event_at", "waits_since", "title", "destination"}


def test_a_dry_run_writes_nothing(
    env: tuple[Settings, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """NEGATIVE CONTROL. --dry-run prints the investigations and writes no record."""
    settings, audit = env
    runs = _with_db(settings, _seed)
    before = _with_db(settings, _state)
    argv = ("needs-you", "clear", "--before", _before(), "--reason", REASON, "--dry-run")
    assert _cli(monkeypatch, *argv) == 0
    out = capsys.readouterr().out
    assert runs["tp"] in out and runs["nmi_old"] in out
    assert runs["nmi_new"] not in out
    assert "soc-ai wrote nothing" in out
    assert _with_db(settings, _state) == before
    audit.log_kind.assert_not_awaited()


def test_a_clear_asks_for_yes_and_clears_on_yes(
    env: tuple[Settings, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings, audit = env
    runs = _with_db(settings, _seed)
    before = _with_db(settings, _state)
    argv = ("needs-you", "clear", "--before", _before(), "--reason", REASON, "--by", "analyst-1")
    # NEGATIVE CONTROL. Any answer other than "yes" clears nothing.
    assert _cli(monkeypatch, *argv, stdin="y\n") == 2
    assert "soc-ai cleared nothing" in capsys.readouterr().out
    assert _with_db(settings, _state) == before
    audit.log_kind.assert_not_awaited()
    assert _cli(monkeypatch, *argv, stdin="yes\n") == 0
    out = capsys.readouterr().out
    assert "Type yes to clear 2 investigations" in out
    assert "soc-ai cleared 2 investigations from Needs you" in out
    after = _with_db(settings, _state)
    assert after["verdicts"] == before["verdicts"]
    assert "needs_you_cleared" in after["reports"][runs["tp"]]
    assert "needs_you_cleared" in after["reports"][runs["nmi_old"]]
    assert "needs_you_cleared" not in after["reports"][runs["nmi_new"]]
    assert after["dismissals"] == 1
    assert [c.args[1] for c in audit.log_kind.await_args_list] == ["needs_you_cleared"] * 2
    assert {c.kwargs["user"] for c in audit.log_kind.await_args_list} == {"analyst-1"}
    # The list now holds the new verdict only.
    assert _cli(monkeypatch, "needs-you", "list", "--json") == 0
    assert [row["id"] for row in json.loads(capsys.readouterr().out)] == [runs["nmi_new"]]


def test_yes_clears_with_no_question_and_restore_brings_the_item_back(
    env: tuple[Settings, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings, audit = env
    runs = _with_db(settings, _seed)
    argv = ("needs-you", "clear", "--before", _before(), "--reason", REASON, "--yes")
    assert _cli(monkeypatch, *argv, "--only", "true_positive") == 0
    assert "Type yes" not in capsys.readouterr().out
    assert _cli(monkeypatch, "needs-you", "restore", runs["tp"]) == 0
    assert "1 action waits again" in capsys.readouterr().out
    assert _cli(monkeypatch, "needs-you", "list", "--json") == 0
    assert len(json.loads(capsys.readouterr().out)) == 3
    assert [c.args[1] for c in audit.log_kind.await_args_list] == [
        "needs_you_cleared",
        "needs_you_restored",
    ]
    # NEGATIVE CONTROL. An investigation with no clear has nothing to restore.
    assert _cli(monkeypatch, "needs-you", "restore", runs["nmi_new"]) == 2
    assert "holds no clear" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (("--reason", "  "), "needs a reason"),
        (("--reason", REASON, "--before", "2999-01-01"), "in the past"),
    ],
)
def test_a_clear_refuses_an_empty_reason_and_a_future_date(
    env: tuple[Settings, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: tuple[str, ...],
    message: str,
) -> None:
    """NEGATIVE CONTROL. The tool never acts without a date and a reason."""
    settings, audit = env
    _with_db(settings, _seed)
    before = _with_db(settings, _state)
    argv = ("needs-you", "clear", "--before", _before(), *extra, "--yes")
    assert _cli(monkeypatch, *argv) == 2
    assert message in capsys.readouterr().err
    assert _with_db(settings, _state) == before
    audit.log_kind.assert_not_awaited()


def test_a_clear_with_no_date_is_refused(
    env: tuple[Settings, AsyncMock], monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL. --before is required."""
    assert _cli(monkeypatch, "needs-you", "clear", "--reason", REASON, "--yes") == 2


def test_a_failed_audit_write_clears_nothing_and_exits_1(
    env: tuple[Settings, AsyncMock],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """NEGATIVE CONTROL. The audit record fails closed."""
    settings, audit = env
    audit.log_kind.side_effect = AuditWriteError("the audit index does not answer")
    _with_db(settings, _seed)
    before = _with_db(settings, _state)
    argv = ("needs-you", "clear", "--before", _before(), "--reason", REASON, "--yes")
    assert _cli(monkeypatch, *argv) == 1
    assert "could not write the audit record" in capsys.readouterr().err
    assert _with_db(settings, _state) == before
