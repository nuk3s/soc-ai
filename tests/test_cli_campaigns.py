"""``soc-ai campaigns``: rebuild the campaigns from the command line, and list them (Task 8).

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, CampaignRunFacts
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_campaign_facts import OUTSIDE, seed_hosts, seed_run


def _settings(settings_kratos: Settings, tmp_path: Path) -> Settings:
    return settings_kratos.model_copy(update={"soc_ai_data_dir": tmp_path / "data"})


def _with_db(settings: Settings, work: Callable[[AsyncSession], Awaitable[Any]]) -> Any:
    async def go() -> Any:
        engine = make_engine(settings)
        await run_migrations(engine)
        try:
            async with make_sessionmaker(engine)() as db:
                return await work(db)
        finally:
            await engine.dispose()

    return asyncio.run(go())


async def _seed(db: AsyncSession) -> None:
    await seed_hosts(db)
    for n in (1, 2, 3):
        await seed_run(db, f"alert-000{n}", event_hours_ago=4 - n, created_minutes_ago=40 - n)
    # A true positive from a source that the Hosts data holds no machine for.
    await seed_run(db, "alert-0009", src=OUTSIDE, event_hours_ago=30, created_minutes_ago=60)


async def _counts(db: AsyncSession) -> tuple[int, int]:
    campaigns = await db.scalar(select(func.count()).select_from(Campaign))
    facts = await db.scalar(select(func.count()).select_from(CampaignRunFacts))
    return int(campaigns or 0), int(facts or 0)


def _cli(monkeypatch: pytest.MonkeyPatch, settings: Settings, *argv: str) -> int:
    from soc_ai import cli

    monkeypatch.setattr("soc_ai.config.get_settings", lambda: settings)
    monkeypatch.setattr(sys, "argv", ["soc-ai", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return int(exit_info.value.code or 0)


def test_rebuild_prints_the_count_line_and_a_dry_run_writes_no_row(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)
    _with_db(settings, _seed)
    line = (
        "1 campaign, 3 investigations. 1 true positive investigation has an end that soc-ai "
        "cannot resolve "
        "to one machine."
    )

    assert _cli(monkeypatch, settings, "campaigns", "rebuild", "--dry-run") == 0
    out = capsys.readouterr().out
    assert out.startswith(line)
    assert "This is a dry run. soc-ai wrote no row." in out
    assert _with_db(settings, _counts) == (0, 0)

    assert _cli(monkeypatch, settings, "campaigns", "rebuild") == 0
    out = capsys.readouterr().out
    assert out.strip() == line
    assert _with_db(settings, _counts) == (1, 4)

    assert _cli(monkeypatch, settings, "campaigns", "list") == 0
    listed = capsys.readouterr().out
    assert "actor-a against web-1" in listed
    assert "open" in listed
    assert "attempt" in listed


def test_rebuild_json_prints_each_campaign_with_its_parties_and_members(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)
    _with_db(settings, _seed)
    assert _cli(monkeypatch, settings, "campaigns", "rebuild", "--dry-run", "--json") == 0
    (draft,) = json.loads(capsys.readouterr().out)
    assert set(draft) == {"title", "bottom_line", "stage", "parties", "members"}
    assert draft["title"] == "actor-a against web-1"
    assert draft["stage"] == "attempt"
    assert [(p["machine_key"], p["role"]) for p in draft["parties"]] == [
        ("agent:a1", "actor"),
        ("ip:t1", "target"),
    ]
    assert [m["link"] for m in draft["members"]] == ["seed", "actor", "actor"]
    assert _with_db(settings, _counts) == (0, 0)


def test_list_of_an_empty_store_says_so_and_no_subcommand_prints_help(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)
    assert _cli(monkeypatch, settings, "campaigns", "list") == 0
    assert "The store holds no campaign." in capsys.readouterr().out
    assert _cli(monkeypatch, settings, "campaigns") == 2
    assert "rebuild" in capsys.readouterr().out


def test_a_failed_rebuild_exits_1(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)

    async def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("the store is locked")

    monkeypatch.setattr("soc_ai.campaigns.service.rebuild", broken)
    assert _cli(monkeypatch, settings, "campaigns", "rebuild") == 1
    assert "soc-ai could not rebuild the campaigns: RuntimeError." in capsys.readouterr().err


def test_list_states_the_decision_of_each_campaign(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)
    _with_db(settings, _seed)
    assert _cli(monkeypatch, settings, "campaigns", "rebuild") == 0
    capsys.readouterr()
    assert _cli(monkeypatch, settings, "campaigns", "list") == 0
    (line,) = capsys.readouterr().out.strip().splitlines()
    # An active campaign with no decision waits on the analyst.
    assert line.split()[3] == "waits"

    async def close(db: AsyncSession) -> None:
        row = (await db.scalars(select(Campaign))).one()
        row.decision = "closed"
        row.close_reason = "test_over"
        await db.commit()

    _with_db(settings, close)
    assert _cli(monkeypatch, settings, "campaigns", "list") == 0
    (line,) = capsys.readouterr().out.strip().splitlines()
    assert line.split()[1:4] == ["open", "attempt", "closed"]
    assert line.endswith("actor-a against web-1")


def test_list_states_an_authorized_campaign_with_its_expiry(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from datetime import timedelta

    from soc_ai.store import authorized_activity as aa
    from soc_ai.store.auth import utcnow

    settings = _settings(settings_kratos, tmp_path)
    _with_db(settings, _seed)
    assert _cli(monkeypatch, settings, "campaigns", "rebuild") == 0
    capsys.readouterr()
    expires = utcnow().replace(second=0, microsecond=0) + timedelta(days=7)

    async def authorize(db: AsyncSession) -> None:
        row = (await db.scalars(select(Campaign))).one()
        record = await aa.create_for_campaign(
            db,
            campaign_id=row.id,
            label="Red team test",
            parties=[
                aa.PartyEntry("agent:a1", "actor"),
                aa.PartyEntry("ip:t1", "target"),
            ],
            starts_at=row.first_event,
            expires_at=expires,
            created_by="casey",
            commit=False,
        )
        row.decision = "authorized"
        row.authorization_id = record.id
        await db.commit()

    _with_db(settings, authorize)
    assert _cli(monkeypatch, settings, "campaigns", "list") == 0
    (line,) = capsys.readouterr().out.strip().splitlines()
    assert line.split()[3] == "authorized"
    assert line.endswith(f"actor-a against web-1  expires {expires:%Y-%m-%d %H:%M} UTC")


def test_list_states_a_campaign_with_a_case_and_its_case_id(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from soc_ai.campaigns import decisions
    from soc_ai.store.auth import utcnow

    settings = _settings(settings_kratos, tmp_path)
    _with_db(settings, _seed)
    assert _cli(monkeypatch, settings, "campaigns", "rebuild") == 0
    capsys.readouterr()

    async def case(db: AsyncSession) -> None:
        row = (await db.scalars(select(Campaign))).one()
        decisions.write_case(
            db,
            row,
            case_id="case-42",
            by="casey",
            note="",
            basis={},
            detail={"caseId": "case-42", "alerts": 1, "by": "casey"},
            now=utcnow(),
        )
        await db.commit()

    _with_db(settings, case)
    assert _cli(monkeypatch, settings, "campaigns", "list") == 0
    (line,) = capsys.readouterr().out.strip().splitlines()
    assert line.split()[3] == "case"
    assert line.endswith("actor-a against web-1  case case-42")
