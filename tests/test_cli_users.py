"""``soc-ai users``: the recovery path for an admin who cannot sign in.

A fresh install had no command that set a password. ``bootstrap_admin`` runs
only on an empty users table, so an admin locked out by a lost password had no
way back short of deleting the store (dogfood 2026-10-19, H1-D1).
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

import pytest
from soc_ai.bootstrap_credential import bootstrap_credential_path
from soc_ai.config import Settings
from soc_ai.store import auth as auth_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import ApiToken, User, UserSession
from sqlalchemy import func, select


def _settings(settings_kratos: Settings, tmp_path: Path) -> Settings:
    return settings_kratos.model_copy(update={"soc_ai_data_dir": tmp_path / "data"})


async def _seed(settings: Settings) -> None:
    engine = make_engine(settings)
    await run_migrations(engine)
    async with make_sessionmaker(engine)() as db:
        admin = await auth_svc.create_user(db, "admin", "old-admin-pw", role="admin")
        await auth_svc.create_user(db, "jordan", "analyst-pw-1", role="analyst")
        await auth_svc.create_session(db, admin, 24)
        await auth_svc.create_api_token(db, "ci", admin.id)
    await engine.dispose()


async def _state(settings: Settings) -> tuple[str, int, int]:
    engine = make_engine(settings)
    async with make_sessionmaker(engine)() as db:
        admin = await db.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        sessions = await db.scalar(
            select(func.count()).select_from(UserSession).where(UserSession.user_id == admin.id)
        )
        live_tokens = await db.scalar(
            select(func.count()).select_from(ApiToken).where(ApiToken.revoked.is_(False))
        )
        out = (str(admin.password_hash), int(sessions or 0), int(live_tokens or 0))
    await engine.dispose()
    return out


def _run(monkeypatch: pytest.MonkeyPatch, settings: Settings, *argv: str) -> int:
    from soc_ai import cli

    monkeypatch.setattr("soc_ai.config.get_settings", lambda: settings)
    monkeypatch.setattr(sys, "argv", ["soc-ai", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return int(exit_info.value.code or 0)


def test_reset_password_prints_a_new_password_once(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)
    asyncio.run(_seed(settings))
    sidecar = bootstrap_credential_path(settings)
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text("old-admin-pw\n")

    assert _run(monkeypatch, settings, "users", "reset-password", "admin") == 0
    out = capsys.readouterr().out
    match = re.search(r"New password for admin: (\S+)", out)
    assert match, out
    new_pw = match.group(1)
    assert "Change password" in out

    pw_hash, sessions, live_tokens = asyncio.run(_state(settings))
    assert asyncio.run(auth_svc.verify_password(new_pw, pw_hash))
    assert not asyncio.run(auth_svc.verify_password("old-admin-pw", pw_hash))
    # The same effect as the console reset: sessions and tokens of the account end.
    assert sessions == 0
    assert live_tokens == 0
    assert "1 API token" in out
    # The generated password in the sidecar is dead, so the file goes.
    assert not sidecar.exists()


def test_reset_password_of_an_unknown_user_is_refused(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)
    asyncio.run(_seed(settings))
    before = asyncio.run(_state(settings))
    assert _run(monkeypatch, settings, "users", "reset-password", "nobody") == 2
    err = capsys.readouterr().err
    assert "nobody" in err
    assert "admin" in err and "jordan" in err
    assert asyncio.run(_state(settings)) == before


def test_users_list_names_each_account(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)
    asyncio.run(_seed(settings))
    assert _run(monkeypatch, settings, "users", "list") == 0
    out = capsys.readouterr().out
    assert re.search(r"admin\s+admin\s+enabled", out), out
    assert re.search(r"jordan\s+analyst\s+enabled", out), out


def test_users_with_no_subcommand_prints_help(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path)
    assert _run(monkeypatch, settings, "users") == 2
    assert "reset-password" in capsys.readouterr().out
