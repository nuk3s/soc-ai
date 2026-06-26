"""Tests for the soc-ai local store (models, migrations, auth services)."""

from __future__ import annotations

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.store import auth as auth_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Base, User, UserSession
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine


async def _create_all(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def test_make_engine_creates_data_dir(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    assert settings_kratos.soc_ai_data_dir.is_dir()
    await engine.dispose()


async def test_user_model_roundtrip(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await _create_all(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        db.add(User(username="alice", password_hash="x", role="analyst"))
        await db.commit()
        row = await db.scalar(select(User).where(User.username == "alice"))
    assert row is not None
    assert row.role == "analyst"
    assert row.disabled is False
    assert row.created_at is not None
    await engine.dispose()


async def _table_names(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        return set(await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names()))


async def test_run_migrations_creates_schema(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    tables = await _table_names(engine)
    assert {"users", "sessions", "api_tokens", "alembic_version"} <= tables
    # idempotent: a second run is a no-op, not an error
    await run_migrations(engine)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _db(settings: Settings) -> tuple[object, object]:  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


# ---------------------------------------------------------------------------
# Auth service tests
# ---------------------------------------------------------------------------


async def test_create_user_and_authenticate(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        user = await auth_svc.create_user(db, "carol", "hunter2!", role="admin")
        assert user.id is not None
        ok = await auth_svc.authenticate(db, "carol", "hunter2!")
        assert ok is not None
        assert ok.last_login_at is not None
        assert await auth_svc.authenticate(db, "carol", "wrong") is None
        assert await auth_svc.authenticate(db, "nobody", "hunter2!") is None
    await engine.dispose()


async def test_disabled_user_cannot_authenticate(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        user = await auth_svc.create_user(db, "dave", "pw")
        user.disabled = True
        await db.commit()
        assert await auth_svc.authenticate(db, "dave", "pw") is None
    await engine.dispose()


async def test_session_roundtrip_and_expiry(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        user = await auth_svc.create_user(db, "erin", "pw")
        raw = await auth_svc.create_session(db, user, ttl_hours=12)
        found = await auth_svc.get_session_user(db, raw)
        assert found is not None
        assert found.username == "erin"
        assert await auth_svc.get_session_user(db, "bogus") is None
        await auth_svc.delete_session(db, raw)
        assert await auth_svc.get_session_user(db, raw) is None
        expired = await auth_svc.create_session(db, user, ttl_hours=-1)
        assert await auth_svc.get_session_user(db, expired) is None
    await engine.dispose()


async def test_api_token_roundtrip(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        user = await auth_svc.create_user(db, "frank", "pw")
        raw = await auth_svc.create_api_token(db, "userscript", user.id)
        assert raw.startswith("scai_")
        token = await auth_svc.check_api_token(db, raw)
        assert token is not None
        assert token.last_used_at is not None
        token.revoked = True
        await db.commit()
        assert await auth_svc.check_api_token(db, raw) is None
        assert await auth_svc.check_api_token(db, "scai_bogus") is None
    await engine.dispose()


async def test_bootstrap_admin(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        pw = await auth_svc.bootstrap_admin(db, None)
        assert pw is not None
        assert await auth_svc.authenticate(db, "admin", pw) is not None
        # second call: users exist, no-op
        assert await auth_svc.bootstrap_admin(db, None) is None
    await engine.dispose()


def test_csrf_token_is_deterministic() -> None:
    assert auth_svc.csrf_token_for("tok") == auth_svc.csrf_token_for("tok")
    assert auth_svc.csrf_token_for("tok") != auth_svc.csrf_token_for("other")


async def test_bootstrap_admin_fixed_password_not_returned(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await auth_svc.bootstrap_admin(db, SecretStr("fixed-pw")) is None
        assert await auth_svc.authenticate(db, "admin", "fixed-pw") is not None
    await engine.dispose()


# ---------------------------------------------------------------------------
# Carry-over A: SQLite FK enforcement
# ---------------------------------------------------------------------------


async def test_foreign_keys_enforced(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        db.add(UserSession(token_hash="x", user_id=999, expires_at=auth_svc.utcnow()))
        with pytest.raises(IntegrityError):
            await db.commit()
    await engine.dispose()


async def test_authenticate_rejects_overlong_password(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await auth_svc.create_user(db, "gina", "pw")
        assert await auth_svc.authenticate(db, "gina", "x" * 100) is None
    await engine.dispose()
