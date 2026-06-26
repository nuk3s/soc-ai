"""Tests for the internal-identifier store + effective-set resolver."""

from __future__ import annotations

import ipaddress

import pytest
from soc_ai.config import Settings
from soc_ai.oracle.identifiers import effective_internal_identifiers
from soc_ai.store import internal_identifiers as ids
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


# ---------------------------------------------------------------------------
# Migration: the new table is created by run_migrations
# ---------------------------------------------------------------------------


async def test_migration_creates_internal_identifier_table(settings_kratos: Settings) -> None:
    from sqlalchemy import inspect

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = set(await conn.run_sync(lambda sc: inspect(sc).get_table_names()))
    assert "internal_identifier" in tables
    await engine.dispose()


# ---------------------------------------------------------------------------
# normalize()
# ---------------------------------------------------------------------------


def test_normalize_suffix_lowercases_and_adds_leading_dot() -> None:
    assert ids.normalize("suffix", "Corp.Acme.Com") == ".corp.acme.com"
    assert ids.normalize("suffix", ".Corp.Acme.Com") == ".corp.acme.com"
    assert ids.normalize("suffix", "  ..corp.acme.com  ") == ".corp.acme.com"


def test_normalize_host_trims_but_preserves_case() -> None:
    assert ids.normalize("host", "  WIN11-01  ") == "WIN11-01"


def test_normalize_cidr_canonicalizes_non_strict() -> None:
    # host bits set → strict=False normalizes to the network address
    assert ids.normalize("cidr", "10.50.0.7/24") == "10.50.0.0/24"
    assert ids.normalize("cidr", "192.168.1.0/24") == "192.168.1.0/24"


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("bogus", "x"),  # invalid kind
        ("suffix", "   "),  # empty
        ("suffix", "."),  # dot-only → empty after strip
        ("host", ""),  # empty
        ("cidr", "not-a-cidr"),  # invalid cidr
        ("cidr", "10.0.0.0/99"),  # invalid prefix
    ],
)
def test_normalize_rejects_invalid(kind: str, value: str) -> None:
    with pytest.raises(ValueError):
        ids.normalize(kind, value)


# ---------------------------------------------------------------------------
# upsert_detected
# ---------------------------------------------------------------------------


async def test_upsert_detected_insert(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        ev = {"host_count": 3, "event_count": 9, "sample": ["a"]}
        row = await ids.upsert_detected(db, "suffix", "Corp.Acme.Com", ev, "active")
        assert row.value == ".corp.acme.com"
        assert row.source == "detected"
        assert row.state == "active"
        assert row.evidence == ev
        assert row.id is not None
    await engine.dispose()


async def test_upsert_detected_refresh_preserves_operator_state(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ids.upsert_detected(db, "suffix", ".corp.acme.com", {"host_count": 3}, "active")
        # operator mutes it
        rows = await ids.list_identifiers(db, "suffix")
        await ids.set_state(db, rows[0].id, "muted")
        # a re-scan re-detects it active, but the mute must survive
        row = await ids.upsert_detected(db, "suffix", ".corp.acme.com", {"host_count": 5}, "active")
        assert row.state == "muted"  # operator mute preserved
        assert row.evidence == {"host_count": 5}  # evidence refreshed
        assert len(await ids.list_identifiers(db, "suffix")) == 1  # no duplicate
    await engine.dispose()


async def test_upsert_detected_leaves_manual_untouched(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        manual = await ids.add_manual(db, "host", "WIN11-01")
        await ids.set_state(db, manual.id, "muted")
        # discovery later detects the same host
        row = await ids.upsert_detected(db, "host", "WIN11-01", {"host_count": 2}, "active")
        assert row.source == "manual"  # untouched
        assert row.state == "muted"  # untouched
        assert row.evidence == {"host_count": 2}  # evidence still refreshed
    await engine.dispose()


# ---------------------------------------------------------------------------
# add_manual
# ---------------------------------------------------------------------------


async def test_add_manual_insert(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await ids.add_manual(db, "suffix", "ad.contoso.local")
        assert row.value == ".ad.contoso.local"
        assert row.source == "manual"
        assert row.state == "active"
        assert row.evidence is None
    await engine.dispose()


async def test_add_manual_unmutes(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # a detected, muted row
        det = await ids.upsert_detected(db, "suffix", ".corp.acme.com", {"x": 1}, "active")
        await ids.set_state(db, det.id, "muted")
        # operator manually adds the same suffix → un-mutes
        row = await ids.add_manual(db, "suffix", "corp.acme.com")
        assert row.id == det.id
        assert row.state == "active"
        assert row.source == "detected"  # source not overwritten to manual
        assert len(await ids.list_identifiers(db, "suffix")) == 1
    await engine.dispose()


# ---------------------------------------------------------------------------
# set_state / delete_manual
# ---------------------------------------------------------------------------


async def test_set_state(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await ids.add_manual(db, "host", "WIN11-01")
        muted = await ids.set_state(db, row.id, "muted")
        assert muted is not None and muted.state == "muted"
        assert await ids.set_state(db, 9999, "active") is None  # missing
        with pytest.raises(ValueError):
            await ids.set_state(db, row.id, "bogus")
    await engine.dispose()


async def test_delete_manual_removes_manual(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await ids.add_manual(db, "cidr", "10.50.0.0/24")
        assert await ids.delete_manual(db, row.id) is True
        assert await ids.list_identifiers(db, "cidr") == []
        assert await ids.delete_manual(db, row.id) is False  # already gone
    await engine.dispose()


async def test_delete_manual_refuses_detected(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        det = await ids.upsert_detected(db, "cidr", "10.50.0.0/24", {"x": 1}, "muted")
        assert await ids.delete_manual(db, det.id) is False
        # the detected row survives (operators mute, never delete)
        assert len(await ids.list_identifiers(db, "cidr")) == 1
    await engine.dispose()


# ---------------------------------------------------------------------------
# effective_internal_identifiers
# ---------------------------------------------------------------------------


async def test_effective_env_only(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        eff = await effective_internal_identifiers(db, settings_kratos)
    # env defaults: suffixes .lan/.local/.internal/.corp; cidrs RFC1918; no hosts
    assert eff.suffixes == (".lan", ".local", ".internal", ".corp")
    assert eff.hosts == ()
    assert ipaddress.ip_network("10.0.0.0/8") in eff.cidrs
    assert ipaddress.ip_network("192.168.0.0/16") in eff.cidrs
    await engine.dispose()


async def test_effective_active_adds_and_mute_removes_default(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # active detected suffix is added
        await ids.upsert_detected(db, "suffix", ".corp.acme.com", {"x": 1}, "active")
        # mute an env-config default suffix → it must be subtracted
        muted = await ids.add_manual(db, "suffix", ".corp")  # creates active first...
        await ids.set_state(db, muted.id, "muted")
        eff = await effective_internal_identifiers(db, settings_kratos)
    assert ".corp.acme.com" in eff.suffixes
    assert ".corp" not in eff.suffixes  # env default suppressed by a muted row
    assert ".lan" in eff.suffixes  # other defaults untouched
    await engine.dispose()


async def test_effective_manual_host_and_cidr_kinds(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await ids.add_manual(db, "host", "WIN11-01")
        await ids.add_manual(db, "cidr", "10.50.0.0/24")
        # a muted detected cidr must NOT appear (suggest-first / tombstone)
        det = await ids.upsert_detected(db, "cidr", "10.60.0.0/24", {"x": 1}, "muted")
        assert det.state == "muted"
        eff = await effective_internal_identifiers(db, settings_kratos)
    assert "WIN11-01" in eff.hosts
    assert ipaddress.ip_network("10.50.0.0/24") in eff.cidrs
    assert ipaddress.ip_network("10.60.0.0/24") not in eff.cidrs
    await engine.dispose()


async def test_effective_dedup(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # an active detected suffix that duplicates an env default
        await ids.upsert_detected(db, "suffix", ".lan", {"x": 1}, "active")
        eff = await effective_internal_identifiers(db, settings_kratos)
    assert eff.suffixes.count(".lan") == 1  # not duplicated
    await engine.dispose()
