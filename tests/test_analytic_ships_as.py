"""A shipped analytic can ship in shadow: ``ships_as: shadow`` on the spec file.

A new detector must not run live on its first deploy. Before the field, a
shipped analytic went live at once, because nothing wrote a status row for it
and the catalog read a missing row as live.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.hunting.spec import CATALOG_DIR, parse_spec
from soc_ai.main import create_app
from soc_ai.store import analytics as analytics_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import AnalyticState

from tests.test_analytics_store import SPEC_TEXT

_NEW = "new-detector-in-shadow"
_SHIPPED = "identity-4662-dcsync-nonmachine"

_NEW_TEXT = """
id: new-detector-in-shadow
title: A new detector that ships in shadow
description: For the ships_as tests.
level: high
scope_field: source.ip
scope_kind: host
ships_as: {ships_as}
precondition:
  all:
    - field: event.code
      value: "4769"
detection:
  all:
    - field: event.code
      value: "4769"
"""


def _write_catalog(directory: Path, *, ships_as: str = "shadow") -> Path:
    """The shipped catalog plus one new file, in a directory the test owns."""
    directory.mkdir(parents=True, exist_ok=True)
    for path in CATALOG_DIR.glob("*.yaml"):
        shutil.copy(path, directory / path.name)
    (directory / f"{_NEW}.yaml").write_text(_NEW_TEXT.format(ships_as=ships_as).lstrip())
    return directory


@pytest.fixture
def catalog_dir(tmp_path: Path) -> Iterator[Path]:
    directory = _write_catalog(tmp_path / "catalog")
    with (
        patch("soc_ai.hunting.catalog_tiers.CATALOG_DIR", directory),
        patch("soc_ai.store.analytics.CATALOG_DIR", directory),
        patch("soc_ai.api.webui.routes_analytics.CATALOG_DIR", directory),
    ):
        yield directory


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def test_the_field_defaults_to_live_and_takes_two_values() -> None:
    spec = parse_spec(SPEC_TEXT)
    assert spec.ships_as == "live"
    assert parse_spec(_NEW_TEXT.format(ships_as="shadow")).ships_as == "shadow"
    with pytest.raises(ValueError):
        parse_spec(_NEW_TEXT.format(ships_as="candidate"))


@pytest.mark.asyncio
async def test_a_shipped_analytic_in_shadow_reads_shadow_before_any_row(
    settings_kratos: Settings, catalog_dir: Path
) -> None:
    """A read path writes nothing and still never runs the detector live."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        cat = await effective_catalog(db)
        row = await db.get(AnalyticState, _NEW)
    await engine.dispose()
    assert cat.status_of(_NEW) == ("shipped", "shadow")
    assert _NEW in cat.specs
    assert _NEW in cat.shadow_ids
    assert row is None


@pytest.mark.asyncio
async def test_the_first_load_writes_a_shadow_row_with_a_version_row(
    settings_kratos: Settings, catalog_dir: Path
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        cat = await effective_catalog(db, seed=True)
        row = await db.get(AnalyticState, _NEW)
        again = await effective_catalog(db, seed=True)
        versions = await analytics_store.versions(db, _NEW)
    await engine.dispose()
    assert row is not None
    assert (row.tier, row.status) == ("shipped", "shadow")
    assert cat.status_of(_NEW) == again.status_of(_NEW) == ("shipped", "shadow")
    # One version row, however often the catalog loads.
    assert len(versions) == 1
    first = versions[0]
    assert (first.from_status, first.to_status) == (None, "shadow")
    assert first.who == analytics_store.CATALOG_ACTOR
    assert first.why == analytics_store.SHIPPED_IN_SHADOW_REASON
    assert "shipped in shadow" in (first.why or "")


@pytest.mark.asyncio
async def test_a_shipped_analytic_without_the_field_still_lands_live(
    settings_kratos: Settings, catalog_dir: Path
) -> None:
    """Negative control. The seed must touch the new file only.

    Every shipped file without the field keeps today's behaviour: live, and no
    row written for it.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        cat = await effective_catalog(db, seed=True)
        rows = await analytics_store.states(db)
    await engine.dispose()
    # The two shipped learned detectors declare the field too, so they land
    # in shadow beside the fixture.
    shipped_in_shadow = {_NEW, "model-cross-plane-silence", "model-logon-chain"}
    assert set(rows) == shipped_in_shadow
    assert cat.status_of(_SHIPPED) == ("shipped", "live")
    assert _SHIPPED in cat.specs and _SHIPPED not in cat.shadow_ids
    others = {sid for sid in cat.listed if sid not in shipped_in_shadow}
    assert others and all(cat.status_of(sid)[1] == "live" for sid in others)


@pytest.mark.asyncio
async def test_a_retired_analytic_is_not_revived_by_the_field(
    settings_kratos: Settings, catalog_dir: Path
) -> None:
    """An analyst retired the analytic before the release that ships it in shadow."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await analytics_store.retire_shipped(
            db, _NEW, shipped_text="", by="analyst", why="no domain controller here"
        )
        cat = await effective_catalog(db, seed=True)
        versions = await analytics_store.versions(db, _NEW)
    await engine.dispose()
    assert cat.status_of(_NEW) == ("shipped", "retired")
    assert _NEW not in cat.specs
    assert [v.to_status for v in versions] == ["retired"]


@pytest.mark.asyncio
async def test_a_retirement_after_the_seed_holds_on_the_next_load(
    settings_kratos: Settings, catalog_dir: Path
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await effective_catalog(db, seed=True)
        await analytics_store.transition(
            db, _NEW, to_status="retired", by="analyst", why="it fires on backups"
        )
        cat = await effective_catalog(db, seed=True)
        versions = await analytics_store.versions(db, _NEW)
    await engine.dispose()
    assert cat.status_of(_NEW) == ("shipped", "retired")
    assert [v.to_status for v in versions] == ["shadow", "retired"]


@pytest.mark.asyncio
async def test_a_later_release_that_ships_it_live_does_not_flip_the_held_analytic(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """The row decides once it exists. Approval to live stays the analyst's."""
    engine, maker = await _db(settings_kratos)
    first = _write_catalog(tmp_path / "release-1", ships_as="shadow")
    second = _write_catalog(tmp_path / "release-2", ships_as="live")
    async with maker() as db:
        with patch("soc_ai.hunting.catalog_tiers.CATALOG_DIR", first):
            await effective_catalog(db, seed=True)
        with patch("soc_ai.hunting.catalog_tiers.CATALOG_DIR", second):
            cat = await effective_catalog(db, seed=True)
        versions = await analytics_store.versions(db, _NEW)
    await engine.dispose()
    assert cat.status_of(_NEW) == ("shipped", "shadow")
    assert _NEW in cat.shadow_ids
    assert len(versions) == 1


@pytest.mark.asyncio
async def test_a_local_analytic_refuses_the_field(settings_kratos: Settings) -> None:
    """A local analytic always starts as a candidate. The field would never be read."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        with pytest.raises(ValueError, match="ships_as"):
            await analytics_store.create_local(
                db, spec_text=SPEC_TEXT + "ships_as: shadow\n", by="analyst"
            )
    await engine.dispose()


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def test_the_analyst_approves_a_shipped_shadow_analytic_through_the_route(
    client: TestClient, catalog_dir: Path
) -> None:
    """The status route writes the row it moves. No sweep has to run first."""
    listed: dict[str, Any] = {
        a["id"]: a for a in client.get("/api/v1/analytics").json()["analytics"]
    }
    assert listed[_NEW]["status"] == "shadow"
    assert listed[_SHIPPED]["status"] == "live"
    res = client.post(
        f"/api/v1/analytics/{_NEW}/status", json={"to": "live", "why": "a clean shadow week"}
    )
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "live"
    versions = client.get(f"/api/v1/analytics/{_NEW}").json()["versions"]
    assert [(v["from_status"], v["to_status"]) for v in versions] == [
        (None, "shadow"),
        ("shadow", "live"),
    ]
    assert versions[0]["who"] == analytics_store.CATALOG_ACTOR
    assert versions[1]["why"] == "a clean shadow week"
