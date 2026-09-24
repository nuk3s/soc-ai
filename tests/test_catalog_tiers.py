"""One catalog from two tiers."""

from __future__ import annotations

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.store import analytics as analytics_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

from tests.test_analytics_store import SPEC_TEXT

pytestmark = pytest.mark.asyncio


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_shipped_specs_are_live_and_a_local_shadow_spec_joins_them(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        state = await analytics_store.create_local(db, spec_text=SPEC_TEXT, by="analyst")
        before = await effective_catalog(db)
        await analytics_store.transition(
            db, state.analytic_id, to_status="shadow", by="analyst", why="try it"
        )
        after = await effective_catalog(db)
    await engine.dispose()
    assert "identity-4662-dcsync-nonmachine" in before.specs
    assert before.status_of("identity-4662-dcsync-nonmachine") == ("shipped", "live")
    # A candidate is listed with its status and is NOT in the runnable specs.
    assert before.status_of(state.analytic_id) == ("local", "candidate")
    assert state.analytic_id not in before.specs
    assert state.analytic_id in before.listed
    assert state.analytic_id in after.specs
    assert after.shadow_ids == frozenset({state.analytic_id})


async def test_a_retired_shipped_spec_is_listed_but_not_run(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await analytics_store.retire_shipped(
            db,
            "identity-4662-dcsync-nonmachine",
            shipped_text="",
            by="analyst",
            why="no domain controller here",
        )
        cat = await effective_catalog(db)
    await engine.dispose()
    assert "identity-4662-dcsync-nonmachine" not in cat.specs
    assert cat.status_of("identity-4662-dcsync-nonmachine") == ("shipped", "retired")
    assert "identity-4662-dcsync-nonmachine" in cat.listed


async def test_a_local_row_that_does_not_parse_is_listed_and_never_runs(
    settings_kratos: Settings,
) -> None:
    """The analyst must be able to see a broken analytic to repair or retire it.

    It was dropped from the list, so the detail route raised a KeyError and the
    row could not be retired. An analytic that disappears with no record of why
    is the same failure as one that runs with no record of what it is.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        state = await analytics_store.create_local(db, spec_text=SPEC_TEXT, by="analyst")
        await analytics_store.transition(
            db, state.analytic_id, to_status="shadow", by="analyst", why="try it"
        )
        state.spec_text = "- no longer a mapping\n"
        await db.commit()
        cat = await effective_catalog(db)
    await engine.dispose()
    assert state.analytic_id not in cat.specs
    assert state.analytic_id not in cat.shadow_ids
    assert cat.status_of(state.analytic_id) == ("local", "shadow")

    placeholder = cat.listed[state.analytic_id]
    assert placeholder.id == state.analytic_id
    assert placeholder.title.endswith("(does not parse)")
    assert "a YAML mapping" in placeholder.description


async def test_a_local_row_with_a_shipped_id_never_replaces_the_shipped_analytic(
    settings_kratos: Settings,
) -> None:
    """The file on disk wins. A row written before the guard existed is ignored.

    A local row that took a shipped id ran in place of the shipped analytic and
    inherited its sweep trail, so the Operate panel showed the shipped title
    over the local logic.
    """
    from soc_ai.store.models import AnalyticState

    shipped_id = "identity-4662-dcsync-nonmachine"
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        db.add(
            AnalyticState(
                analytic_id=shipped_id,
                tier="local",
                status="shadow",
                spec_text=SPEC_TEXT.replace(
                    "id: local-svc-ticket-from-workstation", f"id: {shipped_id}"
                ),
                created_by="analyst",
            )
        )
        await db.commit()
        cat = await effective_catalog(db)
    await engine.dispose()
    assert cat.status_of(shipped_id) == ("shipped", "live")
    assert shipped_id not in cat.shadow_ids
    assert cat.specs[shipped_id].title == cat.listed[shipped_id].title
    assert "Kerberos ticket request" not in cat.specs[shipped_id].title
