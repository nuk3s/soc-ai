"""The outcome ledger of one analytic, computed on read."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.leads import content_fingerprint, form_leads, record_observation
from soc_ai.hunting.ledger import analytic_ledger
from soc_ai.hunting.weight import Kind
from soc_ai.store import leads as leads_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

pytestmark = pytest.mark.asyncio
_NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_the_ledger_counts_observations_leads_and_outcomes(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for host in ("10.1.2.7", "10.1.2.8"):
            await record_observation(
                db,
                entity_kind="host",
                entity_key=host,
                kind=Kind.NOVEL_DESTINATION,
                spec_id="a-1",
                fingerprint=content_fingerprint("a-1", host),
                now=_NOW,
            )
            await record_observation(
                db,
                entity_kind="host",
                entity_key=host,
                kind=Kind.RARE_FOR_PEERS,
                spec_id="p-1",
                fingerprint=content_fingerprint("p-1", host),
                now=_NOW,
            )
        outcome = await form_leads(
            db, entity_keys=[("host", "10.1.2.7"), ("host", "10.1.2.8")], now=_NOW
        )
        await leads_store.mark_hunting(db, outcome.formed[0], hunt_id="01H")
        await leads_store.dismiss(
            db, outcome.formed[1], reason="expected_for_role", note=None, by="a", now=_NOW
        )
        ledger = await analytic_ledger(db, "a-1", since=_NOW - timedelta(days=30), now=_NOW)
    await engine.dispose()
    assert ledger.observations == 2 and ledger.entities == 2
    assert ledger.leads == 2 and ledger.hunted == 1 and ledger.promoted == 0
    assert ledger.dismissed == {"expected_for_role": 1}
    assert ledger.as_dict()["leads"] == 2


async def test_the_ledger_counts_shadow_hits_and_the_unread_ones(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        read = await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.7",
            kind=Kind.CATALOG_MATCH,
            spec_id="local-x",
            fingerprint=content_fingerprint("local-x", "10.1.2.7"),
            source="candidate",
            shadow=True,
            now=_NOW,
        )
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.8",
            kind=Kind.CATALOG_MATCH,
            spec_id="local-x",
            fingerprint=content_fingerprint("local-x", "10.1.2.8"),
            source="candidate",
            shadow=True,
            now=_NOW,
        )
        read.read_at = _NOW.replace(tzinfo=None)
        await db.commit()
        ledger = await analytic_ledger(db, "local-x", since=_NOW - timedelta(days=30), now=_NOW)
    await engine.dispose()
    assert ledger.observations == 2
    assert ledger.shadow_hits == 2 and ledger.unread_shadow_hits == 1


async def test_the_batch_ledger_agrees_with_the_single_one(
    settings_kratos: Settings,
) -> None:
    """The analytics list read one ledger per analytic, one query set each.

    The batch does the same counting with one query per counter, so the two
    must produce the same numbers. Anything else is two answers to one
    question, and the list and the detail view would disagree on screen.
    """
    from soc_ai.hunting.ledger import analytic_ledgers
    from soc_ai.store.models import HuntSpecSweep, PriorSpecRun

    engine, maker = await _db(settings_kratos)
    since = _NOW - timedelta(days=30)
    async with maker() as db:
        for host in ("10.1.2.7", "10.1.2.8"):
            await record_observation(
                db,
                entity_kind="host",
                entity_key=host,
                kind=Kind.NOVEL_DESTINATION,
                spec_id="a-1",
                fingerprint=content_fingerprint("a-1", host),
                now=_NOW,
            )
            await record_observation(
                db,
                entity_kind="host",
                entity_key=host,
                kind=Kind.CATALOG_MATCH,
                spec_id="p-1",
                fingerprint=content_fingerprint("p-1", host),
                shadow=True,
                now=_NOW,
            )
        outcome = await form_leads(
            db, entity_keys=[("host", "10.1.2.7"), ("host", "10.1.2.8")], now=_NOW
        )
        await leads_store.mark_hunting(db, outcome.formed[0], hunt_id="01H")
        await leads_store.dismiss(
            db, outcome.formed[1], reason="known_change", note=None, by="a", now=_NOW
        )
        db.add(
            HuntSpecSweep(
                spec_id="a-1",
                created_at=_NOW.replace(tzinfo=None),
                window_since="now-24h",
                window_until="now",
                precondition_docs=120,
                duration_ms=45,
            )
        )
        db.add(
            HuntSpecSweep(
                spec_id="a-1",
                created_at=_NOW.replace(tzinfo=None),
                window_since="now-24h",
                window_until="now",
                precondition_docs=80,
                duration_ms=15,
            )
        )
        db.add(
            PriorSpecRun(
                spec_id="p-1",
                created_at=(_NOW - timedelta(days=1)).replace(tzinfo=None),
                measured=3,
                learning=1,
                blind=2,
            )
        )
        db.add(
            PriorSpecRun(
                spec_id="p-1",
                created_at=_NOW.replace(tzinfo=None),
                measured=9,
                learning=0,
                blind=1,
            )
        )
        await db.commit()

        many = await analytic_ledgers(db, ["a-1", "p-1", "never-run"], since=since, now=_NOW)
        singles = {
            spec: await analytic_ledger(db, spec, since=since, now=_NOW)
            for spec in ("a-1", "p-1", "never-run")
        }
    await engine.dispose()

    assert many == singles
    assert many["a-1"].docs_scanned == 200 and many["a-1"].sweeps == 2
    assert many["a-1"].runtime_ms == 60
    assert many["a-1"].leads == 2 and many["a-1"].hunted == 1
    assert many["a-1"].dismissed == {"known_change": 1}
    # The newest prior run, not the sum of the window.
    assert many["p-1"].coverage == {"measured": 9, "learning": 0, "blind": 1}
    assert many["p-1"].shadow_hits == 2 and many["p-1"].unread_shadow_hits == 2
    assert many["never-run"].observations == 0 and many["never-run"].coverage == {}


async def test_an_analytic_that_has_never_run_reads_as_zero_and_not_as_an_error(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        ledger = await analytic_ledger(db, "never-run", since=_NOW - timedelta(days=30), now=_NOW)
    await engine.dispose()
    assert ledger.observations == 0 and ledger.leads == 0
    assert ledger.sweeps == 0 and ledger.docs_scanned == 0 and ledger.runtime_ms == 0
    assert ledger.coverage == {}
