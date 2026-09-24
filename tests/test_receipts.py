"""A shadow hit brings receipts, or it says which part it could not bring."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from soc_ai.config import Settings
from soc_ai.hunting.execute import Candidate, SpecRun
from soc_ai.hunting.leads import content_fingerprint, record_observation
from soc_ai.hunting.receipts import Receipts, build_receipts, overlap_with_live
from soc_ai.hunting.weight import Kind
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

# No module-level asyncio mark: half of these tests are synchronous, and
# ``asyncio_mode = "auto"`` already collects the async ones.
_NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _dry(fires: int, entities: list[str]) -> SpecRun:
    return SpecRun(
        spec_id="local-x",
        since="now-30d",
        until="now",
        blind=False,
        precondition_docs=100,
        matched_docs=fires,
        candidates=[
            Candidate(
                spec_id="local-x",
                scope_key=e,
                scope_kind="host",
                doc_count=1,
                sample_ids=("d9",),
                anchor_id="d9",
                anchor_index="i",
                first_seen=None,
                last_seen=None,
            )
            for e in entities
        ],
        precondition_since="",
    )


async def test_overlap_finds_a_live_observation_on_the_same_documents(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.7",
            kind=Kind.CATALOG_MATCH,
            spec_id="identity-4769-rc4-service-ticket",
            fingerprint=content_fingerprint("identity-4769-rc4-service-ticket", "10.1.2.7"),
            evidence={"sample_ids": ["d1", "d2"]},
            source="catalog",
            now=_NOW,
        )
        hits = await overlap_with_live(db, entity_key="10.1.2.7", sample_ids=["d2", "d3"], now=_NOW)
    await engine.dispose()
    assert hits == [{"analytic": "identity-4769-rc4-service-ticket", "documents": 1}]


async def test_a_shadow_observation_is_never_counted_as_an_overlap(
    settings_kratos: Settings,
) -> None:
    """Overlap means "a LIVE analytic already sees this". A shadow row does not."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.7",
            kind=Kind.CATALOG_MATCH,
            spec_id="local-other",
            fingerprint=content_fingerprint("local-other", "10.1.2.7"),
            evidence={"sample_ids": ["d1", "d2"]},
            source="candidate",
            shadow=True,
            now=_NOW,
        )
        hits = await overlap_with_live(db, entity_key="10.1.2.7", sample_ids=["d2"], now=_NOW)
    await engine.dispose()
    assert hits == []


def test_complete_receipts_for_a_query_analytic() -> None:
    r = build_receipts(
        matched_ids=["d1", "d2"],
        matched_fields=["event.code", "winlog.event_data.TargetUserName"],
        dry_run=_dry(2, ["10.1.2.7"]),
        overlap=[],
        baseline=None,
        profile=False,
    )
    assert isinstance(r, Receipts) and r.complete and r.missing == []
    assert r.as_dict()["dry_run"] == {"window_days": 30, "fires": 2, "entities": ["10.1.2.7"]}


def test_a_profile_analytic_without_a_baseline_is_incomplete() -> None:
    r = build_receipts(
        matched_ids=["d1"],
        matched_fields=[],
        dry_run=None,
        overlap=[],
        baseline=None,
        profile=True,
        requires_dry_run=False,
    )
    assert not r.complete and r.missing == ["baseline"]


def test_a_profile_receipt_with_a_baseline_and_no_dry_run_is_complete() -> None:
    """A profile analytic has no query, so the baseline IS its dry run."""
    r = build_receipts(
        matched_ids=[],
        matched_fields=["served_ports"],
        dry_run=None,
        overlap=[],
        baseline={"dimension": "served_ports", "member": "3389", "baseline_size": 4},
        profile=True,
        requires_dry_run=False,
        requires_matched_ids=False,
    )
    assert r.complete and r.missing == []
    assert r.as_dict()["dry_run"] is None


def test_a_failed_dry_run_is_incomplete_and_named() -> None:
    run = replace(_dry(0, []), error="detection: ConnectionTimeout")
    r = build_receipts(
        matched_ids=["d1"],
        matched_fields=["event.code"],
        dry_run=run,
        overlap=[],
        baseline=None,
        profile=False,
    )
    assert not r.complete and r.missing == ["dry_run"]


def test_a_blind_dry_run_is_incomplete() -> None:
    run = replace(_dry(0, []), blind=True)
    r = build_receipts(
        matched_ids=["d1"],
        matched_fields=["event.code"],
        dry_run=run,
        overlap=[],
        baseline=None,
        profile=False,
    )
    assert not r.complete and r.missing == ["dry_run"]


def test_no_matched_documents_is_incomplete() -> None:
    r = build_receipts(
        matched_ids=[],
        matched_fields=[],
        dry_run=_dry(1, ["10.1.2.7"]),
        overlap=[],
        baseline=None,
        profile=False,
    )
    assert not r.complete and "matched_ids" in r.missing
