"""The Investigations list as a real QUERY: SQL filters, SQL counts, paging.

The disease this file pins: ``GET /api/v1/investigations`` used to be the newest
100 rows by ``created_at`` with the screen filtering those 100 CLIENT-SIDE — so
on a deployment whose newest 100 runs were all completed false positives, every
older errored run was unreachable under ANY filter the operator could set
(selecting Status=error searched the same 100 completed rows and found nothing).
This is the phantom-untriaged / phantom-NMI illness again: a filter (or a count)
and the rows it promises disagreeing about their window.

The acceptance test seeds production's measured shape — a few hundred rows
dominated by one outcome, with a handful of errors older than the old 100-row
cutoff — and asserts Status=error returns every one of them.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_investigations import _row_status
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation
from soc_ai.triage_models import is_pipeline_fallback

# The persisted report shape of an E1.2 pipeline-failure fallback — the marker
# `is_pipeline_fallback` keys on, mirrored from `_synth_failure_fallback_report`.
_FALLBACK_REPORT: dict[str, Any] = {
    "verdict": "needs_more_info",
    "confidence": 0.3,
    "summary": "Synth-first pipeline fallback.",
    "resolution": {"provenance": "pipeline_fallback", "phase": "synth_first_round1"},
}


def _mk(
    seq: int,
    *,
    status: str,
    created_at: datetime,
    verdict: str | None = None,
    alert: str | None = None,
    report: dict[str, Any] | None = None,
    rule: str = "GPL ICMP Large ICMP Packet",
    src: str = "192.168.50.10",
    dst: str = "192.168.50.99",
) -> Investigation:
    """One seeded run. Ids are zero-padded so the id-desc tiebreak is deterministic."""
    return Investigation(
        id=f"{seq:026d}",
        alert_es_id=alert or f"ev-{seq}",
        rule_name=rule,
        verdict=verdict,
        status=status,
        src_ip=src,
        dest_ip=dst,
        started_by="test",
        created_at=created_at,
        report=report,
        # Stamp the denormalized flag the way finalize/resolve do, so a
        # directly-constructed row matches a production one — query_page reads
        # this column, not the report JSON.
        is_fallback=is_pipeline_fallback(report),
    )


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _seed_production_shape(db: Any, now: datetime) -> None:
    """Production's measured pathology: 300 recent completed FPs saturating the
    newest-100 page, 7 errors and 2 interrupted runs OLDER than that cutoff."""
    rows = [
        _mk(
            1000 + i,
            status="complete",
            verdict="false_positive",
            created_at=now - timedelta(minutes=8 * i),
        )
        for i in range(300)
    ]
    rows += [
        _mk(500 + i, status="error", created_at=now - timedelta(days=3, hours=i)) for i in range(7)
    ]
    rows += [
        _mk(400 + i, status="interrupted", created_at=now - timedelta(days=5, hours=i))
        for i in range(2)
    ]
    db.add_all(rows)
    await db.commit()


# ---------------------------------------------------------------------------
# Store: query_page
# ---------------------------------------------------------------------------


async def test_status_error_reaches_runs_older_than_the_page_cutoff(
    settings_kratos: Settings,
) -> None:
    """THE acceptance test. Errored runs older than the newest-100 cutoff must be
    returned — and counted — by a status=error query, page saturation be damned."""
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        await _seed_production_shape(db, now)

        # The old page: newest 100, saturated by completed FPs — zero errors.
        default_page = await inv_svc.query_page(db, limit=100)
        assert default_page.total == 309
        assert len(default_page.rows) == 100
        assert all(r.status == "complete" for r in default_page.rows)

        # The cure: the filter runs in SQL, so all 7 errors surface with an
        # honest total — even though every one predates the old page cutoff.
        errors = await inv_svc.query_page(db, statuses=["error"], limit=100)
        assert errors.total == 7
        assert [r.status for r in errors.rows] == ["error"] * 7
        oldest_on_default_page = min(r.created_at for r in default_page.rows)
        assert all(r.created_at < oldest_on_default_page for r in errors.rows)

        both = await inv_svc.query_page(db, statuses=["error", "interrupted"], limit=100)
        assert both.total == 9
    await engine.dispose()


async def test_effective_status_matches_the_display_mapping(settings_kratos: Settings) -> None:
    """Filtering must use the DISPLAY status the row will render with, not the raw
    column: a 'complete' run with no verdict displays as error (`_row_status`),
    so status=error must return it and status=complete must not — otherwise the
    filter promises a set the table contradicts."""
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        db.add_all(
            [
                _mk(1, status="complete", verdict="false_positive", created_at=now),
                # Finished without a verdict — displays as error.
                _mk(2, status="complete", verdict=None, created_at=now),
                _mk(3, status="complete", verdict="   ", created_at=now),
                # Unknown stored status — displays as error, never as complete.
                _mk(4, status="weird", verdict=None, created_at=now),
                _mk(5, status="error", verdict=None, created_at=now),
            ]
        )
        await db.commit()

        errors = await inv_svc.query_page(db, statuses=["error"])
        assert {r.id for r in errors.rows} == {f"{i:026d}" for i in (2, 3, 4, 5)}
        assert errors.total == 4

        complete = await inv_svc.query_page(db, statuses=["complete"])
        assert {r.id for r in complete.rows} == {f"{1:026d}"}
        assert complete.total == 1
    await engine.dispose()


async def test_verdict_filter_with_synthetic_pipeline_error(settings_kratos: Settings) -> None:
    """'pipeline_error' is not a stored verdict — it means the report carries the
    fallback marker. A fallback row matches ONLY pipeline_error (its stored
    needs_more_info must not leak into the NMI filter), mirroring the screen's
    matchesVerdict semantics exactly."""
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        db.add_all(
            [
                _mk(
                    1,
                    status="complete",
                    verdict="needs_more_info",
                    created_at=now,
                    report=_FALLBACK_REPORT,
                ),
                _mk(
                    2,
                    status="complete",
                    verdict="needs_more_info",
                    created_at=now,
                    report={"verdict": "needs_more_info"},
                ),
                _mk(3, status="complete", verdict="true_positive", created_at=now),
                # report=None: json_extract over NULL must count as not-fallback,
                # not silently exclude the row from every verdict filter.
                _mk(4, status="complete", verdict="true_positive", created_at=now, report=None),
            ]
        )
        await db.commit()

        nmi = await inv_svc.query_page(db, verdicts=["needs_more_info"])
        assert {r.id for r in nmi.rows} == {f"{2:026d}"}

        fb = await inv_svc.query_page(db, verdicts=["pipeline_error"])
        assert {r.id for r in fb.rows} == {f"{1:026d}"}

        both = await inv_svc.query_page(db, verdicts=["pipeline_error", "needs_more_info"])
        assert {r.id for r in both.rows} == {f"{1:026d}", f"{2:026d}"}
        assert both.total == 2

        tp = await inv_svc.query_page(db, verdicts=["true_positive"])
        assert {r.id for r in tp.rows} == {f"{3:026d}", f"{4:026d}"}
    await engine.dispose()


# ---------------------------------------------------------------------------
# Differential: the SQL twins against the Python originals they mirror
#
# Both filters are SQL REIMPLEMENTATIONS of a Python predicate the UI renders
# from. A test that merely RESTATES the expected mapping (as the two above do)
# stays green when one side moves — the filter and the badge part company in
# silence, which is the exact failure mode this whole branch exists to cure.
# So these two assert the SQL result set EQUALS the Python predicate's, over a
# matrix built to include the shapes each side handles differently.
# ---------------------------------------------------------------------------

# Verdict strings spanning the ASCII whitespace kinds: SQLite's one-argument
# trim() strips SPACES only, where Python's str.strip() strips all whitespace,
# so a tab-only verdict is where the two implementations first disagree. Every
# character of `string.whitespace` appears here, which is exactly the charset
# `_display_status_sql` passes to trim().
#
# Not here, deliberately: the Unicode whitespace `str.strip()` also strips but
# `string.whitespace` does not contain (NEL, NBSP, U+2028, the C1 separators).
# Those still diverge, and closing that would mean spelling every Unicode space
# codepoint into a SQL charset for a column whose values are written by the
# backend from a fixed verdict enum. The boundary is stated rather than hidden:
# this test pins the ASCII half, and `_display_status_sql`'s docstring says so.
_VERDICT_SHAPES = (
    None,
    "",
    " ",
    "  ",
    "\t",
    "\n",
    "\r\n",
    "\x0b",
    "\x0c",
    " \t\n\r\x0b\x0c ",
    "true_positive",
    "inconclusive",
)

# Report shapes the fallback predicate must classify identically in both
# languages. `is_pipeline_fallback` is defensive by design (a rendering
# predicate must never break a page), so the matrix is mostly the malformed
# column values it defends against: non-dict reports, non-dict resolutions and
# non-string provenance all have to come back not-a-fallback on BOTH sides.
_REPORT_SHAPES: tuple[Any, ...] = (
    None,
    {},
    {"resolution": None},
    {"resolution": {}},
    {"resolution": "pipeline_fallback"},
    {"resolution": ["pipeline_fallback"]},
    {"resolution": 7},
    {"resolution": {"provenance": None}},
    {"resolution": {"provenance": 7}},
    {"resolution": {"provenance": ["pipeline_fallback"]}},
    {"resolution": {"provenance": {"value": "pipeline_fallback"}}},
    {"resolution": {"provenance": ""}},
    {"resolution": {"provenance": "PIPELINE_FALLBACK"}},
    {"resolution": {"provenance": "pipeline_fallback_x"}},
    {"resolution": {"provenance": "manual_override"}},
    {"resolution": {"provenance": "pipeline_fallback"}},
    _FALLBACK_REPORT,
    7,
    "pipeline_fallback",
    ["pipeline_fallback"],
)


async def test_status_filter_matches_the_renderer_row_for_row(settings_kratos: Settings) -> None:
    """DIFFERENTIAL: for every display status, the SQL filter returns exactly the
    rows ``_row_status`` renders with that status.

    Pinning the SQL against the renderer itself — not against a restatement of
    what the renderer is believed to do — is what makes the two move together:
    edit ``_row_status`` and this fails, instead of the filter quietly promising
    a set the table contradicts.
    """
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    # Derived from the vocabulary, not a copy of it: a status added to
    # DISPLAY_STATUSES seeds a row here and so has to pass through BOTH sides.
    # Plus two values outside it, which both sides must render as 'error'.
    stored_statuses = (*inv_svc.DISPLAY_STATUSES, "weird", "")
    async with maker() as db:
        db.add_all(
            [
                _mk(i, status=s, verdict=v, created_at=now - timedelta(seconds=i))
                for i, (s, v) in enumerate(
                    itertools.product(stored_statuses, _VERDICT_SHAPES), start=1
                )
            ]
        )
        await db.commit()

        everything = await inv_svc.query_page(db, limit=inv_svc.MAX_PAGE_LIMIT)
        assert len(everything.rows) == len(stored_statuses) * len(_VERDICT_SHAPES)

        for display in inv_svc.DISPLAY_STATUSES:
            page = await inv_svc.query_page(db, statuses=[display], limit=inv_svc.MAX_PAGE_LIMIT)
            expected = {r.id for r in everything.rows if _row_status(r) == display}
            assert {r.id for r in page.rows} == expected, f"status={display} rows"
            assert page.total == len(expected), f"status={display} total"

        # And no row escapes the vocabulary: filtering on all five returns the
        # whole table, so nothing renders under a status the filter cannot offer.
        every = await inv_svc.query_page(
            db, statuses=list(inv_svc.DISPLAY_STATUSES), limit=inv_svc.MAX_PAGE_LIMIT
        )
        assert every.total == everything.total
    await engine.dispose()


async def test_pipeline_error_filter_matches_is_pipeline_fallback_row_for_row(
    settings_kratos: Settings,
) -> None:
    """DIFFERENTIAL: ``verdict=pipeline_error`` returns exactly the rows
    ``is_pipeline_fallback`` calls fallbacks, and a real-verdict filter returns
    exactly the complement — over a matrix of malformed report shapes.

    The two sides are the badge and the filter: the row renders its
    pipeline-error chip from the Python predicate and is FOUND by the SQL one.
    """
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        db.add_all(
            [
                _mk(
                    i,
                    status="complete",
                    verdict="true_positive",
                    created_at=now - timedelta(seconds=i),
                    report=report,
                )
                for i, report in enumerate(_REPORT_SHAPES, start=1)
            ]
        )
        await db.commit()

        everything = await inv_svc.query_page(db, limit=inv_svc.MAX_PAGE_LIMIT)
        assert len(everything.rows) == len(_REPORT_SHAPES)
        fallbacks = {r.id for r in everything.rows if is_pipeline_fallback(r.report)}
        assert fallbacks, "matrix must contain at least one real fallback"
        assert len(fallbacks) < len(_REPORT_SHAPES), "matrix must contain non-fallbacks too"

        page = await inv_svc.query_page(
            db, verdicts=[inv_svc.PIPELINE_ERROR_VERDICT], limit=inv_svc.MAX_PAGE_LIMIT
        )
        assert {r.id for r in page.rows} == fallbacks
        assert page.total == len(fallbacks)

        # The complement. Every row stores true_positive, so a real-verdict
        # filter must return precisely the rows the predicate did NOT mark —
        # a fallback's stored verdict never leaks into the settled-verdict view.
        stored = await inv_svc.query_page(
            db, verdicts=["true_positive"], limit=inv_svc.MAX_PAGE_LIMIT
        )
        assert {r.id for r in stored.rows} == {r.id for r in everything.rows} - fallbacks
        assert stored.total == len(_REPORT_SHAPES) - len(fallbacks)
    await engine.dispose()


async def test_since_until_bound_created_at_inclusively(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    t0 = utcnow().replace(microsecond=0)
    async with maker() as db:
        db.add_all(
            [
                _mk(1, status="complete", verdict="false_positive", created_at=t0),
                _mk(
                    2,
                    status="complete",
                    verdict="false_positive",
                    created_at=t0 + timedelta(hours=1),
                ),
                _mk(
                    3,
                    status="complete",
                    verdict="false_positive",
                    created_at=t0 + timedelta(hours=2),
                ),
            ]
        )
        await db.commit()

        page = await inv_svc.query_page(db, since=t0 + timedelta(hours=1))
        assert {r.id for r in page.rows} == {f"{2:026d}", f"{3:026d}"}  # inclusive lower edge
        assert page.total == 2

        page = await inv_svc.query_page(db, until=t0 + timedelta(hours=1))
        assert {r.id for r in page.rows} == {f"{1:026d}", f"{2:026d}"}  # inclusive upper edge

        page = await inv_svc.query_page(
            db, since=t0 + timedelta(hours=1), until=t0 + timedelta(hours=1)
        )
        assert {r.id for r in page.rows} == {f"{2:026d}"}
    await engine.dispose()


async def test_paging_slices_newest_first_with_stable_total(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        db.add_all(
            [
                _mk(
                    i,
                    status="complete",
                    verdict="false_positive",
                    created_at=now - timedelta(minutes=i),
                )
                for i in range(1, 8)
            ]
        )
        await db.commit()

        first = await inv_svc.query_page(db, limit=3, offset=0)
        second = await inv_svc.query_page(db, limit=3, offset=3)
        third = await inv_svc.query_page(db, limit=3, offset=6)
        assert [r.id for r in first.rows] == [f"{i:026d}" for i in (1, 2, 3)]
        assert [r.id for r in second.rows] == [f"{i:026d}" for i in (4, 5, 6)]
        assert [r.id for r in third.rows] == [f"{7:026d}"]
        assert first.total == second.total == third.total == 7
    await engine.dispose()


async def test_counts_track_the_same_filter_set_as_the_rows(settings_kratos: Settings) -> None:
    """The header figures. Counted in SQL over the SAME WHERE as the page — a
    page-local tally would rebuild the phantom-untriaged bug (a figure describing
    100 rows while reading as the filter set's)."""
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        db.add_all(
            [
                _mk(1, status="complete", verdict="false_positive", created_at=now),
                _mk(2, status="complete", verdict="true_positive", created_at=now),
                _mk(3, status="running", created_at=now),
                # Outside the window: must not leak into the filtered figures,
                # but MUST keep `active` true (poll gating is global).
                _mk(4, status="running", created_at=now - timedelta(days=3)),
                _mk(
                    5,
                    status="complete",
                    verdict="true_positive",
                    created_at=now - timedelta(days=3),
                ),
            ]
        )
        await db.commit()

        page = await inv_svc.query_page(db, since=now - timedelta(hours=24), limit=2)
        assert page.total == 3
        assert page.running == 1
        assert page.true_positives == 1
        assert len(page.rows) == 2  # the counts describe the filter set, not the page
        assert page.total_all == 5
        assert page.active is True

        # No running rows at all -> active False.
        page2 = await inv_svc.query_page(db, statuses=["complete"])
        assert page2.active is True  # still true: two running rows exist globally
    await engine.dispose()


async def test_true_positive_count_applies_the_row_filter_fallback_guard(
    settings_kratos: Settings,
) -> None:
    """The TP figure must honour the same not-a-fallback guard the ROW filter
    applies to ``verdict=true_positive``. Without it, a fallback-marked row that
    still carries a true_positive verdict counts as a true positive while
    rendering a pipeline-error chip — a header figure describing a set the rows
    below it are not in, on the one screen built to stop exactly that."""
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        db.add_all(
            [
                _mk(
                    1,
                    status="complete",
                    verdict="true_positive",
                    created_at=now,
                    report=_FALLBACK_REPORT,
                ),
                _mk(2, status="complete", verdict="true_positive", created_at=now),
            ]
        )
        await db.commit()

        # Under the pipeline-error filter the page holds ONE row, and that row
        # is not a true positive by the filter's own semantics.
        fb = await inv_svc.query_page(db, verdicts=[inv_svc.PIPELINE_ERROR_VERDICT])
        assert {r.id for r in fb.rows} == {f"{1:026d}"}
        assert fb.true_positives == 0

        # And unfiltered: the row set that verdict=true_positive would return is
        # one row, so the figure over the whole table is one too.
        page = await inv_svc.query_page(db)
        assert page.total == 2
        assert page.true_positives == 1
        assert {r.id for r in (await inv_svc.query_page(db, verdicts=["true_positive"])).rows} == {
            f"{2:026d}"
        }
    await engine.dispose()


async def test_aggregate_reads_the_is_fallback_column_not_the_report(
    settings_kratos: Settings,
) -> None:
    """The fallback aggregate reads the persisted ``is_fallback`` column, never
    the report JSON — the whole point of the denormalization (no per-row
    json_extract on each poll). Proven by DESYNCING the two: a row stamped
    fallback whose report carries NO marker still counts as pipeline_error, and a
    row stamped not-fallback whose report DOES carry the marker does not.
    """
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        # Stamped fallback, but the report has no marker at all.
        stamped_fb = _mk(1, status="complete", verdict="true_positive", created_at=now, report=None)
        stamped_fb.is_fallback = True
        # Stamped NOT fallback, but the report DOES carry the marker.
        stamped_ok = _mk(
            2,
            status="complete",
            verdict="true_positive",
            created_at=now,
            report=_FALLBACK_REPORT,
        )
        stamped_ok.is_fallback = False
        db.add_all([stamped_fb, stamped_ok])
        await db.commit()

        fb = await inv_svc.query_page(db, verdicts=[inv_svc.PIPELINE_ERROR_VERDICT])
        assert {r.id for r in fb.rows} == {f"{1:026d}"}  # the COLUMN decides, not the report
        assert fb.total == 1

        # The true-positive figure honours the same column-based guard: only the
        # not-fallback-stamped row counts, even though its report LOOKS like a fallback.
        page = await inv_svc.query_page(db)
        assert page.total == 2
        assert page.true_positives == 1
        tp = await inv_svc.query_page(db, verdicts=["true_positive"])
        assert {r.id for r in tp.rows} == {f"{2:026d}"}
    await engine.dispose()


async def test_runs_for_alerts_returns_full_groups_newest_first(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        db.add_all(
            [
                _mk(1, status="error", alert="alertA", created_at=now - timedelta(hours=3)),
                _mk(
                    2,
                    status="complete",
                    verdict="false_positive",
                    alert="alertA",
                    created_at=now - timedelta(hours=2),
                ),
                _mk(3, status="error", alert="alertA", created_at=now - timedelta(hours=1)),
                _mk(4, status="complete", verdict="true_positive", alert="alertB", created_at=now),
            ]
        )
        await db.commit()

        rows = await inv_svc.runs_for_alerts(db, ["alertA"])
        assert [r.id for r in rows] == [f"{i:026d}" for i in (3, 2, 1)]  # newest first
    await engine.dispose()


# ---------------------------------------------------------------------------
# Route: GET /api/v1/investigations
# ---------------------------------------------------------------------------


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _seed_route(client: TestClient, rows: list[Investigation]) -> None:
    async def _run() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            db.add_all(rows)
            await db.commit()

    asyncio.run(_run())


def test_route_returns_query_shape_with_honest_counts(client: TestClient) -> None:
    """The wire contract: rows + total + running + truePositives + totalAll +
    active + limit + offset — the /dossiers list shape. Status=error reaches
    errored runs the old newest-100 page could never show."""
    now = utcnow()
    rows = [
        _mk(
            1000 + i,
            status="complete",
            verdict="false_positive",
            created_at=now - timedelta(minutes=i),
        )
        for i in range(120)
    ]
    rows += [
        _mk(500 + i, status="error", created_at=now - timedelta(days=3, hours=i)) for i in range(4)
    ]
    _seed_route(client, rows)

    body = client.get("/api/v1/investigations?status=error&limit=100").json()
    assert body["total"] == 4
    assert body["totalAll"] == 124
    assert body["running"] == 0
    assert body["truePositives"] == 0
    assert body["active"] is False
    assert body["limit"] == 100
    assert body["offset"] == 0
    assert [r["status"] for r in body["rows"]] == ["error"] * 4
    # A run that ended without a verdict renders 'untriaged' — unchanged row shape.
    assert all(r["verdict"] == "untriaged" for r in body["rows"])

    # Unknown filter members are DROPPED (a mangled deep link must not 500 or
    # wedge the filter): 'bogus' alone means unfiltered.
    assert client.get("/api/v1/investigations?status=bogus&limit=200").json()["total"] == 124

    # Paging: second page picks up where the first stopped.
    p1 = client.get("/api/v1/investigations?limit=100&offset=0").json()
    p2 = client.get("/api/v1/investigations?limit=100&offset=100").json()
    assert len(p1["rows"]) == 100
    assert len(p2["rows"]) == 24
    assert p1["total"] == p2["total"] == 124
    assert {r["id"] for r in p1["rows"]}.isdisjoint({r["id"] for r in p2["rows"]})

    # The limit clamp is echoed so the client pages by what the server DID.
    assert client.get("/api/v1/investigations?limit=9999").json()["limit"] == 500


def test_route_verdict_filter_and_pipeline_error(client: TestClient) -> None:
    now = utcnow()
    _seed_route(
        client,
        [
            _mk(
                1,
                status="complete",
                verdict="needs_more_info",
                created_at=now,
                report=_FALLBACK_REPORT,
            ),
            _mk(2, status="complete", verdict="needs_more_info", created_at=now),
            _mk(3, status="complete", verdict="true_positive", created_at=now),
        ],
    )
    fb = client.get("/api/v1/investigations?verdict=pipeline_error").json()
    assert [r["id"] for r in fb["rows"]] == [f"{1:026d}"]
    assert fb["rows"][0]["fallback"] is True
    assert fb["total"] == 1

    nmi = client.get("/api/v1/investigations?verdict=needs_more_info").json()
    assert [r["id"] for r in nmi["rows"]] == [f"{2:026d}"]

    multi = client.get("/api/v1/investigations?verdict=true_positive,needs_more_info").json()
    assert {r["id"] for r in multi["rows"]} == {f"{2:026d}", f"{3:026d}"}
    assert multi["truePositives"] == 1


def test_route_primary_is_computed_over_the_whole_alert_group(client: TestClient) -> None:
    """Trap 1. Primacy is a property of the run within its FULL alert group, not
    of whatever happened to match the filter: under status=error, alert A's
    errored retries must arrive isPrimary=false (their complete sibling — NOT on
    the page — is the canonical run), while alert B (errors only) keeps its
    newest error as primary."""
    now = utcnow()
    _seed_route(
        client,
        [
            _mk(1, status="error", alert="alertA", created_at=now - timedelta(hours=3)),
            _mk(
                2,
                status="complete",
                verdict="false_positive",
                alert="alertA",
                created_at=now - timedelta(hours=2),
            ),
            _mk(3, status="error", alert="alertA", created_at=now - timedelta(hours=1)),
            _mk(4, status="error", alert="alertB", created_at=now - timedelta(hours=4)),
            _mk(5, status="error", alert="alertB", created_at=now - timedelta(minutes=30)),
        ],
    )
    body = client.get("/api/v1/investigations?status=error").json()
    by_id = {r["id"]: r for r in body["rows"]}
    assert by_id[f"{1:026d}"]["isPrimary"] is False
    assert by_id[f"{3:026d}"]["isPrimary"] is False  # A's canonical run is the complete one
    assert by_id[f"{5:026d}"]["isPrimary"] is True  # B has no live run; newest error leads
    assert by_id[f"{4:026d}"]["isPrimary"] is False

    # Unfiltered, the same rows carry the same primacy — the filter changed
    # WHICH rows came back, never what primary MEANS.
    full = {r["id"]: r for r in client.get("/api/v1/investigations").json()["rows"]}
    assert full[f"{2:026d}"]["isPrimary"] is True
    assert full[f"{3:026d}"]["isPrimary"] is False


def test_route_reports_a_failed_newest_run_on_the_primary_row(client: TestClient) -> None:
    """D8 (degraded-grid dogfood, 2026-08-14). Re-investigate an alert against a
    down grid and the newest run errors. Primacy keeps the older COMPLETE run as
    the representative row — that rule is right, it stops failed retries burying
    the run that landed a verdict — so the row goes on reading "True positive ·
    Complete", and the failure was collapsed into a bare "1 earlier" chip that
    said nothing about having failed. A batch that mostly died read as a
    mostly-calm list.

    So the row must carry BOTH: the complete run is still primary, and the row
    reports what happened to its alert last.
    """
    now = utcnow()
    _seed_route(
        client,
        [
            _mk(
                1,
                status="complete",
                verdict="true_positive",
                alert="alertA",
                created_at=now - timedelta(minutes=10),
            ),
            _mk(2, status="error", alert="alertA", created_at=now - timedelta(seconds=5)),
        ],
    )
    rows = {r["id"]: r for r in client.get("/api/v1/investigations").json()["rows"]}
    primary = rows[f"{1:026d}"]

    # Unchanged: the run that reached a verdict still represents the alert.
    assert primary["isPrimary"] is True
    assert primary["status"] == "complete"
    assert primary["verdict"] == "true_positive"
    assert rows[f"{2:026d}"]["isPrimary"] is False

    # New: and the row says the alert's newest run is not this one, and failed.
    assert primary["latestRunStatus"] == "error"
    assert primary["latestRunId"] == f"{2:026d}"
    assert primary["latestRunWhen"] == "now"


def test_route_leaves_an_uncontested_run_reporting_only_itself(client: TestClient) -> None:
    """The control for the test above, and the over-correction this batch must
    not ship: an ordinary completed investigation with no re-run behind it must
    grow no warning at all. Its newest run IS itself, so the latest-run fields
    name its own id and its own status — the screen renders nothing extra.

    Same for a run that is genuinely the newest of its group: alert B's error is
    both primary and latest, so its row must not report a SECOND failure
    alongside the one its Status column already shows.
    """
    now = utcnow()
    _seed_route(
        client,
        [
            _mk(
                1,
                status="complete",
                verdict="false_positive",
                alert="alertA",
                created_at=now - timedelta(hours=1),
            ),
            _mk(2, status="error", alert="alertB", created_at=now - timedelta(hours=2)),
            _mk(3, status="error", alert="alertB", created_at=now - timedelta(minutes=2)),
        ],
    )
    rows = {r["id"]: r for r in client.get("/api/v1/investigations").json()["rows"]}

    lone = rows[f"{1:026d}"]
    assert lone["latestRunId"] == lone["id"]
    assert lone["latestRunStatus"] == "complete"
    assert lone["latestRunWhen"] == lone["when"]

    newest_error = rows[f"{3:026d}"]
    assert newest_error["isPrimary"] is True
    assert newest_error["latestRunId"] == newest_error["id"]
    assert newest_error["latestRunStatus"] == "error"


def test_route_since_until_pass_through(client: TestClient) -> None:
    now = utcnow().replace(microsecond=0)
    _seed_route(
        client,
        [
            _mk(
                1, status="complete", verdict="false_positive", created_at=now - timedelta(hours=30)
            ),
            _mk(
                2, status="complete", verdict="false_positive", created_at=now - timedelta(hours=1)
            ),
        ],
    )
    since = (now - timedelta(hours=24)).isoformat()
    body = client.get(f"/api/v1/investigations?since={since}").json()
    assert [r["id"] for r in body["rows"]] == [f"{2:026d}"]
    assert body["total"] == 1
    assert body["totalAll"] == 2


# ---------------------------------------------------------------------------
# Free-text search (dogfood A3)
# ---------------------------------------------------------------------------


async def _seed_searchable(db: Any, now: datetime) -> None:
    """Three runs that differ in rule name, source and destination — one field
    each, so a match can only have come from the field under test."""
    db.add_all(
        [
            _mk(
                1,
                status="complete",
                verdict="true_positive",
                created_at=now,
                rule="ET MALWARE Cobalt Strike Beacon",
                alert="ev-cs",
                src="10.0.0.14",
                dst="203.0.113.9",
            ),
            _mk(
                2,
                status="complete",
                verdict="false_positive",
                created_at=now - timedelta(minutes=1),
                rule="GPL ICMP Large ICMP Packet",
                alert="ev-icmp",
                src="10.0.0.142",
                dst="203.0.113.20",
            ),
            _mk(
                3,
                status="complete",
                verdict="false_positive",
                created_at=now - timedelta(minutes=2),
                rule="ET SCAN Suspicious inbound",
                alert="ev-scan",
                src="192.0.2.200",
                dst="198.51.100.4",
            ),
        ]
    )
    await db.commit()


async def test_search_matches_the_rule_name(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_searchable(db, utcnow())
        page = await inv_svc.query_page(db, q="cobalt")
        assert [r.rule_name for r in page.rows] == ["ET MALWARE Cobalt Strike Beacon"]
        assert page.total == 1
    await engine.dispose()


async def test_search_matches_the_source_host(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_searchable(db, utcnow())
        # A substring, deliberately: an operator typing a /24 prefix wants the
        # subnet, not an exact-address lookup.
        page = await inv_svc.query_page(db, q="10.0.0.14")
        assert sorted(r.src_ip or "" for r in page.rows) == ["10.0.0.14", "10.0.0.142"]
    await engine.dispose()


async def test_search_matches_the_destination_ip(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_searchable(db, utcnow())
        page = await inv_svc.query_page(db, q="198.51.100.4")
        assert [r.dest_ip for r in page.rows] == ["198.51.100.4"]
    await engine.dispose()


async def test_search_is_case_insensitive_and_partial(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_searchable(db, utcnow())
        assert (await inv_svc.query_page(db, q="COBALT")).total == 1
        assert (await inv_svc.query_page(db, q="10.0.0.")).total == 2
    await engine.dispose()


async def test_search_narrows_the_counts_not_just_the_rows(settings_kratos: Settings) -> None:
    # The header figures come from the SAME filter set as the rows — a search
    # that narrows the table while the counts describe the whole store is the
    # phantom-count defect this query exists to prevent.
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_searchable(db, utcnow())
        page = await inv_svc.query_page(db, q="cobalt")
        assert page.total == 1
        assert page.true_positives == 1
        # …while the whole-store figures stay whole-store.
        assert page.total_all == 3
    await engine.dispose()


async def test_search_combines_with_the_other_filters(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_searchable(db, utcnow())
        assert (await inv_svc.query_page(db, q="Beacon", verdicts=["true_positive"])).total == 1
        assert (await inv_svc.query_page(db, q="Beacon", verdicts=["false_positive"])).total == 0
        assert (await inv_svc.query_page(db, q="Beacon")).total == 1
        assert (await inv_svc.query_page(db, q="ICMP")).total == 1
    await engine.dispose()


async def test_blank_search_is_no_filter_at_all(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_searchable(db, utcnow())
        assert (await inv_svc.query_page(db, q="   ")).total == 3
        assert (await inv_svc.query_page(db, q=None)).total == 3
    await engine.dispose()


async def test_search_wildcards_are_literal(settings_kratos: Settings) -> None:
    # A '%' the operator types is a percent sign, not "match everything".
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_searchable(db, utcnow())
        assert (await inv_svc.query_page(db, q="%")).total == 0
        assert (await inv_svc.query_page(db, q="_")).total == 0
    await engine.dispose()


def test_route_passes_the_search_term_through(client: TestClient) -> None:
    """?q= is a SERVER filter: the rows AND the counts narrow together."""
    now = utcnow()
    _seed_route(
        client,
        [
            _mk(
                1,
                status="complete",
                verdict="true_positive",
                created_at=now,
                rule="ET MALWARE Cobalt Strike Beacon",
                alert="ev-cs",
                src="10.0.0.14",
            ),
            _mk(
                2,
                status="complete",
                verdict="false_positive",
                created_at=now - timedelta(minutes=1),
                rule="GPL ICMP Large ICMP Packet",
                alert="ev-icmp",
                src="10.0.0.142",
            ),
        ],
    )
    body = client.get("/api/v1/investigations", params={"q": "cobalt"}).json()
    assert [r["name"] for r in body["rows"]] == ["ET MALWARE Cobalt Strike Beacon"]
    assert body["total"] == 1
    # The whole-store figure is untouched by a filter, by design.
    assert body["totalAll"] == 2

    by_host = client.get("/api/v1/investigations", params={"q": "10.0.0.142"}).json()
    assert [r["host"] for r in by_host["rows"]] == ["10.0.0.142"]


def test_an_over_long_search_is_refused_not_truncated(client: TestClient) -> None:
    """Truncating a search term makes the answer a SUPERSET of the question.

    `q[:200]` turns "match this string" into "match this prefix", so the table
    renders rows that do not contain what was typed and the header count agrees
    with them — a list quietly answering a different question, which is the
    exact failure this endpoint exists to have stopped doing.
    """
    resp = client.get("/api/v1/investigations", params={"q": "x" * 201})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "search_too_long"

    # The bound itself is still usable.
    ok = client.get("/api/v1/investigations", params={"q": "x" * 200})
    assert ok.status_code == 200, ok.text
