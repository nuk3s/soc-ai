"""Recovery after a grid gap: an operator gap, the hits the gap wrote, and the holds.

The range sensor was down from 2026-10-15 13:36Z to 2026-10-19 10:15Z. soc-ai
kept no record of it. The first sweep after the recovery wrote five "connection
rate collapsed" hits and three "plane falls silent" hits for hours inside the
outage, one joined a lead, and the hit budget held a live analytic. To clean
up, the operator opened every hit and marked it benign: 24 actions. Then the
operator found out alone that the hold came from the outage (dogfood
2026-10-19, R1-I5, R3-I1, R3-I2, R4-I3).

Each test seeds its rows relative to now, so no test rots as the calendar
moves.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting import gap_recovery, self_heal
from soc_ai.store import analytics as analytics_store
from soc_ai.store import grid_gaps
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.leads import GRID_GAP_REASON
from soc_ai.store.models import EntityObservation, Lead

from tests.test_analytics_store import SPEC_TEXT

_ID = "local-svc-ticket-from-workstation"
_OTHER = "local-svc-ticket-from-workstation-two"
_SETTLE = timedelta(minutes=grid_gaps.DEFAULT_SETTLE_MINUTES)
_seq = itertools.count(1)
_QUERY = 'source.ip:"192.0.2.11" AND @timestamp:["2026-10-18T11:00:00Z" TO "2026-10-19T10:00:00Z"]'


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def _iso(at: datetime) -> str:
    return at.replace(tzinfo=UTC).isoformat()


async def _maker(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _row(
    *,
    host: str,
    born: datetime,
    kind: str = "below_baseline",
    source: str = "profile",
    spec_id: str = "profile-connection-rate-collapsed",
    evidence: dict[str, Any] | None = None,
    observed_at: datetime | None = None,
    rerun_query: str | None = None,
    shadow: bool = False,
    lead_id: int | None = None,
) -> EntityObservation:
    return EntityObservation(
        entity_kind="host",
        entity_key=host,
        kind=kind,
        spec_id=spec_id,
        fingerprint=f"fp-{next(_seq)}",
        birth_weight=0.5,
        born_at=born,
        first_seen_at=born,
        occurrences=1,
        source=source,
        shadow=shadow,
        evidence_json=evidence,
        observed_at=observed_at,
        rerun_query=rerun_query,
        lead_id=lead_id,
    )


def _window(start: datetime, end: datetime) -> dict[str, Any]:
    return {"window": {"start": _iso(start), "end": _iso(end)}}


async def _gap(db: Any, start: datetime, end: datetime, now: datetime) -> Any:
    row, _created = await grid_gaps.record_operator_gap(
        db, started_at=start, ended_at=end, detail="The sensor was down.", now=now
    )
    return row


# ── the operator gap ─────────────────────────────────────────────────────────


async def test_an_operator_records_a_gap_soc_ai_did_not_see(settings_kratos: Settings) -> None:
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        row, created = await grid_gaps.record_operator_gap(
            db,
            started_at=now - timedelta(days=4),
            ended_at=now - timedelta(hours=3),
            detail="The sensor VM was down.",
            now=now,
        )
        again, created_again = await grid_gaps.record_operator_gap(
            db,
            started_at=now - timedelta(days=4),
            ended_at=now - timedelta(hours=3),
            detail="The sensor VM was down.",
            now=now,
        )
        rows = await grid_gaps.overlapping(db, since=now - timedelta(days=7), until=now)
    await engine.dispose()
    assert created is True
    assert row.source == grid_gaps.SOURCE_OPERATOR == "operator"
    assert row.plane is None
    # A repeat of the same command records nothing new.
    assert created_again is False
    assert again.id == row.id
    assert [r.id for r in rows] == [row.id]
    assert grid_gaps.describe(row).startswith("An operator recorded a grid gap from ")


@pytest.mark.parametrize(
    ("start", "end", "code"),
    [
        (timedelta(hours=-3), timedelta(hours=-4), "gap_end_before_start"),
        (timedelta(hours=-3), timedelta(hours=-3), "gap_end_before_start"),
        (timedelta(days=-40), timedelta(days=-9), "gap_too_long"),
        (timedelta(hours=1), timedelta(hours=2), "gap_start_in_future"),
        (timedelta(hours=-1), timedelta(hours=2), "gap_end_in_future"),
    ],
)
async def test_the_ledger_refuses_a_bad_operator_gap(
    settings_kratos: Settings, start: timedelta, end: timedelta, code: str
) -> None:
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        with pytest.raises(grid_gaps.GapRefused) as refused:
            await grid_gaps.record_operator_gap(
                db, started_at=now + start, ended_at=now + end, detail="", now=now
            )
        rows = await grid_gaps.overlapping(db, since=now - timedelta(days=60), until=now)
    await engine.dispose()
    assert refused.value.code == code
    assert rows == []


# ── the hits inside a gap ────────────────────────────────────────────────────


async def _plant(db: Any, now: datetime) -> dict[str, EntityObservation]:
    """Hits inside the gap, beside the hits the rule must leave alone.

    The gap runs from now - 4 days to now - 3 hours. The settle margin adds one
    hour, so the review window ends at now - 2 hours. The sweep that wrote the
    false hits ran at now - 150 minutes, inside the margin.
    """
    gap_start = now - timedelta(days=4)
    sweep = now - timedelta(minutes=150)
    lead = Lead(
        status="open", entities_json=[["host", "192.0.2.10"]], kinds_json=["below_baseline"]
    )
    db.add(lead)
    await db.flush()
    rows = {
        # A rate departure: its run lies inside the gap. It joined a lead.
        "rate": _row(
            host="192.0.2.10",
            born=sweep,
            evidence=_window(now - timedelta(hours=27), now - timedelta(hours=4)),
            lead_id=lead.id,
        ),
        # The same departure from an older sweep: no evidence.window. The
        # query it wrote names the run.
        "old_rate": _row(
            host="192.0.2.11",
            born=sweep,
            evidence={"baseline": {"dimension": "connection_rate"}},
            rerun_query=(
                'source.ip:"192.0.2.11" AND @timestamp:["'
                + (now - timedelta(hours=26)).strftime("%Y-%m-%dT%H:%M:%SZ")
                + '" TO "'
                + (now - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
                + '"] | count'
            ),
        ),
        # A plane silence that starts 30 minutes before the gap. It overlaps.
        "silence": _row(
            host="192.0.2.12",
            born=sweep,
            kind="telemetry_silence",
            source="model",
            spec_id="model-cross-plane-silence",
            evidence={
                "baseline": {
                    "features": {
                        "silent_from": _iso(gap_start - timedelta(minutes=30)),
                        "silent_until": _iso(now - timedelta(hours=4)),
                    }
                }
            },
        ),
        # Negative control: a hit of another host from the same sweep. Its
        # run lies before the gap, so the gap does not explain it.
        "other_host": _row(
            host="192.0.2.20",
            born=sweep,
            evidence=_window(now - timedelta(days=6), now - timedelta(days=5)),
        ),
        # Negative control: a run after the gap and its margin.
        "after": _row(
            host="192.0.2.10",
            born=now - timedelta(minutes=20),
            evidence=_window(now - timedelta(minutes=90), now - timedelta(minutes=30)),
        ),
        # Negative control: a catalog hit inside the gap. Its documents exist.
        "catalog": _row(
            host="192.0.2.13",
            born=sweep,
            kind="catalog_match",
            source="catalog",
            spec_id=_ID,
            observed_at=now - timedelta(days=1),
            evidence={
                "first_seen": _iso(now - timedelta(days=1)),
                "last_seen": _iso(now - timedelta(days=1)),
            },
        ),
        # Negative control: an alert verdict inside the gap.
        "alert": _row(
            host="192.0.2.14",
            born=sweep,
            kind="alert",
            source="alert",
            spec_id="alert:ET SCAN",
            observed_at=now - timedelta(days=1),
        ),
    }
    db.add_all(rows.values())
    await db.commit()
    return rows


async def test_the_review_lists_the_count_hits_whose_events_overlap_the_gap(
    settings_kratos: Settings,
) -> None:
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        rows = await _plant(db, now)
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        found = await gap_recovery.hits_in_gap(db, gap, settle=_SETTLE, now=now)
    await engine.dispose()
    ids = {hit.row.id for hit in found}
    assert ids == {rows["rate"].id, rows["old_rate"].id, rows["silence"].id}
    for name in ("other_host", "after", "catalog", "alert"):
        assert rows[name].id not in ids, name


async def test_the_old_rate_row_reads_its_run_from_the_query(settings_kratos: Settings) -> None:
    now = _now()
    row = _row(
        host="192.0.2.11",
        born=now,
        evidence={"baseline": {"dimension": "connection_rate"}},
        rerun_query=_QUERY + " | count",
    )
    span = gap_recovery.hit_window(row)
    assert span == (
        datetime(2026, 10, 18, 11, tzinfo=UTC),
        datetime(2026, 10, 19, 10, tzinfo=UTC),
    )
    # Another dimension names the read window in its query. The event is the
    # newest document.
    novel = _row(
        host="192.0.2.11",
        born=now,
        kind="novel_served_port",
        evidence={"baseline": {"dimension": "served_ports"}},
        observed_at=datetime(2026, 10, 19, 9, 30),
        rerun_query=_QUERY,
    )
    at = datetime(2026, 10, 19, 9, 30, tzinfo=UTC)
    assert gap_recovery.hit_window(novel) == (at, at)
    # No document time at all: the record time.
    bare = _row(host="192.0.2.11", born=datetime(2026, 10, 19, 9, 0))
    bare.first_seen_at = datetime(2026, 10, 18, 9, 0)
    assert gap_recovery.hit_window(bare) == (
        datetime(2026, 10, 18, 9, tzinfo=UTC),
        datetime(2026, 10, 19, 9, tzinfo=UTC),
    )


async def _plant_range_shape(db: Any, now: datetime) -> dict[str, EntityObservation]:
    """The shape of the live gap review on the range (dogfood round 2, G-1).

    The range gap ran four days. Its review listed 12 hits. Eight lay inside
    the gap: rate collapses and plane silences of the outage. The others only
    touched it: two rate SPIKES and a collapse that ran on after the recovery.
    Here the gap runs from now - 4 days to now - 3 hours, and the review window
    ends at now - 2 hours.
    """
    gap_start = now - timedelta(days=4)
    review_end = now - timedelta(hours=2)
    sweep = now - timedelta(minutes=150)
    rows = {
        # Inside: a collapse over the last 21 hours of the gap.
        "collapse": _row(
            host="192.0.2.11",
            born=sweep,
            evidence=_window(now - timedelta(hours=24), now - timedelta(hours=3)),
        ),
        # Inside: a plane silence over the last 6 hours of the gap.
        "silence": _row(
            host="192.0.2.12",
            born=sweep,
            kind="telemetry_silence",
            source="model",
            spec_id="model-cross-plane-silence",
            evidence={
                "baseline": {
                    "features": {
                        "silent_from": _iso(now - timedelta(hours=9)),
                        "silent_until": _iso(now - timedelta(hours=3)),
                    }
                }
            },
        ),
        # Inside the gap, but a spike: the gap gives no documents, so it
        # cannot make more of them. Only a back-fill burst can.
        "spike": _row(
            host="198.51.100.254",
            born=gap_start + timedelta(hours=3),
            kind="above_baseline",
            spec_id="profile-connection-rate-spiked",
            evidence=_window(gap_start + timedelta(hours=1), gap_start + timedelta(hours=2)),
        ),
        # Overlaps only: the collapse runs one hour past the review window.
        "runs_on": _row(
            host="203.0.113.123",
            born=now - timedelta(minutes=50),
            evidence=_window(now - timedelta(hours=21), now - timedelta(hours=1)),
        ),
        # Overlaps only, and a spike: it starts in the settle margin.
        "late_spike": _row(
            host="198.51.100.46",
            born=now - timedelta(minutes=50),
            kind="above_baseline",
            spec_id="profile-connection-rate-spiked",
            evidence=_window(
                review_end - timedelta(minutes=15), review_end + timedelta(minutes=45)
            ),
        ),
        # Overlaps only: the silence began 30 minutes before the gap.
        "early": _row(
            host="192.0.2.13",
            born=sweep,
            kind="telemetry_silence",
            source="model",
            spec_id="model-cross-plane-silence",
            evidence={
                "baseline": {
                    "features": {
                        "silent_from": _iso(gap_start - timedelta(minutes=30)),
                        "silent_until": _iso(now - timedelta(hours=4)),
                    }
                }
            },
        ),
    }
    db.add_all(rows.values())
    await db.commit()
    return rows


async def test_the_review_selects_only_the_hits_whose_events_lie_inside_the_gap(
    settings_kratos: Settings,
) -> None:
    """One confirm used to mark every listed hit, a real spike included (G-1)."""
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        rows = await _plant_range_shape(db, now)
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        found = {
            hit.row.id: hit
            for hit in await gap_recovery.hits_in_gap(db, gap, settle=_SETTLE, now=now)
        }
    await engine.dispose()
    # Every hit that touches the gap is listed.
    assert set(found) == {row.id for row in rows.values()}
    by_name = {name: found[row.id] for name, row in rows.items()}
    assert by_name["collapse"].selected and by_name["collapse"].inside
    assert by_name["silence"].selected and by_name["silence"].inside
    assert by_name["collapse"].reasons == ()
    # A spike stays unselected even inside the gap.
    assert by_name["spike"].inside is True
    assert by_name["spike"].selected is False
    assert by_name["spike"].reasons == (gap_recovery.SPIKE_REASON,)
    for name in ("runs_on", "early"):
        assert by_name[name].inside is False, name
        assert by_name[name].selected is False, name
        assert by_name[name].reasons == (gap_recovery.EDGE_REASON,), name
    assert by_name["late_spike"].reasons == (gap_recovery.SPIKE_REASON, gap_recovery.EDGE_REASON)
    assert (
        gap_recovery.SPIKE_REASON == "A gap does not explain a spike. Check for a back-fill burst."
    )
    assert gap_recovery.EDGE_REASON == "Part of this window is outside the gap."


async def test_mark_benign_marks_only_the_selected_hits(settings_kratos: Settings) -> None:
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        rows = await _plant_range_shape(db, now)
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        picked = [rows["collapse"].id, rows["silence"].id]
        result = await gap_recovery.mark_benign(
            db, gap, ids=picked, by="jordan", settle=_SETTLE, now=now
        )
        stored = {name: await db.get(EntityObservation, row.id) for name, row in rows.items()}
        left = await gap_recovery.hits_in_gap(db, gap, settle=_SETTLE, now=now)
    await engine.dispose()
    assert sorted(result.ids) == sorted(picked)
    for name, row in stored.items():
        assert row is not None
        if name in ("collapse", "silence"):
            assert row.dismissed_reason == GRID_GAP_REASON, name
        else:
            assert row.dismissed_at is None, name
    # The unselected hits wait for the next review.
    assert {hit.row.id for hit in left} == {
        rows[name].id for name in ("spike", "runs_on", "late_spike", "early")
    }


async def test_mark_benign_refuses_an_id_that_left_the_gap_list(settings_kratos: Settings) -> None:
    """A selected id that is no longer in the list writes nothing at all."""
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        rows = await _plant(db, now)
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        # "other_host" was never in the list: its run lies before the gap.
        picked = [rows["rate"].id, rows["other_host"].id]
        with pytest.raises(gap_recovery.HitsChanged) as changed:
            await gap_recovery.mark_benign(
                db, gap, ids=picked, by="jordan", settle=_SETTLE, now=now
            )
        rate = await db.get(EntityObservation, rows["rate"].id)
    await engine.dispose()
    assert changed.value.gone == [rows["other_host"].id]
    assert rate is not None and rate.dismissed_at is None


async def test_mark_benign_writes_one_reason_and_detaches_nothing(
    settings_kratos: Settings,
) -> None:
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        rows = await _plant(db, now)
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        picked = [rows["rate"].id, rows["old_rate"].id, rows["silence"].id]
        result = await gap_recovery.mark_benign(
            db, gap, ids=picked, by="jordan", settle=_SETTLE, now=now
        )
        again = await gap_recovery.hits_in_gap(db, gap, settle=_SETTLE, now=now)
        stored = {name: await db.get(EntityObservation, row.id) for name, row in rows.items()}
        lead = await db.get(Lead, rows["rate"].lead_id)
    await engine.dispose()
    note = gap_recovery.gap_note(gap)
    assert note.startswith("Grid gap from ")
    assert sorted(result.ids) == sorted([rows["rate"].id, rows["old_rate"].id, rows["silence"].id])
    assert result.leads == [rows["rate"].lead_id]
    for name in ("rate", "old_rate", "silence"):
        row = stored[name]
        assert row is not None
        assert row.dismissed_reason == GRID_GAP_REASON
        assert row.dismissed_note == note
        assert row.dismissed_by == "jordan"
    for name in ("other_host", "after", "catalog", "alert"):
        row = stored[name]
        assert row is not None and row.dismissed_at is None, name
    # The hit keeps its lead, and the lead stays open. Its weight reads the
    # observations that remain.
    assert stored["rate"] is not None and stored["rate"].lead_id == rows["rate"].lead_id
    assert lead is not None and lead.status == "open"
    # A second review finds nothing left to mark.
    assert again == []


async def test_mark_benign_refuses_a_hit_another_hand_marked_first(
    settings_kratos: Settings,
) -> None:
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        rows = await _plant(db, now)
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        picked = [rows["rate"].id, rows["old_rate"].id]
        await gap_recovery.mark_benign(
            db, gap, ids=[rows["old_rate"].id], by="sam", settle=_SETTLE, now=now
        )
        with pytest.raises(gap_recovery.HitsChanged) as changed:
            await gap_recovery.mark_benign(
                db, gap, ids=picked, by="jordan", settle=_SETTLE, now=now
            )
        left = await gap_recovery.hits_in_gap(db, gap, settle=_SETTLE, now=now)
    await engine.dispose()
    assert changed.value.gone == [rows["old_rate"].id]
    assert {hit.row.id for hit in left} == {rows["rate"].id, rows["silence"].id}


# ── the hold the gap hits caused ─────────────────────────────────────────────


def _spec(analytic_id: str, budget: int) -> str:
    return SPEC_TEXT.replace(_ID, analytic_id) + f"fire_budget_per_day: {budget}\n"


async def _live(db: Any, analytic_id: str, budget: int, at: datetime) -> None:
    await analytics_store.create_local(
        db, spec_text=_spec(analytic_id, budget), by="analyst", now=at
    )
    await analytics_store.transition(
        db, analytic_id, to_status="shadow", by="analyst", why="try", now=at
    )
    await analytics_store.transition(
        db, analytic_id, to_status="live", by="analyst", why="a clean week", now=at
    )


def _gap_hit(analytic_id: str, host: str, now: datetime) -> EntityObservation:
    return _row(
        host=host,
        born=now - timedelta(minutes=150),
        spec_id=analytic_id,
        evidence=_window(now - timedelta(hours=27), now - timedelta(hours=4)),
    )


def _plain_hit(analytic_id: str, host: str, now: datetime) -> EntityObservation:
    return _row(
        host=host,
        born=now - timedelta(minutes=20),
        spec_id=analytic_id,
        evidence=_window(now - timedelta(minutes=90), now - timedelta(minutes=30)),
    )


async def test_a_hold_that_only_gap_hits_broke_is_offered_return_to_live(
    settings_kratos: Settings,
) -> None:
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        await _live(db, _ID, 3, now - timedelta(days=5))
        await _live(db, _OTHER, 3, now - timedelta(days=5))
        # Five gap hits on each analytic. The second one also wrote four hits
        # after the gap, and four alone break its limit of three.
        db.add_all([_gap_hit(_ID, f"192.0.2.{i}", now) for i in range(1, 6)])
        db.add_all([_gap_hit(_OTHER, f"198.51.100.{i}", now) for i in range(1, 6)])
        db.add_all([_plain_hit(_OTHER, f"203.0.113.{i}", now) for i in range(1, 5)])
        await db.commit()
        # soc-ai did not see the gap. The hold counts every hit.
        healed = await self_heal.run_self_heal(db, now=now)
        assert sorted(d.analytic_id for d in healed.demoted) == sorted([_ID, _OTHER])
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        holds = {
            h.analytic_id: h for h in await gap_recovery.gap_holds(db, settle=_SETTLE, now=now)
        }
        for_gap = await gap_recovery.gap_holds(db, settle=_SETTLE, now=now, gap=gap)
        one = await gap_recovery.gap_holds(db, settle=_SETTLE, now=now, analytic_id=_ID)
    await engine.dispose()
    first = holds[_ID]
    assert (first.gap_hits, first.hits, first.budget) == (5, 5, 3)
    assert first.return_offered is True
    assert first.gap_ids == (gap.id,)
    second = holds[_OTHER]
    assert (second.gap_hits, second.hits, second.budget) == (5, 9, 3)
    assert second.return_offered is False
    assert {h.analytic_id for h in for_gap} == {_ID, _OTHER}
    assert [h.analytic_id for h in one] == [_ID]


async def test_spikes_inside_a_gap_do_not_earn_return_to_live(
    settings_kratos: Settings,
) -> None:
    """The review does not select a spike, so the hold must not lean on one.

    On the range the spiked analytic was offered Return to live on 2 spikes
    inside the gap, while the review said "A gap does not explain a spike."
    """
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        await _live(db, _ID, 3, now - timedelta(days=5))
        spikes = [_gap_hit(_ID, f"192.0.2.{i}", now) for i in range(1, 3)]
        for row in spikes:
            row.kind = "above_baseline"
        db.add_all(spikes)
        db.add_all([_plain_hit(_ID, f"203.0.113.{i}", now) for i in range(1, 3)])
        await db.commit()
        healed = await self_heal.run_self_heal(db, now=now)
        assert [d.analytic_id for d in healed.demoted] == [_ID]
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        holds = await gap_recovery.gap_holds(db, settle=_SETTLE, now=now, gap=gap)
    await engine.dispose()
    assert [h.analytic_id for h in holds] == [_ID]
    hold = holds[0]
    assert (hold.gap_hits, hold.spike_hits, hold.hits, hold.budget) == (2, 2, 4, 3)
    assert hold.return_offered is False


async def test_the_hold_is_found_after_a_later_sweep_flags_its_hits_shadow(
    settings_kratos: Settings,
) -> None:
    """On the range the review said held: [] while the hold stood (G-1).

    The hold moved the analytic to shadow. The next sweep saw the same hits
    again, and a sighting sets the flag of a row to the status of the analytic
    now. Every hit that broke the limit then read as shadow, and the count of
    the live hits found none of them.
    """
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        await _live(db, _ID, 3, now - timedelta(days=5))
        hits = [_gap_hit(_ID, f"192.0.2.{i}", now) for i in range(1, 6)]
        db.add_all(hits)
        await db.commit()
        healed = await self_heal.run_self_heal(db, now=now)
        assert [d.analytic_id for d in healed.demoted] == [_ID]
        # The next sweep sees the same documents: the flag follows the status.
        for row in hits:
            row.shadow = True
        # Negative control: a hit the analytic wrote in shadow after the hold.
        late = _gap_hit(_ID, "192.0.2.99", now)
        late.shadow = True
        late.first_seen_at = now + timedelta(minutes=30)
        late.born_at = now + timedelta(minutes=30)
        db.add(late)
        await db.commit()
        gap = await _gap(db, now - timedelta(days=4), now - timedelta(hours=3), now)
        holds = await gap_recovery.gap_holds(
            db, settle=_SETTLE, now=now + timedelta(hours=1), gap=gap
        )
    await engine.dispose()
    assert [h.analytic_id for h in holds] == [_ID]
    assert (holds[0].gap_hits, holds[0].hits, holds[0].budget) == (5, 5, 3)
    assert holds[0].return_offered is True


async def test_no_gap_names_no_hold(settings_kratos: Settings) -> None:
    """The control: the same hold with no gap on record carries no gap line."""
    now = _now()
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        await _live(db, _ID, 3, now - timedelta(days=5))
        db.add_all([_gap_hit(_ID, f"192.0.2.{i}", now) for i in range(1, 6)])
        await db.commit()
        await self_heal.run_self_heal(db, now=now)
        holds = await gap_recovery.gap_holds(db, settle=_SETTLE, now=now)
    await engine.dispose()
    assert holds == []
