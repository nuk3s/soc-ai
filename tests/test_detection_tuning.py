"""Tests for detection tuning: assess() heuristic, the override store, the
verdict-trend store helper, and the GET/POST detection-tuning endpoints."""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import detection_overrides as override_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.webui import detection_tuning as dt
from soc_ai.webui.alerts_query import AlertGroup
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


# ---------------------------------------------------------------------------
# Migration: the new table is created by run_migrations
# ---------------------------------------------------------------------------


async def test_migration_creates_detection_override_table(settings_kratos: Settings) -> None:
    from sqlalchemy import inspect

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = set(await conn.run_sync(lambda sc: inspect(sc).get_table_names()))
    assert "detection_override" in tables
    await engine.dispose()


# ---------------------------------------------------------------------------
# assess() — the pure heuristic
# ---------------------------------------------------------------------------


def test_assess_noisy_all_fp_recommends_mute() -> None:
    # High volume, several FP, zero TP -> a confident mute.
    is_noisy, rec, reason = dt.assess(alert_count=412, fp=8, tp=0, nmi=0)
    assert is_noisy is True
    assert rec == "mute"
    assert "412" in reason and "false positive" in reason


def test_assess_has_tp_is_never_noisy() -> None:
    # Even a constantly-firing rule is kept if it ever caught a real positive.
    is_noisy, rec, reason = dt.assess(alert_count=999, fp=20, tp=1, nmi=0)
    assert is_noisy is False
    assert rec == "none"
    assert "true positive" in reason


def test_assess_low_volume_is_none() -> None:
    # Below the volume floor it is not a tuning problem, whatever the verdicts.
    is_noisy, rec, _ = dt.assess(alert_count=5, fp=5, tp=0, nmi=0)
    assert is_noisy is False
    assert rec == "none"


def test_assess_thin_history_high_volume_monitors() -> None:
    # High volume but too few investigations to trust the trend -> monitor.
    is_noisy, rec, reason = dt.assess(alert_count=300, fp=1, tp=0, nmi=0)
    assert is_noisy is False
    assert rec == "monitor"
    assert "watch it" in reason


def test_assess_all_fp_under_high_volume_bar_monitors() -> None:
    # All-FP and over the noisy floor but under MUTE_MIN_ALERTS -> monitor (noisy).
    assert dt.MIN_ALERTS <= 50 < dt.MUTE_MIN_ALERTS
    is_noisy, rec, _ = dt.assess(alert_count=50, fp=4, tp=0, nmi=1)
    assert is_noisy is True
    assert rec == "monitor"


def test_assess_threshold_boundary_mute() -> None:
    # Exactly at MUTE_MIN_ALERTS with enough FP and zero TP -> mute.
    is_noisy, rec, _ = dt.assess(alert_count=dt.MUTE_MIN_ALERTS, fp=dt.MIN_FP, tp=0, nmi=0)
    assert is_noisy is True
    assert rec == "mute"


# ---------------------------------------------------------------------------
# assess() — analyst FP-override signal (E4.3)
# ---------------------------------------------------------------------------


def test_assess_override_default_is_backcompat() -> None:
    # override_fp defaults to 0 → identical to a call without it (positional
    # callers — the agent tool + MCP — are unaffected).
    assert dt.assess(412, 8, 0, 0) == dt.assess(412, 8, 0, 0, 0)
    assert dt.assess(50, 4, 0, 1) == dt.assess(50, 4, 0, 1, 0)


def test_assess_override_fp_upgrades_thin_ai_history() -> None:
    # High volume, thin AI-FP history (would be a bare "monitor") but the analyst
    # overrode it to FP repeatedly → stronger lean + a reason naming the feedback.
    is_noisy, rec, reason = dt.assess(alert_count=300, fp=1, tp=0, nmi=0, override_fp=3)
    assert is_noisy is True
    assert rec == "mute"  # high volume + strong analyst signal
    assert "analyst FP-overrides" in reason


def test_assess_override_fp_surfaces_below_volume_floor() -> None:
    # Below the volume floor (normally "none") but repeated analyst FP-overrides
    # → surfaced as a monitor with a reason citing the human feedback.
    is_noisy, rec, reason = dt.assess(alert_count=5, fp=0, tp=0, nmi=0, override_fp=2)
    assert is_noisy is True
    assert rec == "monitor"
    assert "analyst FP-overrides" in reason


def test_assess_override_fp_upgrades_monitor_to_mute_below_bar() -> None:
    # All-FP over the noisy floor but under the high-volume bar would be "monitor";
    # a strong analyst signal upgrades it to a confident mute.
    is_noisy, rec, reason = dt.assess(alert_count=50, fp=4, tp=0, nmi=1, override_fp=2)
    assert is_noisy is True
    assert rec == "mute"
    assert "analyst FP-overrides" in reason


def test_assess_override_fp_below_signal_is_unchanged() -> None:
    # A single override (below OVERRIDE_FP_SIGNAL) does not change assess's lean —
    # nominate() surfaces the rule + notes the single override, but assess is coarse.
    assert dt.assess(50, 4, 0, 1, override_fp=1) == dt.assess(50, 4, 0, 1)


def test_assess_tp_veto_wins_over_override_fp() -> None:
    # SAFETY: a rule that ever caught a real TP is never suppressed, even with
    # many analyst FP-overrides — the tp>0 veto wins.
    is_noisy, rec, reason = dt.assess(alert_count=999, fp=20, tp=1, nmi=0, override_fp=9)
    assert is_noisy is False
    assert rec == "none"
    assert "true positive" in reason


# ---------------------------------------------------------------------------
# override store: create / list_active / muted_rule_names / deactivate
# ---------------------------------------------------------------------------


async def test_override_create_and_list_active(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await override_svc.create(
            db, rule_name="ET NOISY RULE", reason="all FP", created_by="alice"
        )
        assert row.id is not None
        assert row.rule_name == "ET NOISY RULE"
        assert row.action == "mute"
        assert row.reason == "all FP"
        assert row.created_by == "alice"
        assert row.active is True

        active = await override_svc.list_active(db)
        assert [o.rule_name for o in active] == ["ET NOISY RULE"]
        assert await override_svc.muted_rule_names(db) == {"ET NOISY RULE"}
    await engine.dispose()


async def test_override_deactivate_unmutes(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await override_svc.create(db, rule_name="ET X")
        assert await override_svc.muted_rule_names(db) == {"ET X"}

        assert await override_svc.deactivate(db, row.id) is True
        # gone from the active set + the mute set; row kept for audit
        assert await override_svc.list_active(db) == []
        assert await override_svc.muted_rule_names(db) == set()

        # idempotent: a second deactivate (already inactive) is False
        assert await override_svc.deactivate(db, row.id) is False
        # missing id is False
        assert await override_svc.deactivate(db, 9999) is False
    await engine.dispose()


async def test_override_reason_optional(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await override_svc.create(db, rule_name="ET Y")
        assert row.reason is None
        assert row.created_by == "anonymous"
    await engine.dispose()


# ---------------------------------------------------------------------------
# verdict_counts_by_rule
# ---------------------------------------------------------------------------


async def _complete(db: AsyncSession, *, rule_name: str, verdict: str, alert_es_id: str) -> None:
    inv = await inv_svc.create(db, alert_es_id=alert_es_id, started_by="t", rule_name=rule_name)
    await inv_svc.finalize(db, inv.id, status="complete", verdict=verdict, confidence=0.9)


async def test_verdict_counts_by_rule_tallies(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _complete(db, rule_name="ET NOISE", verdict="false_positive", alert_es_id="a1")
        await _complete(db, rule_name="ET NOISE", verdict="false_positive", alert_es_id="a2")
        await _complete(db, rule_name="ET NOISE", verdict="needs_more_info", alert_es_id="a3")
        await _complete(db, rule_name="ET REAL", verdict="true_positive", alert_es_id="b1")
        # a still-running investigation must NOT be counted
        await inv_svc.create(db, alert_es_id="c1", started_by="t", rule_name="ET NOISE")

        counts = await inv_svc.verdict_counts_by_rule(db, ["ET NOISE", "ET REAL", "ET ABSENT"])
    assert counts["ET NOISE"] == {
        "true_positive": 0,
        "false_positive": 2,
        "needs_more_info": 1,
        "total": 3,
    }
    assert counts["ET REAL"]["true_positive"] == 1
    assert counts["ET REAL"]["total"] == 1
    assert "ET ABSENT" not in counts  # no completed investigations
    await engine.dispose()


async def test_verdict_counts_by_rule_empty(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.verdict_counts_by_rule(db, []) == {}
    await engine.dispose()


# ---------------------------------------------------------------------------
# nominate() — the join of volume + verdict trend
# ---------------------------------------------------------------------------


async def test_nominate_joins_volume_and_verdicts(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # ET NOISE: high volume, all FP -> mute candidate
        for i in range(8):
            await _complete(db, rule_name="ET NOISE", verdict="false_positive", alert_es_id=f"n{i}")
        # ET REAL: caught a TP -> never nominated
        await _complete(db, rule_name="ET REAL", verdict="true_positive", alert_es_id="r1")
        # ET NOISE is already muted by an operator
        await override_svc.create(db, rule_name="ET MUTED", reason="x")

    groups = [
        AlertGroup(rule_name="ET NOISE", count=412, severity="high", latest_ts="", latest_id="x"),
        AlertGroup(rule_name="ET REAL", count=999, severity="high", latest_ts="", latest_id="y"),
        AlertGroup(rule_name="ET QUIET", count=2, severity="low", latest_ts="", latest_id="z"),
        AlertGroup(rule_name="ET MUTED", count=50, severity="low", latest_ts="", latest_id="m"),
    ]
    state = SimpleNamespace(settings=settings_kratos, elastic=AsyncMock(), db_sessionmaker=maker)
    with patch(
        "soc_ai.webui.detection_tuning.aq.fetch_groups",
        AsyncMock(return_value=(groups, 1463)),
    ):
        noms = await dt.nominate(state)

    by_name = {n["rule_name"]: n for n in noms}
    # ET NOISE: nominated, mute
    assert by_name["ET NOISE"]["recommendation"] == "mute"
    assert by_name["ET NOISE"]["fp"] == 8
    assert by_name["ET NOISE"]["tp"] == 0
    assert by_name["ET NOISE"]["already_muted"] is False
    # ET REAL: has a TP -> not nominated
    assert "ET REAL" not in by_name
    # ET QUIET: below volume floor, never investigated -> not nominated
    assert "ET QUIET" not in by_name
    # ET MUTED: surfaced because it is already muted (so the operator can keep it)
    assert by_name["ET MUTED"]["already_muted"] is True
    # sorted by alert_count desc
    counts = [n["alert_count"] for n in noms]
    assert counts == sorted(counts, reverse=True)
    await engine.dispose()


async def _resolve(db: AsyncSession, inv_id: str, *, verdict: str, resolved_via: str) -> None:
    await inv_svc.resolve(
        db,
        inv_id,
        verdict=verdict,
        confidence=1.0,
        rationale="analyst",
        recommended_actions=None,
        resolved_by="alice",
        resolved_via=resolved_via,
    )


async def test_nominate_surfaces_analyst_overrides(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # ET FEEDBACK: moderate volume, thin AI-FP trend, but the analyst has
        # overridden it to FP twice (once chat, once manual) — the human feedback
        # should drive a nomination the AI trend alone would not.
        i1 = await inv_svc.create(db, alert_es_id="fb1", started_by="t", rule_name="ET FEEDBACK")
        await inv_svc.finalize(db, i1.id, status="complete", verdict="needs_more_info")
        await _resolve(db, i1.id, verdict="false_positive", resolved_via="manual")
        i2 = await inv_svc.create(db, alert_es_id="fb2", started_by="t", rule_name="ET FEEDBACK")
        await inv_svc.finalize(db, i2.id, status="complete", verdict="needs_more_info")
        await _resolve(db, i2.id, verdict="false_positive", resolved_via="chat")
        # ET PLAIN: high volume, all AI-FP, no analyst overrides — behaves as before.
        for i in range(8):
            await _complete(db, rule_name="ET PLAIN", verdict="false_positive", alert_es_id=f"p{i}")

    groups = [
        AlertGroup(rule_name="ET PLAIN", count=412, severity="high", latest_ts="", latest_id="x"),
        AlertGroup(rule_name="ET FEEDBACK", count=40, severity="low", latest_ts="", latest_id="f"),
    ]
    state = SimpleNamespace(settings=settings_kratos, elastic=AsyncMock(), db_sessionmaker=maker)
    with patch(
        "soc_ai.webui.detection_tuning.aq.fetch_groups",
        AsyncMock(return_value=(groups, 452)),
    ):
        noms = await dt.nominate(state)

    by_name = {n["rule_name"]: n for n in noms}
    # ET FEEDBACK: nominated purely on the analyst-override signal; the feedback
    # fields + a reason naming it are surfaced.
    fb = by_name["ET FEEDBACK"]
    assert fb["override_fp"] == 2
    assert fb["chat_resolved"] == 1
    assert fb["manual_resolved"] == 1
    assert fb["recommendation"] in ("mute", "monitor")
    assert "analyst FP-override" in fb["reason"]
    # ET PLAIN: unchanged AI-only behavior; no analyst feedback.
    plain = by_name["ET PLAIN"]
    assert plain["recommendation"] == "mute"
    assert plain["override_fp"] == 0
    assert plain["chat_resolved"] == 0
    assert plain["manual_resolved"] == 0
    await engine.dispose()


async def test_nominate_empty_feed(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    state = SimpleNamespace(settings=settings_kratos, elastic=AsyncMock(), db_sessionmaker=maker)
    with patch("soc_ai.webui.detection_tuning.aq.fetch_groups", AsyncMock(return_value=([], 0))):
        assert await dt.nominate(state) == []
    await engine.dispose()


# ---------------------------------------------------------------------------
# Endpoints: GET /detection-tuning, POST override, POST override/{id}/remove
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


def test_get_detection_tuning_returns_nominations_and_overrides(client: TestClient) -> None:
    noms = [
        {
            "rule_name": "ET NOISE",
            "alert_count": 412,
            "investigations": 8,
            "fp": 8,
            "tp": 0,
            "nmi": 0,
            "recommendation": "mute",
            "reason": "fired 412×, investigated 8× — all false positive (8 FP / 0 NMI), 0 TP",
            "already_muted": False,
        }
    ]
    with patch("soc_ai.webui.detection_tuning.nominate", AsyncMock(return_value=noms)):
        resp = client.get("/api/v1/detection-tuning")
    assert resp.status_code == 200
    body = resp.json()
    assert body["nominations"][0]["rule_name"] == "ET NOISE"
    assert body["nominations"][0]["recommendation"] == "mute"
    assert body["overrides"] == []


def test_post_override_then_remove_roundtrip(client: TestClient) -> None:
    # Create a mute via the endpoint.
    resp = client.post(
        "/api/v1/detection-tuning/override",
        json={"rule_name": "ET NOISE", "action": "mute", "reason": "all FP"},
    )
    assert resp.status_code == 200
    created = resp.json()
    assert created["rule_name"] == "ET NOISE"
    assert created["action"] == "mute"
    assert created["active"] is True
    assert created["created_by"] == "anonymous"  # identify_caller w/o a session
    override_id = created["id"]

    # It now shows up in the overrides list.
    with patch("soc_ai.webui.detection_tuning.nominate", AsyncMock(return_value=[])):
        listing = client.get("/api/v1/detection-tuning").json()
    assert [o["rule_name"] for o in listing["overrides"]] == ["ET NOISE"]

    # Remove it (un-mute).
    rm = client.post(f"/api/v1/detection-tuning/override/{override_id}/remove")
    assert rm.status_code == 200
    assert rm.json() == {"removed": True}

    # Removing again 404s (no active override).
    rm2 = client.post(f"/api/v1/detection-tuning/override/{override_id}/remove")
    assert rm2.status_code == 404


def test_post_override_rejects_non_mute_action(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/detection-tuning/override",
        json={"rule_name": "ET X", "action": "disable"},
    )
    assert resp.status_code == 400


def test_muted_rule_excluded_from_alerts_feed(client: TestClient) -> None:
    # Mute ET NOISE, then confirm the alerts feed drops it by default and shows
    # it (flagged) with ?include_muted=true.
    client.post(
        "/api/v1/detection-tuning/override",
        json={"rule_name": "ET NOISE", "action": "mute"},
    )
    groups = [
        AlertGroup(rule_name="ET NOISE", count=412, severity="high", latest_ts="", latest_id="x"),
        AlertGroup(rule_name="ET REAL", count=3, severity="high", latest_ts="", latest_id="y"),
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 415))),
        patch(
            "soc_ai.api.webui_api.inv_svc.latest_complete_for_rules",
            AsyncMock(return_value={}),
        ),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        default = client.get("/api/v1/alerts").json()
        with_muted = client.get("/api/v1/alerts?include_muted=true").json()

    # default feed: ET NOISE suppressed
    assert {g["name"] for g in default} == {"ET REAL"}
    # include_muted: ET NOISE present and flagged
    by_name = {g["name"]: g for g in with_muted}
    assert by_name["ET NOISE"]["muted"] is True
    assert by_name["ET REAL"]["muted"] is False
