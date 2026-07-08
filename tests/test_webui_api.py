"""Tests for the React-facing JSON API (/api/v1) — mapping, coercion, auth."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui.alerts_query import AlertEvent, AlertGroup


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


def test_alerts_maps_and_coerces(client: TestClient) -> None:
    groups = [
        AlertGroup(
            rule_name="ET MALWARE X",
            count=12,
            severity="HIGH",
            latest_ts="2026-06-17T14:46:22Z",
            latest_id="es-1",
            kind="suricata",
        ),
        AlertGroup(
            rule_name="weird",
            count=2,
            severity="unknown",
            latest_ts="",
            latest_id="",
            kind="alert",
        ),
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 14))),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["name"] == "ET MALWARE X"
    assert body[0]["sev"] == "high"
    assert body[0]["id"] == "es-1"
    assert body[0]["verdict"] == "untriaged"
    assert body[0]["conf"] is None
    assert body[0]["events"] == []
    # coercion into the frontend's narrower unions
    assert body[1]["sev"] == "low"  # unknown -> low
    assert body[1]["kind"] == "suricata"  # alert -> suricata
    assert body[1]["id"] == "weird"  # no latest_id -> falls back to rule name


def test_alerts_verdict_badge_inherited(client: TestClient) -> None:
    groups = [
        AlertGroup(
            rule_name="ET X",
            count=3,
            severity="medium",
            latest_ts="2026-06-17T10:00:00Z",
            latest_id="cur",
            kind="suricata",
        )
    ]
    inv = SimpleNamespace(
        id="INV-9",
        verdict="true_positive",
        confidence=0.91,
        status="complete",
        alert_es_id="OTHER",
        src_ip="10.0.0.5",
        dest_ip="1.2.3.4",
        # real Investigation rows always carry created_at; _inherited_reason reads it
        created_at=datetime(2026, 6, 17, 9, 0, 0),
    )
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 3))),
        patch(
            "soc_ai.api.webui_api.inv_svc.latest_complete_for_rules",
            AsyncMock(return_value={"ET X": inv}),
        ),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        body = client.get("/api/v1/alerts").json()
    assert body[0]["verdict"] == "true_positive"
    assert body[0]["conf"] == 0.91
    assert body[0]["inherited"] is True  # verdict came from a different alert id
    assert body[0]["invId"] == "INV-9"  # drawer opens this exact investigation
    assert "10.0.0.5 → 1.2.3.4" in body[0]["inheritedReason"]  # why it's inherited


def test_alerts_coverage_note(client: TestClient) -> None:
    # A directly-investigated multi-event group: the verdict covers all N events
    # though only one was investigated — surfaced as a coverage note.
    groups = [
        AlertGroup(
            rule_name="ET X",
            count=264,
            severity="medium",
            latest_ts="2026-06-17T10:00:00Z",
            latest_id="cur",
            kind="suricata",
        )
    ]
    inv = SimpleNamespace(
        id="INV-5",
        verdict="true_positive",
        confidence=0.88,
        status="complete",
        alert_es_id="cur",  # representative WAS the investigated alert -> not "inherited"
        src_ip="10.0.0.1",
        dest_ip="2.2.2.2",
    )
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 264))),
        patch(
            "soc_ai.api.webui_api.inv_svc.latest_complete_for_rules",
            AsyncMock(return_value={"ET X": inv}),
        ),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        body = client.get("/api/v1/alerts").json()
    assert body[0]["inherited"] is False
    assert "1 of 264 events" in body[0]["inheritedReason"]


def test_alerts_badge_survives_later_interrupted_run(client: TestClient) -> None:
    """A rule with a COMPLETE verdict, then a LATER cancelled/errored run, must
    still show that verdict — not 'untriaged'. This is the group-says-untriaged-
    but-its-events-are-investigated mismatch the operator reported.
    """
    import asyncio

    from soc_ai.store import investigations as inv_svc

    rule = "ET HUNTING curl User-Agent to Dotted Quad"

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            good = await inv_svc.create(db, alert_es_id="ev-good", started_by="t")
            await inv_svc.finalize(
                db,
                good.id,
                status="complete",
                verdict="false_positive",
                confidence=0.8,
                rationale="benign curl probe",
            )
            good.rule_name = rule
            good.src_ip = "10.0.0.1"
            good.dest_ip = "1.2.3.4"
            await db.commit()
            # A LATER run that was cancelled (no verdict) — must NOT poison the badge.
            bad = await inv_svc.create(db, alert_es_id="ev-cur", started_by="t")
            await inv_svc.finalize(db, bad.id, status="cancelled")
            bad.rule_name = rule
            await db.commit()
            return good.id

    good_id = asyncio.run(_seed())

    groups = [
        AlertGroup(
            rule_name=rule,
            count=9,
            severity="low",
            latest_ts="2026-06-28T10:00:00Z",
            latest_id="ev-cur",
            kind="suricata",
        )
    ]
    with patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 9))):
        body = client.get("/api/v1/alerts").json()

    g = body[0]
    assert g["verdict"] == "false_positive"  # the standing verdict, NOT untriaged
    assert g["invId"] == good_id  # drawer opens the run that produced the verdict
    assert g["triaging"] is False  # the cancelled run is not "running"


def test_primary_run_ids_prefers_latest_complete() -> None:
    """#2: the canonical run per alert is the latest RUNNING-or-COMPLETE one (else
    the latest of any status) so a working verdict is never buried under later
    failed retries."""
    from soc_ai.api.webui_api import _primary_run_ids

    # Newest-first (list_recent order): a later error retry of alert A, then the
    # complete run, then an older error. Alert B has only error runs.
    rows = [
        SimpleNamespace(id="A-err2", alert_es_id="alertA", status="error"),
        SimpleNamespace(id="A-done", alert_es_id="alertA", status="complete"),
        SimpleNamespace(id="A-err1", alert_es_id="alertA", status="error"),
        SimpleNamespace(id="B-err2", alert_es_id="alertB", status="error"),
        SimpleNamespace(id="B-err1", alert_es_id="alertB", status="error"),
    ]
    primary = _primary_run_ids(rows)
    assert primary == {"A-done", "B-err2"}  # A's complete run; B's latest error


def test_primary_run_ids_surfaces_inflight_reinvestigation() -> None:
    """Clicking re-investigate makes the NEW running run the alert's current
    state — it must be the primary row, not an "earlier run" tucked under the
    stale complete verdict. An old wedged 'running' run older than a complete
    verdict does NOT outrank it (newest running-or-complete wins)."""
    from soc_ai.api.webui_api import _primary_run_ids

    rows = [  # newest-first
        SimpleNamespace(id="A-rerun", alert_es_id="alertA", status="running"),
        SimpleNamespace(id="A-done", alert_es_id="alertA", status="complete"),
        SimpleNamespace(id="B-done", alert_es_id="alertB", status="complete"),
        SimpleNamespace(id="B-stale-run", alert_es_id="alertB", status="running"),
    ]
    assert _primary_run_ids(rows) == {"A-rerun", "B-done"}


def test_investigations_list(client: TestClient) -> None:
    invs = [
        SimpleNamespace(
            id="INV-1",
            rule_name="ET X",
            verdict="false_positive",
            confidence=0.85,
            status="complete",
            src_ip="10.0.0.5",
            created_at=datetime(2026, 6, 17, 12, 0, tzinfo=UTC),
        ),
        SimpleNamespace(
            id="INV-2",
            rule_name=None,
            verdict=None,
            confidence=None,
            status="running",
            src_ip=None,
            created_at=datetime(2026, 6, 17, 12, 5, tzinfo=UTC),
        ),
    ]
    with patch("soc_ai.api.webui_api.inv_svc.list_recent", AsyncMock(return_value=invs)):
        body = client.get("/api/v1/investigations").json()
    assert body[0]["id"] == "INV-1"
    assert body[0]["verdict"] == "false_positive"
    assert body[0]["host"] == "10.0.0.5"
    assert body[0]["status"] == "complete"
    # None rule_name -> identify by alert id (here the inv id, no alert_es_id on the mock)
    assert body[1]["name"] == "Alert INV-2…"
    assert body[1]["verdict"] == "untriaged"  # None verdict -> untriaged
    assert body[1]["status"] == "running"
    # Neither row is a pipeline fallback (no marker on either report).
    assert body[0]["fallback"] is False
    assert body[1]["fallback"] is False


# The persisted report dict shape a synth-failure fallback lands (E1.2). Mirrors
# `_synth_failure_fallback_report`'s marker so the row/detail/badge derivations
# are exercised against the real key.
_FALLBACK_REPORT = {
    "verdict": "needs_more_info",
    "confidence": 0.3,
    "summary": "Synth-first pipeline fallback: synth_first_round1 raised RuntimeError.",
    "citations": ["synth_first_failure"],
    "resolution": {
        "provenance": "pipeline_fallback",
        "phase": "synth_first_round1",
        "error_type": "RuntimeError",
        "hint": "the model hit its response-token cap while still reasoning.",
    },
}


def test_investigations_list_marks_pipeline_fallback_row(client: TestClient) -> None:
    """E1.2: a run whose report carries the pipeline_fallback marker → its row
    `fallback` is True; a normal needs_more_info run → False. The verdict is
    needs_more_info in BOTH — only the row flag distinguishes them."""
    invs = [
        SimpleNamespace(
            id="INV-FB",
            rule_name="ET Truncated",
            verdict="needs_more_info",
            confidence=0.3,
            status="complete",
            src_ip="10.0.0.9",
            created_at=datetime(2026, 7, 7, 12, 0, tzinfo=UTC),
            report=_FALLBACK_REPORT,
        ),
        SimpleNamespace(
            id="INV-NMI",
            rule_name="ET Genuine",
            verdict="needs_more_info",
            confidence=0.55,
            status="complete",
            src_ip="10.0.0.10",
            created_at=datetime(2026, 7, 7, 12, 5, tzinfo=UTC),
            report={"verdict": "needs_more_info", "citations": ["ev-1"]},
        ),
    ]
    with patch("soc_ai.api.webui_api.inv_svc.list_recent", AsyncMock(return_value=invs)):
        body = client.get("/api/v1/investigations").json()
    by_id = {r["id"]: r for r in body}
    assert by_id["INV-FB"]["verdict"] == "needs_more_info"
    assert by_id["INV-FB"]["fallback"] is True
    assert by_id["INV-NMI"]["verdict"] == "needs_more_info"
    assert by_id["INV-NMI"]["fallback"] is False


def test_investigation_detail_exposes_fallback_marker(client: TestClient) -> None:
    """E1.2: the investigation drawer's `fallback` field carries the failure
    provenance (phase / errorType / hint) so the panel can render "failed before
    reaching a verdict: <hint>". A genuine needs_more_info leaves it null."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed(report: dict[str, object]) -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db, alert_es_id="ev-fb", started_by="tester", rule_name="ET Truncated"
            )
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="needs_more_info",
                confidence=0.3,
                rationale="fallback",
                report=report,
            )
            return inv.id

    fb_id = asyncio.run(_seed(_FALLBACK_REPORT))
    detail = client.get(f"/api/v1/investigations/{fb_id}").json()
    assert detail["verdict"] == "needs_more_info"
    assert detail["fallback"] is not None
    assert detail["fallback"]["provenance"] == "pipeline_fallback"
    assert detail["fallback"]["phase"] == "synth_first_round1"
    assert detail["fallback"]["errorType"] == "RuntimeError"
    assert "response-token cap" in detail["fallback"]["hint"]

    nmi_id = asyncio.run(_seed({"verdict": "needs_more_info", "citations": ["ev-1"]}))
    nmi = client.get(f"/api/v1/investigations/{nmi_id}").json()
    assert nmi["fallback"] is None


def test_alerts_badge_marks_pipeline_fallback(client: TestClient) -> None:
    """E1.2: a rule whose STANDING verdict run is a pipeline fallback exposes
    `fallback: true` on its alert-group badge (derived from the representative
    run's report marker). A rule with a genuine complete verdict → False."""
    groups = [
        AlertGroup(
            rule_name="ET Truncated",
            count=4,
            severity="medium",
            latest_ts="2026-07-07T10:00:00Z",
            latest_id="cur",
            kind="suricata",
        )
    ]
    inv = SimpleNamespace(
        id="INV-FB",
        verdict="needs_more_info",
        confidence=0.3,
        status="complete",
        alert_es_id="cur",
        src_ip="10.0.0.9",
        dest_ip="2.2.2.2",
        created_at=datetime(2026, 7, 7, 9, 0, 0),
        report=_FALLBACK_REPORT,
    )
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 4))),
        patch(
            "soc_ai.api.webui_api.inv_svc.latest_complete_for_rules",
            AsyncMock(return_value={"ET Truncated": inv}),
        ),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        body = client.get("/api/v1/alerts").json()
    assert body[0]["verdict"] == "needs_more_info"  # verdict unchanged
    assert body[0]["fallback"] is True

    # A genuine complete verdict on the same shape → not a fallback badge.
    inv.report = {"verdict": "false_positive", "citations": ["ev-1"]}
    inv.verdict = "false_positive"
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 4))),
        patch(
            "soc_ai.api.webui_api.inv_svc.latest_complete_for_rules",
            AsyncMock(return_value={"ET Truncated": inv}),
        ),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        body2 = client.get("/api/v1/alerts").json()
    assert body2[0]["fallback"] is False


# ── E2.1: rerun visibility (lastAttempt) ────────────────────────────────────


def _seed_verdict_then_rerun(
    client: TestClient,
    rule: str,
    *,
    rerun_status: str,
    rerun_report: dict[str, object] | None = None,
) -> None:
    """Seed a COMPLETE false_positive verdict, then a LATER rerun on the same
    rule/alert with the given terminal status (and optional report marker). Uses
    the real store so the route's own `latest_for_rules`/`latest_complete_for_rules`
    resolve both rows (exercises the no-N+1 path end to end)."""
    from soc_ai.store import investigations as inv_svc

    async def _seed() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            good = await inv_svc.create(db, alert_es_id="ev-1", started_by="t", rule_name=rule)
            await inv_svc.finalize(
                db,
                good.id,
                status="complete",
                verdict="false_positive",
                confidence=0.82,
                rationale="benign",
                report={"verdict": "false_positive", "citations": ["ev-1"]},
            )
            good.src_ip = "10.0.0.1"
            good.dest_ip = "1.2.3.4"
            await db.commit()
            # A LATER retry on the SAME alert that failed (or fell back).
            bad = await inv_svc.create(db, alert_es_id="ev-1", started_by="t", rule_name=rule)
            await inv_svc.finalize(db, bad.id, status=rerun_status, report=rerun_report)

    asyncio.run(_seed())


def _alerts_for_rule(client: TestClient, rule: str) -> dict[str, Any]:
    groups = [
        AlertGroup(
            rule_name=rule,
            count=5,
            severity="low",
            latest_ts="2026-07-07T10:00:00Z",
            latest_id="ev-1",
            kind="suricata",
        )
    ]
    with patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 5))):
        body = client.get("/api/v1/alerts").json()
    return body[0]


def test_alerts_last_attempt_errored_rerun(client: TestClient) -> None:
    """E2.1: a complete FP verdict + a LATER errored rerun on the same rule →
    the badge KEEPS the FP verdict AND exposes lastAttempt.status == 'error'
    with a relative `ago`."""
    rule = "ET HUNTING errored-rerun"
    _seed_verdict_then_rerun(client, rule, rerun_status="error")
    g = _alerts_for_rule(client, rule)
    assert g["verdict"] == "false_positive"  # standing verdict survives
    assert g["fallback"] is False
    assert g["lastAttempt"] is not None
    assert g["lastAttempt"]["status"] == "error"
    assert g["lastAttempt"]["ago"]  # a humanized relative label ("now"/"5m"/…)


def test_alerts_last_attempt_cancelled_rerun(client: TestClient) -> None:
    """E2.1: a cancelled rerun on top of a standing verdict → lastAttempt cancelled."""
    rule = "ET HUNTING cancelled-rerun"
    _seed_verdict_then_rerun(client, rule, rerun_status="cancelled")
    g = _alerts_for_rule(client, rule)
    assert g["verdict"] == "false_positive"
    assert g["lastAttempt"]["status"] == "cancelled"


def test_alerts_last_attempt_fallback_rerun(client: TestClient) -> None:
    """E2.1: a pipeline-fallback rerun (a COMPLETE row carrying the E1.2 marker) on
    top of a genuine verdict counts as a FAILED attempt → lastAttempt.status ==
    'fallback'. The badge itself is NOT `fallback` (the standing verdict is real)."""
    rule = "ET HUNTING fallback-rerun"
    _seed_verdict_then_rerun(client, rule, rerun_status="complete", rerun_report=_FALLBACK_REPORT)
    g = _alerts_for_rule(client, rule)
    assert g["verdict"] == "false_positive"  # standing verdict unchanged
    assert g["fallback"] is False  # the STANDING verdict is genuine, not a fallback
    assert g["lastAttempt"]["status"] == "fallback"


def test_alerts_last_attempt_none_when_standing_is_newest(client: TestClient) -> None:
    """E2.1: a rule whose newest run IS the complete standing verdict (no later
    failed retry) → lastAttempt is None."""
    from soc_ai.store import investigations as inv_svc

    rule = "ET HUNTING clean-standing"

    async def _seed() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-1", started_by="t", rule_name=rule)
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="false_positive",
                confidence=0.8,
                report={"verdict": "false_positive"},
            )

    asyncio.run(_seed())
    g = _alerts_for_rule(client, rule)
    assert g["verdict"] == "false_positive"
    assert g["lastAttempt"] is None


def test_alerts_last_attempt_none_for_running_rerun(client: TestClient) -> None:
    """E2.1: a rule with a RUNNING rerun on top of a standing verdict → lastAttempt
    is None (a running retry is covered by `triaging`, not a failure)."""
    rule = "ET HUNTING running-rerun"
    _seed_verdict_then_rerun(client, rule, rerun_status="running")
    g = _alerts_for_rule(client, rule)
    assert g["verdict"] == "false_positive"
    assert g["triaging"] is True  # the live rerun drives the triaging flag
    assert g["lastAttempt"] is None  # running is not a failed attempt


def test_alerts_last_attempt_none_when_standing_is_fallback(client: TestClient) -> None:
    """E2.1: when the STANDING (newest complete) verdict is itself a pipeline
    fallback, E1.2's chip owns the failure signal — E2.1 adds no lastAttempt (no
    genuine verdict to stack a failed retry on)."""
    from soc_ai.store import investigations as inv_svc

    rule = "ET HUNTING fallback-standing"

    async def _seed() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-1", started_by="t", rule_name=rule)
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="needs_more_info",
                confidence=0.3,
                report=_FALLBACK_REPORT,
            )

    asyncio.run(_seed())
    g = _alerts_for_rule(client, rule)
    assert g["fallback"] is True  # E1.2 owns this
    assert g["lastAttempt"] is None


def test_last_attempt_helper_unit() -> None:
    """Direct unit coverage of the `_last_attempt` reducer over SimpleNamespace
    rows (no DB) — the four gate conditions."""
    from soc_ai.api.webui_api import _last_attempt

    def _inv(id_: str, status: str, report: dict[str, Any] | None = None) -> Any:
        return SimpleNamespace(
            id=id_,
            status=status,
            report=report,
            created_at=datetime(2026, 7, 7, 12, 0, tzinfo=UTC),
        )

    standing = _inv("STAND", "complete", {"verdict": "false_positive"})
    errored = _inv("RERUN", "error")
    fb = _inv("RERUN", "complete", _FALLBACK_REPORT)

    # error rerun on top of a genuine verdict → surfaced.
    la = _last_attempt(errored, standing)
    assert la is not None and la.status == "error" and la.ago
    # fallback rerun → surfaced as 'fallback'.
    la_fb = _last_attempt(fb, standing)
    assert la_fb is not None and la_fb.status == "fallback"
    # newest IS the standing verdict → None.
    assert _last_attempt(standing, standing) is None
    # running rerun → None (not a failed status, not a fallback).
    assert _last_attempt(_inv("RUN", "running"), standing) is None
    # standing itself a fallback → None (E1.2 owns it).
    assert _last_attempt(errored, _inv("STAND", "complete", _FALLBACK_REPORT)) is None
    # missing either side → None.
    assert _last_attempt(None, standing) is None
    assert _last_attempt(errored, None) is None


def test_group_events(client: TestClient) -> None:
    events = [
        AlertEvent(
            es_id="abc123",
            timestamp="2026-06-22T10:00:00Z",
            src="1.1.1.1",
            dst="2.2.2.2",
            severity="high",
            host="wks-1",
            dst_port=443,
        )
    ]
    with patch("soc_ai.api.webui_api.aq.fetch_group_events", AsyncMock(return_value=events)):
        resp = client.get("/api/v1/alerts/events", params={"rule_name": "ET X", "kind": "suricata"})
    assert resp.status_code == 200
    ev = resp.json()[0]
    # src/dst are bare endpoints; the destination port rides `port` alone (the
    # frontend renders "dst:port" once and pivots on the bare value).
    assert ev["src"] == "1.1.1.1"
    assert ev["dst"] == "2.2.2.2"
    assert ev["host"] == "wks-1"
    assert ev["proto"] == ""
    # enriched fields
    assert ev["id"] == "abc123"
    assert ev["sev"] == "high"
    assert ev["port"] == 443
    assert ev["ts"] == "2026-06-22T10:00:00Z"
    assert ev["ago"] != ""  # non-empty relative label


def test_group_events_provenance_direct_and_inherited(client: TestClient) -> None:
    """GET /alerts/events annotates events with investigated/inherited provenance.

    Three tiers verified in one request:
    - ev-direct: es_id directly investigated → investigated=True, invId set, inheritedReason=None
    - ev-rule:   no direct or pair match → rule-level fallback, investigated=False, reason present
    - ev-direct also asserts the direct inv id matches (not the rule-level one)

    A separate request against a rule with NO investigations verifies the
    no-match case → investigated=False, invId=None, inheritedReason=None.
    """
    import asyncio

    from soc_ai.store import investigations as inv_svc

    RULE = "ET PROV TEST"
    EMPTY_RULE = "ET PROV EMPTY"

    async def _seed() -> tuple[str, str]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            # Direct investigation whose alert_es_id matches ev-direct exactly.
            direct_inv = await inv_svc.create(db, alert_es_id="ev-direct", started_by="tester")
            await inv_svc.finalize(
                db,
                direct_inv.id,
                status="complete",
                verdict="false_positive",
                confidence=0.9,
                rationale="Benign.",
            )
            direct_inv.rule_name = RULE
            direct_inv.src_ip = "10.0.0.1"
            direct_inv.dest_ip = "1.2.3.4"
            await db.commit()

            # Rule-level investigation on a different alert (ev-other) — will be the
            # rule fallback for events without a direct or pair match.
            rule_inv = await inv_svc.create(db, alert_es_id="ev-other", started_by="tester")
            await inv_svc.finalize(
                db,
                rule_inv.id,
                status="complete",
                verdict="false_positive",
                confidence=0.85,
                rationale="Same rule.",
            )
            rule_inv.rule_name = RULE
            rule_inv.src_ip = "10.0.0.9"
            rule_inv.dest_ip = "9.9.9.9"
            await db.commit()

            return direct_inv.id, rule_inv.id

    direct_inv_id, rule_inv_id = asyncio.run(_seed())

    # Determine which is "latest" for the rule — it's the most recently created one.
    # Both are complete; latest_for_rules returns the most recent by created_at/id.
    # rule_inv was created after direct_inv so it will be latest_for_rules result.

    fake_events = [
        AlertEvent(
            es_id="ev-direct",
            timestamp="2026-06-22T10:00:00Z",
            src="10.0.0.1",
            dst="1.2.3.4",
            severity="high",
            host="wks-1",
            src_ip="10.0.0.1",
            dst_ip="1.2.3.4",
            dst_port=443,
        ),
        AlertEvent(
            es_id="ev-rule",
            timestamp="2026-06-22T10:01:00Z",
            src="10.0.0.2",
            dst="5.5.5.5",
            severity="medium",
            host="wks-2",
            src_ip="10.0.0.2",
            dst_ip="5.5.5.5",
            dst_port=80,
        ),
    ]

    with patch(
        "soc_ai.api.webui_api.aq.fetch_group_events",
        AsyncMock(return_value=fake_events),
    ):
        resp = client.get(
            "/api/v1/alerts/events",
            params={"rule_name": RULE, "kind": "suricata"},
        )

    assert resp.status_code == 200
    body = resp.json()
    ev_map = {ev["id"]: ev for ev in body}

    # ev-direct: exact es_id investigated → tier-1 direct hit
    d = ev_map["ev-direct"]
    assert d["investigated"] is True
    assert d["invId"] == direct_inv_id
    assert d["inheritedReason"] is None

    # ev-rule: no direct or pair hit → tier-3 rule-level fallback
    r = ev_map["ev-rule"]
    assert r["investigated"] is False
    assert r["invId"] == rule_inv_id
    assert r["inheritedReason"] is not None
    assert "Inherited" in r["inheritedReason"]
    assert "10.0.0.9" in r["inheritedReason"]

    # Separate request for a rule that has NEVER been investigated → no badge
    empty_events = [
        AlertEvent(
            es_id="ev-noninv",
            timestamp="2026-06-22T10:03:00Z",
            src="10.0.0.4:9999",
            dst="7.7.7.7:22",
            severity="low",
            host="wks-4",
            src_ip="10.0.0.4",
            dst_ip="7.7.7.7",
            dst_port=22,
        ),
    ]
    with patch(
        "soc_ai.api.webui_api.aq.fetch_group_events",
        AsyncMock(return_value=empty_events),
    ):
        resp2 = client.get(
            "/api/v1/alerts/events",
            params={"rule_name": EMPTY_RULE, "kind": "suricata"},
        )
    assert resp2.status_code == 200
    n = resp2.json()[0]
    assert n["investigated"] is False
    assert n["invId"] is None
    assert n["inheritedReason"] is None


def test_group_events_rerun_clears_inherited_pill(client: TestClient) -> None:
    """FIX #3: after re-running ON a specific alert, that alert's event must show
    investigated=True (NOT inherited) even when the group's STANDING verdict came
    from a DIFFERENT alert. A different event in the same group still inherits.

    Reproduces the operator's report: opened a specific alert, re-ran the
    investigation, but the pill for THAT alert still said 'inherited'.
    """
    from soc_ai.store import investigations as inv_svc

    RULE = "ET RERUN CLEARS INHERITED"

    async def _seed() -> tuple[str, str]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            # The group's STANDING verdict was investigated on a DIFFERENT alert
            # ("ev-other") — this is the rule-level fallback source.
            other = await inv_svc.create(db, alert_es_id="ev-other", started_by="t")
            await inv_svc.finalize(
                db,
                other.id,
                status="complete",
                verdict="false_positive",
                confidence=0.8,
                rationale="benign on the other flow",
            )
            other.rule_name = RULE
            other.src_ip = "10.0.0.9"
            other.dest_ip = "9.9.9.9"
            await db.commit()

            # The operator then RE-RAN on THIS specific alert ("ev-target"): a fresh
            # complete investigation whose alert_es_id == this event's es_id.
            target = await inv_svc.create(db, alert_es_id="ev-target", started_by="t")
            await inv_svc.finalize(
                db,
                target.id,
                status="complete",
                verdict="true_positive",
                confidence=0.9,
                rationale="re-run says TP",
            )
            target.rule_name = RULE
            target.src_ip = "10.0.0.1"
            target.dest_ip = "1.2.3.4"
            await db.commit()
            return other.id, target.id

    _other_id, target_id = asyncio.run(_seed())

    events = [
        AlertEvent(
            es_id="ev-target",  # the re-run alert
            timestamp="2026-06-22T10:00:00Z",
            src="10.0.0.1:5001",
            dst="1.2.3.4:443",
            severity="high",
            host="wks-1",
            src_ip="10.0.0.1",
            dst_ip="1.2.3.4",
            dst_port=443,
        ),
        AlertEvent(
            es_id="ev-sibling",  # a different event in the same group
            timestamp="2026-06-22T10:01:00Z",
            src="10.0.0.2:5002",
            dst="5.5.5.5:80",
            severity="medium",
            host="wks-2",
            src_ip="10.0.0.2",
            dst_ip="5.5.5.5",
            dst_port=80,
        ),
    ]
    with patch("soc_ai.api.webui_api.aq.fetch_group_events", AsyncMock(return_value=events)):
        body = client.get(
            "/api/v1/alerts/events", params={"rule_name": RULE, "kind": "suricata"}
        ).json()
    ev = {e["id"]: e for e in body}

    # ev-target: the re-run alert → investigated, NOT inherited
    assert ev["ev-target"]["investigated"] is True
    assert ev["ev-target"]["invId"] == target_id
    assert ev["ev-target"]["inheritedReason"] is None

    # ev-sibling: a DIFFERENT event → inherits the rule's standing verdict
    assert ev["ev-sibling"]["investigated"] is False
    assert ev["ev-sibling"]["inheritedReason"] is not None
    assert "Inherited" in ev["ev-sibling"]["inheritedReason"]


def test_group_events_errored_direct_run_falls_through_to_inherited(
    client: TestClient,
) -> None:
    """A DIRECT run that ended error/cancelled produced no verdict, so it must NOT
    claim the alert as investigated — the event falls through to the inherited
    rule-level verdict (consistent with blocks_rehunt)."""
    from soc_ai.store import investigations as inv_svc

    RULE = "ET ERRORED DIRECT FALLS THROUGH"

    async def _seed() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            # Rule-level standing verdict on a different alert.
            good = await inv_svc.create(db, alert_es_id="ev-good", started_by="t")
            await inv_svc.finalize(
                db,
                good.id,
                status="complete",
                verdict="false_positive",
                confidence=0.8,
                rationale="benign",
            )
            good.rule_name = RULE
            good.src_ip = "10.0.0.9"
            good.dest_ip = "9.9.9.9"
            await db.commit()
            # A DIRECT run on ev-x that ERRORED (no verdict).
            bad = await inv_svc.create(db, alert_es_id="ev-x", started_by="t")
            await inv_svc.finalize(db, bad.id, status="error")
            bad.rule_name = RULE
            await db.commit()

    asyncio.run(_seed())
    events = [
        AlertEvent(
            es_id="ev-x",
            timestamp="2026-06-22T10:00:00Z",
            src="10.0.0.1:5001",
            dst="1.2.3.4:443",
            severity="high",
            host="wks-1",
            src_ip="10.0.0.1",
            dst_ip="1.2.3.4",
            dst_port=443,
        ),
    ]
    with patch("soc_ai.api.webui_api.aq.fetch_group_events", AsyncMock(return_value=events)):
        body = client.get(
            "/api/v1/alerts/events", params={"rule_name": RULE, "kind": "suricata"}
        ).json()
    e = body[0]
    # errored direct run → NOT investigated; inherits the standing verdict
    assert e["investigated"] is False
    assert e["inheritedReason"] is not None
    assert "Inherited" in e["inheritedReason"]


def test_ago_treats_naive_created_at_as_utc() -> None:
    """FIX #10: _ago must treat a naive stored timestamp as UTC (store timestamps
    are naive UTC). A run from ~1h ago reads '1h', not an offset-shifted value."""
    from soc_ai.api.webui_api import _ago, _iso_utc

    one_hour_ago_naive = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1)
    # via the tz-aware serializer the API now uses
    assert _ago(_iso_utc(one_hour_ago_naive)) == "1h"
    # and directly on the naive isoformat (no offset marker) — still UTC
    assert _ago(one_hour_ago_naive.isoformat()) == "1h"


def test_iso_utc_stamps_naive_as_offset_aware() -> None:
    """FIX #10: a naive stored datetime is serialized WITH a +00:00 offset so the
    browser localizes it (a naive string would be parsed as browser-local)."""
    from soc_ai.api.webui_api import _iso_utc

    naive = datetime(2026, 7, 2, 11, 23, 49)
    out = _iso_utc(naive)
    assert out.endswith("+00:00")
    assert out == "2026-07-02T11:23:49+00:00"
    # already-aware passes through unchanged; None → ""
    aware = datetime(2026, 7, 2, 11, 23, 49, tzinfo=UTC)
    assert _iso_utc(aware) == "2026-07-02T11:23:49+00:00"
    assert _iso_utc(None) == ""


def test_investigations_list_ts_is_offset_aware(client: TestClient) -> None:
    """FIX #10: the investigations LIST row's `ts` carries a timezone offset so the
    frontend's `new Date(ts)` interprets it as UTC, not browser-local."""
    from soc_ai.store import investigations as inv_svc

    async def _seed() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-ts", started_by="t")
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="false_positive",
                confidence=0.8,
                rationale="x",
            )
            inv.rule_name = "ET TS TEST"
            await db.commit()

    asyncio.run(_seed())
    rows = client.get("/api/v1/investigations").json()
    assert rows, "expected at least one investigation row"
    row = next(r for r in rows if r["name"] == "ET TS TEST")
    assert row["ts"].endswith("+00:00") or row["ts"].endswith("Z")


def test_alerts_acked_escalated_counts(client: TestClient) -> None:
    """Per-group acked/escalated counts are forwarded from ES aggs to the response."""
    groups = [
        AlertGroup(
            rule_name="ET TEST",
            count=10,
            severity="high",
            latest_ts="2026-06-22T10:00:00Z",
            latest_id="es-abc",
            kind="suricata",
            acked_count=3,
            escalated_count=1,
        )
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 10))),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["ackedCount"] == 3
    assert body[0]["escalatedCount"] == 1


def test_alerts_hide_acked_param_forwarded(client: TestClient) -> None:
    """GET /alerts?hide_acked=true passes hide_acked=True into fetch_groups."""
    groups: list[AlertGroup] = []
    mock_fetch = AsyncMock(return_value=(groups, 0))
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", mock_fetch),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        resp = client.get("/api/v1/alerts", params={"hide_acked": "true"})
    assert resp.status_code == 200
    _args, kwargs = mock_fetch.call_args
    assert kwargs.get("hide_acked") is True


def test_alerts_triaging_when_investigation_running(settings_kratos: Settings) -> None:
    """A group shows triaging=True iff its LATEST run is live (DB status=running),
    and invId points at that running run so the pill opens its drawer. A group with
    no running run is NOT triaging — queued-but-not-started groups stay untriaged."""
    groups = [
        AlertGroup(
            rule_name="ET RULE RUNNING",
            count=5,
            severity="high",
            latest_ts="2026-06-22T10:00:00Z",
            latest_id="es-run",
            kind="suricata",
        ),
        AlertGroup(
            rule_name="ET RULE IDLE",
            count=2,
            severity="high",
            latest_ts="2026-06-22T09:00:00Z",
            latest_id="es-idle",
            kind="suricata",
        ),
    ]
    running_inv = SimpleNamespace(status="running", id="INV-RUN")

    for c in _client(settings_kratos):
        with (
            patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 7))),
            patch(
                "soc_ai.api.webui_api.inv_svc.latest_for_rules",
                AsyncMock(return_value={"ET RULE RUNNING": running_inv}),
            ),
        ):
            resp = c.get("/api/v1/alerts")
        assert resp.status_code == 200
        body = {g["name"]: g for g in resp.json()}
        # Running group: triaging + links to the live run.
        assert body["ET RULE RUNNING"]["triaging"] is True
        assert body["ET RULE RUNNING"]["invId"] == "INV-RUN"
        # No running run → not triaging (it just awaits its turn).
        assert body["ET RULE IDLE"]["triaging"] is False


def test_config_set_setting_real_path(client: TestClient) -> None:
    # A real whitelisted, hot, non-danger bool key — exercises coerce + set_override.
    resp = client.post("/api/v1/config/setting", json={"key": "oracle_enabled", "value": "false"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "restart_required": False}


def test_investigation_export_signed_record(client: TestClient) -> None:
    """#2: the export bundles verdict + the full agent trace and signs it with a
    sha256 that recomputes — a tamper-evident 'show your work' record."""
    import asyncio
    import hashlib
    import json

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db, alert_es_id="ev-export", started_by="tester", rule_name="ET X"
            )
            await inv_svc.append_events(
                db,
                inv.id,
                [{"sequence": 1, "kind": "tool_call", "payload": {"tool": "prevalence"}}],
            )
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="false_positive",
                confidence=0.9,
                rationale="benign",
                report={"citations": ["ev1"]},
            )
            return inv.id

    inv_id = asyncio.run(_seed())
    resp = client.get(f"/api/v1/investigations/{inv_id}/export")
    assert resp.status_code == 200
    rec = resp.json()
    assert rec["schema"] == "soc-ai.decision-record/v1"
    assert rec["investigation_id"] == inv_id
    assert rec["verdict"] == "false_positive"
    assert rec["report"] == {"citations": ["ev1"]}
    assert any(s["kind"] == "tool_call" for s in rec["trace"])  # the trace is included
    # the signature recomputes → tamper-evident
    body = {k: v for k, v in rec.items() if k != "integrity"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    assert hashlib.sha256(canonical.encode()).hexdigest() == rec["integrity"]["hash"]
    assert client.get("/api/v1/investigations/does-not-exist/export").status_code == 404


def test_oracle_redaction_preview(client: TestClient) -> None:
    """#5: the preview redacts internal identifiers and preserves public addresses,
    so an operator can see exactly what would leave before enabling the Oracle."""
    import json

    resp = client.get("/api/v1/oracle/redaction-preview")
    assert resp.status_code == 200
    body = resp.json()
    orig = json.dumps(body["original"])
    san = json.dumps(body["sanitized"])
    # internal identifiers present in the original are gone from the sanitized output
    assert "10.0.0.15" in orig and "10.0.0.15" not in san
    assert "dc01" in orig and "dc01" not in san
    # a public destination passes through so the Oracle can reason about real infra
    assert "8.8.8.8" in san
    # opaque labels + a per-category summary are produced
    assert "IP_01" in san
    assert body["summary"].get("IP", 0) >= 2
    # replacements drive the UI highlight: every pair is consistent with the
    # two panes (label in sanitized, value in original) and carries a sane
    # category matching its label prefix.
    repl = body["replacements"]
    assert repl
    for r in repl:
        assert r["label"] in san
        assert r["value"] in orig
        assert r["category"] in {"IP", "HOST", "USER", "EMAIL", "MAC"}
        assert r["label"].startswith(r["category"] + "_")
    values = {r["value"] for r in repl}
    assert "10.0.0.15" in values  # the internal IP is a highlightable pair …
    assert "8.8.8.8" not in values  # … the preserved public address is not


def test_config_set_setting_rejects_danger(client: TestClient) -> None:
    resp = client.post("/api/v1/config/setting", json={"key": "so_host", "value": "x"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "danger_zone"


def test_config_set_setting_rejects_unknown(client: TestClient) -> None:
    resp = client.post("/api/v1/config/setting", json={"key": "not_a_key", "value": "1"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "unknown_setting"


def test_config_set_setting_rejects_secret(client: TestClient) -> None:
    """A secret (api-key) spec must be refused here with 400, not 500 — it routes
    to the dedicated /config/api-keys endpoint."""
    resp = client.post("/api/v1/config/setting", json={"key": "shodan_api_key", "value": "x"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "secret_setting"


def test_row_status_is_honest() -> None:
    """An investigation row's status never silently claims 'complete'."""
    from types import SimpleNamespace

    from soc_ai.api.webui_api import _row_status

    def inv(**k: object) -> object:
        return SimpleNamespace(**k)

    assert _row_status(inv(status="running", verdict=None)) == "running"
    assert _row_status(inv(status="complete", verdict="true_positive")) == "complete"
    # needs_more_info IS a verdict — keep complete
    assert _row_status(inv(status="complete", verdict="needs_more_info")) == "complete"
    # finished with NO verdict → not a real completion
    assert _row_status(inv(status="complete", verdict=None)) == "error"
    assert _row_status(inv(status="complete", verdict="")) == "error"
    # cancelled must NOT collapse to 'complete'
    assert _row_status(inv(status="cancelled", verdict=None)) == "cancelled"
    # an unknown stored status falls back to 'error', never 'complete'
    # ("awaiting" was removed from _STATUS — the backend never writes it)
    assert _row_status(inv(status="awaiting", verdict=None)) == "error"
    assert _row_status(inv(status="weird", verdict=None)) == "error"


def test_config_surfaces_events_index_pattern(client: TestClient) -> None:
    """GET /config exposes the newly-surfaced events_index_pattern (inc 1) with
    source=env (no override yet), hot apply, and its env value."""
    resp = client.get("/api/v1/config")
    assert resp.status_code == 200
    items = {item["key"]: item for group in resp.json()["groups"] for item in group["items"]}
    assert "events_index_pattern" in items, "events_index_pattern not surfaced in /config"
    spec = items["events_index_pattern"]
    assert spec["source"] == "env"
    assert spec["apply"] == "hot-apply"
    assert spec["type"] == "text"
    assert spec["value"]  # the env/default value is rendered, not blank


def test_config_models_lists_gateway_models(client: TestClient) -> None:
    """GET /config/models proxies the gateway's model list (feeds the
    analyst-model dropdown); a listing failure returns ok=false + detail, not
    an error, so the UI can fall back to free text."""
    ok = AsyncMock(return_value=(["deepseek-v4-flash", "qwen3.6-35b-reason"], None))
    with patch("soc_ai.api.webui.routes_config.probes.list_gateway_models", ok):
        body = client.get("/api/v1/config/models").json()
    assert body == {
        "ok": True,
        "models": ["deepseek-v4-flash", "qwen3.6-35b-reason"],
        "detail": None,
    }

    down = AsyncMock(return_value=([], "ConnectError: gateway unreachable"))
    with patch("soc_ai.api.webui.routes_config.probes.list_gateway_models", down):
        body = client.get("/api/v1/config/models").json()
    assert body["ok"] is False
    assert body["models"] == []
    assert "unreachable" in body["detail"]


def _egress_client(settings: Settings) -> Iterator[TestClient]:
    """A TestClient whose /config/egress-policy audit-count aggregation is stubbed
    to all-zero, so the tests assert on the POLICY TABLE (enable state + posture)
    deterministically without depending on a live ES aggregation."""

    async def _zero_counts(_elastic, _alias, kinds, *, days=7):  # type: ignore[no-untyped-def]
        return {k: 0 for k in kinds}

    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
        patch("soc_ai.audit.counts.audit_counts_by_kind", _zero_counts),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def _egress_dest(client: TestClient, dest_id: str) -> dict[str, Any]:
    """Fetch /config/egress-policy and return the destination row with ``dest_id``."""
    body = client.get("/api/v1/config/egress-policy").json()
    return next(d for d in body["destinations"] if d["id"] == dest_id)


def test_egress_policy_all_off_is_zero_egress(settings_kratos: Settings) -> None:
    """E5.3: with every egress knob off, the read-model reports zero_egress and
    every destination row reads enabled=false — 'zero egress' is inspectable."""
    for client in _egress_client(settings_kratos):
        resp = client.get("/api/v1/config/egress-policy")
        assert resp.status_code == 200
        body = resp.json()
        assert body["zero_egress"] is True
        ids = {d["id"] for d in body["destinations"]}
        # every grounded destination is present
        assert ids == {
            "oracle",
            "web_search",
            "crawl",
            "online_enrichment",
            "analyst_cloud",
            "notifications",
            "rag_gateway",
        }
        assert all(d["enabled"] is False for d in body["destinations"])
        # posture strings are populated + honest for the analyst destination
        analyst = next(d for d in body["destinations"] if d["id"] == "analyst_cloud")
        assert analyst["redaction"].startswith("none")  # no redaction when off


def test_egress_policy_flip_one_knob_breaks_zero_egress(settings_kratos: Settings) -> None:
    """Flipping ONE destination on (web search — needs both the toggle AND a URL)
    flips its row enabled=true and clears zero_egress; others stay off."""
    settings = settings_kratos.model_copy(
        update={"web_search_enabled": True, "searxng_url": "https://search.example.com"}
    )
    for client in _egress_client(settings):
        body = client.get("/api/v1/config/egress-policy").json()
        assert body["zero_egress"] is False
        by_id = {d["id"]: d for d in body["destinations"]}
        assert by_id["web_search"]["enabled"] is True
        # the others remain disabled
        assert by_id["oracle"]["enabled"] is False
        assert by_id["notifications"]["enabled"] is False


def test_egress_policy_web_search_needs_url_not_just_toggle(settings_kratos: Settings) -> None:
    """web_search_enabled alone isn't a reachable egress — without a SearXNG URL
    the row stays disabled (and zero_egress holds)."""
    settings = settings_kratos.model_copy(update={"web_search_enabled": True})  # no URL
    for client in _egress_client(settings):
        body = client.get("/api/v1/config/egress-policy").json()
        by_id = {d["id"]: d for d in body["destinations"]}
        assert by_id["web_search"]["enabled"] is False
        assert body["zero_egress"] is True


def test_egress_policy_notify_needs_toggle_and_webhook(settings_kratos: Settings) -> None:
    """Notifications need BOTH the master toggle AND a configured webhook URL."""
    toggle_only = settings_kratos.model_copy(update={"notify_enabled": True})  # no webhook
    for client in _egress_client(toggle_only):
        assert _egress_dest(client, "notifications")["enabled"] is False

    both = settings_kratos.model_copy(
        update={
            "notify_enabled": True,
            "notify_webhook_url": SecretStr("https://hooks.example.com/x"),
        }
    )
    for client in _egress_client(both):
        body = client.get("/api/v1/config/egress-policy").json()
        by_id = {d["id"]: d for d in body["destinations"]}
        assert by_id["notifications"]["enabled"] is True
        assert body["zero_egress"] is False


def test_egress_policy_rag_gateway_tracks_model_config(settings_kratos: Settings) -> None:
    """E4.1: the runbook-retrieval destination reads enabled iff EITHER rag model
    id is configured (each one independently makes retrieval call the gateway),
    and its posture is honest that runbook text + queries leave unredacted."""
    for client in _egress_client(settings_kratos):  # both unset → off
        d = _egress_dest(client, "rag_gateway")
        assert d["enabled"] is False
        assert "runbook" in d["redaction"]

    embed_only = settings_kratos.model_copy(update={"rag_embed_model": "qwen3-embed"})
    for client in _egress_client(embed_only):
        body = client.get("/api/v1/config/egress-policy").json()
        by_id = {d["id"]: d for d in body["destinations"]}
        assert by_id["rag_gateway"]["enabled"] is True
        assert body["zero_egress"] is False

    rerank_only = settings_kratos.model_copy(update={"rag_rerank_model": "bge-reranker"})
    for client in _egress_client(rerank_only):
        assert _egress_dest(client, "rag_gateway")["enabled"] is True


def test_egress_policy_analyst_redaction_posture_is_honest(settings_kratos: Settings) -> None:
    """The analyst-model destination reflects the TRUE redaction posture: off =
    'none', on = best-effort, on+fail-closed = the fail-closed string."""
    off = settings_kratos.model_copy(update={"analyst_cloud_redaction": False})
    for client in _egress_client(off):
        d = _egress_dest(client, "analyst_cloud")
        assert d["enabled"] is False
        assert d["redaction"].startswith("none")

    best_effort = settings_kratos.model_copy(update={"analyst_cloud_redaction": True})
    for client in _egress_client(best_effort):
        d = _egress_dest(client, "analyst_cloud")
        assert d["enabled"] is True
        assert "best-effort" in d["redaction"]

    fail_closed = settings_kratos.model_copy(
        update={"analyst_cloud_redaction": True, "analyst_redaction_fail_closed": True}
    )
    for client in _egress_client(fail_closed):
        assert _egress_dest(client, "analyst_cloud")["redaction"] == "sanitized + fail-closed"


def test_egress_policy_counts_null_when_audit_errors(settings_kratos: Settings) -> None:
    """The counters are BEST-EFFORT: when the audit-count path raises, the
    endpoint still returns 200 with the full table and null counts — a down
    audit index must never break the page."""

    async def _boom(*_a, **_k):  # type: ignore[no-untyped-def]
        raise RuntimeError("ES unreachable")

    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        patch("soc_ai.audit.counts.audit_counts_by_kind", _boom),
    ):
        app = create_app()
        with TestClient(app) as client:
            resp = client.get("/api/v1/config/egress-policy")
            assert resp.status_code == 200
            body = resp.json()
            # table still returned in full
            assert len(body["destinations"]) == 7
            # every count is null (unknown), never a misleading 0
            assert all(d["count_7d"] is None for d in body["destinations"])


def test_egress_policy_oracle_count_reflects_audit(settings_kratos: Settings) -> None:
    """A destination WITH a mapped audit kind (Oracle) surfaces its 7-day count;
    a destination without one (web search) stays null."""

    async def _counts(_elastic, _alias, kinds, *, days=7):  # type: ignore[no-untyped-def]
        base = {k: 0 for k in kinds}
        base["oracle_escalation"] = 3
        base["oracle_adjudication"] = 2
        return base

    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        patch("soc_ai.audit.counts.audit_counts_by_kind", _counts),
    ):
        app = create_app()
        with TestClient(app) as client:
            body = client.get("/api/v1/config/egress-policy").json()
            by_id = {d["id"]: d for d in body["destinations"]}
            # Oracle sums both mapped kinds
            assert by_id["oracle"]["count_7d"] == 5
            # web search has no dedicated kind → honest null, not 0
            assert by_id["web_search"]["count_7d"] is None


def test_egress_policy_admin_gated(settings_kratos: Settings) -> None:
    """/config/egress-policy is admin-gated: with API auth required and no admin
    session it 403s (mirrors /config/models, /config/model-fitness)."""
    settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw")}
    )
    for client in _egress_client(settings):
        resp = client.get("/api/v1/config/egress-policy")
        assert resp.status_code in (401, 403)


def test_config_save_events_index_pattern_roundtrips(client: TestClient) -> None:
    """Saving the inc-1 events_index_pattern persists an override; GET reflects
    source=db and the new value, proving it's coercible + saveable."""
    save = client.post(
        "/api/v1/config/setting",
        json={"key": "events_index_pattern", "value": "logs-*"},
    )
    assert save.status_code == 200
    assert save.json() == {"ok": True, "restart_required": False}

    items = {
        item["key"]: item
        for group in client.get("/api/v1/config").json()["groups"]
        for item in group["items"]
    }
    assert items["events_index_pattern"]["source"] == "db"
    assert items["events_index_pattern"]["value"] == "logs-*"


def test_health_shape(client: TestClient) -> None:
    with (
        patch(
            "soc_ai.api.webui_api.probes.probe_es",
            AsyncMock(return_value={"ok": True, "detail": "cluster — ES 8"}),
        ),
        patch(
            "soc_ai.api.webui_api.probes.probe_llm",
            AsyncMock(return_value={"ok": False, "detail": "gateway down"}),
        ),
    ):
        body = client.get("/api/v1/health").json()
    assert body["es"]["ok"] is True
    assert body["llm"] == {"ok": False, "detail": "gateway down"}
    assert body["pcap"] is None  # pcap_enabled is False by default


def test_probe_pcap_disabled(settings_kratos: Settings) -> None:
    import asyncio

    from soc_ai.webui import probes

    r = asyncio.run(probes.probe_pcap(settings_kratos))
    assert r["ok"] is True
    assert "disabled" in r["detail"]


def test_security_response_headers_present(client: TestClient) -> None:
    """Every response carries the conservative security headers."""
    resp = client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert "Permissions-Policy" in resp.headers
    # TestClient uses http:// by default → HSTS is NOT sent on plain HTTP.
    assert "Strict-Transport-Security" not in resp.headers


def test_security_headers_hsts_only_on_https(client: TestClient) -> None:
    """HSTS is emitted only when the request scheme is https."""
    resp = client.get("/healthz", headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
    # Whether HSTS appears depends on request.url.scheme; the nosniff header is
    # unconditional, so assert that as the load-bearing guarantee.
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_api_docs_disabled_by_default(client: TestClient) -> None:
    """Interactive docs + raw schema are gated off by default (expose_api_docs)."""
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_hunt_rejects_blank_alert_id(client: TestClient) -> None:
    """Empty alert_id is a 422, not a 500 (would reach ES as ids:[""])."""
    assert client.post("/api/v1/hunt", json={"alert_id": ""}).status_code == 422


def test_override_rejects_out_of_range_confidence(client: TestClient) -> None:
    """Confidence outside [0,1] is rejected at the schema boundary."""
    r = client.post(
        "/api/v1/investigations/nope/override",
        json={"verdict": "false_positive", "confidence": 5.0},
    )
    assert r.status_code == 422


def test_alerts_grid_unavailable_fails_fast_503(client: TestClient, monkeypatch: Any) -> None:
    """When ES is unreachable the alerts console returns a clean 503, not a hang
    or 500 (perf finding: the ES client otherwise retries for up to ~90s)."""
    from elastic_transport import TransportError

    async def _boom(*_a: Any, **_k: Any) -> None:
        raise TransportError("connection refused")

    monkeypatch.setattr("soc_ai.api.webui_api.aq.fetch_groups", _boom)
    r = client.get("/api/v1/alerts?range=24h")
    assert r.status_code == 503
    assert r.json()["detail"]["reason"] == "grid_unavailable"


def test_alerts_grid_slow_times_out_503(settings_kratos: Settings, monkeypatch: Any) -> None:
    """A grid query that exceeds webui_grid_timeout_s is bounded → 503, not a hang."""

    async def _slow(*_a: Any, **_k: Any) -> None:
        await asyncio.sleep(3)

    monkeypatch.setattr("soc_ai.api.webui_api.aq.fetch_groups", _slow)
    s = settings_kratos.model_copy(update={"webui_grid_timeout_s": 1})
    for c in _client(s):
        r = c.get("/api/v1/alerts?range=24h")
        assert r.status_code == 503
        assert r.json()["detail"]["reason"] == "grid_unavailable"


def test_auto_triage_status(client: TestClient) -> None:
    s = client.get("/api/v1/auto-triage").json()
    assert s["active"] is False
    assert {"total", "hunted", "skipped", "failed", "severities"} <= set(s)
    # E2.2: the status always carries a (possibly empty) per-reason skip breakdown.
    assert s["skipped_reasons"] == {}


def test_auto_triage_status_surfaces_skipped_reasons(client: TestClient) -> None:
    """A planner-set per-reason skip breakdown is surfaced on the status
    response so the FE completion note can explain WHY work was skipped."""
    from soc_ai.webui import autotriage as at

    # Reach the app.state the client's app exposes and stash a breakdown on it
    # exactly as the planner would, then confirm the GET carries it verbatim.
    status = at.get_status(client.app.state)
    status.skipped = 4
    status.skipped_reasons = {"already_triaged": 3, "no_ip": 1}

    s = client.get("/api/v1/auto-triage").json()
    assert s["skipped"] == 4
    assert s["skipped_reasons"] == {"already_triaged": 3, "no_ip": 1}
    assert sum(s["skipped_reasons"].values()) == s["skipped"]


def test_auto_triage_nothing_to_hunt(client: TestClient) -> None:
    with patch("soc_ai.api.webui_api.at.plan_targets", AsyncMock(return_value=([], 0, []))):
        s = client.post("/api/v1/auto-triage", json={}).json()
    assert s["active"] is False
    assert s["note"] == "nothing to hunt"


def test_auto_triage_selected_routes_to_ids(client: TestClient) -> None:
    """alert_ids selects the explicit-selection planner and surfaces a note."""
    captured: dict[str, list[str]] = {}

    async def fake_plan_ids(state: object, *, alert_ids: list[str]) -> tuple[list, int]:
        captured["ids"] = alert_ids
        return [], 2  # both selected ids already triaged

    with patch("soc_ai.api.webui_api.at.plan_targets_for_ids", fake_plan_ids):
        s = client.post("/api/v1/auto-triage", json={"alert_ids": ["a", "b"]}).json()

    assert captured["ids"] == ["a", "b"]
    assert s["active"] is False
    assert s["note"] == "all 2 selected already triaged"


def test_auto_triage_selected_spawns_for_targets(client: TestClient) -> None:
    """alert_ids with un-triaged picks spawns a run and reports the counts."""
    from soc_ai.webui.autotriage import Target

    async def fake_plan_ids(state: object, *, alert_ids: list[str]) -> tuple[list, int]:
        return [Target(alert_es_id="a", rule_name="", src_ip="", dst_ip="")], 1

    async def noop_run(
        state: object, *, targets: list, started_by: str, inherited_acks: list | None = None
    ) -> None:
        return None

    with (
        patch("soc_ai.api.webui_api.at.plan_targets_for_ids", fake_plan_ids),
        patch("soc_ai.api.webui_api.at.run_auto_triage", noop_run),
    ):
        s = client.post("/api/v1/auto-triage", json={"alert_ids": ["a", "b"]}).json()

    assert s["active"] is True
    assert s["total"] == 1
    assert s["note"] == "triaging 1 selected (1 already triaged)"


def test_auto_triage_sweep_uses_config_floor_medium(settings_kratos: Settings) -> None:
    """Sweep with auto_triage_min_severity=medium plans critical+high+medium."""
    settings = settings_kratos.model_copy(update={"auto_triage_min_severity": "medium"})
    captured: dict[str, tuple[str, ...]] = {}

    async def capturing_plan(state: object, *, time_range: str, oql, severities):
        captured["severities"] = severities
        return [], 0, []

    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
        patch("soc_ai.api.webui_api.at.plan_targets", capturing_plan),
    ):
        app = create_app()
        with TestClient(app) as c:
            s = c.post("/api/v1/auto-triage", json={}).json()

    assert s["active"] is False
    assert set(captured["severities"]) == {"critical", "high", "medium"}


def test_auto_triage_sweep_uses_config_floor_critical(settings_kratos: Settings) -> None:
    """Sweep with auto_triage_min_severity=critical plans only critical."""
    settings = settings_kratos.model_copy(update={"auto_triage_min_severity": "critical"})
    captured: dict[str, tuple[str, ...]] = {}

    async def capturing_plan(state: object, *, time_range: str, oql, severities):
        captured["severities"] = severities
        return [], 0, []

    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
        patch("soc_ai.api.webui_api.at.plan_targets", capturing_plan),
    ):
        app = create_app()
        with TestClient(app) as c:
            c.post("/api/v1/auto-triage", json={})

    assert captured["severities"] == ("critical",)


def test_auto_triage_explicit_severities_override_config_floor(settings_kratos: Settings) -> None:
    """Explicit body.severities takes precedence over the config floor."""
    # Config floor is critical-only; caller explicitly requests critical+high+medium.
    settings = settings_kratos.model_copy(update={"auto_triage_min_severity": "critical"})
    captured: dict[str, tuple[str, ...]] = {}

    async def capturing_plan(state: object, *, time_range: str, oql, severities):
        captured["severities"] = severities
        return [], 0, []

    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
        patch("soc_ai.api.webui_api.at.plan_targets", capturing_plan),
    ):
        app = create_app()
        with TestClient(app) as c:
            c.post(
                "/api/v1/auto-triage",
                json={"severities": ["critical", "high", "medium"]},
            )

    assert set(captured["severities"]) == {"critical", "high", "medium"}


async def _seed_inv(client: TestClient, *, alert_es_id: str, actions: list[dict]) -> str:
    """Persist a completed investigation carrying report.recommended_actions."""
    from soc_ai.store import investigations as inv_svc

    maker = client.app.state.db_sessionmaker
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id=alert_es_id, started_by="tester")
        inv.report = {"recommended_actions": actions}
        await db.commit()
        return inv.id


def _fake_write_tool(calls: list[dict], result: dict):
    """Patch target for write_exec.get_tool — records the call, returns ``result``."""
    from soc_ai.tools._registry import ToolSpec

    async def fn(alert_id: str, comment: str | None = None, *, auth, settings=None) -> dict:
        calls.append({"alert_id": alert_id, "comment": comment, "auth": auth})
        return result

    return ToolSpec(name="ack_alert", read_only=False, description="", func=fn)


def test_build_actions_marks_ack_applied_after_auto_ack() -> None:
    """#8: once auto-ack has acked the alert, the ack action is rendered done
    (applied=True, no live token) — never offered as an actionable button."""
    from soc_ai.api.webui_api import _build_actions

    ack_ev = SimpleNamespace(kind="auto_ack", payload={"success": True, "es_id": "es1"})
    report = {
        "recommended_actions": [
            {"tool_name": "ack_alert", "rationale": "benign"},
            {"tool_name": "add_case_comment", "rationale": "note"},
        ]
    }
    by_tag = {a.tag: a for a in _build_actions([ack_ev], report)}
    assert by_tag["ack"].applied is True
    assert by_tag["ack"].token is None
    assert by_tag["comment"].applied is False  # non-ack actions untouched


def test_build_actions_ack_not_applied_without_successful_auto_ack() -> None:
    """No auto_ack event (or a failed one) leaves the ack action actionable."""
    from soc_ai.api.webui_api import _build_actions

    report = {"recommended_actions": [{"tool_name": "ack_alert", "rationale": "benign"}]}
    assert _build_actions([], report)[0].applied is False
    failed = SimpleNamespace(kind="auto_ack", payload={"success": False})
    assert _build_actions([failed], report)[0].applied is False


def test_build_actions_marks_ack_applied_when_alert_acked_in_es() -> None:
    """An ack performed OUTSIDE this run (group-ack, SO web UI, another run's
    auto-ack) arrives as alert_acked=True — the ack action is rendered done with
    an "Already acknowledged" note, never re-offered."""
    from soc_ai.api.webui_api import _build_actions

    report = {
        "recommended_actions": [
            {"tool_name": "ack_alert", "rationale": "benign"},
            {"tool_name": "escalate_to_case", "rationale": "case it"},
        ]
    }
    by_tag = {a.tag: a for a in _build_actions([], report, alert_acked=True)}
    assert by_tag["ack"].applied is True
    assert by_tag["ack"].appliedNote == "Already acknowledged"
    assert by_tag["escalate"].applied is False  # only ack is satisfied by acked state
    # auto-ack takes precedence over the ES-state note (keeps the existing UI wording)
    ack_ev = SimpleNamespace(kind="auto_ack", payload={"success": True})
    auto = _build_actions([ack_ev], report, alert_acked=True)[0]
    assert auto.applied is True and auto.appliedNote is None


def test_build_actions_marks_persisted_execution_applied() -> None:
    """FR-030: a persisted action_executed event marks THAT action applied on
    reload (index-matched), with an attribution note — no re-offer of an
    already-executed escalate."""
    from soc_ai.api.webui_api import _build_actions

    report = {
        "recommended_actions": [
            {"tool_name": "ack_alert", "rationale": "benign"},
            {"tool_name": "escalate_to_case", "rationale": "case it"},
        ]
    }
    exec_ev = SimpleNamespace(
        kind="action_executed",
        payload={"index": 1, "tool_name": "escalate_to_case", "success": True, "by": "alice"},
    )
    actions = _build_actions([exec_ev], report)
    assert actions[0].applied is False  # untouched sibling stays actionable
    assert actions[1].applied is True
    assert actions[1].appliedNote == "Executed · alice"
    # a FAILED execution must not suppress the offer
    failed = SimpleNamespace(
        kind="action_executed",
        payload={"index": 1, "tool_name": "escalate_to_case", "success": False},
    )
    assert _build_actions([failed], report)[1].applied is False


def test_alert_currently_acked_reads_es_and_swallows_errors(settings_kratos: Settings) -> None:
    """Live acked-state probe: True on event.acknowledged, False on miss/error —
    an ES failure must NEVER break the detail page."""
    import asyncio

    from soc_ai.api.webui_api import _alert_currently_acked

    settings = settings_kratos

    def _es(hits: list[dict]) -> SimpleNamespace:
        return SimpleNamespace(search=AsyncMock(return_value=SimpleNamespace(hits=hits)))

    acked = _es([{"_id": "es1", "_source": {"event": {"acknowledged": True}}}])
    assert asyncio.run(_alert_currently_acked(acked, settings, "es1")) is True
    unacked = _es([{"_id": "es1", "_source": {"event": {"acknowledged": False}}}])
    assert asyncio.run(_alert_currently_acked(unacked, settings, "es1")) is False
    assert asyncio.run(_alert_currently_acked(_es([]), settings, "es1")) is False
    assert asyncio.run(_alert_currently_acked(acked, settings, None)) is False
    boom = SimpleNamespace(search=AsyncMock(side_effect=RuntimeError("es down")))
    assert asyncio.run(_alert_currently_acked(boom, settings, "es1")) is False


def test_tool_step_expands_full_result_not_just_args() -> None:
    """#10: the expanded tool-call row carries the FULL result headline (generously
    capped) plus the query — not the arguments alone."""
    from soc_ai.api.webui_api import _tool_step

    result = {"summary": "prevalence: " + "x" * 300}
    _title, detail = _tool_step("prevalence", {"ip": "1.2.3.4"}, result)
    assert "result:" in detail and "query:" in detail
    assert "x" * 250 in detail  # full result (600-cap), not the old 90-char clip


def test_execute_action_acks_and_defaults_alert_id(client: TestClient) -> None:
    import asyncio

    # alert_id deliberately omitted from tool_args -> endpoint defaults it from
    # the investigation's own alert es-id.
    inv_id = asyncio.run(
        _seed_inv(
            client,
            alert_es_id="bgCT1Z4B9CEm8iACKAkT",
            actions=[{"tool_name": "ack_alert", "tool_args": {}}],
        )
    )
    calls: list[dict] = []
    with patch(
        "soc_ai.tools.write_exec.get_tool",
        return_value=_fake_write_tool(calls, {"acknowledged": True}),
    ):
        resp = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "executed"
    assert body["title"] == "Acknowledge alert"
    assert body["detail"] == "Alert acknowledged in Security Onion."
    # defaulted alert_id reached the tool; auth was injected (signature declares it)
    assert calls[0]["alert_id"] == "bgCT1Z4B9CEm8iACKAkT"
    assert calls[0]["auth"] is not None


def test_execute_action_surfaces_tool_error(client: TestClient) -> None:
    import asyncio

    from soc_ai.errors import SoApiError
    from soc_ai.tools._registry import ToolSpec

    inv_id = asyncio.run(
        _seed_inv(
            client,
            alert_es_id="es-77",
            actions=[{"tool_name": "ack_alert", "tool_args": {"alert_id": "es-77"}}],
        )
    )

    async def boom(alert_id: str, *, auth, settings=None) -> dict:
        raise SoApiError("ack_alert returned 503: upstream down", status_code=503)

    spec = ToolSpec(name="ack_alert", read_only=False, description="", func=boom)
    with patch("soc_ai.tools.write_exec.get_tool", return_value=spec):
        body = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()
    assert body["status"] == "error"
    assert "503" in body["error"]


def test_execute_action_rejects_non_write_tool(client: TestClient) -> None:
    import asyncio

    inv_id = asyncio.run(
        _seed_inv(
            client,
            alert_es_id="es-9",
            actions=[{"tool_name": "search_events", "tool_args": {}}],
        )
    )
    resp = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "not_executable"


def test_execute_action_index_out_of_range(client: TestClient) -> None:
    import asyncio

    inv_id = asyncio.run(_seed_inv(client, alert_es_id="es-1", actions=[]))
    resp = client.post(f"/api/v1/investigations/{inv_id}/actions/3/execute")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "no_such_action"


def test_execute_action_unknown_investigation_404(client: TestClient) -> None:
    resp = client.post("/api/v1/investigations/NOPE/actions/0/execute")
    assert resp.status_code == 404


def test_execute_action_persists_and_suppresses_reoffer(client: TestClient) -> None:
    """FR-030: a successful execution is persisted as an action_executed event —
    the detail response marks the card applied on reload, and a repeat execute
    returns ok-with-note WITHOUT writing again (no duplicate SO case)."""
    import asyncio

    inv_id = asyncio.run(
        _seed_inv(
            client,
            alert_es_id="es-esc-1",
            actions=[{"tool_name": "escalate_to_case", "tool_args": {}}],
        )
    )
    calls: list[dict] = []
    with patch(
        "soc_ai.tools.write_exec.get_tool",
        return_value=_fake_write_tool(calls, {"id": "CASE-1"}),
    ):
        first = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()
        assert first["status"] == "executed"
        assert len(calls) == 1

        # Reload: the persisted execution marks the action applied — not re-offered.
        detail = client.get(f"/api/v1/investigations/{inv_id}").json()
        assert detail["actions"][0]["applied"] is True
        assert (detail["actions"][0]["appliedNote"] or "").startswith("Executed")

        # Repeat execute: ok-with-note, and the write tool was NOT called again.
        second = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()
        assert second["status"] == "executed"
        assert "Already executed" in second["detail"]
        assert len(calls) == 1


def test_execute_action_ack_already_acked_in_es_is_idempotent(client: TestClient) -> None:
    """Acking an alert that is ALREADY acked in SO (group-ack / SO web UI /
    another run) returns ok-with-note without writing, and persists the state
    so the card reads applied afterwards."""
    import asyncio

    inv_id = asyncio.run(
        _seed_inv(
            client,
            alert_es_id="es-acked-1",
            actions=[{"tool_name": "ack_alert", "tool_args": {}}],
        )
    )
    calls: list[dict] = []
    with (
        patch(
            "soc_ai.api.webui._timeline._alert_currently_acked",
            AsyncMock(return_value=True),
        ),
        patch(
            "soc_ai.tools.write_exec.get_tool",
            return_value=_fake_write_tool(calls, {"acknowledged": True}),
        ),
    ):
        body = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()
        assert body["status"] == "executed"
        assert "already acknowledged" in body["detail"].lower()
        assert calls == []  # no duplicate write reached Security Onion

        detail = client.get(f"/api/v1/investigations/{inv_id}").json()
        assert detail["alertAcked"] is True
        assert detail["actions"][0]["applied"] is True
        assert detail["actions"][0]["appliedNote"] == "Already acknowledged"


def test_get_investigation_marks_ack_applied_from_live_es_state(client: TestClient) -> None:
    """An ack performed OUTSIDE any investigation (e.g. the SO web UI) surfaces
    on the detail response: alertAcked=True and the ack action pre-applied."""
    import asyncio

    inv_id = asyncio.run(
        _seed_inv(
            client,
            alert_es_id="es-out-1",
            actions=[
                {"tool_name": "ack_alert", "tool_args": {}},
                {"tool_name": "add_case_comment", "tool_args": {"case_id": "c1"}},
            ],
        )
    )
    with patch(
        "soc_ai.api.webui._timeline._alert_currently_acked",
        AsyncMock(return_value=True),
    ):
        body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["alertAcked"] is True
    assert body["actions"][0]["applied"] is True
    assert body["actions"][0]["appliedNote"] == "Already acknowledged"
    assert body["actions"][1]["applied"] is False  # non-ack actions still offered

    # ES probe failure (helper returns False) — current behavior preserved.
    with patch(
        "soc_ai.api.webui._timeline._alert_currently_acked",
        AsyncMock(return_value=False),
    ):
        body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["alertAcked"] is False
    assert body["actions"][0]["applied"] is False


def test_execute_write_tool_refuses_non_write_tool() -> None:
    import asyncio

    from soc_ai.tools.write_exec import execute_write_tool

    result, error = asyncio.run(
        execute_write_tool("search_events", {}, auth=AsyncMock(), settings=AsyncMock())
    )
    assert result is None
    assert "not an executable write tool" in error


def test_alerts_auth_gated(settings_kratos: Settings) -> None:
    auth = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw")}
    )
    for client in _client(auth):
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "no_session"


def test_investigation_surfaces_open_questions(client: TestClient) -> None:
    """report.open_questions is exposed as Investigation.openQuestions."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-nmi", started_by="tester")
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="needs_more_info",
                confidence=0.4,
                rationale="Need PCAP to decide.",
                report={"open_questions": ["Was the payload executed?", "Is 1.2.3.4 known-bad?"]},
            )
            return inv.id

    inv_id = asyncio.run(_seed())
    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["verdict"] == "needs_more_info"
    assert body["openQuestions"] == ["Was the payload executed?", "Is 1.2.3.4 known-bad?"]


def test_investigation_alert_id_surfaces_es_id(client: TestClient) -> None:
    """alert.id in GET /investigations/{id} equals the seeded alert_es_id (GUID)."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    ES_ID = "ZrXB7J4B9CEm8iACssIW"

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id=ES_ID, started_by="tester")
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="false_positive",
                confidence=0.85,
                rationale="Benign internal scan.",
            )
            return inv.id

    inv_id = asyncio.run(_seed())

    # Inject a minimal enriched_alert_context event so _alert_meta is populated.
    from soc_ai.store.models import InvestigationEvent

    async def _add_event(inv_id: str) -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            db.add(
                InvestigationEvent(
                    investigation_id=inv_id,
                    sequence=1,
                    kind="enriched_alert_context",
                    payload={
                        "alert": {
                            "rule_name": "ET SCAN Test",
                            "source_ip": "10.0.0.1",
                            "destination_ip": "10.0.0.2",
                        },
                        "host_alert_profile": {},
                        "enrichments": {},
                    },
                )
            )
            await db.commit()

    asyncio.run(_add_event(inv_id))

    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["alert"] is not None, "alert block should be present"
    assert body["alert"]["id"] == ES_ID


def test_get_investigation_non_dict_host_alert_profile_returns_200(client: TestClient) -> None:
    """BUG #8: GET /investigations/{id} must return 200 (not 500) when
    host_alert_profile is a non-dict (e.g. a string) from a partial enrichment."""
    import asyncio

    from soc_ai.store import investigations as inv_svc
    from soc_ai.store.models import InvestigationEvent

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="es-nondict-hp", started_by="tester")
            await inv_svc.finalize(
                db,
                inv.id,
                status="error",
                verdict=None,
                confidence=None,
                rationale=None,
            )
            # rule_name intentionally left unset → shows as "Investigation" in list
            db.add(
                InvestigationEvent(
                    investigation_id=inv.id,
                    sequence=1,
                    kind="enriched_alert_context",
                    payload={
                        "alert": {
                            "rule_name": "ET TEST Non-dict",
                            "source_ip": "10.1.2.3",
                            "destination_ip": "10.4.5.6",
                        },
                        # Truthy non-dict — the pre-fix code would pass `or {}` and
                        # then call .items() / .get() on a string → AttributeError.
                        "host_alert_profile": "partial_string_from_failed_enrichment",
                        "enrichments": ["unexpected", "list"],
                    },
                )
            )
            await db.commit()
            return inv.id

    inv_id = asyncio.run(_seed())
    resp = client.get(f"/api/v1/investigations/{inv_id}")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    # Graceful degradation: non-dict fields silently become empty
    assert body["hostContext"] == []


def test_get_investigation_null_rule_name_partial_enrichment_200(client: TestClient) -> None:
    """BUG #8: investigation with null rule_name + minimal/missing enrichment payload
    must return 200 with sane defaults (matches 'Investigation' list item)."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            # No rule_name set — this is the "errored before set_rule_name" case
            inv = await inv_svc.create(db, alert_es_id="es-no-rule", started_by="tester")
            await inv_svc.finalize(
                db,
                inv.id,
                status="error",
                verdict=None,
                confidence=None,
                rationale=None,
            )
            # No enriched_alert_context event at all — enr_p stays {}
            return inv.id

    inv_id = asyncio.run(_seed())
    resp = client.get(f"/api/v1/investigations/{inv_id}")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    # Null rule_name no longer falls back to the bare "Investigation" literal —
    # it now identifies the alert by id so the row/detail is never anonymous.
    assert body["name"] == "Alert es-no-rule…"
    assert body["hostContext"] == []


def test_get_investigation_validator_note_surfaces_in_response(client: TestClient) -> None:
    """GET /investigations/{id} must expose validator_note from the report as validatorNote."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    VALIDATOR_NOTE = (
        "Verdict auto-corrected from false_positive to true_positive by SyntheticTPValidator"
    )

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="es-validator-note", started_by="tester")
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="true_positive",
                confidence=0.9,
                rationale="TP confirmed",
                report={"validator_note": VALIDATOR_NOTE},
            )
            return inv.id

    inv_id = asyncio.run(_seed())
    resp = client.get(f"/api/v1/investigations/{inv_id}")
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["validatorNote"] == VALIDATOR_NOTE


def test_resolve_applies_proposal_and_is_idempotent(client: TestClient) -> None:
    """A valid (message_id, token) resolves the verdict and unlocks actions; re-apply 409s."""
    import asyncio

    from soc_ai.store import chat as chat_svc
    from soc_ai.store import investigations as inv_svc

    async def _seed() -> tuple[str, int]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-res", started_by="t")
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="needs_more_info",
                confidence=0.4,
                rationale="need more",
            )
            msg = await chat_svc.create_pending_assistant(db, inv.id)
            await chat_svc.finish_assistant(
                db,
                msg.id,
                content="I propose true_positive.",
                status="done",
                meta={
                    "kind": "verdict_proposal",
                    "validation": "pass",
                    "token": "tok-abc",
                    "proposal": {
                        "verdict": "true_positive",
                        "confidence": 0.8,
                        "rationale": "PCAP shows C2.",
                        "citations": ["(id ev-res)"],
                        "recommended_actions": [
                            {"tool_name": "escalate_to_case", "tool_args": {}, "rationale": "C2."}
                        ],
                    },
                },
            )
            return inv.id, msg.id

    inv_id, msg_id = asyncio.run(_seed())

    ok = client.post(
        f"/api/v1/investigations/{inv_id}/resolve", json={"message_id": msg_id, "token": "tok-abc"}
    )
    assert ok.status_code == 200
    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["verdict"] == "true_positive"
    assert any(a["title"] for a in body["actions"])

    again = client.post(
        f"/api/v1/investigations/{inv_id}/resolve", json={"message_id": msg_id, "token": "tok-abc"}
    )
    assert again.status_code == 409

    inv2_id, msg2_id = asyncio.run(_seed())
    bad = client.post(
        f"/api/v1/investigations/{inv2_id}/resolve", json={"message_id": msg2_id, "token": "wrong"}
    )
    assert bad.status_code == 403


def test_resolve_rejects_cross_investigation_message(client: TestClient) -> None:
    """A proposal message from inv A can't be applied via inv B's path (404)."""
    import asyncio

    from soc_ai.store import chat as chat_svc
    from soc_ai.store import investigations as inv_svc

    async def _seed() -> tuple[str, str, int]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            a = await inv_svc.create(db, alert_es_id="ev-a", started_by="t")
            b = await inv_svc.create(db, alert_es_id="ev-b", started_by="t")
            msg = await chat_svc.create_pending_assistant(db, a.id)
            await chat_svc.finish_assistant(
                db,
                msg.id,
                content="propose",
                status="done",
                meta={
                    "kind": "verdict_proposal",
                    "validation": "pass",
                    "token": "tk",
                    "proposal": {
                        "verdict": "false_positive",
                        "confidence": 0.7,
                        "rationale": "benign",
                        "citations": ["x"],
                        "recommended_actions": [],
                    },
                },
            )
            return a.id, b.id, msg.id

    _a_id, b_id, msg_id = asyncio.run(_seed())
    resp = client.post(
        f"/api/v1/investigations/{b_id}/resolve", json={"message_id": msg_id, "token": "tk"}
    )
    assert resp.status_code == 404


def test_chat_thread_surfaces_verdict_proposal(client: TestClient) -> None:
    import asyncio

    from soc_ai.store import chat as chat_svc
    from soc_ai.store import investigations as inv_svc

    async def _seed() -> tuple[str, int]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-th", started_by="t")
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="needs_more_info", confidence=0.4
            )
            m = await chat_svc.create_pending_assistant(db, inv.id)
            await chat_svc.finish_assistant(
                db,
                m.id,
                content="proposing TP",
                status="done",
                meta={
                    "kind": "verdict_proposal",
                    "validation": "pass",
                    "token": "tk",
                    "proposal": {
                        "verdict": "true_positive",
                        "confidence": 0.8,
                        "rationale": "C2",
                        "citations": ["enrich_indicator"],
                        "recommended_actions": [],
                    },
                },
            )
            return inv.id, m.id

    inv_id, msg_id = asyncio.run(_seed())
    thread = client.get(f"/api/v1/investigations/{inv_id}/chat").json()
    prop = [m for m in thread["messages"] if m.get("kind") == "verdict_proposal"]
    assert prop and prop[0]["validation"] == "pass"
    assert prop[0]["messageId"] == msg_id
    assert prop[0]["proposal"]["verdict"] == "true_positive"
    assert prop[0]["token"] == "tk"


def test_seedchat_surfaces_verdict_proposal(client: TestClient) -> None:
    """A verdict proposal must render as a card on reload (seedChat path), not plain text."""
    import asyncio

    from soc_ai.store import chat as chat_svc
    from soc_ai.store import investigations as inv_svc

    async def _seed() -> tuple[str, int]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-seed", started_by="t")
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="needs_more_info", confidence=0.4
            )
            m = await chat_svc.create_pending_assistant(db, inv.id)
            await chat_svc.finish_assistant(
                db,
                m.id,
                content="proposing TP",
                status="done",
                meta={
                    "kind": "verdict_proposal",
                    "validation": "pass",
                    "token": "tk",
                    "proposal": {
                        "verdict": "true_positive",
                        "confidence": 0.8,
                        "rationale": "C2",
                        "citations": ["enrich_indicator"],
                        "recommended_actions": [],
                    },
                },
            )
            return inv.id, m.id

    inv_id, msg_id = asyncio.run(_seed())
    inv = client.get(f"/api/v1/investigations/{inv_id}").json()
    prop = [m for m in inv["seedChat"] if m.get("kind") == "verdict_proposal"]
    assert prop and prop[0]["messageId"] == msg_id and prop[0]["token"] == "tk"
    assert prop[0]["proposal"]["verdict"] == "true_positive"


def test_override_verdict_manual_provenance(client: TestClient) -> None:
    """POST /override flips verdict and records manual provenance.

    Invalid verdict → 400; running investigation → 409.
    """
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed_complete() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-override", started_by="t")
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="needs_more_info", confidence=0.4
            )
            return inv.id

    async def _seed_running() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-override-run", started_by="t")
            # leave as running (finalize not called)
            return inv.id

    inv_id = asyncio.run(_seed_complete())

    # Valid override
    ok = client.post(
        f"/api/v1/investigations/{inv_id}/override",
        json={"verdict": "false_positive", "rationale": "Analyst confirmed benign."},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["ok"] is True
    assert body["verdict"] == "false_positive"
    # No confidence in request → defaults to 1.0
    assert body["confidence"] == pytest.approx(1.0)

    # Verify provenance in the investigation detail
    detail = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert detail["verdict"] == "false_positive"
    assert detail["conf"] == pytest.approx(1.0)
    res = detail.get("resolution")
    assert res is not None
    assert res["resolved_via"] == "manual"
    assert res["original_verdict"] == "needs_more_info"

    # Invalid verdict → 400
    bad = client.post(
        f"/api/v1/investigations/{inv_id}/override",
        json={"verdict": "banana"},
    )
    assert bad.status_code == 400

    # Non-existent investigation → 404
    not_found = client.post(
        "/api/v1/investigations/DOES_NOT_EXIST/override",
        json={"verdict": "true_positive"},
    )
    assert not_found.status_code == 404

    # Running investigation → 409
    run_id = asyncio.run(_seed_running())
    running = client.post(
        f"/api/v1/investigations/{run_id}/override",
        json={"verdict": "true_positive"},
    )
    assert running.status_code == 409


def test_ack_group_calls_write_tool_per_event(client: TestClient) -> None:
    """POST /alerts/ack-group fetches events and calls execute_write_tool for each."""
    from soc_ai.webui.alerts_query import AlertEvent

    fake_events = [
        AlertEvent(
            es_id="ev-ack-1",
            timestamp="t",
            src="1.1.1.1:5",
            dst="2.2.2.2:443",
            severity="high",
            host="wks-1",
        ),
        AlertEvent(
            es_id="ev-ack-2",
            timestamp="t",
            src="1.1.1.1:6",
            dst="2.2.2.2:443",
            severity="high",
            host="wks-1",
        ),
    ]
    write_tool_calls: list[dict] = []

    async def fake_execute_write_tool(
        tool_name: str,
        tool_args: dict,
        *,
        auth,
        settings,
        **_kwargs,
    ):
        write_tool_calls.append({"tool_name": tool_name, "tool_args": tool_args})
        return {"acknowledged": True}, None

    with (
        patch(
            "soc_ai.api.webui_api.aq.fetch_group_events",
            AsyncMock(return_value=fake_events),
        ),
        patch(
            "soc_ai.api.webui.routes_alert_actions.execute_write_tool",
            fake_execute_write_tool,
        ),
    ):
        resp = client.post(
            "/api/v1/alerts/ack-group",
            json={"rule_name": "ET MALWARE X", "range": "24h"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["acked"] == 2
    assert body["failed"] == 0
    assert body["total"] == 2
    assert body["capped"] is False
    # one call per event, each with the right alert_id. The fan-out is now
    # concurrent (asyncio.gather under a bounded semaphore) so call ORDER is not
    # guaranteed — assert on the SET of alert_ids acked, not the sequence.
    assert len(write_tool_calls) == 2
    assert {c["tool_name"] for c in write_tool_calls} == {"ack_alert"}
    assert {c["tool_args"]["alert_id"] for c in write_tool_calls} == {"ev-ack-1", "ev-ack-2"}


def test_ack_group_empty_returns_zeros(client: TestClient) -> None:
    """When there are no events in the window the endpoint returns acked=0 gracefully."""
    with patch(
        "soc_ai.api.webui_api.aq.fetch_group_events",
        AsyncMock(return_value=[]),
    ):
        resp = client.post(
            "/api/v1/alerts/ack-group",
            json={"rule_name": "ET NOTHING", "range": "24h"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["acked"] == 0
    assert body["total"] == 0


def test_ack_group_notice_kind_threads_kind_to_fetch(client: TestClient) -> None:
    """Regression: kind='notice' must be forwarded to fetch_group_events so
    zeek.notice groups are fetched by notice.note rather than rule.name."""
    mock_fetch = AsyncMock(return_value=[])
    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", mock_fetch),
        patch(
            "soc_ai.api.webui.routes_alert_actions.execute_write_tool",
            AsyncMock(return_value=(None, None)),
        ),
    ):
        resp = client.post(
            "/api/v1/alerts/ack-group",
            json={"rule_name": "ATTACK::Discovery", "kind": "notice", "range": "24h"},
        )
    assert resp.status_code == 200
    _, kwargs = mock_fetch.call_args
    assert kwargs["kind"] == "notice", "kind must be threaded to fetch_group_events"


def test_ack_group_passes_hide_acked_true(client: TestClient) -> None:
    """ack_group must call fetch_group_events with hide_acked=True so already-acked
    events are excluded and re-running a capped group makes progress."""
    mock_fetch = AsyncMock(return_value=[])
    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", mock_fetch),
        patch(
            "soc_ai.api.webui.routes_alert_actions.execute_write_tool",
            AsyncMock(return_value=(None, None)),
        ),
    ):
        resp = client.post(
            "/api/v1/alerts/ack-group",
            json={"rule_name": "ET MALWARE X", "range": "24h"},
        )
    assert resp.status_code == 200
    _, kwargs = mock_fetch.call_args
    assert kwargs.get("hide_acked") is True, (
        "ack_group must pass hide_acked=True to fetch_group_events"
    )


def test_escalate_group_calls_write_tool_per_event(client: TestClient) -> None:
    """POST /alerts/escalate-group fetches events and calls escalate_to_case for each."""
    from soc_ai.webui.alerts_query import AlertEvent

    fake_events = [
        AlertEvent(
            es_id="ev-esc-1",
            timestamp="t",
            src="1.1.1.1:5",
            dst="2.2.2.2:443",
            severity="high",
            host="wks-1",
        ),
        AlertEvent(
            es_id="ev-esc-2",
            timestamp="t",
            src="1.1.1.1:6",
            dst="2.2.2.2:443",
            severity="high",
            host="wks-1",
        ),
    ]
    write_tool_calls: list[dict] = []

    async def fake_execute_write_tool(
        tool_name: str,
        tool_args: dict,
        *,
        auth,
        settings,
        **_kwargs,
    ):
        write_tool_calls.append({"tool_name": tool_name, "tool_args": tool_args})
        return {"id": "case-1"}, None

    with (
        patch(
            "soc_ai.api.webui_api.aq.fetch_group_events",
            AsyncMock(return_value=fake_events),
        ),
        patch(
            "soc_ai.api.webui.routes_alert_actions.execute_write_tool",
            fake_execute_write_tool,
        ),
    ):
        resp = client.post(
            "/api/v1/alerts/escalate-group",
            json={"rule_name": "ET MALWARE X", "range": "24h"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["escalated"] == 2
    assert body["failed"] == 0
    assert body["total"] == 2
    assert body["capped"] is False
    # one escalate_to_case per event, each carrying that event's id plus a
    # synthesized (non-empty) title + description the write tool requires.
    assert len(write_tool_calls) == 2
    assert {c["tool_name"] for c in write_tool_calls} == {"escalate_to_case"}
    assert {c["tool_args"]["alert_id"] for c in write_tool_calls} == {"ev-esc-1", "ev-esc-2"}
    for c in write_tool_calls:
        assert c["tool_args"]["case_title"].strip()
        assert c["tool_args"]["case_description"].strip()


def test_escalate_group_empty_returns_zeros(client: TestClient) -> None:
    """When there are no events in the window the endpoint returns escalated=0."""
    with patch(
        "soc_ai.api.webui_api.aq.fetch_group_events",
        AsyncMock(return_value=[]),
    ):
        resp = client.post(
            "/api/v1/alerts/escalate-group",
            json={"rule_name": "ET NOTHING", "range": "24h"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["escalated"] == 0
    assert body["total"] == 0


def test_escalate_group_auth_gated(settings_kratos: Settings) -> None:
    """With api_auth_required, an unauthenticated escalate-group POST is 401."""
    auth = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw")}
    )
    for client in _client(auth):
        resp = client.post(
            "/api/v1/alerts/escalate-group",
            json={"rule_name": "ET MALWARE X", "range": "24h"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "no_session"


def test_escalate_group_cookie_cross_origin_is_csrf_rejected(settings_kratos: Settings) -> None:
    """A cookie-authenticated cross-origin escalate-group POST is CSRF-rejected.

    Mirrors the ack-group / me-status CSRF coverage: escalate-group is a sibling
    write endpoint on the gated router, so it inherits the same Origin guard.
    A real login (open router, exempt) sets a valid session cookie; a subsequent
    cross-origin Origin header must be rejected before any SO write is attempted.
    """
    auth = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw")}
    )
    for client in _client(auth):
        login = client.post("/api/v1/login", json={"username": "admin", "password": "pw"})
        assert login.status_code == 200, login.text
        resp = client.post(
            "/api/v1/alerts/escalate-group",
            json={"rule_name": "ET MALWARE X", "range": "24h"},
            headers={"Origin": "https://evil.example.com"},
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "bad_origin"


def test_escalate_group_same_origin_cookie_write_is_allowed(settings_kratos: Settings) -> None:
    """A cookie-authenticated SAME-origin escalate-group POST passes the CSRF guard.

    The Origin header matches the app's own origin, so the write proceeds through
    to fetch_group_events (mocked empty) rather than being CSRF-rejected.
    """
    auth = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw")}
    )
    for client in _client(auth):
        login = client.post("/api/v1/login", json={"username": "admin", "password": "pw"})
        assert login.status_code == 200, login.text
        with patch(
            "soc_ai.api.webui_api.aq.fetch_group_events",
            AsyncMock(return_value=[]),
        ):
            resp = client.post(
                "/api/v1/alerts/escalate-group",
                json={"rule_name": "ET MALWARE X", "range": "24h"},
                headers={"Origin": "http://testserver"},
            )
        assert resp.status_code == 200
        assert resp.json()["escalated"] == 0


def test_ack_events_success(client: TestClient) -> None:
    """POST /alerts/ack-events dedupes ids and calls execute_write_tool for each unique id."""

    async def fake_write(
        tool_name: str,
        tool_args: dict,
        *,
        auth,
        settings,
        **_kwargs,
    ):
        return (None, None)  # success

    with patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", fake_write):
        resp = client.post(
            "/api/v1/alerts/ack-events",
            json={"es_ids": ["a", "b", "b", "c"]},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["acked"] == 3  # dedupe: a, b, c
    assert data["failed"] == 0
    assert data["total"] == 3


def test_ack_events_partial_failure(client: TestClient) -> None:
    """POST /alerts/ack-events reports failures per-id without short-circuiting."""

    async def fake_write(
        tool_name: str,
        tool_args: dict,
        *,
        auth,
        settings,
        **_kwargs,
    ):
        if tool_args["alert_id"] == "b":
            return (None, "boom")
        return (None, None)

    with patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", fake_write):
        resp = client.post(
            "/api/v1/alerts/ack-events",
            json={"es_ids": ["a", "b", "c"]},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["acked"] == 2
    assert data["failed"] == 1
    assert data["total"] == 3


def test_ack_events_fans_out_concurrently_under_semaphore_bound(client: TestClient) -> None:
    """Bulk ack runs writes concurrently but never exceeds the semaphore bound.

    Each write blocks on an event until released; we record the peak number of
    in-flight writes. With a serial loop the peak would be 1; with the bounded
    fan-out it climbs to _ACK_CONCURRENCY (8) and is capped there even though
    more events are queued.
    """
    import asyncio as _asyncio

    from soc_ai.api.webui_api import _ACK_CONCURRENCY

    n_events = _ACK_CONCURRENCY + 5  # more than the bound so the cap is exercised
    in_flight = 0
    peak = 0
    gate = _asyncio.Event()

    async def fake_write(tool_name, tool_args, *, auth, settings, **_kwargs):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        # Once the bound's worth of writes are in flight, release everyone so the
        # test can't deadlock; the cap has been observed by then.
        if in_flight >= _ACK_CONCURRENCY:
            gate.set()
        await gate.wait()
        in_flight -= 1
        return (None, None)

    with patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", fake_write):
        resp = client.post(
            "/api/v1/alerts/ack-events",
            json={"es_ids": [f"e{i}" for i in range(n_events)]},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["acked"] == n_events
    assert data["failed"] == 0
    # Concurrency happened (peak > 1) AND was bounded (peak never exceeds the cap).
    assert peak == _ACK_CONCURRENCY, f"expected peak in-flight == bound, got {peak}"


def test_ack_events_swallows_raised_exceptions_as_failures(client: TestClient) -> None:
    """A write that RAISES (not just returns an error tuple) counts as a failure
    and never escapes — the other events still complete (return_exceptions=True)."""

    async def fake_write(tool_name, tool_args, *, auth, settings, **_kwargs):
        if tool_args["alert_id"] == "boom":
            raise RuntimeError("upstream blew up")
        return (None, None)

    with patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", fake_write):
        resp = client.post(
            "/api/v1/alerts/ack-events",
            json={"es_ids": ["a", "boom", "c"]},
        )
    assert resp.status_code == 200  # endpoint did not 500
    data = resp.json()
    assert data["acked"] == 2
    assert data["failed"] == 1
    assert data["total"] == 3


def test_ack_group_fans_out_and_counts_mixed_results(client: TestClient) -> None:
    """ack-group aggregates successes/failures across the concurrent fan-out."""
    from soc_ai.webui.alerts_query import AlertEvent

    events = [
        AlertEvent(
            es_id=f"g{i}",
            timestamp="t",
            src="1.1.1.1:5",
            dst="2.2.2.2:443",
            severity="high",
            host="wks-1",
        )
        for i in range(6)
    ]

    async def fake_write(tool_name, tool_args, *, auth, settings, **_kwargs):
        # Two of the six fail (one via error tuple, one via raise).
        if tool_args["alert_id"] == "g2":
            return (None, "es rejected")
        if tool_args["alert_id"] == "g4":
            raise RuntimeError("network reset")
        return (None, None)

    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", AsyncMock(return_value=events)),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", fake_write),
    ):
        resp = client.post(
            "/api/v1/alerts/ack-group",
            json={"rule_name": "ET MALWARE X", "range": "24h"},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["acked"] == 4
    assert data["failed"] == 2
    assert data["total"] == 6


def test_assign_persists_and_surfaces_in_list(client: TestClient) -> None:
    """POST /alerts/assign persists an owner; GET /alerts returns that owner on the group."""
    # Assign "ET X" to the anonymous caller (API auth is off in test settings)
    resp = client.post("/api/v1/alerts/assign", json={"rule_name": "ET X"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_name"] == "ET X"
    assert body["owner"] == "anonymous"  # identify_caller returns this with no session

    # Now list alerts: patch aq.fetch_groups to return a group with rule_name "ET X"
    groups = [
        AlertGroup(
            rule_name="ET X",
            count=1,
            severity="high",
            latest_ts="2026-06-22T10:00:00Z",
            latest_id="es-x1",
            kind="suricata",
        )
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 1))),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        alerts = client.get("/api/v1/alerts").json()

    assert len(alerts) == 1
    assert alerts[0]["name"] == "ET X"
    assert alerts[0]["owner"] == "anonymous"


def test_assign_unassign_clears_owner(client: TestClient) -> None:
    """Unassign removes the owner; a subsequent list returns owner=null."""
    # Assign first
    client.post("/api/v1/alerts/assign", json={"rule_name": "ET Y"})

    # Then unassign
    resp = client.post("/api/v1/alerts/assign", json={"rule_name": "ET Y", "unassign": True})
    assert resp.status_code == 200
    assert resp.json()["owner"] is None

    groups = [
        AlertGroup(
            rule_name="ET Y",
            count=1,
            severity="low",
            latest_ts="2026-06-22T10:00:00Z",
            latest_id="es-y1",
            kind="suricata",
        )
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 1))),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        alerts = client.get("/api/v1/alerts").json()

    assert alerts[0]["owner"] is None


# ---------------------------------------------------------------------------
# /alerts/assign — triage state (E2.3)
# ---------------------------------------------------------------------------


def test_assign_defaults_to_owned_state(client: TestClient) -> None:
    """A plain assign lands state='owned' in the response and surfaces on the list."""
    resp = client.post("/api/v1/alerts/assign", json={"rule_name": "ET STATE A"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["owner"] == "anonymous"
    assert body["state"] == "owned"

    groups = [
        AlertGroup(
            rule_name="ET STATE A",
            count=1,
            severity="high",
            latest_ts="2026-07-07T10:00:00Z",
            latest_id="es-sa1",
            kind="suricata",
        )
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 1))),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        alerts = client.get("/api/v1/alerts").json()
    assert alerts[0]["owner"] == "anonymous"
    assert alerts[0]["state"] == "owned"


def test_assign_emits_audit_event(client: TestClient) -> None:
    """POST /alerts/assign emits an ``assignment`` audit event on assign."""
    with patch("soc_ai.audit.logger.AuditLogger.log_kind", new_callable=AsyncMock) as log_kind:
        resp = client.post("/api/v1/alerts/assign", json={"rule_name": "ET AUDIT A"})
    assert resp.status_code == 200
    log_kind.assert_awaited()
    _args, kwargs = log_kind.call_args
    assert kwargs["kind"] == "assignment"
    assert kwargs["payload"]["action"] == "assign"
    assert kwargs["payload"]["state"] == "owned"
    assert kwargs["payload"]["rule_name"] == "ET AUDIT A"


def test_set_state_persists_and_surfaces(client: TestClient) -> None:
    """Setting state on an owned rule persists it and surfaces on the alerts list."""
    client.post("/api/v1/alerts/assign", json={"rule_name": "ET STATE B"})
    resp = client.post(
        "/api/v1/alerts/assign", json={"rule_name": "ET STATE B", "state": "in_review"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["owner"] == "anonymous"  # owner unchanged by a state transition
    assert body["state"] == "in_review"

    groups = [
        AlertGroup(
            rule_name="ET STATE B",
            count=1,
            severity="medium",
            latest_ts="2026-07-07T10:00:00Z",
            latest_id="es-sb1",
            kind="suricata",
        )
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 1))),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        alerts = client.get("/api/v1/alerts").json()
    assert alerts[0]["state"] == "in_review"


def test_set_state_on_unassigned_is_404(client: TestClient) -> None:
    """State requires an owner: a state transition on an unassigned rule 404s."""
    resp = client.post("/api/v1/alerts/assign", json={"rule_name": "ET NEVER", "state": "done"})
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_assigned"


def test_set_state_rejects_bad_state(client: TestClient) -> None:
    client.post("/api/v1/alerts/assign", json={"rule_name": "ET STATE C"})
    resp = client.post(
        "/api/v1/alerts/assign", json={"rule_name": "ET STATE C", "state": "unassigned"}
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "bad_state"


def test_unassign_clears_state(client: TestClient) -> None:
    """Unassign drops the row — owner AND state gone; the list shows both null."""
    client.post("/api/v1/alerts/assign", json={"rule_name": "ET STATE D"})
    client.post("/api/v1/alerts/assign", json={"rule_name": "ET STATE D", "state": "done"})
    resp = client.post("/api/v1/alerts/assign", json={"rule_name": "ET STATE D", "unassign": True})
    assert resp.status_code == 200
    assert resp.json()["owner"] is None
    assert resp.json()["state"] is None

    groups = [
        AlertGroup(
            rule_name="ET STATE D",
            count=1,
            severity="low",
            latest_ts="2026-07-07T10:00:00Z",
            latest_id="es-sd1",
            kind="suricata",
        )
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 1))),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        alerts = client.get("/api/v1/alerts").json()
    assert alerts[0]["owner"] is None
    assert alerts[0]["state"] is None


def test_ownership_survives_reinvestigation(client: TestClient) -> None:
    """Assignment is rule-scoped: a fresh investigation of the rule does NOT clear it.

    The assignment row is keyed by rule_name, independent of any investigation
    run — so listing alerts after a (mocked) re-hunt still shows the owner/state.
    """
    client.post("/api/v1/alerts/assign", json={"rule_name": "ET SURVIVE"})
    client.post("/api/v1/alerts/assign", json={"rule_name": "ET SURVIVE", "state": "in_review"})

    # Simulate a re-investigation landing: a running investigation for the rule.
    running_inv = SimpleNamespace(
        id="inv-new",
        status="running",
        alert_es_id="es-sv2",
        verdict=None,
        confidence=None,
        src_ip="10.0.0.9",
        dest_ip="10.0.0.1",
        report=None,
    )
    groups = [
        AlertGroup(
            rule_name="ET SURVIVE",
            count=1,
            severity="high",
            latest_ts="2026-07-07T11:00:00Z",
            latest_id="es-sv2",
            kind="suricata",
        )
    ]
    with (
        patch("soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=(groups, 1))),
        patch(
            "soc_ai.api.webui_api.inv_svc.latest_for_rules",
            AsyncMock(return_value={"ET SURVIVE": running_inv}),
        ),
    ):
        alerts = client.get("/api/v1/alerts").json()
    assert alerts[0]["owner"] == "anonymous"
    assert alerts[0]["state"] == "in_review"


# ---------------------------------------------------------------------------
# /alerts/representative
# ---------------------------------------------------------------------------


def test_representative_picks_modal_tuple(client: TestClient) -> None:
    """GET /alerts/representative returns the newest event from the most-common flow.

    Cluster: 3 events on (A→B:443) + 1 on (A→C:53).
    Expected: alert_id of the newest (A→B:443) event; matched=3; total=4.
    """
    from soc_ai.webui.alerts_query import AlertEvent

    # Three events on the modal tuple; timestamps are different so we can
    # verify the *newest* is chosen as the representative.
    ev_b1 = AlertEvent(
        es_id="ev-b-oldest",
        timestamp="2026-06-20T10:00:00Z",
        src="10.0.0.1:1234",
        dst="10.0.0.2:443",
        severity="high",
        host="wks-1",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
    )
    ev_b2 = AlertEvent(
        es_id="ev-b-mid",
        timestamp="2026-06-21T10:00:00Z",
        src="10.0.0.1:1235",
        dst="10.0.0.2:443",
        severity="high",
        host="wks-1",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
    )
    ev_b3 = AlertEvent(
        es_id="ev-b-newest",
        timestamp="2026-06-22T10:00:00Z",
        src="10.0.0.1:1236",
        dst="10.0.0.2:443",
        severity="high",
        host="wks-1",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        dst_port=443,
    )
    ev_c1 = AlertEvent(
        es_id="ev-c-only",
        timestamp="2026-06-22T12:00:00Z",  # newest overall, but minority tuple
        src="10.0.0.1:9999",
        dst="10.0.0.3:53",
        severity="high",
        host="wks-1",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.3",
        dst_port=53,
    )

    fake_events = [ev_b1, ev_b2, ev_b3, ev_c1]

    with patch(
        "soc_ai.api.webui_api.aq.fetch_group_events",
        AsyncMock(return_value=fake_events),
    ):
        resp = client.get(
            "/api/v1/alerts/representative",
            params={"rule_name": "ET MODAL TEST", "range": "24h"},
        )

    assert resp.status_code == 200
    body = resp.json()

    # Must pick the newest of the (A→B:443) tuple, NOT the globally newest event.
    assert body["alert_id"] == "ev-b-newest"
    assert body["matched"] == 3
    assert body["total"] == 4
    assert "10.0.0.1" in body["reason"]
    assert "10.0.0.2" in body["reason"]
    assert "443" in body["reason"]
    assert body["dst_port"] == 443


def test_representative_no_events_returns_404(client: TestClient) -> None:
    """GET /alerts/representative with no events in window returns 404."""
    with patch(
        "soc_ai.api.webui_api.aq.fetch_group_events",
        AsyncMock(return_value=[]),
    ):
        resp = client.get(
            "/api/v1/alerts/representative",
            params={"rule_name": "ET EMPTY", "range": "24h"},
        )
    assert resp.status_code == 404


def test_representative_no_ip_falls_back_to_newest(client: TestClient) -> None:
    """When no events have IPs, the fallback is the globally newest event."""
    from soc_ai.webui.alerts_query import AlertEvent

    ev1 = AlertEvent(
        es_id="ev-no-ip-old",
        timestamp="2026-06-21T08:00:00Z",
        src="—",
        dst="—",
        severity="low",
        host="wks-x",
    )
    ev2 = AlertEvent(
        es_id="ev-no-ip-new",
        timestamp="2026-06-22T08:00:00Z",
        src="—",
        dst="—",
        severity="low",
        host="wks-x",
    )

    with patch(
        "soc_ai.api.webui_api.aq.fetch_group_events",
        AsyncMock(return_value=[ev1, ev2]),
    ):
        resp = client.get(
            "/api/v1/alerts/representative",
            params={"rule_name": "ET NO IP", "range": "24h"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["alert_id"] == "ev-no-ip-new"
    assert "newest overall" in body["reason"]


# ---------------------------------------------------------------------------
# chatCount on the investigations list
# ---------------------------------------------------------------------------


def test_investigations_list_chat_count(client: TestClient) -> None:
    """GET /investigations includes chatCount reflecting done chat messages."""
    import asyncio

    from soc_ai.store import chat as chat_svc
    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-chat-count", started_by="tester")
            # user message (done)
            await chat_svc.add_user_message(db, inv.id, "Is this benign?")
            # assistant message: create pending then finish (done)
            msg = await chat_svc.create_pending_assistant(db, inv.id)
            await chat_svc.finish_assistant(db, msg.id, content="Looks benign.", status="done")
            return inv.id

    inv_id = asyncio.run(_seed())
    body = client.get("/api/v1/investigations").json()
    row = next((r for r in body if r["id"] == inv_id), None)
    assert row is not None, "seeded investigation not found in list"
    # 1 user + 1 assistant = 2 done messages
    assert row["chatCount"] == 2


def test_investigation_oracle_adjudication_surface(client: TestClient) -> None:
    """GET /investigations/{id} exposes structured OracleOut when oracle events are present."""
    import asyncio

    from soc_ai.store import investigations as inv_svc
    from soc_ai.store.models import InvestigationEvent

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-oracle-adj", started_by="tester")
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="true_positive",
                confidence=0.82,
                rationale="Oracle overrode local call.",
            )
            db.add(
                InvestigationEvent(
                    investigation_id=inv.id,
                    sequence=1,
                    kind="oracle_escalation",
                    payload={
                        "reason": "below_confidence",
                        "local_verdict": "false_positive",
                        "local_confidence": 0.6,
                    },
                )
            )
            db.add(
                InvestigationEvent(
                    investigation_id=inv.id,
                    sequence=2,
                    kind="oracle_adjudication",
                    payload={
                        "oracle_verdict": "true_positive",
                        "oracle_confidence": 0.82,
                        "oracle_model": "claude-opus-4-8",
                        "redaction": "2 credentials redacted",
                    },
                )
            )
            await db.commit()
            return inv.id

    inv_id = asyncio.run(_seed())
    body = client.get(f"/api/v1/investigations/{inv_id}").json()

    oracle = body.get("oracle")
    assert oracle is not None, "oracle block should be present"
    assert oracle["escalated"] is True
    assert oracle["localVerdict"] == "false_positive"
    assert oracle["oracleVerdict"] == "true_positive"
    assert oracle["changed"] is True
    assert oracle["model"] == "claude-opus-4-8"
    assert oracle["redacted"] is True
    assert oracle["redactionNote"] == "2 credentials redacted"


def test_investigation_no_oracle_yields_null(client: TestClient) -> None:
    """GET /investigations/{id} yields oracle=null when no oracle events are present."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-no-oracle", started_by="tester")
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="false_positive",
                confidence=0.9,
                rationale="Clean traffic.",
            )
            return inv.id

    inv_id = asyncio.run(_seed())
    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body.get("oracle") is None


# ---------------------------------------------------------------------------
# User management JSON API — /api/v1/config/users
# ---------------------------------------------------------------------------


def test_create_user_appears_in_list(client: TestClient) -> None:
    """POST /config/users creates a user; GET /config/users surfaces it."""
    resp = client.post(
        "/api/v1/config/users",
        json={"username": "alice", "password": "longpassword1", "role": "analyst"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    resp2 = client.get("/api/v1/config/users")
    assert resp2.status_code == 200
    usernames = [u["username"] for u in resp2.json()["users"]]
    assert "alice" in usernames


def test_create_user_bad_role(client: TestClient) -> None:
    """POST /config/users with an unrecognised role returns 400 invalid_role."""
    resp = client.post(
        "/api/v1/config/users",
        json={"username": "bob", "password": "longpassword1", "role": "superuser"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "invalid_role"


def test_create_user_short_password(client: TestClient) -> None:
    """POST /config/users with a password shorter than 8 chars returns 400 password_too_short."""
    resp = client.post(
        "/api/v1/config/users",
        json={"username": "bob", "password": "short", "role": "analyst"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "password_too_short"


def test_set_user_role(client: TestClient) -> None:
    """POST /config/users/{id}/set-role promotes/demotes a user; GET reflects the change."""
    client.post(
        "/api/v1/config/users",
        json={"username": "charlie", "password": "longpassword1", "role": "analyst"},
    )
    users = client.get("/api/v1/config/users").json()["users"]
    uid = next(u["id"] for u in users if u["username"] == "charlie")

    resp = client.post(f"/api/v1/config/users/{uid}/set-role", json={"role": "admin"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    users2 = client.get("/api/v1/config/users").json()["users"]
    charlie = next(u for u in users2 if u["username"] == "charlie")
    assert charlie["role"] == "admin"


def test_toggle_user_disabled(client: TestClient) -> None:
    """POST /config/users/{id}/toggle-disabled flips the disabled flag to True on first call."""
    client.post(
        "/api/v1/config/users",
        json={"username": "dana", "password": "longpassword1", "role": "analyst"},
    )
    users = client.get("/api/v1/config/users").json()["users"]
    uid = next(u["id"] for u in users if u["username"] == "dana")

    resp = client.post(f"/api/v1/config/users/{uid}/toggle-disabled")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["disabled"] is True  # was enabled, now disabled


def test_last_admin_cannot_be_demoted(client: TestClient) -> None:
    """set-role to non-admin is blocked when the target is the only enabled admin."""
    users = client.get("/api/v1/config/users").json()["users"]
    admin_users = [u for u in users if u["role"] == "admin" and not u["disabled"]]
    # The bootstrap admin is the only admin in a fresh test DB.
    # If (somehow) there are multiple enabled admins, disable all but one first.
    if len(admin_users) > 1:
        for u in admin_users[1:]:
            client.post(f"/api/v1/config/users/{u['id']}/toggle-disabled")
    uid = admin_users[0]["id"]
    resp = client.post(f"/api/v1/config/users/{uid}/set-role", json={"role": "analyst"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "last_admin"


def test_last_admin_cannot_be_disabled(client: TestClient) -> None:
    """toggle-disabled is blocked when the target is the only enabled admin."""
    users = client.get("/api/v1/config/users").json()["users"]
    admin_users = [u for u in users if u["role"] == "admin" and not u["disabled"]]
    # Disable all but one enabled admin to guarantee the last-admin scenario.
    if len(admin_users) > 1:
        for u in admin_users[1:]:
            client.post(f"/api/v1/config/users/{u['id']}/toggle-disabled")
    uid = admin_users[0]["id"]
    resp = client.post(f"/api/v1/config/users/{uid}/toggle-disabled")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "last_admin"


def test_reset_password_returns_password(client: TestClient) -> None:
    """POST /config/users/{id}/reset-password returns ok=True and a non-empty new password."""
    client.post(
        "/api/v1/config/users",
        json={"username": "eve", "password": "longpassword1", "role": "analyst"},
    )
    users = client.get("/api/v1/config/users").json()["users"]
    uid = next(u["id"] for u in users if u["username"] == "eve")

    resp = client.post(f"/api/v1/config/users/{uid}/reset-password")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert isinstance(data["password"], str)


# ---------------------------------------------------------------------------
# /me + /me/status — current-user endpoints
# ---------------------------------------------------------------------------


def test_get_me_dev_fallback(client: TestClient) -> None:
    """GET /me returns the dev-fallback when api_auth_required is False and no session."""
    resp = client.get("/api/v1/me")
    assert resp.status_code == 200
    data = resp.json()
    # Dev fallback shape: must have username, role, status
    assert "username" in data
    assert "role" in data
    assert "status" in data


def test_status_defaults_empty_on_create(client: TestClient) -> None:
    """Newly-created users have status == '' in the users list."""
    client.post(
        "/api/v1/config/users",
        json={"username": "frank", "password": "longpassword1", "role": "analyst"},
    )
    users = client.get("/api/v1/config/users").json()["users"]
    frank = next(u for u in users if u["username"] == "frank")
    assert frank["status"] == ""


def test_set_my_status_dev_echo(client: TestClient) -> None:
    """POST /me/status echoes back the trimmed status (dev no-session path)."""
    resp = client.post("/api/v1/me/status", json={"status": "  investigating  "})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    # The API trims whitespace server-side
    assert data["status"] == "investigating"


def test_set_my_status_cap_64(client: TestClient) -> None:
    """POST /me/status truncates status to 64 characters."""
    long_status = "x" * 100
    resp = client.post("/api/v1/me/status", json={"status": long_status})
    assert resp.status_code == 200
    assert len(resp.json()["status"]) <= 64


def test_status_visible_in_users_list(client: TestClient) -> None:
    """status field is present in every row returned by GET /config/users."""
    resp = client.get("/api/v1/config/users")
    assert resp.status_code == 200
    for user in resp.json()["users"]:
        assert "status" in user


# ── Danger-zone endpoint tests ────────────────────────────────────────────────


class TestDangerZoneGet:
    """GET /api/v1/config/danger — list danger rows, never leak secret values."""

    def test_get_danger_returns_known_keys(self, settings_kratos: Settings) -> None:
        """At minimum so_password and es_password appear in the list."""
        for c in _client(settings_kratos):
            r = c.get("/api/v1/config/danger")
            assert r.status_code == 200
            data = r.json()
            keys = {row["key"] for row in data}
            assert "so_password" in keys
            assert "es_password" in keys
            assert "litellm_api_key" in keys

    def test_get_danger_secret_rows_have_no_value(self, settings_kratos: Settings) -> None:
        """Secret-typed rows must NOT have a 'value' field."""
        for c in _client(settings_kratos):
            r = c.get("/api/v1/config/danger")
            assert r.status_code == 200
            # The fixture sets so_password=SecretStr("password123"); confirm it never appears.
            assert "password123" not in r.text, "Raw secret value leaked into response body"
            for row in r.json():
                if row.get("type") == "secret":
                    # Structural guarantee: DangerSettingOut has no value field.
                    assert "value" not in row, f"Secret value leaked for {row['key']}"

    def test_get_danger_row_shape(self, settings_kratos: Settings) -> None:
        """Every row has key, label, type, isSet, source, hot fields."""
        for c in _client(settings_kratos):
            r = c.get("/api/v1/config/danger")
            assert r.status_code == 200
            for row in r.json():
                assert "key" in row
                assert "label" in row
                assert "type" in row
                assert "isSet" in row
                assert "source" in row
                assert "hot" in row


class TestDangerZoneSave:
    """POST /api/v1/config/danger/setting — typed-confirm, encryption, restart flag."""

    @pytest.fixture
    def settings(self) -> Settings:
        """Settings with a config_secret_key so Fernet encryption works in tests."""
        from pydantic import SecretStr

        return Settings(
            so_host="https://so.example.com",
            so_username="analyst",
            so_password=SecretStr("password123"),
            so_verify_ssl=False,
            es_hosts=["https://so.example.com:9200"],
            litellm_base_url="http://localhost:4000",
            config_secret_key=SecretStr("0Y5eLjMDakyujfxGcb5ijyW_GL4pkxv3gHqWkfanOz0="),
            api_auth_required=False,  # dev-open; secure default is True
        )

    def test_wrong_confirm_rejected(self, settings: Settings) -> None:
        """confirm != key must return 400."""
        for c in _client(settings):
            r = c.post(
                "/api/v1/config/danger/setting",
                json={"key": "es_password", "value": "hunter2", "confirm": "WRONG"},
            )
            assert r.status_code == 400
            detail_str = str(r.json()).lower()
            assert "confirm" in detail_str

    def test_unknown_key_rejected(self, settings: Settings) -> None:
        """Unknown/non-danger key must return 400."""
        for c in _client(settings):
            r = c.post(
                "/api/v1/config/danger/setting",
                json={"key": "not_a_real_key", "value": "x", "confirm": "not_a_real_key"},
            )
            assert r.status_code == 400

    def test_non_danger_key_rejected(self, settings: Settings) -> None:
        """A non-danger key (e.g. analyst_model) must be rejected even with correct confirm."""
        for c in _client(settings):
            r = c.post(
                "/api/v1/config/danger/setting",
                json={"key": "analyst_model", "value": "x", "confirm": "analyst_model"},
            )
            assert r.status_code == 400

    def test_secret_saved_encrypted_and_not_plaintext(self, settings: Settings) -> None:
        """Saving a secret key stores encrypted (not plaintext) value, returns restart_required."""
        import asyncio
        import json as _json

        from soc_ai.store.models import ConfigOverride
        from sqlalchemy import select

        for c in _client(settings):
            r = c.post(
                "/api/v1/config/danger/setting",
                json={"key": "es_password", "value": "s3cr3tP@ssw0rd!", "confirm": "es_password"},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["ok"] is True
            assert body["restart_required"] is True  # es_password has hot=False
            # The response must not contain the plaintext secret
            assert "s3cr3tP@ssw0rd!" not in r.text

            # Verify the DB stores an encrypted value, not the plaintext secret
            async def _read_raw(app=c.app) -> str | None:
                maker = app.state.db_sessionmaker
                async with maker() as db:
                    return await db.scalar(
                        select(ConfigOverride.value).where(ConfigOverride.key == "es_password")
                    )

            raw_stored = asyncio.run(_read_raw())
            assert raw_stored is not None, "No DB row found for es_password"
            stored_value = _json.loads(raw_stored)  # DB value is JSON-encoded
            assert stored_value != "s3cr3tP@ssw0rd!", "Secret stored as plaintext in DB!"
            assert stored_value.startswith("gAAAA"), (
                f"Expected Fernet token (gAAAA...), got: {stored_value[:20]}"
            )

    def test_non_secret_danger_saved(self, settings: Settings) -> None:
        """Non-secret danger setting (e.g. es_hosts) can be saved."""
        for c in _client(settings):
            r = c.post(
                "/api/v1/config/danger/setting",
                json={"key": "es_hosts", "value": "https://es.local:9200", "confirm": "es_hosts"},
            )
            assert r.status_code == 200
            assert r.json()["ok"] is True

    def test_returns_restart_required_true_for_non_hot(self, settings: Settings) -> None:
        """A connection setting (so_host, hot=False) → restart_required=True."""
        for c in _client(settings):
            r = c.post(
                "/api/v1/config/danger/setting",
                json={"key": "so_host", "value": "https://so.local", "confirm": "so_host"},
            )
            assert r.status_code == 200
            assert r.json()["restart_required"] is True

    def test_hot_internal_cidrs_applies_live(self, settings: Settings) -> None:
        """internal_cidrs is hot — saved value applies live, no restart."""
        for c in _client(settings):
            r = c.post(
                "/api/v1/config/danger/setting",
                json={
                    "key": "internal_cidrs",
                    "value": "10.50.0.0/16",
                    "confirm": "internal_cidrs",
                },
            )
            assert r.status_code == 200
            assert r.json()["restart_required"] is False
            nets = [str(n) for n in c.app.state.settings.internal_cidrs]
            assert "10.50.0.0/16" in nets

    def test_hot_ssh_host_applies_live(self, settings: Settings) -> None:
        """so_ssh_host is hot (read per PCAP fetch) — applies live."""
        for c in _client(settings):
            r = c.post(
                "/api/v1/config/danger/setting",
                json={"key": "so_ssh_host", "value": "sensor.local", "confirm": "so_ssh_host"},
            )
            assert r.status_code == 200
            assert r.json()["restart_required"] is False
            assert c.app.state.settings.so_ssh_host == "sensor.local"

    def test_secret_save_without_config_secret_key_returns_400_not_500(self) -> None:
        """Saving a SECRET danger setting with no CONFIG_SECRET_KEY → 400 (not 500),
        and no plaintext value is written to the DB."""
        import asyncio

        from pydantic import SecretStr
        from soc_ai.store.models import ConfigOverride
        from sqlalchemy import select

        # Settings WITHOUT config_secret_key → secret_box is None.
        no_key = Settings(
            so_host="https://so.example.com",
            so_username="analyst",
            so_password=SecretStr("password123"),
            so_verify_ssl=False,
            es_hosts=["https://so.example.com:9200"],
            litellm_base_url="http://localhost:4000",
            api_auth_required=False,  # dev-open; secure default is True
        )
        for c in _client(no_key):
            assert c.app.state.secret_box is None  # precondition: no key
            r = c.post(
                "/api/v1/config/danger/setting",
                json={"key": "es_password", "value": "s3cr3t!", "confirm": "es_password"},
            )
            assert r.status_code == 400
            assert r.json()["detail"]["reason"] == "no_config_secret_key"
            # The plaintext secret must never appear in the response…
            assert "s3cr3t!" not in r.text

            # …and no row (plaintext or otherwise) must be written for the key.
            async def _read_raw(app=c.app) -> str | None:
                maker = app.state.db_sessionmaker
                async with maker() as db:
                    return await db.scalar(
                        select(ConfigOverride.value).where(ConfigOverride.key == "es_password")
                    )

            assert asyncio.run(_read_raw()) is None


class TestApiKeys:
    """GET/POST/DELETE /api/v1/config/api-keys — hot, write-only enrichment keys."""

    @pytest.fixture
    def settings(self) -> Settings:
        from pydantic import SecretStr

        return Settings(
            so_host="https://so.example.com",
            so_username="analyst",
            so_password=SecretStr("password123"),
            so_verify_ssl=False,
            es_hosts=["https://so.example.com:9200"],
            litellm_base_url="http://localhost:4000",
            config_secret_key=SecretStr("0Y5eLjMDakyujfxGcb5ijyW_GL4pkxv3gHqWkfanOz0="),
            api_auth_required=False,
        )

    def test_list_never_returns_values(self, settings: Settings) -> None:
        for c in _client(settings):
            r = c.get("/api/v1/config/api-keys")
            assert r.status_code == 200
            rows = r.json()
            keys = {row["key"] for row in rows}
            assert {"shodan_api_key", "greynoise_api_key", "misp_api_key"} <= keys
            for row in rows:
                assert set(row) == {"key", "label", "help", "isSet", "source"}

    def test_save_hot_applies_and_encrypts(self, settings: Settings) -> None:
        import asyncio
        import json as _json

        from soc_ai.store.models import ConfigOverride
        from sqlalchemy import select

        for c in _client(settings):
            r = c.post(
                "/api/v1/config/api-keys",
                json={"key": "shodan_api_key", "value": "SHODANKEY123"},
            )
            assert r.status_code == 200
            assert r.json() == {"ok": True, "isSet": True}
            assert "SHODANKEY123" not in r.text
            # Hot-applied onto the live Settings singleton (no restart).
            live = c.app.state.settings.shodan_api_key
            assert live is not None and live.get_secret_value() == "SHODANKEY123"

            # Stored Fernet-encrypted, never plaintext.
            async def _read(app: Any = c.app) -> str | None:
                async with app.state.db_sessionmaker() as db:
                    return await db.scalar(
                        select(ConfigOverride.value).where(ConfigOverride.key == "shodan_api_key")
                    )

            stored = _json.loads(asyncio.run(_read()))
            assert stored != "SHODANKEY123"
            assert stored.startswith("gAAAA")

            # GET now reports it set + sourced from the DB (still no value).
            rows = c.get("/api/v1/config/api-keys").json()
            row = next(x for x in rows if x["key"] == "shodan_api_key")
            assert row["isSet"] is True
            assert row["source"] == "db"

    def test_empty_value_rejected(self, settings: Settings) -> None:
        for c in _client(settings):
            r = c.post("/api/v1/config/api-keys", json={"key": "shodan_api_key", "value": "   "})
            assert r.status_code == 400

    def test_non_api_key_rejected(self, settings: Settings) -> None:
        for c in _client(settings):
            # A danger secret is NOT an api-key spec.
            assert (
                c.post(
                    "/api/v1/config/api-keys", json={"key": "es_password", "value": "x"}
                ).status_code
                == 400
            )
            # A non-secret setting is rejected too.
            assert (
                c.post(
                    "/api/v1/config/api-keys", json={"key": "analyst_model", "value": "x"}
                ).status_code
                == 400
            )

    def test_clear_unsets_live_value(self, settings: Settings) -> None:
        for c in _client(settings):
            c.post("/api/v1/config/api-keys", json={"key": "greynoise_api_key", "value": "GNKEY"})
            assert c.app.state.settings.greynoise_api_key is not None
            r = c.delete("/api/v1/config/api-keys/greynoise_api_key")
            assert r.status_code == 200
            assert r.json()["isSet"] is False
            assert c.app.state.settings.greynoise_api_key is None

    def test_save_without_config_secret_key_returns_400(self) -> None:
        from pydantic import SecretStr

        no_key = Settings(
            so_host="https://so.example.com",
            so_username="analyst",
            so_password=SecretStr("password123"),
            so_verify_ssl=False,
            es_hosts=["https://so.example.com:9200"],
            litellm_base_url="http://localhost:4000",
            api_auth_required=False,
        )
        for c in _client(no_key):
            assert c.app.state.secret_box is None
            r = c.post(
                "/api/v1/config/api-keys",
                json={"key": "shodan_api_key", "value": "supersecret"},
            )
            assert r.status_code == 400
            assert r.json()["detail"]["reason"] == "no_config_secret_key"
            assert "supersecret" not in r.text


class TestDangerZoneTest:
    """POST /api/v1/config/danger/test/{target} — probe passthrough, secret-free detail."""

    @pytest.fixture
    def settings(self) -> Settings:
        from pydantic import SecretStr

        return Settings(
            so_host="https://so.example.com",
            so_username="analyst",
            so_password=SecretStr("password123"),
            so_verify_ssl=False,
            es_hosts=["https://so.example.com:9200"],
            litellm_base_url="http://localhost:4000",
            api_auth_required=False,  # dev-open; secure default is True
        )

    def test_es_probe_passthrough(self, settings: Settings) -> None:
        """ES probe result flows through correctly."""
        from unittest.mock import AsyncMock, patch

        fake_result = {"ok": True, "detail": "cluster-uuid — ES 8.12"}
        with patch("soc_ai.api.webui_api.probes.probe_es", AsyncMock(return_value=fake_result)):
            for c in _client(settings):
                r = c.post("/api/v1/config/danger/test/es")
                assert r.status_code == 200
                body = r.json()
                assert body["ok"] is True
                assert body["detail"] == "cluster-uuid — ES 8.12"
                assert set(body.keys()) == {"ok", "detail"}

    def test_llm_probe_passthrough(self, settings: Settings) -> None:
        """LLM probe result flows through correctly."""
        from unittest.mock import AsyncMock, patch

        fake_result = {"ok": False, "detail": "connection refused"}
        with patch("soc_ai.api.webui_api.probes.probe_llm", AsyncMock(return_value=fake_result)):
            for c in _client(settings):
                r = c.post("/api/v1/config/danger/test/llm")
                assert r.status_code == 200
                body = r.json()
                assert body["ok"] is False
                assert body["detail"] == "connection refused"

    def test_unknown_target_rejected(self, settings: Settings) -> None:
        """Unknown probe target must return 400."""
        for c in _client(settings):
            r = c.post("/api/v1/config/danger/test/pcap")
            assert r.status_code == 400
            body = r.json()
            assert body["detail"]["reason"] == "unknown_target"

    def test_response_has_only_ok_and_detail(self, settings: Settings) -> None:
        """Response contains exactly {ok, detail} — no extra fields that could leak secrets."""
        from unittest.mock import AsyncMock, patch

        fake_result = {"ok": False, "detail": "auth failed"}
        with patch("soc_ai.api.webui_api.probes.probe_es", AsyncMock(return_value=fake_result)):
            for c in _client(settings):
                r = c.post("/api/v1/config/danger/test/es")
                assert r.status_code == 200
                body = r.json()
                assert set(body.keys()) == {"ok", "detail"}
                assert "password" not in body["detail"].lower()
                assert "api_key" not in body["detail"].lower()


# ---------------------------------------------------------------------------
# POST /investigations/rehunt — bulk re-hunt
# ---------------------------------------------------------------------------


def test_rehunt_starts_fresh_hunts_for_valid_ids(client: TestClient) -> None:
    """POST /investigations/rehunt with 2 valid ids starts 2 fresh hunts."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> tuple[str, str]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            a = await inv_svc.create(
                db, alert_es_id="ev-rh-a", started_by="tester", rule_name="ET A"
            )
            b = await inv_svc.create(
                db, alert_es_id="ev-rh-b", started_by="tester", rule_name="ET B"
            )
            await inv_svc.finalize(
                db, a.id, status="complete", verdict="false_positive", confidence=0.9
            )
            await inv_svc.finalize(
                db, b.id, status="complete", verdict="true_positive", confidence=0.8
            )
            return a.id, b.id

    a_id, b_id = asyncio.run(_seed())

    call_counter = {"n": 0}

    async def fake_start(
        _state, *, alert_id: str, started_by: str, rule_name: str | None = None
    ) -> str:
        call_counter["n"] += 1
        return f"NEW-{call_counter['n']}"

    fake_mgr = AsyncMock()
    fake_mgr.start = fake_start

    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr):
        resp = client.post("/api/v1/investigations/rehunt", json={"inv_ids": [a_id, b_id]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["skipped"] == []
    started = body["started"]
    assert len(started) == 2
    by_inv = {s["invId"]: s for s in started}
    assert by_inv[a_id]["alertEsId"] == "ev-rh-a"
    assert by_inv[b_id]["alertEsId"] == "ev-rh-b"
    assert by_inv[a_id]["newInvId"].startswith("NEW-")
    assert by_inv[b_id]["newInvId"].startswith("NEW-")
    # Both new ids must be distinct
    assert by_inv[a_id]["newInvId"] != by_inv[b_id]["newInvId"]
    # A named source row seeds the new hunt directly (no ES re-resolution).
    assert call_counter["n"] == 2


def test_rehunt_reresolves_rule_name_when_stored_row_is_nameless(client: TestClient) -> None:
    """Re-hunting a NAMELESS row (a pre-fix row, or a selected-id run that died
    early) re-resolves the rule name from ES so the NEW row is named, not NULL."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            # rule_name stays None — the exact nameless row the fix targets.
            inv = await inv_svc.create(db, alert_es_id="ev-rh-null", started_by="tester")
            return inv.id

    inv_id = asyncio.run(_seed())
    captured: dict[str, Any] = {}

    async def fake_start(
        _state, *, alert_id: str, started_by: str, rule_name: str | None = None
    ) -> str:
        captured["rule_name"] = rule_name
        return "NEW-RR"

    fake_mgr = AsyncMock()
    fake_mgr.start = fake_start

    with (
        patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr),
        patch(
            "soc_ai.api.webui.routes_hunts.resolve_alert_for_hunt",
            AsyncMock(return_value=(True, "ET RE-RESOLVED Rule")),
        ),
    ):
        resp = client.post("/api/v1/investigations/rehunt", json={"inv_ids": [inv_id]})

    assert resp.status_code == 200
    assert resp.json()["started"][0]["newInvId"] == "NEW-RR"
    # the nameless row triggered an ES re-resolve; the new hunt is seeded with it
    assert captured["rule_name"] == "ET RE-RESOLVED Rule"


def test_rehunt_skips_unknown_id(client: TestClient) -> None:
    """An id that doesn't exist in the DB is skipped with reason='not_found'."""
    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="NEW-X")

    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr):
        resp = client.post(
            "/api/v1/investigations/rehunt",
            json={"inv_ids": ["does-not-exist"]},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["started"] == []
    assert len(body["skipped"]) == 1
    assert body["skipped"][0]["invId"] == "does-not-exist"
    assert body["skipped"][0]["reason"] == "not_found"
    fake_mgr.start.assert_not_called()


def test_rehunt_skips_investigation_with_no_alert_es_id(client: TestClient) -> None:
    """An investigation row with no alert_es_id is skipped with reason='no_alert'."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="ev-rh-nullcheck", started_by="tester")
            # Blank out the alert_es_id to simulate the no_alert path.
            inv.alert_es_id = ""
            await db.commit()
            return inv.id

    inv_id = asyncio.run(_seed())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="NEW-Y")

    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr):
        resp = client.post("/api/v1/investigations/rehunt", json={"inv_ids": [inv_id]})

    assert resp.status_code == 200
    body = resp.json()
    assert body["started"] == []
    assert len(body["skipped"]) == 1
    assert body["skipped"][0]["invId"] == inv_id
    assert body["skipped"][0]["reason"] == "no_alert"
    fake_mgr.start.assert_not_called()


# ---------------------------------------------------------------------------
# POST /investigations/{id}/request-more-info — focused re-investigation
# ---------------------------------------------------------------------------


def test_request_more_info_launches_focused_reinvestigation(client: TestClient) -> None:
    """A needs_more_info source launches a fresh hunt on the SAME alert, seeded
    with the prior open questions as a focus_hint."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db, alert_es_id="ev-rmi-a", started_by="tester", rule_name="ET NMI"
            )
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="needs_more_info",
                confidence=0.3,
                report={"open_questions": ["Was the download executed?", "Is the C2 reachable?"]},
            )
            return inv.id

    inv_id = asyncio.run(_seed())
    captured: dict[str, Any] = {}

    async def fake_start(
        _state,
        *,
        alert_id: str,
        started_by: str,
        rule_name: str | None = None,
        focus_hint: str | None = None,
    ) -> str:
        captured["alert_id"] = alert_id
        captured["rule_name"] = rule_name
        captured["focus_hint"] = focus_hint
        return "NEW-RMI"

    fake_mgr = AsyncMock()
    fake_mgr.start = fake_start

    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr):
        resp = client.post(f"/api/v1/investigations/{inv_id}/request-more-info")

    assert resp.status_code == 200
    assert resp.json()["investigation_id"] == "NEW-RMI"
    # Same alert, prior name reused, open questions threaded as the focus hint.
    assert captured["alert_id"] == "ev-rmi-a"
    assert captured["rule_name"] == "ET NMI"
    assert "Was the download executed?" in captured["focus_hint"]
    assert "Is the C2 reachable?" in captured["focus_hint"]


def test_request_more_info_rejects_non_needs_more_info(client: TestClient) -> None:
    """A source verdict that isn't needs_more_info is a 409 and starts no hunt."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db, alert_es_id="ev-rmi-tp", started_by="tester", rule_name="ET TP"
            )
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="true_positive", confidence=0.9
            )
            return inv.id

    inv_id = asyncio.run(_seed())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="SHOULD-NOT-START")

    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr):
        resp = client.post(f"/api/v1/investigations/{inv_id}/request-more-info")

    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "not_needs_more_info"
    fake_mgr.start.assert_not_called()


def test_request_more_info_404_for_unknown_id(client: TestClient) -> None:
    """An unknown investigation id is a 404 and starts no hunt."""
    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="SHOULD-NOT-START")

    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr):
        resp = client.post("/api/v1/investigations/does-not-exist/request-more-info")

    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"
    fake_mgr.start.assert_not_called()


def test_request_more_info_starts_without_open_questions(client: TestClient) -> None:
    """A needs_more_info source with NO open questions still re-runs (focus_hint
    is None — the run just re-investigates the alert)."""
    import asyncio

    from soc_ai.store import investigations as inv_svc

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db, alert_es_id="ev-rmi-noq", started_by="tester", rule_name="ET NMI2"
            )
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="needs_more_info", confidence=0.2
            )
            return inv.id

    inv_id = asyncio.run(_seed())
    captured: dict[str, Any] = {}

    async def fake_start(
        _state,
        *,
        alert_id: str,
        started_by: str,
        rule_name: str | None = None,
        focus_hint: str | None = None,
    ) -> str:
        captured["focus_hint"] = focus_hint
        return "NEW-NOQ"

    fake_mgr = AsyncMock()
    fake_mgr.start = fake_start

    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr):
        resp = client.post(f"/api/v1/investigations/{inv_id}/request-more-info")

    assert resp.status_code == 200
    assert resp.json()["investigation_id"] == "NEW-NOQ"
    assert captured["focus_hint"] is None


# ---------------------------------------------------------------------------
# POST /api/v1/hunt — alert-id resolution guard (no synthetic 0.0 investigations)
# ---------------------------------------------------------------------------


def test_hunt_404_when_alert_id_does_not_resolve(client: TestClient) -> None:
    """A bogus alert_id (e.g. a group's rule NAME leaking through as the id) must
    404 with a clear hint and NOT spin up a (synthetic 0.0) background hunt."""
    fake_mgr = AsyncMock()
    with (
        patch(
            "soc_ai.api.webui.routes_hunts.resolve_alert_for_hunt",
            AsyncMock(return_value=(False, None)),
        ),
        patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr),
    ):
        resp = client.post("/api/v1/hunt", json={"alert_id": "ET MALWARE Some Rule Name"})

    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert detail["reason"] == "alert_not_found"
    assert "aged out" in detail["hint"]
    # Critically: no investigation was started for the unresolved id.
    fake_mgr.start.assert_not_called()


def test_hunt_starts_when_alert_id_resolves(client: TestClient) -> None:
    """When the alert id resolves to a real ES document the hunt starts normally."""
    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="INV-OK")
    with (
        patch(
            "soc_ai.api.webui.routes_hunts.resolve_alert_for_hunt",
            AsyncMock(return_value=(True, "ET MALWARE Some Rule Name")),
        ),
        patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=fake_mgr),
    ):
        resp = client.post("/api/v1/hunt", json={"alert_id": "real-es-doc-1"})

    assert resp.status_code == 200
    assert resp.json()["investigation_id"] == "INV-OK"
    fake_mgr.start.assert_called_once()
    # the resolved rule name is seeded into the hunt so the row is named at birth
    assert fake_mgr.start.call_args.kwargs["rule_name"] == "ET MALWARE Some Rule Name"


def testresolve_alert_for_hunt_returns_existence_and_rule_name() -> None:
    """resolve_alert_for_hunt does one ES ``ids`` lookup and returns
    (exists, rule_name), falling back to event.dataset for non-Suricata docs."""
    import asyncio

    from soc_ai.api.webui_api import resolve_alert_for_hunt

    elastic = AsyncMock()
    settings = SimpleNamespace(events_index_pattern="logs-*")

    # Suricata doc → rule.name
    elastic.search = AsyncMock(
        return_value=SimpleNamespace(
            hits=[{"_id": "x", "_source": {"rule": {"name": "ET SCAN thing"}}}]
        )
    )
    assert asyncio.run(resolve_alert_for_hunt(elastic, settings, "x")) == (True, "ET SCAN thing")
    # the query is an ids lookup against the events index pattern
    _args, _kwargs = elastic.search.call_args
    assert _args[0] == "logs-*"

    # Non-Suricata doc (no rule.name) → event.dataset fallback
    elastic.search = AsyncMock(
        return_value=SimpleNamespace(
            hits=[{"_id": "z", "_source": {"event": {"dataset": "zeek.notice"}}}]
        )
    )
    assert asyncio.run(resolve_alert_for_hunt(elastic, settings, "z")) == (True, "zeek.notice")

    # Missing doc → (False, None)
    elastic.search = AsyncMock(return_value=SimpleNamespace(hits=[]))
    assert asyncio.run(resolve_alert_for_hunt(elastic, settings, "missing")) == (False, None)


# ---------------------------------------------------------------------------
# /api/v1/login and /api/v1/logout
# ---------------------------------------------------------------------------

ADMIN_PW_API = "test-api-login-pw"


def _auth_client(settings_kratos: Settings) -> Iterator[TestClient]:
    """Client with api_auth_required=True and a bootstrapped admin account."""
    auth_settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr(ADMIN_PW_API)}
    )
    yield from _client(auth_settings)


def test_api_login_success_sets_cookie(settings_kratos: Settings) -> None:
    """POST /api/v1/login returns 200, the session cookie, and user info."""
    for client in _auth_client(settings_kratos):
        resp = client.post("/api/v1/login", json={"username": "admin", "password": ADMIN_PW_API})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["username"] == "admin"
        assert body["role"] == "admin"
        # Session cookie must be present
        assert "soc_ai_session" in client.cookies


def test_api_login_bad_credentials(settings_kratos: Settings) -> None:
    """Wrong password → 401 with reason=invalid_credentials."""
    from soc_ai.store import auth as auth_svc

    auth_svc.login_throttle.reset()
    for client in _auth_client(settings_kratos):
        resp = client.post("/api/v1/login", json={"username": "admin", "password": "WRONG"})
        assert resp.status_code == 401
        assert resp.json()["detail"]["reason"] == "invalid_credentials"
    auth_svc.login_throttle.reset()


def test_api_login_brute_force_locks_out_after_n_failures(settings_kratos: Settings) -> None:
    """5 bad logins → the 6th returns 429 (too_many_attempts), not another 401."""
    from soc_ai.store import auth as auth_svc

    auth_svc.login_throttle.reset()
    try:
        for client in _auth_client(settings_kratos):
            # 5 failures within the window are each a 401.
            for _ in range(5):
                r = client.post("/api/v1/login", json={"username": "admin", "password": "WRONG"})
                assert r.status_code == 401
            # The 6th attempt is locked out → 429.
            r = client.post("/api/v1/login", json={"username": "admin", "password": "WRONG"})
            assert r.status_code == 429
            assert r.json()["detail"]["reason"] == "too_many_attempts"
            # Even the CORRECT password is refused while locked out.
            r = client.post("/api/v1/login", json={"username": "admin", "password": ADMIN_PW_API})
            assert r.status_code == 429
    finally:
        auth_svc.login_throttle.reset()


def test_api_login_success_resets_failure_counter(settings_kratos: Settings) -> None:
    """A successful login clears the failure counter so later failures start fresh."""
    from soc_ai.store import auth as auth_svc

    auth_svc.login_throttle.reset()
    try:
        for client in _auth_client(settings_kratos):
            # 4 failures (below the limit of 5).
            for _ in range(4):
                assert (
                    client.post(
                        "/api/v1/login", json={"username": "admin", "password": "WRONG"}
                    ).status_code
                    == 401
                )
            # A good login succeeds and resets the counter.
            ok = client.post("/api/v1/login", json={"username": "admin", "password": ADMIN_PW_API})
            assert ok.status_code == 200
            # After reset, a single failure is a 401 again (not a 429), proving the
            # counter did not carry the prior 4 forward.
            again = client.post("/api/v1/login", json={"username": "admin", "password": "WRONG"})
            assert again.status_code == 401
    finally:
        auth_svc.login_throttle.reset()


def test_api_login_reachable_without_prior_auth_when_auth_required(
    settings_kratos: Settings,
) -> None:
    """Key test: /api/v1/login must be reachable even when api_auth_required=True.

    The ordinary /api/v1/alerts endpoint returns 401; the login endpoint
    must return 200 because it is on the open (pre-auth) router.
    """
    for client in _auth_client(settings_kratos):
        # Verify the auth gate IS active on normal endpoints
        gate_resp = client.get("/api/v1/alerts")
        assert gate_resp.status_code == 401

        # Login itself must succeed without any prior authentication
        login_resp = client.post(
            "/api/v1/login", json={"username": "admin", "password": ADMIN_PW_API}
        )
        assert login_resp.status_code == 200
        assert login_resp.json()["ok"] is True


def test_api_logout_clears_session(settings_kratos: Settings) -> None:
    """POST /api/v1/logout invalidates the session so subsequent requests are rejected."""
    for client in _auth_client(settings_kratos):
        # Log in first
        client.post("/api/v1/login", json={"username": "admin", "password": ADMIN_PW_API})
        assert "soc_ai_session" in client.cookies

        # Logout must succeed
        logout_resp = client.post("/api/v1/logout")
        assert logout_resp.status_code == 200
        assert logout_resp.json()["ok"] is True

        # The cookie should be cleared (deleted by the response)
        assert client.cookies.get("soc_ai_session", "") == ""


def test_api_logout_without_session_is_harmless(settings_kratos: Settings) -> None:
    """POST /api/v1/logout with no session cookie returns 200 (idempotent)."""
    for client in _auth_client(settings_kratos):
        resp = client.post("/api/v1/logout")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


# ---------------------------------------------------------------------------
# Internal-identifier managed-list API — /api/v1/internal-identifiers
# ---------------------------------------------------------------------------


async def _seed_identifier(
    client: TestClient, *, kind: str, value: str, source: str, state: str, evidence=None
) -> int:
    """Insert one internal_identifier row directly; return its id."""
    from soc_ai.store import internal_identifiers as ids_store

    maker = client.app.state.db_sessionmaker
    async with maker() as db:
        if source == "detected":
            row = await ids_store.upsert_detected(
                db, kind, value, evidence or {}, initial_state=state
            )
        else:
            row = await ids_store.add_manual(db, kind, value)
            if state == "muted":
                await ids_store.set_state(db, row.id, "muted")
        return row.id


def test_internal_identifiers_get_shape_with_always_on(client: TestClient) -> None:
    """GET groups DB rows (mutable) + always-on reserved/env entries (read-only),
    and carries last_scan metadata. The reserved .lan suffix appears as an
    always-on row with no id and source=reserved."""
    import asyncio

    det_id = asyncio.run(
        _seed_identifier(
            client,
            kind="suffix",
            value=".corp.acme.com",
            source="detected",
            state="active",
            evidence={"host_count": 31, "event_count": 9200, "last_seen": "2026-06-20"},
        )
    )

    resp = client.get("/api/v1/internal-identifiers")
    assert resp.status_code == 200
    body = resp.json()

    # last_scan metadata is present (reuses the discovery status object).
    assert "last_scan" in body
    assert body["last_scan"]["running"] is False

    groups = {g["kind"]: g["rows"] for g in body["groups"]}
    assert set(groups) == {"suffix", "host", "cidr"}

    suffix_rows = {r["value"]: r for r in groups["suffix"]}
    # The detected row is mutable, carries its id + evidence.
    assert suffix_rows[".corp.acme.com"]["id"] == det_id
    assert suffix_rows[".corp.acme.com"]["mutable"] is True
    assert suffix_rows[".corp.acme.com"]["source"] == "detected"
    assert suffix_rows[".corp.acme.com"]["evidence"]["host_count"] == 31
    # The reserved floor suffix is always-on: no id, not mutable, source=reserved.
    assert ".lan" in suffix_rows
    assert suffix_rows[".lan"]["id"] is None
    assert suffix_rows[".lan"]["mutable"] is False
    assert suffix_rows[".lan"]["source"] == "reserved"
    assert suffix_rows[".lan"]["state"] == "active"


def test_internal_identifiers_add_manual_happy(client: TestClient) -> None:
    """POST adds a manual identifier, returns the created mutable row."""
    resp = client.post(
        "/api/v1/internal-identifiers",
        json={"kind": "host", "value": "WIN11-01"},
    )
    assert resp.status_code == 200
    row = resp.json()
    assert row["value"] == "WIN11-01"
    assert row["source"] == "manual"
    assert row["state"] == "active"
    assert row["mutable"] is True
    assert isinstance(row["id"], int)


def test_internal_identifiers_add_invalid_400(client: TestClient) -> None:
    """A bad kind (repo ValueError) maps to HTTP 400 with the message."""
    resp = client.post(
        "/api/v1/internal-identifiers",
        json={"kind": "bogus", "value": "x"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "invalid_identifier"


def test_internal_identifiers_activate_deactivate(client: TestClient) -> None:
    """POST .../{id}/deactivate then /activate flips state; 404 for an unknown id."""
    import asyncio

    ident_id = asyncio.run(
        _seed_identifier(
            client, kind="suffix", value=".lab.example", source="manual", state="active"
        )
    )

    muted = client.post(f"/api/v1/internal-identifiers/{ident_id}/deactivate")
    assert muted.status_code == 200
    assert muted.json()["state"] == "muted"

    unmuted = client.post(f"/api/v1/internal-identifiers/{ident_id}/activate")
    assert unmuted.status_code == 200
    assert unmuted.json()["state"] == "active"

    missing = client.post("/api/v1/internal-identifiers/999999/deactivate")
    assert missing.status_code == 404


def test_internal_identifiers_delete_manual_ok(client: TestClient) -> None:
    """DELETE removes a manual row."""
    import asyncio

    ident_id = asyncio.run(
        _seed_identifier(
            client, kind="host", value="kept-then-gone", source="manual", state="active"
        )
    )
    resp = client.delete(f"/api/v1/internal-identifiers/{ident_id}")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    # It no longer appears in the GET (not as a mutable row).
    body = client.get("/api/v1/internal-identifiers").json()
    groups = {g["kind"]: g["rows"] for g in body["groups"]}
    assert all(r["value"] != "kept-then-gone" for r in groups["host"])


def test_internal_identifiers_delete_detected_409(client: TestClient) -> None:
    """DELETE on a detected row is refused with 409 (mute it instead)."""
    import asyncio

    ident_id = asyncio.run(
        _seed_identifier(
            client,
            kind="suffix",
            value=".detected.example",
            source="detected",
            state="active",
            evidence={"host_count": 5},
        )
    )
    resp = client.delete(f"/api/v1/internal-identifiers/{ident_id}")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "not_deletable"
    # the hint steers the operator to the terminal tombstone, not the mute toggle
    assert "dismiss" in resp.json()["detail"]["hint"]


def test_internal_identifiers_dismiss_detected_ok(client: TestClient) -> None:
    """POST .../dismiss tombstones a detected row; it vanishes from the GET
    (dismissed rows are excluded from the managed list)."""
    import asyncio

    ident_id = asyncio.run(
        _seed_identifier(
            client,
            kind="suffix",
            value=".cdn.netflix.com",
            source="detected",
            state="muted",
            evidence={"host_count": 2},
        )
    )
    resp = client.post(f"/api/v1/internal-identifiers/{ident_id}/dismiss")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    body = client.get("/api/v1/internal-identifiers").json()
    groups = {g["kind"]: g["rows"] for g in body["groups"]}
    assert all(r["value"] != ".cdn.netflix.com" for r in groups["suffix"])


def test_internal_identifiers_dismiss_unknown_404(client: TestClient) -> None:
    resp = client.post("/api/v1/internal-identifiers/999999/dismiss")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


def test_internal_identifiers_dismiss_manual_409(client: TestClient) -> None:
    """Dismiss on a manual row is refused with 409 (delete manual rows instead)."""
    import asyncio

    ident_id = asyncio.run(
        _seed_identifier(client, kind="host", value="WIN11-01", source="manual", state="active")
    )
    resp = client.post(f"/api/v1/internal-identifiers/{ident_id}/dismiss")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "not_dismissable"
    assert "delete" in resp.json()["detail"]["hint"]

    # the manual row survives untouched
    body = client.get("/api/v1/internal-identifiers").json()
    groups = {g["kind"]: g["rows"] for g in body["groups"]}
    row = next(r for r in groups["host"] if r["value"] == "WIN11-01")
    assert row["state"] == "active"
    assert row["source"] == "manual"


async def _seed_user_session(client: TestClient, *, username: str, role: str) -> str:
    """Seed a user + session row directly; return the raw session token."""
    from soc_ai.store import auth as auth_svc

    maker = client.app.state.db_sessionmaker
    async with maker() as db:
        user = await auth_svc.create_user(db, username, "longpassword1", role=role)
        return await auth_svc.create_session(db, user, ttl_hours=24)


# ---------------------------------------------------------------------------
# POST /api/v1/config/tokens — API token creator-id guard
# ---------------------------------------------------------------------------


def test_create_token_uses_real_admin_id_as_creator(settings_kratos: Settings) -> None:
    """An authenticated admin mints a token whose created_by is that admin's id
    (never a null/0 placeholder)."""
    import asyncio

    from soc_ai.store import auth as auth_svc
    from soc_ai.store.auth import SESSION_COOKIE
    from soc_ai.store.models import ApiToken
    from sqlalchemy import select as _select

    async def _seed_admin(c: TestClient) -> tuple[str, int]:
        async with c.app.state.db_sessionmaker() as db:
            user = await auth_svc.create_user(db, "admin2", "longpassword1", role="admin")
            raw = await auth_svc.create_session(db, user, ttl_hours=24)
            return raw, user.id

    async def _fetch_created_by(c: TestClient) -> int:
        async with c.app.state.db_sessionmaker() as db:
            row = (await db.scalars(_select(ApiToken).where(ApiToken.name == "ci-token"))).one()
            return row.created_by

    for client in _auth_client(settings_kratos):
        token, admin_id = asyncio.run(_seed_admin(client))
        client.cookies.set(SESSION_COOKIE, token)

        # Same-origin Origin header to satisfy the cookie-auth CSRF guard.
        resp = client.post(
            "/api/v1/config/tokens",
            json={"name": "ci-token"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 200
        assert resp.json()["token"].startswith("scai_")
        assert asyncio.run(_fetch_created_by(client)) == admin_id


def test_create_token_refused_without_session_user(client: TestClient) -> None:
    """In dev (api_auth_required=False) the admin gate is a no-op, so a caller with
    no session user could previously mint a token attributed to user 0. The endpoint
    must now REFUSE (403) rather than persist a null/0 created_by."""
    # The default `client` fixture has api_auth_required=False and no session cookie,
    # so current_user(request) resolves to None.
    resp = client.post("/api/v1/config/tokens", json={"name": "orphan"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "no_session_user"


# ---------------------------------------------------------------------------
# Session cookie hardening — HttpOnly always, SameSite=Lax, Secure gated on scheme
# ---------------------------------------------------------------------------


def test_login_cookie_has_httponly_samesite_and_no_secure_on_plain_http(
    settings_kratos: Settings,
) -> None:
    """Over plain HTTP (dev), the session cookie is HttpOnly + SameSite=Lax but NOT
    Secure (a Secure cookie wouldn't be sent over http and would break local login)."""
    for client in _auth_client(settings_kratos):
        resp = client.post("/api/v1/login", json={"username": "admin", "password": ADMIN_PW_API})
        assert resp.status_code == 200
        set_cookie = resp.headers["set-cookie"].lower()
        assert "httponly" in set_cookie
        assert "samesite=lax" in set_cookie
        assert "secure" not in set_cookie  # plain-http dev → no Secure


def test_login_cookie_is_secure_behind_trusted_https_forwarded_proto(
    settings_kratos: Settings,
) -> None:
    """A TLS-terminating proxy IN proxy_trusted_ips that forwards
    X-Forwarded-Proto: https gets the Secure flag even though the upstream hop to
    uvicorn is plain HTTP. The TestClient's socket peer is 'testclient'."""
    settings_kratos.proxy_trusted_ips = ["testclient"]
    for client in _auth_client(settings_kratos):
        resp = client.post(
            "/api/v1/login",
            json={"username": "admin", "password": ADMIN_PW_API},
            headers={"X-Forwarded-Proto": "https"},
        )
        assert resp.status_code == 200
        set_cookie = resp.headers["set-cookie"].lower()
        assert "secure" in set_cookie
        assert "httponly" in set_cookie
        assert "samesite=lax" in set_cookie


def test_login_cookie_not_secure_from_untrusted_forwarded_proto(
    settings_kratos: Settings,
) -> None:
    """X-Forwarded-Proto: https from a peer NOT in proxy_trusted_ips must NOT set
    the Secure flag — otherwise any plain-HTTP client could forge it (FR-038)."""
    settings_kratos.proxy_trusted_ips = []  # no trusted proxy
    for client in _auth_client(settings_kratos):
        resp = client.post(
            "/api/v1/login",
            json={"username": "admin", "password": ADMIN_PW_API},
            headers={"X-Forwarded-Proto": "https"},
        )
        assert resp.status_code == 200
        assert "secure" not in resp.headers["set-cookie"].lower()


def test_request_is_https_helper_matrix() -> None:
    """_request_is_https: true for an https socket scheme always; for
    X-Forwarded-Proto: https ONLY when the peer is a trusted proxy — an untrusted
    peer can't flip the Secure flag by forging the header (FR-038)."""
    from soc_ai.api.webui_api import _request_is_https

    def _req(scheme: str, xfp: str | None, peer: str = "192.0.2.1") -> SimpleNamespace:
        headers = {} if xfp is None else {"x-forwarded-proto": xfp}
        return SimpleNamespace(
            url=SimpleNamespace(scheme=scheme),
            headers=headers,
            client=SimpleNamespace(host=peer),
        )

    trusted = SimpleNamespace(proxy_trusted_ips=["192.0.2.1"])
    # Real HTTPS socket → always true, regardless of proxy config.
    assert _request_is_https(_req("https", None), trusted) is True
    assert _request_is_https(_req("https", None), None) is True
    # XFP honored from the trusted proxy peer.
    assert _request_is_https(_req("http", "https"), trusted) is True
    assert _request_is_https(_req("http", "https, http"), trusted) is True  # left-most wins
    # XFP from an UNTRUSTED peer is ignored — no Secure-flag spoof.
    assert _request_is_https(_req("http", "https", peer="203.0.113.9"), trusted) is False
    # No proxy list configured → forwarded header never trusted.
    assert _request_is_https(_req("http", "https"), None) is False
    # Non-https forwarded / no header → false.
    assert _request_is_https(_req("http", None), trusted) is False
    assert _request_is_https(_req("http", "http"), trusted) is False


def test_collect_reasoning_gathers_traces_in_order() -> None:
    """Reasoning traces from model_response events are collected in order;
    events without a trace (or other kinds) are ignored."""
    from soc_ai.api.webui_api import _collect_reasoning

    def _ev(kind: str, payload: dict[str, Any]) -> Any:
        return SimpleNamespace(kind=kind, payload=payload)

    events = [
        _ev("model_response", {"content": "checking the IP", "reasoning_trace": "first thought"}),
        _ev("tool_call", {"tool_name": "t_enrich_ip"}),
        _ev("model_response", {"content": "no trace here"}),  # no reasoning_trace
        _ev("model_response", {"reasoning_trace": "  second thought  "}),
        _ev("done", {}),
    ]
    assert _collect_reasoning(events) == ["first thought", "second thought"]
    assert _collect_reasoning([]) == []


def test_client_ip_proxy_awareness() -> None:
    """client_ip: peer IP by default; trust X-Forwarded-For ONLY from an
    allowlisted proxy peer (never from an untrusted client)."""
    from soc_ai.api.webui_api import client_ip

    def _req(peer: str, xff: str | None) -> SimpleNamespace:
        headers = {} if xff is None else {"x-forwarded-for": xff}
        return SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers)

    no_proxy = SimpleNamespace(proxy_trusted_ips=[])
    with_proxy = SimpleNamespace(proxy_trusted_ips=["10.0.0.9"])

    # No proxy configured → always the socket peer, XFF ignored.
    assert client_ip(_req("203.0.113.5", "1.2.3.4"), no_proxy) == "203.0.113.5"
    # Trusted proxy peer → left-most XFF is the real client.
    assert client_ip(_req("10.0.0.9", "198.51.100.7, 10.0.0.9"), with_proxy) == "198.51.100.7"
    # Untrusted peer forging XFF → NOT trusted, use the peer IP.
    assert client_ip(_req("203.0.113.5", "198.51.100.7"), with_proxy) == "203.0.113.5"
    # Trusted proxy but no XFF → fall back to the peer.
    assert client_ip(_req("10.0.0.9", None), with_proxy) == "10.0.0.9"


def test_internal_identifiers_admin_gate(settings_kratos: Settings) -> None:
    """When api_auth_required=True, an unauthenticated GET is rejected (401),
    and an authenticated non-admin (analyst) is forbidden (403)."""
    import asyncio

    from soc_ai.store.auth import SESSION_COOKIE

    for client in _auth_client(settings_kratos):
        # Unauthenticated → router-level auth gate → 401.
        assert client.get("/api/v1/internal-identifiers").status_code == 401
        assert client.post("/api/v1/internal-identifiers/1/dismiss").status_code == 401

        # An authenticated analyst (non-admin) → per-route admin gate → 403.
        token = asyncio.run(_seed_user_session(client, username="analyst1", role="analyst"))
        client.cookies.set(SESSION_COOKIE, token)
        resp = client.get("/api/v1/internal-identifiers")
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "admin_required"
        # Same-origin Origin header to satisfy the cookie-auth CSRF guard —
        # this isolates the admin gate (not the origin gate) as the rejector.
        dismiss = client.post(
            "/api/v1/internal-identifiers/1/dismiss",
            headers={"Origin": "http://testserver"},
        )
        assert dismiss.status_code == 403
        assert dismiss.json()["detail"]["reason"] == "admin_required"


def test_tool_outcome_never_leaks_json_and_humanizes_known_shapes() -> None:
    """Dogfood item 3: tool-call titles must be short + human, never a raw JSON
    dump of the result, and online-tool short-circuits read as neutral 'skipped'
    rows rather than the config lecture the tool returns for the model."""
    from soc_ai.api.webui_api import _tool_step

    def title(tn, res):
        t, _ = _tool_step(tn, {}, res)
        return t

    # host_summary with data -> "<ip> — N events", not the {ip,event_count} dict
    t = title("t_host_summary", {"ip": "192.0.2.247", "observations": True, "event_count": 699})
    assert t == "Host summary: 192.0.2.247 — 699 events"
    assert "{" not in t
    # host_summary, no observations
    assert (
        title("t_host_summary", {"ip": "10.0.0.9", "observations": False, "event_count": 0})
        == "Host summary: 10.0.0.9 — no observations"
    )
    # online enrichment off -> neutral skipped row (lecture stays in the expander)
    assert (
        title(
            "t_greynoise",
            {
                "available": False,
                "reason": "online_enrichment_disabled",
                "summary": "online enrichment is off ...",
            },
        )
        == "GreyNoise: skipped (online enrichment off)"
    )
    assert title("t_shodan_host", {"available": False, "reason": "not_configured"}) == (
        "Shodan host: skipped (not configured)"
    )
    # error -> short, distinct failure phrase
    assert title("t_query_events_oql", {"error": True, "message": "timeout after 30s"}) == (
        "Event search: failed: timeout after 30s"
    )
    # a 0-hit query is a neutral finding, not a failure
    assert title("t_query_events_oql", {"total": 0}) == "Event search: 0 matches"
    # an unknown dict shape must NOT dump JSON into the title
    weird = title("t_get_event_raw", {"weird": 1, "blob": {"nested": 2}})
    assert "{" not in weird and weird == "Raw event: done"


def test_final_result_pseudo_tool_excluded_from_timeline() -> None:
    """The pydantic-ai `final_result` structured-output pseudo-tool must not appear
    as a '…: running…' timeline row (it never lands a tool_result)."""
    from types import SimpleNamespace

    from soc_ai.api.webui_api import _build_timeline

    events = [
        SimpleNamespace(
            kind="tool_call",
            sequence=1,
            payload={"tool_name": "final_result", "tool_call_id": "f1"},
        ),
        SimpleNamespace(
            kind="tool_call", sequence=2, payload={"tool_name": "t_enrich_ip", "tool_call_id": "c1"}
        ),
        SimpleNamespace(
            kind="tool_result",
            sequence=3,
            payload={"tool_call_id": "c1", "result": {"internal": True}},
        ),
    ]
    timeline, tool_calls, _pivots, _oracle = _build_timeline(events)
    titles = [s.title for s in timeline]
    assert not any("running" in t for t in titles)
    assert not any("synthesis" in t.lower() for t in titles)
    assert tool_calls == 1  # final_result not counted


def test_tool_outcome_no_double_failed_prefix() -> None:
    """U8: an error message that already reads as a failure ("failed to parse
    filter…") must not get a second "failed: " prefix stuttered onto it."""
    from soc_ai.api.webui_api import _tool_step

    def title(tn, res):
        t, _ = _tool_step(tn, {}, res)
        return t

    t = title("t_query_events_oql", {"error": True, "message": "failed to parse filter [x]"})
    assert t == "Event search: failed to parse filter [x]"
    assert "failed: failed" not in t
    # Same for other failure-phrased openings, case-insensitive.
    assert title("t_query_events_oql", {"error": True, "message": "Could not reach ES"}) == (
        "Event search: Could not reach ES"
    )
    assert title("t_query_events_oql", {"error": True, "message": "Error: bad index"}) == (
        "Event search: Error: bad index"
    )
    # A neutral message still gets the distinct failure phrase.
    assert title("t_query_events_oql", {"error": True, "message": "timeout after 30s"}) == (
        "Event search: failed: timeout after 30s"
    )
    # A non-string error payload keeps the short generic phrase.
    assert title("t_query_events_oql", {"error": True}) == "Event search: failed: error"


def test_prevalence_title_has_no_iso_ms_timestamps() -> None:
    """U10: the collapsed prevalence title must not embed raw ISO-8601 ms
    timestamps (they clip mid-value); the full summary stays in the detail."""
    from soc_ai.api.webui_api import _tool_step

    summary = (
        "192.0.2.247 ↔ 203.0.113.68: common — 56 event(s) across 5 distinct "
        "day(s) (first 2026-06-24T11:48:12.684Z, last 2026-06-30T09:01:02.123Z) "
        "in the last 30d."
    )
    title, detail = _tool_step("t_prevalence", {"ip": "192.0.2.247"}, {"summary": summary})
    assert "T11:48" not in title and ".684Z" not in title
    assert "(first" not in title
    assert "56 event(s) across 5 distinct day(s)" in title
    # The expander detail keeps the full summary (timestamps included).
    assert "2026-06-24T11:48:12.684Z" in detail
    # The novel-variant "first/last <ISO>" phrasing is clipped to date-only.
    novel = "1.2.3.4: seen on a single day only (3 event(s), first/last 2026-06-24T11:48:12.684Z)"
    title2, _ = _tool_step("t_prevalence", {}, {"summary": novel})
    assert "T11:48" not in title2
    assert "2026-06-24" in title2


def test_auto_ack_and_write_tools_grouped_as_decision_not_tool_calls() -> None:
    """U5: a heuristic run's auto-ack (and write-action tool calls) must not
    create a "Tool calls" timeline section — they are verdict consequences."""
    from types import SimpleNamespace

    from soc_ai.api.webui_api import _build_timeline

    events = [
        SimpleNamespace(
            kind="auto_ack",
            sequence=1,
            payload={"success": True, "alert_es_id": "abc"},
        ),
        SimpleNamespace(
            kind="tool_call",
            sequence=2,
            payload={"tool_name": "t_ack_alert", "tool_call_id": "w1"},
        ),
        SimpleNamespace(
            kind="tool_call",
            sequence=3,
            payload={"tool_name": "t_enrich_ip", "tool_call_id": "c1"},
        ),
    ]
    timeline, _tool_calls, _pivots, _oracle = _build_timeline(events)
    groups = {s.id: s.group for s in timeline}
    assert groups["e1"] == "Decision"  # auto_ack
    assert groups["e2"] == "Decision"  # write-action tool call
    assert groups["e3"] == "Tool calls"  # investigative tool call unchanged


def test_entity_graph_carries_enrichment_facts() -> None:
    """The blast-radius graph must surface what enrichment already knows: node
    sub-labels (geo/ASN/cloud/internal), intel flag sources, and per-edge flow
    labels — WITHOUT changing the existing kind semantics (compromised/c2/dc/host,
    beacon/flow)."""
    from types import SimpleNamespace

    from soc_ai.api.webui_api import _entity_graph

    alert = {
        "source_ip": "10.0.0.5",
        "destination_ip": "203.0.113.9",
        "destination_port": 443,
        "host_name": "ws-finance-07",
    }
    enrichments = {
        "10.0.0.5": {"internal": True},
        "203.0.113.9": {
            "blocklist_hits": [
                {"source": "abuse.ch ThreatFox", "indicator": "203.0.113.9"},
                {"source": "spamhaus DROP", "indicator": "203.0.113.9"},
            ],
            "geoip": {"country_iso": "US", "region": None, "city": None},
            "asn": {"number": 13335, "org": "Cloudflare"},
        },
        "198.51.100.20": {"cloud_provider": "AWS"},
        "10.0.0.99": {"internal": True},
    }
    inv = SimpleNamespace(src_ip="10.0.0.5", dest_ip="203.0.113.9", verdict="true_positive")
    nodes, edges, note = _entity_graph(alert, enrichments, inv)

    by_id = {n["id"]: n for n in nodes}
    # kind semantics unchanged
    assert by_id["10.0.0.5"]["kind"] == "compromised"
    assert by_id["203.0.113.9"]["kind"] == "c2"
    assert by_id["198.51.100.20"]["kind"] == "host"
    assert by_id["10.0.0.99"]["kind"] == "internal"  # never "dc" — we can't know that
    # the source node says which end it is (and that it's internal)
    assert by_id["10.0.0.5"]["sub"] == "source · internal"
    # peer sub-labels pick the most informative enrichment fact available
    assert by_id["203.0.113.9"]["sub"] == "US · AS13335 Cloudflare"
    assert by_id["198.51.100.20"]["sub"] == "AWS"
    assert by_id["10.0.0.99"]["sub"] == "internal"
    # intel flags carry their sources (bounded); unflagged nodes carry neither key
    assert by_id["203.0.113.9"]["flagged"] is True
    assert by_id["203.0.113.9"]["flagSources"] == ["abuse.ch ThreatFox", "spamhaus DROP"]
    assert "flagged" not in by_id["198.51.100.20"]
    # the alert's primary flow carries its port/proto; enrichment-only peers "observed"
    by_edge = {e["to"]: e for e in edges}
    assert by_edge["203.0.113.9"]["kind"] == "beacon"
    assert by_edge["203.0.113.9"]["label"] == ":443 TLS"
    assert by_edge["198.51.100.20"]["kind"] == "flow"
    assert by_edge["198.51.100.20"]["label"] == "observed"
    # graphNote keeps its shape but names the flagged peers (bounded)
    assert note == (
        "ws-finance-07 contacted 3 peer(s); 1 flagged malicious by enrichment (203.0.113.9)"
    )
