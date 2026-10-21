"""Dogfood 2026-10-19, Alerts and investigations: the backend half of the fixes.

Each block names the finding it closes. Every positive test has a negative
control beside it: the path the fix must leave alone. R2-D1 lives in
tests/test_analyst_verdict_guard.py.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui._timeline import _build_timeline, _entity_graph, _graph_scope
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.webui.alerts_query import AlertEvent, AlertGroup, GroupPage


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _run(
    client: TestClient,
    *,
    alert_es_id: str,
    rule_name: str,
    verdict: str | None = "true_positive",
    status: str = "complete",
    started_by: str = "tester",
    kind: str = "suricata",
    age_minutes: int = 0,
    report: dict[str, Any] | None = None,
) -> str:
    async def _go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(
                db,
                alert_es_id=alert_es_id,
                started_by=started_by,
                rule_name=rule_name,
                kind=kind,
            )
            if status != "running":
                await inv_svc.finalize(
                    db,
                    inv.id,
                    status=status,
                    verdict=verdict,
                    confidence=0.7 if verdict else None,
                    report=report,
                )
            if age_minutes:
                inv.created_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
                    minutes=age_minutes
                )
                await db.commit()
            return str(inv.id)

    return asyncio.run(_go())


# ── R2-D3: the Alerts row opens the alert's standing run ────────────────────


def _row(client: TestClient, rule: str, latest_id: str) -> dict[str, Any]:
    groups = [
        AlertGroup(
            rule_name=rule,
            count=1,
            severity="high",
            latest_ts="2026-10-19T10:00:00Z",
            latest_id=latest_id,
            kind="suricata",
        )
    ]
    with patch(
        "soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=GroupPage(groups, 1))
    ):
        body = client.get("/api/v1/alerts").json()
    return dict(body["groups"][0])


def test_the_row_opens_the_newer_run_of_the_same_alert(client: TestClient) -> None:
    """The newer run carries another name: a lead promotion of the alert."""
    rule = "ET EXPLOIT Possible GoldenPac Priv Esc in-use"
    _run(client, alert_es_id="ev-gp", rule_name=rule, age_minutes=60)
    lead_run = _run(client, alert_es_id="ev-gp", rule_name="Lead 12 on 192.0.2.10", kind="lead")

    row = _row(client, rule, "ev-gp")

    assert row["invId"] == lead_run


def test_a_newer_run_of_another_alert_leaves_the_row_alone(client: TestClient) -> None:
    """NEGATIVE CONTROL. Only the same alert moves the row."""
    rule = "ET EXPLOIT Possible GoldenPac Priv Esc in-use"
    own = _run(client, alert_es_id="ev-gp", rule_name=rule, age_minutes=60)
    _run(client, alert_es_id="ev-other", rule_name="Lead 12 on 192.0.2.10", kind="lead")

    assert _row(client, rule, "ev-gp")["invId"] == own


# ── R2-D4: an override on a superseded record is refused ────────────────────


def test_an_override_on_a_superseded_run_is_a_409(client: TestClient) -> None:
    old = _run(client, alert_es_id="ev-ov", rule_name="ET X", age_minutes=60)
    newer = _run(client, alert_es_id="ev-ov", rule_name="ET X", verdict="false_positive")

    refused = client.post(
        f"/api/v1/investigations/{old}/override", json={"verdict": "false_positive"}
    )
    assert refused.status_code == 409
    assert refused.json()["detail"]["reason"] == "superseded"
    assert refused.json()["detail"]["invId"] == newer

    # NEGATIVE CONTROL: the standing run takes the override.
    ok = client.post(f"/api/v1/investigations/{newer}/override", json={"verdict": "true_positive"})
    assert ok.status_code == 200


def test_an_in_flight_newer_run_also_refuses_the_override(client: TestClient) -> None:
    old = _run(client, alert_es_id="ev-fl", rule_name="ET X", age_minutes=60)
    running = _run(client, alert_es_id="ev-fl", rule_name="ET X", status="running")

    refused = client.post(
        f"/api/v1/investigations/{old}/override", json={"verdict": "false_positive"}
    )
    assert refused.status_code == 409
    assert refused.json()["detail"]["invId"] == running


# ── R2-D12: the NMI run links the run that answered it ──────────────────────


def _fake_manager(client: TestClient, status: str = "running") -> Any:
    """A hunt manager whose start writes a real row, as the real one does."""

    async def start(_state: Any, *, alert_id: str, started_by: str, **_kw: Any) -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(db, alert_es_id=alert_id, started_by=started_by)
            if status != "running":
                await inv_svc.finalize(db, inv.id, status=status)
            return str(inv.id)

    mgr = AsyncMock()
    mgr.start = start
    return mgr


def test_a_backtest_nmi_run_links_its_answer_and_refuses_a_second_press(
    client: TestClient,
) -> None:
    """A backtest replay stands alone, so the alert group never linked it to
    the live run Request more info started. The page now names that run, and
    a second press starts nothing."""
    nmi = _run(
        client,
        alert_es_id="ev-nmi",
        rule_name="Weak Encryption Enabled and Kerberoast",
        verdict="needs_more_info",
        started_by="backtest",
        age_minutes=60,
    )
    with patch("soc_ai.api.webui_api.hunt_manager.get_manager", return_value=_fake_manager(client)):
        first = client.post(f"/api/v1/investigations/{nmi}/request-more-info")
        assert first.status_code == 200
        answer = first.json()["investigation_id"]

        detail = client.get(f"/api/v1/investigations/{nmi}").json()
        assert detail["supersededBy"] == answer
        assert detail["supersededRun"]["id"] == answer

        second = client.post(f"/api/v1/investigations/{nmi}/request-more-info")
    assert second.status_code == 409
    assert second.json()["detail"]["reason"] == "already_answered"
    assert second.json()["detail"]["invId"] == answer


def test_a_failed_answer_leaves_the_nmi_run_open(client: TestClient) -> None:
    """NEGATIVE CONTROL. An answer that errored answers nothing."""
    nmi = _run(
        client,
        alert_es_id="ev-nmi-2",
        rule_name="ET NMI",
        verdict="needs_more_info",
        started_by="backtest",
        age_minutes=60,
    )
    with patch(
        "soc_ai.api.webui_api.hunt_manager.get_manager",
        return_value=_fake_manager(client, status="error"),
    ):
        assert client.post(f"/api/v1/investigations/{nmi}/request-more-info").status_code == 200
        assert client.get(f"/api/v1/investigations/{nmi}").json()["supersededBy"] is None
        again = client.post(f"/api/v1/investigations/{nmi}/request-more-info")
    assert again.status_code == 200


# ── R2-D6: the timeline shows operator text, never the prompt ───────────────


def _step(events: list[Any], seq: int) -> Any:
    return {s.id: s for s in _build_timeline(events)[0]}[f"e{seq}"]


def test_the_dossier_step_shows_host_lines_only() -> None:
    from soc_ai.dossier.prompt import _assemble

    block = _assemble(
        [
            "- 192.0.2.5 (source) — role: workstation [inferred]\n  hostname: ws-01 [dns]",
            "- (+2 more hosts omitted for space. Call `t_host_dossier` for them.)",
        ]
    )
    events = [
        SimpleNamespace(
            kind="host_dossier",
            sequence=1,
            payload={"hosts": {"192.0.2.5": "source"}, "hosts_omitted": 2, "block": block},
        )
    ]
    detail = _step(events, 1).detail
    assert "192.0.2.5 (source)" in detail
    assert "hostname: ws-01" in detail
    assert "2 more host(s) not described." in detail
    for prompt_text in ("Do not cite", "t_host_dossier", "Simplified Technical English", "##"):
        assert prompt_text not in detail


def test_the_zeek_prefetch_hint_reads_as_what_happened() -> None:
    events = [
        SimpleNamespace(
            kind="tool_call",
            sequence=1,
            payload={
                "tool_name": "t_query_zeek_logs",
                "args": {"community_id": "1:abc="},
                "tool_call_id": "c1",
            },
        ),
        SimpleNamespace(
            kind="tool_result",
            sequence=2,
            payload={
                "tool_call_id": "c1",
                "result": {
                    "prefetch_already_has_this": True,
                    "community_id": "1:abc=",
                    "hint": "The orchestrator already pre-fetched events. Read those.",
                },
            },
        ),
    ]
    detail = _step(events, 1).detail
    assert "soc-ai already loaded the Zeek events of this flow." in detail
    assert "orchestrator" not in detail


def test_internal_labels_do_not_reach_the_timeline() -> None:
    events = [
        SimpleNamespace(kind="session_start", sequence=1, payload={"pipeline": "synth_first"}),
        SimpleNamespace(
            kind="investigation_loop_entered",
            sequence=2,
            payload={"reason": "definitely_investigate", "round1_verdict": None},
        ),
        SimpleNamespace(
            kind="decision_template_match",
            sequence=3,
            payload={
                "matched": True,
                "template_id": "clean_internal_traffic",
                "verdict": "false_positive",
                "confidence": 0.85,
                "rationale": "Both hosts are internal.",
            },
        ),
        SimpleNamespace(
            kind="investigation_loop_entered",
            sequence=4,
            payload={
                "reason": "verdict_not_evidence_backed",
                "round1_verdict": "false_positive",
                "round1_confidence": 0.6,
            },
        ),
    ]
    assert "synth_first" not in _step(events, 1).detail
    # A stored run without the trigger states no cause (round 2, V1-A1).
    assert _step(events, 2).detail == (
        "A soc-ai rule sends this alert to the full investigation. soc-ai skipped the first pass."
    )
    template = _step(events, 3).detail
    assert "→" not in template
    assert "The pattern gives a false positive at 0.85." in template
    assert _step(events, 4).detail == (
        "The first-pass verdict has no evidence behind it. "
        "The first pass reached a false positive at 0.60."
    )


# ── R2-D9: a re-run does not read its own earlier run as the session ────────


async def test_session_verdicts_leave_out_the_alerts_own_runs(settings_kratos: Settings) -> None:
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    session = "1:hV6oYm5cQ8mQPWNQdCJvL5cM7YM="
    async with maker() as db:
        ids = {}
        for alert in ("this-alert", "other-alert"):
            inv = await inv_svc.create(db, alert_es_id=alert, started_by="t")
            await inv_svc.set_alert_fields(db, inv.id, community_id=session)
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="false_positive", confidence=0.8
            )
            ids[alert] = inv.id

        got = await inv_svc.session_verdicts(
            db, community_id=session, exclude_alert_es_id="this-alert"
        )
        # NEGATIVE CONTROL: without the alert id both rows still come back.
        both = await inv_svc.session_verdicts(db, community_id=session)
    await engine.dispose()

    assert [d["id"] for d in got] == [ids["other-alert"]]
    assert {d["id"] for d in both} == set(ids.values())


# ── R2-D10: lateral movement only when both ends are internal ───────────────


def _inv(verdict: str, src: str, dst: str) -> Any:
    return SimpleNamespace(verdict=verdict, src_ip=src, dest_ip=dst)


def test_an_external_source_is_inbound_and_not_compromised() -> None:
    alert = {"source_ip": "198.51.100.77", "destination_ip": "192.0.2.42"}
    enrichments = {"198.51.100.77": {"internal": False}, "192.0.2.42": {"internal": True}}
    inv = _inv("true_positive", "198.51.100.77", "192.0.2.42")

    assert _graph_scope(alert, enrichments, inv) == "inbound"
    nodes, _edges, _note = _entity_graph(alert, enrichments, inv)
    src = next(n for n in nodes if n["id"] == "198.51.100.77")
    assert src["kind"] == "host"
    assert src["sub"] == "source · external"


def test_an_internal_pair_is_lateral_and_the_tp_source_compromised() -> None:
    """NEGATIVE CONTROL. Real lateral movement keeps both labels."""
    alert = {"source_ip": "192.0.2.20", "destination_ip": "192.0.2.40"}
    enrichments = {"192.0.2.20": {"internal": True}, "192.0.2.40": {"internal": True}}
    inv = _inv("true_positive", "192.0.2.20", "192.0.2.40")

    assert _graph_scope(alert, enrichments, inv) == "lateral"
    nodes, _edges, _note = _entity_graph(alert, enrichments, inv)
    assert next(n for n in nodes if n["id"] == "192.0.2.20")["kind"] == "compromised"
    no_dst = _inv("true_positive", "192.0.2.20", "")
    assert _graph_scope({"source_ip": "192.0.2.20"}, enrichments, no_dst) is None


def test_outbound_is_named() -> None:
    alert = {"source_ip": "192.0.2.20", "destination_ip": "203.0.113.9"}
    enrichments = {"192.0.2.20": {"internal": True}, "203.0.113.9": {"internal": False}}
    assert _graph_scope(alert, enrichments, _inv("false_positive", "", "")) == "outbound"


# ── R2-D11: the rule base rate is anchored on the alert time ────────────────


def _ranges(node: Any) -> list[Any]:
    """Every ``range`` clause anywhere in a query."""
    if isinstance(node, dict):
        found = [node] if "range" in node else []
        return found + [r for v in node.values() for r in _ranges(v)]
    if isinstance(node, list):
        return [r for v in node for r in _ranges(v)]
    return []


async def test_rule_prevalence_reads_the_window_before_the_alert(
    settings_kratos: Settings,
) -> None:
    from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
    from soc_ai.tools.rule_prevalence import rule_prevalence

    queries: list[dict[str, Any]] = []

    async def _capture(_index: str, query: dict[str, Any], **_kw: Any) -> EsSearchResult:
        queries.append(query)
        return EsSearchResult(total=0, took_ms=1, hits=[], aggregations=None)

    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()):
        elastic = ElasticClient(settings_kratos)
    elastic.search = _capture  # type: ignore[method-assign]
    anchor = datetime(2026, 9, 1, 0, 35, 45, tzinfo=UTC)

    await rule_prevalence("ET X", elastic=elastic, settings=settings_kratos, time_anchor=anchor)
    # NEGATIVE CONTROL: no anchor keeps the live window.
    await rule_prevalence("ET X", elastic=elastic, settings=settings_kratos)

    anchored = queries[0]["bool"]["filter"][0]["range"]["@timestamp"]
    assert anchored == {
        "gte": (anchor - timedelta(days=30)).isoformat(),
        "lte": anchor.isoformat(),
    }
    # The import probe of the empty answer asks about the same window.
    assert {"range": {"@timestamp": anchored}} in _ranges(queries[1])
    live = queries[2]["bool"]["filter"][0]["range"]["@timestamp"]
    assert live == {"gte": "now-30d", "lte": "now"}


# ── R2-D15: a second press says what was already done ───────────────────────


def _event(es_id: str, *, acked: bool = False, escalated: bool = False) -> AlertEvent:
    return AlertEvent(
        es_id=es_id,
        timestamp="t",
        src="192.0.2.1:5",
        dst="192.0.2.2:443",
        severity="low",
        host="ws-1",
        acknowledged=acked,
        escalated=escalated,
    )


def _hiding_grid(hidden: list[AlertEvent]) -> AsyncMock:
    """A grid that hides handled events from a hide_acked read."""

    async def fetch(*_a: Any, hide_acked: bool = False, offset: int = 0, **_kw: Any) -> Any:
        if hide_acked or offset:
            return []
        return hidden

    return AsyncMock(side_effect=fetch)


def test_a_second_ack_press_counts_what_the_grid_hid(client: TestClient) -> None:
    write = AsyncMock(return_value=(None, None))
    grid = _hiding_grid([_event("e1", acked=True), _event("e2", acked=True)])
    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", grid),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", write),
    ):
        body = client.post(
            "/api/v1/alerts/ack-group", json={"rule_name": "ET INFO Java", "range": "24h"}
        ).json()
    write.assert_not_awaited()
    assert body["acked"] == 0
    assert body["already_acked"] == 2


def test_a_second_escalate_press_names_the_existing_case(client: TestClient) -> None:
    from soc_ai.store import escalations as esc_svc

    async def _ledger() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            await esc_svc.claim(db, ["e-tor"], actor="tester")
            await esc_svc.record_case(db, "e-tor", "case-tor-1")

    asyncio.run(_ledger())
    write = AsyncMock(return_value=(None, None))
    grid = _hiding_grid([_event("e-tor", acked=True, escalated=True)])
    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", grid),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", write),
    ):
        body = client.post(
            "/api/v1/alerts/escalate-group", json={"rule_name": "ET TOR", "range": "24h"}
        ).json()
    write.assert_not_awaited()
    assert body["escalated"] == 0
    assert body["already_escalated"] == 1
    assert [c["id"] for c in body["existing_cases"]] == ["case-tor-1"]


def test_a_first_press_reads_the_grid_once(client: TestClient) -> None:
    """NEGATIVE CONTROL. A press that has work to do pays for no second read."""
    write = AsyncMock(return_value=(None, None))
    grid = AsyncMock(return_value=[_event("e1")])
    with (
        patch("soc_ai.api.webui_api.aq.fetch_group_events", grid),
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", write),
    ):
        body = client.post(
            "/api/v1/alerts/ack-group", json={"rule_name": "ET INFO Java", "range": "24h"}
        ).json()
    assert body["acked"] == 1
    assert all(c.kwargs.get("hide_acked") is True for c in grid.call_args_list)


def test_the_detail_carries_the_scope_and_the_host_window(
    client: TestClient, settings_kratos: Settings
) -> None:
    """R2-D10 and R2-D21 on the wire: the page reads both from the detail."""
    run = _run(client, alert_es_id="ev-wire", rule_name="ET X")

    async def _endpoints() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await db.get(inv_svc.Investigation, run)
            inv.src_ip = "198.51.100.77"
            inv.dest_ip = "192.0.2.42"
            await db.commit()

    asyncio.run(_endpoints())
    body = client.get(f"/api/v1/investigations/{run}").json()
    # No enrichment on the row: TEST-NET addresses are not global, so both
    # ends read internal by the fallback.
    assert body["graphScope"] == "lateral"
    assert body["hostContextWindowHours"] == settings_kratos.host_risk_window_hours


# ── R2 STE items 9 to 13: the timeline restates model-facing tool text ──────


def _tool_detail(tool: str, args: dict[str, Any], result: dict[str, Any]) -> Any:
    events = [
        SimpleNamespace(
            kind="tool_call",
            sequence=1,
            payload={"tool_name": tool, "args": args, "tool_call_id": "c1"},
        ),
        SimpleNamespace(
            kind="tool_result", sequence=2, payload={"tool_call_id": "c1", "result": result}
        ),
    ]
    return _step(events, 1)


_MODEL_TEXT = ("—", " not ", "rather than", "WAYPOINT", "absence of evidence")


def _assert_operator_text(step: Any) -> None:
    for text in (step.title, step.detail.split("\nquery:")[0]):
        for bad in _MODEL_TEXT:
            assert bad not in text, (bad, text)


def test_a_prevalence_answer_reads_in_ste() -> None:
    step = _tool_detail(
        "t_prevalence",
        {"ip": "192.0.2.20", "peer_ip": "192.0.2.40"},
        {
            "observed": True,
            "first_seen": "2026-09-01T00:00:00Z",
            "last_seen": "2026-09-02T23:00:00Z",
            "total_events": 1915,
            "distinct_days": 2,
            "rarity": "concentrated",
            "summary": "192.0.2.20 <-> 192.0.2.40: concentrated — 1915 event(s) packed into "
            "just 2 distinct day(s). Heavy short-span activity, not a long-running baseline.",
        },
    )
    _assert_operator_text(step)
    assert "1915 events on 2 days" in step.detail
    assert "Rarity: concentrated." in step.detail


def test_a_rule_prevalence_burst_states_no_rate() -> None:
    """Item 10: the stored text gave a per-day rate and then called it no rate."""
    step = _tool_detail(
        "t_rule_prevalence",
        {"rule_name": "ET X"},
        {
            "observed": True,
            "lookback_days": 30,
            "total_fires": 12,
            "active_days": 1,
            "distinct_src_hosts": 1,
            "distinct_dest_hosts": 2,
            "is_burst": True,
            "fires_per_day": None,
            "noisiness": "burst",
            "summary": "'ET X' fired 12x, about 5.0/day, bursty, not a background rate: ...",
        },
    )
    _assert_operator_text(step)
    assert "The rule fired 12 times on 1 day in the 30-day window." in step.detail
    assert "The fires form one burst." in step.detail
    assert "/day" not in step.detail.split("\nquery:")[0]


def test_an_origin_chain_answer_reads_in_ste() -> None:
    step = _tool_detail(
        "t_origin_chain",
        {"ip": "192.0.2.20"},
        {
            "ip": "192.0.2.20",
            "observations": True,
            "lookback_minutes": 30,
            "inbound_sessions": [{"source_ip": "192.0.2.9"}, {"source_ip": "192.0.2.9"}],
            "closest_preceding": {"source_ip": "192.0.2.9", "seconds_before": 42.0},
            "summary": "2 inbound sessions ... This host may be a WAYPOINT rather than the origin",
        },
    )
    _assert_operator_text(step)
    assert (
        "2 inbound remote-access sessions reached 192.0.2.20 in the 30 minutes "
        "before the activity." in step.detail
    )
    assert "The closest came from 192.0.2.9, 42 seconds before." in step.detail


def test_a_rule_tuning_answer_reads_in_ste() -> None:
    step = _tool_detail(
        "t_suggest_rule_tuning",
        {"rule_name": "ET X"},
        {
            "alert_count": 0,
            "lookback_days": 7,
            "recommendation": "none",
            "summary": "fired 0x in 7d — that is an absence of evidence, not evidence of "
            "absence — recommendation: none",
        },
    )
    _assert_operator_text(step)
    assert "The rule raised 0 alerts in the 7-day window. The recommendation is none." in (
        step.detail
    )


def test_control_another_tool_keeps_its_own_summary() -> None:
    step = _tool_detail("t_host_summary", {"ip": "192.0.2.20"}, {"summary": "A plain answer."})
    assert "result: A plain answer." in step.detail


# ── stored shapes the STE summaries must survive ─────────────────────────────


@pytest.mark.parametrize(
    ("tool", "args", "result"),
    [
        # The demo fixtures store the call arguments as a string.
        ("t_prevalence", "ip=192.0.2.5", {"total_events": 4, "distinct_days": 2, "observed": True}),
        # An older run stored a rarity object where a word is now.
        (
            "t_prevalence",
            {"ip": "192.0.2.5"},
            {"total_events": 4, "distinct_days": 2, "observed": True, "first_seen": {"t": 1}},
        ),
        (
            "t_origin_chain",
            {},
            {
                "lookback_minutes": 30,
                "ip": "192.0.2.5",
                "observations": 1,
                "inbound_sessions": "two",
                "closest_preceding": {"source_ip": "198.51.100.7", "seconds_before": "soon"},
            },
        ),
        (
            "t_rule_prevalence",
            {},
            {"total_fires": 3, "lookback_days": 30, "fires_per_day": "a few"},
        ),
    ],
)
def test_an_odd_stored_shape_never_fails_the_summary(tool: str, args: Any, result: Any) -> None:
    """A summary that cannot read its fields returns a sentence or None, never raises.

    The demo detail page answered 500 for every investigation after the STE
    summaries landed, because the stored arguments were a string.
    """
    from soc_ai.api.webui._timeline import _ste_tool_summary, _tool_step

    out = _ste_tool_summary(tool, args, result)
    assert out is None or isinstance(out, str)
    title, _detail = _tool_step(tool, args if isinstance(args, dict) else {}, result)
    assert title
