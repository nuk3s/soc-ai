"""Dogfood 2026-10-06, the investigation page: the backend half of the fixes.

Each block names the finding it closes. Every positive test has a negative
control beside it: the path the guard must leave alone.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui._timeline import _alert_ack_state, _build_actions
from soc_ai.config import Settings
from soc_ai.main import create_app


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


async def _seed(
    client: TestClient,
    *,
    alert_es_id: str,
    actions: list[dict[str, Any]],
    rule_name: str | None = None,
    verdict: str | None = None,
    confidence: float | None = None,
    status: str = "complete",
    summary: str | None = None,
    rationale: str | None = None,
) -> str:
    from soc_ai.store import investigations as inv_svc

    async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
        inv = await inv_svc.create(
            db, alert_es_id=alert_es_id, started_by="tester", rule_name=rule_name
        )
        inv.report = {"recommended_actions": actions, "summary": summary or ""}
        inv.verdict = verdict
        inv.confidence = confidence
        inv.status = status
        inv.rationale = rationale
        await db.commit()
        return str(inv.id)


def _write_tool(calls: list[dict[str, Any]], result: dict[str, Any]) -> Any:
    from soc_ai.tools._registry import ToolSpec

    async def fn(
        alert_id: str, comment: str | None = None, *, auth: Any, settings: Any = None
    ) -> dict[str, Any]:
        calls.append({"alert_id": alert_id})
        return result

    return ToolSpec(name="ack_alert", read_only=False, description="", func=fn)


# ── S3: every executed action names who and when, and the card follows the grid ──

_ACK = {"tool_name": "ack_alert", "rationale": "benign"}
_ESC = {"tool_name": "escalate_to_case", "rationale": "case it"}


def _marker(payload: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(kind="action_executed", payload={"success": True, **payload})


def test_an_executed_action_names_its_actor_and_time() -> None:
    ev = _marker(
        {
            "index": 1,
            "tool_name": "escalate_to_case",
            "by": "alice",
            "at": "2026-10-06T11:09:00+00:00",
            "detail": "soc-ai created case 7.",
        }
    )
    out = _build_actions([ev], {"recommended_actions": [_ACK, _ESC]})
    assert out[1].applied is True
    assert out[1].appliedBy == "alice"
    assert out[1].appliedAt == "2026-10-06T11:09:00+00:00"
    assert out[1].appliedDetail == "soc-ai created case 7."
    # Negative control: the sibling nobody executed names nobody.
    assert out[0].applied is False
    assert out[0].appliedBy is None and out[0].appliedAt is None


def test_an_auto_ack_names_auto_ack_and_the_run_time() -> None:
    ev = SimpleNamespace(kind="auto_ack", payload={"success": True})
    out = _build_actions([ev], {"recommended_actions": [_ACK]}, ran_at="2026-10-06T03:12:00+00:00")
    assert out[0].applied is True
    assert out[0].appliedBy == "auto-ack"
    assert out[0].appliedAt == "2026-10-06T03:12:00+00:00"


def test_an_ack_the_grid_shows_unacknowledged_does_not_read_executed() -> None:
    """The range case: a group ack covered eight other alerts of the rule, and
    the alert of this run stayed unacknowledged. The card said "Executed"."""
    ev = _marker(
        {
            "index": 0,
            "tool_name": "ack_alert",
            "by": "anonymous",
            "group": True,
            "at": "2026-10-06T11:09:00+00:00",
        }
    )
    report = {"recommended_actions": [_ACK]}
    stale = _build_actions([ev], report, alert_unacked=True)[0]
    assert stale.applied is False
    assert stale.pendingNote is not None and "not acknowledged" in stale.pendingNote
    assert "other alerts of this rule" in stale.pendingNote
    # The earlier write is still named, so nothing is hidden.
    assert stale.appliedBy == "anonymous"
    # Negative control: a grid that did not answer proves nothing. The record stands.
    assert _build_actions([ev], report, alert_unacked=False)[0].applied is True


def test_the_grid_rule_touches_only_the_ack() -> None:
    ev = _marker({"index": 0, "tool_name": "escalate_to_case", "by": "alice"})
    out = _build_actions([ev], {"recommended_actions": [_ESC]}, alert_unacked=True)
    assert out[0].applied is True


def test_an_auto_ack_the_grid_undid_is_offered_again() -> None:
    ev = SimpleNamespace(kind="auto_ack", payload={"success": True})
    out = _build_actions([ev], {"recommended_actions": [_ACK]}, alert_unacked=True)
    assert out[0].applied is False
    assert out[0].pendingNote == "Security Onion shows this alert as not acknowledged."


def test_the_ack_probe_has_three_answers(settings_kratos: Settings) -> None:
    def es(hits: list[dict[str, Any]]) -> Any:
        return SimpleNamespace(search=AsyncMock(return_value=SimpleNamespace(hits=hits)))

    acked = es([{"_id": "a", "_source": {"event": {"acknowledged": True}}}])
    unacked = es([{"_id": "a", "_source": {"event": {"acknowledged": False}}}])
    boom = SimpleNamespace(search=AsyncMock(side_effect=RuntimeError("down")))
    assert asyncio.run(_alert_ack_state(acked, settings_kratos, "a")) is True
    assert asyncio.run(_alert_ack_state(unacked, settings_kratos, "a")) is False
    # A miss, an error and no id are "the grid did not say", never "not acked".
    assert asyncio.run(_alert_ack_state(es([]), settings_kratos, "a")) is None
    assert asyncio.run(_alert_ack_state(boom, settings_kratos, "a")) is None
    assert asyncio.run(_alert_ack_state(acked, settings_kratos, None)) is None


def test_an_execute_receipt_carries_its_time(client: TestClient) -> None:
    inv_id = asyncio.run(_seed(client, alert_es_id="es-t-1", actions=[_ESC]))
    calls: list[dict[str, Any]] = []
    with (
        patch(
            "soc_ai.tools.write_exec.get_tool",
            return_value=_write_tool(
                calls, {"id": "C-1", "alert_linked": True, "marked_escalated": True}
            ),
        ),
        patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)),
    ):
        assert (
            client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()["status"]
            == "executed"
        )
        detail = client.get(f"/api/v1/investigations/{inv_id}").json()
    action = detail["actions"][0]
    assert action["applied"] is True
    assert action["appliedBy"]
    assert action["appliedAt"] and action["appliedAt"].endswith("+00:00")


# ── First hour S2: the ack states its scope before the click ────────────────


def _ev(es_id: str, src_ip: str) -> Any:
    from soc_ai.webui.alerts_query import AlertEvent

    return AlertEvent(
        es_id=es_id,
        timestamp="2026-10-06T00:00:00Z",
        src=src_ip,
        dst="192.0.2.200",
        severity="medium",
        host="sensor",
        src_ip=src_ip,
        dst_ip="192.0.2.200",
    )


_GROUP = [_ev("e1", "192.0.2.1"), _ev("e2", "192.0.2.1"), _ev("e3", "192.0.2.2")]


async def _seed_tp_on(client: TestClient, es_id: str) -> None:
    from soc_ai.store import investigations as inv_svc

    async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
        inv = await inv_svc.create(db, alert_es_id=es_id, started_by="t", rule_name="R")
        inv.verdict = "true_positive"
        inv.status = "complete"
        await db.commit()


def _ack_fixture(client: TestClient) -> str:
    inv_id = asyncio.run(_seed(client, alert_es_id="own", rule_name="R", actions=[_ACK]))
    asyncio.run(_seed_tp_on(client, "e3"))
    return inv_id


def test_the_ack_scope_names_count_hosts_window_and_held(client: TestClient) -> None:
    inv_id = _ack_fixture(client)
    with (
        patch("soc_ai.webui.alerts_query.fetch_group_events", AsyncMock(return_value=_GROUP)),
        patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=False)),
    ):
        body = client.get(f"/api/v1/investigations/{inv_id}/actions/0/scope").json()
    assert body["scope"] == "group"
    # e1 and e2, plus the alert of this run, which sits outside the window.
    # e3 carries a true positive verdict of its own and is held back.
    assert body["count"] == 3
    assert body["hosts"] == 1
    assert body["held"] == 1
    assert body["sentence"] == (
        "Acknowledge 3 alerts of this rule from the last 7 days, on 1 host. "
        "soc-ai leaves 1 alert with a true positive or needs more info verdict open."
    )


def test_the_group_ack_writes_the_plan_and_reports_the_count(client: TestClient) -> None:
    inv_id = _ack_fixture(client)
    calls: list[dict[str, Any]] = []
    with (
        patch("soc_ai.webui.alerts_query.fetch_group_events", AsyncMock(return_value=_GROUP)),
        patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=False)),
        patch("soc_ai.tools.write_exec.get_tool", return_value=_write_tool(calls, {"ok": True})),
    ):
        body = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()
    assert body["status"] == "executed"
    assert body["count"] == 3
    assert body["detail"].startswith("Acknowledged 3 alerts of this rule from the last 7 days.")
    assert sorted(c["alert_id"] for c in calls) == ["e1", "e2", "own"]
    # Negative control: the true positive alert is never acknowledged.
    assert "e3" not in {c["alert_id"] for c in calls}


def test_acknowledge_this_alert_only_writes_one_alert(client: TestClient) -> None:
    inv_id = _ack_fixture(client)
    calls: list[dict[str, Any]] = []
    fetch = AsyncMock(return_value=_GROUP)
    with (
        patch("soc_ai.webui.alerts_query.fetch_group_events", fetch),
        patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=False)),
        patch("soc_ai.tools.write_exec.get_tool", return_value=_write_tool(calls, {"ok": True})),
    ):
        body = client.post(
            f"/api/v1/investigations/{inv_id}/actions/0/execute", json={"scope": "alert"}
        ).json()
        assert body["status"] == "executed"
        assert [c["alert_id"] for c in calls] == ["own"]
        fetch.assert_not_called()
        # After an earlier write that left this alert open, "this alert only"
        # still writes. Negative control: a group press repeats nothing.
        again = client.post(
            f"/api/v1/investigations/{inv_id}/actions/0/execute", json={"scope": "alert"}
        ).json()
        assert again["status"] == "executed"
        assert [c["alert_id"] for c in calls] == ["own", "own"]
        group = client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute").json()
        assert group["detail"] == "Already executed. soc-ai did not repeat it."
        assert len(calls) == 2


def test_the_escalate_scope_is_one_case_for_this_alert(client: TestClient) -> None:
    inv_id = asyncio.run(_seed(client, alert_es_id="own", rule_name="R", actions=[_ESC]))
    body = client.get(f"/api/v1/investigations/{inv_id}/actions/0/scope").json()
    assert body == {
        "tool": "escalate_to_case",
        "scope": "alert",
        "count": 1,
        "hosts": None,
        "held": 0,
        "rangeLabel": "",
        "sentence": "Open one Security Onion case for this alert.",
    }


def test_an_ack_with_no_group_falls_back_to_this_alert(client: TestClient) -> None:
    inv_id = asyncio.run(_seed(client, alert_es_id="own", rule_name="R", actions=[_ACK]))
    with patch("soc_ai.webui.alerts_query.fetch_group_events", AsyncMock(return_value=[])):
        body = client.get(f"/api/v1/investigations/{inv_id}/actions/0/scope").json()
    assert body["scope"] == "alert"
    assert body["sentence"] == "Acknowledge this alert in Security Onion."


# ── First hour S4: a dismissal is stored with the actor and the time ───────


def test_a_dismissal_is_stored_and_can_be_undone(client: TestClient) -> None:
    inv_id = asyncio.run(_seed(client, alert_es_id="own", actions=[_ACK, _ESC]))
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        out = client.post(f"/api/v1/investigations/{inv_id}/actions/0/dismiss")
        assert out.status_code == 200
        assert out.json()["dismissed"] is True and out.json()["by"] and out.json()["at"]
        detail = client.get(f"/api/v1/investigations/{inv_id}").json()
        assert detail["actions"][0]["dismissed"] is True
        assert detail["actions"][0]["dismissedBy"] == out.json()["by"]
        assert detail["actions"][0]["dismissedAt"] == out.json()["at"]
        # Negative control: the sibling is not dismissed.
        assert detail["actions"][1]["dismissed"] is False
        # The dismissal stays out of the timeline.
        assert not any("dismiss" in step["title"].lower() for step in detail["timeline"])

        undo = client.post(f"/api/v1/investigations/{inv_id}/actions/0/restore").json()
        assert undo["dismissed"] is False
        detail = client.get(f"/api/v1/investigations/{inv_id}").json()
        assert detail["actions"][0]["dismissed"] is False


def test_an_executed_action_cannot_be_dismissed(client: TestClient) -> None:
    inv_id = asyncio.run(_seed(client, alert_es_id="own", actions=[_ESC]))
    calls: list[dict[str, Any]] = []
    with patch(
        "soc_ai.tools.write_exec.get_tool",
        return_value=_write_tool(calls, {"id": "C-1", "alert_linked": True}),
    ):
        client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute")
    resp = client.post(f"/api/v1/investigations/{inv_id}/actions/0/dismiss")
    assert resp.status_code == 409


def test_the_newest_dismissal_record_wins() -> None:
    from soc_ai.api.webui._timeline import _dismissals

    def ev(kind: str, seq: int) -> SimpleNamespace:
        return SimpleNamespace(kind=kind, sequence=seq, payload={"index": 0, "by": "a"})

    assert "#idx:0" not in _dismissals([ev("action_dismissed", 1), ev("action_restored", 2)])
    assert "#idx:0" in _dismissals([ev("action_restored", 1), ev("action_dismissed", 2)])
    # Order is by sequence, not by list position.
    assert "#idx:0" not in _dismissals([ev("action_restored", 3), ev("action_dismissed", 2)])


# ── Investigation S1: an older run names the newer run and its verdict ──────


def test_an_older_run_names_the_newer_run_and_its_verdict(client: TestClient) -> None:
    old = asyncio.run(
        _seed(client, alert_es_id="es-s1", actions=[], verdict="needs_more_info", confidence=0.5)
    )
    new = asyncio.run(
        _seed(client, alert_es_id="es-s1", actions=[], verdict="true_positive", confidence=0.65)
    )
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        older = client.get(f"/api/v1/investigations/{old}").json()
        newer = client.get(f"/api/v1/investigations/{new}").json()
    assert older["supersededBy"] == new
    assert older["supersededRun"] == {
        "id": new,
        "status": "complete",
        "verdict": "true_positive",
        "conf": 0.65,
    }
    # Negative control: the newest run names no newer run.
    assert newer["supersededBy"] is None
    assert newer["supersededRun"] is None


def test_a_running_newer_run_has_no_verdict_yet(client: TestClient) -> None:
    old = asyncio.run(
        _seed(client, alert_es_id="es-s1b", actions=[], verdict="needs_more_info", confidence=0.5)
    )
    new = asyncio.run(_seed(client, alert_es_id="es-s1b", actions=[], status="running"))
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        older = client.get(f"/api/v1/investigations/{old}").json()
    assert older["supersededRun"] == {"id": new, "status": "running", "verdict": None, "conf": None}


# ── First hour S3: an override replaces the headline and the actions ───────


def _override_seed(client: TestClient) -> str:
    return asyncio.run(
        _seed(
            client,
            alert_es_id="es-ov",
            rule_name="ET INFO Outbound MSSQL",
            actions=[{**_ACK, "rationale": "Benign MSSQL traffic."}],
            verdict="false_positive",
            confidence=0.8,
            rationale="Benign MSSQL traffic on a non-standard port.",
        )
    )


def test_a_true_positive_override_escalates_and_drops_the_ack(client: TestClient) -> None:
    inv_id = _override_seed(client)
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        out = client.post(
            f"/api/v1/investigations/{inv_id}/override",
            json={"verdict": "true_positive", "rationale": "PCAP shows exfiltration"},
        ).json()
        detail = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert out["resolvedBy"]
    assert detail["rationale"] == f"Verdict set by {out['resolvedBy']}: PCAP shows exfiltration."
    tags = [a["tag"] for a in detail["actions"]]
    assert tags == ["escalate"]
    # Negative control: the benign ack and its reason are gone.
    assert "Benign" not in " ".join(a["rationale"] for a in detail["actions"])


def test_an_override_with_no_reason_names_the_analyst(client: TestClient) -> None:
    inv_id = _override_seed(client)
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        out = client.post(
            f"/api/v1/investigations/{inv_id}/override", json={"verdict": "needs_more_info"}
        ).json()
        detail = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert detail["rationale"] == f"Verdict set by {out['resolvedBy']}."
    assert detail["actions"] == []


def test_the_escalate_an_override_adds_carries_a_case_title() -> None:
    from soc_ai.api.webui.routes_actions import _override_actions

    (esc,) = _override_actions(
        "true_positive", user="a", rule_name="R1", headline="Verdict set by a."
    )
    assert esc["tool_args"] == {"case_title": "R1", "case_description": "Verdict set by a."}
    (ack,) = _override_actions("false_positive", user="a", rule_name="R1", headline="h")
    assert ack["tool_name"] == "ack_alert"


# ── Investigation W4: the two fields the range saw rejected ────────────────


def test_soc_ai_alert_names_query_the_grid_field() -> None:
    from soc_ai.so_client.oql import GroupBy, Term, parse_oql, validate_oql

    ast = parse_oql("event_action:allowed AND source_ip:192.0.2.1 | groupby host_name")
    validate_oql(ast)
    fields = sorted(t.field for t in ast.filter_.children if isinstance(t, Term))  # type: ignore[union-attr]
    assert fields == ["event.action", "source.ip"]
    assert ast.pipes == (GroupBy(fields=("host.name",)),)


def test_the_ssh_auth_field_soc_ai_reads_is_queryable() -> None:
    from soc_ai.so_client.oql import parse_oql, validate_oql

    validate_oql(parse_oql("system.auth.ssh.event:Failed"))


def test_an_unknown_field_is_still_refused() -> None:
    from soc_ai.errors import OqlValidationError
    from soc_ai.so_client.oql import parse_oql, validate_oql

    with pytest.raises(OqlValidationError):
        validate_oql(parse_oql("event_actions:allowed"))
    with pytest.raises(OqlValidationError):
        validate_oql(parse_oql("system.cpu.total:1"))


# ── Investigation C1: the headline instruction ─────────────────────────────


def test_the_report_prompt_keeps_paths_out_of_the_headline() -> None:
    from soc_ai.agent import prompts

    texts = [v for v in vars(prompts).values() if isinstance(v, str)]
    assert any("Keep field paths, document ids and tool names out of it." in t for t in texts)
    # Negative control: the old wording that asked for a citation inside the
    # rationale text is gone.
    assert not any("must reference at least one citation" in t for t in texts)


# ── O1: the Oracle line, and the failed-run hint ───────────────────────────


def test_the_oracle_line_says_why_no_review_ran(settings_kratos: Settings) -> None:
    from soc_ai.api.webui.routes_investigations import _oracle_line

    inv = SimpleNamespace(status="complete", confidence=0.7)
    off = settings_kratos.model_copy(update={"oracle_enabled": False})
    on = settings_kratos.model_copy(
        update={"oracle_enabled": True, "oracle_escalate_below_confidence": 0.7}
    )
    assert _oracle_line(off, inv, False) == (  # type: ignore[arg-type]
        "The Oracle is off on this deployment. No verdict goes to a review."
    )
    assert _oracle_line(on, inv, False) == (  # type: ignore[arg-type]
        "Oracle review: not needed. Confidence 0.70 is above the review band."
    )
    low = SimpleNamespace(status="complete", confidence=0.55)
    assert _oracle_line(on, low, False) == (  # type: ignore[arg-type]
        "Oracle review: not run. Confidence 0.55 is under 0.70."
    )
    assert _oracle_line(on, low, True).startswith("Oracle review: done.")  # type: ignore[arg-type]
    # Negative control: no line repeats the old internal words.
    for line in (_oracle_line(off, inv, False), _oracle_line(on, inv, False)):  # type: ignore[arg-type]
        assert "local verdict" not in line


def test_the_failed_run_hint_names_no_setting() -> None:
    from soc_ai.api.webui._timeline import _failure_out

    stored = SimpleNamespace(
        kind="error",
        payload={
            "message": "investigation cancelled before reaching a verdict",
            "phase": "run_cancelled",
            "hint": "the per-target cap fired; it is floored above investigation_run_timeout_s",
        },
    )
    out = _failure_out("error", [stored])
    assert out is not None and out.hint is not None
    assert "investigation_run_timeout_s" not in out.hint
    assert out.hint.startswith("This run stopped before a verdict.")
    # Negative control: a phase with no analyst sentence keeps its stored hint.
    other = SimpleNamespace(
        kind="error", payload={"message": "boom", "phase": "synth", "hint": "Check the gateway."}
    )
    other_out = _failure_out("error", [other])
    assert other_out is not None and other_out.hint == "Check the gateway."


# ── Hunting C4: a promoted investigation names its finding first ───────────


def test_a_promoted_investigation_names_its_finding(client: TestClient) -> None:
    from soc_ai.store import hunts as hunt_svc
    from soc_ai.store import investigations as inv_svc

    findings = [
        {"title": "Port scan", "detail": "A scan.", "hosts": ["192.0.2.9"], "citations": ["d0"]},
        {
            "title": "HTTP service executes id command as root",
            "detail": "The response holds uid=0.",
            "severity": "high",
            "hosts": ["192.0.2.40", "198.51.100.30"],
            "citations": ["doc-1", "doc-2"],
        },
    ]

    async def go() -> tuple[str, str]:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            hunt = await hunt_svc.create(db, objective="Read each document id.", started_by="a")
            await hunt_svc.finalize(db, hunt.id, status="complete", report={"findings": findings})
            promoted = await inv_svc.create(
                db,
                alert_es_id="doc-1",
                started_by="a",
                kind="hunt",
                hunt_id=hunt.id,
                finding_ordinal=1,
            )
            plain = await inv_svc.create(db, alert_es_id="es-plain", started_by="a")
            return str(promoted.id), str(plain.id)

    promoted_id, plain_id = asyncio.run(go())
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        promoted = client.get(f"/api/v1/investigations/{promoted_id}").json()
        plain = client.get(f"/api/v1/investigations/{plain_id}").json()
    pf = promoted["promotedFinding"]
    assert pf["label"] == "F2"
    assert pf["title"] == "HTTP service executes id command as root"
    assert pf["citations"] == ["doc-1", "doc-2"]
    assert pf["hosts"] == ["192.0.2.40", "198.51.100.30"]
    assert pf["detail"] == "The response holds uid=0."
    # The run names no flow, so the shared builder claims no attacker.
    assert pf["attacker"] is None
    # Negative control: an alert investigation has no promoted finding.
    assert plain["promotedFinding"] is None


# ── First hour W4: the drawer's Alert details name the user ────────────────


def test_alert_details_carry_the_user_and_the_host() -> None:
    from soc_ai.api.webui._timeline import _alert_meta

    inv = SimpleNamespace(alert_es_id="es-1", rule_name="R")
    meta = _alert_meta(
        {
            "rule_name": "R",
            "user_name": "svc_backup",
            "host_name": "ws-01",
            "source_ip": "192.0.2.1",
        },
        {},
        inv,  # type: ignore[arg-type]
    )
    assert meta is not None
    assert meta["user"] == "svc_backup" and meta["host"] == "ws-01"
    # Negative control: an alert that names no user says None, never a dash.
    bare = _alert_meta({"rule_name": "R"}, {}, inv)  # type: ignore[arg-type]
    assert bare is not None and bare["user"] is None and bare["host"] is None


# ── First hour W11: a running run names its step and an estimate ──────────


def test_a_running_run_names_its_step_and_the_typical_run_time(client: TestClient) -> None:
    from datetime import timedelta

    from soc_ai.store import investigations as inv_svc

    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            for i, minutes in enumerate((2, 3, 4)):
                done = await inv_svc.create(db, alert_es_id=f"es-done-{i}", started_by="t")
                done.status = "complete"
                done.verdict = "false_positive"
                done.finished_at = done.created_at + timedelta(minutes=minutes)
            running = await inv_svc.create(db, alert_es_id="es-run", started_by="t")
            await db.commit()
            await inv_svc.append_events(
                db,
                running.id,
                [
                    {
                        "sequence": 1,
                        "kind": "tool_call",
                        "payload": {"tool_name": "t_search_events", "tool_call_id": "c1"},
                    }
                ],
            )
            return str(running.id)

    run_id = asyncio.run(go())
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        detail = client.get(f"/api/v1/investigations/{run_id}").json()
    assert detail["status"] == "investigating"
    assert detail["currentStep"]
    assert detail["typicalRun"] == {"lowMin": 2, "highMin": 4, "medianMin": 3, "samples": 3}


def test_a_finished_run_carries_no_estimate(client: TestClient) -> None:
    inv_id = asyncio.run(
        _seed(client, alert_es_id="es-fin", actions=[], verdict="false_positive", confidence=0.9)
    )
    with patch("soc_ai.api.webui._timeline._alert_ack_state", AsyncMock(return_value=None)):
        detail = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert detail["currentStep"] is None
    assert detail["typicalRun"] is None
