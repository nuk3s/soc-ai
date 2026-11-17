"""A one-time clear of old items of Needs you (owner, 2026-11-16).

Needs you has no time limit since 2026-11-15, so each undecided investigation
stays. The operator lists the old items and clears the ones before a date,
with a reason. A clear writes its audit record first. It dismisses the
waiting actions of a true positive through the dismiss path, and it records
"cleared" on a verdict that needs more info. It changes no verdict and is no
analyst override. The count and the list of Needs you read one rule.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.audit.logger import AuditWriteError
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.store import rule_prior
from soc_ai.store.models import Investigation, InvestigationEvent, RulePriorDecision
from soc_ai.webui import needs_you_clear as clear_svc
from sqlalchemy import func, select

from tests.test_campaign_facts import OUTSIDE, RULE, seed_run
from tests.test_campaign_needs_you import _do, _items, _needs_you, _seed
from tests.test_needs_you_count import _seed_lead

REASON = "Old work from before the new rules."


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _ago(hours: float) -> datetime:
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _audit(*, fail: bool = False) -> Any:
    audit = AsyncMock()
    if fail:
        audit.log_kind.side_effect = AuditWriteError("the audit index does not answer")
    return audit


def _waiting(client: TestClient, **kw: Any) -> list[clear_svc.WaitingInvestigation]:
    async def work(db: Any) -> list[clear_svc.WaitingInvestigation]:
        return await clear_svc.waiting_investigations(db, state=client.app.state, **kw)

    result: list[clear_svc.WaitingInvestigation] = _do(client, work)
    return result


def _clear(
    client: TestClient,
    audit: Any,
    *,
    before: datetime,
    reason: str = REASON,
    only: str | None = None,
) -> clear_svc.ClearResult:
    async def work(db: Any) -> clear_svc.ClearResult:
        items = await clear_svc.waiting_investigations(
            db, state=client.app.state, before=before, only=only
        )
        return await clear_svc.clear_items(
            db, items, reason=reason, by="analyst-1", audit=audit, state=client.app.state
        )

    result: clear_svc.ClearResult = _do(client, work)
    return result


def _restore(client: TestClient, audit: Any, inv_id: str) -> clear_svc.RestoreResult:
    async def work(db: Any) -> clear_svc.RestoreResult:
        return await clear_svc.restore(db, inv_id, by="analyst-2", audit=audit)

    result: clear_svc.RestoreResult = _do(client, work)
    return result


def _item_ids(client: TestClient, kind: str = "investigation") -> set[str]:
    return {i["id"] for i in _items(client)["items"] if i["type"] == kind}


def _events(client: TestClient, inv_id: str, kind: str) -> list[dict[str, Any]]:
    async def work(db: Any) -> list[dict[str, Any]]:
        rows = (
            await db.scalars(
                select(InvestigationEvent)
                .where(
                    InvestigationEvent.investigation_id == inv_id,
                    InvestigationEvent.kind == kind,
                )
                .order_by(InvestigationEvent.sequence)
            )
        ).all()
        return [dict(r.payload or {}) for r in rows]

    result: list[dict[str, Any]] = _do(client, work)
    return result


def _report(client: TestClient, inv_id: str) -> dict[str, Any]:
    async def work(db: Any) -> dict[str, Any]:
        row = await db.get(Investigation, inv_id)
        return dict(row.report or {})

    result: dict[str, Any] = _do(client, work)
    return result


# ── The list ──────────────────────────────────────────────────────────────


def test_the_list_is_the_investigation_set_of_the_needs_you_items(client: TestClient) -> None:
    runs = _seed(client)
    waiting = _waiting(client)
    assert {w.id for w in waiting} == _item_ids(client)
    assert {w.id for w in waiting} == {runs["alone"], runs["differs"], runs["old"]}
    by_id = {w.id: w for w in waiting}
    assert by_id[runs["alone"]].verdict == "true_positive"
    assert by_id[runs["alone"]].actions == 1
    assert by_id[runs["old"]].verdict == "needs_more_info"
    assert by_id[runs["old"]].actions == 0
    assert by_id[runs["old"]].source == OUTSIDE
    assert by_id[runs["old"]].event_at is not None
    assert by_id[runs["old"]].event_at < _ago(39 * 24)
    # The oldest event first.
    assert waiting[0].id == runs["old"]
    # A date keeps the investigations with an event before it.
    assert {w.id for w in _waiting(client, before=_ago(24))} == {runs["old"]}
    assert {w.id for w in _waiting(client, only="true_positive")} == {runs["alone"]}


# ── The clear ─────────────────────────────────────────────────────────────


def test_a_clear_takes_each_old_investigation_out_of_the_count_and_the_list(
    client: TestClient,
) -> None:
    runs = _seed(client)
    _seed_lead(client, formed_hours_ago=50 * 24)
    before_count = _needs_you(client)
    assert before_count["investigations_waiting"] == 3
    audit = _audit()

    result = _clear(client, audit, before=_ago(1.95))

    assert {w.id for w in result.cleared} == {runs["alone"], runs["old"]}
    assert result.dismissed == 1
    assert result.failed is None
    count = _needs_you(client)
    assert count["needs_more_info"] == 1
    assert count["pending_actions"] == 0
    assert count["investigations_waiting"] == 1
    # The list of Needs you holds what the count counts.
    assert _item_ids(client) == {runs["differs"]}
    listed = client.get("/api/v1/investigations", params={"needs_you": "true"}).json()
    assert {row["id"] for row in listed["rows"]} == {runs["differs"]}
    assert listed["total"] == count["investigations_waiting"]
    # NEGATIVE CONTROL. A campaign and a lead are no part of the clear.
    assert count["campaigns"] == before_count["campaigns"] == 1
    assert count["leads_needing_decision"] == before_count["leads_needing_decision"] == 1
    assert _item_ids(client, "campaign") == {runs["campaign"]}
    assert len(_item_ids(client, "lead")) == 1
    # NEGATIVE CONTROL. The actions of an investigation that a campaign holds stay.
    assert _events(client, runs["held"], "action_dismissed") == []
    # The verdict filter of the Investigations list still holds the cleared verdict.
    nmi = client.get(
        "/api/v1/investigations", params={"verdict": "needs_more_info", "range": "all"}
    ).json()
    assert {runs["old"], runs["differs"]} <= {row["id"] for row in nmi["rows"]}
    # One record for each investigation, mutating, with the reason and the user.
    assert audit.log_kind.await_count == 2
    for call in audit.log_kind.await_args_list:
        assert call.args[1] == "needs_you_cleared"
        assert call.kwargs["mutating"] is True
        assert call.kwargs["user"] == "analyst-1"
        payload = call.args[2]
        assert payload["reason"] == REASON
        assert payload["verdict"] in ("true_positive", "needs_more_info")
    # The dismissal goes through the dismiss path and carries the reason.
    (dismissal,) = _events(client, runs["alone"], "action_dismissed")
    assert dismissal["by"] == "analyst-1"
    assert dismissal["reason"] == REASON
    assert dismissal["index"] == 0
    assert dismissal["cleared"] == _report(client, runs["alone"])["needs_you_cleared"]["id"]


def test_an_investigation_after_the_date_stays(client: TestClient) -> None:
    """NEGATIVE CONTROL. The date reads the event time of the investigation."""
    runs = _seed(client)
    result = _clear(client, _audit(), before=_ago(24))
    assert {w.id for w in result.cleared} == {runs["old"]}
    assert _item_ids(client) == {runs["alone"], runs["differs"]}
    assert "needs_you_cleared" not in _report(client, runs["differs"])


def test_the_only_option_clears_one_verdict(client: TestClient) -> None:
    runs = _seed(client)
    result = _clear(client, _audit(), before=_ago(1.95), only="needs_more_info")
    assert {w.id for w in result.cleared} == {runs["old"]}
    assert _item_ids(client) == {runs["alone"], runs["differs"]}


def test_a_failed_audit_write_clears_nothing(client: TestClient) -> None:
    """NEGATIVE CONTROL. The audit record comes first, and it fails closed."""
    runs = _seed(client)
    audit = _audit(fail=True)
    result = _clear(client, audit, before=_ago(1.95))
    assert result.cleared == []
    assert result.failed is not None
    assert audit.log_kind.await_count == 1
    assert _item_ids(client) == {runs["alone"], runs["differs"], runs["old"]}
    assert _needs_you(client)["investigations_waiting"] == 3
    assert _events(client, runs["alone"], "action_dismissed") == []
    assert "needs_you_cleared" not in _report(client, runs["old"])


def test_a_failed_store_write_states_on_the_trail_that_the_clear_did_not_happen(
    client: TestClient,
) -> None:
    """The record came first. A store write that then fails gets a record that says so."""
    runs = _seed(client)
    audit = _audit()
    with patch(
        "soc_ai.store.investigations.append_events",
        AsyncMock(side_effect=RuntimeError("the store is locked")),
    ):
        result = _clear(client, audit, before=_ago(1.95))
    assert result.cleared == []
    assert result.failed == runs["old"]
    kinds = [c.args[1] for c in audit.log_kind.await_args_list]
    assert kinds == ["needs_you_cleared", "needs_you_clear_failed"]
    assert audit.log_kind.await_args_list[1].args[2]["investigation_id"] == runs["old"]
    assert "needs_you_cleared" not in _report(client, runs["old"])
    assert _item_ids(client) == {runs["alone"], runs["differs"], runs["old"]}


@pytest.mark.parametrize("reason", ["", "   "])
def test_an_empty_reason_is_refused(client: TestClient, reason: str) -> None:
    """NEGATIVE CONTROL. A clear without a reason writes nothing."""
    runs = _seed(client)
    audit = _audit()
    with pytest.raises(ValueError, match="reason"):
        _clear(client, audit, before=_ago(1.95), reason=reason)
    audit.log_kind.assert_not_awaited()
    assert _item_ids(client) == {runs["alone"], runs["differs"], runs["old"]}


def test_a_date_in_the_future_is_refused() -> None:
    """NEGATIVE CONTROL. The tool never takes every item with a date that has not come."""
    with pytest.raises(ValueError, match="past"):
        clear_svc.check_before(_ago(-1))
    clear_svc.check_before(_ago(1))


def test_a_clear_changes_no_verdict_and_is_no_override(client: TestClient) -> None:
    """The rule prior, the outcome counts and the analyst verdicts read the same."""
    runs = _seed(client)
    ids = [runs[k] for k in ("alone", "old", "differs", "held", "held_2")]

    async def snapshot(db: Any) -> dict[str, Any]:
        rows = [await db.get(Investigation, i) for i in ids]
        for row in rows:
            await db.refresh(row)
        return {
            "verdicts": {r.id: (r.verdict, r.confidence, r.status) for r in rows},
            "resolutions": {r.id: inv_svc.analyst_resolution(r) for r in rows},
            "override": await rule_prior.rule_has_analyst_override(db, RULE),
            "by_rule": await inv_svc.verdict_counts_by_rule(db, [RULE]),
            "overrides": await inv_svc.override_counts_by_rule(db, [RULE]),
            "since": await inv_svc.verdict_counts_since(db, _ago(100 * 24)),
            "analyst": await inv_svc.analyst_verdicts_for_alerts(
                db, [r.alert_es_id for r in rows if r.alert_es_id]
            ),
            "prior_rows": await db.scalar(select(func.count()).select_from(RulePriorDecision)),
            "prior_stats": await rule_prior.stats_by_rule(db, [RULE]),
        }

    before = _do(client, snapshot)
    result = _clear(client, _audit(), before=_ago(1.95))
    assert len(result.cleared) == 2
    after = _do(client, snapshot)
    assert after == before
    assert after["override"] is False
    assert all(v is None for v in after["resolutions"].values())


# ── The restore ───────────────────────────────────────────────────────────


def test_a_restore_brings_the_item_back(client: TestClient) -> None:
    runs = _seed(client)
    _clear(client, _audit(), before=_ago(1.95))
    audit = _audit()
    for key in ("alone", "old"):
        _restore(client, audit, runs[key])
    assert _item_ids(client) == {runs["alone"], runs["differs"], runs["old"]}
    count = _needs_you(client)
    assert count["investigations_waiting"] == 3
    assert count["pending_actions"] == 1
    assert count["needs_more_info"] == 2
    assert "needs_you_cleared" not in _report(client, runs["old"])
    assert [c.args[1] for c in audit.log_kind.await_args_list] == ["needs_you_restored"] * 2
    assert all(c.kwargs["mutating"] is True for c in audit.log_kind.await_args_list)
    (undo,) = _events(client, runs["alone"], "action_restored")
    assert undo["by"] == "analyst-2"


def test_a_failed_restore_states_on_the_trail_that_it_did_not_happen(
    client: TestClient,
) -> None:
    runs = _seed(client)
    _clear(client, _audit(), before=_ago(1.95))
    audit = _audit()
    with (
        patch(
            "soc_ai.store.investigations.append_events",
            AsyncMock(side_effect=RuntimeError("the store is locked")),
        ),
        pytest.raises(RuntimeError),
    ):
        _restore(client, audit, runs["old"])
    kinds = [c.args[1] for c in audit.log_kind.await_args_list]
    assert kinds == ["needs_you_restored", "needs_you_restore_failed"]
    # The clear stands.
    assert "needs_you_cleared" in _report(client, runs["old"])
    assert runs["old"] not in _item_ids(client)


def test_a_restore_of_an_investigation_with_no_clear_is_refused(client: TestClient) -> None:
    runs = _seed(client)
    audit = _audit()
    with pytest.raises(clear_svc.NotClearedError):
        _restore(client, audit, runs["old"])
    with pytest.raises(clear_svc.NotClearedError):
        _restore(client, audit, "no-such-investigation")
    audit.log_kind.assert_not_awaited()


def test_a_restore_leaves_a_dismissal_of_the_analyst(client: TestClient) -> None:
    """NEGATIVE CONTROL. A restore undoes the dismissals of its clear and no other."""

    def action(alert_id: str, why: str) -> dict[str, Any]:
        return {
            "tool_name": "escalate_to_case",
            "tool_args": {"alert_id": alert_id, "case_title": "t", "case_description": "d"},
            "rationale": why,
        }

    async def work(db: Any) -> str:
        return await seed_run(
            db,
            "alert-two",
            src=OUTSIDE,
            dst=OUTSIDE,
            event_hours_ago=30 * 24,
            report={
                "recommended_actions": [
                    action("alert-two", "Open a case for the upload."),
                    action("alert-two", "Open a case for the second upload."),
                ]
            },
        )

    inv_id = _do(client, work)
    # The analyst dismisses the second action in the console.
    res = client.post(f"/api/v1/investigations/{inv_id}/actions/1/dismiss")
    assert res.status_code == 200, res.text
    result = _clear(client, _audit(), before=_ago(24))
    assert [w.id for w in result.cleared] == [inv_id]
    assert result.dismissed == 1
    assert inv_id not in _item_ids(client)
    _restore(client, _audit(), inv_id)
    actions = client.get(f"/api/v1/investigations/{inv_id}").json()["actions"]
    assert [a["dismissed"] for a in actions] == [False, True]


# ── The investigation page ────────────────────────────────────────────────


def test_the_investigation_page_states_the_clear(client: TestClient) -> None:
    runs = _seed(client)
    assert client.get(f"/api/v1/investigations/{runs['old']}").json()["needsYouCleared"] is None
    _clear(client, _audit(), before=_ago(1.95))
    body = client.get(f"/api/v1/investigations/{runs['old']}").json()
    today = datetime.now(UTC).date().isoformat()
    assert body["needsYouCleared"] == f"Cleared from Needs you on {today} by analyst-1: {REASON}"
    # The verdict on the page is the verdict of the run.
    assert body["verdict"] == "needs_more_info"
    _restore(client, _audit(), runs["old"])
    assert client.get(f"/api/v1/investigations/{runs['old']}").json()["needsYouCleared"] is None
