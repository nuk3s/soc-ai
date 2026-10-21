"""Check Security Onion now for one stranded escalation (dogfood 2026-10-19, R5-I5).

The Status page lists each escalation claim that has no answer from Security
Onion. Only a group escalate that covers the alert compared a claim with the
grid, so a claim whose alert left the queue never settled. ``POST
/escalations/check`` re-reads one claim's case links and alert in Security
Onion and applies the rule the group escalate already applies: a case link
settles the claim with its case, and a complete read with no link releases
it. A read that fails leaves the claim alone.

The guard that matters is on the release. A claim inside the settling window
can belong to an escalate still in flight, and an alert that Security Onion
marks escalated is on a case even when no link shows. Both stay open.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ConnectionError as EsConnectionError
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import escalations as esc_svc

_ALERT = "alert-check-1"


class _Grid:
    """A fake Security Onion grid: the case index and the alert index."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.links: dict[str, str] = {}
        self.alerts: dict[str, dict[str, Any]] = {_ALERT: {"rule": {"name": "ET example"}}}
        self.down = False
        # A case read where one shard failed: Security Onion answered, and the
        # answer is incomplete.
        self.partial_cases = False
        self.calls: list[str] = []

    async def search(self, *, index: str, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        self.calls.append(index)
        if self.down:
            raise EsConnectionError("connection refused")
        if index == self.settings.cases_index_pattern:
            wanted = body["query"]["bool"]["filter"][1]["terms"]["so_related.fields.soc_id"]
            buckets = [
                {
                    "key": alert_id,
                    "first_case": {
                        "hits": {"hits": [{"_source": {"so_related": {"caseId": case}}}]}
                    },
                }
                for alert_id, case in self.links.items()
                if alert_id in wanted
            ]
            out: dict[str, Any] = {
                "hits": {"hits": []},
                "aggregations": {"by_alert": {"buckets": buckets}},
            }
            if self.partial_cases:
                out["_shards"] = {"total": 2, "failed": 1}
            return out
        wanted_ids = body["query"]["ids"]["values"]
        hits = [
            {"_id": alert_id, "_source": source}
            for alert_id, source in self.alerts.items()
            if alert_id in wanted_ids
        ]
        return {"hits": {"total": {"value": len(hits)}, "hits": hits}}


@pytest.fixture
def grid(settings_kratos: Settings) -> _Grid:
    return _Grid(settings_kratos)


@pytest.fixture
def client(settings_kratos: Settings, grid: _Grid) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_es.search.side_effect = grid.search
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            app.state.audit = AsyncMock()
            yield c


def _db(client: TestClient, fn: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            return await fn(db)

    return asyncio.run(go())


def _claim(client: TestClient, alert_id: str = _ALERT, *, age_minutes: int = 90) -> None:
    """Claim the alert, then age the claim, since a claim is stamped now."""
    from sqlalchemy import text

    async def go(db: Any) -> None:
        await esc_svc.claim(db, [alert_id], actor="alice")
        await db.execute(
            text(
                "UPDATE alert_escalations SET created_at = datetime('now', :d) WHERE alert_id = :a"
            ),
            {"d": f"-{age_minutes} minutes", "a": alert_id},
        )
        await db.commit()

    _db(client, go)


def _ledger(client: TestClient, alert_id: str = _ALERT) -> dict[str, str | None]:
    return _db(client, lambda db: esc_svc.cases_for_alerts(db, [alert_id]))  # type: ignore[no-any-return]


def _check(client: TestClient, alert_id: str = _ALERT) -> Any:
    return client.post("/api/v1/escalations/check", json={"alert_id": alert_id})


def _audit_kinds(client: TestClient) -> list[str]:
    audit = client.app.state.audit  # type: ignore[attr-defined]
    return [call.args[1] for call in audit.log_kind.await_args_list]


class TestSettle:
    def test_a_case_link_settles_the_claim_with_its_case(
        self, client: TestClient, grid: _Grid
    ) -> None:
        _claim(client)
        grid.links[_ALERT] = "case-7"

        resp = _check(client)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["result"] == "case_found"
        assert body["settled"] is True
        assert body["case_id"] == "case-7"
        assert (
            body["message"] == f"soc-ai found case case-7 for alert {_ALERT}. The claim is settled."
        )
        # The panel links the case (2026-10-20). None when no host is set.
        assert body["case_url"] is None or body["case_url"].endswith("/#/case/case-7")
        assert _ledger(client) == {_ALERT: "case-7"}
        assert client.get("/api/v1/escalations/stranded").json()["total"] == 0
        assert _audit_kinds(client) == ["escalation_claim_settled"]

    def test_no_case_link_releases_the_claim(self, client: TestClient, grid: _Grid) -> None:
        _claim(client)

        resp = _check(client)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["result"] == "no_case"
        assert body["settled"] is True
        assert body["case_id"] is None
        assert body["message"] == (
            "soc-ai released the claim. Security Onion has no case for the alert."
        )
        assert _ledger(client) == {}
        assert _audit_kinds(client) == ["escalation_claim_settled"]

    def test_an_alert_that_left_the_grid_is_released_too(
        self, client: TestClient, grid: _Grid
    ) -> None:
        """The case this route exists for: the alert left the queue, so no
        group escalate ever covers it again."""
        _claim(client)
        grid.alerts.clear()

        body = _check(client).json()

        assert body["result"] == "no_case"
        assert _ledger(client) == {}


class TestStillWaiting:
    def test_a_young_claim_with_no_link_stays_open(self, client: TestClient, grid: _Grid) -> None:
        """The escalate that wrote this claim can still be in flight. A release
        now frees the alert for a second case."""
        _claim(client, age_minutes=2)

        resp = _check(client)

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["result"] == "waiting"
        assert body["settled"] is False
        assert body["message"] == (
            "The claim stays open. The escalation is less than 15 minutes old."
        )
        assert _ledger(client) == {_ALERT: None}
        assert _audit_kinds(client) == []

    def test_control_a_young_claim_with_a_link_settles(
        self, client: TestClient, grid: _Grid
    ) -> None:
        """A link is positive evidence at any age."""
        _claim(client, age_minutes=2)
        grid.links[_ALERT] = "case-8"

        assert _check(client).json()["result"] == "case_found"
        assert _ledger(client) == {_ALERT: "case-8"}

    def test_an_alert_marked_escalated_with_no_link_stays_open(
        self, client: TestClient, grid: _Grid
    ) -> None:
        """Security Onion stamps the flag when it escalates. The alert is on a
        case that the link read does not show, so a release is wrong."""
        _claim(client)
        grid.alerts[_ALERT] = {"event": {"escalated": True}}

        body = _check(client).json()

        assert body["result"] == "waiting"
        assert body["settled"] is False
        assert body["message"] == (
            "The claim stays open. Security Onion marks the alert as escalated and shows no "
            "case link."
        )
        assert _ledger(client) == {_ALERT: None}


class TestSecurityOnionDown:
    def test_a_failed_read_leaves_the_claim_open(self, client: TestClient, grid: _Grid) -> None:
        _claim(client)
        grid.down = True

        resp = _check(client)

        assert resp.status_code == 503
        detail = resp.json()["detail"]
        assert detail["reason"] == "grid_unavailable"
        assert detail["hint"] == "The claim stays open. Security Onion did not answer."
        assert _ledger(client) == {_ALERT: None}
        assert _audit_kinds(client) == []

    def test_a_partial_read_leaves_the_claim_open(self, client: TestClient, grid: _Grid) -> None:
        """A degraded read with no link is "could not see", never "no case"."""
        _claim(client)
        grid.partial_cases = True

        resp = _check(client)

        assert resp.status_code == 503
        assert _ledger(client) == {_ALERT: None}


class TestRefusals:
    def test_an_unknown_claim_answers_404(self, client: TestClient, grid: _Grid) -> None:
        resp = _check(client, "no-such-alert")

        assert resp.status_code == 404
        assert resp.json()["detail"]["reason"] == "claim_not_found"
        assert grid.calls == []

    def test_a_settled_claim_answers_without_a_read(self, client: TestClient, grid: _Grid) -> None:
        _claim(client)
        _db(client, lambda db: esc_svc.record_case(db, _ALERT, "case-9"))

        body = _check(client).json()

        assert body["result"] == "already_settled"
        assert body["settled"] is True
        assert body["case_id"] == "case-9"
        assert grid.calls == []

    def test_a_check_already_running_answers_409(self, client: TestClient, grid: _Grid) -> None:
        _claim(client)
        from soc_ai.webui import escalation_check

        escalation_check.checks_running(client.app.state).add(_ALERT)  # type: ignore[attr-defined]

        resp = _check(client)

        assert resp.status_code == 409
        assert resp.json()["detail"]["reason"] == "check_running"
        assert grid.calls == []
        assert _ledger(client) == {_ALERT: None}

    def test_an_empty_alert_id_is_refused(self, client: TestClient) -> None:
        resp = client.post("/api/v1/escalations/check", json={"alert_id": "  "})
        assert resp.status_code == 422


def test_the_audit_kind_is_declared() -> None:
    import typing

    from soc_ai.audit.schemas import AuditKind

    assert "escalation_claim_settled" in typing.get_args(AuditKind)
