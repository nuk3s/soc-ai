"""GET /api/v1/audit/verify-schedule: the scheduled audit-chain check, read from memory.

The Status page lists every job that runs with no operator. The scheduled
audit-chain check keeps its state in an in-memory slot on ``app.state``
(``soc_ai.main._audit_verify_loop``), and no route served that slot. The bell
showed a break, and nothing said when the check last ran.

The route is a read. It runs no check and reads no index, so the tests below
seed the slot directly and assert on what comes back. One test pins that the
read does not create the slot: a read that writes app state would make the
loop's "never ran" look like "ran".
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.api.webui._shared import require_admin_api
from soc_ai.api.webui.routes_config import _AuditVerifyStatus
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store.auth import SESSION_COOKIE

PATH = "/api/v1/audit/verify-schedule"


def _client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _slot(client: TestClient, **fields: object) -> _AuditVerifyStatus:
    status = _AuditVerifyStatus(**fields)  # type: ignore[arg-type]
    client.app.state._audit_verify_status = status  # type: ignore[attr-defined]
    return status


def test_no_check_yet_reads_as_never_run_with_the_live_schedule(client: TestClient) -> None:
    client.app.state.__dict__.pop("_audit_verify_status", None)  # type: ignore[attr-defined]
    body = client.get(PATH).json()
    assert body == {
        "enabled": True,
        "interval_hours": 24,
        "window_days": 7,
        "last_run": None,
        "broken": False,
        "broken_since": None,
        "detail": None,
        "last_outcome": None,
    }


def test_the_read_does_not_create_the_slot(client: TestClient) -> None:
    # The loop's due-check reads last_run off this slot. A read that created
    # it would change nothing today, and a later field with a non-null default
    # would turn every page view into a fake "ran" for the loop.
    state = client.app.state  # type: ignore[attr-defined]
    state.__dict__.pop("_audit_verify_status", None)
    assert client.get(PATH).status_code == 200
    assert getattr(state, "_audit_verify_status", None) is None


def test_a_check_with_no_alarm_reports_its_time_and_no_break(client: TestClient) -> None:
    ran = (datetime.now(UTC) - timedelta(hours=3)).isoformat()
    _slot(client, last_run=ran)
    body = client.get(PATH).json()
    assert body["last_run"] == ran
    assert body["broken"] is False
    assert body["broken_since"] is None
    assert body["detail"] is None
    assert body["last_outcome"] is None


def test_the_last_outcome_tells_a_clean_check_from_one_that_could_not_read(
    client: TestClient,
) -> None:
    ran = (datetime.now(UTC) - timedelta(hours=3)).isoformat()
    _slot(client, last_run=ran, last_outcome="not_checked")
    assert client.get(PATH).json()["last_outcome"] == "not_checked"
    _slot(client, last_run=ran, last_outcome="intact")
    assert client.get(PATH).json()["last_outcome"] == "intact"


def test_a_standing_alarm_reports_the_break_its_start_and_its_size(client: TestClient) -> None:
    now = datetime.now(UTC)
    since = (now - timedelta(days=2)).isoformat()
    ran = (now - timedelta(minutes=20)).isoformat()
    _slot(
        client,
        last_run=ran,
        alarm={
            "alarm_since": since,
            "detected_at": ran,
            "blast_radius": "2 records claim sequence 503.",
            "break_detail": "seq 503 is claimed twice",
            "window_days": 7,
        },
    )
    body = client.get(PATH).json()
    assert body["broken"] is True
    assert body["last_run"] == ran
    assert body["broken_since"] == since
    # The census sentence wins over the single-break detail, as on the bell.
    assert body["detail"] == "2 records claim sequence 503."


def test_an_alarm_without_a_census_falls_back_to_the_break_detail(client: TestClient) -> None:
    _slot(client, last_run=datetime.now(UTC).isoformat(), alarm={"break_detail": "seq 9 edited"})
    body = client.get(PATH).json()
    assert body["broken"] is True
    assert body["detail"] == "seq 9 edited"
    assert body["broken_since"] is None


def test_the_schedule_fields_follow_the_live_settings(settings_kratos: Settings) -> None:
    off = settings_kratos.model_copy(
        update={
            "audit_verify_schedule_enabled": False,
            "audit_verify_schedule_interval_hours": 6,
            "audit_verify_days": 30,
        }
    )
    for client in _client(off):
        body = client.get(PATH).json()
        assert body["enabled"] is False
        assert body["interval_hours"] == 6
        assert body["window_days"] == 30


async def _analyst_session(client: TestClient) -> str:
    from soc_ai.store import auth as auth_svc

    async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
        user = await auth_svc.create_user(db, "analyst-status", "longpassword1", role="analyst")
        return await auth_svc.create_session(db, user, ttl_hours=24)


def test_the_route_is_analyst_readable_and_needs_a_session(settings_kratos: Settings) -> None:
    # Bell parity: the notifications route already shows a break to any
    # signed-in caller. The route is therefore not admin-gated. It still sits
    # behind the API auth gate.
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
    routes = [r for r in app.routes if isinstance(r, APIRoute) and r.path == PATH]
    assert len(routes) == 1
    assert routes[0].methods == {"GET"}
    assert require_admin_api not in [d.call for d in routes[0].dependant.dependencies]

    auth_on = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw-status-1")}
    )
    for client in _client(auth_on):
        assert client.get(PATH).status_code == 401

        token = asyncio.run(_analyst_session(client))
        client.cookies.set(SESSION_COOKIE, token)
        assert client.get(PATH).status_code == 200
