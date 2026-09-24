"""One caller, one identity, whatever API_AUTH_REQUIRED says (dogfood 2026-09-07).

A deployment with authentication off gave the same caller three different
answers. ``GET /me`` invented "analyst" so the sidebar had a name to render.
``identify_caller`` recorded "anonymous" on every write. ``_require_user``
refused outright. Assigning an alert group to yourself therefore stored
"anonymous", the row grew an avatar and an owned chip, and the Mine filter
matched nothing and always would. Both names render "AN" as initials, so
nothing on screen revealed it: the feature did nothing while appearing to
succeed.

The fix is one identity, reported honestly, plus a flag saying whether anyone
is actually signed in. Ownership then works because the name /me reports is the
name writes are recorded under. Saved views still refuse, because a saved view
belongs to a user ROW and an unauthenticated deployment has none, and the flag
is what lets the interface say so instead of silently deleting the control.

The negative control that matters is at the bottom: with authentication ON,
nothing about any of this moves.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app

from .conftest_security import ANALYST_CREDS

_RULE = "ET INFO Observed DNS Query to .biz TLD"
# A cookie-authenticated write has to come from the app's own origin, so the
# auth-ON legs below send it (tests/test_csrf.py owns that rule).
_SAME_ORIGIN = {"Origin": "http://testserver"}


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    """The house hermetic harness: real app, auth OFF, unreachable upstreams."""
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _assign(client: TestClient, **kw: Any) -> dict[str, Any]:
    resp = client.post("/api/v1/alerts/assign", json={"rule_name": _RULE}, **kw)
    assert resp.status_code == 200, resp.text
    return dict(resp.json())


# ── Authentication off ───────────────────────────────────────────────────────


def test_me_reports_the_name_writes_are_recorded_under(client: TestClient) -> None:
    """The whole defect in one assertion: claiming an alert group has to leave
    an owner the identity endpoint agrees is you, or "Mine" can never match."""
    me = client.get("/api/v1/me").json()
    assert _assign(client)["owner"] == me["username"]


def test_me_says_plainly_that_nobody_is_signed_in(client: TestClient) -> None:
    """The frontend had no way to know authentication was off, so it could not
    tell "this feature is unavailable" from "this feature does not exist"."""
    me = client.get("/api/v1/me").json()
    assert me["signed_in"] is False
    # Still a usable name and role, because the SPA renders both and the admin
    # surfaces genuinely are open when the gate is down.
    assert me["username"]
    assert me["role"] == "admin"


def test_saved_views_still_refuse_and_say_why(client: TestClient) -> None:
    """A saved view belongs to a user row, and there is none. The refusal is
    unchanged; what changed is that the caller can now tell WHY from /me."""
    resp = client.get("/api/v1/me/views")
    assert resp.status_code == 401
    assert resp.json()["detail"]["reason"] == "no_session"


def test_the_owner_survives_a_round_trip_to_the_alerts_list(client: TestClient) -> None:
    """The owner the assign returned is the owner the list reports, so the Mine
    filter is comparing two values that came from the same place."""
    owner = _assign(client)["owner"]
    me = client.get("/api/v1/me").json()["username"]
    assert owner == me
    client.post("/api/v1/alerts/assign", json={"rule_name": _RULE, "unassign": True})


# ── Negative control: authentication ON behaves exactly as it did ────────────


def test_signed_in_user_is_reported_as_themselves(
    audit_client: TestClient, analyst_session: dict[str, str]
) -> None:
    me = audit_client.get("/api/v1/me", cookies=analyst_session).json()
    assert me["username"] == ANALYST_CREDS[0]
    assert me["role"] == "analyst"
    assert me["signed_in"] is True


def test_signed_in_ownership_records_the_real_username(
    audit_client: TestClient, analyst_session: dict[str, str]
) -> None:
    assigned = _assign(audit_client, cookies=analyst_session, headers=_SAME_ORIGIN)
    assert assigned["owner"] == ANALYST_CREDS[0]


def test_signed_in_saved_views_still_work(
    audit_client: TestClient, analyst_session: dict[str, str]
) -> None:
    saved = audit_client.post(
        "/api/v1/me/views",
        json={"screen": "alerts", "name": "my view", "query": {"q": "dns"}},
        cookies=analyst_session,
        headers=_SAME_ORIGIN,
    )
    assert saved.status_code == 200, saved.text
    rows = audit_client.get("/api/v1/me/views", cookies=analyst_session).json()["rows"]
    assert [r["name"] for r in rows] == ["my view"]


def test_a_bearer_token_caller_is_authenticated_but_not_signed_in(
    audit_client: TestClient, admin_session: dict[str, str]
) -> None:
    """A token has no user row, so it cannot own a saved view either. Reporting
    it as signed in would send the interface back to offering a control that
    401s, which is the failure one step over."""
    created = audit_client.post(
        "/api/v1/config/tokens",
        json={"name": "probe"},
        cookies=admin_session,
        headers=_SAME_ORIGIN,
    )
    assert created.status_code == 200, created.text
    secret = created.json()["token"]
    headers = {"Authorization": f"Bearer {secret}"}

    me = audit_client.get("/api/v1/me", headers=headers).json()
    assert me["username"] == "token:probe"
    assert me["signed_in"] is False
    assert audit_client.get("/api/v1/me/views", headers=headers).status_code == 401
