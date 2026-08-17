"""Regression coverage for the 2026-07-30 review test-gap findings.

Three gaps this file closes:

* F49 — the export's Ed25519 signature was never verified end-to-end (only the
  sha256 was recomputed), so silent loss of tamper-evidence shipped green.
* F50 — the admin gate on high-risk config routes was untested (the default
  client runs ``api_auth_required=False``, making ``require_admin_api`` a no-op),
  so a dropped ``Depends(require_admin_api)`` would pass the whole suite.
* F64 — the demo pipeline-error showcase row had no ``replays[]`` entry, so its
  "Re-run investigation" CTA silently 404'd.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.main import create_app


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


# ---------------------------------------------------------------------------
# F49 — the export's Ed25519 signature must actually verify (and degrade honestly)
# ---------------------------------------------------------------------------


async def _seed_complete_investigation(client: TestClient) -> str:
    from soc_ai.store import investigations as inv_svc

    maker = client.app.state.db_sessionmaker
    async with maker() as db:
        inv = await inv_svc.create(
            db, alert_es_id="ev-sig", started_by="tester", rule_name="ET SIG X"
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


def _canonical_bytes(rec: dict) -> bytes:
    import json

    body = {k: v for k, v in rec.items() if k != "integrity"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def test_export_signature_verifies_with_published_key(settings_kratos: Settings) -> None:
    """The exported record carries an Ed25519 detached signature that VERIFIES
    against its embedded public key — the actual tamper-evidence guarantee, not
    just the recomputable checksum. A one-byte body tamper must fail that verify,
    and the embedded key must match the published /decision-record/public-key."""
    from soc_ai.store import signing

    for client in _client(settings_kratos):
        inv_id = asyncio.run(_seed_complete_investigation(client))
        rec = client.get(f"/api/v1/investigations/{inv_id}/export").json()

        sig = rec["integrity"]["signature"]
        assert sig["algo"] == "ed25519"
        assert sig["value"] and sig["public_key"]

        canonical = _canonical_bytes(rec)
        assert signing.verify(canonical, sig["value"], sig["public_key"]) is True
        # A single trailing byte flips the canonical bytes → signature must fail.
        assert signing.verify(canonical + b" ", sig["value"], sig["public_key"]) is False

        pub = client.get("/api/v1/decision-record/public-key").json()
        assert pub["algo"] == "ed25519"
        assert pub["public_key"] is not None
        assert pub["public_key"] == sig["public_key"]


def test_export_is_checksum_only_when_signer_absent(settings_kratos: Settings) -> None:
    """When no signer is present (load-or-create failed / lifespan refactor /
    read-only data dir), the export degrades to checksum-only: no ``signature``
    block, ``/decision-record/public-key`` returns null, and the sha256 still
    recomputes. Pins the documented silent-degradation contract."""
    import hashlib

    for client in _client(settings_kratos):
        # Simulate the signer being unavailable (main.py swallows load failures
        # and sets app.state.decision_signer = None).
        client.app.state.decision_signer = None

        inv_id = asyncio.run(_seed_complete_investigation(client))
        rec = client.get(f"/api/v1/investigations/{inv_id}/export").json()

        assert "signature" not in rec["integrity"]
        assert rec["integrity"]["algo"] == "sha256"
        assert hashlib.sha256(_canonical_bytes(rec)).hexdigest() == rec["integrity"]["hash"]

        pub = client.get("/api/v1/decision-record/public-key").json()
        assert pub["public_key"] is None


# ---------------------------------------------------------------------------
# F50 — the admin gate on high-risk config routes must be enforced
# ---------------------------------------------------------------------------

# Highest-value admin-surface routes (method, path). A refactor that drops
# `Depends(require_admin_api)` from any of these — or renames the path — fails
# this scan, even though the default (api_auth_required=False) client can't.
_ADMIN_SURFACE = {
    ("POST", "/api/v1/config/setting"),
    ("POST", "/api/v1/config/danger/setting"),
    ("POST", "/api/v1/config/api-keys"),
    ("DELETE", "/api/v1/config/api-keys/{key}"),
    ("POST", "/api/v1/config/tokens"),
    ("POST", "/api/v1/config/users"),
    ("GET", "/api/v1/config"),
    ("GET", "/api/v1/internal-identifiers"),
    # Host dossier: reads are the analyst default, but declaring what a host IS
    # (or silencing the system's disagreement with that) is an admin act — an
    # analyst who could relabel a host's criticality could bury it.
    ("POST", "/api/v1/dossiers/{ip}/override"),
    ("DELETE", "/api/v1/dossiers/{ip}/override/{field}"),
    ("POST", "/api/v1/dossiers/{ip}/conflicts/{field}/snooze"),
    ("POST", "/api/v1/dossiers/refresh"),
}


def test_admin_surface_routes_carry_admin_gate(settings_kratos: Settings) -> None:
    """Every high-risk config/admin route declares ``require_admin_api`` in its
    dependencies. A static route-table scan so the guarantee holds even under the
    default client (which runs api_auth_required=False, making the gate a no-op)."""
    from soc_ai.api.webui._shared import require_admin_api

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()

    seen: dict[tuple[str, str], bool] = {}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        gated = require_admin_api in [d.call for d in route.dependant.dependencies]
        for method in route.methods:
            key = (method, route.path)
            if key in _ADMIN_SURFACE:
                seen[key] = gated

    missing = _ADMIN_SURFACE - set(seen)
    assert not missing, f"admin-surface routes disappeared from the route table: {missing}"
    ungated = {key for key, ok in seen.items() if not ok}
    assert not ungated, f"admin-surface routes missing require_admin_api: {ungated}"


ADMIN_PW = "test-review-admin-pw"


def _auth_client(settings_kratos: Settings) -> Iterator[TestClient]:
    auth_settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr(ADMIN_PW)}
    )
    yield from _client(auth_settings)


async def _seed_analyst_session(client: TestClient) -> str:
    from soc_ai.store import auth as auth_svc

    maker = client.app.state.db_sessionmaker
    async with maker() as db:
        user = await auth_svc.create_user(db, "analyst-review", "longpassword1", role="analyst")
        return await auth_svc.create_session(db, user, ttl_hours=24)


def test_config_write_routes_reject_analyst_session(settings_kratos: Settings) -> None:
    """With api_auth_required=True, an authenticated analyst-role session is
    forbidden (403 admin_required) on the credential/gateway-rewrite routes —
    the escalation the gate exists to stop. Origin header satisfies the cookie
    CSRF guard so the admin gate (not the origin gate) is what rejects."""
    from soc_ai.store.auth import SESSION_COOKIE

    for client in _auth_client(settings_kratos):
        token = asyncio.run(_seed_analyst_session(client))
        client.cookies.set(SESSION_COOKIE, token)
        headers = {"Origin": "http://testserver"}

        cases = [
            (
                "/api/v1/config/danger/setting",
                {"key": "so_password", "value": "x", "confirm": "so_password"},
            ),
            ("/api/v1/config/api-keys", {"key": "shodan_api_key", "value": "x"}),
            ("/api/v1/config/tokens", {"name": "t"}),
        ]
        for path, body in cases:
            resp = client.post(path, json=body, headers=headers)
            assert resp.status_code == 403, f"{path} -> {resp.status_code}"
            assert resp.json()["detail"]["reason"] == "admin_required", path


# ---------------------------------------------------------------------------
# F64 — every demo pipeline-error row must have a replay so its re-run CTA works
# ---------------------------------------------------------------------------


def test_demo_pipeline_error_rows_have_a_replay_that_reaches_a_verdict() -> None:
    """Each demo investigation that renders the "Pipeline error" panel (its
    "Re-run investigation" button POSTs /api/v1/hunt) must have a matching
    ``replays[]`` entry whose recorded stream reaches a real triage verdict — so
    the re-run the panel tells the visitor to click actually lands a run instead
    of 404 alert_not_found."""
    from soc_ai.demo.fixtures import load_fixtures
    from soc_ai.demo.replay import find_replay
    from soc_ai.triage_models import is_pipeline_fallback

    data = load_fixtures()
    fallbacks = [
        inv for inv in data.get("investigations", []) if is_pipeline_fallback(inv.get("report"))
    ]
    assert fallbacks, "expected at least one demo pipeline-error showcase row"

    for inv in fallbacks:
        alert_id = inv.get("alert_es_id")
        replay = find_replay(data, alert_id)
        assert replay is not None, (
            f"pipeline-error demo row {inv.get('id')} (alert {alert_id}) has no "
            "replays[] entry — its Re-run CTA would 404"
        )
        report_events = [e for e in replay.get("events", []) if e.get("kind") == "triage_report"]
        assert report_events, f"replay for {alert_id} never emits a triage_report"
        verdict = report_events[-1].get("payload", {}).get("verdict")
        # A real verdict, not another pipeline-fallback / needs_more_info stall.
        assert verdict in {"true_positive", "false_positive"}, (
            f"replay for {alert_id} re-runs to a non-verdict ({verdict!r})"
        )
