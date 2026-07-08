"""Tests for the E5.2 analyst-path redaction preview endpoint.

``GET /analyst/redaction-preview/{inv_id}`` rebuilds the round-1 analyst
prompt from a PAST investigation's stored events and shows original vs
sanitized under the CURRENT identifier config — read-only, no model calls, no
egress, no writes. These tests seed real investigations + events through the
app's sessionmaker (mirrors ``test_webui_api.py``'s export-endpoint seeding);
NOTHING here touches a real gateway or model.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext


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


def _enriched_payload(alert_id: str = "ev-e52") -> dict[str, Any]:
    """The stored ``enriched_alert_context`` event payload.

    Exactly what the orchestrator persists (``model_dump(mode="json")`` of the
    model), carrying an internal source IP + an internal-suffix hostname the
    sanitizer MUST redact, and a public destination it MUST preserve.
    """
    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            rule_name="ET MALWARE Beacon",
            severity_label="high",
            source_ip="10.0.0.5",
            destination_ip="8.8.8.8",
            host_name="dc01.corp.local",
            classtype="trojan-activity",
        )
    )
    return enriched.model_dump(mode="json")


# The stored decision_template_match payload — the orchestrator's event shape
# (matched/template_id/verdict/confidence/rationale, NO cited_evidence). The
# rationale deliberately carries the internal IP: the endpoint's final sweep
# over the composed message must redact it (the load-bearing E5.1 behavior).
_TEMPLATE_EVENT: dict[str, Any] = {
    "matched": True,
    "template_id": "blocklist_hit_major_severity",
    "verdict": "true_positive",
    "confidence": 0.9,
    "rationale": "beacon from 10.0.0.5 to a blocklisted destination",
}


def _seed(client: TestClient, events: list[dict[str, Any]], alert_id: str = "ev-e52") -> str:
    """Seed one COMPLETE investigation carrying *events*, return its id."""
    from soc_ai.store import investigations as inv_svc

    async def _run() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db, alert_es_id=alert_id, started_by="tester", rule_name="ET MALWARE Beacon"
            )
            await inv_svc.append_events(db, inv.id, events)
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="true_positive",
                confidence=0.9,
                rationale="beacon",
                report={"citations": []},
            )
            return inv.id

    return asyncio.run(_run())


def _standard_events() -> list[dict[str, Any]]:
    return [
        {"sequence": 1, "kind": "enriched_alert_context", "payload": _enriched_payload()},
        {"sequence": 2, "kind": "decision_template_match", "payload": dict(_TEMPLATE_EVENT)},
    ]


def test_happy_path_rebuilds_and_redacts(settings_kratos: Settings) -> None:
    """Seeded run with the required events → 200 with original ≠ sanitized:
    internal identifiers (including those inside the candidate rationale) are
    redacted, public infrastructure passes through, summary counts are sane."""
    settings = settings_kratos.model_copy(
        update={"analyst_cloud_redaction": True, "analyst_redaction_fail_closed": True}
    )
    for client in _client(settings):
        inv_id = _seed(client, _standard_events())
        resp = client.get(f"/api/v1/analyst/redaction-preview/{inv_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["investigation_id"] == inv_id
        assert body["redaction_enabled"] is True
        assert body["fail_closed"] is True
        # The original side is the honestly-raw composed round-1 prompt.
        assert "Triage alert ev-e52" in body["original"]
        assert "## Decision-template candidate" in body["original"]
        assert "blocklist_hit_major_severity" in body["original"]
        assert "10.0.0.5" in body["original"]
        assert "dc01.corp.local" in body["original"]
        # Redaction: internal identifiers gone (enriched JSON AND the candidate
        # rationale, which only the final composed-message sweep catches) …
        assert "10.0.0.5" not in body["sanitized"]
        assert "dc01" not in body["sanitized"]
        assert "IP_" in body["sanitized"]
        # … while the public destination passes through for real reasoning.
        assert "8.8.8.8" in body["sanitized"]
        # Same summary shape as the Oracle preview: per-category counts.
        assert body["summary"].get("IP", 0) >= 1
        assert body["note"]


def test_redaction_off_still_previews(client: TestClient) -> None:
    """analyst_cloud_redaction defaults OFF → 200 with redaction_enabled false,
    but the preview still shows what WOULD be redacted (simulation)."""
    inv_id = _seed(client, _standard_events())
    resp = client.get(f"/api/v1/analyst/redaction-preview/{inv_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["redaction_enabled"] is False
    assert body["fail_closed"] is False
    assert "10.0.0.5" not in body["sanitized"]  # the simulation still redacts
    assert "currently OFF" in body["note"]  # and the note says it's a simulation


def test_prior_outcomes_event_included(client: TestClient) -> None:
    """When the E4.2 prior_outcomes event exists, the rebuilt message carries
    the memory block — structure from the stored items, with an honest
    placeholder note (rationale digests are deliberately not persisted)."""
    events = _standard_events()
    events.append(
        {
            "sequence": 3,
            "kind": "prior_outcomes",
            "payload": {
                "count": 1,
                "window_days": 30,
                "items": [
                    {"id": "INV-old", "verdict": "false_positive", "matched_on": "rule+src+dest"}
                ],
            },
        }
    )
    inv_id = _seed(client, events)
    body = client.get(f"/api/v1/analyst/redaction-preview/{inv_id}").json()
    assert "## Prior outcomes for similar alerts" in body["original"]
    assert "rule+src+dest" in body["original"]
    assert "false_positive" in body["original"]
    # The block also rides the sanitized side (it egresses like everything else).
    assert "rule+src+dest" in body["sanitized"]
    assert "rationale digests are not stored" in body["note"].lower()


def test_missing_events_409(client: TestClient) -> None:
    """An old investigation without the rebuild events → 409 events_missing
    (machine-readable, so the UI shows a friendly note, not an error)."""
    inv_id = _seed(
        client, [{"sequence": 1, "kind": "tool_call", "payload": {"tool": "prevalence"}}]
    )
    resp = client.get(f"/api/v1/analyst/redaction-preview/{inv_id}")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["code"] == "events_missing"
    assert "enriched_alert_context" in detail["missing"]


def test_unknown_investigation_404(client: TestClient) -> None:
    resp = client.get("/api/v1/analyst/redaction-preview/does-not-exist")
    assert resp.status_code == 404


def test_admin_gated(settings_kratos: Settings) -> None:
    """Admin-gated like the other config/egress reads: with API auth required
    and no admin session, the preview is refused (mirrors /config/egress-policy)."""
    settings = settings_kratos.model_copy(
        update={"api_auth_required": True, "bootstrap_admin_password": SecretStr("pw")}
    )
    for client in _client(settings):
        resp = client.get("/api/v1/analyst/redaction-preview/anything")
        assert resp.status_code in (401, 403)
