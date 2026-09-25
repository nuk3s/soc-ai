"""The SO-write guard keys off every promoted anchor, whatever kind promoted it.

A finding promotion lands ``kind='hunt'``; a lead promotion lands
``kind='lead'`` with the hunt as its subject. Both anchor on a cited telemetry
document that has no Security Onion alert behind it, so every surface that
refuses (or disarms) a write over a hunt-kind anchor must do the same over a
lead-kind anchor: ``hunt_anchor_ids`` itself, ``POST /investigate`` (runs with
SO writes off) and ``POST /alerts/ack-events`` (refuses the id outright).

Known trade-off, the same one already accepted for hunt-kind anchors: a lead
whose anchor happens to be a real alert document has ack-events refused for
that id. The analyst acks it from the alert itself.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

_ORIGIN = {"Origin": "http://testserver"}

_LEAD_SUBJECT: dict[str, Any] = {
    "type": "hunt",
    "hunt_id": "01HUNTLEAD00000000000000000",
    "lead_id": 7,
}


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _seed_lead_promotion(client: TestClient, *, alert_es_id: str) -> str:
    """Seed what ``POST /hunts/leads/{id}/promote`` persists: a ``kind='lead'``
    row anchored on a cited document, with the hunt as its subject."""
    import asyncio

    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id=alert_es_id,
                started_by="audit",
                rule_name="Lead 7 on 10.0.0.5",
                kind="lead",
                hunt_id=_LEAD_SUBJECT["hunt_id"],
                subject=_LEAD_SUBJECT,
            )
            return inv.id

    return asyncio.run(_go())


async def test_hunt_anchor_ids_recognises_a_lead_promotion_anchor(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await inv_svc.create(
            db,
            alert_es_id="lead-anchor-1",
            started_by="x",
            rule_name="Lead 7 on 10.0.0.5",
            kind="lead",
            hunt_id=_LEAD_SUBJECT["hunt_id"],
            subject=_LEAD_SUBJECT,
        )
        await inv_svc.create(
            db,
            alert_es_id="hunt-anchor-1",
            started_by="x",
            rule_name="Beaconing to rare external IP",
            kind="hunt",
            hunt_id=_LEAD_SUBJECT["hunt_id"],
            finding_ordinal=0,
        )
        await inv_svc.create(db, alert_es_id="plain-alert-1", started_by="x", rule_name="ET X")

        anchors = await inv_svc.hunt_anchor_ids(
            db, ["lead-anchor-1", "hunt-anchor-1", "plain-alert-1", "unknown-1"]
        )
    assert anchors == {"lead-anchor-1", "hunt-anchor-1"}
    await engine.dispose()


def test_investigate_disables_so_writes_over_a_lead_anchor(
    audit_client: TestClient, analyst_session: dict[str, str]
) -> None:
    anchor = "lead-anchor-000001"
    _seed_lead_promotion(audit_client, alert_es_id=anchor)

    captured: dict[str, Any] = {}

    def _fake_investigate(alert_id: str, **kwargs: Any) -> Any:
        async def _gen() -> Any:
            captured["alert_id"] = alert_id
            captured["kwargs"] = kwargs
            return
            yield  # pragma: no cover — makes _gen an async generator

        return _gen()

    with patch("soc_ai.api.routes.investigate", _fake_investigate):
        resp = audit_client.post(
            "/investigate",
            json={"alert_id": anchor},
            cookies=analyst_session,
            headers=_ORIGIN,
        )

    assert resp.status_code == 200, resp.text
    assert captured, "patched investigate() was never consumed"
    assert captured["kwargs"].get("allow_so_writes") is False, (
        f"/investigate launched over a lead anchor with SO writes enabled: {captured['kwargs']}"
    )


def test_ack_events_refuses_a_promoted_lead_anchor(
    audit_client: TestClient, analyst_session: dict[str, str]
) -> None:
    anchor = "lead-anchor-000002"
    _seed_lead_promotion(audit_client, alert_es_id=anchor)

    with patch(
        "soc_ai.api.webui.routes_alert_actions.execute_write_tool",
        new=AsyncMock(return_value=({}, None)),
    ) as write_spy:
        resp = audit_client.post(
            "/api/v1/alerts/ack-events",
            json={"es_ids": [anchor]},
            cookies=analyst_session,
            headers=_ORIGIN,
        )

    assert resp.status_code == 400, f"lead anchor ack not refused: {resp.status_code} {resp.text}"
    assert resp.json()["detail"]["reason"] == "hunt_kind_no_so_target"
    write_spy.assert_not_awaited()


@pytest.mark.parametrize("promoted_kind", ["hunt", "lead"])
def test_execute_action_refuses_a_row_laundered_over_a_promoted_anchor(
    audit_client: TestClient, analyst_session: dict[str, str], promoted_kind: str
) -> None:
    """The execute-action guard keys off the anchor document: an ordinary
    kind='suricata' row over a promoted anchor (a re-investigation) must not
    launder the ack, whichever kind promoted the anchor."""
    import asyncio

    anchor = f"promoted-anchor-{promoted_kind}"

    async def _go() -> str:
        maker = audit_client.app.state.db_sessionmaker
        async with maker() as db:
            await inv_svc.create(
                db,
                alert_es_id=anchor,
                started_by="audit",
                kind=promoted_kind,
                hunt_id=_LEAD_SUBJECT["hunt_id"],
                finding_ordinal=0 if promoted_kind == "hunt" else None,
                subject=_LEAD_SUBJECT if promoted_kind == "lead" else None,
            )
            laundered = await inv_svc.create(db, alert_es_id=anchor, started_by="audit")
            await inv_svc.finalize(
                db,
                laundered.id,
                status="complete",
                verdict="true_positive",
                report={
                    "recommended_actions": [
                        {"tool_name": "ack_alert", "tool_args": {}, "rationale": "ack it"}
                    ]
                },
            )
            return laundered.id

    laundered_id = asyncio.run(_go())

    with patch(
        "soc_ai.api.webui.routes_actions.execute_write_tool",
        new=AsyncMock(return_value=({}, None)),
    ) as write_spy:
        resp = audit_client.post(
            f"/api/v1/investigations/{laundered_id}/actions/0/execute",
            cookies=analyst_session,
            headers=_ORIGIN,
        )

    assert resp.status_code == 400, f"laundered ack not refused: {resp.status_code} {resp.text}"
    assert resp.json()["detail"]["reason"] == "hunt_kind_no_so_target"
    write_spy.assert_not_awaited()
