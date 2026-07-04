"""Audit fail-closed wiring on the SO-mutating write path (execute_write_tool).

Covers the requirement that a mutating action is aborted BEFORE touching
Security Onion when its audit record can't be written and ``audit_fail_closed``
is on — and proceeds (fail-open) when the setting is off.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.api.approvals import execute_write_tool
from soc_ai.audit.logger import AuditLogger
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._registry import ToolSpec


class _ES:
    """ES double whose index() raises (simulated audit-index outage)."""

    def __init__(self, *, index_fails: bool) -> None:
        self.index_fails = index_fails
        self.indexed: list[dict[str, Any]] = []
        self.indices = AsyncMock()

    async def index(self, *, index: str, body: dict[str, Any]) -> None:
        if self.index_fails:
            raise RuntimeError("audit ES down")
        self.indexed.append(body)

    async def search(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return {"hits": {"hits": []}}  # start from genesis


def _audit(es: _ES, settings: Settings) -> AuditLogger:
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es):
        elastic = ElasticClient(settings)
    return AuditLogger(settings, elastic)


def _fake_ack_tool(executed: list[str]):
    """A fake ack_alert tool that records when the SO write actually runs."""

    async def fn(alert_id: str, *, auth: Any = None, settings: Any = None) -> dict[str, Any]:
        executed.append(alert_id)
        return {"acknowledged": True}

    return ToolSpec(name="ack_alert", read_only=False, description="", func=fn)


@pytest.mark.asyncio
async def test_fail_closed_aborts_so_write(settings_kratos: Settings) -> None:
    """audit_fail_closed=True + audit write fails ⇒ error returned, SO not touched."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    es = _ES(index_fails=True)
    audit = _audit(es, settings)
    executed: list[str] = []

    with patch("soc_ai.tools.write_exec.get_tool", return_value=_fake_ack_tool(executed)):
        result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": "es-1"},
            auth=AsyncMock(),
            settings=settings,
            audit=audit,
        )

    assert result is None
    assert error is not None and "aborted" in error
    assert executed == []  # the SO state change NEVER ran


@pytest.mark.asyncio
async def test_fail_open_proceeds_when_setting_off(settings_kratos: Settings) -> None:
    """audit_fail_closed=False + audit write fails ⇒ SO write still proceeds."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": False})
    es = _ES(index_fails=True)
    audit = _audit(es, settings)
    executed: list[str] = []

    with patch("soc_ai.tools.write_exec.get_tool", return_value=_fake_ack_tool(executed)):
        result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": "es-1"},
            auth=AsyncMock(),
            settings=settings,
            audit=audit,
        )

    assert error is None
    assert result == {"acknowledged": True}
    assert executed == ["es-1"]  # SO write happened despite the audit failure


@pytest.mark.asyncio
async def test_no_audit_logger_is_unaudited_passthrough(settings_kratos: Settings) -> None:
    """Without an audit logger the path behaves exactly as before (no abort)."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    executed: list[str] = []
    with patch("soc_ai.tools.write_exec.get_tool", return_value=_fake_ack_tool(executed)):
        _result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": "es-1"},
            auth=AsyncMock(),
            settings=settings,
            audit=None,
        )
    assert error is None
    assert executed == ["es-1"]


@pytest.mark.asyncio
async def test_successful_audit_then_so_write_records_both(settings_kratos: Settings) -> None:
    """When ES is healthy, both the intent and result audit records are written."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    es = _ES(index_fails=False)
    audit = _audit(es, settings)
    executed: list[str] = []
    with patch("soc_ai.tools.write_exec.get_tool", return_value=_fake_ack_tool(executed)):
        _result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": "es-1"},
            auth=AsyncMock(),
            settings=settings,
            audit=audit,
        )
    assert error is None
    assert executed == ["es-1"]
    phases = [d["payload"]["phase"] for d in es.indexed]
    assert phases == ["intent", "result"]
    # The intent record is the mutating one and carries the hash chain.
    assert es.indexed[0]["seq"] == 0
    assert es.indexed[0]["hash"] is not None


@pytest.mark.asyncio
async def test_audit_records_resolved_approver(settings_kratos: Settings) -> None:
    """A write's audit events carry the resolved approver in ``approved_by``."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    es = _ES(index_fails=False)
    audit = _audit(es, settings)
    executed: list[str] = []
    with patch("soc_ai.tools.write_exec.get_tool", return_value=_fake_ack_tool(executed)):
        _result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": "es-1"},
            auth=AsyncMock(),
            settings=settings,
            audit=audit,
            user="token:analyst-jane",
        )
    assert error is None
    # Both intent + result records attribute the write to the resolved caller.
    assert [d["approved_by"] for d in es.indexed] == [
        "token:analyst-jane",
        "token:analyst-jane",
    ]
    assert [d["user"] for d in es.indexed] == ["token:analyst-jane", "token:analyst-jane"]


@pytest.mark.asyncio
async def test_audit_records_anonymous_when_unauthenticated(
    settings_kratos: Settings,
) -> None:
    """A no-auth write records ``approved_by="anonymous"`` (not the bare default)."""
    settings = settings_kratos.model_copy(update={"audit_fail_closed": True})
    es = _ES(index_fails=False)
    audit = _audit(es, settings)
    executed: list[str] = []
    with patch("soc_ai.tools.write_exec.get_tool", return_value=_fake_ack_tool(executed)):
        # No `user=` passed → defaults to "unknown"; normalized to "anonymous".
        _result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": "es-1"},
            auth=AsyncMock(),
            settings=settings,
            audit=audit,
        )
    assert error is None
    assert all(d["approved_by"] == "anonymous" for d in es.indexed)
