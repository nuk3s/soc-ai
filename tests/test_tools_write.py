"""Tests for write tools.

Write tools are the v1 safety boundary. These tests verify:

- A write tool registered as ``read_only=False`` lands correctly in the
  registry and never auto-executes (it is excluded from the read-only set the
  agent runs freely).
- Each write tool issues the documented HTTP shape via the auth client.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest
from soc_ai.errors import SoApiError
from soc_ai.tools._registry import list_tools
from soc_ai.tools.ack_alert import ack_alert
from soc_ai.tools.add_case_comment import add_case_comment
from soc_ai.tools.escalate_to_case import escalate_to_case

# =====================================================================
# Registry classification
# =====================================================================


def test_registry_classifies_read_and_write_tools() -> None:
    names_read = {t.name for t in list_tools(only_read_only=True)}
    names_all = {t.name for t in list_tools()}

    # Read tools we registered with @tool(read_only=True)
    assert "query_events_oql" in names_read
    assert "get_alert_context" in names_read
    assert "query_cases" in names_read
    assert "query_zeek_logs" in names_read

    # Write tools must not be in the read-only set
    write_names = {"ack_alert", "escalate_to_case", "add_case_comment"}
    assert write_names.isdisjoint(names_read)
    # ...but they must be in the full set
    assert write_names.issubset(names_all)


# =====================================================================
# Write tools (HTTP shape)
# =====================================================================


def _mock_auth(response: httpx.Response) -> AsyncMock:
    auth = AsyncMock()
    auth.request.return_value = response
    return auth


@pytest.mark.asyncio
async def test_ack_alert_posts_soc_id_to_events_ack() -> None:
    """SO 3.0.0 expects POST /api/events/ack with the soc_id shortcut.

    The body shape mirrors what the SO web UI sends from the hunt page
    when the alert detail panel is expanded — eventFilter narrows to the
    specific document via ``soc_id`` (== ES ``_id``) inside a wide
    searchFilter.
    """
    auth = _mock_auth(httpx.Response(200, json={"errors": []}))
    result = await ack_alert("alert-001", "false positive", auth=auth)

    auth.request.assert_awaited_once()
    method, url = auth.request.call_args.args[:2]
    assert method == "POST"
    assert url == "/api/events/ack"

    body = auth.request.call_args.kwargs["json"]
    assert body["searchFilter"] == "tags:alert"
    assert body["eventFilter"] == {"soc_id": "alert-001"}
    assert body["acknowledge"] is True
    assert body["escalate"] is False
    # date-range is a non-empty string in the SO format and timezone is set.
    assert isinstance(body["dateRange"], str)
    assert " - " in body["dateRange"]
    assert body["dateRangeFormat"]
    assert body["timezone"]
    assert result["acknowledged"] is True
    assert result["alert_id"] == "alert-001"


@pytest.mark.asyncio
async def test_ack_alert_uses_configured_timezone() -> None:
    """When `settings` is passed, ack uses settings.so_timezone."""
    from soc_ai.config import Settings

    auth = _mock_auth(httpx.Response(200, json={}))
    settings = Settings.model_construct(so_timezone="UTC")  # type: ignore[arg-type]
    await ack_alert("alert-001", auth=auth, settings=settings)
    assert auth.request.call_args.kwargs["json"]["timezone"] == "UTC"


@pytest.mark.asyncio
async def test_ack_alert_raises_on_4xx() -> None:
    auth = _mock_auth(httpx.Response(403, text="forbidden"))
    with pytest.raises(SoApiError, match="403"):
        await ack_alert("alert-001", auth=auth)


@pytest.mark.asyncio
async def test_escalate_to_case_posts_full_body() -> None:
    auth = _mock_auth(httpx.Response(201, json={"id": "case-new", "title": "Suspicious"}))
    result = await escalate_to_case(
        "alert-001",
        case_title="Suspicious",
        case_description="Triage outbound traffic from workstation-01",
        auth=auth,
    )
    body = auth.request.call_args.kwargs["json"]
    assert body == {
        "title": "Suspicious",
        "description": "Triage outbound traffic from workstation-01",
        "originalEventId": "alert-001",
    }
    assert result["id"] == "case-new"


@pytest.mark.asyncio
async def test_escalate_to_case_validates_inputs() -> None:
    auth = _mock_auth(httpx.Response(200, json={}))
    with pytest.raises(ValueError, match="case_title"):
        await escalate_to_case("alert-001", case_title=" ", case_description="x", auth=auth)
    with pytest.raises(ValueError, match="case_description"):
        await escalate_to_case("alert-001", case_title="x", case_description="", auth=auth)
    auth.request.assert_not_called()


@pytest.mark.asyncio
async def test_escalate_to_case_raises_on_5xx() -> None:
    auth = _mock_auth(httpx.Response(503, text="busy"))
    with pytest.raises(SoApiError, match="503"):
        await escalate_to_case("alert-001", case_title="x", case_description="y", auth=auth)


@pytest.mark.asyncio
async def test_add_case_comment_posts_description() -> None:
    auth = _mock_auth(httpx.Response(200, json={"id": "comment-1"}))
    result = await add_case_comment("case-001", "investigated; closing", auth=auth)
    method, url = auth.request.call_args.args[:2]
    assert method == "POST"
    assert url == "/connect/case/case-001/comment"
    assert auth.request.call_args.kwargs["json"] == {"description": "investigated; closing"}
    assert result["id"] == "comment-1"


@pytest.mark.asyncio
async def test_add_case_comment_rejects_empty() -> None:
    auth = _mock_auth(httpx.Response(200, json={}))
    with pytest.raises(ValueError, match="comment"):
        await add_case_comment("case-001", "", auth=auth)
    auth.request.assert_not_called()


@pytest.mark.asyncio
async def test_add_case_comment_rejects_path_injecting_case_id() -> None:
    """A case_id with path-control characters must be refused before any
    request — it is interpolated into the URL path."""
    auth = _mock_auth(httpx.Response(200, json={}))
    for bad in ("../../connect/case", "case/../admin", "case?x=1", "case#frag", "case 1"):
        with pytest.raises(ValueError, match="invalid case_id"):
            await add_case_comment(bad, "noted", auth=auth)
    auth.request.assert_not_called()


@pytest.mark.asyncio
async def test_add_case_comment_returns_synthetic_when_response_not_json() -> None:
    auth = _mock_auth(httpx.Response(200, text="OK"))
    result = await add_case_comment("case-001", "noted", auth=auth)
    assert result == {"case_id": "case-001", "added": True}


@pytest.mark.asyncio
async def test_ack_alert_returns_synthetic_when_response_not_json() -> None:
    auth = _mock_auth(httpx.Response(200, text=""))
    result = await ack_alert("alert-001", auth=auth)
    assert result["alert_id"] == "alert-001"
    assert result["acknowledged"] is True
    assert result["raw"] is None


# =====================================================================
# C7: ID-shape guards for ack_alert and escalate_to_case
# =====================================================================

_INVALID_IDS = [
    'abc"}',  # brace + quote
    "x y",  # whitespace
    "a\nb",  # control char (newline)
    "a\x00b",  # NUL byte
    "short",  # too short (< 8 chars)
    "a" * 129,  # too long (> 128 chars)
    "../../etc",  # path traversal
]

_VALID_ID = "alert-001"  # 9 chars, safe


@pytest.mark.asyncio
async def test_ack_alert_rejects_malformed_ids() -> None:
    """ack_alert raises ValueError BEFORE any HTTP call for malformed ids."""
    for bad_id in _INVALID_IDS:
        auth = _mock_auth(httpx.Response(200, json={}))
        with pytest.raises(ValueError, match="invalid alert_id"):
            await ack_alert(bad_id, auth=auth)
        auth.request.assert_not_called()


@pytest.mark.asyncio
async def test_ack_alert_accepts_valid_id() -> None:
    """A well-formed ES-style id passes validation."""
    auth = _mock_auth(httpx.Response(200, json={}))
    result = await ack_alert(_VALID_ID, auth=auth)
    assert result["acknowledged"] is True
    auth.request.assert_awaited_once()


@pytest.mark.asyncio
async def test_escalate_to_case_rejects_malformed_ids() -> None:
    """escalate_to_case raises ValueError BEFORE any HTTP call for malformed ids."""
    for bad_id in _INVALID_IDS:
        auth = _mock_auth(httpx.Response(200, json={}))
        with pytest.raises(ValueError, match="invalid alert_id"):
            await escalate_to_case(bad_id, case_title="T", case_description="D", auth=auth)
        auth.request.assert_not_called()


@pytest.mark.asyncio
async def test_escalate_to_case_accepts_valid_id() -> None:
    """A well-formed ES-style id passes validation."""
    auth = _mock_auth(httpx.Response(201, json={"id": "case-new"}))
    result = await escalate_to_case(
        _VALID_ID, case_title="Title", case_description="Desc", auth=auth
    )
    assert result["id"] == "case-new"
    auth.request.assert_awaited_once()
