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
from soc_ai.tools._so_api import DATE_RANGE_FORMAT
from soc_ai.tools.ack_alert import ack_alert
from soc_ai.tools.add_case_comment import add_case_comment
from soc_ai.tools.escalate_to_case import escalate_to_case
from soc_ai.webui.alerts_query import ALERT_LABEL_CANDIDATES

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


def _mock_auth_seq(*responses: httpx.Response) -> AsyncMock:
    """An auth client that answers each successive request from ``responses``."""
    auth = AsyncMock()
    auth.request.side_effect = list(responses)
    return auth


def _requested_urls(auth: AsyncMock) -> list[str]:
    return [call.args[1] for call in auth.request.call_args_list]


@pytest.mark.asyncio
async def test_ack_alert_posts_soc_id_to_events_ack() -> None:
    """SO 3.0.0 expects POST /api/events/ack with the soc_id shortcut.

    The body shape mirrors what the SO web UI sends from the hunt page
    when the alert detail panel is expanded — eventFilter narrows to the
    specific document via ``soc_id`` (== ES ``_id``) inside a wide
    searchFilter.
    """
    from soc_ai.tools.ack_alert import _ACK_SCOPE_FILTER

    auth = _mock_auth(httpx.Response(200, json={"errors": []}))
    result = await ack_alert("alert-001", "false positive", auth=auth)

    auth.request.assert_awaited_once()
    method, url = auth.request.call_args.args[:2]
    assert method == "POST"
    assert url == "/api/events/ack"

    body = auth.request.call_args.kwargs["json"]
    assert body["searchFilter"] == _ACK_SCOPE_FILTER
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
async def test_ack_alert_scope_does_not_exclude_alerts_missing_a_label() -> None:
    """The ack scope must not name an alert label the target may not carry.

    Security Onion ANDs ``searchFilter`` with the ``eventFilter`` pin, so a
    scope naming one label silently excludes every alert written without it.
    Verified on a live SO 3.x grid: with ``searchFilter`` set to ``tags:alert``
    an Elastic Defend endpoint alert (``event.kind:alert``, no SO tag) returned
    400 and stayed unacknowledged, while the same document under a permissive
    scope returned 200 with ``updatedCount: 1``.

    The pin is what narrows the write, and ``_EVENT_ID_RE`` guarantees it is
    present and well formed before the call, so the scope carries no safety
    weight and must not carry a label.
    """
    auth = _mock_auth(httpx.Response(200, json={"errors": []}))
    await ack_alert("alert-001", auth=auth)

    body = auth.request.call_args.kwargs["json"]
    assert body["searchFilter"] == "*"
    # The pin still has to be there: a permissive scope with no pin would be a
    # grid-wide write.
    assert body["eventFilter"] == {"soc_id": "alert-001"}
    # Negative control: naming ANY of the labels a grid uses to mean "alert"
    # reintroduces the defect, whichever one is chosen.
    for label in ALERT_LABEL_CANDIDATES:
        assert label not in body["searchFilter"]


@pytest.mark.asyncio
async def test_ack_alert_scope_ignores_the_configured_alerts_query() -> None:
    """Deriving the scope from ``webui_alerts_query`` would rebuild the bug.

    An operator whose feed is narrowed to one label would get an ack scope
    narrowed to the same label, and the feed unions in Sigma and Zeek-notice
    sources on top of that setting anyway, so a feed-visible alert can miss it.
    """
    from soc_ai.config import Settings

    auth = _mock_auth(httpx.Response(200, json={}))
    settings = Settings.model_construct(  # type: ignore[arg-type]
        so_timezone="UTC", webui_alerts_query="tags:alert"
    )
    await ack_alert("alert-001", auth=auth, settings=settings)
    assert auth.request.call_args.kwargs["json"]["searchFilter"] == "*"


@pytest.mark.asyncio
async def test_ack_alert_never_sends_comment_and_signals_not_persisted() -> None:
    """SO 3.0.0's /api/events/ack has no comment field. ack_alert must (a) never
    put ``comment`` in the request body, and (b) signal ``comment_persisted=False``
    so the UI/analyst is not left believing SO now carries that context (F54).

    The body assertion also pins the contract: a future SO version that DOES add
    a comment field can't silently start relying on it without a test noticing.
    """
    auth = _mock_auth(httpx.Response(200, json={"errors": []}))
    result = await ack_alert(
        "alert-001", comment="confirmed internal vuln scanner per case #123", auth=auth
    )
    body = auth.request.call_args.kwargs["json"]
    assert "comment" not in body
    assert result["comment_persisted"] is False


@pytest.mark.asyncio
async def test_ack_alert_omits_persist_signal_when_no_comment() -> None:
    """With no comment supplied there is nothing to flag — the signal is absent."""
    auth = _mock_auth(httpx.Response(200, json={}))
    result = await ack_alert("alert-001", auth=auth)
    assert "comment_persisted" not in result


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
async def test_escalate_to_case_creates_the_case_then_links_the_alert() -> None:
    """SO 3.x has no single "escalate this alert" route.

    Creating a case and linking an event to it are two calls, exactly as the SO
    web UI makes them: ``POST /api/case/`` returns the new case, then
    ``POST /api/case/events`` attaches the alert by its ``soc_id``. Measured
    against a live SO 3.2.0 grid on 2026-09-06.
    """
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new", "title": "Suspicious"}),
        httpx.Response(202, json={"count": 1}),
        httpx.Response(200, json={}),
    )
    result = await escalate_to_case(
        "alert-001",
        case_title="Suspicious",
        case_description="Triage outbound traffic from workstation-01",
        auth=auth,
    )

    create, attach, _mark = auth.request.call_args_list
    assert create.args[:2] == ("POST", "/api/case/")
    assert create.kwargs["json"] == {
        "title": "Suspicious",
        "description": "Triage outbound traffic from workstation-01",
    }

    assert attach.args[:2] == ("POST", "/api/case/events")
    attach_body = attach.kwargs["json"]
    assert attach_body["caseId"] == "case-new"
    assert attach_body["fields"] == {"soc_id": "alert-001"}
    assert attach_body["dateRangeFormat"] == DATE_RANGE_FORMAT
    assert " - " in attach_body["dateRange"]
    assert attach_body["timezone"]

    assert result["case_id"] == "case-new"
    assert result["case_created"] is True
    assert result["alert_linked"] is True
    assert result["events_attached"] == 1


@pytest.mark.asyncio
async def test_escalate_to_case_never_targets_the_connect_api() -> None:
    """Negative control for the defect: ``/connect/*`` is the licensed external
    alias, absent on an unlicensed grid (measured: nginx 404, not a SOC error).
    No request this tool makes may go there."""
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new"}),
        httpx.Response(202, json={"count": 1}),
        httpx.Response(200, json={}),
    )
    await escalate_to_case("alert-001", case_title="T", case_description="D", auth=auth)
    assert all(not url.startswith("/connect") for url in _requested_urls(auth))


@pytest.mark.asyncio
async def test_escalate_to_case_marks_the_alert_escalated_in_security_onion() -> None:
    """The third write Security Onion's own console makes.

    Attaching an alert to a case writes a related document on the case and
    nothing on the alert, so an alert soc-ai escalated still reads as untouched
    in Security Onion's alert list. An analyst working that list escalates it
    again, and the grid ends up with two cases for one alert by a route no
    ledger inside soc-ai can see.

    Measured against a live SO 3.2.0 grid on 2026-09-06, one variable changed
    per probe, reading ``_source`` before and after:

        escalate=true,  acknowledge=true  -> 200, escalated=true, acknowledged=true
        escalate=true,  acknowledge=false -> 200, escalated unset, acknowledged=false

    So the acknowledge is not an optional extra: Security Onion applies the
    ``acknowledge`` value to both flags, and there is no request shape that
    stamps escalated on its own. That matches the console, where escalating an
    alert also takes it out of the triage queue, which is the right outcome for
    an alert that is now case work.
    """
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new"}),
        httpx.Response(202, json={"count": 1}),
        httpx.Response(200, json={}),
    )
    result = await escalate_to_case("alert-001", case_title="T", case_description="D", auth=auth)

    mark = auth.request.call_args_list[2]
    assert mark.args[:2] == ("POST", "/api/events/ack")
    body = mark.kwargs["json"]
    assert body["eventFilter"] == {"soc_id": "alert-001"}
    assert body["escalate"] is True
    assert body["acknowledge"] is True
    assert result["marked_escalated"] is True


@pytest.mark.asyncio
async def test_a_failed_mark_never_undoes_the_case() -> None:
    """The case exists the moment Security Onion answers the create. A flag that
    would not stamp is a cosmetic loss in one console; raising on it would make
    the caller retry and open a second case, which is the defect this whole path
    exists to avoid."""
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new"}),
        httpx.Response(202, json={"count": 1}),
        httpx.Response(400, text="The request could not be processed."),
    )
    result = await escalate_to_case("alert-001", case_title="T", case_description="D", auth=auth)

    assert result["case_id"] == "case-new"
    assert result["alert_linked"] is True
    assert result["marked_escalated"] is False
    assert "400" in result["mark_error"]


@pytest.mark.asyncio
async def test_an_unattached_alert_is_never_marked_escalated() -> None:
    """Negative control. The stamp says "this alert is on a case". When the
    attach failed the alert is NOT on the case, and stamping it would hide a
    real alert from the triage queue on the strength of a link that does not
    exist."""
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new"}),
        httpx.Response(500, text="nope"),
    )
    result = await escalate_to_case("alert-001", case_title="T", case_description="D", auth=auth)

    assert result["alert_linked"] is False
    assert result["marked_escalated"] is False
    assert "/api/events/ack" not in _requested_urls(auth)


@pytest.mark.asyncio
async def test_escalate_to_case_reports_an_unlinked_alert_without_raising() -> None:
    """The case already exists once the create returns, so a failed link must not
    raise: a retry would open a second case. Report the case id and say plainly
    that the alert is not attached to it."""
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new"}),
        httpx.Response(500, text="The request could not be processed."),
    )
    result = await escalate_to_case("alert-001", case_title="T", case_description="D", auth=auth)
    assert result["case_id"] == "case-new"
    assert result["case_created"] is True
    assert result["alert_linked"] is False
    assert result["events_attached"] == 0
    assert "500" in result["link_error"]


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
async def test_escalate_to_case_returns_synthetic_when_response_not_json() -> None:
    """A 2xx with an empty/non-JSON body (transient proxy, 204 variant) means the
    case WAS created SO-side. Raising here would make the caller/agent retry and
    create a DUPLICATE case, so degrade gracefully — mirroring add_case_comment's
    identical-situation handling (F55). Only 4xx/5xx is a real failure.

    Without a case id there is nothing to attach the alert to, so the link is
    reported as not done rather than attempted against a guessed id."""
    for resp in (httpx.Response(201, text=""), httpx.Response(200, text="OK")):
        auth = _mock_auth(resp)
        result = await escalate_to_case(
            "alert-001", case_title="Suspicious", case_description="triage", auth=auth
        )
        assert result["case_created"] is True
        assert result["case_id"] is None
        assert result["alert_linked"] is False
        assert auth.request.await_count == 1


@pytest.mark.asyncio
async def test_add_case_comment_posts_to_the_case_comments_route() -> None:
    """SO 3.x takes the case id in the BODY, not the path: the per-case
    ``/api/case/{id}/comment`` shape 404s (measured on a live SO 3.2.0 grid on
    2026-09-06); ``POST /api/case/comments`` with ``caseId`` + ``description``
    returns the stored comment."""
    auth = _mock_auth(httpx.Response(200, json={"id": "comment-1"}))
    result = await add_case_comment("case-001", "investigated; closing", auth=auth)
    method, url = auth.request.call_args.args[:2]
    assert method == "POST"
    assert url == "/api/case/comments"
    assert auth.request.call_args.kwargs["json"] == {
        "caseId": "case-001",
        "description": "investigated; closing",
    }
    assert result["id"] == "comment-1"


@pytest.mark.asyncio
async def test_add_case_comment_never_targets_the_connect_api() -> None:
    """Negative control for the defect: no request may reach ``/connect/*``."""
    auth = _mock_auth(httpx.Response(200, json={"id": "comment-1"}))
    await add_case_comment("case-001", "noted", auth=auth)
    assert all(not url.startswith("/connect") for url in _requested_urls(auth))


@pytest.mark.asyncio
async def test_add_case_comment_rejects_empty() -> None:
    auth = _mock_auth(httpx.Response(200, json={}))
    with pytest.raises(ValueError, match="comment"):
        await add_case_comment("case-001", "", auth=auth)
    auth.request.assert_not_called()


@pytest.mark.asyncio
async def test_add_case_comment_rejects_malformed_case_id() -> None:
    """A hallucinated or hostile case_id is refused before any request.

    SO 3.x carries the id in the body rather than the path, so this is no longer
    a URL-routing guard; it is still the cheapest way to turn a bad id into a
    clear error instead of the grid's opaque 500."""
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
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new"}),
        httpx.Response(202, json={"count": 1}),
        httpx.Response(200, json={}),
    )
    result = await escalate_to_case(
        _VALID_ID, case_title="Title", case_description="Desc", auth=auth
    )
    assert result["case_id"] == "case-new"
    assert auth.request.await_count == 3


# =====================================================================
# An accepted attach that attached nothing is not a linked alert
# =====================================================================


@pytest.mark.asyncio
async def test_a_case_that_attached_nothing_is_not_a_linked_alert() -> None:
    """The defect, at the tool. Security Onion answers the attach 200 with
    ``{"count": 0}`` when the query it rebuilds from ``fields`` matches no
    document, which is what happens when the alert rolled over or was deleted
    between the read and the write. Nothing is on the case, and the tool used to
    call that a link because the status code was not an error.
    """
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new"}),
        httpx.Response(200, json={"count": 0}),
    )
    result = await escalate_to_case("alert-001", case_title="T", case_description="D", auth=auth)

    assert result["case_created"] is True
    assert result["case_id"] == "case-new"
    assert result["alert_linked"] is False
    assert result["events_attached"] == 0
    assert "case-new" in result["link_error"]
    assert "alert-001" in result["link_error"]
    # The stamp says "this alert is on a case". It is not.
    assert "/api/events/ack" not in _requested_urls(auth)


@pytest.mark.asyncio
async def test_an_attach_that_reports_no_count_is_not_reported_as_linked() -> None:
    """A 2xx whose body carries no ``count`` is an unobserved attach, not an
    observed one. Reading it as a link is the same false all-clear as reading a
    zero as a link, so it is reported as unconfirmed and the alert is not
    stamped escalated on the strength of it."""
    for body in ({}, {"count": None}):
        auth = _mock_auth_seq(
            httpx.Response(200, json={"id": "case-new"}),
            httpx.Response(202, json=body),
        )
        result = await escalate_to_case(
            "alert-001", case_title="T", case_description="D", auth=auth
        )
        assert result["alert_linked"] is False
        assert result["events_attached"] == 0
        assert "case-new" in result["link_error"]
        assert "/api/events/ack" not in _requested_urls(auth)


@pytest.mark.asyncio
async def test_an_attach_that_reports_one_event_still_links_and_stamps() -> None:
    """Negative control for the two above. The ordinary escalate, where Security
    Onion really did attach the alert, must still read as linked and must still
    stamp the flag. A guard that refused every escalate would pass the two tests
    above and be worse than the defect."""
    auth = _mock_auth_seq(
        httpx.Response(200, json={"id": "case-new"}),
        httpx.Response(202, json={"count": 1}),
        httpx.Response(200, json={}),
    )
    result = await escalate_to_case("alert-001", case_title="T", case_description="D", auth=auth)

    assert result["alert_linked"] is True
    assert result["events_attached"] == 1
    assert result["marked_escalated"] is True
    assert "link_error" not in result
    assert "/api/events/ack" in _requested_urls(auth)
