"""``ack_alert`` write tool — acknowledge a SOC alert.

Routes via SO 3.0.0's web-API endpoint ``POST /api/events/ack`` (the same
endpoint the SO web UI uses when the analyst clicks the bell icon on an
alert row). v1 originally aimed at the Connect API ``/connect/event/ack``
which is paywalled and never reachable on an OSS grid; this implementation
uses the always-available web path through Kratos cookie auth.

Body shape (matches the SO web UI's hunt route, ``soc_id`` shortcut):

    POST /api/events/ack
    {
        "searchFilter":    "tags:alert",
        "eventFilter":     {"soc_id": "<es-_id>"},
        "dateRange":       "<wide range, see _wide_date_range>",
        "dateRangeFormat": "YYYY/MM/DD h:mm:ss a",
        "timezone":        "America/New_York",
        "escalate":        false,
        "acknowledge":     true   /* false = un-ack */
    }

The ``soc_id`` shortcut is supported by the SO server because the web UI
uses it whenever the alert detail panel is expanded (the JS sends only
``{soc_id}`` instead of every field). For us, every alert id we
investigate IS its ES ``_id`` (== ``soc_id``), so we always use this
path.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from soc_ai.config import Settings
from soc_ai.errors import SoApiError
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.tools._registry import tool

# ES-style document ids are URL-safe alphanumeric tokens, typically 20-char
# base58 strings or sequential ``alert-NNN`` slugs. Whitespace, braces,
# quotes, or control chars in the id would be injection paths in headers,
# JSON bodies, and audit log entries — reject before any HTTP call.
# Mirror add_case_comment's _CASE_ID_RE guard style (same error type and
# message shape).
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

# SO web UI's default i18n.timePickerSample (en-us). The server uses Go's
# `time.Parse` so the FORMAT itself is the canonical Go reference time
# (2006-01-02T15:04:05) projected through the chosen layout. Sending a
# moment.js-style string here returns 400 "could not be processed".
_DATE_RANGE_FORMAT = "2006/01/02 3:04:05 PM"


def _wide_date_range(now: datetime | None = None) -> str:
    """Build a 365-day-wide date range string in SO's expected format.

    SO's events-ack endpoint takes a date range string the operator's web
    UI builds from a date picker. We don't have a picker; pick a range
    wide enough to cover any alert the agent might be triaging.
    """
    now = now or datetime.now(UTC)
    start = now - timedelta(days=365)
    fmt = "%Y/%m/%d %I:%M:%S %p"
    return f"{start.strftime(fmt)} - {now.strftime(fmt)}"


@tool(read_only=False, description="Acknowledge a SOC alert. Optional comment.")
async def ack_alert(
    alert_id: str,
    comment: str | None = None,
    *,
    auth: SoAuthClient,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """POST /api/events/ack with the alert id; mark the alert acknowledged.

    Returns ``{"alert_id": ..., "acknowledged": true, "raw": <api-response>}``
    on 2xx, or raises :class:`SoApiError` on 4xx/5xx. ``comment`` is
    accepted for caller convenience but the SO 3.0.0 ack endpoint does
    not currently surface a comment field; it's silently dropped (a
    note in the audit trail still records what the agent intended).
    """
    if not _EVENT_ID_RE.match(alert_id):
        raise ValueError(
            f"invalid alert_id {alert_id!r}: expected an ES-style id matching "
            r"[A-Za-z0-9_-]{8,128}"
        )
    timezone = settings.so_timezone if settings is not None else "America/New_York"
    body: dict[str, Any] = {
        "searchFilter": "tags:alert",
        "eventFilter": {"soc_id": alert_id},
        "dateRange": _wide_date_range(),
        "dateRangeFormat": _DATE_RANGE_FORMAT,
        "timezone": timezone,
        "escalate": False,
        "acknowledge": True,
    }

    resp = await auth.request("POST", "/api/events/ack", json=body)
    if resp.status_code >= httpx.codes.BAD_REQUEST:
        detail = f"ack_alert returned {resp.status_code}: {resp.text[:300]}"
        if resp.status_code == httpx.codes.BAD_REQUEST:
            # SO 3.0 returns this same generic 400 for an expired srv-token
            # (CSRF), a zero-match event filter, and an already-acknowledged
            # alert alike — the body does not distinguish them.
            detail += (
                " (note: SO 3.0 returns this generic 400 for expired srv-token, "
                "zero-match filter, or already-acknowledged alerts alike)"
            )
        raise SoApiError(
            detail,
            status_code=resp.status_code,
            url="/api/events/ack",
        )

    parsed: Any = None
    if resp.content:
        try:
            parsed = resp.json()
        except ValueError:
            parsed = None

    return {
        "alert_id": alert_id,
        "acknowledged": True,
        "raw": parsed,
    }
