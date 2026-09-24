"""``ack_alert`` write tool — acknowledge a SOC alert.

Routes via SO 3.0.0's web-API endpoint ``POST /api/events/ack`` (the same
endpoint the SO web UI uses when the analyst clicks the bell icon on an
alert row). v1 originally aimed at the Connect API ``/connect/event/ack``
which is paywalled and never reachable on an OSS grid; this implementation
uses the always-available web path through Kratos cookie auth.

Body shape (matches the SO web UI's hunt route, ``soc_id`` shortcut):

    POST /api/events/ack
    {
        "searchFilter":    "*",
        "eventFilter":     {"soc_id": "<es-_id>"},
        "dateRange":       "<wide range, see _so_api.wide_date_range>",
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
from typing import Any

import httpx

from soc_ai.config import Settings
from soc_ai.errors import SoApiError
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.tools._registry import tool
from soc_ai.tools._so_api import DATE_RANGE_FORMAT, DEFAULT_TIMEZONE, wide_date_range

# ES-style document ids are URL-safe alphanumeric tokens, typically 20-char
# base58 strings or sequential ``alert-NNN`` slugs. Whitespace, braces,
# quotes, or control chars in the id would be injection paths in headers,
# JSON bodies, and audit log entries — reject before any HTTP call.
# Mirror add_case_comment's _CASE_ID_RE guard style (same error type and
# message shape).
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

# Scope filter for the ack. Security Onion ANDs this with the ``eventFilter``
# pin, so anything narrower than "everything" silently excludes alerts that do
# not match it. This used to be the literal ``tags:alert``, which held only
# while every alert soc-ai could show carried Security Onion's own tag. Elastic
# Defend endpoint alerts do not: Elastic's package pipeline writes them, they
# never reach the tag-deriving pipeline, and they carry ``event.kind:alert``
# instead.
#
# Measured on a live SO 3.x grid on 2026-09-05, one variable changed per probe,
# same session and same auth:
#   tags:alert + soc_id=<sigma alert, tagged>    -> 200, updatedCount 1
#   tags:alert + soc_id=<Defend endpoint alert>  -> 400, still unacknowledged
#   *          + soc_id=<Defend endpoint alert>  -> 200, updatedCount 1
# The last probe ran over a window holding roughly fifteen documents and still
# updated exactly one, which is the evidence that the pin, not the scope, is
# what narrows the write.
#
# Deliberately NOT derived from ``webui_alerts_query``: the feed unions that
# setting with other sources, so a feed-visible alert can miss it, and a grid
# whose operator narrowed the setting would get a narrowed ack scope with it.
# Leaning on the pin is safe because ``_EVENT_ID_RE`` rejects an empty or
# malformed id before any HTTP call, so an ack can never go out unpinned.
_ACK_SCOPE_FILTER = "*"


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
    on 2xx, or raises :class:`SoApiError` on 4xx/5xx. ``comment`` is accepted
    for caller convenience but the SO 3.0.0 ack endpoint has no comment field,
    so it never reaches the SO record. When a comment is supplied the result
    also carries ``"comment_persisted": False`` so the caller is not left
    believing SO now holds that context — only soc-ai's own audit trail records
    the intended comment.
    """
    if not _EVENT_ID_RE.match(alert_id):
        raise ValueError(
            f"invalid alert_id {alert_id!r}: expected an ES-style id matching "
            r"[A-Za-z0-9_-]{8,128}"
        )
    timezone = settings.so_timezone if settings is not None else DEFAULT_TIMEZONE
    body: dict[str, Any] = {
        "searchFilter": _ACK_SCOPE_FILTER,
        "eventFilter": {"soc_id": alert_id},
        "dateRange": wide_date_range(),
        "dateRangeFormat": DATE_RANGE_FORMAT,
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

    result: dict[str, Any] = {
        "alert_id": alert_id,
        "acknowledged": True,
        "raw": parsed,
    }
    if comment is not None:
        # SO 3.0.0's ack endpoint has no comment field, so the supplied comment
        # never lands in the SO record. Flag that explicitly rather than letting
        # the caller assume it persisted (only the audit trail keeps the intent).
        result["comment_persisted"] = False
    return result
