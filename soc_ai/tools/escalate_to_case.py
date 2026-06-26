"""``escalate_to_case`` write tool - create a SOC case from an alert.

Routes via ``POST /connect/case`` with title/description/originalEventId.
Approval-gated.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from soc_ai.errors import SoApiError
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.tools._registry import tool

# ES-style document ids are URL-safe alphanumeric tokens. The alert_id is
# carried in the JSON body as originalEventId; reject malformed ids before
# any HTTP call. Mirror add_case_comment's _CASE_ID_RE guard style.
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


@tool(
    read_only=False,
    description="Create a SOC case from an alert (title + description required).",
)
async def escalate_to_case(
    alert_id: str,
    case_title: str,
    case_description: str,
    *,
    auth: SoAuthClient,
) -> dict[str, Any]:
    """POST /connect/case with title/description, linking to ``alert_id``.

    Returns the new case JSON on 2xx, or raises :class:`SoApiError`.
    """
    if not _EVENT_ID_RE.match(alert_id):
        raise ValueError(
            f"invalid alert_id {alert_id!r}: expected an ES-style id matching "
            r"[A-Za-z0-9_-]{8,128}"
        )
    if not case_title.strip():
        raise ValueError("case_title must not be empty")
    if not case_description.strip():
        raise ValueError("case_description must not be empty")

    body: dict[str, Any] = {
        "title": case_title.strip(),
        "description": case_description.strip(),
        "originalEventId": alert_id,
    }
    resp = await auth.request("POST", "/connect/case", json=body)
    if resp.status_code >= httpx.codes.BAD_REQUEST:
        raise SoApiError(
            f"escalate_to_case returned {resp.status_code}: {resp.text[:200]}",
            status_code=resp.status_code,
            url="/connect/case",
        )
    try:
        return dict(resp.json())
    except ValueError as e:
        raise SoApiError(f"escalate_to_case response was not JSON: {e}") from e
