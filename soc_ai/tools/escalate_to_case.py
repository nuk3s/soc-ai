"""``escalate_to_case`` write tool - create a SOC case from an alert.

Security Onion 3.x has no one-shot "escalate this alert" route. Escalation is
three writes, and this tool makes the same three the SO web UI makes:

    POST /api/case/         {"title": ..., "description": ...}      -> the case
    POST /api/case/events   {"caseId": ..., "fields": {"soc_id": ...}, ...}
    POST /api/events/ack    {"eventFilter": {"soc_id": ...}, "escalate": true, ...}

The second call is query-shaped rather than id-shaped: SO rebuilds a search from
``fields`` and attaches every match, answering 202 with ``{"count": n}`` once the
work is queued.

The third stamps ``event.escalated`` on the alert itself. soc-ai used to skip
it, and the consequence was that an alert soc-ai had put on a case still read as
untouched in Security Onion's own alert list, so an analyst working that list
escalated it a second time. It also acknowledges the alert, and that is not a
choice this tool gets to make: measured on a live SO 3.2.0 grid on 2026-09-06,
``escalate:true, acknowledge:false`` left ``event.escalated`` unset, so Security
Onion applies the ``acknowledge`` value to both flags and there is no request
shape that stamps one alone. The console behaves the same way, and taking an
alert that is now case work out of the triage queue is the right outcome.

v1 posted to ``/connect/case``. ``/connect/*`` is not a Go route at all - it is
an nginx alias for ``/api/*`` that Security Onion only renders when the grid
carries the licensed ``api`` feature, so on an unlicensed grid every case write
soc-ai made hit nginx's own 404 and the case was never created. Measured against
a live SO 3.2.0 grid on 2026-09-06: ``POST /connect/case`` -> 404 with nginx's
plain-text body, ``POST /api/case/`` -> 200 with the new case document.

``open_finding_case`` is the same three writes for a hunt finding. A finding is
no alert: its documents are Zeek and host records, and sometimes an alert. The
create call takes a title and a description and no event, so the case can
exist with no alert on it. Each alert the finding cites is then attached and
marked the way ``escalate_to_case`` does it, through the same two request
builders, so the two tools cannot send different shapes.

Approval-gated.
"""

from __future__ import annotations

import contextlib
import re
from typing import Any

import httpx

from soc_ai.config import Settings
from soc_ai.errors import SoApiError
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.tools._registry import tool
from soc_ai.tools._so_api import DATE_RANGE_FORMAT, DEFAULT_TIMEZONE, wide_date_range

# ES-style document ids are URL-safe alphanumeric tokens. The alert_id is
# carried in the JSON body as the ``soc_id`` attach field; reject malformed ids
# before any HTTP call. Mirror add_case_comment's _CASE_ID_RE guard style.
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

_CREATE_URL = "/api/case/"
_ATTACH_URL = "/api/case/events"
_MARK_URL = "/api/events/ack"

# Same scope filter and the same reasoning as ``ack_alert``: Security Onion ANDs
# this with the ``soc_id`` pin, and anything narrower silently excludes Elastic
# Defend endpoint alerts, which carry no ``tags:alert``.
_MARK_SCOPE_FILTER = "*"


# Security Onion's own limits on a case, read in source: securityonion-soc
# server/modules/elastic/elasticcasestore.go (branches 2.4/main and 3/main)
# validates ``Title`` with ``validateStringRequired(1, SHORT_STRING_MAX)`` and
# ``Description`` with ``validateStringRequired(1, LONG_STRING_MAX)``, where
# SHORT_STRING_MAX is 100 and LONG_STRING_MAX is 1000000. The check is Go's
# ``len(str)``, which counts BYTES. A longer title is a 400 "title is too long
# (117/100)" on every press, so the action can never run.
CASE_TITLE_MAX_BYTES = 100
CASE_DESCRIPTION_MAX_BYTES = 1_000_000


def _fit_bytes(text: str, limit: int) -> str:
    """``text`` stripped and cut to ``limit`` UTF-8 bytes, on a character boundary."""
    text = text.strip()
    raw = text.encode("utf-8")
    if len(raw) <= limit:
        return text
    # A cut inside a multi-byte character leaves a partial sequence at the
    # end, and "ignore" drops exactly that sequence.
    return raw[:limit].decode("utf-8", errors="ignore").rstrip()


def fit_case_title(text: str) -> str:
    """A case title that Security Onion accepts: at most 100 bytes."""
    return _fit_bytes(text, CASE_TITLE_MAX_BYTES)


def fit_case_description(text: str) -> str:
    """A case description that Security Onion accepts: at most 1000000 bytes."""
    return _fit_bytes(text, CASE_DESCRIPTION_MAX_BYTES)


def _case_body(case_title: str, case_description: str) -> dict[str, str]:
    """The create request of both tools. Every path that opens a case sends this."""
    return {
        "title": fit_case_title(case_title),
        "description": fit_case_description(case_description),
    }


# The error text of a create that Security Onion answered with a client error.
_REFUSED_CREATE_RE = re.compile(r"^open_(?:finding|campaign)_case returned 4\d\d:")


def refused_before_a_case(error: str) -> bool:
    """Whether the error of a finding case or a campaign case proves that no case exists.

    True for a create that Security Onion answered with a 4xx, and for an
    argument this module refused before any request. A 5xx or a transport
    fault can follow a create that took effect, so those prove nothing.
    """
    return bool(_REFUSED_CREATE_RE.match(error)) or error.startswith(
        ("tool invocation failed: invalid alert id", "tool invocation failed: case_")
    )


def _timezone(settings: Settings | None) -> str:
    return settings.so_timezone if settings is not None else DEFAULT_TIMEZONE


async def _post_attach(
    auth: SoAuthClient, case_id: str, alert_id: str, timezone: str
) -> httpx.Response:
    """Ask Security Onion to put the event ``alert_id`` on ``case_id``."""
    return await auth.request(
        "POST",
        _ATTACH_URL,
        json={
            "caseId": case_id,
            "fields": {"soc_id": alert_id},
            "dateRange": wide_date_range(),
            "dateRangeFormat": DATE_RANGE_FORMAT,
            "timezone": timezone,
        },
    )


async def _post_mark(auth: SoAuthClient, alert_id: str, timezone: str) -> httpx.Response:
    """Ask Security Onion to stamp ``alert_id`` escalated (and acknowledged)."""
    return await auth.request(
        "POST",
        _MARK_URL,
        json={
            "searchFilter": _MARK_SCOPE_FILTER,
            "eventFilter": {"soc_id": alert_id},
            "dateRange": wide_date_range(),
            "dateRangeFormat": DATE_RANGE_FORMAT,
            "timezone": timezone,
            "escalate": True,
            # Not separable from the escalate: see the module docstring.
            "acknowledge": True,
        },
    )


def _attached_count(attach: httpx.Response) -> int | None:
    """How many events an attach put on the case, or None when it did not say.

    The attach is a query Security Onion rebuilds from ``fields``, so a 2xx
    only says the query ran. ``count`` is the only thing that says a document
    was put on the case. An unparseable body, or one with no count in it, is
    an attach nobody observed.
    """
    attached: int | None = None
    with contextlib.suppress(ValueError, TypeError):
        count = dict(attach.json()).get("count")
        attached = None if count is None else int(count)
    return attached


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
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Create a case, link ``alert_id`` to it, then mark the alert escalated.

    Returns ``case_id``, whether the case was created, whether the alert is
    attached to it, how many events SO reported attaching, and whether the alert
    now carries Security Onion's escalated flag.

    ``alert_linked`` is the count Security Onion reported, not its status code.
    The attach is query-shaped, so an alert that is no longer on the grid (rolled
    over, deleted, or never there) gets a 200 with ``{"count": 0}``: the case is
    created and empty and the alert is on no case. A 2xx whose body carries no
    ``count`` is an attach nobody observed, which is the same unproven claim, so
    both are reported as not linked with the case id named in ``link_error``.

    Only the CREATE can raise :class:`SoApiError`. Once SO answers 2xx the case
    exists, so a failed link is reported in ``link_error`` with
    ``alert_linked: False`` rather than raised: raising would make the caller
    retry and open a DUPLICATE case. A 2xx with an empty or non-JSON create body
    is the same situation with no id to link against, so the link is reported as
    not done rather than attempted against a guessed id. The mark is reported
    the same way in ``mark_error``, and it is only attempted once the alert is
    actually attached: the flag claims the alert is on a case, and stamping it
    over a failed attach would hide a live alert behind a link that is not there.
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

    resp = await auth.request(
        "POST",
        _CREATE_URL,
        json=_case_body(case_title, case_description),
    )
    if resp.status_code >= httpx.codes.BAD_REQUEST:
        raise SoApiError(
            f"escalate_to_case returned {resp.status_code}: {resp.text[:200]}",
            status_code=resp.status_code,
            url=_CREATE_URL,
        )

    case: dict[str, Any] | None
    try:
        case = dict(resp.json())
    except ValueError:
        case = None

    case_id = str(case.get("id") or "") if case else ""
    result: dict[str, Any] = {
        "alert_id": alert_id,
        "case_id": case_id or None,
        "case_created": True,
        "alert_linked": False,
        "events_attached": 0,
        "marked_escalated": False,
        "case": case,
    }
    if not case_id:
        result["link_error"] = (
            "Security Onion accepted the case but returned no case id, so the "
            "alert could not be attached to it"
        )
        return result

    timezone = _timezone(settings)
    attach = await _post_attach(auth, case_id, alert_id, timezone)
    if attach.status_code >= httpx.codes.BAD_REQUEST:
        result["link_error"] = (
            f"case {case_id} was created but attaching the alert returned "
            f"{attach.status_code}: {attach.text[:200]}"
        )
        return result

    # An attach nobody observed is treated the same as an observed zero:
    # unproven, never a link.
    attached = _attached_count(attach)
    result["events_attached"] = attached or 0
    if not attached:
        result["link_error"] = (
            f"case {case_id} was created but Security Onion attached no event for "
            f"alert {alert_id}"
            + (
                ": the alert is not on the grid, and the case is empty"
                if attached == 0
                else " and reported no attachment count, so the alert is not "
                "confirmed to be on the case"
            )
        )
        return result
    result["alert_linked"] = True

    mark = await _post_mark(auth, alert_id, timezone)
    if mark.status_code >= httpx.codes.BAD_REQUEST:
        result["mark_error"] = (
            f"case {case_id} holds the alert but marking it escalated in "
            f"Security Onion returned {mark.status_code}: {mark.text[:200]}"
        )
        return result
    result["marked_escalated"] = True
    return result


@tool(
    read_only=False,
    description="Create a SOC case from a hunt finding and attach the alerts it cites.",
)
async def open_finding_case(
    case_title: str,
    case_description: str,
    alert_ids: list[str] | None = None,
    *,
    auth: SoAuthClient,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Create a case for a hunt finding, then attach and mark each alert in ``alert_ids``.

    No report may recommend this tool, and no model supplies its arguments.
    The execute route builds the title, the description and the alert list
    from the stored finding (:mod:`soc_ai.api.webui.routes_actions`).

    Returns ``case_id``, ``alerts_attached`` (the ids now on the case, each
    also marked escalated unless it is in ``alerts_unmarked``) and
    ``alerts_unattached`` (id to the reason). A case with nothing attached is
    a complete answer here, unlike ``escalate_to_case``: the finding is the
    subject of the case, and it may cite no alert at all.

    Only the CREATE can raise. Once Security Onion answers 2xx the case
    exists, so every later failure is reported in the result: raising would
    make the caller retry and open a DUPLICATE case. That holds for a
    transport fault on an attach too, which is caught and named.
    """
    return await _open_case(
        "open_finding_case", case_title, case_description, alert_ids, auth=auth, settings=settings
    )


@tool(
    read_only=False,
    description="Create a SOC case from a campaign and attach the alerts of its investigations.",
)
async def open_campaign_case(
    case_title: str,
    case_description: str,
    alert_ids: list[str] | None = None,
    *,
    auth: SoAuthClient,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Create one case for a campaign, then attach and mark each alert in ``alert_ids``.

    The same writes as :func:`open_finding_case`. No report may recommend
    this tool, and no model supplies its arguments: the campaign route builds
    the title, the description and the alert list from the stored campaign
    (:mod:`soc_ai.api.webui.routes_campaign_case`).
    """
    return await _open_case(
        "open_campaign_case", case_title, case_description, alert_ids, auth=auth, settings=settings
    )


async def _open_case(
    tool_name: str,
    case_title: str,
    case_description: str,
    alert_ids: list[str] | None,
    *,
    auth: SoAuthClient,
    settings: Settings | None,
) -> dict[str, Any]:
    """The create, then the attach and the mark of each alert. Only the create can raise."""
    ids = list(dict.fromkeys(alert_ids or []))
    for alert_id in ids:
        if not isinstance(alert_id, str) or not _EVENT_ID_RE.match(alert_id):
            raise ValueError(
                f"invalid alert id {alert_id!r}: expected an ES-style id matching "
                r"[A-Za-z0-9_-]{8,128}"
            )
    if not case_title.strip():
        raise ValueError("case_title must not be empty")
    if not case_description.strip():
        raise ValueError("case_description must not be empty")

    resp = await auth.request(
        "POST",
        _CREATE_URL,
        json=_case_body(case_title, case_description),
    )
    if resp.status_code >= httpx.codes.BAD_REQUEST:
        raise SoApiError(
            f"{tool_name} returned {resp.status_code}: {resp.text[:200]}",
            status_code=resp.status_code,
            url=_CREATE_URL,
        )

    case: dict[str, Any] | None
    try:
        case = dict(resp.json())
    except ValueError:
        case = None

    case_id = str(case.get("id") or "") if case else ""
    attached: list[str] = []
    unattached: dict[str, str] = {}
    unmarked: list[str] = []
    result: dict[str, Any] = {
        "case_id": case_id or None,
        "case_created": True,
        "alerts_attached": attached,
        "alerts_unattached": unattached,
        "alerts_unmarked": unmarked,
        "case": case,
    }
    if not case_id:
        result["link_error"] = (
            "Security Onion accepted the case but returned no case id, so no "
            "alert could be attached to it"
        )
        return result

    timezone = _timezone(settings)
    for alert_id in ids:
        try:
            attach = await _post_attach(auth, case_id, alert_id, timezone)
        except Exception as exc:
            unattached[alert_id] = f"the attach did not complete ({type(exc).__name__})"
            continue
        if attach.status_code >= httpx.codes.BAD_REQUEST:
            unattached[alert_id] = f"the attach returned {attach.status_code}"
            continue
        count = _attached_count(attach)
        if not count:
            unattached[alert_id] = (
                "the alert is not on the grid"
                if count == 0
                else "Security Onion reported no attachment count"
            )
            continue
        attached.append(alert_id)
        # The flag claims the alert is on a case, so it follows a proven attach.
        try:
            mark = await _post_mark(auth, alert_id, timezone)
        except Exception:
            unmarked.append(alert_id)
            continue
        if mark.status_code >= httpx.codes.BAD_REQUEST:
            unmarked.append(alert_id)
    return result
