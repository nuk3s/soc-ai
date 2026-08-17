"""Host-dossier endpoints: see what the system believes about a host, and flip it.

The dossier keeps two physically separate lanes per field — what the network sweep
inferred, and what an operator declared — and there is no stored "current value"
column at all. Every response in this module therefore comes out of
:mod:`soc_ai.dossier.resolve`, the one function that decides what a field
effectively says. Reading a raw ``inferred_value`` / ``operator_value`` column
into a response body would be a second answer to that question, and the API and
the investigation prompt would start describing different hosts.

Read is the analyst default (the shared router carries ``require_api_auth``);
the four routes that change something are admin-gated, because relabelling a
host's criticality is how you bury it.

Absence is deliberately not an error. ``GET /dossiers/{ip}`` answers ``found:
false`` for an address the sweep has no row for, so the entity card can say "no
dossier for this host" — the same thing the prompt block says out loud — rather
than rendering an error state that reads as "nothing notable". A path segment
that is not an address at all IS a 404: this resource is keyed on IPs, and a
hostname cannot name a row in it.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any, Literal

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import _iso_utc, require_admin_api, router
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.config import Settings
from soc_ai.dossier.infer import ROLE_VOCABULARY
from soc_ai.dossier.resolve import (
    DEFAULT_MIN_CONFIDENCE,
    DEFAULT_STALENESS_HOURS,
    ResolvedConflict,
    ResolvedDossier,
    ResolvedField,
    resolve_dossier_from_settings,
    resolve_field,
    unknown_dossier,
)
from soc_ai.dossier.types import DOSSIER_FIELDS
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import investigations as inv_svc
from soc_ai.webui import host_activity as activity_query
from soc_ai.webui.deps import current_user

_LOGGER = logging.getLogger(__name__)

# Sort keys the store understands. Spelled as a Literal so a typo is a 422 with
# the legal set in the OpenAPI schema rather than a silent fall back that
# leaves the operator wondering why the column header lied. "attention" — what
# needs the operator, worst first — is the default: sorted by last_seen the
# anonymous tail floats and the one host that matters lands last. "importance"
# — graded critical/high first, then named, then the rest of the grading — is
# what the Hosts SCREEN asks for and lands on; the two answer deliberately
# different questions (see the store's two order builders), and the screen
# names its own landing view.
DossierSort = Literal[
    "importance", "attention", "last_seen", "first_seen", "ip", "stale", "event_count"
]

# Audit kinds, as STRING LITERALS on purpose: the docs-vs-code accuracy gate
# scans for literal emissions, and the AuditKind enum lives in a module this one
# does not own.
_AUDIT_OVERRIDE = "dossier_override"
_AUDIT_CONFLICT = "dossier_conflict_nudge"


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class DossierConflictOut(BaseModel):
    """An OPEN disagreement between the two lanes, with its throttle state."""

    kind: str | None = None  # 'mismatch' | 'retracted' | 'rebound'
    first_seen_at: str | None = None
    observations: int = 0
    last_prompted_at: str | None = None
    # Doubles as the notification cycle id: a client-side dismissal keyed on it
    # sticks for this prod and does not hide the next one.
    prompt_count: int = 0
    snoozed_until: str | None = None


class DossierFieldBriefOut(BaseModel):
    """One resolved field, list-weight: the answer without the paper trail.

    The list can return 200 hosts x 12 fields; shipping each field's evidence
    blob and both lanes' bookkeeping would make the host list heavier than the
    detail card it links to. Everything here still comes from the resolver.
    """

    field: str
    value: str | None = None
    value_json: Any | None = None
    source: str | None = None  # 'operator', a provenance rung, or null
    confidence: float = 0.0
    strength: str = "none"
    # Null when the field resolved; otherwise why it did not
    # ('stale' | 'low_confidence' | 'no_signal').
    reason: str | None = None
    overridden: bool = False
    conflict_kind: str | None = None


class DossierFieldOut(DossierFieldBriefOut):
    """One resolved field with both lanes and the evidence behind them.

    The ``inferred_*`` attributes are the belief underneath the answer. They are
    populated even when an operator override wins, because an override suppresses
    EFFECT and never OBSERVATION — the conflict card argues from exactly this
    pair, and a response that dropped the losing lane could not show it.
    """

    evidence: dict[str, Any] = Field(default_factory=dict)
    observed_at: str | None = None
    first_seen: str | None = None
    # Last build that EVALUATED this field, even if it concluded nothing. Null
    # means never evaluated — "no signal" and "not looked at yet" are different.
    last_run_at: str | None = None
    retracted_at: str | None = None
    operator_actor: str | None = None
    operator_note: str | None = None
    operator_set_at: str | None = None
    inferred_value: str | None = None
    inferred_value_json: Any | None = None
    inferred_confidence: float | None = None
    inferred_source: str | None = None
    conflict: DossierConflictOut | None = None


class DossierRowOut(BaseModel):
    """One host in the host list."""

    ip: str
    found: bool = True
    fields: list[DossierFieldBriefOut] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    last_built_at: str | None = None
    last_observed_at: str | None = None
    event_count: int = 0
    # Set when a DIFFERENT machine appears to hold this address now — an override
    # on this row may describe a host that has moved on.
    identity_rebound_at: str | None = None
    build_error: str | None = None
    override_count: int = 0
    conflict_count: int = 0
    # An agent ON this machine is currently reporting about itself — any field
    # whose inference lane holds a live value at the 'hostlog' rung, per the
    # resolver's gates (ResolvedDossier.reporting). Explicit on the wire because
    # a client cannot derive it: an override masks the winning `source` on the
    # field it takes (a renamed host would read as agentless), and the staleness
    # window is a server knob. Same definition the summary's `reporting` counts.
    reporting: bool = False


class DossierOut(DossierRowOut):
    """One host's full dossier: every field, both lanes, all evidence."""

    fields: list[DossierFieldOut] = Field(default_factory=list)  # type: ignore[assignment]


class DossierListOut(BaseModel):
    rows: list[DossierRowOut]
    # The whole match set, not the page — the pager needs it and the client must
    # not have to guess from a short page.
    total: int
    limit: int
    offset: int


class DossierConflictRowOut(BaseModel):
    """One disagreement that has earned the operator's attention."""

    ip: str
    field: str
    kind: str | None = None
    first_seen_at: str | None = None
    observations: int = 0
    last_prompted_at: str | None = None
    prompt_count: int = 0
    snoozed_until: str | None = None
    # What the operator said vs what the builder keeps seeing — in BOTH lanes.
    # services_offered / activity_profile / management_plane are overridden
    # through value_json with the scalar left null, and those disagreements do
    # reach this list, so a row that carried only the scalars would render blank
    # on exactly the three fields whose conflict is hardest to read.
    operator_value: str | None = None
    operator_value_json: Any | None = None
    inferred_value: str | None = None
    inferred_value_json: Any | None = None
    identity_rebound_at: str | None = None
    href: str = ""


class DossierConflictsOut(BaseModel):
    # The nudge count, in the DetectionTuningSummaryOut.pending shape so the
    # dashboard renders it with the tuning nudge it already has.
    pending: int
    rows: list[DossierConflictRowOut]


class DossierSummaryOut(BaseModel):
    """Network-wide dossier counts — the WHOLE table, never the page on screen.

    The host list is paged in SQL at 50 rows against a 5,000-host cap, so every
    number here is answered by an aggregate. A client that derived any of them
    from the rows it happened to be holding would state a figure about a fiftieth
    of the network as if it were the network's.
    """

    hosts: int = 0
    never_built: int = Field(
        default=0,
        description=(
            "Hosts with no clean build on record: never swept at all, or the last "
            "sweep recorded an error."
        ),
    )
    named: int = Field(
        default=0,
        description=(
            "Hosts whose 'hostname' field the resolver would assert — the operator "
            "lane, or an inferred name that clears both the confidence floor and "
            "the staleness window. A stored name the resolver withholds is not "
            "counted, so this agrees with the hostname column in the list."
        ),
    )
    reporting: int = Field(
        default=0,
        description=(
            "Hosts whose inference lane currently holds a value at the 'hostlog' "
            "rung — an agent on the machine reporting about itself. Counts the "
            "OBSERVATION, so an operator override on the field does not hide it."
        ),
    )
    conflicts: int = Field(
        default=0,
        description="Open disagreements past the observation gate — the /dossiers/conflicts count.",
    )
    roles: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "Hosts per effective role — the operator's declaration where one "
            "exists, otherwise an inferred role the resolver would assert "
            "(confidence floor + staleness window). Hosts with no resolved role "
            "are in no bucket, so the values need not sum to `hosts`; the "
            "difference is the unresolved remainder."
        ),
    )
    last_built_at: str | None = Field(
        default=None,
        description="The newest build stamp in the table; null when nothing has ever been swept.",
    )
    schedule_enabled: bool = Field(
        default=False,
        description=(
            "Whether sweeps run on a schedule. Off by default, in which case these "
            "counts are only as fresh as the last manual Rebuild."
        ),
    )
    role_vocabulary: list[str] = Field(
        default_factory=lambda: list(ROLE_VOCABULARY),
        description=(
            "The classifier's closed role vocabulary (soc_ai.dossier.infer."
            "ROLE_VOCABULARY). Travels with the summary so the host filter and the "
            "declare datalist offer every role the classifier can emit, not only the "
            "ones a host on the current page happens to carry."
        ),
    )


class DossierOverrideIn(BaseModel):
    """An operator's declaration about one field.

    ``value_json`` exists for the three fields a scalar cannot carry
    (``services_offered``, ``activity_profile``, ``management_plane``); without
    it those would be the only fields an operator could never correct.
    """

    field: str = Field(min_length=1, max_length=64)
    value: str | None = Field(default=None, max_length=2000)
    value_json: Any | None = None
    note: str | None = Field(default=None, max_length=2000)


class DossierBulkOverrideIn(BaseModel):
    """One declaration, applied to a selection of hosts.

    Same three payload fields as :class:`DossierOverrideIn` plus the selection,
    because a bulk declare IS the single declare repeated — a second write shape
    would be a second way for the operator lane to be written, and the two-lane
    invariant only holds while there is one.
    """

    # Bounded well above MAX_BULK_HOSTS so an absurd payload is refused before it
    # is buffered, while a merely-too-large selection still gets the friendly 400.
    ips: list[str] = Field(default_factory=list, max_length=5000)
    field: str = Field(min_length=1, max_length=64)
    value: str | None = Field(default=None, max_length=2000)
    value_json: Any | None = None
    note: str | None = Field(default=None, max_length=2000)


class DossierBulkFailureOut(BaseModel):
    """One host the write did not land on, and why."""

    ip: str
    reason: str


class DossierBulkOverrideOut(BaseModel):
    """What the declaration did, host by host.

    A three-way partition, not a count: a selection can outlive a sweep, a
    single host can fail on its own, and "3 of 5" with no names leaves the
    operator re-checking all five by hand.

    ``updated`` took the declaration, ``not_found`` are hosts the sweep has
    never built a row for, ``failed`` hit an error of their own. Every arm names
    its hosts, and the audit line records what actually landed — a batch that
    half-succeeded and then 500'd was the one shape that told nobody anything.
    """

    updated: list[str]
    not_found: list[str]
    failed: list[DossierBulkFailureOut] = Field(default_factory=list)


class DossierRefreshOut(BaseModel):
    running: bool
    last_run: str | None = None
    last_summary: dict[str, Any] | None = None
    note: str | None = None


class DossierSweepHealthOut(BaseModel):
    """The sweep-health projection any authenticated caller may read.

    A CLOSED, four-field set — see :func:`dossier_sweep_health` for what each
    field is allowed to say and why nothing else crosses this boundary.
    ``extra="forbid"`` so a refactor that splats a richer object in here fails
    loudly instead of quietly widening the projection.
    """

    model_config = ConfigDict(extra="forbid")

    running: bool
    degraded: bool
    last_run: str | None = None
    error_count: int = 0


# The activity models are built by splatting the query layer's dataclasses
# (``**asdict(peer)``), which makes them the one place in this module where the
# wire shape and an internal shape have to stay in step. Pydantic's default
# ``extra="ignore"`` would let a field added to the dataclass compile, typecheck
# and pass every test while never reaching the browser — the silent-drop class
# that once cost the agent its prefetched evidence. Fail loudly instead.
_WIRE_STRICT = ConfigDict(extra="forbid")


class HostPeerOut(BaseModel):
    """One address this host exchanged traffic with over the chosen window."""

    model_config = _WIRE_STRICT

    ip: str
    hostname: str | None = None
    direction: Literal["in", "out", "both"] = "out"
    ports: list[int] = Field(default_factory=list)
    events: int = 0
    alerted: bool = False


class VolumePointOut(BaseModel):
    """One bar of the connection-volume chart.

    The series is NOT a fixed-length window: it starts at the host's first
    activity in the range, not at the range's edge, so a quiet host returns
    fewer bars than there are hours or days. Render off ``ts``; never index by
    position or assume a bar count.
    """

    model_config = _WIRE_STRICT

    ts: str
    events: int


class UserSeenOut(BaseModel):
    model_config = _WIRE_STRICT

    name: str
    events: int
    last_seen: str


class LatestInvestigationOut(BaseModel):
    model_config = _WIRE_STRICT

    id: str
    # Null while a run is still in flight — a live investigation is worth linking
    # to before it has concluded anything.
    verdict: str | None = None
    ts: str


class HostActivityOut(BaseModel):
    """What a host is DOING — read off the grid on the request that renders it.

    The dossier half of the host page is swept and cached; this half cannot be.
    A stale peer list would show a machine as quiet while it is beaconing.

    ``users`` is null, not ``[]``, for an address the grid holds no host-log
    authentication documents for; ``[]`` means it holds some that name nobody.
    The two need different copy — one is a coverage gap, the other a finding.

    Null is WINDOW-scoped. It means "no auth documents in the range you asked
    for", which an agent-carrying machine nobody logged into for 24h also
    returns. The page must say "no host auth logs in the last 24h" and must NOT
    say "this machine ships no host logs": the query cannot distinguish those,
    and asserting the stronger one sends someone to install an agent that is
    already running.
    """

    model_config = _WIRE_STRICT

    peers: list[HostPeerOut] = Field(default_factory=list)
    volume: list[VolumePointOut] = Field(default_factory=list)
    users: list[UserSeenOut] | None = None
    alerts_7d: int = 0
    latest_investigation: LatestInvestigationOut | None = None
    # Set by the query layer's fold from the PRE-cut lengths, so the page's
    # "the N busiest…" footnotes state a cut that happened rather than
    # re-inferring one from a copied cap constant (which read exactly-cap lists
    # as truncated and went quietly false whenever the cap moved).
    peers_truncated: bool = Field(
        default=False,
        description="The ranked peer list was cut to the server cap; rows fell off the end.",
    )
    users_truncated: bool = Field(
        default=False,
        description=(
            "The account list was cut to the server cap. Always false when "
            "`users` is null — an absent list is not a cut one."
        ),
    )


# ---------------------------------------------------------------------------
# Serialization — resolver output in, wire shapes out
# ---------------------------------------------------------------------------


def _ts(value: datetime | None) -> str | None:
    """Stored naive-UTC timestamp -> timezone-aware ISO, or null.

    ``_iso_utc`` returns "" for None; the wire wants null, so a client renders
    "never" instead of an empty cell it has to special-case.
    """
    return _iso_utc(value) or None


def _brief_out(resolved: ResolvedField) -> DossierFieldBriefOut:
    return DossierFieldBriefOut(
        field=resolved.field,
        value=resolved.value,
        value_json=resolved.value_json,
        source=resolved.source,
        confidence=resolved.confidence,
        strength=resolved.strength,
        reason=resolved.reason,
        overridden=resolved.overridden,
        conflict_kind=resolved.conflict.kind if resolved.conflict else None,
    )


def _conflict_out(conflict: ResolvedConflict | None) -> DossierConflictOut | None:
    if conflict is None:
        return None
    return DossierConflictOut(
        kind=conflict.kind,
        first_seen_at=_ts(conflict.first_seen_at),
        observations=conflict.observations,
        last_prompted_at=_ts(conflict.last_prompted_at),
        prompt_count=conflict.prompt_count,
        snoozed_until=_ts(conflict.snoozed_until),
    )


def _field_out(resolved: ResolvedField) -> DossierFieldOut:
    return DossierFieldOut(
        **_brief_out(resolved).model_dump(),
        evidence=resolved.evidence,
        observed_at=_ts(resolved.observed_at),
        first_seen=_ts(resolved.first_seen),
        last_run_at=_ts(resolved.last_run_at),
        retracted_at=_ts(resolved.retracted_at),
        operator_actor=resolved.operator_actor,
        operator_note=resolved.operator_note,
        operator_set_at=_ts(resolved.operator_set_at),
        inferred_value=resolved.inferred_value,
        inferred_value_json=resolved.inferred_value_json,
        inferred_confidence=resolved.inferred_confidence,
        inferred_source=resolved.inferred_source,
        conflict=_conflict_out(resolved.conflict),
    )


def _header(resolved: ResolvedDossier) -> dict[str, Any]:
    """The per-host columns both the row and the detail shapes carry."""
    return {
        "ip": resolved.ip,
        "found": resolved.found,
        "first_seen": _ts(resolved.first_seen),
        "last_seen": _ts(resolved.last_seen),
        "last_built_at": _ts(resolved.last_built_at),
        "last_observed_at": _ts(resolved.last_observed_at),
        "event_count": resolved.event_count,
        "identity_rebound_at": _ts(resolved.identity_rebound_at),
        "build_error": resolved.build_error,
        "override_count": sum(1 for f in resolved.fields.values() if f.overridden),
        "conflict_count": sum(1 for f in resolved.fields.values() if f.conflict is not None),
        "reporting": resolved.reporting,
    }


def _row_out(resolved: ResolvedDossier) -> DossierRowOut:
    return DossierRowOut(
        **_header(resolved),
        fields=[_brief_out(f) for f in resolved.fields.values()],
    )


def _dossier_out(resolved: ResolvedDossier) -> DossierOut:
    return DossierOut(
        **_header(resolved),
        fields=[_field_out(f) for f in resolved.fields.values()],
    )


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


def _require_ip(ip: str) -> str:
    """Normalize a path segment to a host key, or 404.

    A hostname or a slug cannot name a row in a table keyed on addresses, so it
    is not-found rather than a 422 — the client asked for a resource that cannot
    exist. Normalizing here (rather than letting the store return None) keeps
    "not an address" distinguishable from "address we have never seen".
    """
    try:
        return dossier_store.normalize_host_key(ip)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_an_ip", "hint": "the dossier is keyed on IP addresses"},
        ) from None


def _require_field(field: str) -> str:
    if field not in DOSSIER_FIELDS:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "unknown_field",
                "hint": f"expected one of: {', '.join(DOSSIER_FIELDS)}",
            },
        )
    return field


async def _audit(
    request: Request,
    *,
    kind: str,
    ip: str,
    field: str,
    action: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Record an operator's change to the dossier. Best-effort, always.

    The kinds are string literals against an enum this module does not own, so an
    unbuilt kind raises inside the logger — and an audit index can be down. Either
    way the operator's declaration has already been committed, and losing it to a
    bookkeeping failure would be strictly worse than losing the audit line.
    """
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is None:
            return
        user = await current_user(request)
        await audit.log_kind(
            session_id=f"dossier:{ip}",
            kind=kind,
            payload={"ip": ip, "field": field, "action": action, **(detail or {})},
            user=user.username if user else "unknown",
        )
    except Exception:
        _LOGGER.warning("dossier %s audit write failed (continuing)", action, exc_info=True)


# ---------------------------------------------------------------------------
# Refresh: single-flight background sweep (the routes_discovery shape)
# ---------------------------------------------------------------------------

_DOSSIER_STATE_ATTR = "_dossier_status"


class _DossierStatus:
    """In-memory status for the manual refresh task on app.state.

    Shared with the scheduler loop, so a manual sweep and a scheduled one can
    never overlap. The DURABLE last-run stamp lives in the ``dossier_run`` table;
    this object is only what the button polls, and a restart legitimately clears
    it without re-sweeping the whole network.
    """

    def __init__(self) -> None:
        self.running: bool = False
        self.last_run: str | None = None
        self.last_summary: dict[str, Any] | None = None
        self._task: asyncio.Task[None] | None = None


def _get_dossier_status(state: Any) -> _DossierStatus:
    if not hasattr(state, _DOSSIER_STATE_ATTR):
        setattr(state, _DOSSIER_STATE_ATTR, _DossierStatus())
    return getattr(state, _DOSSIER_STATE_ATTR)  # type: ignore[no-any-return]


def _refresh_out(status: _DossierStatus, note: str | None = None) -> DossierRefreshOut:
    return DossierRefreshOut(
        running=status.running,
        last_run=status.last_run,
        last_summary=status.last_summary,
        note=note,
    )


async def _run_dossier_task(state: Any) -> None:
    """Background worker: one network sweep, summary stashed, never raises.

    The enrichment import sits INSIDE the guard along with the sweep: a task that
    died — on an import, on a down grid, on anything — while holding the
    single-flight slot would wedge the Rebuild button until the next restart, and
    the slot is only released in ``finally``.
    """
    status = _get_dossier_status(state)
    try:
        from soc_ai.enrichment.host_dossier import run_dossier_refresh  # noqa: PLC0415 - lazy

        summary = await run_dossier_refresh(
            state.elastic, state.db_sessionmaker, state.settings, trigger="manual"
        )
        status.last_summary = asdict(summary)
    except Exception:
        _LOGGER.exception("host dossier: refresh task failed")
        status.last_summary = {"errors": ["refresh failed; see server logs"]}
    finally:
        status.running = False
        status.last_run = datetime.now(UTC).isoformat()


# NOTE: /dossiers/refresh, /dossiers/sweep-health, /dossiers/conflicts and
# /dossiers/summary are declared BEFORE /dossiers/{ip}. FastAPI matches in
# declaration order, and the other way round each would be swallowed as an
# ``ip`` path parameter — and answered with the 404 ``_require_ip`` raises for
# a segment that is not an address.


@router.post(
    "/dossiers/refresh",
    response_model=DossierRefreshOut,
    dependencies=[Depends(require_admin_api)],
)
async def start_dossier_refresh(request: Request) -> DossierRefreshOut:
    """Rebuild the network dossier NOW, in the background (single-flight).

    Poll ``GET /dossiers/refresh`` for status. A second POST while a sweep is in
    flight reports the running one rather than starting a second: a sweep is
    hundreds of hosts times several Elasticsearch round trips, and two of them at
    once is the connection-pool pressure that has frozen this app before.
    Returns a note when the master switch is off (nothing is started).
    """
    state = request.app.state
    status = _get_dossier_status(state)
    if status.running:
        return _refresh_out(status, note="already running")
    if not getattr(state.settings, "dossier_enabled", False):
        return _refresh_out(status, note="dossier disabled")
    status.running = True  # claim the slot BEFORE scheduling, or two POSTs race
    status._task = asyncio.create_task(_run_dossier_task(state))
    return _refresh_out(status, note="started")


@router.get(
    "/dossiers/refresh",
    response_model=DossierRefreshOut,
    dependencies=[Depends(require_admin_api)],
)
async def dossier_refresh_status(request: Request) -> DossierRefreshOut:
    return _refresh_out(_get_dossier_status(request.app.state))


def _summary_error_count(last_summary: dict[str, Any] | None) -> int:
    """How many failure strings the last run recorded, read defensively.

    Mirrors the client's own guard (frontend ``lib/sweepErrors.ts``): the
    summary is a dataclass dumped whole, and a task that died outright writes a
    bare ``{"errors": [...]}``. Anything that is not a list counts as no errors
    — an unrecognised shape is not evidence of trouble — and only string
    entries count, so the two readers of this record cannot disagree about
    whether a run was degraded.
    """
    if not last_summary:
        return 0
    errors = last_summary.get("errors")
    if not isinstance(errors, list):
        return 0
    return sum(1 for e in errors if isinstance(e, str))


@router.get("/dossiers/sweep-health", response_model=DossierSweepHealthOut)
async def dossier_sweep_health(request: Request) -> DossierSweepHealthOut:
    """The sweep's health, projected down to what ANY authenticated caller may learn.

    ACCESS-CONTROL BOUNDARY — read this before adding a field.

    ``GET /dossiers/refresh`` is admin-gated because ``last_summary`` carries
    the sweep's raw failure strings: index names, query text, whatever an
    exception chose to say about the estate. But gating ALL of it left a
    non-admin with no sweep record at all, and the Hosts and host screens'
    empty states fell back to "the sweep hasn't run yet" over a sweep that ran
    and died — a false all-clear, served precisely to the role least able to
    check. A blind sensor reported as calm outranks any loud error.

    So this route answers with a closed projection, each field something those
    screens already imply to any reader:

    * ``running``     — the Rebuild button's disabled state says this anyway.
    * ``degraded``    — the last completed run recorded errors. Keyed to the
      ``errors`` list and NOTHING else: advisory ``notes`` and zero counts are
      what a healthy run on a settled estate reports (see
      :func:`_summary_error_count`).
    * ``last_run``    — when it finished; the summary bar dates the data itself.
    * ``error_count`` — how many ways it failed. The COUNT only, never the
      strings.

    Deliberately excluded, and to stay excluded: the error strings and the
    ``notes`` (the reason the full route is gated), and the run's counters
    (``hosts_built`` / ``fields_written`` stay on the admin read). Do not add a
    field here without deciding, in writing, that a non-privileged caller may
    learn it — and do not loosen the gate on the full status instead; the two
    routes exist so that trade never has to be made.
    """
    status = _get_dossier_status(request.app.state)
    error_count = _summary_error_count(status.last_summary)
    return DossierSweepHealthOut(
        running=status.running,
        degraded=error_count > 0,
        last_run=status.last_run,
        error_count=error_count,
    )


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


@router.get("/dossiers/conflicts", response_model=DossierConflictsOut)
async def list_dossier_conflicts(
    request: Request,
    limit: int = Query(dossier_store.DEFAULT_LIST_LIMIT, ge=1, le=dossier_store.MAX_LIST_LIMIT),
    settings: Settings = Depends(get_settings_dep),
) -> DossierConflictsOut:
    """Open disagreements the builder has kept seeing, oldest first.

    A row stays here after it has prodded: the prompt interval throttles the
    NOTIFICATION, not the disagreement, and a row that vanished the moment it
    fired would be unresolvable from the UI. Snoozed rows are excluded — that is
    what "keep mine" bought. Resolve either way: accept the inference (DELETE the
    override) or keep yours (snooze).
    """
    now = datetime.now(UTC)
    async with request.app.state.db_sessionmaker() as db:
        pairs, total = await dossier_store.conflicts_due(
            db,
            now=now,
            min_observations=int(
                getattr(
                    settings,
                    "dossier_conflict_min_observations",
                    dossier_store.DEFAULT_CONFLICT_MIN_OBSERVATIONS,
                )
            ),
            limit=limit,
        )
        rows = []
        for host, field_row in pairs:
            # The per-field resolver rather than the whole-dossier one: a
            # conflicts page is a flat list of rows, not a set of hosts. Same
            # module either way — a second path to an effective value would be a
            # second answer.
            resolved = resolve_field(
                field_row,
                now=now,
                min_confidence=float(
                    getattr(settings, "dossier_min_confidence", DEFAULT_MIN_CONFIDENCE)
                ),
                staleness_hours=int(
                    getattr(settings, "dossier_staleness_hours", DEFAULT_STALENESS_HOURS)
                ),
            )
            conflict = resolved.conflict or ResolvedConflict()
            rows.append(
                DossierConflictRowOut(
                    ip=host.ip,
                    field=resolved.field,
                    kind=conflict.kind,
                    first_seen_at=_ts(conflict.first_seen_at),
                    observations=conflict.observations,
                    last_prompted_at=_ts(conflict.last_prompted_at),
                    prompt_count=conflict.prompt_count,
                    snoozed_until=_ts(conflict.snoozed_until),
                    operator_value=resolved.value if resolved.overridden else None,
                    operator_value_json=resolved.value_json if resolved.overridden else None,
                    inferred_value=resolved.inferred_value,
                    inferred_value_json=resolved.inferred_value_json,
                    identity_rebound_at=_ts(host.identity_rebound_at),
                    href=f"/entity/{host.ip}",
                )
            )
    return DossierConflictsOut(pending=total, rows=rows)


@router.get("/dossiers/summary", response_model=DossierSummaryOut)
async def dossier_summary(
    request: Request, settings: Settings = Depends(get_settings_dep)
) -> DossierSummaryOut:
    """The network-wide counts above the host list, in three aggregate queries.

    Deliberately an endpoint rather than something the host list computes for
    itself: that list is one SQL page of up to 5,000 hosts, and a headline count
    derived from the fifty rows on screen would describe a fiftieth of the
    network while reading as the whole of it. This app has shipped that exact
    defect twice.

    ``last_built_at`` and ``schedule_enabled`` travel WITH the counts because
    ``dossier_schedule_enabled`` is off until an operator turns it on: without
    them the strip cannot say that its numbers are as old as the last manual
    Rebuild, and stale counts read exactly like fresh ones.
    """
    async with request.app.state.db_sessionmaker() as db:
        summary = await dossier_store.summarize_dossiers(
            db,
            now=datetime.now(UTC),
            min_confidence=float(
                getattr(settings, "dossier_min_confidence", DEFAULT_MIN_CONFIDENCE)
            ),
            staleness_hours=int(
                getattr(settings, "dossier_staleness_hours", DEFAULT_STALENESS_HOURS)
            ),
            min_observations=int(
                getattr(
                    settings,
                    "dossier_conflict_min_observations",
                    dossier_store.DEFAULT_CONFLICT_MIN_OBSERVATIONS,
                )
            ),
        )
    return DossierSummaryOut(
        hosts=summary.hosts,
        never_built=summary.never_built,
        named=summary.named,
        reporting=summary.reporting,
        conflicts=summary.conflicts,
        roles=summary.roles,
        last_built_at=_ts(summary.last_built_at),
        schedule_enabled=bool(getattr(settings, "dossier_schedule_enabled", False)),
        role_vocabulary=list(ROLE_VOCABULARY),
    )


@router.get("/dossiers", response_model=DossierListOut)
async def list_dossiers(
    request: Request,
    q: str | None = Query(None, max_length=253),
    role: str | None = Query(None, max_length=64),
    source: Literal["operator", "inferred"] | None = None,
    health: Literal["broken"] | None = Query(
        None,
        description=(
            "'broken' selects hosts with no clean build on record — never built, "
            "or the last build errored: exactly the set the summary's never_built "
            "counts, so that KPI can click through to the rows behind its number."
        ),
    ),
    limit: int = Query(dossier_store.DEFAULT_LIST_LIMIT, ge=1, le=dossier_store.MAX_LIST_LIMIT),
    offset: int = Query(0, ge=0),
    sort: DossierSort = "attention",
    settings: Settings = Depends(get_settings_dep),
) -> DossierListOut:
    """A page of the network, every field resolved.

    Paged in SQL, unlike the internal-identifier list which ships its whole
    table: that contract is right for ~100 rows and wrong for a 5,000-host cap.
    ``role`` is a coarse prefilter over the stored lanes — the resolver still
    applies the confidence floor and the staleness window, so a host listed under
    a role can resolve to unknown on its detail card, which is the honest answer
    rather than a filter that quietly disagrees with the card it links to.

    The default order is ``attention``: hosts with no clean build first (never
    built or errored — the same set ``health=broken`` filters and the summary's
    ``never_built`` counts, so the KPI's click-through leads its own order),
    then conflicts due, then hosts the operator has declared something about
    (critical first), then named hosts, then the rest by last seen — ranked in
    SQL, before the page is cut. ``sort=importance`` inverts the emphasis —
    graded critical or high, then named, then the rest of the grading, then
    declared-anything — and is what the Hosts screen asks for on arrival,
    because on an estate where almost nothing has been built yet "no clean
    build" is not a tier, it is the whole table. Only the two grades that assert
    the host matters lead the named ones: ranking every grade first would let a
    bulk tagging pass over a subnet of printers as ``low`` bury the named
    servers, which is the same defect this order answers.
    The knobs travel with the call because both ranked orders' "named" tier
    applies the resolver's own gates and the attention order's conflict tier the
    queue's own predicate; wired to different thresholds than the rows
    underneath, an order would promote a host whose row shows a dash.
    """
    now = datetime.now(UTC)
    async with request.app.state.db_sessionmaker() as db:
        page, total = await dossier_store.list_dossiers(
            db,
            q=q,
            role=role,
            source=source,
            health=health,
            limit=limit,
            offset=offset,
            sort=sort,
            now=now,
            min_confidence=float(
                getattr(settings, "dossier_min_confidence", DEFAULT_MIN_CONFIDENCE)
            ),
            staleness_hours=int(
                getattr(settings, "dossier_staleness_hours", DEFAULT_STALENESS_HOURS)
            ),
            min_observations=int(
                getattr(
                    settings,
                    "dossier_conflict_min_observations",
                    dossier_store.DEFAULT_CONFLICT_MIN_OBSERVATIONS,
                )
            ),
        )
        rows = [
            _row_out(resolve_dossier_from_settings(host, fields, now=now, settings=settings))
            for host, fields in page
        ]
    return DossierListOut(rows=rows, total=total, limit=limit, offset=offset)


@router.get("/dossiers/{ip}", response_model=DossierOut)
async def get_dossier(
    request: Request, ip: str, settings: Settings = Depends(get_settings_dep)
) -> DossierOut:
    """One host's dossier: every field resolved, both lanes, all evidence.

    An address the sweep has no row for answers 200 with ``found: false`` and
    twelve ``no_signal`` fields rather than 404 — "we have never looked at this
    host" is a real answer the entity card has to state, and a 404 there would
    render as an error where the honest reading is "unknown".
    """
    key = _require_ip(ip)
    now = datetime.now(UTC)
    async with request.app.state.db_sessionmaker() as db:
        found = await dossier_store.get_dossier(db, key)
        resolved = (
            resolve_dossier_from_settings(found[0], found[1], now=now, settings=settings)
            if found is not None
            else unknown_dossier(key)
        )
    return _dossier_out(resolved)


# ---------------------------------------------------------------------------
# Activity — the live half of the host page
# ---------------------------------------------------------------------------


def _peer_name_lookup(request: Request, settings: Settings) -> activity_query.PeerNameLookup:
    """Batch peer-IP -> hostname, THROUGH the resolver like every other read here.

    A peer row that read ``inferred_value`` straight off the column would be a
    second answer to "what is this host called" — the failure this module's
    docstring exists to prevent — and would ignore an operator's rename of the
    very machine the analyst is looking at.

    Names come back keyed on the caller's own spelling of each address: the
    aggregation hands over whatever text Elasticsearch stored, while the table is
    keyed on the ``ipaddress``-canonical form, and for IPv6 those differ.
    """

    async def _names(ips: list[str]) -> dict[str, str]:
        now = datetime.now(UTC)
        async with request.app.state.db_sessionmaker() as db:
            rows = await dossier_store.get_dossiers(db, ips)
            by_key: dict[str, str] = {}
            for host, fields in rows:
                resolved = resolve_dossier_from_settings(host, fields, now=now, settings=settings)
                hostname = resolved.fields.get("hostname")
                if hostname is not None and hostname.value:
                    by_key[host.host_key] = hostname.value
        named: dict[str, str] = {}
        for ip in ips:
            try:
                key = dossier_store.normalize_host_key(ip)
            except ValueError:
                continue
            if key in by_key:
                named[ip] = by_key[key]
        return named

    return _names


def _investigation_lookup(request: Request) -> activity_query.InvestigationLookup:
    """The newest investigation touching this address, whatever its status.

    ``for_entity`` is the store's existing per-IP lookup (the entity card's), and
    it orders newest-first across both endpoints — so a limit of one is the
    latest run rather than a scan the route has to sort itself.

    KNOWN GAP, pre-existing in ``for_entity``: it matches ``src_ip``/``dest_ip``
    only, while the activity endpoint's alert count also counts host-shaped
    detections (Sigma process/file rules carry an agent address and no flow at
    all). A machine whose only detections are host-shaped therefore shows a
    non-zero ``alerts_7d`` beside a null ``latest_investigation`` — the count is
    right and the link is missing, not the other way round. Closing it means
    teaching the investigations store about the host lane, which is a change to
    a shared query the alerts console also reads.
    """

    async def _latest(ip: str) -> activity_query.LatestInvestigation | None:
        async with request.app.state.db_sessionmaker() as db:
            rows = await inv_svc.for_entity(db, ip, limit=1)
        if not rows:
            return None
        newest = rows[0]
        return activity_query.LatestInvestigation(
            id=newest.id, verdict=newest.verdict, ts=_iso_utc(newest.created_at)
        )

    return _latest


# Route order: unlike /dossiers/refresh and /dossiers/conflicts above, this one
# is NOT at risk of being swallowed by /dossiers/{ip} — a path parameter matches
# a single segment, so "/dossiers/x/activity" cannot resolve against a
# one-segment template whatever the declaration order. Nothing else declares a
# two-segment GET under /dossiers either. Proven, not assumed, by
# test_activity_does_not_shadow_the_literal_dossier_routes.
@router.get("/dossiers/{ip}/activity", response_model=HostActivityOut)
async def get_dossier_activity(
    request: Request,
    ip: str,
    range_: Literal["24h", "7d"] = Query("24h", alias="range"),
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> HostActivityOut:
    """One host's live activity: peers, connection volume, users, alert count.

    Deliberately UNCACHED and deliberately separate from ``GET /dossiers/{ip}``.
    The dossier answers who a host is from the sweep and keeps answering while
    the grid is down; this answers what it is doing right now and cannot, so the
    page fetches the two independently and degrades only the half that failed.

    ``range`` is a closed set rather than the alerts console's time picker: the
    volume chart's bucket width is derived from it (hourly for 24h, daily for
    7d), so an unsupported window is a 422 and not a silently re-bucketed chart.
    """
    key = _require_ip(ip)
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            activity = await activity_query.fetch_host_activity(
                elastic,
                settings,
                key,
                range=range_,
                dossier_lookup=_peer_name_lookup(request, settings),
                investigation_lookup=_investigation_lookup(request),
            )
    except OqlValidationError as exc:
        # The alert count is scoped by the same ``build_filter`` the alerts
        # console uses, so a misconfigured ``webui_alerts_query`` reaches both
        # surfaces. Answer it the way the console does, or one setting typed
        # wrong once produces a named 400 there and a bare 500 here.
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc
    except (TimeoutError, TransportError) as exc:
        # The console's standard degraded signal. An empty panel here would read
        # as "this host did nothing", which is the opposite of what is known.
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        # A saturated grid answers rather than dropping the connection: a full
        # search queue, an aggregation tripping the circuit breaker, a mapping
        # conflict on a mixed index. ``ApiError`` is NOT an ``elastic_transport``
        # ``TransportError`` — separate hierarchies — so the arm above misses
        # every one of them and this panel 500'd where its own contract promises
        # a clean degraded signal. Same split the alerts list makes: an ES 4xx is
        # a bad query (400), anything else is the grid (503).
        raise _es_api_error_http(exc) from exc
    return HostActivityOut(
        peers=[HostPeerOut(**asdict(peer)) for peer in activity.peers],
        volume=[VolumePointOut(**asdict(point)) for point in activity.volume],
        users=(
            None
            if activity.users is None
            else [UserSeenOut(**asdict(user)) for user in activity.users]
        ),
        alerts_7d=activity.alerts_7d,
        latest_investigation=(
            LatestInvestigationOut(**asdict(activity.latest_investigation))
            if activity.latest_investigation is not None
            else None
        ),
        peers_truncated=activity.peers_truncated,
        users_truncated=activity.users_truncated,
    )


# ---------------------------------------------------------------------------
# Operator lane — admin only
# ---------------------------------------------------------------------------


async def _current_dossier(request: Request, key: str, settings: Settings) -> DossierOut:
    """Re-read one host through the resolver, for a mutation's response body.

    The card the operator is looking at re-renders from this, so a mutation
    answers with the whole resolved host rather than the single row it touched —
    setting ``role`` can clear a conflict, and a partial response would leave the
    UI showing a disagreement that no longer exists.
    """
    now = datetime.now(UTC)
    async with request.app.state.db_sessionmaker() as db:
        found = await dossier_store.get_dossier(db, key)
        resolved = (
            resolve_dossier_from_settings(found[0], found[1], now=now, settings=settings)
            if found is not None
            else unknown_dossier(key)
        )
    return _dossier_out(resolved)


@router.post(
    "/dossiers/{ip}/override",
    response_model=DossierOut,
    dependencies=[Depends(require_admin_api)],
)
async def set_dossier_override(
    request: Request,
    ip: str,
    body: DossierOverrideIn,
    settings: Settings = Depends(get_settings_dep),
) -> DossierOut:
    """Declare a field's value. The operator lane wins from here on.

    The override is not a hint the next build can outvote: it lands in a separate
    column family and the resolver reads it first, so no inference run can clobber
    it. The builder keeps observing regardless — persistent disagreement is what
    eventually earns one rate-limited prod, and it can only accumulate because the
    inference lane is still being written underneath.

    An override with neither a value nor a structured value is refused: it would
    resolve to nothing while looking like a decision. To hand a field back to the
    builder, DELETE the override.

    A BLANK value counts as no value. Whitespace is not a declaration, and stored
    as one it would still win in the resolver — pinning the field to empty and
    suppressing the inference underneath it until someone thinks to DELETE an
    override they never meant to make. Whitespace around a real value is a paste
    artefact and is trimmed off, so " hypervisor " and "hypervisor" are one claim
    rather than two the disagreement check has to fold together.
    """
    key = _require_ip(ip)
    field = _require_field(body.field)
    value = body.value.strip() if body.value is not None else None
    if not value:
        value = None
    if value is None and body.value_json is None:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "empty_override",
                "hint": "an override needs a value; DELETE it to accept the inference",
            },
        )
    actor = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        row = await dossier_store.set_override(
            db, key, field, value, value_json=body.value_json, actor=actor, note=body.note
        )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found", "hint": "no dossier for that host yet"},
        )
    await _audit(
        request,
        kind=_AUDIT_OVERRIDE,
        ip=key,
        field=field,
        action="set",
        detail={"value": value, "note": body.note, "actor": actor},
    )
    return await _current_dossier(request, key, settings)


# A selection is bounded by what an operator can meaningfully review before
# clicking. It is also the ceiling on one request's write loop.
MAX_BULK_HOSTS = 500

# The two fields a bulk declare constrains to a closed vocabulary — one word
# each, both read by something other than the eye (the ROLES distribution and
# facet; the importance order). Named once so the vocabulary checks and the
# "not JSON-shaped" refusal below cannot come to cover different fields.
_SCALAR_VOCABULARY_FIELDS: tuple[str, ...] = ("role", dossier_store.CRITICALITY_FIELD)


@router.post(
    "/dossiers/bulk-override",
    response_model=DossierBulkOverrideOut,
    dependencies=[Depends(require_admin_api)],
)
async def bulk_set_dossier_override(
    request: Request, body: DossierBulkOverrideIn
) -> DossierBulkOverrideOut:
    """Declare one field across a selection of hosts.

    Tagging a subnet of unnamed printers, or grading a rack of servers, was a
    one-host-at-a-time chore — the Hosts list was the only list screen with no
    checkboxes at all (dogfood A4).

    This reuses :func:`~soc_ai.store.host_dossier.set_override`, host by host.
    That is the point and not an implementation detail: the operator lane has
    exactly one writer, so a bulk declare cannot drift from a single one, cannot
    skip the conflict-clock reset, and cannot invent a second precedence rule.
    The loop is a loop; a set-based UPDATE would be the second writer.

    Validation is all-or-nothing and happens BEFORE any write: a batch that is
    half-refused would leave the operator guessing which half. Hosts the sweep
    has never seen are the one per-host outcome, and they come back named.

    ``role`` and ``criticality`` are the two fields this path constrains harder
    than the single-host declare does — see the vocabulary checks below for why.

    Nothing here changes the list's order. ``criticality`` feeds the importance
    sort, where only ``critical`` and ``high`` rank above a named host — so
    tagging two hundred anonymous printers ``low`` cannot bury the domain
    controller under them, which is the failure this action would otherwise be
    the fastest way to cause.
    """
    field = _require_field(body.field)
    value = body.value.strip() if body.value is not None else None
    if not value:
        value = None
    if value is None and body.value_json is None:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "empty_override",
                "hint": "an override needs a value; DELETE it per host to accept the inference",
            },
        )
    if field in _SCALAR_VOCABULARY_FIELDS and body.value_json is not None:
        # The vocabulary gates below read the SCALAR, so the same crafted request
        # they refuse walked straight past them with the word in `value_json`
        # instead — and landed worse than the hole they close. The resolver takes
        # the operator lane whichever half holds the value, so the page renders
        # `super-important`; the importance sort and the Hosts flags cell both
        # read the scalar, so the order ranks the host as ungraded and the table
        # shows no grade at all. Declared, unreadable, and invisible on the one
        # screen the declaration was made from.
        #
        # Refused rather than vocabulary-checked, because a role and a grade are
        # single words: even `value_json: "critical"` is a valid grade written to
        # the column that nothing ranks on. `value_json` exists for the three
        # fields a scalar cannot carry, and these two are not among them.
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "not_a_json_field",
                "hint": (
                    f"{field} is a single word — send it as `value`; `value_json` is for "
                    "services_offered, activity_profile and management_plane"
                ),
            },
        )
    if field == "role" and value is not None and value not in ROLE_VOCABULARY:
        # BULK role is closed vocabulary; the SINGLE-host declare is deliberately
        # not. That asymmetry is the whole point. One operator who knows a
        # machine is a `jump_host` is telling the truth about one host they
        # looked at, and the distribution bar reads it as the one row it is —
        # refusing that would make the product argue with someone who knows
        # more than it does. Here the same keystroke lands on every selected
        # host, and a role is not a per-host label: it is a bucket in the ROLES
        # distribution and an entry in the role facet, for every user of the
        # deployment. `srever-typo-role` on three hosts is a new first-class
        # role everyone now has to read past. Checked server-side because the
        # API is not entitled to assume the caller is our own <select>.
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "unknown_role",
                "hint": (
                    "a bulk role declaration must be one of: "
                    f"{', '.join(ROLE_VOCABULARY)} — declare a novel role one host at a time"
                ),
            },
        )
    if (
        field == dossier_store.CRITICALITY_FIELD
        and value is not None
        and value.lower() not in dossier_store.CRITICALITY_VOCABULARY
    ):
        # Same hole as `role`, one field over: the screen offers a four-option
        # <select> and the API accepted anything the caller typed. Criticality is
        # worse than a mislabel, because it is not a label at all — it is the top
        # key of the landing order (host_dossier._CRITICALITY_RANK). A grade
        # outside the four ranks as UNRANKED, i.e. exactly as "not stated": a
        # bulk declare of `super-important` therefore takes N hosts OUT of the
        # grading the operator selected them to be given, while still rendering
        # the word on every row. Silent, and the wrong way round.
        #
        # Folded lower() because the rank map compares lower(trim())-folded, so
        # "Critical" is already one claim with "critical" there; a gate stricter
        # than the order it guards would refuse a grade that sorts perfectly
        # well. The value is stored as typed — this validates, it does not
        # normalise, and rewriting the operator's capitalisation is a different
        # decision than the one this check is making.
        #
        # Single-host stays free text, for the reason spelled out above `role`.
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "unknown_criticality",
                "hint": (
                    "a bulk criticality declaration must be one of: "
                    f"{', '.join(dossier_store.CRITICALITY_VOCABULARY)} — these are the "
                    "grades the importance order ranks on"
                ),
            },
        )
    keys: list[str] = []
    for raw in body.ips:
        try:
            key = dossier_store.normalize_host_key(raw)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "not_an_ip",
                    "hint": f"the dossier is keyed on IP addresses; got {raw!r}",
                },
            ) from None
        if key not in keys:
            keys.append(key)
    if not keys:
        raise HTTPException(
            status_code=400,
            detail={"reason": "no_hosts", "hint": "select at least one host"},
        )
    if len(keys) > MAX_BULK_HOSTS:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "too_many_hosts",
                "hint": f"declare at most {MAX_BULK_HOSTS} hosts at a time",
            },
        )

    actor = await identify_caller(request)
    updated: list[str] = []
    not_found: list[str] = []
    failed: list[DossierBulkFailureOut] = []
    async with request.app.state.db_sessionmaker() as db:
        for key in keys:
            # Per host, because each set_override COMMITS. Letting an exception
            # escape the loop left the hosts before it declared, with the audit
            # line (which sits after the loop) never written and a 500 telling
            # the operator nothing landed — a partial write that denies being
            # one. Partial writes are fine here: one writer, and each host is
            # independently meaningful. Partial writes with no record are not.
            try:
                row = await dossier_store.set_override(
                    db, key, field, value, value_json=body.value_json, actor=actor, note=body.note
                )
            except Exception as exc:  # one bad host must not sink the batch
                _LOGGER.warning("bulk dossier override failed for %s", key, exc_info=True)
                await db.rollback()
                failed.append(DossierBulkFailureOut(ip=key, reason=type(exc).__name__))
                continue
            (updated if row is not None else not_found).append(key)

    # One audit line for one operator action, ALWAYS emitted and always naming
    # what actually landed — including after a partial batch, which is exactly
    # when a record matters most. Five hundred lines saying the same thing at
    # the same second is not a better record of it.
    await _audit(
        request,
        # The same KIND as a single declare — it is the same act on the same
        # lane, and a reader filtering for "who changed this field" must not
        # have to know there are two spellings. `action` carries the difference.
        kind=_AUDIT_OVERRIDE,
        ip=f"{len(updated)} hosts",
        field=field,
        action="bulk_set",
        detail={
            "value": value,
            "note": body.note,
            "actor": actor,
            "ips": updated,
            "not_found": not_found,
            "failed": [f.ip for f in failed],
        },
    )
    return DossierBulkOverrideOut(updated=updated, not_found=not_found, failed=failed)


@router.delete(
    "/dossiers/{ip}/override/{field}",
    response_model=DossierOut,
    dependencies=[Depends(require_admin_api)],
)
async def clear_dossier_override(
    request: Request, ip: str, field: str, settings: Settings = Depends(get_settings_dep)
) -> DossierOut:
    """Accept the inference: drop the operator value and close the disagreement.

    404 for a host or field row that does not exist; 409 for a field carrying no
    override, because deleting an inferred value is not a thing that can happen —
    the next build writes it straight back. Same disambiguation the identifier
    delete/dismiss pair uses.
    """
    key = _require_ip(ip)
    field = _require_field(field)
    async with request.app.state.db_sessionmaker() as db:
        existing = await dossier_store.get_field(db, key, field)
        if existing is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": "not_found", "hint": "no dossier field for that host"},
            )
        if existing.operator_value is None and existing.operator_value_json is None:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "no_operator_override",
                    "hint": (
                        f"no operator override on '{field}' — inferred values cannot be "
                        "deleted, they are recomputed on every build"
                    ),
                },
            )
        await dossier_store.clear_override(db, key, field)
    await _audit(request, kind=_AUDIT_OVERRIDE, ip=key, field=field, action="clear")
    return await _current_dossier(request, key, settings)


@router.post(
    "/dossiers/{ip}/conflicts/{field}/snooze",
    response_model=DossierOut,
    dependencies=[Depends(require_admin_api)],
)
async def snooze_dossier_conflict(
    request: Request, ip: str, field: str, settings: Settings = Depends(get_settings_dep)
) -> DossierOut:
    """ "Keep mine": postpone this disagreement, with a doubling backoff.

    Nothing is resolved — the override stands, the builder keeps observing, and
    the conflict re-surfaces later unless the evidence comes back into agreement
    (which clears the snooze along with the rest of the conflict state). The
    interval doubles per prod already fired and caps at 90 days, so the nag decays
    instead of repeating.

    409 when the row has no OPEN conflict: snoozing a disagreement that does not
    exist would silently do nothing, and the caller believes it just answered a
    question.
    """
    key = _require_ip(ip)
    field = _require_field(field)
    async with request.app.state.db_sessionmaker() as db:
        existing = await dossier_store.get_field(db, key, field)
        if existing is None:
            raise HTTPException(
                status_code=404,
                detail={"reason": "not_found", "hint": "no dossier field for that host"},
            )
        if existing.conflict_first_seen_at is None:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "no_open_conflict",
                    "hint": f"nothing currently disagrees with the '{field}' override",
                },
            )
        row = await dossier_store.snooze_conflict(
            db,
            key,
            field,
            interval_hours=int(
                getattr(
                    settings,
                    "dossier_conflict_prompt_interval_hours",
                    dossier_store.DEFAULT_CONFLICT_PROMPT_INTERVAL_HOURS,
                )
            ),
        )
        # Read the new deadline while the row is still attached to its session.
        snoozed_until = _ts(row.conflict_snoozed_until) if row is not None else None
    await _audit(
        request,
        kind=_AUDIT_CONFLICT,
        ip=key,
        field=field,
        action="snooze",
        detail={"resolution": "keep_mine", "snoozed_until": snoozed_until},
    )
    return await _current_dossier(request, key, settings)
