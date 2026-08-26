"""Draft-detection routes (1.3 slice 3, Task 5): export-only, flag-gated.

Two POST routes let an analyst draft a Sigma detection rule (plus its OQL
would-have-fired dry run) from a confirmed hunt finding — one keyed off a
hunt id + finding ordinal directly, one off a promoted hunt-kind
investigation. Both are READ + draft only: no persistence, no Security Onion
write, no new ``WRITE_TOOL``. The drafted, validated
:class:`~soc_ai.detection.models.SigmaDraft` is returned inline for the
review pane; export (copy/download) happens client-side.

Gated behind ``settings.sigma_authoring_enabled`` (default off — see
:attr:`soc_ai.config.Settings.sigma_authoring_enabled`); the gated-off shape
mirrors ``crawl_page``'s disabled-tool refusal, applied at the route instead
of inside a tool. Route guards (hunt/finding lookup, ordinal bounds, the
running/complete status checks, the ES-timeout wrapper) mirror
``soc_ai.api.webui.routes_hunts.promote_finding``.

Confirm-first doctrine (owner-approved, STRICT): a detection may be drafted
ONLY from a finding whose promoted investigation completed with a
``true_positive`` verdict. Both routes enforce it — the hunt-finding route
looks up the finding's latest promotion
(:func:`soc_ai.store.investigations.latest_for_finding`), the
investigation route checks the investigation's own verdict — and refuse
anything else with a 409 ``not_confirmed_true_positive``.

Grounding: the drafter has no tools and never reads the grid, so its
evidence must carry the OBSERVED discriminating field values or the rule's
values are invented. Before drafting, the shared pipeline resolves the
finding's first few citations to real ES documents (full ``_source``,
bounded at :data:`_MAX_CITED_DOCS`) and folds their non-null notable fields
into the evidence string. A finding whose citations resolve to nothing on
the grid is refused with the same 422 ``no_promotable_evidence`` shape
``promote_finding`` uses. The first cited event's ``@timestamp`` also
anchors the would-have-fired dry-run window on when the activity happened,
not on now.

Egress: a hunt finding's evidence carries REAL internal IPs/hostnames
(``Hunt.report`` is desanitized before persistence), and
:func:`~soc_ai.detection.drafter.draft_detection` has no gateway-level
redaction of its own — this route is the only place that decides whether the
analyst-model call is guarded. When ``settings.analyst_cloud_redaction is
True``, both routes build an :class:`~soc_ai.agent.egress_guard.EgressGuard`
(reusing ``runbook_promotion._build_guard`` — same helper, same effective
internal-identifier set) while the DB session is still open, and pass it
into :func:`draft_detection`. The evidence string (cited-event field values
included) is part of the composed prompt, so it rides the guard's full
sanitize → residue-sweep → desanitize round trip. A fail-closed residue leak
(:class:`~soc_ai.agent.egress_guard.EgressResidueError`) is mapped to a 502
``egress_blocked`` response, mirroring
``soc_ai.api.webui.routes_runbooks.promote_runbook``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import httpx
import yaml
from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Request
from pydantic_ai.exceptions import AgentRunError
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.agent.egress_guard import EgressGuard, EgressResidueError
from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.webui._shared import router
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.api.webui.routes_hunts import _ID_SHAPED, _hunt_report
from soc_ai.config import Settings
from soc_ai.detection.drafter import draft_detection
from soc_ai.detection.models import SigmaDraft
from soc_ai.detection.untrusted import neutralize_untrusted
from soc_ai.detection.validators import dry_run_detection, validate_sigma_yaml
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import get_dotted
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Hunt, Investigation
from soc_ai.webui.runbook_promotion import _build_guard

# Citation-resolution bound: full ``_source`` is fetched for at most this many
# cited docs — enough to ground the drafter and anchor the dry-run window,
# small enough that fetching whole documents stays cheap.
_MAX_CITED_DOCS = 5

# Citation ids listed verbatim in the evidence string before eliding the rest.
_MAX_CITED_IDS_LISTED = 20

# Per-value render cap in the evidence string (a runaway field value must not
# blow up the drafter's prompt). Every untrusted splice below also goes
# through neutralize_untrusted (2026-08-25 audit, M1): control characters are
# escaped so a hostile value with an embedded newline cannot break out of its
# ``- id: path=value`` list item and render injected sentences as their own
# lines inside the drafter's ground-truth block.
_MAX_VALUE_CHARS = 120

# Dotted paths surfaced (when non-null) from each resolved cited doc — the
# OBSERVED discriminating values the drafter is told to key the rule on.
# ECS names first, ``zeek.*`` fallbacks after, mirroring the coalesce order
# in :mod:`soc_ai.so_client.fields`.
_OBSERVED_FIELDS: tuple[str, ...] = (
    "event.dataset",
    "event.action",
    "rule.name",
    "network.transport",
    "network.protocol",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "dns.query.name",
    "dns.question.name",
    "zeek.dns.query",
    "dce_rpc.operation",
    "zeek.dce_rpc.operation",
    "zeek.dce_rpc.endpoint",
    "http.request.method",
    "url.original",
    "process.name",
    "user.name",
    "host.name",
)

_NOT_CONFIRMED_DETAIL: dict[str, str] = {
    "reason": "not_confirmed_true_positive",
    "hint": (
        "Investigate and confirm this finding as a true positive before drafting a detection."
    ),
}


def _require_sigma_authoring(settings: Settings) -> None:
    """403 in the gated-off shape when the detection bridge is disabled.

    Mirrors ``crawl_page``'s disabled-tool refusal (``settings.crawl4ai_enabled``
    check), applied at the route boundary rather than inside a tool.
    """
    if not settings.sigma_authoring_enabled:
        raise HTTPException(
            status_code=403,
            detail={
                "reason": "sigma_authoring_disabled",
                "hint": "Enable it in the config console.",
            },
        )


def _citation_ids(finding: dict[str, Any]) -> list[str]:
    """The finding's citation ids coerced to str, order preserved.

    Same don't-trust-stored-JSON coercion ``promote_finding`` applies: report
    JSON is not schema-enforced, so a stray int/None in ``citations`` must not
    TypeError downstream.
    """
    citations = finding.get("citations")
    if not isinstance(citations, list):
        return []
    return [str(c) for c in citations if isinstance(c, (str, int))]


async def _resolve_cited_docs(
    elastic: ElasticClient, settings: Settings, citations: list[str]
) -> list[dict[str, Any]]:
    """Resolve the finding's first few ID-shaped citations to real ES docs.

    Bounded at :data:`_MAX_CITED_DOCS` ids — few enough that fetching full
    ``_source`` per doc is fine. Citation order is preserved; ids that don't
    resolve are simply absent from the result.
    """
    ids = [c for c in citations if _ID_SHAPED.match(c)][:_MAX_CITED_DOCS]
    if not ids:
        return []
    lookup = await elastic.search(
        settings.events_index_pattern, {"ids": {"values": ids}}, size=len(ids)
    )
    hits = [h for h in (lookup.hits or []) if isinstance(h, dict)]
    by_id = {h.get("_id"): h for h in hits}
    return [by_id[i] for i in ids if i in by_id]


def _observed_values(doc: dict[str, Any]) -> list[str]:
    """Non-null notable field values of one cited doc, as ``path=value`` parts.

    Field values are ATTACKER-CONTROLLABLE telemetry: each is neutralized
    (control characters escaped, fence punctuation defused, capped at
    :data:`_MAX_VALUE_CHARS`) so it stays confined to its list item — see the
    module note on M1.
    """
    source = doc.get("_source")
    if not isinstance(source, dict):
        return []
    parts: list[str] = []
    for path in _OBSERVED_FIELDS:
        value = get_dotted(source, path)
        if value is None or value in ("", [], {}):
            continue
        rendered = neutralize_untrusted(str(value), cap=_MAX_VALUE_CHARS)
        parts.append(f"{path}={rendered}")
    return parts


def _cited_time_anchor(cited_docs: list[dict[str, Any]]) -> datetime | None:
    """``@timestamp`` of the first cited doc carrying a parseable one.

    Anchors the would-have-fired dry-run window on when the cited activity
    actually happened instead of on now — a hunt over last month's telemetry
    must not dry-run against an empty "past 30 days from today".
    """
    for doc in cited_docs:
        source = doc.get("_source")
        if not isinstance(source, dict):
            continue
        raw = source.get("@timestamp")
        if not isinstance(raw, str) or not raw:
            continue
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def _build_evidence(finding: dict[str, Any], cited_docs: list[dict[str, Any]]) -> str:
    """Format one hunt finding's own fields + resolved citations as the
    drafter's grounding evidence string.

    The finding's ``title``/``detail``/``hosts`` are folded into the drafter's
    prompt separately (:func:`soc_ai.detection.drafter._build_draft_prompt`);
    this adds severity, category, the citation ids (capped at
    :data:`_MAX_CITED_IDS_LISTED`, with an "… and N more" elision), and — the
    part that grounds the rule — the OBSERVED field values read from the
    resolved cited documents themselves.

    Everything spliced here is untrusted (report JSON is not schema-enforced;
    cited-doc values and ids come off the grid), so every piece rides through
    :func:`neutralize_untrusted` — a value cannot start a line of its own.
    """
    lines: list[str] = []
    severity = finding.get("severity")
    if severity:
        lines.append(f"Severity: {neutralize_untrusted(str(severity), cap=_MAX_VALUE_CHARS)}")
    category = finding.get("category")
    if category:
        lines.append(f"Category: {neutralize_untrusted(str(category), cap=_MAX_VALUE_CHARS)}")
    cite_ids = _citation_ids(finding)
    if cite_ids:
        listed = [
            neutralize_untrusted(c, cap=_MAX_VALUE_CHARS) for c in cite_ids[:_MAX_CITED_IDS_LISTED]
        ]
        suffix = (
            f", … and {len(cite_ids) - len(listed)} more" if len(cite_ids) > len(listed) else ""
        )
        lines.append("Cited evidence (ES document ids): " + ", ".join(listed) + suffix)
    else:
        lines.append("No cited evidence ids on this finding.")
    if cited_docs:
        lines.append("")
        lines.append(
            "Observed field values from the cited events "
            "(ground truth — key the rule on these, never on invented values):"
        )
        for doc in cited_docs:
            parts = _observed_values(doc)
            rendered = "; ".join(parts) if parts else "(no notable field values)"
            doc_id = neutralize_untrusted(str(doc.get("_id")), cap=_MAX_VALUE_CHARS)
            lines.append(f"- {doc_id}: {rendered}")
    return "\n".join(lines)


def _stamp_provenance(
    draft: SigmaDraft, *, hunt_id: str, ordinal: int, investigation_id: str | None
) -> SigmaDraft:
    """Deterministically stamp the drafted rule's YAML with its origin.

    Server-side, never model-authored: a leading ``#`` comment naming the hunt
    + finding (+ investigation when known) and a Sigma ``author: soc-ai`` key
    (appended at top level, only when the YAML parses to a mapping without
    one), so the exported ``.yml`` carries where it came from. A comment can
    never change how YAML parses; the appended ``author`` key is re-checked by
    the caller's re-validation.
    """
    comment = f"# drafted by soc-ai from hunt {hunt_id} finding {ordinal}"
    if investigation_id:
        comment += f" (investigation {investigation_id})"
    lines = [comment, draft.sigma_yaml.rstrip("\n")]
    try:
        doc = yaml.safe_load(draft.sigma_yaml)
    except yaml.YAMLError:
        doc = None
    if isinstance(doc, dict) and "author" not in doc:
        lines.append("author: soc-ai")
    return draft.model_copy(update={"sigma_yaml": "\n".join(lines) + "\n"})


def _provenanced(
    draft: SigmaDraft, *, hunt_id: str, ordinal: int, investigation_id: str | None
) -> SigmaDraft:
    """Stamp provenance, then re-validate so ``schema_ok`` reflects the final
    exported YAML. If (pathologically) the appended ``author`` key breaks a
    previously-valid rule, fall back to the untouched draft rather than
    downgrade it — provenance must never cost validity.
    """
    stamped = validate_sigma_yaml(
        _stamp_provenance(
            draft, hunt_id=hunt_id, ordinal=ordinal, investigation_id=investigation_id
        )
    )
    if stamped.schema_ok is False and draft.schema_ok is not False:
        return draft
    return stamped


async def _drafted_detection(
    settings: Settings,
    elastic: ElasticClient,
    finding: dict[str, Any],
    *,
    guard: EgressGuard | None,
    hunt_id: str,
    ordinal: int,
    investigation_id: str | None,
) -> SigmaDraft:
    """The shared resolve-evidence → draft → validate → stamp → dry-run
    pipeline both routes run.

    ``guard`` is threaded straight into :func:`draft_detection` — the caller
    (each route, below) already decided whether redaction applies and built
    it while its DB session was open; this function only round-trips it.
    :class:`~soc_ai.agent.egress_guard.EgressResidueError` (fail-closed
    redaction blocked the outbound prompt — the model was never called) is
    mapped to a 502 ``egress_blocked``, mirroring
    ``soc_ai.api.webui.routes_runbooks.promote_runbook``: the leaked COUNT is
    reported, never the values.

    The two grid touches (citation resolution, the dry run) are each wrapped
    in the ``webui_grid_timeout_s`` budget + ES-error mapping (same shape
    ``promote_finding`` wraps its own ES call in). The analyst-model call has
    its OWN wall-clock budget (``sigma_draft_timeout_s`` — deliberately below
    the SPA's client draft timeout, so a slow draft gets an honest 504 back
    before the client aborts and the server's work is discarded) and its own
    error map: a timeout is a 504 ``draft_timeout``; a transport/gateway
    failure or retry exhaustion (httpx errors, pydantic-ai's
    :class:`AgentRunError` family) is a 502 ``draft_model_unavailable`` —
    never a bare 500.
    """
    citations = _citation_ids(finding)
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            cited_docs = await _resolve_cited_docs(elastic, settings, citations)
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        raise _es_api_error_http(exc) from exc
    if not cited_docs:
        raise HTTPException(
            status_code=422,
            detail={
                "reason": "no_promotable_evidence",
                "hint": (
                    "None of the finding's citations resolve to an event on the "
                    "grid — there is no observed evidence to ground a detection on."
                ),
            },
        )
    evidence = _build_evidence(finding, cited_docs)
    time_anchor = _cited_time_anchor(cited_docs)

    try:
        async with asyncio.timeout(settings.sigma_draft_timeout_s):
            draft = await draft_detection(settings, finding=finding, evidence=evidence, guard=guard)
    except EgressResidueError as exc:
        raise HTTPException(
            status_code=502,
            detail={"reason": "egress_blocked", "leaked_count": len(exc.leaked)},
        ) from exc
    except TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail={
                "reason": "draft_timeout",
                "hint": "Drafting the rule ran out of time — try again.",
            },
        ) from exc
    except (httpx.HTTPError, AgentRunError) as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "reason": "draft_model_unavailable",
                "hint": "The analyst model could not be reached or did not answer — try again.",
            },
        ) from exc

    draft = validate_sigma_yaml(draft)
    draft = _provenanced(draft, hunt_id=hunt_id, ordinal=ordinal, investigation_id=investigation_id)
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            draft = await dry_run_detection(
                draft, elastic=elastic, settings=settings, time_anchor=time_anchor
            )
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        raise _es_api_error_http(exc) from exc
    return draft


async def _guard_for(db: AsyncSession, settings: Settings) -> EgressGuard | None:
    """Build the egress guard iff cloud redaction is on, else ``None``.

    ``is True`` (not truthiness) so a non-Settings test double can never flip
    redaction on — the same guard-rail ``draft_runbook_for_rule`` uses. Must
    be called while *db* (the caller's open session) is still alive —
    ``_build_guard`` resolves the deployment's effective internal-identifier
    set from it.
    """
    if settings.analyst_cloud_redaction is True:
        return await _build_guard(db, settings)
    return None


# response_model=None on both draft routes: the SigmaDraft max_length caps
# validate the DRAFTER's output (inside draft_detection); the server-side
# provenance stamp then grows sigma_yaml by ~60-130 chars, so FastAPI
# re-validating the response would 500 a successful draft sitting within
# stamp headroom of the cap. The ``-> SigmaDraft`` annotation stays for
# typing; the pydantic object still serializes via jsonable_encoder.
@router.post("/hunts/{hunt_id}/findings/{ordinal}/draft-detection", response_model=None)
async def draft_hunt_finding_detection(
    request: Request,
    hunt_id: str,
    ordinal: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> SigmaDraft:
    """Draft a Sigma detection rule from one hunt finding, by ordinal.

    ``ordinal`` is the finding's index into ``hunt.report["findings"]`` — the
    same convention ``promote_finding`` uses (the FastAPI ``int`` path
    convertor already refuses a negative segment with a bare 404).

    Confirm-first: the finding must have been promoted to an investigation
    that completed with a ``true_positive`` verdict — anything else
    (unpromoted, still running, or any other verdict) is refused with a 409.
    """
    _require_sigma_authoring(settings)
    async with request.app.state.db_sessionmaker() as db:
        hunt = await db.get(Hunt, hunt_id)
        if hunt is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if hunt.status == "running":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "still_running",
                    "hint": (
                        "The hunt is still running — findings can be drafted "
                        "once it lands its report."
                    ),
                },
            )
        findings = _hunt_report(hunt).get("findings") or []
        if not (0 <= ordinal < len(findings)) or not isinstance(findings[ordinal], dict):
            raise HTTPException(
                status_code=404,
                detail={
                    "reason": "finding_not_found",
                    "hint": "That finding is not in this hunt's report.",
                },
            )
        finding = findings[ordinal]
        promoted = await inv_svc.latest_for_finding(db, hunt_id, ordinal)
        if promoted is None or promoted.status != "complete" or promoted.verdict != "true_positive":
            raise HTTPException(status_code=409, detail=dict(_NOT_CONFIRMED_DETAIL))
        investigation_id = promoted.id
        guard = await _guard_for(db, settings)
    return await _drafted_detection(
        settings,
        elastic,
        finding,
        guard=guard,
        hunt_id=hunt_id,
        ordinal=ordinal,
        investigation_id=investigation_id,
    )


@router.post("/investigations/{inv_id}/draft-detection", response_model=None)
async def draft_investigation_detection(
    request: Request,
    inv_id: str,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> SigmaDraft:
    """Draft a Sigma detection rule from a complete, hunt-kind investigation's
    promoted finding.

    ``hunt_id`` carries no foreign key (an investigation must survive hunt
    deletion — see the :class:`~soc_ai.store.models.Investigation` model
    note), so a dangling reference degrades to a 404 rather than an
    unhandled lookup failure.

    Confirm-first: the investigation must have landed a ``true_positive``
    verdict — a false positive or an inconclusive run is refused with a 409.
    """
    _require_sigma_authoring(settings)
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if inv.kind != "hunt":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "not_a_hunt_investigation",
                    "hint": "Only a promoted hunt finding can draft a detection.",
                },
            )
        if inv.status != "complete":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "not_complete",
                    "hint": "The investigation must finish before drafting a detection.",
                },
            )
        if inv.verdict != "true_positive":
            raise HTTPException(status_code=409, detail=dict(_NOT_CONFIRMED_DETAIL))
        hunt = await db.get(Hunt, inv.hunt_id) if inv.hunt_id else None
        if hunt is None:
            raise HTTPException(status_code=404, detail={"reason": "hunt_not_found"})
        findings = _hunt_report(hunt).get("findings") or []
        ordinal = inv.finding_ordinal
        if (
            ordinal is None
            or not (0 <= ordinal < len(findings))
            or not isinstance(findings[ordinal], dict)
        ):
            raise HTTPException(status_code=404, detail={"reason": "finding_not_found"})
        finding = findings[ordinal]
        guard = await _guard_for(db, settings)
    return await _drafted_detection(
        settings,
        elastic,
        finding,
        guard=guard,
        hunt_id=hunt.id,
        ordinal=ordinal,
        investigation_id=inv_id,
    )
