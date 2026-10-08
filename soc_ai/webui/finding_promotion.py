"""Open an investigation of a hunt finding: the promotion service.

Three callers open an investigation of a hunt's evidence: the finding
promotion route (``POST /hunts/{id}/findings/{o}/investigate``), the lead
promotion route and the hunt runner, which investigates every subject finding
of a hunt as part of the hunt (:mod:`soc_ai.webui.hunt_findings`). All three
pass through :func:`start_promotion`, so a promotion has one anchor rule, one
focus block and one start path.

The service holds no ``Request``. It reads ``state`` (``app.state``) the way the
background managers do, so the hunt runner calls it from a background task.
A route maps :class:`PromotionRefused` and the grid errors to its HTTP answers.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

from soc_ai.agent.context import HuntSubject, InvestigationContext
from soc_ai.agent.prompts import FocusOrigin
from soc_ai.config import Settings
from soc_ai.hunting.findings import DOCUMENT_ID_RE
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import get_dotted


def investigation_manager(state: Any) -> Any:
    """The app's investigation manager (:mod:`soc_ai.webui.hunt_manager`).

    Imported on call. The manager imports the API package, and the API package
    imports this module through the hunt routes. A module-level import made
    the cycle fail for a caller that imported this module first.
    """
    from soc_ai.webui import hunt_manager  # noqa: PLC0415 - import cycle

    return hunt_manager.get_manager(state)


# Detector-flag datasets: an anchor from these is another detector's CLAIM, not
# raw telemetry. A cited telemetry document wins over them, because a promoted
# finding is investigated from its evidence.
DETECTOR_DATASETS = frozenset({"suricata.alert", "sigma.alert", "zeek.notice"})

# The hint of a promotion whose citations resolve to nothing on the grid.
NO_EVIDENCE_HINT = "None of the citations resolve to an event on the grid."
# The hint of a promotion the investigation manager did not start.
COULD_NOT_START_HINT = (
    "The console did not start the run. Check the model gateway on the Config screen."
)


class PromotionRefused(Exception):
    """The promotion did not start. ``status`` is the HTTP code a route answers."""

    def __init__(self, status: int, reason: str, hint: str) -> None:
        super().__init__(hint)
        self.status = status
        self.reason = reason
        self.hint = hint


async def resolve_finding_anchor(
    elastic: ElasticClient, settings: Settings, citations: Sequence[str]
) -> str | None:
    """Pick the finding's anchor document: the cited id the investigation runs on.

    Citation order is kept within each class, and telemetry wins over a
    detector document. None when nothing resolves.

    Only ``event.dataset`` is read from each hit, so the lookup asks for that
    field alone and caps the id list: a report with hundreds of citations must
    not turn one anchor pick into a bulk document fetch.
    """
    ids = [c for c in citations if DOCUMENT_ID_RE.match(c)][:100]
    if not ids:
        return None
    lookup = await elastic.search(
        settings.events_index_pattern,
        {"ids": {"values": ids}},
        size=len(ids),
        source=["event.dataset"],
    )
    hits = list(lookup.hits or [])
    if not hits:
        return None
    by_id = {h.get("_id"): h for h in hits}
    ordered = [by_id[i] for i in ids if i in by_id]
    for h in ordered:
        ds = str(get_dotted(h.get("_source", {}), "event.dataset") or "").lower()
        if ds not in DETECTOR_DATASETS:
            return h.get("_id")
    return ordered[0].get("_id")


def anchor_from_subject(subject: HuntSubject) -> str | None:
    """The anchor document of a hunt-subject run, from the documents it holds.

    Same rule as :func:`resolve_finding_anchor`: the promoted finding's
    documents come first and telemetry wins over a detector's claim. No second
    grid read, because the subject builder fetched these documents already.
    """
    for doc in subject.documents:
        if str(doc.event_dataset or "").lower() not in DETECTOR_DATASETS:
            return doc.id
    return subject.documents[0].id if subject.documents else None


def promotion_focus(
    *,
    focus_origin: FocusOrigin,
    title: str,
    detail: str,
    hosts: Sequence[str],
    hunt_subject: bool,
) -> str:
    """The focus block the investigator reads first."""
    host_text = ", ".join(hosts) or "none named"
    lead_in = f"Promoted {focus_origin.replace('_', ' ')}: {title}. {detail} Hosts involved: "
    if hunt_subject:
        return (
            f"{lead_in}{host_text}. The subject of this investigation is the hunt, not one "
            "event. Answer the hunt's objective. Do not assume the framing is correct."
        )
    return (
        f"{lead_in}{host_text}. This investigation targets the cited evidence event. Assess "
        "whether the activity is malicious. Do not assume the framing is correct."
    )


async def promotion_anchor(
    *,
    settings: Settings,
    elastic: ElasticClient,
    citations: Sequence[str],
    subject: HuntSubject | None,
) -> str:
    """The anchor document of a promotion, or :class:`PromotionRefused` (422).

    A grid failure propagates as ``TimeoutError``, ``TransportError`` or
    ``ApiError``. The caller names the failure in its own words.
    """
    anchor_id = anchor_from_subject(subject) if subject is not None else None
    if anchor_id is None:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            anchor_id = await resolve_finding_anchor(elastic, settings, citations)
    if anchor_id is None:
        raise PromotionRefused(422, "no_promotable_evidence", NO_EVIDENCE_HINT)
    return anchor_id


async def start_promotion(
    state: Any,
    *,
    anchor_id: str,
    started_by: str,
    title: str,
    detail: str,
    hosts: Sequence[str],
    kind: str,
    hunt_id: str | None,
    finding_ordinal: int | None,
    focus_origin: FocusOrigin,
    is_synth_eval: bool,
    subject: HuntSubject | None = None,
    ctx: InvestigationContext | None = None,
) -> str:
    """Start an investigation of the hunt on ``anchor_id`` and return its id.

    ``subject`` (D2) carries the hunt. The run reads the hunt's objective, its
    findings and every document they cite. The anchor is one document, because
    the pipeline anchors its time windows on one timestamp, but the subject of
    the verdict is the hunt.

    ``ctx`` is the context the run uses. None builds a fresh one from
    ``state``, which is the route's case. The hunt runner passes a copy of its
    own context, so an investigation of an evaluation hunt sees what the hunt
    saw.

    Raises :class:`PromotionRefused` (503) when the manager did not start it.
    """
    focus = promotion_focus(
        focus_origin=focus_origin,
        title=title,
        detail=detail,
        hosts=hosts,
        hunt_subject=subject is not None,
    )
    kwargs: dict[str, Any] = {
        "alert_id": anchor_id,
        "started_by": started_by,
        "rule_name": title,
        "focus_hint": focus,
        "kind": kind,
        "hunt_id": hunt_id,
        "finding_ordinal": finding_ordinal,
        # A promoted anchor is cited telemetry, not an SO alert. No unattended
        # write can ever apply to it, and its focus text is the promoter's own
        # framing, not a prior investigation's open questions.
        "allow_so_writes": False,
        "focus_origin": focus_origin,
        "is_synth_eval": is_synth_eval,
        "subject": subject,
    }
    if ctx is not None:
        kwargs["ctx"] = ctx
    inv_id = await investigation_manager(state).start(state, **kwargs)
    if inv_id is None:
        raise PromotionRefused(503, "could_not_start", COULD_NOT_START_HINT)
    return str(inv_id)


def fresh_context(ctx: InvestigationContext) -> InvestigationContext:
    """A new context for one investigation, built from a hunt's context.

    The shared clients and the synthetic-evaluation scope carry over. The
    per-run state (the dedup tracker, the time anchor, the visible tools) starts
    empty, because an investigation builds its own.
    """
    return InvestigationContext(
        settings=ctx.settings,
        auth=ctx.auth,
        elastic=ctx.elastic,
        misp=ctx.misp,
        audit=ctx.audit,
        blocklist=ctx.blocklist,
        maxmind=ctx.maxmind,
        cloud=ctx.cloud,
        include_synth=ctx.include_synth,
        db_sessionmaker=ctx.db_sessionmaker,
    )


__all__ = [
    "COULD_NOT_START_HINT",
    "DETECTOR_DATASETS",
    "NO_EVIDENCE_HINT",
    "PromotionRefused",
    "anchor_from_subject",
    "fresh_context",
    "promotion_anchor",
    "promotion_focus",
    "resolve_finding_anchor",
    "start_promotion",
]
