"""Oracle redaction preview + signed decision-record export endpoints."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Literal

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from soc_ai import __version__
from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui._shared import (
    require_admin_api,
    router,
)
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Investigation

_LOGGER = logging.getLogger(__name__)

# ── Oracle pre-egress redaction preview ────────────────────────────────────────


class RedactionReplacementOut(BaseModel):
    """One redacted span: the opaque label ↔ the real value it replaced.

    Drives the before/after highlight in the preview UI.  Carrying the real
    value is deliberate and safe HERE ONLY: both preview endpoints are
    admin-gated and already return the raw original text in the same response,
    so the pair reveals nothing the caller doesn't have.
    """

    label: str
    value: str
    category: str


class RedactionPreviewOut(BaseModel):
    original: dict[str, Any]
    sanitized: dict[str, Any]
    summary: dict[str, int]
    # Only the pairs that actually occur in THIS preview's sanitized output —
    # never the whole identifier config.
    replacements: list[RedactionReplacementOut]
    note: str


@router.get(
    "/oracle/redaction-preview",
    response_model=RedactionPreviewOut,
    dependencies=[Depends(require_admin_api)],
)
async def oracle_redaction_preview(
    settings: Settings = Depends(get_settings_dep),
) -> RedactionPreviewOut:
    """Show EXACTLY what leaves the network before an Oracle call.

    Runs THIS deployment's own internal identifiers (derived from
    ``oracle_internal_suffixes``) through the real pre-egress sanitizer and returns
    the before → after, plus a per-category count. Lets an operator inspect and
    trust the redaction before enabling the Oracle — and confirm that public
    addresses pass through while every internal identifier is pseudonymized.
    """
    from soc_ai.oracle.sanitize import (  # noqa: PLC0415
        Mapping,
        redaction_replacements,
        redaction_summary,
        sanitize,
    )

    suffix = (settings.oracle_internal_suffixes or (".local",))[0]
    # A representative sample: internal host/IP/MAC/user/email (all must redact) +
    # one PUBLIC destination (must pass through so the Oracle sees real infra).
    sample: dict[str, Any] = {
        "host": {"name": f"dc01{suffix}", "ip": "10.0.0.15"},
        "source": {"ip": "192.168.1.42", "mac": "00:1a:2b:3c:4d:5e"},
        "user": {"name": "jsmith", "email": f"jsmith@corp{suffix}"},
        "destination": {"ip": "8.8.8.8"},  # external — preserved
        "note": f"beacon from dc01{suffix} (10.0.0.15) to 8.8.8.8 every 60s",
    }
    mapping = Mapping()
    sanitized = sanitize(sample, mapping, extra_suffixes=settings.oracle_internal_suffixes)
    # The mapping only ever holds what sanitize() actually matched, but filter
    # by occurrence in the sanitized output anyway — the contract is "what YOU
    # see highlighted", not "what the sanitizer learned along the way".
    sanitized_json = json.dumps(sanitized)
    return RedactionPreviewOut(
        original=sample,
        sanitized=sanitized,
        summary=redaction_summary(mapping),
        replacements=[
            RedactionReplacementOut(label=r.label, value=r.value, category=r.category)
            for r in redaction_replacements(mapping)
            if r.label in sanitized_json
        ],
        note=(
            "Internal identifiers are replaced with stable opaque labels (IP_01, "
            "HOST_01, …) before any Oracle call — the same real value always maps to "
            "the same label so the model's reasoning stays coherent. Public/external "
            "addresses pass through so the Oracle can reason about real infrastructure. "
            "Nothing is sent at all unless you enable the Oracle."
        ),
    )


# ── Analyst-path redaction preview (E5.2) ──────────────────────────────────────


class AnalystRedactionPreviewOut(BaseModel):
    # Literal discriminator (mirrors HealthResponse's status idiom) — pairs with
    # AnalystRedactionPreviewUnavailableOut in the endpoint's union response.
    status: Literal["ok"] = "ok"
    investigation_id: str
    # Current settings, so the UI can say "this is a simulation; redaction is
    # currently off" — the preview itself ALWAYS shows what redaction would do.
    redaction_enabled: bool
    fail_closed: bool
    # The rebuilt round-1 analyst prompt — text, not the Oracle preview's dict
    # (the analyst egress boundary is a composed message string).
    original: str
    sanitized: str
    summary: dict[str, int]
    # (label ↔ value) pairs occurring in this preview — see RedactionReplacementOut.
    replacements: list[RedactionReplacementOut]
    note: str


# Event kinds the rebuild cannot proceed without. Both are emitted
# unconditionally by the synth-first pipeline; investigations from before these
# kinds existed (or from the legacy pipeline) get a 200 events_missing body.
_REQUIRED_PREVIEW_KINDS = ("enriched_alert_context", "decision_template_match")


class AnalystRedactionPreviewUnavailableOut(BaseModel):
    """A NON-FATAL preview outcome: the investigation exists, but its stored
    events cannot honestly rebuild the analyst prompt.

    Deliberately HTTP 200, not 4xx — the UI renders these as a friendly note,
    and a 4xx would land a console error in the browser (tripping the
    browser-smoke's zero-console-error gate) for a state that is not a failure.
    Discriminated from the OK shape by the literal ``status`` field.
    """

    status: Literal["events_missing", "context_unparseable"]
    detail: str
    # The required event kinds absent from this run (events_missing only).
    missing: list[str] = []


def _analyst_preview_note(
    *,
    redaction_enabled: bool,
    event_kinds: set[str],
    prior_block_present: bool,
    cited_dropped: bool,
) -> str:
    """Assemble the preview's honesty note from what the rebuild actually did.

    Every sentence is conditional on observed state — the note never claims a
    caveat that doesn't apply to THIS investigation's stored events.
    """
    parts = [
        "Rebuilt from this investigation's stored events and redacted with the "
        "CURRENT identifier configuration — a simulation of the analyst-path "
        "egress, not a byte-replay of the original run.",
        "The stored enriched context is written before any redaction (local "
        "storage never egresses), so the original side is the true raw prompt "
        "material even for runs that executed with redaction on.",
    ]
    if not redaction_enabled:
        parts.append(
            "analyst_cloud_redaction is currently OFF — a real analyst call "
            "would send the original text unredacted; the sanitized side shows "
            "what WOULD be sent if you enable it."
        )
    if "synth_round1_skipped" in event_kinds:
        parts.append(
            "This run skipped the round-1 synthesis (routed straight to the "
            "investigation loop); shown is the message round 1 WOULD have received."
        )
    if "context_trimmed" in event_kinds:
        parts.append(
            "The original run trimmed the enriched context to the model window; "
            "the trim is not replayed here (window discovery would call the gateway)."
        )
    if prior_block_present:
        parts.append(
            "Prior-outcome rationale digests are not stored in events; the "
            "rebuilt memory block carries placeholders for them."
        )
    if cited_dropped:
        parts.append(
            "The candidate's cited-evidence lines could not be reproduced "
            "(template logic changed since this run) and are omitted."
        )
    return " ".join(parts)


@router.get(
    "/analyst/redaction-preview/{inv_id}",
    response_model=AnalystRedactionPreviewOut | AnalystRedactionPreviewUnavailableOut,
    dependencies=[Depends(require_admin_api)],
)
async def analyst_redaction_preview(
    inv_id: str,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> AnalystRedactionPreviewOut | AnalystRedactionPreviewUnavailableOut:
    """Show what the ANALYST model would receive for a PAST investigation.

    Rebuilds the round-1 synthesizer user message from the investigation's
    stored events — enriched context + decision-template candidate + the E4.2
    prior-outcomes block when that event exists — in the orchestrator's exact
    composition order, then runs it through a THROWAWAY
    :class:`~soc_ai.agent.egress_guard.EgressGuard` built from the CURRENT
    settings/identifier config. Read-only: no model call, no egress, no writes;
    the guard (and its label mapping) is discarded with the response.

    Honesty notes (each verified against ``_run_synth_first_pipeline``):

    - The stored ``enriched_alert_context`` event carries the RAW context: the
      orchestrator emits it BEFORE any sanitization (deliberately — "local
      storage, never egress"), so the ``original`` side is genuinely raw even
      for runs that executed with redaction ON.
    - The preview redacts with the CURRENT identifier configuration, not the
      run-time one, and skips the context-window trim (window discovery calls
      the gateway, and this endpoint must not egress).
    - The ``prior_outcomes`` event deliberately stores no rationale text, so a
      rebuilt memory block carries "(no rationale recorded)" placeholders.
    - The ``decision_template_match`` event stores no ``cited_evidence``; it
      is recovered by re-running the pure template matcher on the stored
      context, and used only when that reproduces the SAME template id.

    Outcomes: 404 for an unknown id; otherwise ALWAYS 200 with a
    status-discriminated body — ``{"status": "ok", ...}`` for a full preview,
    ``{"status": "events_missing", ...}`` when the run predates the required
    event kinds, ``{"status": "context_unparseable", ...}`` when the stored
    context no longer validates against the current schema. The two non-ok
    shapes are non-fatal states the UI renders as a friendly note; a 4xx here
    would log a browser console error for a perfectly healthy page.
    """
    # Lazy agent-layer imports (mirrors the oracle preview above): the export
    # routes module stays import-light for every request that isn't this one.
    from soc_ai.agent.decision_templates import (  # noqa: PLC0415
        CandidateVerdict,
        match_decision_template,
    )
    from soc_ai.agent.egress_guard import EgressGuard  # noqa: PLC0415
    from soc_ai.agent.evidence import _materialize_prefetch_evidence  # noqa: PLC0415
    from soc_ai.agent.orchestrator import (  # noqa: PLC0415
        _format_chat_memory_block,
        _format_prior_outcomes_block,
    )
    from soc_ai.agent.prompts import build_synth_first_user_message  # noqa: PLC0415
    from soc_ai.tools.get_alert_context import EnrichedAlertContext  # noqa: PLC0415

    async with request.app.state.db_sessionmaker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
    if got is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    inv, events = got

    # First payload per kind, in sequence order (each rebuild input is emitted
    # at most once per run).
    by_kind: dict[str, dict[str, Any]] = {}
    for ev in events:
        by_kind.setdefault(ev.kind, ev.payload or {})

    missing = [k for k in _REQUIRED_PREVIEW_KINDS if k not in by_kind]
    if missing:
        return AnalystRedactionPreviewUnavailableOut(
            status="events_missing",
            missing=missing,
            detail=(
                "This investigation predates the stored events needed to "
                "rebuild the analyst prompt — only newer runs can be previewed."
            ),
        )

    try:
        enriched = EnrichedAlertContext.model_validate(by_kind["enriched_alert_context"])
    except Exception:
        # Schema drift on an old run: the stored payload no longer parses.
        # Distinct status from events_missing — the events exist, we just
        # can't honestly rebuild from them.
        return AnalystRedactionPreviewUnavailableOut(
            status="context_unparseable",
            detail=(
                "The stored enriched context no longer parses against the "
                "current schema, so the analyst prompt cannot be rebuilt honestly."
            ),
        )

    # ----- Decision-template candidate (Phase B) -----
    # The stored event carries verdict/confidence/template_id/rationale but NOT
    # cited_evidence. The matcher is a pure function of the enriched context,
    # so re-run it to recover the cited lines — but trust it only when it
    # reproduces the SAME template the run recorded (template logic may have
    # changed since); otherwise omit the lines and say so in the note.
    tm = by_kind["decision_template_match"]
    candidate: CandidateVerdict | None = None
    cited_dropped = False
    if tm.get("matched") and tm.get("template_id"):
        recomputed = match_decision_template(enriched)
        if recomputed is not None and recomputed.template_id == tm.get("template_id"):
            cited = recomputed.cited_evidence
        else:
            cited = []
            cited_dropped = True
        candidate = CandidateVerdict(
            # Defensive default keeps a malformed stored payload a 200-preview
            # rather than a 500 (the verdict text is display material here).
            verdict=tm.get("verdict") or "needs_more_info",
            confidence=float(tm.get("confidence") or 0.0),
            cited_evidence=cited,
            template_id=str(tm.get("template_id")),
            rationale=str(tm.get("rationale") or ""),
        )

    # ----- E4.2 prior-outcomes block (round-1 only, when the run recalled any) --
    # The event stores ids/verdicts/tier ONLY — never rationale text — so the
    # rebuilt block renders the same structure with placeholder digests/ages.
    prior_block: str | None = None
    if "prior_outcomes" in by_kind:
        items = by_kind["prior_outcomes"].get("items") or []
        digests = [
            {"verdict": it.get("verdict"), "matched_on": it.get("matched_on")}
            for it in items
            if isinstance(it, dict)
        ]
        if digests:
            prior_block = _format_prior_outcomes_block(digests)

    # ----- Chat-transcript memory block (sibling of priors, same contract) ----
    # The chat_memory event stores source/thread/role ONLY — never snippet
    # text — so the rebuilt block renders the same structure with an explicit
    # placeholder where the excerpt was (mirrors the priors' honesty note).
    chat_block: str | None = None
    if "chat_memory" in by_kind:
        chat_items = by_kind["chat_memory"].get("items") or []
        chat_digests = [
            {
                "source": it.get("source"),
                "role": it.get("role"),
                "snippet": "(no transcript text stored in the event)",
            }
            for it in chat_items
            if isinstance(it, dict)
        ]
        if chat_digests:
            chat_block = _format_chat_memory_block(chat_digests)

    # ----- Compose, mirroring the orchestrator's order -----
    # Orchestrator: trim+serialize enriched → sanitize it → materialize evidence
    # → sanitize it → compose (candidate + priors ride the composed message) →
    # final sanitize sweep → residue gate. Here: same order minus the trim (see
    # docstring) and minus the residue gate (nothing egresses). focus_hint is
    # not persisted in events, so re-launched runs rebuild without it.
    enriched_json = enriched.model_dump_json()
    materialized = _materialize_prefetch_evidence(enriched)
    alert_id = inv.alert_es_id or inv.id
    original = build_synth_first_user_message(
        alert_id=alert_id,
        enriched_ctx_json=enriched_json,
        materialized_evidence=materialized,
        candidate=candidate,
        focus_hint=None,
        prior_outcomes_block=prior_block,
        chat_memory_block=chat_block,
    )

    guard = await EgressGuard.for_settings(settings, request.app.state.db_sessionmaker)
    sanitized = guard.sanitize_text(
        build_synth_first_user_message(
            alert_id=alert_id,
            enriched_ctx_json=guard.sanitize_text(enriched_json),
            materialized_evidence=guard.sanitize_obj(materialized),
            candidate=candidate,
            focus_hint=None,
            prior_outcomes_block=prior_block,
            chat_memory_block=chat_block,
        )
    )

    redaction_enabled = settings.analyst_cloud_redaction is True
    return AnalystRedactionPreviewOut(
        investigation_id=inv.id,
        redaction_enabled=redaction_enabled,
        fail_closed=settings.analyst_redaction_fail_closed is True,
        original=original,
        sanitized=sanitized,
        summary=guard.redaction_summary(),
        # Same occurrence filter as the Oracle preview: the guard's lifetime
        # mapping IS this one preview here, but only pairs whose label made it
        # into the final composed string get highlighted.
        replacements=[
            RedactionReplacementOut(label=r.label, value=r.value, category=r.category)
            for r in guard.redaction_replacements()
            if r.label in sanitized
        ],
        note=_analyst_preview_note(
            redaction_enabled=redaction_enabled,
            event_kinds=set(by_kind),
            prior_block_present=prior_block is not None,
            cited_dropped=cited_dropped,
        ),
    )


# ── Audit-grade decision record ("show your work") export ──────────────────────


def _decision_record(
    inv: Investigation, events: list[Any], *, signer: Any | None = None
) -> dict[str, Any]:
    """A self-contained record of how a verdict was reached.

    Bundles the verdict + rationale + the full agent trace (every tool call, every
    cited event) + provenance. Integrity: a sha256 checksum over the canonical JSON
    (accidental-corruption detection) AND — when a signing key is available — an
    Ed25519 detached SIGNATURE over the same bytes with the public key embedded, so
    an external auditor can prove the record was not altered using the public key
    alone. The "show your work" artifact for audit, compliance, and hand-off.
    """
    body: dict[str, Any] = {
        "schema": "soc-ai.decision-record/v1",
        "soc_ai_version": __version__,
        "investigation_id": inv.id,
        "alert_es_id": inv.alert_es_id,
        "rule_name": inv.rule_name,
        "verdict": inv.verdict,
        "confidence": inv.confidence,
        "rationale": inv.rationale,
        "summary": inv.summary,
        "flow": {"src": inv.src_ip, "dst": inv.dest_ip},
        "status": inv.status,
        "provenance": {
            "started_by": inv.started_by,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "finished_at": inv.finished_at.isoformat() if inv.finished_at else None,
        },
        # The full triage report: citations, recommended_actions, model metadata,
        # any validator notes and resolution/override provenance.
        "report": inv.report,
        # The agent trace, in order — the actual evidence the verdict rests on.
        "trace": [{"sequence": e.sequence, "kind": e.kind, "payload": e.payload} for e in events],
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    integrity: dict[str, Any] = {
        "algo": "sha256",
        "hash": digest,
        "note": (
            "sha256 checksum over the canonical JSON of this record with the "
            "'integrity' field removed — detects accidental corruption in "
            "transit/storage."
        ),
    }
    if signer is not None:
        # Detached Ed25519 signature over the SAME canonical bytes the checksum
        # covers. Verify: recompute the canonical JSON (integrity field removed),
        # then ed25519-verify(signature, canonical) against public_key. Tamper-
        # evident — a post-export edit cannot be re-signed without the private key.
        try:
            integrity["signature"] = {
                "algo": "ed25519",
                "value": signer.sign_hex(canonical.encode("utf-8")),
                "public_key": signer.public_key_hex(),
                "note": (
                    "detached Ed25519 signature over the canonical JSON (integrity "
                    "field removed); verify with the public_key — no server secret needed."
                ),
            }
        except Exception:  # pragma: no cover - signing must never break the export
            _LOGGER.warning("decision-record signing failed; exporting with checksum only")
    body["integrity"] = integrity
    return body


@router.get("/investigations/{inv_id}/export")
async def export_investigation(inv_id: str, request: Request) -> JSONResponse:
    """Download the audit-grade decision record for one investigation.

    JSON with a sha256 integrity checksum AND (when a signing key is present) an
    Ed25519 detached signature + public key — verifiable by an external auditor
    with the public key alone (see GET /decision-record/public-key).
    """
    async with request.app.state.db_sessionmaker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
    if got is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    inv, events = got
    signer = getattr(request.app.state, "decision_signer", None)
    record = _decision_record(inv, events, signer=signer)
    return JSONResponse(
        content=record,
        headers={"Content-Disposition": f'attachment; filename="soc-ai-{inv.id}.json"'},
    )


@router.get("/decision-record/public-key")
async def decision_record_public_key(request: Request) -> dict[str, Any]:
    """The Ed25519 public key that verifies decision-record export signatures.

    A verification key is meant to be published; it's also embedded in every
    export's integrity block, so an external auditor can verify from the exported
    file alone. Returns ``{"algo": "ed25519", "public_key": null}`` when signing is
    unavailable (exports then carry the checksum only).
    """
    signer = getattr(request.app.state, "decision_signer", None)
    return {
        "algo": "ed25519",
        "public_key": signer.public_key_hex() if signer is not None else None,
    }
