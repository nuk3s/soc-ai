"""Oracle redaction preview + signed decision-record export endpoints."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

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


class RedactionPreviewOut(BaseModel):
    original: dict[str, Any]
    sanitized: dict[str, Any]
    summary: dict[str, int]
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
    from soc_ai.oracle.sanitize import Mapping, redaction_summary, sanitize  # noqa: PLC0415

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
    return RedactionPreviewOut(
        original=sample,
        sanitized=sanitized,
        summary=redaction_summary(mapping),
        note=(
            "Internal identifiers are replaced with stable opaque labels (IP_01, "
            "HOST_01, …) before any Oracle call — the same real value always maps to "
            "the same label so the model's reasoning stays coherent. Public/external "
            "addresses pass through so the Oracle can reason about real infrastructure. "
            "Nothing is sent at all unless you enable the Oracle."
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
