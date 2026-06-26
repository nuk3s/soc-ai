"""Pydantic schemas for audit events.

Every LLM I/O and every tool invocation flows through one of these. The
``reasoning_trace`` field is intentionally a sibling of ``payload`` (not
nested in it) so a downstream consumer can easily separate "what the model
said" from "what the model thought" without parsing JSON deeper.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

AuditKind = Literal[
    "llm_request",
    "llm_response",
    "tool_call",
    "tool_result",
    "model_response",
    "approval_request",
    "approval_required",
    "approval_decision",
    "session_start",
    "session_end",
    "alert_context",
    "enriched_alert_context",
    "classification",
    "triage_report",
    "investigation_transcript",
    # Theme-1 investigation loop (synth-first pipeline)
    "investigation_loop_entered",
    "synth_round1_skipped",
    # citation validators (orchestrator synth-first path)
    "citation_validation",
    "citation_cap",
    "template_ceiling",
    "verdict_floor_rewrite",
    # coverage / rubric
    "coverage_cap",
    "rubric_derivation",
    # fast-path flow
    "fast_path_escalation",
    "fast_path_evidence_guard",
    "fast_path_verdict_cap",
    # icmp / targeted dispatch
    "icmp_solicited_downgrade",
    "targeted_dispatch",
    "targeted_tool_result",
    # decision helpers
    "decision_template_match",
    "recommended_actions_blocked",
    # retask
    "usage",
    "retask",
    "retask_skipped_no_closeable_gap",
    # oracle frontier adjudication
    "oracle_escalation",
    "oracle_adjudication",
    "done",
    "error",
]


class AuditEvent(BaseModel):
    """One event in the audit log.

    The trailing ``seq``/``prev_hash``/``hash`` fields form a tamper-evident
    hash chain (see :mod:`soc_ai.audit.logger`). They are ``None`` on a freshly
    constructed event and stamped by :meth:`AuditLogger.log` just before the ES
    write. They are intentionally *optional* so records written before the
    hash-chain feature shipped (and any externally constructed events) still
    parse.
    """

    session_id: str
    user: str = "unknown"
    # Structured approver identity for write-tool execution (ack/escalate/
    # comment). Resolved from the session/token via ``identify_caller`` at
    # approval-execution time. ``None`` on non-approval events; the literal
    # string ``"anonymous"`` when a write is executed with no authenticated
    # caller (dev / no-auth) — distinct from the generic ``"unknown"`` default
    # so an unattributed write is explicit, not a missing field.
    approved_by: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    kind: AuditKind
    payload: dict[str, Any] = Field(default_factory=dict)
    reasoning_trace: str | None = None
    model_alias: str | None = None
    reasoning_mode: str | None = None
    redacted: bool = False
    # --- Tamper-evident hash chain (stamped at log() time) -----------------
    seq: int | None = None
    prev_hash: str | None = None
    hash: str | None = None
