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
    # proactive context budgeting: oldest pivot events dropped to fit the
    # analyst model's input window (soc_ai.agent.context_budget)
    "context_trimmed",
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
    # flag-gated N-sample self-consistency vote on the final verdict
    # (verdict_consistency_samples > 1; a split lands verdict=inconclusive)
    "self_consistency_vote",
    # decision helpers
    "decision_template_match",
    "recommended_actions_blocked",
    # E4.2 deterministic investigation memory: prior-outcome digests injected
    # into the synth round-1 prompt (soc_ai/agent/orchestrator.py). Payload is
    # deliberately light — count/window plus per-item id/verdict/matched_on,
    # never rationale text. Emitted ONLY when a non-empty block was actually
    # injected; must be a valid audit kind or _audit silently drops it (same
    # trap the downgrade kinds hit above).
    "prior_outcomes",
    # Chat-transcript memory (sibling of prior_outcomes): past-chat snippet
    # digests injected into the synth round-1 prompt as CONTEXT ONLY (never
    # evidence — user statements in transcripts may be wrong). Payload is
    # deliberately light — count/window plus per-item source/thread_id/role,
    # never snippet text. Emitted ONLY when a non-empty block was actually
    # injected; must be a valid audit kind or _audit silently drops it.
    "chat_memory",
    # evidence-gate / anchor downgrades (emitted by the synth-first + legacy
    # post-validators). Without these the AuditEvent Literal rejected them and
    # _audit swallowed the ValidationError — so every such downgrade was silently
    # dropped from the audit trail (caught by the docs-vs-code accuracy gate).
    "evidence_gate_downgrade",
    "ungrounded_host_anchored_tp_downgrade",
    "malware_rule_name_ungrounded_downgrade",
    # retask
    "usage",
    "retask",
    "retask_skipped_no_closeable_gap",
    # oracle frontier adjudication
    "oracle_escalation",
    "oracle_adjudication",
    # model-fitness preflight probe (soc_ai/webui/probes.probe_model_fitness):
    # emitted by GET /config/model-fitness with the overall grade so an operator
    # switching analyst_model to an unfit model leaves an audit trail of the
    # warning that was surfaced. Read-only probe; never a mutating write.
    "model_fitness",
    # investigation-history → runbook-draft promotion (soc_ai/webui/
    # runbook_promotion.py, POST /runbooks/promote). Emitted best-effort when a
    # distillation lands a DRAFT runbook so "the machine wrote a runbook from N
    # investigations of rule X" is provable from the trail. Payload is
    # deliberately light — rule name + input counts + the new runbook id, never
    # the distilled content (it may carry internal identifiers, and the row
    # itself is already in the store). Must be a valid audit kind or _audit
    # silently drops it (the recurring trap documented on the downgrade kinds).
    "runbook_promotion",
    # nightly quality micro-eval regression (soc_ai/cli.py eval-nightly). Emitted
    # best-effort when the trend detector trips — payload carries the mode, the
    # detector's reason strings, and the snapshot metrics, so "quality degraded
    # on <date>" is provable from the audit trail even after the 90-row snapshot
    # prune. Must be a valid audit kind or the write is silently dropped (the
    # same trap the downgrade kinds document above).
    "quality_regression",
    # alert ownership / triage-state changes (soc_ai/api/webui/routes_alert_actions.py
    # POST /alerts/assign). Emitted best-effort on assign / state-change / unassign so a
    # multi-analyst team has a trail of who took (or released) a rule and moved it through
    # owned → in_review → done. A failed audit index must never break the assignment write.
    "assignment",
    # outbound notification webhook (soc_ai/notify.py::fire). Emitted best-effort on
    # EVERY attempted send (high-confidence TP, hunt threat finding, model-fitness
    # FAIL, or the canned Test event) so the ONLY new outbound egress path leaves an
    # audit trail. The webhook URL is a secret and NEVER appears in the payload —
    # only the format + outcome (ok/status/error). A failed audit index must never
    # break a send (fail-soft).
    "notification",
    # unattended high-confidence-FP acknowledge (maybe_auto_ack_fp). Emitted as a
    # StepEvent AND written to the audit trail; the WebUI reads it back
    # (webui_api ``e.kind == "auto_ack"``) to badge an alert as auto-acked, so it
    # MUST be a valid audit kind or every auto-ack fails to record and the badge
    # never shows.
    "auto_ack",
    # auto-ack ARMED for a confident FP but held back by a guard
    # (maybe_auto_ack_fp: high_stakes severity/exploit-class cap, or confidence
    # below the threshold). Recorded so the drawer can explain WHY the pending
    # ack needs a human (_build_actions ``e.kind == "auto_ack_skipped"`` →
    # pendingNote). No write happened; the payload carries reason + numbers.
    "auto_ack_skipped",
    # analyst-egress fail-closed residue sweep (soc_ai/agent/orchestrator.py::
    # _guard_egress). Emitted best-effort when analyst_redaction_fail_closed is on
    # and the INDEPENDENT unsafe_residue detector finds an internal identifier that
    # survived sanitization on a composed outbound message: the analyst model is
    # NOT called and the run lands a pipeline error. The payload carries only the
    # leaked-identifier COUNT + the call site — NEVER the leaked values (logging
    # them would defect on the whole point of the block). A failed audit index
    # must never turn a blocked-egress into an actual egress (fail-soft).
    "egress_blocked",
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
    # write-execution time. ``None`` on non-write events; the literal
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
