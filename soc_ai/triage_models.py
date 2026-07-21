"""Output schema for the agent's final triage report (neutral, shared types).

The agent's ``output_type=TriageReport`` constrains its final answer to
this shape - PydanticAI ensures the model emits valid JSON or retries.

Recommended actions are **suggestions only** in v1 - they map to write
tools (``ack_alert`` / ``escalate_to_case`` / ``add_case_comment``) but
never auto-execute. They surface in the report, and the analyst executes
them selectively through the actions API
(``POST /api/v1/investigations/{id}/actions/{index}/execute``).

These models live at the package root (below both ``soc_ai.agent`` and
``soc_ai.oracle``) so consumers like the Oracle client can import the report
types without pulling in the whole agent package — importing
``soc_ai.agent.triage`` executes ``soc_ai.agent.__init__`` and therefore the
orchestrator, which created an oracle↔agent import cycle.
``soc_ai.agent.triage`` re-exports everything here for compatibility.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

WriteToolName = Literal["ack_alert", "escalate_to_case", "add_case_comment"]
# ``inconclusive`` is a TERMINAL non-committed verdict produced ONLY by the
# orchestrator's flag-gated self-consistency vote (a split across N samples).
# The model must never emit it directly (the field description says so); it is
# in the Literal so voted reports validate/persist/read back like any verdict.
Verdict = Literal["true_positive", "false_positive", "needs_more_info", "inconclusive"]


def _decode_stringified_json(v: Any) -> Any:
    """Decode a JSON-encoded string into its container (dict/list), else pass through.

    Serving models recurrently emit nested container fields as JSON-encoded
    strings instead of objects/arrays: Nemotron-30B did it to
    ``InvestigationTranscript.rubric_coverage`` (Phase 2 smoke), and
    deepseek-v4-flash does it to ``TriageReport.gap_for_investigator`` (prod
    run 01KY0T3ZDPX5MXD1TYMPVDQ5ZH, 2026-07-20 — all 3 schema retries failed
    identically, so retry feedback does not recover it). The payload inside the
    string is well-formed; auto-parsing it is strictly more accepting. Strings
    that don't parse to a container fall through to Pydantic's normal error.
    """
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
        except (json.JSONDecodeError, TypeError, ValueError):
            return v
        if isinstance(parsed, (dict, list)):
            return parsed
    return v


class RecommendedAction(BaseModel):
    """One write-tool invocation the agent recommends for the analyst to execute."""

    tool_name: WriteToolName = Field(description="Which write tool the analyst should invoke.")
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments to pass to the tool. Must match the tool's signature.",
    )
    rationale: str = Field(description="One-line justification visible to the analyst.")

    _decode_tool_args = field_validator("tool_args", mode="before")(_decode_stringified_json)


class RubricCoverage(BaseModel):
    """Per-investigation coverage rubric.

    The investigator MUST emit this alongside its evidence so the
    synthesizer can confidence-cap when required coverage was missed.
    Each field is "did the investigator do this thing?" — not "is the
    finding positive?". An empty MISP enrichment with
    ``enrichment_called=True`` reflects a real check that turned up
    no signal; it does NOT count as positive evidence of benignness.
    """

    model_config = ConfigDict(extra="forbid")

    related_alerts_checked: bool = Field(
        default=False,
        description=(
            "True if the investigator queried for related alerts on the "
            "same host / community_id / user (typically via "
            "`t_query_events_oql` or relied on the prefetched pivots)."
        ),
    )
    playbook_consulted: bool = Field(
        default=False,
        description=(
            "True if a playbook was consulted (auto-prefetched, or the "
            "investigator called `t_get_playbooks`/`t_lookup_runbook`)."
        ),
    )
    enrichment_called: bool = Field(
        default=False,
        description=(
            "True if at least one `t_enrich_*` tool (IP / domain / hash) "
            "was invoked. Empty MISP results count as 'called' — they're "
            "absence of evidence, not positive findings."
        ),
    )
    dns_or_sni_pivoted: bool = Field(
        default=False,
        description=(
            "True if the agent looked at the domain context (DNS query or "
            "SSL SNI from `payload_printable` or the DNS/SSL name fields — "
            "`dns.query.name`/`ssl.server_name` on a modern grid, "
            "`zeek.dns.query`/`zeek.ssl.server_name` on older SO) for any "
            "external IOC referenced in the alert. False when the alert "
            "involves an external indicator and the agent didn't pivot on it."
        ),
    )
    payload_inspected_if_banner_rule: bool = Field(
        default=False,
        description=(
            "True if the rule is banner/content-class (matches packet "
            "bytes — most ET INFO/POLICY rules) AND the agent actually "
            "read `alert.payload_printable`. Set to True automatically "
            "when the rule isn't banner-class."
        ),
    )
    enrichment_skipped_reason: str | None = Field(
        default=None,
        description=(
            "Escape hatch. When the alert has an external IOC "
            "but `enrichment_called=False`, the investigator MUST set "
            "this to a short justification (e.g. 'MISP rate-limited', "
            "'indicator is a private DNS suffix, no provider would "
            "have it'). The orchestrator's coverage gate uses this to "
            "decide whether to retry the investigator turn — a non-empty "
            "reason satisfies the gate."
        ),
    )


class InvestigationTranscript(BaseModel):
    """Output of the investigator (fast model) phase.

    The investigator's job is to gather evidence with the read tools and hand
    a concise, structured summary to the synthesizer (heavy model). It does
    NOT decide a verdict or recommend write actions — those live in
    :class:`TriageReport`.
    """

    evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Bullet-point findings backed by tool results. Each item should be "
            "a single fact + the ES `_id` or SOC API id that supports it."
        ),
    )
    tentative_summary: str = Field(
        description=(
            "2-4 sentence neutral narrative of what happened, written for the "
            "synthesizer (NOT the analyst). No verdict; no recommendations."
        )
    )
    open_questions: list[str] = Field(
        default_factory=list,
        description=(
            "Specific gaps the investigator could not close (missing logs, "
            "unenriched indicators, ambiguous behavior). Used to retask the "
            "investigator if the synthesizer comes back low-confidence."
        ),
    )
    rubric_coverage: RubricCoverage = Field(
        default_factory=RubricCoverage,
        description=(
            "Coverage rubric. The synthesizer caps confidence "
            "at 0.6 when any required-for-class field is False. Be honest: "
            "marking a field True without doing the work hides the gap "
            "from the synthesizer's confidence calc."
        ),
    )

    # Accept a JSON string for `rubric_coverage` and auto-parse to object —
    # Phase 2 smoke against Nemotron-30B showed the model recurrently emits it
    # stringified (e.g. ``"rubric_coverage": "{\"enrichment_called\": true}"``).
    _decode_rubric = field_validator("rubric_coverage", mode="before")(_decode_stringified_json)


class TargetedGap(BaseModel):
    """Synth's request for ONE specific tool call to close ONE specific gap.

    Phase D of the synth-first redesign. When a synth round-1 emits a
    non-null gap, the orchestrator dispatches the 30B targeted-investigator
    with the exact tool call specified, then runs synth round 2 with the
    result appended.

    Hard cap: one Phase D call per investigation. The orchestrator enforces
    this by rejecting a non-null gap on synth round 2.
    """

    question: str = Field(
        ..., description="Human-readable: 'What was the SSL SNI for community_id X?'"
    )
    tool_name: Literal[
        "t_query_zeek_logs",
        "t_query_events_oql",
        "t_enrich_ip",
        "t_enrich_domain",
        "t_enrich_hash",
        "t_get_playbooks",
        "t_lookup_runbook",
        "t_query_cases",
        "t_query_detections",
        "t_get_rule_content",
        "t_get_event_raw",
        "t_decode_payload",
        "t_get_pcap",
        "t_web_search",
        "t_crawl_page",
    ] = Field(..., description="Which tool the targeted-investigator should call.")
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Exact args; the targeted-investigator runs them verbatim.",
    )
    why_this_matters: str = Field(..., description="One line: how the answer changes the verdict.")

    _decode_tool_args = field_validator("tool_args", mode="before")(_decode_stringified_json)


class TriageReport(BaseModel):
    """The agent's final structured triage output."""

    verdict: Verdict = Field(
        description=(
            "true_positive: confirmed malicious / suspicious; "
            "false_positive: benign / expected; "
            "needs_more_info: insufficient evidence to decide. "
            "(inconclusive is reserved for the orchestrator's self-consistency "
            "vote — NEVER emit it directly; use needs_more_info when unsure.)"
        )
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence in the verdict, 0.0-1.0. Below 0.6 means 'needs_more_info' "
            "rather than a guess."
        ),
    )
    summary: str = Field(
        description=(
            "Plain-English narrative summarizing what happened, in 3-6 sentences. "
            "Written for the on-call analyst."
        )
    )
    citations: list[str] = Field(
        default_factory=list,
        description=(
            "Specific event/case/detection IDs that support the conclusions. "
            "Each item is an ES _id or SOC API id."
        ),
    )
    recommended_actions: list[RecommendedAction] = Field(
        default_factory=list,
        description=(
            "Write-tool invocations recommended for the analyst to execute. "
            "DO NOT execute these automatically - each runs only on an "
            "explicit analyst action."
        ),
    )
    field_reconciliation: str | None = Field(
        default=None,
        description=(
            "Structured-output reconciliation field. When the alert has typed "
            "fields whose plain-English interpretation could appear to "
            "contradict each other — most commonly layered protocols where "
            "alert.proto != the conn transport (`network.transport`, or "
            "`zeek.conn.proto` on older SO) for the same community_id (ICMP "
            "T3/C4 PMTUD referring to a UDP flow), or alert.alert_action="
            "allowed but high severity_score — the synthesizer MUST emit a "
            "one-line reconciliation note here. Example: 'alert.proto=ICMP "
            "refers to the UDP flow at community_id X (PMTUD unreachable, "
            "not a TCP connection)'. Leave empty when no apparent "
            "contradictions exist."
        ),
    )
    gap_for_investigator: TargetedGap | None = Field(
        default=None,
        description=(
            "If non-null on synth round 1, the orchestrator dispatches the 30B "
            "targeted-investigator with these exact args and feeds the result "
            "back as a synth round 2. Hard cap: one Phase D call per "
            "investigation. Synth round 2 MUST emit gap_for_investigator=None."
        ),
    )
    validator_note: str | None = Field(
        default=None,
        description=(
            "Machine/analyst-facing note explaining any deterministic "
            "post-validator override. Set by the orchestrator when a "
            "post-validator corrects the verdict; the summary is then "
            "rewritten to lead with the correct conclusion. Contains the "
            "override reason and the original agent summary so nothing is "
            "lost, just relocated."
        ),
    )
    resolution: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Provenance marker for a report the pipeline did NOT reason its way "
            "to. Set ONLY on the synth-failure fallback path (model truncation, "
            "gateway 5xx, schema-validation exhaustion) to "
            "``{'provenance': 'pipeline_fallback', 'phase', 'error_type', "
            "'hint'}`` — so a failure-driven needs_more_info renders distinctly "
            "from a genuine one, is filterable, and is excluded from the "
            "Needs-info KPI. The verdict stays needs_more_info; only the "
            "rendering differs. Distinct from the manual/chat override "
            "``report['resolution']`` (which carries ``resolved_via``, added "
            "post-hoc by the resolve endpoint) — the two never conflate because "
            "``provenance`` and ``resolved_via`` are different keys."
        ),
    )

    _decode_containers = field_validator(
        "gap_for_investigator", "recommended_actions", "citations", mode="before"
    )(_decode_stringified_json)


# Sentinel written into ``TriageReport.resolution['provenance']`` (and, downstream,
# the persisted ``report['resolution']`` dict) by the synth-failure fallback path.
PIPELINE_FALLBACK_PROVENANCE = "pipeline_fallback"


def is_pipeline_fallback(report: dict[str, Any] | None) -> bool:
    """True iff a persisted report dict is a pipeline-failure fallback.

    A run is a "pipeline fallback" iff its report's ``resolution`` marker carries
    ``provenance == "pipeline_fallback"`` — set only by
    ``_synth_failure_fallback_report`` when the synth path raises (model
    truncation, gateway 5xx, schema-validation exhaustion). This is the single
    shared predicate every downstream consumer (timeline builder, investigation
    row, alerts badge, dashboard KPI) derives its boolean from, so the notion of
    "failure vs. genuine needs_more_info" lives in exactly one place.

    Defensive: a non-dict ``report`` / ``resolution`` (a manual override's
    ``resolution`` is always a dict, but old rows or a mangled column may not be)
    returns False rather than raising — a rendering predicate must never break a
    page.
    """
    if not isinstance(report, dict):
        return False
    resolution = report.get("resolution")
    if not isinstance(resolution, dict):
        return False
    return resolution.get("provenance") == PIPELINE_FALLBACK_PROVENANCE


__all__ = [
    "PIPELINE_FALLBACK_PROVENANCE",
    "InvestigationTranscript",
    "RecommendedAction",
    "RubricCoverage",
    "TargetedGap",
    "TriageReport",
    "Verdict",
    "WriteToolName",
    "is_pipeline_fallback",
]
