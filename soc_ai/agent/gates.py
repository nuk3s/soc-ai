"""Deterministic verdict gates and downgrades — citation validation, evidence-grounding
checks, and the post-synthesis guard stack. No LLM calls; these are the trust layer.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Any, Literal

from soc_ai.agent.evidence import (
    _bundle_dump_text,
    _classify_citation,
    _path_exists_in_alert,
    _tool_was_invoked,
    count_successful_tool_calls,
)
from soc_ai.enrichment.blocklists import BlocklistDB

_LOGGER = logging.getLogger(__name__)


# Substantive-token regex for semantic citation resolution.
# A token is alphanumeric-led + 2+ chars of word/dot/slash/dash. Colons
# and `=` are NOT in the class so they split tokens — necessary for
# forms like ``community_id:1:abc=`` to yield separate tokens that each
# can be checked independently against the bundle JSON.
_FUZZY_TOKEN_RE = re.compile(r"[A-Za-z0-9][\w./\-]{2,}")

# GATE C: generic tokens that must never, on their own, resolve a citation
# semantically. A citation that "matches" the bundle only on one of these (or on
# a short generic substring) is hollow — it proves the model echoed a common word,
# not that it cited a specific piece of evidence. Distinctive values (JA3 hashes,
# IPs, domains, SPNs, file names) are long and/or unambiguous and still resolve.
_CITATION_STOP_WORDS: frozenset[str] = frozenset(
    {
        "rule",
        "name",
        "tag",
        "alert",
        "event",
        "true",
        "false",
        "the",
        "and",
        "for",
        "with",
        "dataset",
        "suricata",
        "zeek",
        "type",
        "field",
        "value",
        "source",
        "dest",
        "destination",
        "host",
        "port",
        "proto",
        "protocol",
        "src",
        "dst",
        "flow",
        "conn",
        "data",
        "info",
        "note",
        "metadata",
        "signature",
        "category",
        "severity",
        "message",
        "http",
        "dns",
        "null",
    }
)


def _semantic_token_resolves(source: str, bundle_text: str) -> bool:
    """True iff a DISTINCTIVE token of ``source`` appears in ``bundle_text``.

    GATE C: a citation may resolve semantically only on a DISTINCTIVE token —
    never a stop-word, and never a bare short generic substring. A token
    qualifies when it is either
      (a) long (>= 8 chars — JA3 hashes, sha256, full IPs, SPNs, ES ids):
          a substring match is enough, OR
      (b) medium (>= 5 chars — a domain label like "c2.xyz", a hyphenated
          host "evil-server", a short FQDN): it must match on WORD BOUNDARIES,
          not as a fragment of a longer word.
    Tokens carry dots/hyphens/slashes (``_FUZZY_TOKEN_RE``), so the (b) path must
    NOT require ``isalnum`` — that would drop every domain and dotted IP. This
    kills hollow <=4-char / generic-word "resolutions" while preserving
    resolution of specific values.
    """
    for tok in _FUZZY_TOKEN_RE.findall(source):
        low = tok.lower()
        if low in _CITATION_STOP_WORDS:
            continue
        if len(tok) >= 8 and low in bundle_text:
            return True
        if len(tok) >= 5 and re.search(rf"\b{re.escape(low)}\b", bundle_text):
            return True
    return False


def _resolve_citations(
    citations: list[str],
    alert_ctx: Any,
    transcripts: list[Any],
    *,
    messages: list[Any] | None = None,
) -> dict[str, Any]:
    """Semantic citation resolution — returns continuous coverage_ratio.

    Replaces the legacy `_validate_citations` shape-strict
    gatekeeper. The old logic classified each citation into
    path/tool/id/unknown and required path-strict walks against
    ``alert_ctx.model_dump()``. Some reasoning models emit citations as
    bare IPs, ``host.name=foo`` forms, free-text quotes, and other
    shapes that the strict classifier rejected wholesale — which then
    cascaded through the multiplicative confidence cap and the floor
    rewrite to erase valid verdicts. This was the
    dominant failure mode for those models.

    The new resolver tries (in order):

    1. **Strict path** — same dotted-path walk against alert_ctx.
    2. **Strict tool** — same ToolCallPart-history check.
    3. **Strict id** — same long-alphanumeric check (model-trusted).
    4. **Semantic substring** — any substantive token from the citation
       (≥3 chars of `[A-Za-z0-9][\\w./:\\-]+`) must appear (case-
       insensitive) in the bundle's JSON dump.

    Resolutions through (4) count as valid; the per_citation entry
    records `kind="semantic"` so audit can distinguish them. Empty
    citation lists return coverage_ratio=1.0 (vacuous truth — no
    missing evidence to penalize).

    Returns:
        ``{counts, total, invalid_examples, valid_citations,
        coverage_ratio, invalid_ratio, per_citation}``. ``invalid_ratio``
        is preserved (= 1.0 - coverage_ratio) for downstream-consumer
        backward compat. ``valid_citations`` retains ALL citations
        (resolved or not) so the published TriageReport doesn't lose
        the model's narrative — the cap reflects coverage instead.
    """
    counts = {"valid": 0, "strict": 0, "semantic": 0, "unresolved": 0}
    invalid_examples: list[str] = []
    per_citation: list[dict[str, Any]] = []

    bundle_text: str | None = None  # lazy

    for c in citations:
        kind, target = _classify_citation(c)
        resolved = False
        resolution_kind = "unresolved"

        if kind == "id":
            # F57: do NOT blind-trust an id-shaped citation. A fabricated id would
            # otherwise resolve to strict_id without ever touching the bundle,
            # inflating coverage_ratio (skipping the confidence cap and defeating
            # the verdict-floor's no-evidence check) — the exact pitfall
            # hunt_gates documents and avoids. Require the id to actually appear in
            # the bundle (same distinctive-token check as the semantic fallback):
            # a real ES id the model was shown is present; a hallucinated one isn't.
            if bundle_text is None:
                bundle_text = _bundle_dump_text(alert_ctx)
            if target and _semantic_token_resolves(target, bundle_text):
                resolved = True
                resolution_kind = "strict_id"
        elif kind == "path":
            if target and _path_exists_in_alert(alert_ctx, target):
                resolved = True
                resolution_kind = "strict_path"
        elif kind == "tool":
            if target and _tool_was_invoked(transcripts, target, messages=messages):
                resolved = True
                resolution_kind = "strict_tool"

        if not resolved:
            # Fall back to semantic resolution: any DISTINCTIVE token from the
            # citation appearing in the bundle dump counts (see
            # :func:`_semantic_token_resolves` for the stop-word / band rules).
            if bundle_text is None:
                bundle_text = _bundle_dump_text(alert_ctx)
            if _semantic_token_resolves(c, bundle_text):
                resolved = True
                resolution_kind = "semantic"

        if resolved:
            counts["valid"] += 1
            if resolution_kind == "semantic":
                counts["semantic"] += 1
            else:
                counts["strict"] += 1
        else:
            counts["unresolved"] += 1
            if len(invalid_examples) < 5:
                invalid_examples.append(c[:160])

        per_citation.append(
            {"citation": c, "kind": kind, "resolved": resolved, "resolution_kind": resolution_kind}
        )

    total = len(citations)
    coverage_ratio = counts["valid"] / total if total > 0 else 1.0
    invalid_ratio = 1.0 - coverage_ratio
    return {
        "counts": counts,
        "total": total,
        "invalid_examples": invalid_examples,
        # `valid_citations` retains the full list — we don't strip in v2.
        "valid_citations": list(citations),
        "coverage_ratio": coverage_ratio,
        "invalid_ratio": invalid_ratio,
        "per_citation": per_citation,
    }


# Backward-compat alias for any external callers / tests still using the
# old name. New code should use `_resolve_citations` directly.
_validate_citations = _resolve_citations

# The confidence a CONFIRMED escalation (true_positive grounded in a concrete IOC
# hit or a cited decisive pivot) is floored to — so a correct catch the model
# reported at 0.60-0.68 isn't scored as an under-confident near-miss.
_ESCALATION_CONF_FLOOR = 0.70


def _citation_confidence_cap(
    confidence: float,
    coverage_ratio: float | None = None,
    floor: float = 0.4,
    *,
    invalid_ratio: float | None = None,
) -> float:
    """Banded-penalty confidence cap based on citation coverage.

    Replaces the legacy multiplicative-to-zero scaling that erased
    valid verdicts when citation shape didn't match the strict
    classifier. New behavior: banded multipliers based on the
    semantic ``coverage_ratio`` from :func:`_resolve_citations`, with
    a hard ``floor`` so confidence never drops below 0.4 due to
    citation issues alone.

    Bands:

    - ``coverage_ratio >= 0.75`` → 1.0x (no penalty)
    - ``coverage_ratio >= 0.50`` → 0.9x
    - ``coverage_ratio >= 0.25`` → 0.75x
    - ``coverage_ratio  < 0.25`` → 0.5x

    The ``floor`` parameter (default 0.4) is the absolute lower bound
    on the capped confidence — the cap pipeline can shave confidence
    but cannot zero it out. The verdict floor (synthesis_confidence_
    floor, default 0.6) is a separate concept handled by the floor
    rewrite, which is now evidence-conditional.

    Backward compatibility: callers passing the legacy ``invalid_ratio``
    kwarg get auto-converted (coverage = 1 - invalid_ratio).
    """
    if coverage_ratio is None:
        coverage_ratio = 1.0 - invalid_ratio if invalid_ratio is not None else 1.0

    if coverage_ratio >= 0.75:
        multiplier = 1.0
    elif coverage_ratio >= 0.5:
        multiplier = 0.9
    elif coverage_ratio >= 0.25:
        multiplier = 0.75
    else:
        multiplier = 0.5

    capped = confidence * multiplier
    # Floor caps the REDUCTION, not the original. If the original
    # confidence is already below ``floor``, we don't promote it up to
    # ``floor`` — the floor's purpose is to prevent the cap from
    # erasing confidence, not to inflate genuine low-confidence
    # reports.
    effective_floor = min(floor, confidence)
    return max(capped, effective_floor)


def _no_semantic_evidence(report: Any, coverage_ratio: float) -> bool:
    """True when the report carries no semantic citation evidence.

    Either no citations at all, OR the citation coverage_ratio from
    `_resolve_citations` is below 0.25 (catastrophic unresolvable
    evidence). B3: shared by the synth-first AND legacy verdict-floor
    rewrites so both pipelines apply the same evidence-conditional gate —
    a well-evidenced verdict must survive low confidence on either path.
    """
    return len(report.citations) == 0 or coverage_ratio < 0.25


def _synth_first_post_validate(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext
    candidate: Any,  # CandidateVerdict | None — from decision_templates.match_decision_template
    *,
    targeted_messages: list[Any] | None = None,
    targeted_tool_called: str | None = None,
    synthesis_confidence_floor: float = 0.6,
    blocklist: BlocklistDB | None = None,
    internal_cidrs: Sequence[Any] | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Apply citation + floor validators to a synth-first TriageReport.

    Returns (validated_report, audit_dict). The audit_dict carries the
    intermediate validator results so the orchestrator can emit SSE events
    (citation_validation, citation_cap, verdict_floor_rewrite) in order.

    The validators applied:

    1. Citation validation — same ``_validate_citations`` as legacy, walking
       paths against ``enriched_ctx`` and IDs against the prefetch
       pivots. Tool refs only valid if matching the Phase-D targeted call
       (when one ran).
    2. Citation cap — same ``_citation_confidence_cap`` scaling by invalid_ratio.
    3. Verdict floor rewrite — if final confidence < synthesis_confidence_floor
       (0.6 default), set verdict=needs_more_info and clear recommended_actions.

    Coverage cap is NOT applied to synth-first runs because the orchestrator
    didn't run an investigator — there's no tool-call ledger to compute
    rubric coverage from. (The template-confidence ceiling that used to fill
    that role was removed — see the note in the body.)

    ``blocklist`` / ``internal_cidrs`` are forwarded to
    :func:`_apply_targeted_downgrades` (solicited-ICMP downgrade): the
    singleton BlocklistDB backs the explicit IOC lookup on contexts without
    enrichments, and ``internal_cidrs`` is the *effective* internal CIDR set
    (``settings.internal_cidrs`` union active ``cidr`` identifier rows minus muted,
    resolved once per investigation; falls back to ``settings.internal_cidrs``
    when there is no DB) so the internal-IP fallback aligns with the enriched
    path. Defaults (``None``) preserve the historical behavior for callers that
    don't thread the resolved set.
    """
    from soc_ai.agent.triage import InvestigationTranscript  # noqa: PLC0415

    audit: dict[str, Any] = {}

    # Citation resolution. No investigator transcripts exist
    # for synth-first; tool refs only valid for the Phase-D targeted call.
    synthetic_transcripts: list[Any] = []
    if targeted_tool_called is not None:
        synthetic_transcripts.append(
            InvestigationTranscript(
                evidence=[f"targeted dispatch: {targeted_tool_called}"],
                tentative_summary="",
                open_questions=[],
            )
        )
    citation_validation = _resolve_citations(
        report.citations, enriched_ctx, synthetic_transcripts, messages=targeted_messages
    )
    audit["citation_validation"] = citation_validation

    # Banded confidence cap. Always apply (cap is a no-op when coverage
    # is full); never zero-out. Preserves all citations — we don't
    # strip in v2; the cap reflects coverage instead.
    coverage_ratio = citation_validation["coverage_ratio"]
    original_conf = report.confidence
    new_conf = _citation_confidence_cap(original_conf, coverage_ratio=coverage_ratio)
    if new_conf != original_conf:
        report = report.model_copy(update={"confidence": new_conf})
        audit["citation_cap"] = {
            "original_confidence": original_conf,
            "capped_confidence": new_conf,
            "coverage_ratio": coverage_ratio,
            "invalid_ratio": 1.0 - coverage_ratio,  # legacy field
        }

    # Template-confidence ceiling REMOVED. The synthesizer
    # LLM reasons over the real alert + enrichments even on the fast path, so the
    # confidence it reports is its actual assessment — clamping it to the generic
    # template constant overrode real signal. Confidence stays the model's own,
    # still grounded by the citation cap above and the verdict floor below.

    # Evidence-conditional confidence FLOOR (recall-v2 calibration).
    # A settled true_positive grounded in a CONCRETE decisive signal — a
    # blocklist/MISP IOC hit, or a cited decisive pivot record (JA3 pair, RC4
    # Kerberos ticket, PE delivery, exfil asymmetry, completed SSH login, beacon/
    # tunnel profile) — is not a hedge case. The model routinely lands a correct
    # escalation at 0.60-0.68; that under-confidence then reads as a detection miss
    # (and can trip the verdict-floor rewrite below). Floor it to the escalation
    # confidence. Only RAISES, only for true_positive, only when real gathered
    # evidence is present — so it can never manufacture a false escalation
    # (precision is measured on benign scenarios, which are never true_positive).
    if (
        report.verdict == "true_positive"
        and report.confidence < _ESCALATION_CONF_FLOOR
        and (
            _has_ioc_hit(enriched_ctx) or _verdict_cites_decisive_pivot_value(report, enriched_ctx)
        )
    ):
        audit["confidence_floor_raise"] = {
            "original_confidence": report.confidence,
            "floored_confidence": _ESCALATION_CONF_FLOOR,
            "grounded_by": "ioc_hit" if _has_ioc_hit(enriched_ctx) else "decisive_pivot_value",
            "reason": (
                "true_positive grounded in a concrete IOC / decisive pivot — a "
                "confirmed catch, floored to escalation confidence rather than "
                "left as an under-confident hedge"
            ),
        }
        report = report.model_copy(update={"confidence": _ESCALATION_CONF_FLOOR})

    # Evidence-conditional verdict floor rewrite.
    # Coerce verdict to needs_more_info ONLY when:
    #   - confidence is strictly below floor, AND
    #   - there is no semantic evidence: either no citations at all, OR
    #     the citation coverage_ratio is below 0.25 (catastrophic
    #     unresolvable evidence).
    # Otherwise keep the verdict label — citation-shape brittleness in
    # the validator must not erase a verdict whose reasoning is sound.
    # Previously the floor rewrite fired on confidence alone, which under
    # some models' varied citation shapes turned valid verdicts into
    # `unknown`/`needs_more_info`.
    no_evidence = _no_semantic_evidence(report, coverage_ratio)
    # `inconclusive` (the self-consistency split outcome) is already a terminal
    # non-committed verdict — like needs_more_info, it is never rewritten here.
    if (
        report.confidence < synthesis_confidence_floor
        and report.verdict not in ("needs_more_info", "inconclusive")
        and no_evidence
    ):
        audit["verdict_floor_rewrite"] = {
            "original_verdict": report.verdict,
            "capped_verdict": "needs_more_info",
            "confidence": report.confidence,
            "floor": synthesis_confidence_floor,
            "coverage_ratio": coverage_ratio,
            "n_citations": len(report.citations),
            "reason": (
                "confidence below floor AND no semantic citation coverage; "
                "verdict label coerced to needs_more_info"
            ),
        }
        report = report.model_copy(
            update={
                "verdict": "needs_more_info",
                "recommended_actions": [],
            }
        )

    # ----- Targeted verdict downgrades -----
    # Shared with the since-deleted legacy pipeline's finalization (B2);
    # applies evidence-aware verdict overrides on the single surviving path.
    report = _apply_targeted_downgrades(
        report, enriched_ctx, audit, blocklist=blocklist, internal_cidrs=internal_cidrs
    )

    # ----- GATE A: malware-rule-name payload gate (#21) -----
    # "Content match is not corroboration." A true_positive on an alert whose
    # rule name / metadata SIGNALS a malware family (ET MALWARE, a named-tool
    # signature, a malware_family tag) must be grounded in a CONCRETE IOC hit OR
    # a cited decisive typed pivot VALUE (JA3/JA3S, file hash, Kerberos SPN, SMB
    # name, DCE-RPC endpoint) — never the rule label alone. Anchoring a TP on the
    # signature name is the BPFDoor false-escalation pattern (a benign gateway↔Mac
    # ping called TP because the rule said "BPFDoor"). When neither corroboration
    # is present, downgrade to needs_more_info so the alert is investigated rather
    # than rationalized from its own label.
    #
    # Runs AFTER _apply_targeted_downgrades so the deterministic solicited-internal
    # -ICMP-echo TP→FP downgrade is already applied and its verdict is no longer
    # true_positive here — that FP defense is preserved. The malware predicate is
    # evaluated defensively: if it can't be assessed for this context (e.g. a
    # partial/mock ctx that only backs model_dump), the gate fails OPEN and leaves
    # the verdict unchanged rather than manufacturing a downgrade.
    #
    # A TP that survived a REAL investigation — a successful tool call in the loop
    # transcript, or a Phase-D targeted dispatch — is corroborated beyond the rule
    # label and is exempt (mirrors the hard evidence gate). The gate targets the
    # zero-investigation "rule name says malware → TP" rationalization.
    has_tool_evidence = (
        count_successful_tool_calls(targeted_messages) >= 1 or targeted_tool_called is not None
    )
    if report.verdict == "true_positive" and not has_tool_evidence:
        try:
            from soc_ai.agent.decision_templates import (  # noqa: PLC0415
                _rule_signals_malware,
            )

            rule_is_malware = _rule_signals_malware(enriched_ctx)
        except Exception:
            rule_is_malware = False
        if (
            rule_is_malware
            and not _has_ioc_hit(enriched_ctx)
            and not _verdict_cites_decisive_pivot_value(report, enriched_ctx)
        ):
            audit["malware_rule_name_ungrounded_downgrade"] = {
                "original_verdict": report.verdict,
                "capped_verdict": "needs_more_info",
                "original_confidence": report.confidence,
                "reason": (
                    "true_positive on a malware-signalling rule name with no "
                    "concrete IOC hit and no cited decisive pivot value — the rule "
                    "label is not corroboration; coerced to needs_more_info for "
                    "investigation"
                ),
            }
            report = report.model_copy(
                update={
                    "verdict": "needs_more_info",
                    "confidence": min(report.confidence, 0.4),
                }
            )

    # ----- Ungrounded host-anchored TP downgrade -----
    # Catches the defect where the LLM escalates to TP solely because the
    # host_alert_profile lists malware/C2 rules (which may themselves be FPs)
    # and the external IP has no reputation — with zero per-alert evidence.
    report = _downgrade_ungrounded_host_anchored_tp(report, enriched_ctx, audit)

    # ----- Hard evidence gate (zero-tool-verdict defense) -----
    # FINAL backstop: a settled TP/FP that rests on prefetched fields with no
    # successful tool call and no strong rule-grounded template is a
    # rationalization, not a finding — coerce it to needs_more_info. Runs LAST so
    # the deterministic, prefetch-grounded downgrades above (the solicited-ICMP
    # FP) are already applied and exempt.
    report = _downgrade_unevidenced_verdict(
        report,
        enriched_ctx,
        candidate,
        audit,
        targeted_messages=targeted_messages,
        targeted_tool_called=targeted_tool_called,
    )

    return report, audit


# Module-level frozenset so it is built once rather than per call.
# Lowercase tokens — matched against lower-cased summary + citations.
# C2-vocabulary additions (M2): heartbeat, keep-alive, interval variants, timed.
_GROUNDED_EVIDENCE_TOKENS: frozenset[str] = frozenset(
    {
        "beacon",
        "payload",
        "lateral",
        "exfil",
        "c2 traffic",
        "c2 session",
        "command and control traffic",
        "pcap",
        "encoded",
        "periodic",
        "cadence",
        "mimikatz",
        "powershell",
        "meterpreter",
        "cobalt",
        # C2-vocabulary additions (M2) — reduce recall gap on timing-based C2
        "heartbeat",
        "keep-alive",
        "keepalive",
        "interval",
        "regular interval",
        "timed",
    }
)


def _downgrade_ungrounded_host_anchored_tp(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext | AlertContext
    audit: dict[str, Any],
) -> Any:
    """Downgrade a TP that rests solely on host_alert_profile + absence of reputation.

    Catches the systemic false-positive escalation pattern (BPFDoor / VPN ICMP,
    confirmed on both Qwen and DeepSeek) where the LLM escalates to
    true_positive because:
      (a) host_alert_profile lists a malware/C2 rule (which may itself be a FP), AND
      (b) the external IP has no reputation ("novel C2" inference from silence).

    Downgrade conditions — ALL must hold (conservative: when in doubt, leave TP):
      1. verdict is true_positive
      2. host_alert_profile is non-empty (the anchor exists)
      3. No per-alert malicious evidence:
         a. No blocklist_hits or misp_hits on ANY indicator in enrichments
         b. The focus alert's own signature is NOT a malware/exploit/attack class
            (checked via _alert_signals_malware + _ATTACK_CLASSTYPES) — if THIS
            alert is itself a confirmed-malware-class signature we leave the TP
         c. No concrete beacon/payload/lateral evidence cited in summary or
            citations (conservative keyword scan; false negative preferred over
            false positive here)

    When ALL conditions hold the verdict is downgraded to needs_more_info at
    confidence 0.5 with recommended_actions cleared and a corrective prefix on
    the summary.
    """
    if report.verdict != "true_positive":
        return report

    # Gate 2: host_alert_profile must be non-empty (the anchor).
    try:
        host_profile = getattr(enriched_ctx, "host_alert_profile", None) or {}
    except Exception:
        return report
    if not host_profile:
        return report

    # Gate 3a: any enrichment IOC hit → leave the TP.
    try:
        d = enriched_ctx.model_dump(mode="json")
    except Exception:
        return report
    enrichments = d.get("enrichments") or {}
    for e in enrichments.values():
        if isinstance(e, dict) and (e.get("blocklist_hits") or e.get("misp_hits")):
            return report  # has real IOC evidence — do not downgrade

    # Gate 3b: focus alert is itself a malware/exploit/attack-class signature
    # (i.e. the TP rests on THIS alert's own malware signal, not just context).
    try:
        from soc_ai.agent.decision_templates import (  # noqa: PLC0415
            _ATTACK_CLASSTYPES,
            _alert_signals_malware,
        )

        alert_obj = getattr(enriched_ctx, "alert", None)
        if alert_obj is not None:
            if _alert_signals_malware(alert_obj):
                return report  # this alert IS malware-class — leave the TP
            classtype = (getattr(alert_obj, "classtype", None) or "").lower()
            if classtype in _ATTACK_CLASSTYPES:
                return report  # attack-class classtype — leave the TP
    except Exception:
        return report  # import or attribute failure → conservatively leave TP

    # Gate 3c: conservative scan of summary + citations for concrete payload/
    # beacon/lateral evidence. If found, we leave the TP to protect recall.
    # Uses the module-level _GROUNDED_EVIDENCE_TOKENS frozenset (built once).
    summary_lower = (report.summary or "").lower()
    citations_text = " ".join(str(c) for c in (report.citations or [])).lower()
    combined = summary_lower + " " + citations_text
    for token in _GROUNDED_EVIDENCE_TOKENS:
        if token in combined:
            return report  # concrete evidence cited — leave the TP

    # All gates passed: downgrade to needs_more_info.
    original_summary = report.summary or ""
    downgrade_reason = (
        "TP rested solely on host_alert_profile context and/or absence of "
        "reputation (no per-alert IOC hit, focus alert is not malware-class, "
        "no beacon/payload/lateral evidence cited)"
    )
    audit["ungrounded_host_anchored_tp_downgrade"] = {
        "original_verdict": "true_positive",
        "downgraded_verdict": "needs_more_info",
        "reason": downgrade_reason,
        "original_summary": original_summary,
    }
    # Lead with the correct conclusion; the agent's original text and the
    # override reason move to validator_note. No confusing inline bracket.
    corrected_summary = (
        "Insufficient per-alert evidence to confirm this as a true positive. "
        "The verdict rested on the host's alert history and absence of "
        "reputation, not on direct evidence in this alert. "
        "Re-investigate to ground a verdict in per-alert evidence."
    )
    validator_note = (
        "Verdict auto-corrected true_positive→needs_more_info by the "
        "ungrounded-host-anchored-TP validator. "
        + downgrade_reason
        + " Original agent summary: "
        + original_summary
    )
    return report.model_copy(
        update={
            "verdict": "needs_more_info",
            "confidence": min(report.confidence, 0.5),
            "recommended_actions": [],
            "summary": corrected_summary,
            "validator_note": validator_note,
        }
    )


def _apply_targeted_downgrades(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext | AlertContext
    audit: dict[str, Any],
    *,
    blocklist: BlocklistDB | None = None,
    internal_cidrs: Sequence[Any] | None = None,
) -> Any:
    """Apply final verdict-level targeted downgrades; returns the report.

    B2: extracted from `_synth_first_post_validate` as a standalone helper
    (the since-deleted legacy pipeline shared it — it previously reproduced
    the BPFDoor false escalation unmitigated). Audit entries are written
    into ``audit`` under the same keys emitted as SSE events
    (``icmp_solicited_downgrade``).

    Solicited-ICMP-echo TP downgrade: a true_positive resting
    on a solicited internal ICMP echo reply (Zeek type-8 request → type-0
    reply, both RFC1918, no IOC hit) is a noisy-signature false escalation
    (e.g. the "ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat" FP cluster),
    not C2. Downgrade to false_positive. Scoped strictly to solicited ICMP
    echo so it cannot regress internal lateral-movement TPs (SMB/Kerberos),
    which are not ping exchanges.

    ``blocklist`` is the per-process singleton :class:`BlocklistDB` (the
    same one the enrich_* tools receive — ``ctx.blocklist``); it backs the
    EXPLICIT IOC lookup required on contexts that carry no enrichments
    (legacy ``AlertContext``). ``internal_cidrs`` is the *effective* internal
    CIDR set (``settings.internal_cidrs`` union active ``cidr`` identifier rows minus
    muted, resolved once per investigation; falls back to
    ``settings.internal_cidrs`` when there is no DB) so the no-enrichment
    internal fallback uses the operator's effective definition of "internal",
    matching the enriched path. The audit ``reason`` names the verification that
    actually ran on the path taken — enrichment-derived vs explicit lookup.
    """
    ioc_verification = (
        _is_solicited_internal_icmp_echo(
            enriched_ctx, blocklist=blocklist, internal_cidrs=internal_cidrs
        )
        if report.verdict == "true_positive"
        else None
    )
    if ioc_verification is not None:
        if ioc_verification == "explicit_blocklist_lookup":
            # Legacy/no-enrichment path: state ONLY what ran — an explicit
            # blocklist probe on both endpoints. No MISP/enrichment check
            # happened here, so the reason must not claim one.
            reason = (
                "solicited internal ICMP echo reply (ping response: Zeek "
                "type-8 request → type-0 reply, both internal; explicit "
                "blocklist lookup clean on both endpoints — no enrichment "
                "context on this path, MISP not consulted) — not a covert "
                "beacon; the malware rule label is an uncorroborated "
                "content match"
            )
        else:
            reason = (
                "solicited internal ICMP echo reply (ping response: Zeek "
                "type-8 request → type-0 reply, both internal, no blocklist/"
                "MISP hit) — not a covert beacon; the malware rule label is "
                "an uncorroborated content match"
            )
        original_summary = report.summary or ""
        audit["icmp_solicited_downgrade"] = {
            "original_verdict": "true_positive",
            "downgraded_verdict": "false_positive",
            "reason": reason,
            "original_summary": original_summary,
        }
        # Lead the summary with the correct conclusion; move the override
        # explanation and the agent's original text to validator_note so
        # nothing is lost, just relocated. This avoids the confusing pattern
        # of a "[Auto-corrected…]" bracket followed by the agent's wrong
        # narrative still narrating C2 under an FP verdict.
        corrected_summary = (
            "Solicited internal ICMP echo request/reply between two internal "
            "hosts — a benign ping exchange. The ET MALWARE signature matched "
            "on packet content only; there are no corroborating C2 indicators "
            "(no beacon cadence, blocklist/MISP hit, or payload evidence)."
        )
        validator_note = (
            "Verdict auto-corrected true_positive→false_positive by the "
            "solicited-ICMP-echo validator. "
            + reason
            + " Original agent summary: "
            + original_summary
        )
        report = report.model_copy(
            update={
                "verdict": "false_positive",
                "recommended_actions": [],
                "confidence": min(report.confidence, 0.8),
                "summary": corrected_summary,
                "validator_note": validator_note,
            }
        )

    return report


def _is_strong_grounded_template(candidate: Any, enriched_ctx: Any) -> bool:
    """True iff *candidate* is a STRONG, rule-grounded BENIGN template match that
    is safe to settle WITHOUT an investigation.

    A strong benign template (clean-internal / STUN-QUIC / NTP / DNSSEC / benign-
    cloud, confidence ≥ 0.8) is a deterministic verdict grounded in the rule +
    locality — not the model's reading of prefetch — so it is an acceptable
    evidence-substitute for the hard evidence gate. Explicitly excluded:
    EXTERNAL-reputation templates (which force investigation), and any
    malware/attack-class rule (a dangerous rule is never fast-settled benign).
    The 0.8 floor keeps the weaker TP templates (e.g. C2-classtype @ 0.65) out —
    those rules also signal malware/attack and are force-investigated anyway.

    NOTE: ``informational_external_clean_benign_cloud`` is confidence exactly 0.8
    and PASSES this threshold — its exclusion relies entirely on the
    ``EXTERNAL_REPUTATION_TEMPLATES`` guard below. Do not remove that guard
    without also tightening this threshold to ``> 0.8``.
    """
    if candidate is None:
        return False
    if getattr(candidate, "confidence", 0.0) < 0.8:
        return False
    from soc_ai.agent.decision_templates import (  # noqa: PLC0415 — avoid circular import
        EXTERNAL_REPUTATION_TEMPLATES,
        _rule_signals_attack,
        _rule_signals_malware,
    )

    if getattr(candidate, "template_id", None) in EXTERNAL_REPUTATION_TEMPLATES:
        return False
    return not (_rule_signals_malware(enriched_ctx) or _rule_signals_attack(enriched_ctx))


def _has_ioc_hit(enriched_ctx: Any) -> bool:
    """True iff any enrichment indicator carries a blocklist or MISP hit.

    A concrete IOC match is real evidence that GROUNDS a verdict — the
    enrichment layer matched a known-bad indicator, not the model reading alert
    metadata. So it exempts the hard evidence gate (same signal the
    ungrounded-host-anchored-TP downgrade uses to leave a TP alone).
    """
    try:
        d = enriched_ctx.model_dump(mode="json")
    except Exception:
        return False
    for e in (d.get("enrichments") or {}).values():
        if isinstance(e, dict) and (e.get("blocklist_hits") or e.get("misp_hits")):
            return True
    return False


# Pivot event attributes whose values are distinctive enough to prove a verdict was
# grounded in correlated evidence when cited (a JA3, a file hash, a Kerberos SPN, a
# service binary name, an RPC endpoint — not generic fields like a port or state).
_PIVOT_DECISIVE_ATTRS: tuple[str, ...] = (
    "zeek_ssl_ja3",
    "zeek_ssl_ja3s",
    "zeek_files_sha256",
    "zeek_files_md5",
    "zeek_kerberos_service",
    "zeek_kerberos_cipher",
    "zeek_smb_name",
    "zeek_dce_rpc_endpoint",
    "zeek_dce_rpc_operation",
)
_PIVOT_ATTRS: tuple[str, ...] = (
    "community_id_events",
    "host_events",
    "user_events",
    "process_events",
    "file_events",
)


def _pivot_evidence_tokens(enriched_ctx: Any) -> set[str]:
    """Distinctive lowercased tokens from prefetched PIVOT documents — their ES ids
    plus decisive typed values (JA3/JA3S, file hashes, Kerberos SPN, SMB file name,
    DCE-RPC endpoint). A verdict that cites one of these is grounded in correlated
    evidence the orchestrator gathered, not in the alert's own label."""
    tokens: set[str] = set()
    for attr in _PIVOT_ATTRS:
        for ev in getattr(enriched_ctx, attr, None) or []:
            eid = getattr(ev, "id", None)
            if eid:
                tokens.add(str(eid).lower())
            for f in _PIVOT_DECISIVE_ATTRS:
                v = getattr(ev, f, None)
                if isinstance(v, str) and len(v) >= 4:
                    tokens.add(v.lower())
    return tokens


def _verdict_grounded_in_pivot(report: Any, enriched_ctx: Any) -> bool:
    """True iff the settled verdict CITES correlated pivot evidence the orchestrator
    prefetched — a pivot doc's ES id, or one of its decisive typed values, appears in
    the report's citations.

    Prefetch pivots ARE gathered evidence: the orchestrator ran the community_id /
    host fan-out as a tool call on the agent's behalf, so a verdict grounded in a
    pivot record is not a zero-investigation rationalization. A verdict that cites
    only the alert's own fields matches nothing here and stays gated — the QVOD
    zero-tool-verdict defense is preserved. The value match is unforgeable: a cited
    JA3/hash/SPN can only match a pivot the model was actually shown."""
    tokens = _pivot_evidence_tokens(enriched_ctx)
    if not tokens:
        return False
    cited = " ".join(str(c) for c in (getattr(report, "citations", None) or [])).lower()
    if not cited:
        return False
    return any(tok in cited for tok in tokens)


def _verdict_cites_decisive_pivot_value(report: Any, enriched_ctx: Any) -> bool:
    """Stricter cousin of :func:`_verdict_grounded_in_pivot`: the verdict must cite a
    decisive typed pivot VALUE (a JA3/JA3S, a file hash, a Kerberos SPN, an SMB file
    name, a DCE-RPC endpoint) — NOT merely a pivot doc's ES id.

    The id-inclusive check is right for the anti-hallucination hard gate ("did the
    agent use gathered evidence?"), but for RAISING confidence a bare doc id is not
    enough — every alert has correlated pivots, so citing one proves nothing about
    maliciousness. Flooring confidence to the escalation level requires a concrete
    malicious-leaning signal the model actually cited."""
    values: set[str] = set()
    for attr in _PIVOT_ATTRS:
        for ev in getattr(enriched_ctx, attr, None) or []:
            for f in _PIVOT_DECISIVE_ATTRS:
                v = getattr(ev, f, None)
                if isinstance(v, str) and len(v) >= 4:
                    values.add(v.lower())
    if not values:
        return False
    cited = " ".join(str(c) for c in (getattr(report, "citations", None) or [])).lower()
    return bool(cited) and any(v in cited for v in values)


def _downgrade_unevidenced_verdict(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext
    candidate: Any,  # CandidateVerdict | None
    audit: dict[str, Any],
    *,
    targeted_messages: list[Any] | None,
    targeted_tool_called: str | None,
) -> Any:
    """HARD evidence gate — the zero-tool-verdict defense.

    A settled verdict (``true_positive`` / ``false_positive``) must rest on REAL
    evidence:

    * at least one SUCCESSFUL tool call from the investigation loop
      (``count_successful_tool_calls(targeted_messages) >= 1``), OR
    * a Phase-D targeted-tool dispatch (``targeted_tool_called is not None``), OR
    * a strong, rule-grounded benign template (:func:`_is_strong_grounded_template`).

    Otherwise the verdict is a rationalization of prefetched alert fields with no
    investigation behind it (the QVOD / zero-tool-TP defect) and is coerced to
    ``needs_more_info`` — the honest "not yet investigated" state — with
    confidence capped and recommended actions cleared. Records ``audit
    ['evidence_gate_downgrade']`` when it fires.

    Runs LAST in the validator chain so the deterministic, prefetch-grounded
    downgrades that PRODUCE a settled verdict (the solicited-ICMP-echo TP→FP) are
    already applied and exempt — that FP is grounded in typed Zeek, not a guess.
    """
    if report.verdict not in ("true_positive", "false_positive"):
        return report
    # Exempt a verdict that a deterministic, prefetch-grounded validator produced
    # (the solicited-ICMP-echo FP). The audit key is code-set, so it can't be
    # spoofed by the model populating a report field.
    if "icmp_solicited_downgrade" in audit:
        return report
    tool_calls = count_successful_tool_calls(targeted_messages)
    has_tool_evidence = tool_calls >= 1 or targeted_tool_called is not None
    # A strong template only grounds a verdict that AGREES with it — a synth that
    # OVERRODE a strong benign template (e.g. escalated a clean-internal alert to
    # TP) is not grounded by that template and must still be gated.
    strong_template = _is_strong_grounded_template(candidate, enriched_ctx) and (
        getattr(candidate, "verdict", None) == report.verdict
    )
    grounded_in_pivot = _verdict_grounded_in_pivot(report, enriched_ctx)
    # An IOC hit is evidence FOR escalation, never for CLEARING. It only grounds a
    # true_positive — a zero-tool false_positive that rationalized away a genuinely
    # known-bad indicator is NOT grounded by that hit and must still be gated.
    ioc_hit_grounds = report.verdict == "true_positive" and _has_ioc_hit(enriched_ctx)
    if (
        has_tool_evidence
        or strong_template
        or ioc_hit_grounds  # a concrete blocklist/MISP IOC grounds a TP only
        or grounded_in_pivot  # grounded in a cited, orchestrator-prefetched pivot record
    ):
        if grounded_in_pivot and not (has_tool_evidence or strong_template):
            audit["evidence_gate_pivot_exemption"] = {
                "reason": (
                    "verdict cites correlated pivot evidence the orchestrator "
                    "prefetched (community_id/host fan-out) — gathered evidence, "
                    "not a zero-investigation rationalization"
                ),
            }
        return report

    capped_conf = min(report.confidence, 0.4)
    audit["evidence_gate_downgrade"] = {
        "original_verdict": report.verdict,
        "capped_verdict": "needs_more_info",
        "original_confidence": report.confidence,
        "capped_confidence": capped_conf,
        "successful_tool_calls": tool_calls,
        "targeted_tool_called": targeted_tool_called,
        "reason": (
            "settled verdict with no investigation evidence — no successful tool "
            "call and no strong rule-grounded template; a prefetch-only "
            "rationalization, coerced to needs_more_info"
        ),
    }
    note = (
        " (Downgraded to needs_more_info by the evidence gate: this verdict rested "
        "on prefetched alert fields with no investigation — no tool was run to "
        "confirm it. Re-run to investigate.)"
    )
    return report.model_copy(
        update={
            "verdict": "needs_more_info",
            "confidence": capped_conf,
            "recommended_actions": [],
            "summary": (getattr(report, "summary", "") or "") + note,
        }
    )


def _is_solicited_internal_icmp_echo(
    enriched_ctx: Any,
    *,
    blocklist: BlocklistDB | None = None,
    internal_cidrs: Sequence[Any] | None = None,
) -> Literal["enrichment", "explicit_blocklist_lookup"] | None:
    """If the alert is a solicited ICMP echo exchange between two internal
    hosts with a verified-clean IOC posture, return WHICH
    verification ran; else ``None`` (no downgrade).

    Return values:
      - ``"enrichment"`` — the context carried per-indicator enrichments
        and none had ``blocklist_hits`` / ``misp_hits`` (synth-first path).
      - ``"explicit_blocklist_lookup"`` — the context carried NO
        enrichments (legacy ``AlertContext``), so both endpoint IPs were
        explicitly probed clean against ``blocklist`` (the same singleton
        :class:`BlocklistDB` the enrich_* tools use — covers the
        operator-curated ``internal_seed.yaml`` known-bad internal hosts).
      - ``None`` — any gate failed, including: blocklist unavailable
        (``None`` / zero loaded sources) or its lookup raising on the
        no-enrichment path. Absence of proof is not proof; wrongly
        suppressing a real TP is worse than letting a false escalation
        through.

    Reads the prefetch via ``model_dump`` (consistent with the citation
    resolver) so it works against both real EnrichedAlertContext objects
    and test doubles. Requires ALL of:
      - typed_zeek.icmp_echo_request_reply (Zeek saw type-8 → type-0), AND
      - both alert endpoints internal, AND
      - a clean IOC verification per the modes above.
    Conservative by construction: a missing zeek.conn pivot, an external
    endpoint, or any IOC hit all return ``None`` (we never suppress
    without positive benign evidence).

    B2: the legacy pipeline's prefetch is a plain ``AlertContext`` — typed
    Zeek fields are never materialized on it (only the synth-first
    ``EnrichedAlertContext`` carries them). When the dump has no
    ``typed_zeek`` block at all, derive it on the fly from the
    community_id pivot's Zeek conn records via the same
    ``parse_typed_zeek_fields`` the enriched prefetch uses, so both
    pipelines see the identical ICMP-echo signal.

    "Internal" for an IP WITHOUT an enrichment entry means membership in
    ``internal_cidrs`` (``settings.internal_cidrs``) when provided — the
    same definition ``enrich_ip`` uses — so a deployment with
    internal_cidrs narrower than RFC1918 gets identical semantics on both
    pipelines. The ipaddress ``is_private|is_loopback|is_link_local``
    fallback applies ONLY when ``internal_cidrs`` is empty/unset.
    """
    try:
        d = enriched_ctx.model_dump(mode="json")
    except Exception:
        return None
    typed_zeek = d.get("typed_zeek") or {}
    if not typed_zeek:
        from soc_ai.enrichment.zeek_parser import parse_typed_zeek_fields  # noqa: PLC0415

        try:
            pivots = getattr(enriched_ctx, "community_id_events", None) or []
            typed_zeek = parse_typed_zeek_fields(pivots).model_dump(mode="json")
        except Exception:
            return None
    if not typed_zeek.get("icmp_echo_request_reply"):
        return None
    alert = d.get("alert") or {}
    enrichments = d.get("enrichments") or {}

    def _internal(ip: str | None) -> bool:
        if not ip:
            return False
        e = enrichments.get(ip)
        if isinstance(e, dict) and "internal" in e:
            return bool(e["internal"])
        try:
            from ipaddress import ip_address  # noqa: PLC0415

            addr = ip_address(ip)
        except ValueError:
            return False
        if internal_cidrs:
            return any(addr in net for net in internal_cidrs)
        return bool(addr.is_private or addr.is_loopback or addr.is_link_local)

    src_ip = alert.get("source_ip")
    dst_ip = alert.get("destination_ip")
    if not (_internal(src_ip) and _internal(dst_ip)):
        return None
    if enrichments:
        for e in enrichments.values():
            if isinstance(e, dict) and (e.get("blocklist_hits") or e.get("misp_hits")):
                return None
        return "enrichment"
    # No enrichment entries (legacy AlertContext): the IOC loop above would
    # be vacuous, so demand EXPLICIT proof — both endpoints clean in the
    # same blocklist source the enrichment tools consult. Unavailable or
    # erroring blocklist → no downgrade (fail toward keeping the TP).
    if blocklist is None:
        _LOGGER.debug("icmp downgrade skipped: no blocklist available for explicit proof")
        return None
    try:
        if not blocklist.loaded_sources:
            _LOGGER.debug("icmp downgrade skipped: blocklist has zero loaded sources")
            return None
        if src_ip is None or dst_ip is None:
            _LOGGER.debug("icmp downgrade skipped: endpoint IP missing from alert")
            return None
        if blocklist.lookup_ip(src_ip) or blocklist.lookup_ip(dst_ip):
            return None
    except Exception:
        return None
    return "explicit_blocklist_lookup"
