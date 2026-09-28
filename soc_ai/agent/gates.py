"""Deterministic verdict gates and downgrades — citation validation, evidence-grounding
checks, and the post-synthesis guard stack. No LLM calls; these are the trust layer.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from ipaddress import ip_address
from typing import Any, Literal

from soc_ai.agent.evidence import (
    _MAX_IDENTITY_WALK_DEPTH,
    _NON_EVIDENCE_RESULT_KEYS,
    _PIVOT_DECISIVE_ATTRS,
    _PIVOT_ID_SAFE_ATTRS,
    _RAISE_SAFE_EVIDENCE_KEYS,
    _bundle_dump_text,
    _classify_citation,
    _collect_evidence_values,
    _num,
    _path_exists_in_alert,
    _tool_was_invoked,
    count_successful_tool_calls,
)
from soc_ai.agent.narrative_grounding import _IPV4 as _ASSERTED_IPV4_RE
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


def _retrieved_evidence_tokens(alert_ctx: Any, messages: list[Any] | None) -> frozenset[str]:
    """Document ids + typed-evidence values this run actually RETRIEVED (lowercased).

    M2 (2026-08-25 audit): an id-shaped citation is a claim that specific
    retrieved EVIDENCE grounds the verdict, so it must resolve by membership in
    this set — never by substring-searching the dumped bundle text (which an
    attacker can seed through any plantable field: a DNS label, TLS SNI, URI,
    User-Agent). Sources, all structural:

    * the enriched alert's own ES id (``alert_ctx.alert.id``),
    * every prefetched pivot event's id (the orchestrator fetched those docs on
      the agent's behalf — same axes as :data:`_PIVOT_ATTRS`) and its id-safe
      typed values (:data:`_PIVOT_ID_SAFE_ATTRS` — the sensor-computed
      JA3/hash/cipher subset of the decisive pivot values; the wire-string
      leaves — SMB file name, requested SPN, DCE-RPC endpoint/operation — are
      attacker-chosen free-form strings on the attacker's own prefetched flow,
      so they ground a verdict (``_pivot_wire_string_cited``, only when cited as a
    distinctive value) but never resolve
      an id-shaped citation),
    * evidence-key leaves (:data:`soc_ai.agent.evidence._EVIDENCE_KEYS` —
      ``_id``/``uid``/``sid``/``uuid``, hash/JA3 leaves, detector rule
      metadata) inside the prefetch bundle's ``model_dump`` and inside the
      CONTENTS of real tool returns in the message history — documents the
      investigation loop / targeted dispatch genuinely pulled.

    The alert/pivot values are read from attributes AND from the ``model_dump``
    (consistent with the rest of the validator chain, which supports
    dump-backed contexts) — but only from those specific identity/typed SLOTS,
    never by scanning arbitrary dumped content, which is the forgeable surface
    this function exists to avoid.
    """
    ids: set[str] = set()
    alert_id = getattr(getattr(alert_ctx, "alert", None), "id", None)
    if isinstance(alert_id, str) and alert_id:
        ids.add(alert_id.lower())
    for attr in _PIVOT_ATTRS:
        for ev in getattr(alert_ctx, attr, None) or []:
            ev_id = getattr(ev, "id", None)
            if isinstance(ev_id, str) and ev_id:
                ids.add(ev_id.lower())
            for decisive in _PIVOT_ID_SAFE_ATTRS:
                value = getattr(ev, decisive, None)
                if isinstance(value, str) and value:
                    ids.add(value.lower())
    try:
        dump = alert_ctx.model_dump(mode="json")
    except Exception:
        dump = None
    if isinstance(dump, dict):
        alert_dump = dump.get("alert")
        if isinstance(alert_dump, dict):
            for key in ("id", "alert_id"):
                value = alert_dump.get(key)
                if isinstance(value, str) and value:
                    ids.add(value.lower())
        for attr in _PIVOT_ATTRS:
            evs = dump.get(attr)
            if isinstance(evs, list):
                for ev_dump in evs:
                    if isinstance(ev_dump, dict):
                        value = ev_dump.get("id")
                        if isinstance(value, str) and value:
                            ids.add(value.lower())
        # Evidence-key leaves anywhere in the bundle's real structure — the
        # typed pivot values and rule metadata a dump-backed context carries.
        # The walk harvests ONLY _EVIDENCE_KEYS leaves and never parses
        # embedded strings, so plantable content fields contribute nothing.
        _collect_evidence_values(dump, ids)
    for msg in messages or []:
        for part in getattr(msg, "parts", []) or []:
            if getattr(part, "part_kind", None) not in ("tool-return", "builtin-tool-return"):
                continue
            _collect_evidence_values(getattr(part, "content", None), ids)
    return frozenset(ids)


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
    3. **Strict id** — membership in :func:`_retrieved_evidence_tokens`:
       the citation must name EVIDENCE the run actually retrieved — a
       document id (the alert itself, a prefetched pivot, a doc inside a
       real tool return) or a decisive typed value harvested from an
       evidence-key leaf (a file hash, a JA3/JA3S, detector rule
       metadata). Id-shaped citations get NO semantic fallback — a
       substring match against dumped text is exactly the M2 forgery
       (an attacker plants an id-shaped token in a DNS label / SNI /
       URI and the gate credits it as a document).
    4. **Semantic substring** (non-id kinds only) — any substantive
       token from the citation (≥3 chars of `[A-Za-z0-9][\\w./:\\-]+`)
       must appear (case-insensitive) in the bundle's JSON dump.

    Resolutions through (4) count as valid; the per_citation entry
    records `kind="semantic"` so audit can distinguish them.

    An EMPTY citation list is reported as ``coverage_ratio=0.0`` with
    ``vacuous=True``. It used to be 1.0 on a vacuous-truth reading (nothing
    failed to resolve, so nothing is missing), which produced the audit line
    ``total: 0, valid: 0, coverage_ratio: 1.0`` on verdicts that had cited
    nothing at all. That reads as full coverage, and it satisfies any
    ``coverage_ratio >= threshold`` test a consumer writes: the same empty-list
    bypass the 2026-07-30 review found in the evidence gate, in a second place.
    A ratio over an empty set is undefined rather than one, so the number is
    reported as zero and the ``vacuous`` flag says why. Whether an uncited
    verdict may stand at all is the hard evidence gate's question; see
    :func:`_citation_confidence_cap` for why the cap does not answer it.

    Returns:
        ``{counts, total, invalid_examples, valid_citations,
        coverage_ratio, invalid_ratio, vacuous, per_citation}``.
        ``invalid_ratio`` is preserved (= 1.0 - coverage_ratio) for
        downstream-consumer backward compat. ``valid_citations`` retains ALL
        citations (resolved or not) so the published TriageReport doesn't lose
        the model's narrative — the cap reflects coverage instead.
    """
    counts = {"valid": 0, "strict": 0, "semantic": 0, "unresolved": 0}
    invalid_examples: list[str] = []
    per_citation: list[dict[str, Any]] = []

    bundle_text: str | None = None  # lazy
    retrieved_ids: frozenset[str] | None = None  # lazy

    for c in citations:
        kind, target = _classify_citation(c)
        resolved = False
        resolution_kind = "unresolved"

        if kind == "id":
            # F57 + M2: do NOT blind-trust an id-shaped citation, and do NOT
            # resolve it by substring against dumped text either. The substring
            # form was forgeable — a fabricated id planted in attacker-
            # controllable field content (a DNS query name, TLS SNI, URI, UA)
            # resolved as strict_id with full coverage, skipping the confidence
            # cap and defeating the verdict-floor's no-evidence check. An id
            # citation is a claim about RETRIEVED EVIDENCE, so it resolves only
            # by membership in the set of document ids and typed-evidence
            # values this run actually retrieved.
            if retrieved_ids is None:
                retrieved_ids = _retrieved_evidence_tokens(alert_ctx, messages)
            if target and target.lower() in retrieved_ids:
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

        if not resolved and kind != "id":
            # Fall back to semantic resolution: any DISTINCTIVE token from the
            # citation appearing in the bundle dump counts (see
            # :func:`_semantic_token_resolves` for the stop-word / band rules).
            # Id-shaped citations are EXCLUDED from this fallback (M2): letting
            # a failed id membership check fall through to a substring match
            # would re-open the exact forgery the strict branch closes.
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
    vacuous = total == 0
    coverage_ratio = counts["valid"] / total if total > 0 else 0.0
    invalid_ratio = 1.0 - coverage_ratio
    return {
        "counts": counts,
        "total": total,
        "invalid_examples": invalid_examples,
        # `valid_citations` retains the full list — we don't strip in v2.
        "valid_citations": list(citations),
        "coverage_ratio": coverage_ratio,
        "invalid_ratio": invalid_ratio,
        # True iff there were no citations to measure. Consumers that want
        # "did the report support itself?" must read this, not the ratio.
        "vacuous": vacuous,
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
    vacuous: bool = False,
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

    ``vacuous`` says there were no citations to measure, which
    :func:`_resolve_citations` reports alongside a coverage_ratio of 0.0. The
    cap is a NO-OP in that case, deliberately. This band answers "of what the
    report cited, how much resolved?", and a report that cited nothing has no
    answer rather than the worst one. Shaving it here would also be
    indiscriminate: on the production instance 41 of the 47 runs that DID call
    tools emitted no citations either, so the shave plus the verdict floor
    would have coerced most of the grid to needs_more_info without telling
    anyone anything. Whether an uncited verdict may stand is the hard evidence
    gate's question, and it asks it about retrieval rather than about wording.

    Backward compatibility: callers passing the legacy ``invalid_ratio``
    kwarg get auto-converted (coverage = 1 - invalid_ratio).
    """
    if vacuous:
        return confidence
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


def _apply_confidence_floor_raise(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext
    audit: dict[str, Any],
    *,
    targeted_messages: list[Any] | None,
    targeted_tool_results: Sequence[Any] | None,
) -> Any:
    """Floor an evidence-grounded true_positive to escalation confidence.

    The grounds and their doctrine live on the call site's comment block in
    :func:`_synth_first_post_validate` (checked strongest-first: ioc_hit,
    decisive_pivot_value, retrieved_decisive_value, retrieved_beacon_profile).
    Only RAISES, only for true_positive — a no-op otherwise.
    """
    if report.verdict != "true_positive" or report.confidence >= _ESCALATION_CONF_FLOOR:
        return report
    grounded_by: str | None = None
    beacon_detail: dict[str, Any] | None = None
    if _has_ioc_hit(enriched_ctx):
        grounded_by = "ioc_hit"
    elif _verdict_cites_decisive_pivot_value(report, enriched_ctx):
        grounded_by = "decisive_pivot_value"
    elif _verdict_cites_retrieved_decisive_value(
        report,
        enriched_ctx,
        targeted_messages=targeted_messages,
        targeted_tool_results=targeted_tool_results,
    ):
        grounded_by = "retrieved_decisive_value"
    else:
        beacon_detail = _retrieved_decisive_beacon_profile(
            enriched_ctx, targeted_messages, targeted_tool_results
        )
        if beacon_detail is not None:
            grounded_by = "retrieved_beacon_profile"
    if grounded_by is None:
        return report
    raise_entry: dict[str, Any] = {
        "original_confidence": report.confidence,
        "floored_confidence": _ESCALATION_CONF_FLOOR,
        "grounded_by": grounded_by,
        "reason": (
            "true_positive grounded in a concrete IOC / decisive "
            "retrieved value — a confirmed catch, floored to escalation "
            "confidence rather than left as an under-confident hedge"
        ),
    }
    if beacon_detail is not None:
        raise_entry["beacon_profile"] = beacon_detail
        raise_entry["reason"] = (
            "true_positive grounded in a retrieved beacon profile at "
            "the beacon tool's own periodic bar — a confirmed catch, "
            "floored to escalation confidence rather than left as an "
            "under-confident hedge"
        )
    audit["confidence_floor_raise"] = raise_entry
    return report.model_copy(update={"confidence": _ESCALATION_CONF_FLOOR})


def _adopt_template_grounds(
    report: Any,  # TriageReport
    candidate: Any,  # CandidateVerdict | None
    audit: dict[str, Any],
) -> Any:
    """Lend a DISPOSITIVE template's own grounds to a report that cited nothing.

    The synthesizer emits no citations on most runs: 41 of the 47 production
    runs that DID call tools emitted none either, so an empty citation list says
    nothing about whether the case was investigated. That leaves a
    template-settled alert closing with an empty "why", which the analyst reads
    in the drawer and the hard evidence gate reads as a report with nothing on
    the record.

    A dispositive template's ``cited_evidence`` is the honest answer to that: it
    is code-set, it names fields of the alert the run actually retrieved, and it
    is exactly what the verdict rests on. Adopted only when the report cited
    NOTHING (never overwriting the model's own citations) and only when the
    report AGREES with the template, so a synthesizer that escalated past a
    benign template cannot inherit its grounds.

    Provisional templates lend nothing. Their grounds are the thing in dispute:
    letting ``clean_internal_traffic`` write "both endpoints internal" into a
    citation list would launder locality into evidence.
    """
    if candidate is None:
        return report
    if getattr(candidate, "authority", "provisional") != "dispositive":
        return report
    if report.verdict not in ("true_positive", "false_positive"):
        return report
    if getattr(candidate, "verdict", None) != report.verdict:
        return report
    if report.citations:
        return report
    grounds = list(getattr(candidate, "cited_evidence", None) or [])
    if not grounds:
        return report
    audit["template_grounds_adopted"] = {
        "template_id": getattr(candidate, "template_id", None),
        "citations": grounds,
        "reason": (
            "the report settled on a dispositive template and cited nothing, so "
            "the template's own grounds are recorded as the citations"
        ),
    }
    return report.model_copy(update={"citations": grounds})


def _carry_investigator_evidence(
    report: Any,  # TriageReport
    investigator_evidence: Sequence[str] | None,
    messages: list[Any] | None,
    audit: dict[str, Any],
) -> Any:
    """Carry the investigator's own evidence bullets into a report that cited nothing.

    The investigator gathers evidence with the read tools and hands the
    synthesizer a transcript of it. The synthesizer writes the verdict, and its
    citation list comes out empty on a third of runs even though the transcript
    it was written from listed eight or nine grounded bullets. Measured on the
    deployed instance: 1,187 of the 3,379 runs that produced both a transcript
    and a report dropped between six and thirteen evidence strings on the way
    (median eight), and 713 of those reports were then acknowledged in Security
    Onion as verdicts resting on nothing. The evidence was never missing. The
    handoff lost it.

    This is a CARRY, not a manufacture, and the difference is load-bearing:

    * it only fires when the report cited NOTHING, so the model's own citations
      are never overwritten or padded;
    * every bullet is handed to :func:`_resolve_citations` unfiltered, so an
      unresolvable one lowers coverage exactly as a fabricated citation would.
      Nothing is dropped to flatter the number;
    * it requires the loop's real message history. Without it
      :func:`~soc_ai.agent.evidence._tool_was_invoked` falls back to a substring
      match against the transcript's own evidence text, and a ``(tool X)``
      bullet carried out of that same transcript would resolve itself. That is
      a citation gate grading its own homework, and it is the one way this
      change could have made things worse than the bug.

    Measured against 400 of the affected production runs, the carried bullets
    resolve at a mean coverage of 0.996 — 3,075 strict resolutions against 15
    that fail — so the grounds were real and structurally checkable all along.
    """
    if report.citations:
        return report
    if messages is None:
        return report
    bullets = [str(e).strip() for e in (investigator_evidence or []) if str(e).strip()]
    if not bullets:
        return report
    audit["investigator_evidence_carried"] = {
        "count": len(bullets),
        "citations": bullets,
        "reason": (
            "the report cited nothing and the investigation loop's own transcript "
            "carried evidence, so the evidence is recorded as the citations"
        ),
    }
    return report.model_copy(update={"citations": bullets})


def _synth_first_post_validate(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext
    candidate: Any,  # CandidateVerdict | None — from decision_templates.match_decision_template
    *,
    investigator_evidence: Sequence[str] | None = None,
    targeted_messages: list[Any] | None = None,
    targeted_tool_called: str | None = None,
    targeted_tool_results: Sequence[Any] | None = None,
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

    ``targeted_tool_results`` carries the raw Phase-D dispatch result(s) —
    the targeted path threads no message history, so without them a verdict
    resting on a value the DISPATCH retrieved would read as unsupported to
    the decisive-value support gate.

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

    # Both run BEFORE the resolver, so the coverage measured below is measured
    # over the grounds the verdict actually rests on.
    #
    # The investigator's own evidence goes first and a template's canned grounds
    # second. Ordering matters only where both are available — a dispositive
    # template that matched AND a loop that ran — and there the run's own
    # retrieval is the better answer to "what is this verdict resting on" than
    # two code-set sentences about the alert's shape.
    report = _carry_investigator_evidence(report, investigator_evidence, targeted_messages, audit)
    report = _adopt_template_grounds(report, candidate, audit)

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
    citations_vacuous = bool(citation_validation["vacuous"])
    original_conf = report.confidence
    new_conf = _citation_confidence_cap(
        original_conf, coverage_ratio=coverage_ratio, vacuous=citations_vacuous
    )
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
    #
    # Four grounds, checked strongest-first:
    #   * ioc_hit — the enrichment layer matched a known-bad indicator;
    #   * decisive_pivot_value — the CITATIONS name a decisive typed value from
    #     a prefetched pivot (the legacy path, unchanged);
    #   * retrieved_decisive_value — the verdict asserts (summary or citations)
    #     a raise-safe decisive value the run genuinely RETRIEVED, including
    #     through its own tool calls. Before this path, evidence the
    #     investigator found for itself was invisible here: a correct TP
    #     resting on a beacon/kerberos document its own OQL pulled stayed at
    #     0.6x and scored as a recall miss (2026-08-26 batch, m1/h1);
    #   * retrieved_beacon_profile — the run retrieved a beacon profile at or
    #     below the beacon tool's own "periodic" bar with a healthy event
    #     count. A beacon profile is a decisive RECORD with no citable string
    #     value (m1's shape: cited by ES id, described statistically), so the
    #     value-assertion grounds above can never see it — see the block
    #     comment on :func:`_retrieved_decisive_beacon_profile`.
    report = _apply_confidence_floor_raise(
        report,
        enriched_ctx,
        audit,
        targeted_messages=targeted_messages,
        targeted_tool_results=targeted_tool_results,
    )

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

    # ----- No-benign-baseline gate (decoy first, then every flagged spec) -----
    report = _refuse_benign_verdict_without_baseline(report, enriched_ctx, audit)

    # ----- Ungrounded host-anchored TP downgrade -----
    # Catches the defect where the LLM escalates to TP solely because the
    # host_alert_profile lists malware/C2 rules (which may themselves be FPs)
    # and the external IP has no reputation — with zero per-alert evidence.
    report = _downgrade_ungrounded_host_anchored_tp(report, enriched_ctx, audit)

    # ----- Decisive-value support gate (H1's deferred half) -----
    # The gates above check evidence was GATHERED; this one checks the gathered
    # evidence CONTAINS the decisive value the verdict asserts. It is what
    # stops the H1 shape — one successful tool call carrying an attacker-
    # dictated TP whose "known-bad IP" appears in nothing the run retrieved.
    # Runs after the deterministic downgrades (whose corrected verdicts it must
    # not touch) and before the hard evidence gate (which exempts tool-evidenced
    # verdicts — exactly the H1 gap this gate closes).
    report = _enforce_decisive_value_support(
        report,
        enriched_ctx,
        audit,
        targeted_messages=targeted_messages,
        targeted_tool_results=targeted_tool_results,
    )

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
        resolved_citations=int(citation_validation["counts"]["valid"]),
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


_DECOY_REFUSAL_NOTE = (
    "A decoy has no benign population, so nothing about how often this source "
    "talks to this destination can clear the interaction. Answer instead what "
    "the decoy's own log recorded, whether the source was authorised to reach a "
    "host that is in no DNS zone and serves no workload, and what drove the "
    "source at that moment."
)


def _refuse_benign_decoy_verdict(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext | AlertContext
    audit: dict[str, Any],
) -> Any:
    """Refuse to close a decoy interaction benign.

    Measured defect. An OpenCanary decoy logged an inbound SSH interaction and
    triage returned false_positive at 0.9 because "over the prior 72h the router
    made 358 SSH connections to internal hosts (111 to one host)". Checked
    against the grid, 348 of the 358 documents were periodic flow records, the
    106 naming the decoy carried 19 distinct source ports in two hourly buckets
    across three days, and the decoy's own log — the authoritative record of
    what touched it — held two documents from that source, ever, both of them
    this interaction.

    The number being wrong is a separate fix (``t_query_events_oql`` now reports
    what it counted). This gate is about the route. The catalog spec for this
    detection says nothing has a legitimate reason to talk to a decoy, so unlike
    every other detection there is no benign population to separate from and
    therefore no threshold, no baseline and no tuning. A volume baseline reasons
    in the opposite direction, and "the router talks to this host a lot, so a
    decoy hit from the router is routine" auto-closes an intruder pivoting
    through the router — which is the case the decoy exists to catch. Reaching a
    defensible answer by a route that also produces the wrong answer is not
    triage.

    So the refusal is on the verdict class, not on the prose. Pattern-matching
    the summary for baseline language would pass the next run that phrases it
    differently, and a second measured run did exactly that: it named the decoy,
    cited the absence of a credential attempt, and still called it routine
    east-west traffic. What is unsafe here is closure itself, whatever argument
    carries it.

    The gate refuses closure only. A ``true_positive`` passes untouched, and so
    does anything already unsettled. The spec's own false-positive list — an
    authorised scanner, the operator's own validation — is explicit that both
    are still worth seeing, so ``needs_more_info`` is the right landing place
    for them rather than an automatic close.

    Fails OPEN on a context it cannot read: a gate that raises takes the
    investigation with it.
    """
    if report.verdict != "false_positive":
        return report
    try:
        from soc_ai.agent.decision_templates import _alert_signals_decoy  # noqa: PLC0415

        alert = getattr(enriched_ctx, "alert", None)
        if alert is None or not _alert_signals_decoy(alert):
            return report
    except Exception:
        return report

    audit["decoy_benign_verdict_refused"] = {
        "original_verdict": report.verdict,
        "capped_verdict": "needs_more_info",
        "original_confidence": report.confidence,
        "reason": (
            "false_positive on a decoy interaction. A decoy has no benign "
            "population to separate from, so no baseline, threshold or volume "
            "argument can clear one; coerced to needs_more_info"
        ),
    }
    note = (
        f"{report.validator_note}\n{_DECOY_REFUSAL_NOTE}"
        if report.validator_note
        else _DECOY_REFUSAL_NOTE
    )
    return report.model_copy(
        update={
            "verdict": "needs_more_info",
            "confidence": min(report.confidence, 0.4),
            "recommended_actions": [],
            "validator_note": note,
        }
    )


def _refuse_benign_verdict_without_baseline(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext | AlertContext
    audit: dict[str, Any],
) -> Any:
    """Refuse to close benign any detection the catalog says has no baseline.

    The decoy gate above hard-codes one case of a general property: some
    detections have no benign population, so a baseline, a threshold or a
    volume argument runs backwards on them. DCSync by a non-machine account
    and an account without Kerberos pre-authentication share it, and until
    this gate nothing on the triage path could know that — the catalog held
    the doctrine and triage never read the catalog. Measured on the range: the
    same real DCSync alert closed false_positive 0.62 one day and escalated
    true_positive 0.75 the next, both runs grounded, the answer depending on
    which way the model leaned that run.

    The decoy gate runs first and unchanged, so its audit key and note are
    exactly what its own tests assert. Then the alert's raw document is put to
    every flagged spec through the same evaluator the coverage gate uses (see
    :mod:`soc_ai.agent.doctrine`), so "does this alert fall under that spec"
    has one answer in the codebase.

    Same shape as the decoy gate in every respect that matters: refusal is on
    the verdict class, not the prose; only closure is refused, a true_positive
    or an unsettled verdict passes untouched; and it fails OPEN on anything it
    cannot read. The note hands the reader the spec's own false-positive list,
    because those are exceptions by identity — the sync appliance's account,
    the one legacy account — and only a human can confirm one.
    """
    report = _refuse_benign_decoy_verdict(report, enriched_ctx, audit)
    if report.verdict != "false_positive":
        return report
    try:
        from soc_ai.agent.doctrine import spec_declaring_no_baseline_for  # noqa: PLC0415

        alert = getattr(enriched_ctx, "alert", None)
        spec = spec_declaring_no_baseline_for(getattr(alert, "raw", None))
    except Exception:
        return report
    if spec is None:
        return report

    exceptions = "; ".join(" ".join(fp.split()) for fp in spec.false_positives) or "none listed"
    note = (
        f"{spec.title}: the catalog spec {spec.id} declares this detection has no benign "
        "population, so no baseline, threshold or volume argument can clear it. Answer "
        f"instead whether the principal is one of the spec's own exceptions ({exceptions}), "
        "and what drove it at that moment."
    )
    audit["no_baseline_verdict_refused"] = {
        "spec_id": spec.id,
        "spec_title": spec.title,
        "spec_level": spec.level,
        "original_verdict": report.verdict,
        "capped_verdict": "needs_more_info",
        "original_confidence": report.confidence,
        "reason": (
            f"false_positive on a detection {spec.id} declares has no benign population; "
            "coerced to needs_more_info"
        ),
    }
    return report.model_copy(
        update={
            "verdict": "needs_more_info",
            "confidence": min(report.confidence, 0.4),
            "recommended_actions": [],
            "validator_note": f"{report.validator_note}\n{note}" if report.validator_note else note,
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
        from soc_ai.agent.classifier import normalize_classtype  # noqa: PLC0415
        from soc_ai.agent.decision_templates import (  # noqa: PLC0415
            _ATTACK_CLASSTYPES,
            _alert_signals_malware,
        )

        alert_obj = getattr(enriched_ctx, "alert", None)
        if alert_obj is not None:
            if _alert_signals_malware(alert_obj):
                return report  # this alert IS malware-class — leave the TP
            # Through the normalizer, not a bare .lower(): the field carries
            # Suricata EVE's classification DESCRIPTION and the set holds
            # shortnames, so the raw comparison this call site used could never
            # match anything a sensor writes. It failed in the direction that
            # costs recall: the exemption never fired, so attack-class true
            # positives were downgraded to needs-more-info.
            if normalize_classtype(getattr(alert_obj, "classtype", None)) in _ATTACK_CLASSTYPES:
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
    """True iff *candidate* is a DISPOSITIVE benign template match that is safe
    to settle WITHOUT an investigation.

    A dispositive benign template (STUN-QUIC / NTP / DNSSEC) reads what the RULE
    DETECTED: the signature names a protocol whose ordinary operation is the
    whole content of the alert. That is a deterministic verdict, not the model's
    reading of prefetch, so it is an acceptable evidence substitute for the hard
    evidence gate.

    A PROVISIONAL template is not, however sure it sounds. This test used to be
    "confidence >= 0.8 and not an external-reputation template", which
    ``clean_internal_traffic`` passed at 0.85 on the sole ground that both
    endpoints were private. Measured on the production instance over nine days:
    13 alerts settled false_positive at 0.85 to 0.90 with zero tool calls, nine
    of them the same ET HUNTING OGNL exploitation-attempt signature, and every
    one auto-acknowledged in Security Onion. Blocklists never name an RFC1918
    address, so that template's other ground was vacuous too.

    Kept on top of the authority test as defence in depth: the 0.8 confidence
    floor, the EXTERNAL-reputation exclusion, and the malware/attack-class rule
    exclusion (a dangerous rule is never fast-settled benign).
    """
    if candidate is None:
        return False
    if getattr(candidate, "authority", "provisional") != "dispositive":
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
# Defined in soc_ai.agent.evidence (imported above), where the id-citation
# resolvers' evidence-key set enumerates its hash/fingerprint/enum SUBSET
# (_PIVOT_ID_SAFE_ATTRS) — the wire-string leaves ground a verdict here but
# never resolve an id-shaped citation.
_PIVOT_ATTRS: tuple[str, ...] = (
    "community_id_events",
    "host_events",
    "user_events",
    "process_events",
    "file_events",
    # A hunt subject's cited documents (D2). Empty on every alert run. They are
    # gathered evidence like the pivots, so a citation of one resolves here.
    "subject_documents",
)


# The decisive pivot leaves that are attacker-composed free-form wire strings
# (SMB file name, requested Kerberos SPN, DCE-RPC endpoint/operation) rather than
# sensor-computed digests/fingerprints or a fixed-vocabulary enum.
_PIVOT_WIRE_STRING_ATTRS: frozenset[str] = frozenset(_PIVOT_DECISIVE_ATTRS) - frozenset(
    _PIVOT_ID_SAFE_ATTRS
)


def _pivot_evidence_tokens(enriched_ctx: Any) -> set[str]:
    """Lowercased tokens from prefetched PIVOT documents that a plain substring
    match may credit: their ES ids plus the id-safe decisive values (JA3/JA3S,
    file hashes, Kerberos cipher). A verdict that cites one of these is grounded in
    correlated evidence the orchestrator gathered, not in the alert's own label.

    The wire-string leaves (SMB file name, SPN, DCE-RPC endpoint/operation) are
    deliberately NOT here — see :func:`_pivot_wire_string_cited`."""
    tokens: set[str] = set()
    for attr in _PIVOT_ATTRS:
        for ev in getattr(enriched_ctx, attr, None) or []:
            eid = getattr(ev, "id", None)
            if eid:
                tokens.add(str(eid).lower())
            for f in _PIVOT_ID_SAFE_ATTRS:
                v = getattr(ev, f, None)
                if isinstance(v, str) and len(v) >= 4:
                    tokens.add(v.lower())
    return tokens


def _pivot_wire_string_cited(enriched_ctx: Any, cited: str) -> bool:
    """True iff a DISTINCTIVE wire-string pivot value appears in ``cited``
    (lowercased citation text).

    The four wire-string leaves are composed by whoever sent the flow, and the
    alert's own flow is what the community-id prefetch normalizes into the pivot
    bundle — so a plain ``len >= 4`` substring match would let a file named
    ``name`` or ``alert`` turn a bare ``alert.rule_name`` citation into
    "grounded in a pivot" and switch the zero-tool-verdict defense off. These
    values therefore take the GATE C distinctiveness bands of
    :func:`_semantic_token_resolves`: never a stop-word, a substring match only
    from 8 chars (a service binary path, an SPN), and a whole-word match from 5
    chars (an RPC endpoint like ``svcctl`` / ``lsarpc``). A planted value that
    equals a whole citation phrase (an SMB file literally named
    ``alert.rule_name``) still matches; that residual is a long, specific string
    the model had to echo verbatim, not a generic fragment."""
    for attr in _PIVOT_ATTRS:
        for ev in getattr(enriched_ctx, attr, None) or []:
            for f in _PIVOT_WIRE_STRING_ATTRS:
                v = getattr(ev, f, None)
                if not isinstance(v, str):
                    continue
                low = v.lower()
                if low in _CITATION_STOP_WORDS:
                    continue
                if len(low) >= 8 and low in cited:
                    return True
                if len(low) >= 5 and re.search(rf"\b{re.escape(low)}\b", cited):
                    return True
    return False


def _verdict_grounded_in_pivot(report: Any, enriched_ctx: Any) -> bool:
    """True iff the settled verdict CITES correlated pivot evidence the orchestrator
    prefetched — a pivot doc's ES id, or one of its decisive typed values, appears in
    the report's citations.

    Prefetch pivots ARE gathered evidence: the orchestrator ran the community_id /
    host fan-out as a tool call on the agent's behalf, so a verdict grounded in a
    pivot record is not a zero-investigation rationalization. A verdict that cites
    only the alert's own fields matches nothing here and stays gated — the QVOD
    zero-tool-verdict defense is preserved. A cited doc id / JA3 / hash can only
    match a pivot the model was actually shown; the attacker-composed wire-string
    leaves count only when cited as a distinctive value
    (:func:`_pivot_wire_string_cited`), so a short generic file name planted on the
    alert's own flow cannot ground an alert-only citation."""
    cited = " ".join(str(c) for c in (getattr(report, "citations", None) or [])).lower()
    if not cited:
        return False
    tokens = _pivot_evidence_tokens(enriched_ctx)
    if any(tok in cited for tok in tokens):
        return True
    return _pivot_wire_string_cited(enriched_ctx, cited)


def _verdict_cites_decisive_pivot_value(report: Any, enriched_ctx: Any) -> bool:
    """Stricter cousin of :func:`_verdict_grounded_in_pivot`: the verdict must cite a
    decisive typed pivot VALUE (a JA3/JA3S, a file hash, a Kerberos SPN, an SMB file
    name, a DCE-RPC endpoint) — NOT merely a pivot doc's ES id.

    The id-inclusive check is right for the anti-hallucination hard gate ("did the
    agent use gathered evidence?"), but for RAISING confidence a bare doc id is not
    enough — every alert has correlated pivots, so citing one proves nothing about
    maliciousness. Flooring confidence to the escalation level requires a concrete
    malicious-leaning signal the model actually cited. The wire-string leaves are
    banded exactly as in :func:`_verdict_grounded_in_pivot`, so the two cannot
    drift apart."""
    cited = " ".join(str(c) for c in (getattr(report, "citations", None) or [])).lower()
    if not cited:
        return False
    values: set[str] = set()
    for attr in _PIVOT_ATTRS:
        for ev in getattr(enriched_ctx, attr, None) or []:
            for f in _PIVOT_ID_SAFE_ATTRS:
                v = getattr(ev, f, None)
                if isinstance(v, str) and len(v) >= 4:
                    values.add(v.lower())
    if any(v in cited for v in values):
        return True
    return _pivot_wire_string_cited(enriched_ctx, cited)


def _retrieved_decisive_value_tokens(
    enriched_ctx: Any,
    messages: list[Any] | None,
    targeted_tool_results: Sequence[Any] | None,
) -> frozenset[str]:
    """Raise-safe decisive values this run actually RETRIEVED (lowercased).

    The floor-raise's credit set. Sources — the same retrieval surfaces as
    :func:`_retrieved_evidence_tokens` (prefetch bundle, tool-return message
    contents, Phase-D dispatch results) — but harvesting ONLY the
    :data:`_RAISE_SAFE_EVIDENCE_KEYS` leaves: sensor-computed digests and
    fingerprints plus fixed-vocabulary cipher enums. Never document ids (a
    doc id proves retrieval, not maliciousness — bare-id citing must not
    raise confidence) and never detector rule metadata (rule-label
    anchoring).

    THE PROPERTY THIS GUARANTEES: every credited value was harvested by
    STRUCTURAL key membership from the real shape of a retrieved payload —
    dicts/lists only, embedded strings never parsed, tool payloads
    echo-filtered (:func:`_evidence_payload`) so a tool echoing the model's
    own argument launders nothing. An attacker who composes free-form wire
    content (a DNS label, TLS SNI, URI, User-Agent, SMB file name, Kerberos
    SPN, DCE-RPC string) can plant tokens only in content leaves, which are
    never harvested; the only values they can influence in the credited
    slots are true digests/fingerprints of their own observed activity.
    Planting a token can therefore never mint raise-earning evidence — the
    same M2 boundary id-citation resolution defends, applied to the side
    that RAISES.
    """
    values: set[str] = set()
    for attr in _PIVOT_ATTRS:
        for ev in getattr(enriched_ctx, attr, None) or []:
            for f in _PIVOT_ID_SAFE_ATTRS:
                v = getattr(ev, f, None)
                if isinstance(v, str) and v:
                    values.add(v.lower())
    try:
        dump = enriched_ctx.model_dump(mode="json")
    except Exception:
        dump = None
    if isinstance(dump, dict):
        _collect_evidence_values(dump, values, keys=_RAISE_SAFE_EVIDENCE_KEYS)
    for msg in messages or []:
        for part in getattr(msg, "parts", []) or []:
            if getattr(part, "part_kind", None) not in ("tool-return", "builtin-tool-return"):
                continue
            payload = _evidence_payload(getattr(part, "content", None))
            if payload is not None:
                _collect_evidence_values(payload, values, keys=_RAISE_SAFE_EVIDENCE_KEYS)
    for result in targeted_tool_results or []:
        payload = _evidence_payload(result)
        if payload is not None:
            _collect_evidence_values(payload, values, keys=_RAISE_SAFE_EVIDENCE_KEYS)
    # Same distinctiveness floor as the prefetch path (`len(v) >= 4`): a
    # 1-3 char fragment could collide with prose by accident.
    return frozenset(v for v in values if len(v) >= 4)


def _verdict_cites_retrieved_decisive_value(
    report: Any,
    enriched_ctx: Any,
    *,
    targeted_messages: list[Any] | None,
    targeted_tool_results: Sequence[Any] | None,
) -> bool:
    """True iff the verdict asserts a raise-safe decisive value the run
    genuinely retrieved — through the prefetch bundle OR its own tool calls.

    The retrieved-evidence cousin of :func:`_verdict_cites_decisive_pivot_value`,
    closing that check's blind spot: it only reads prefetch pivot attrs, so a
    correct TP resting on a decisive value the investigation loop found for
    itself (the m1/h1 shape, 2026-08-26 batch) earned no floor-raise. The
    assertion surface is summary + citations — the same surface
    :func:`_asserted_decisive_values` scans — because models routinely cite
    documents by id and name the decisive value in prose.

    Direction of trust, and why this is safe to widen: the CREDIT side is
    locked down (:func:`_retrieved_decisive_value_tokens` — structural,
    unforgeable value classes only); the assertion side is model-authored
    text either way. A match means "the model asserts a sensor-computed /
    fixed-vocabulary value that a retrieved document really carries" — which
    is exactly the grounding the raise exists to reward.
    """
    text_parts = [str(getattr(report, "summary", "") or "")]
    text_parts.extend(str(c) for c in (getattr(report, "citations", None) or []))
    asserted = " ".join(text_parts).lower()
    if not asserted.strip():
        return False
    values = _retrieved_decisive_value_tokens(
        enriched_ctx, targeted_messages, targeted_tool_results
    )
    return any(v in asserted for v in values)


# ----- Beacon-profile ground for the confidence floor-raise -----
# m1-cobalt-strike-beacon's shape (2026-08-26 batch): the report cites the
# decisive records — the beacon aggregate and the TLS row — by ES id and
# describes the beacon STATISTICALLY ("~60s interval, low jitter"). There is no
# decisive string value to assert, because a beacon profile is a decisive
# RECORD whose evidence is its measured statistics, not any citable token. The
# value-assertion grounds above can therefore never see it, and crediting the
# cited doc ids instead is forbidden (bare-id doctrine,
# tests/test_recall_fix.py::test_confidence_floor_raise_requires_decisive_value_not_bare_id).
# This ground credits the PROFILE itself: when the run genuinely RETRIEVED a
# beacon profile whose measured cadence clears the beacon tool's OWN
# "periodic" bar (analytics._CV_PERIODIC) with at least its default min_events
# sample floor, the profile is decisive evidence for a C2-beacon
# true_positive — regardless of whether the model quoted a string.
#
# Raise-side safety (the M2 boundary, reasoned for this ground specifically):
#   * The statistics are computed by the sensor / by our own analytics tool
#     over OBSERVED connection timestamps — structural numeric leaves in a
#     retrieved payload. Embedded strings are never parsed, so a token planted
#     in free-form wire content can never become a profile dict.
#   * An attacker does control their own beacon's cadence — they could beacon
#     regularly on purpose. That manufactures confidence only in the verdict
#     that THEIR OWN traffic is malicious C2: making your C2 more detectable
#     is self-defeating, not an attack. Framing an innocent third party is
#     not reachable this way: producing a periodic profile attributed to host
#     V requires completing real connections FROM V (spoofed sources cannot
#     finish the TCP/TLS handshakes the zeek conn/ssl rows record), i.e.
#     compromising V — at which point the true_positive is correct.
#   * The profile must concern THIS alert's flow: when the payload names
#     endpoints (src/dst, source.ip/destination.ip), one must match the
#     alert's own — a different pair's beacon elsewhere on the grid grounds
#     nothing about this alert.
#   * As with every ground here, the raise only lifts an ALREADY-committed
#     true_positive to the escalation floor; it can never create one. Benign
#     regular cadences (b1's deliberately MORE regular updater profile) are
#     decided at the verdict, not here — and b1's own profile (6 connections)
#     falls below the tool's min_events bar regardless.

# Key leaves a retrieved beacon-profile dict rides under: the SoAlert typed
# attr (prefetch pivots), the raw-document spellings normalized by
# so_client.fields.BEACON_PROFILE (`rita.beacon`, `network.beacon_profile`,
# the eval fixture's `synth.beacon_profile`). `beacon.profile` (leaf
# `profile`) is deliberately not keyed — far too generic; that spelling still
# reaches the gate via the typed prefetch attr.
_BEACON_PROFILE_KEYS: frozenset[str] = frozenset(
    {"beacon_profile", "zeek_beacon_profile", "beacon"}
)
# Leaves that name a flow endpoint on a profile or its carrier document:
# t_beacon_profile items (`src`/`dst`), typed pivot dumps
# (`source_ip`/`destination_ip`), raw ES docs (`source.ip` → leaf `ip`).
_ENDPOINT_LEAF_KEYS: frozenset[str] = frozenset({"src", "dst", "ip", "source_ip", "destination_ip"})


def _beacon_profile_stats(profile: dict[str, Any]) -> tuple[float, float] | None:
    """(inter-arrival cv, event count) a retrieved beacon profile measured.

    Tolerates the two real shapes: a ``t_beacon_profile`` candidate item
    (``cv``/``events``/``mean_interval_s``) and a RITA-style summary document
    (``interval_stddev_seconds`` / ``mean_interval_seconds`` /
    ``connection_count``; alternate spellings per evidence._num). Returns None
    when the profile does not carry enough to measure a cadence — an
    unmeasurable profile grounds nothing.
    """
    cv = _num(profile, "cv")
    if cv is None:
        mean = _num(profile, "mean_interval_seconds", "interval_mean_seconds", "mean_interval_s")
        stdev = _num(profile, "interval_stddev_seconds", "stdev_s")
        if mean is None or mean <= 0 or stdev is None:
            return None
        cv = stdev / mean
    events = _num(profile, "events", "connection_count", "total_connections")
    if events is None:
        return None
    return cv, events


def _beacon_tool_item_shape(d: dict[str, Any]) -> bool:
    """A ``t_beacon_profile`` candidate item, recognized by the tool's own
    output contract: numeric ``cv`` + ``events`` + ``mean_interval_s``
    co-occurring (soc_ai.tools.analytics.beacon_profile's documented item
    shape; no other payload in the toolset carries that triple)."""

    def _numeric(v: Any) -> bool:
        return isinstance(v, (int, float)) and not isinstance(v, bool)

    return all(_numeric(d.get(k)) for k in ("cv", "events", "mean_interval_s"))


def _collect_beacon_profiles(
    node: Any,
    out: list[tuple[dict[str, Any], dict[str, Any]]],
    depth: int = 0,
) -> None:
    """Collect ``(profile, carrier)`` pairs from real retrieved STRUCTURE.

    The same walk discipline as :func:`_collect_evidence_values`: dicts/lists
    only, depth-bounded, embedded strings never parsed. ``carrier`` is the
    dict the profile was found on (the pivot dump / ES ``_source`` / the tool
    item itself) — the surface that names the flow's endpoints.
    """
    if depth > _MAX_IDENTITY_WALK_DEPTH:
        return
    if isinstance(node, dict):
        if _beacon_tool_item_shape(node):
            out.append((node, node))
        for key, value in node.items():
            leaf = key.rsplit(".", 1)[-1] if isinstance(key, str) else ""
            if leaf in _BEACON_PROFILE_KEYS and isinstance(value, dict):
                out.append((value, node))
            _collect_beacon_profiles(value, out, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _collect_beacon_profiles(item, out, depth + 1)


def _carrier_endpoints(profile: dict[str, Any], carrier: dict[str, Any]) -> set[str]:
    """Endpoint IP strings the profile's payload names (lowercased)."""
    found: set[str] = set()
    for d in (profile, carrier):
        for key, value in d.items():
            leaf = key.rsplit(".", 1)[-1] if isinstance(key, str) else ""
            if leaf in _ENDPOINT_LEAF_KEYS and isinstance(value, str) and value:
                found.add(value.lower())
            elif leaf in ("source", "destination") and isinstance(value, dict):
                ip = value.get("ip")
                if isinstance(ip, str) and ip:
                    found.add(ip.lower())
    return found


def _retrieved_decisive_beacon_profile(
    enriched_ctx: Any,
    messages: list[Any] | None,
    targeted_tool_results: Sequence[Any] | None,
) -> dict[str, Any] | None:
    """Audit detail of a decisive beacon profile this run RETRIEVED, or None.

    Retrieval surfaces are exactly the floor-raise's existing ones
    (:func:`_retrieved_decisive_value_tokens`): the prefetch bundle dump,
    tool-return message contents, and Phase-D targeted dispatch results —
    tool payloads echo-filtered through :func:`_evidence_payload`. "Decisive"
    is the beacon tool's own bar, imported from soc_ai.tools.analytics rather
    than re-invented: inter-arrival ``cv <= _CV_PERIODIC`` (the threshold
    behind its "periodic" verdict_hint) AND event count >= its default
    ``min_events`` floor. A marginal profile — semi-regular cadence
    (``_CV_PERIODIC < cv <= _CV_MAX``) or too few samples — is not decisive.
    """
    from soc_ai.tools.analytics import (  # noqa: PLC0415 — keep the tools stack off gate import
        _CV_PERIODIC,
        _MIN_EVENTS_DEFAULT,
    )

    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    try:
        dump = enriched_ctx.model_dump(mode="json")
    except Exception:
        dump = None
    if isinstance(dump, dict):
        _collect_beacon_profiles(dump, candidates)
    for msg in messages or []:
        for part in getattr(msg, "parts", []) or []:
            if getattr(part, "part_kind", None) not in ("tool-return", "builtin-tool-return"):
                continue
            payload = _evidence_payload(getattr(part, "content", None))
            if payload is not None:
                _collect_beacon_profiles(payload, candidates)
    for result in targeted_tool_results or []:
        payload = _evidence_payload(result)
        if payload is not None:
            _collect_beacon_profiles(payload, candidates)

    alert = getattr(enriched_ctx, "alert", None)
    alert_endpoints = {
        str(ip).lower()
        for ip in (getattr(alert, "source_ip", None), getattr(alert, "destination_ip", None))
        if ip
    }
    for profile, carrier in candidates:
        stats = _beacon_profile_stats(profile)
        if stats is None:
            continue
        cv, events = stats
        if cv > _CV_PERIODIC or events < _MIN_EVENTS_DEFAULT:
            continue  # marginal: semi-regular cadence, or too few samples
        if not (_carrier_endpoints(profile, carrier) & alert_endpoints):
            continue  # someone else's flow, or no endpoint correlation at all
        return {
            "cv": cv,
            "events": int(events),
            "cv_periodic_max": _CV_PERIODIC,
            "min_events": _MIN_EVENTS_DEFAULT,
        }
    return None


# ----- Decisive-value support gate (H1, 2026-08-25 audit — the deferred half) -----
# The trust gates checked that evidence was GATHERED, never that it SUPPORTS the
# verdict: one successful tool call let an attacker-dictated true_positive @0.95
# persist verbatim, escalate action and all. This gate asks the deterministic
# half of "does the conclusion follow?": a decisive indicator VALUE the verdict
# asserts must appear in a document the run actually RETRIEVED. No model call —
# LLM-checking-LLM is the wrong instrument for a trust gate (declined once
# already, deliberately).

# Digest-shaped tokens: MD5/JA3 (32), SHA-1 (40), SHA-256 (64) hex. Longest
# alternative first; \b keeps a 64-hex token from yielding a 32-hex fragment
# (hex chars are word chars, so an interior boundary never exists). The 32-hex
# arm is narrative_grounding._JA3 verbatim.
_ASSERTED_HASH_RE = re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")


def _asserted_decisive_values(report: Any) -> frozenset[str]:
    """The concrete indicator VALUES a verdict asserts (lowercased).

    Scans the report's summary + citations — the assertion surface — for the
    two shapes that are unambiguously a decisive indicator and never a
    formatting voice:

    * a **globally-routable unicast IPv4** ("beaconing to a known-bad IP").
      Private/loopback/link-local/documentation/multicast addresses are
      scenery, not the decisive indicator — the alert's own internal source IP
      must never let a fabricated external one ride through on partial credit,
      and a mistyped internal IP must never gate a sound verdict;
    * a **file-hash / JA3-shaped hex digest** (32/40/64 hex chars).

    Deliberately NOT extracted: domains and hostnames. A dotted path citation
    (``alert.rule_metadata.signature_severity``) is indistinguishable from a
    domain by shape, and the model-variance doctrine forbids punishing
    citation shape — so those assertions stay out of this gate's reach (an
    honest, documented limit rather than a false-fire surface).

    An empty return is the gate's SILENCE condition: no decisive value
    asserted → the gate has nothing to say.
    """
    text_parts = [str(getattr(report, "summary", "") or "")]
    text_parts.extend(str(c) for c in (getattr(report, "citations", None) or []))
    text = " ".join(text_parts)
    values: set[str] = set()
    for m in _ASSERTED_IPV4_RE.finditer(text):
        try:
            addr = ip_address(m.group(0))
        except ValueError:  # pragma: no cover — the regex validates octets
            continue
        if addr.is_global and not addr.is_multicast:
            values.add(m.group(0).lower())
    for m in _ASSERTED_HASH_RE.finditer(text):
        values.add(m.group(0).lower())
    return frozenset(values)


def _evidence_payload(content: Any) -> Any | None:
    """The evidence-bearing STRUCTURE of one retrieved tool payload, or None.

    Error strings and error/dedup/prefetch-short-circuit dicts retrieved
    nothing. Top-level bookkeeping echo keys (:data:`_NON_EVIDENCE_RESULT_KEYS`
    — ``ip``, ``query``, ``indicator``, ``hash`` …) are dropped so a tool that
    merely ECHOES the model's own argument cannot launder a fabricated value
    into "retrieved" (calling ``t_enrich_ip`` on an invented IP must not make
    that IP supported — and a fabricated hash echoed back must not earn the
    floor-raise). Real document content — hits, sources, nested leaves —
    survives intact. Shared by the decisive-value support gate (which then
    text-searches the JSON dump; safe, a match only SILENCES a downgrade) and
    the floor-raise's credit-set harvest (which walks the structure by key
    membership; a match RAISES, so it never touches dumped text).
    """
    if content is None or isinstance(content, str):
        return None
    if isinstance(content, dict):
        if (
            content.get("error")
            or content.get("duplicate_call")
            or content.get("prefetch_already_has_this")
        ):
            return None
        return {k: v for k, v in content.items() if k not in _NON_EVIDENCE_RESULT_KEYS}
    return content


def _support_corpus_fragment(content: Any) -> str | None:
    """Lowercased JSON text of ONE retrieved tool payload, echo-filtered
    (see :func:`_evidence_payload` for what is dropped and why)."""
    payload = _evidence_payload(content)
    if payload is None:
        return None
    try:
        return json.dumps(payload, default=str).lower()
    except Exception:
        return None


def _retrieved_support_corpus(
    bundle_text: str,
    messages: list[Any] | None,
    targeted_tool_results: Sequence[Any] | None,
) -> str:
    """Everything this run actually retrieved, as lowercased text.

    The prefetched bundle dump, plus the CONTENTS of real tool returns in the
    message history (the investigation loop), plus any Phase-D targeted
    dispatch results. Text membership is safe HERE — unlike id-citation
    resolution (M2), where a substring hit UPGRADED a forged citation to a
    resolved document, a match in this corpus can only SILENCE a downgrade:
    the claim being checked is exactly "this value appears in a retrieved
    document", which a text hit makes literally true. An attacker can only
    prevent the gate from firing (by actually planting the value in the
    telemetry the run retrieved), never cause it to fire on someone else's
    sound verdict.
    """
    parts: list[str] = [bundle_text]
    for msg in messages or []:
        for part in getattr(msg, "parts", []) or []:
            if getattr(part, "part_kind", None) not in ("tool-return", "builtin-tool-return"):
                continue
            frag = _support_corpus_fragment(getattr(part, "content", None))
            if frag:
                parts.append(frag)
    for result in targeted_tool_results or []:
        frag = _support_corpus_fragment(result)
        if frag:
            parts.append(frag)
    return "\n".join(parts)


def _decisive_value_is_retrieved(value: str, corpus: str) -> bool:
    """Boundary-aware membership: ``10.0.0.1`` must not match inside
    ``10.0.0.111``, and a 32-hex digest must not match inside a 64-hex one."""
    if "." in value:  # dotted IPv4
        pattern = rf"(?<!\d){re.escape(value)}(?!\d)"
    else:  # hex digest
        pattern = rf"(?<![0-9a-f]){re.escape(value)}(?![0-9a-f])"
    return re.search(pattern, corpus) is not None


def _enforce_decisive_value_support(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext
    audit: dict[str, Any],
    *,
    targeted_messages: list[Any] | None,
    targeted_tool_results: Sequence[Any] | None,
) -> Any:
    """A true_positive's asserted decisive value must appear in RETRIEVED evidence.

    This is a support check on cited evidence, NOT a judgment on whether the
    reasoning is sound. Doctrine, per the floor-rewrite lessons this module
    encodes:

    * **Silent** when the verdict asserts no decisive value at all
      (:func:`_asserted_decisive_values` returns empty), when every asserted
      value IS retrieved, and when the bundle cannot be read at all (fail
      OPEN — absence of visibility is not absence of evidence).
    * **Band, never zero** when SOME asserted values are retrieved: the
      verdict label survives and confidence takes the same banded shave as
      the citation cap (:func:`_citation_confidence_cap`, floor 0.4).
    * **Coerce** to ``needs_more_info`` in the 0.4 band — actions cleared,
      the honest "not yet investigated" state — only when the asserted
      evidence is genuinely absent: NOT ONE asserted decisive value appears
      in anything the run retrieved, and no real IOC hit grounds the
      escalation (an attacker cannot manufacture that exemption; it requires
      the indicator to actually be on a blocklist).

    Evidence-conditional, not shape-conditional: matching is over VALUES in
    the full retrieved corpus, never over how a citation was formatted — a
    model whose voice differs but whose asserted values are real is untouched
    (``tests/test_validator_model_variance.py`` is the contract).
    """
    if report.verdict != "true_positive":
        return report
    asserted = _asserted_decisive_values(report)
    if not asserted:
        return report  # silence condition: nothing decisive asserted
    bundle_text = _bundle_dump_text(enriched_ctx)
    if not bundle_text:
        return report  # can't see the bundle → fail open, never manufacture a downgrade
    corpus = _retrieved_support_corpus(bundle_text, targeted_messages, targeted_tool_results)
    unsupported = sorted(v for v in asserted if not _decisive_value_is_retrieved(v, corpus))
    if not unsupported:
        return report
    support_ratio = (len(asserted) - len(unsupported)) / len(asserted)

    if support_ratio == 0.0 and not _has_ioc_hit(enriched_ctx):
        capped_conf = min(report.confidence, 0.4)
        audit["unsupported_decisive_value_downgrade"] = {
            "original_verdict": report.verdict,
            "capped_verdict": "needs_more_info",
            "original_confidence": report.confidence,
            "capped_confidence": capped_conf,
            "asserted_values": sorted(asserted),
            "unsupported_values": unsupported,
            "reason": (
                "true_positive asserts decisive indicator value(s) that appear "
                "in no retrieved document — not in the prefetched bundle and "
                "not in any tool result this run gathered; the cited evidence "
                "does not contain the value the verdict rests on, so it is "
                "coerced to needs_more_info for a real investigation"
            ),
        }
        note = (
            " (Downgraded to needs_more_info by the decisive-value support "
            "gate: the verdict asserts " + ", ".join(unsupported) + " — which "
            "appears in no document this run retrieved.)"
        )
        return report.model_copy(
            update={
                "verdict": "needs_more_info",
                "confidence": capped_conf,
                "recommended_actions": [],
                "summary": (getattr(report, "summary", "") or "") + note,
            }
        )

    original_conf = report.confidence
    capped = _citation_confidence_cap(original_conf, coverage_ratio=support_ratio)
    audit["decisive_value_support_cap"] = {
        "original_confidence": original_conf,
        "capped_confidence": capped,
        "support_ratio": support_ratio,
        "asserted_values": sorted(asserted),
        "unsupported_values": unsupported,
        "ioc_hit_exemption": support_ratio == 0.0,
        "reason": (
            "some asserted decisive indicator value(s) appear in no retrieved "
            "document; the verdict label is preserved (retrieved evidence is "
            "not genuinely absent) and confidence takes the banded shave"
        ),
    }
    if capped != original_conf:
        report = report.model_copy(update={"confidence": capped})
    return report


def _downgrade_unevidenced_verdict(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext
    candidate: Any,  # CandidateVerdict | None
    audit: dict[str, Any],
    *,
    targeted_messages: list[Any] | None,
    targeted_tool_called: str | None,
    resolved_citations: int | None = None,
) -> Any:
    """HARD evidence gate — the zero-tool-verdict defense.

    A settled verdict (``true_positive`` / ``false_positive``) must rest on REAL
    evidence:

    * at least one SUCCESSFUL tool call from the investigation loop
      (``count_successful_tool_calls(targeted_messages) >= 1``), OR
    * a Phase-D targeted-tool dispatch (``targeted_tool_called is not None``), OR
    * a DISPOSITIVE benign template (:func:`_is_strong_grounded_template`) whose
      verdict the report agrees with AND at least one citation that resolves.

    Otherwise the verdict is a rationalization of prefetched alert fields with no
    investigation behind it (the QVOD / zero-tool-TP defect) and is coerced to
    ``needs_more_info`` — the honest "not yet investigated" state — with
    confidence capped and recommended actions cleared. Records ``audit
    ['evidence_gate_downgrade']`` when it fires.

    ``resolved_citations`` is the count from :func:`_resolve_citations`, threaded
    by :func:`_synth_first_post_validate`. The template exemption exists so a
    template can settle a case on ITS OWN grounds, so those grounds have to be on
    the record: zero retrieval plus zero citations is a state with nothing in it,
    whatever matched. In practice the report is rarely uncited by the time it
    gets here, because :func:`_adopt_template_grounds` has already lent it the
    template's cited_evidence. ``None`` falls back to the raw citation count for
    direct callers that never ran the resolver.

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
    if resolved_citations is None:
        resolved_citations = len(getattr(report, "citations", None) or [])
    # A dispositive template only grounds a verdict that AGREES with it — a synth
    # that OVERRODE a benign template (e.g. escalated a clean-internal alert to
    # TP) is not grounded by that template and must still be gated. It also has
    # to have left its grounds on the record: an exemption for "the template
    # knows" cannot cover a report that says nothing about why.
    strong_template = (
        _is_strong_grounded_template(candidate, enriched_ctx)
        and getattr(candidate, "verdict", None) == report.verdict
        and resolved_citations >= 1
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
        "resolved_citations": resolved_citations,
        "template_id": getattr(candidate, "template_id", None),
        "template_authority": getattr(candidate, "authority", None),
        "reason": (
            "settled verdict with no investigation evidence — no successful tool "
            "call and no dispositive template with grounds on the record; a "
            "prefetch-only rationalization, coerced to needs_more_info"
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


# ---------------------------------------------------------------------------
# Same-session verdict consistency
# ---------------------------------------------------------------------------


def _session_true_positive(
    session_digests: Sequence[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """The most recent completed TRUE POSITIVE already reached on this session."""
    for digest in session_digests or []:
        if isinstance(digest, dict) and digest.get("verdict") == "true_positive":
            return digest
    return None


def enforce_session_verdict_consistency(
    report: Any,  # TriageReport
    session_digests: Sequence[dict[str, Any]] | None,
) -> tuple[Any, dict[str, Any] | None]:
    """A false positive may not stand while a true positive holds the same session.

    Two alerts from one TCP session, twenty-eight minutes apart, settled
    opposite ways on the range: one true positive recommending escalation, one
    false positive recommending acknowledgement. Same source, same destination,
    same port, same community id. An analyst working the queue top down meets
    the false positive first, acknowledges on the product's recommendation, and
    never reaches the row saying the same session was lateral movement.

    The two are not two opinions about a resemblance, they are one conversation
    read twice, so one of the readings is wrong. This gate does not decide which.
    Adopting the prior verdict would make an older run authoritative over the
    evidence in front of this one, and a gate that can promote a verdict is a
    gate that can invent one. It refuses the CLOSE instead: the verdict becomes
    ``needs_more_info``, the recommended actions go (the acknowledge
    recommendation is the whole harm), and the note names the prior
    investigation so the analyst reads both.

    Returns ``(report, audit)``. ``audit`` is ``None`` when nothing fired, which
    is every run with no true positive on its session and every run that did not
    settle false positive: a true positive agreeing with a true positive needs no
    correction, and neither does a needs_more_info already asking for help.
    """
    prior = _session_true_positive(session_digests)
    if prior is None or getattr(report, "verdict", None) != "false_positive":
        return report, None
    prior_id = str(prior.get("id") or "unknown")
    note = (
        "Verdict held at needs_more_info by the same-session gate. This alert was "
        f"settled false positive, but investigation {prior_id} already reached true "
        "positive on the SAME network session (matching community id). One session "
        "cannot be both, so the false positive does not stand and the alert is not "
        "recommended for acknowledgement. Read both before deciding. Original "
        f"summary: {getattr(report, 'summary', '')}"
    )
    audit = {
        "original_verdict": "false_positive",
        "held_verdict": "needs_more_info",
        "prior_investigation_id": prior_id,
        "prior_confidence": prior.get("confidence"),
        "dropped_actions": [
            getattr(a, "tool_name", "") for a in getattr(report, "recommended_actions", [])
        ],
        "reason": (
            "a completed true positive holds the same network session; a false "
            "positive on it would close an alert the product has already called "
            "malicious"
        ),
    }
    return (
        report.model_copy(
            update={
                "verdict": "needs_more_info",
                "recommended_actions": [],
                "validator_note": note,
            }
        ),
        audit,
    )
