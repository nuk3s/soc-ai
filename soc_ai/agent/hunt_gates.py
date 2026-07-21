"""Deterministic post-hunt citation gate for HuntReport findings.

Investigations validate citations deterministically (soc_ai.agent.gates); hunt
findings did not — a finding could cite an ES ``_id`` the hunt never actually
pulled. This module closes that gap: after the agent lands a
:class:`~soc_ai.agent.hunt.HuntReport`, each finding's citations are resolved
against the evidence the hunt ACTUALLY gathered (the ``tool_result`` payloads
that streamed this run). A finding whose citations resolve to nothing has its
non-resolving citations stripped and its severity capped; a high/critical
finding that cites nothing at all is capped too. Finding and chart ``title``s
are also clamped to a display-safe length (:func:`_clamp_title`) — the schema
asks the model for short headlines, but the clamp is what guarantees it. No LLM
calls — this is the trust layer, one layer down from the investigation citation
gate.

Resolver choice — the TOKEN fallback, not ``gates._resolve_citations``: hunt
citations are overwhelmingly bare ES ``_id`` strings, and
``_resolve_citations`` short-circuits any id-shaped citation to ``strict_id``
(model-trusted) WITHOUT checking the bundle — so a FABRICATED id would resolve
and defeat the whole gate. We therefore reuse the distinctive-token machinery
(``_FUZZY_TOKEN_RE`` + ``_CITATION_STOP_WORDS``) from
:mod:`soc_ai.agent.gates` and require a citation's distinctive tokens to appear
in the JSON dump of the gathered tool-result payloads — the fallback the E1.3
spec explicitly sanctions for exactly this shape mismatch.
"""

from __future__ import annotations

import json
import re
from typing import Any

from soc_ai.agent.gates import _CITATION_STOP_WORDS, _FUZZY_TOKEN_RE

# Severity ordinal — "cap at X" == min(current, X). Only ever LOWERS a severity.
_SEV_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
_SEV_RANK: dict[str, int] = {s: i for i, s in enumerate(_SEV_ORDER)}

_UNRESOLVED_NOTE = "Citations did not resolve to gathered evidence; severity capped to low."
_HIGH_NO_CITE_NOTE = "High-severity finding lacks citations; capped to medium."
_ALERT_ONLY_NOTE = (
    "Only detector alerts cited — corroborate before asserting compromise; "
    "severity capped to medium."
)

# ── Corroboration gate: alert-query vs corroborating-evidence tools ───────────
# The trust-erosion failure this closes (two real prod hunts, 2026-07): a
# wall-clock-truncated hunt gets written up from a transcript DOMINATED by
# Suricata alert documents, and the synthesizer asserts compromise at HIGH
# severity citing the very alert that IS the claim. The E1.3 gate above passes
# such a finding because the cited id genuinely EXISTS in the transcript — it
# checks existence, not corroboration. This gate adds the missing check: a
# high/critical THREAT finding must cite at least one item that resolves into a
# NON-alert (corroborating) tool result, or its severity is capped.
#
# ``_ALERT_QUERY_TOOLS`` is a DENY-set — the tools whose results ARE the
# detector's claim (Suricata alert documents, rule text, rule base-rates), which
# therefore CANNOT corroborate a threat asserted from those same alerts:
#   * t_query_events_oql   — the primary lens; returns raw event docs INCLUDING
#     suricata.alert documents (the loud alert titles that dominated the
#     truncated prod transcripts). Its results are partitioned per-document by
#     ``_oql_telemetry_docs`` BEFORE the membership test below — docs positively
#     identified as non-alert telemetry corroborate; alert docs and
#     unidentifiable docs do not (2026-07-20 telemetry-latitude design).
#   * t_query_detections   — searches detection RULES (the claim source itself).
#   * t_get_rule_content   — returns the signature's own definition (the claim).
#   * t_rule_prevalence    — a rule's base-rate/noisiness (rule metadata).
#   * t_suggest_rule_tuning — rule disposition trend (rule metadata).
# Every OTHER tool is corroborating evidence BEYOND the alert document —
# t_get_pcap / t_decode_payload (decoded packets), t_enrich_* (blocklist/MISP/
# ASN), t_prevalence (host novelty), t_host_summary (host artifact/OS),
# t_query_zeek_logs / t_get_event_raw (the underlying flow records), the online
# quartet (greynoise/shodan/cve) and the web tools. A finding grounded in ANY of
# those has looked past the alert title, which is exactly what the gate requires.
_ALERT_QUERY_TOOLS: frozenset[str] = frozenset(
    {
        "t_query_events_oql",
        "t_query_detections",
        "t_get_rule_content",
        "t_rule_prevalence",
        "t_suggest_rule_tuning",
    }
)

# Chart budget — a model that emits plausible-but-uncited charts freely is the whole
# risk, so beyond this ceiling extras are dropped even if they'd otherwise resolve.
_MAX_CHARTS = 4

# Title clamp — the HuntReport schema + prompt ask for <= ~60-char headlines, but a
# model can't be trusted to comply, and an overlong title just ellipsizes in the UI.
# This is the deterministic backstop: anything past the ceiling is word-boundary
# truncated here so the model can't overflow the display regardless.
_MAX_TITLE_CHARS = 90


def _clamp_title(title: str) -> str:
    """Word-boundary truncate ``title`` to at most :data:`_MAX_TITLE_CHARS` chars.

    A compliant title passes through untouched (modulo surrounding whitespace).
    An overlong one is cut at the last word boundary that fits and gets a
    trailing ellipsis; a single overlong token is hard-cut (no boundary to use).
    """
    text = (title or "").strip()
    if len(text) <= _MAX_TITLE_CHARS:
        return text
    cut = text[: _MAX_TITLE_CHARS - 1]  # leave room for the ellipsis
    head = cut.rpartition(" ")[0].rstrip()
    return f"{head or cut.rstrip()}…"


def _cap_severity(severity: str, ceiling: str) -> str:
    """Lower ``severity`` to at most ``ceiling`` (never raises). Unknown severities
    are treated as their lowest safe rank so a malformed value can't dodge the cap.
    """
    cur = _SEV_RANK.get((severity or "").strip().lower(), _SEV_RANK["critical"])
    cap = _SEV_RANK[ceiling]
    return _SEV_ORDER[min(cur, cap)]


def _gathered_evidence_text(tool_results: list[Any]) -> str:
    """Lower-cased JSON dump of every gathered tool-result payload.

    ``tool_results`` are the ``result`` values from the run's ``tool_result``
    events (the data the hunt actually pulled). Mirrors
    :func:`soc_ai.agent.evidence._bundle_dump_text` — one flat, lower-cased JSON
    blob the citation tokens are substring/word-boundary matched against.
    """
    if not tool_results:
        return ""
    try:
        return json.dumps(tool_results, default=str).lower()
    except Exception:
        return ""


def _citation_resolves(citation: str, evidence_text: str) -> bool:
    """True iff a DISTINCTIVE token of ``citation`` appears in ``evidence_text``.

    Reuses the investigation gate's distinctive-token discipline (GATE C): a
    stop-word or a short generic fragment never resolves a citation on its own;
    a long token (>= 8 chars — an ES ``_id``, a hash, a full IP) resolves on a
    substring match, a medium token (>= 5 chars — a domain label, a hyphenated
    host) resolves only on a word boundary. This kills hollow matches while
    resolving real ids/values the hunt pulled.
    """
    if not evidence_text:
        return False
    for tok in _FUZZY_TOKEN_RE.findall(citation):
        low = tok.lower()
        if low in _CITATION_STOP_WORDS:
            continue
        if len(tok) >= 8 and low in evidence_text:
            return True
        if len(tok) >= 5 and re.search(rf"\b{re.escape(low)}\b", evidence_text):
            return True
    return False


def _oql_telemetry_docs(result: Any) -> list[Any]:
    """The subset of an OQL result's hit docs POSITIVELY identified as telemetry.

    ``t_query_events_oql`` returns ``EsSearchResult.model_dump()`` —
    ``{total, hits: [<ES hit>], aggregations, ...}`` where each hit carries the
    doc under ``_source`` (or ``fields`` with list-wrapped values). A doc is
    telemetry iff its ``event.dataset`` is present and is NOT ``suricata.alert``
    and its ``event.kind`` is not ``alert``. Everything else — alert docs, docs
    with no dataset, aggregation-only results, malformed shapes — is excluded,
    so this helper can only ever ADD corroboration for docs that are provably
    not the detector's own claim. Never raises on shape surprises.
    """
    if not isinstance(result, dict):
        return []
    hits = result.get("hits")
    if not isinstance(hits, list):
        return []

    def _one(container: dict[str, Any], dotted: str) -> Any:
        # _source form nests ({"event": {"dataset": ...}}); fields form is flat
        # dotted keys with list-wrapped values ({"event.dataset": ["zeek.dns"]}).
        head, _, tail = dotted.partition(".")
        nested = container.get(head)
        value = nested.get(tail) if isinstance(nested, dict) else container.get(dotted)
        if isinstance(value, list):
            return value[0] if value else None
        return value

    telemetry: list[Any] = []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        src = hit.get("_source")
        if not isinstance(src, dict):
            src = hit.get("fields")
        if not isinstance(src, dict):
            continue
        dataset = _one(src, "event.dataset")
        kind = _one(src, "event.kind")
        if not isinstance(dataset, str) or not dataset:
            continue  # cannot positively identify → not corroborating
        if dataset == "suricata.alert" or kind == "alert":
            continue  # the detector's claim cannot corroborate itself
        telemetry.append(hit)
    return telemetry


def _corroborating_evidence_text(tool_results: list[Any]) -> str:
    """Lower-cased JSON dump of ONLY the corroborating (non-alert) tool results.

    ``tool_results`` are labeled ``{tool_name, result}`` items (the shape
    :func:`soc_ai.api.hunt_runner._stream_node` now gathers). Items whose
    ``tool_name`` is in :data:`_ALERT_QUERY_TOOLS` are the detector's own claim
    (Suricata alert documents, rule text, rule base-rates) and are EXCLUDED, so a
    citation that resolves only into an alert document does NOT resolve here.
    ``t_query_events_oql`` is special-cased first: its result is partitioned
    per-document by :func:`_oql_telemetry_docs`, so a zeek/host doc found via
    the broad lens corroborates while the alert docs in the same result don't.
    Everything else — decoded payloads, enrichment, host/prevalence, zeek flow
    records — is corroboration and its ``result`` is included.

    Defensive: a bare (un-labeled) item — a legacy shape, or a tool_result that
    somehow arrived without a ``tool_name`` — is treated as corroborating (it is
    not a KNOWN alert-query tool), so this can only ever ADD trust, never
    silently strip a real corroboration on a shape surprise.
    """
    corroborating: list[Any] = []
    for item in tool_results:
        if isinstance(item, dict) and "tool_name" in item and "result" in item:
            tool = item.get("tool_name")
            if tool == "t_query_events_oql":
                # Partition at the DOC level: zeek/host docs found through the
                # broad lens are real corroboration; alert docs and anything
                # not positively identified stay out.
                docs = _oql_telemetry_docs(item["result"])
                if docs:
                    corroborating.append(docs)
                continue
            if tool in _ALERT_QUERY_TOOLS:
                continue  # a detector-claim result cannot corroborate itself
            corroborating.append(item["result"])
        else:
            # Un-labeled / legacy item: not a known alert-query tool → corroborating.
            corroborating.append(item)
    return _gathered_evidence_text(corroborating)


def _has_corroborating_citation(citations: list[str], corroborating_text: str) -> bool:
    """True iff ANY citation resolves into a NON-alert (corroborating) tool result.

    Uses the same distinctive-token resolver as citation resolution, but against
    ``corroborating_text`` — the JSON dump of only the non-alert tool results (see
    :func:`_corroborating_evidence_text`). This is what a high/critical THREAT
    finding must satisfy: at least one piece of support that looked BEYOND the
    detector alert that raised the claim.
    """
    if not corroborating_text:
        return False
    return any(_citation_resolves(c, corroborating_text) for c in citations)


def _resolve_finding_citations(citations: list[str], evidence_text: str) -> tuple[list[str], float]:
    """Return (resolved_citations, coverage_ratio) for one finding's citations.

    ``coverage_ratio`` = resolved / total; an empty citation list is vacuously
    1.0 (no missing evidence to penalize — same convention as the investigation
    gate), and its resolved list is empty.
    """
    if not citations:
        return [], 1.0
    resolved = [c for c in citations if _citation_resolves(c, evidence_text)]
    return resolved, len(resolved) / len(citations)


def _validate_hunt_findings(
    findings: list[Any],
    tool_results: list[Any],
) -> tuple[list[Any], dict[str, int]]:
    """Deterministic citation gate over a HuntReport's findings — PURE.

    For each finding (a :class:`~soc_ai.agent.hunt.HuntFinding` or any object
    supporting ``model_copy(update=...)``):

    * Resolve its ``citations`` against ``tool_results`` (the JSON payloads the
      hunt actually gathered) via the distinctive-token resolver.
    * ``coverage_ratio == 0`` with a NON-empty citation list (NONE resolve):
      strip the non-resolving citations (keep any that resolved — here none),
      cap severity at ``"low"``, set ``validator_note``.
    * EMPTY citation list: left alone UNLESS severity is high/critical, in which
      case cap to ``"medium"`` with the "lacks citations" note.
    * Otherwise (at least one citation resolves): keep only the resolving
      citations if some didn't resolve. The finding is GROUNDED — but a
      ``category == "threat"`` finding at high/critical severity gets one more
      check (the CORROBORATION gate): at least one of its resolving citations
      must resolve into a NON-alert tool result (a tool NOT in
      :data:`_ALERT_QUERY_TOOLS`). If EVERY resolving citation resolves only into
      detector-alert documents (Suricata alerts / rule text / rule base-rates),
      the claim is asserted purely from the alert that raised it — severity is
      capped to ``"medium"`` with :data:`_ALERT_ONLY_NOTE`. A non-threat finding,
      or a threat below high, keeps its severity (only the loud high/critical
      alert-title write-up is the trust failure this closes).

    Independently of citations, every finding's ``title`` is clamped via
    :func:`_clamp_title` — an overlong machine headline is word-boundary
    truncated so the UI never has to ellipsize it.

    Returns ``(validated_findings, counts)`` where ``counts`` carries per-hunt
    tallies for the ``citation_validation`` audit event:
    ``{findings, findings_capped, citations_total, citations_stripped}``.
    """
    evidence_text = _gathered_evidence_text(tool_results)
    # The corroboration subset: only NON-alert tool results. A high/critical
    # threat finding must cite at least one item resolving into THIS, or the
    # claim rests solely on the detector alert that raised it. Computed once.
    corroborating_text = _corroborating_evidence_text(tool_results)
    validated: list[Any] = []
    counts = {
        "findings": len(findings),
        "findings_capped": 0,
        "citations_total": 0,
        "citations_stripped": 0,
    }

    for raw_finding in findings:
        # Deterministic title clamp (independent of citations): the schema/prompt
        # ask for short headlines, but the clamp is what guarantees it.
        title = str(getattr(raw_finding, "title", None) or "")
        clamped_title = _clamp_title(title)
        finding = (
            raw_finding
            if clamped_title == title
            else raw_finding.model_copy(update={"title": clamped_title})
        )

        citations = list(getattr(finding, "citations", None) or [])
        severity = str(getattr(finding, "severity", None) or "info")
        counts["citations_total"] += len(citations)

        if not citations:
            # No citations: fine for an observation, but a high/critical claim
            # with nothing behind it is capped to medium.
            if _SEV_RANK.get(severity.lower(), 0) >= _SEV_RANK["high"]:
                validated.append(
                    finding.model_copy(
                        update={
                            "severity": _cap_severity(severity, "medium"),
                            "validator_note": _HIGH_NO_CITE_NOTE,
                        }
                    )
                )
                counts["findings_capped"] += 1
            else:
                validated.append(finding)
            continue

        resolved, coverage = _resolve_finding_citations(citations, evidence_text)

        if coverage == 0.0:
            # None of the finding's citations resolve to gathered evidence:
            # strip them and cap the severity at low.
            counts["citations_stripped"] += len(citations)
            validated.append(
                finding.model_copy(
                    update={
                        "citations": resolved,  # == [] here (nothing resolved)
                        "severity": _cap_severity(severity, "low"),
                        "validator_note": _UNRESOLVED_NOTE,
                    }
                )
            )
            counts["findings_capped"] += 1
        elif len(resolved) < len(citations):
            # Partial coverage: keep only the resolving citations (drop the
            # fabricated ones). The finding is grounded, but a high/critical
            # threat still faces the corroboration gate on its RESOLVING cites.
            counts["citations_stripped"] += len(citations) - len(resolved)
            grounded = finding.model_copy(update={"citations": resolved})
            validated.append(
                _apply_corroboration_cap(grounded, resolved, corroborating_text, counts)
            )
        else:
            # Fully grounded — but a high/critical threat must still corroborate
            # beyond the detector alert (the E1.3 pass above only proved the
            # cited ids EXIST, not that they look past the alert).
            validated.append(
                _apply_corroboration_cap(finding, resolved, corroborating_text, counts)
            )

    return validated, counts


def _apply_corroboration_cap(
    finding: Any,
    resolved_citations: list[str],
    corroborating_text: str,
    counts: dict[str, int],
) -> Any:
    """Cap a high/critical THREAT finding that cites only detector alerts.

    Given a finding that already PASSED citation resolution (its
    ``resolved_citations`` all exist in the gathered evidence), enforce the extra
    corroboration bar: if it is a ``category == "threat"`` finding at high/critical
    severity and NONE of its resolving citations resolve into a non-alert
    (corroborating) tool result, its claim rests solely on the detector alert that
    raised it — cap severity to ``"medium"`` and set :data:`_ALERT_ONLY_NOTE`
    (incrementing ``findings_capped``). Anything else passes through untouched:
    a non-threat finding, a threat below high, or a threat with real
    corroboration keeps its severity. PURE aside from the ``counts`` tally.
    """
    category = str(getattr(finding, "category", None) or "").strip().lower()
    severity = str(getattr(finding, "severity", None) or "info")
    if category != "threat" or _SEV_RANK.get(severity.lower(), 0) < _SEV_RANK["high"]:
        return finding
    if _has_corroborating_citation(resolved_citations, corroborating_text):
        return finding  # grounded in evidence beyond the detector alert
    counts["findings_capped"] += 1
    return finding.model_copy(
        update={
            "severity": _cap_severity(severity, "medium"),
            "validator_note": _ALERT_ONLY_NOTE,
        }
    )


def _validate_hunt_charts(
    charts: list[Any],
    tool_results: list[Any],
) -> tuple[list[Any], dict[str, int]]:
    """Deterministic chart gate over a HuntReport's charts — PURE.

    The model may author charts (a beacon-interval histogram, bytes-over-time)
    that a generic chart can't guess — but an INVENTED series must never render.
    Each chart is held to the SAME trust bar as findings (E3.3): its
    ``source_citations`` are resolved against ``tool_results`` (the JSON payloads
    the hunt actually gathered) with the SAME distinctive-token resolver
    :func:`_validate_hunt_findings` uses. A chart is DROPPED when it has:

    * NO ``source_citations`` at all (nothing ties its numbers to gathered data), or
    * source_citations of which NONE resolve to gathered evidence (an invented
      series citing ids the hunt never pulled), or
    * an EMPTY ``series`` (nothing to plot).

    Surviving charts are capped at :data:`_MAX_CHARTS` (extras beyond the ceiling
    are dropped) — bias is toward DROPPING; a chart that can't be traced to
    evidence is never rendered. Kept charts get their ``title`` clamped via
    :func:`_clamp_title` (same word-boundary truncation as findings).

    Returns ``(kept_charts, counts)`` where ``counts`` carries per-hunt tallies
    for the ``citation_validation`` audit event:
    ``{charts, charts_dropped}``.
    """
    evidence_text = _gathered_evidence_text(tool_results)
    kept: list[Any] = []
    counts = {"charts": len(charts), "charts_dropped": 0}

    for chart in charts:
        citations = list(getattr(chart, "source_citations", None) or [])
        series = list(getattr(chart, "series", None) or [])
        # DROP: nothing to plot, no citations, or none of the citations resolve.
        if not series or not citations or len(kept) >= _MAX_CHARTS:
            counts["charts_dropped"] += 1
            continue
        if not any(_citation_resolves(c, evidence_text) for c in citations):
            counts["charts_dropped"] += 1
            continue
        # Same deterministic title clamp as findings — only for kept charts.
        title = str(getattr(chart, "title", None) or "")
        clamped_title = _clamp_title(title)
        kept.append(
            chart if clamped_title == title else chart.model_copy(update={"title": clamped_title})
        )

    return kept, counts
