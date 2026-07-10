"""Promote investigation history into DRAFT runbooks (suggestions, never auto-applied).

The retrieval A/B showed generic runbooks don't move verdicts — the plausible
value is ORG-SPECIFIC knowledge, and the deployment already holds months of it:
completed investigations (verdicts, confidences, rationales), analyst chat
threads, and the analyst-override trail. This module closes that loop the same
way detection tuning (E4.3, :mod:`soc_ai.webui.detection_tuning`) closes the
noisy-rule loop: distill what actually happened into a SUGGESTION the operator
reviews. Nothing here ever reaches an agent prompt on its own —

* :func:`promotable_rules` nominates rules with enough completed, non-fallback
  history and no runbook already covering them (drives the UI list);
* :func:`draft_runbook_for_rule` gathers ONE rule's history, composes a
  grounded distillation prompt, makes ONE structured-output analyst-model call
  (the same builder + egress guard the synthesizer uses), and stores the result
  as a ``draft=True`` runbook — excluded from every retrieval tier
  (:mod:`soc_ai.store.runbooks`) until the operator approves it in the
  Runbooks page.

Egress: when ``analyst_cloud_redaction`` is on, the composed prompt is
sanitized through an :class:`~soc_ai.agent.egress_guard.EgressGuard` (stable
opaque labels), swept fail-closed when ``analyst_redaction_fail_closed`` is on
(:class:`~soc_ai.agent.egress_guard.EgressResidueError` propagates — the model
is never called), and the model's structured output is DESANITIZED before
storage — the stored draft must name the org's real hosts/IPs to be useful
locally. This mirrors the orchestrator's synth round-1 wiring exactly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field
from pydantic_ai import Agent
from sqlalchemy import select

from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.agent.models import build_synthesizer_model
from soc_ai.oracle.identifiers import effective_internal_identifiers
from soc_ai.store import chat_memory
from soc_ai.store import runbooks as runbooks_svc
from soc_ai.store.investigations import _digest_rationale, override_counts_by_rule
from soc_ai.store.models import Investigation, Runbook
from soc_ai.store.runbooks import _rule_link_match
from soc_ai.triage_models import is_pipeline_fallback

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from soc_ai.audit.logger import AuditLogger
    from soc_ai.config import Settings

_LOGGER = logging.getLogger(__name__)

# How many of the rule's newest completed investigations feed the prompt. ~20
# is enough to show a trend + the distinguishing details without blowing the
# prompt budget (each line is a compact digest, not a report).
_MAX_INVESTIGATIONS = 20

# Bounded SQL overscan for the fallback post-filter (same pattern as
# prior_outcomes): pipeline-fallback rows are dropped AFTER the fetch, so pull
# a small multiple to survive a streak of them without an unbounded scan.
_FALLBACK_OVERSCAN = 3

# Chat-snippet ask. relevant_chat_snippets hard-caps at its own _MAX_SNIPPETS
# (5) — a deliberate prompt-budget guard we inherit rather than bypass; the
# larger ask just means "give me everything up to your cap".
_MAX_CHAT_SNIPPETS = 10

# Chat retrieval window. Promotion distills INSTITUTIONAL memory, so it looks
# much further back than the per-investigation chat-memory injection (which
# optimizes for recency); a year covers "months of history" with a bound.
_CHAT_WINDOW_DAYS = 365

# Candidate-discovery scan bound: newest completed investigations considered
# when grouping per rule. Plenty for a home-lab/SMB deployment's active rules;
# keeps discovery a bounded read on every Runbooks-page visit.
_DISCOVERY_SCAN_ROWS = 2000

# Deterministic dominant-verdict tiebreak order (most actionable first).
_VERDICT_ORDER = ("false_positive", "true_positive", "needs_more_info")


class NoPromotableHistoryError(Exception):
    """The rule has no completed, non-fallback investigations to distill."""


class RunbookDraftOutput(BaseModel):
    """The structured output the analyst model must return for a draft.

    Mirrors the runbook write shape (title/content/tags/linked_rules) so the
    mapping to :func:`soc_ai.store.runbooks.create` is 1:1. ``linked_rules``
    is advisory — the service ALWAYS forces the promoted rule into the stored
    list, because candidate discovery and retrieval both key on that link.
    """

    title: str = Field(min_length=1, max_length=512)
    content: str
    tags: list[str] = Field(default_factory=list)
    linked_rules: list[str] = Field(default_factory=list)


@dataclass
class DraftRunbook:
    """A stored draft + the input volumes that produced it (for UI/audit)."""

    runbook: Runbook
    investigations_used: int
    chat_snippets_used: int


# The system prompt sets the ROLE and the hard grounding rule; the per-rule
# user prompt (below) carries the observed history and the required section
# structure. Kept apart so tests can assert on the composed user prompt alone.
_SYSTEM_PROMPT = """You are a senior SOC analyst writing an INTERNAL triage runbook \
for one specific detection rule on one specific network, distilled from that \
network's own investigation history. Write for a colleague triaging this alert at \
3am: concrete, imperative, org-specific.

HARD RULE — ground every specific claim (a host, an IP, a pattern, a "known \
benign") in the observed history you are given. Do NOT invent example hosts, \
IPs, or scenarios that are not in the history. Generic advice is worthless here; \
the value is what THIS network's outcomes showed."""


def _verdict_bucket(verdict: str | None) -> str:
    """Map a stored verdict to the three tally buckets (tuning convention).

    ``inconclusive`` (the self-consistency split non-decision) folds into
    needs_more_info exactly as :func:`~soc_ai.store.investigations
    .verdict_counts_by_rule` does, so promotion stats match the tuning panel's.
    """
    v = "needs_more_info" if verdict == "inconclusive" else (verdict or "")
    return v if v in _VERDICT_ORDER else "needs_more_info"


def _dominant_verdict(counts: dict[str, int]) -> str:
    """Highest-count bucket; ties break by fixed order for determinism."""
    return max(_VERDICT_ORDER, key=lambda v: (counts.get(v, 0), -_VERDICT_ORDER.index(v)))


async def _completed_non_fallback(
    db: AsyncSession, rule_name: str, *, cap: int
) -> list[Investigation]:
    """The rule's newest completed, verdict-bearing, NON-fallback investigations.

    Pipeline-fallback rows (synth failures that landed the honest low-confidence
    NMI shape, E1.2) are model-failure noise, not institutional knowledge — the
    shared :func:`is_pipeline_fallback` predicate drops them in Python (the
    report is a portable JSON column), with a bounded SQL overscan to survive a
    fallback streak.
    """
    rows = (
        await db.scalars(
            select(Investigation)
            .where(
                Investigation.rule_name == rule_name,
                Investigation.status == "complete",
                Investigation.verdict.is_not(None),
            )
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
            .limit(cap * _FALLBACK_OVERSCAN)
        )
    ).all()
    kept = [inv for inv in rows if not is_pipeline_fallback(inv.report)]
    return kept[:cap]


async def promotable_rules(
    db: AsyncSession, *, min_investigations: int = 3
) -> list[dict[str, Any]]:
    """Rules whose history is deep enough to distill and not already covered.

    A rule qualifies when it has ≥ ``min_investigations`` completed,
    verdict-bearing, non-fallback investigations AND no existing runbook —
    draft or published — already links it (same :func:`_rule_link_match`
    semantics retrieval uses, so "covered" here means exactly "the agent would
    already find a runbook for this rule"; counting drafts keeps the button
    idempotent — one draft per rule until the operator acts on it).

    Newest-activity-first. Each entry::

        {rule_name, investigations, false_positive, true_positive,
         needs_more_info, dominant_verdict, last_activity (datetime),
         newest_id (ULID of the newest counted run — the sort tiebreak)}
    """
    rows = (
        await db.scalars(
            select(Investigation)
            .where(
                Investigation.status == "complete",
                Investigation.verdict.is_not(None),
                Investigation.rule_name.is_not(None),
            )
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
            .limit(_DISCOVERY_SCAN_ROWS)
        )
    ).all()

    stats: dict[str, dict[str, Any]] = {}
    for inv in rows:
        if not inv.rule_name or is_pipeline_fallback(inv.report):
            continue
        entry = stats.setdefault(
            inv.rule_name,
            {
                "rule_name": inv.rule_name,
                "investigations": 0,
                "false_positive": 0,
                "true_positive": 0,
                "needs_more_info": 0,
                # Rows arrive newest-first, so the first row seen per rule IS
                # the newest activity — no per-row max() needed. The ULID id
                # rides along as a monotonic tiebreak: SQLite's CURRENT_TIMESTAMP
                # is 1-second-granular, so a burst of runs across rules would
                # otherwise sort non-deterministically.
                "last_activity": inv.created_at,
                "newest_id": inv.id,
            },
        )
        entry["investigations"] += 1
        entry[_verdict_bucket(inv.verdict)] += 1

    candidates = [e for e in stats.values() if e["investigations"] >= min_investigations]
    if not candidates:
        return []

    # Exclude rules a runbook already links — same bounded scan retrieval uses.
    runbooks = list((await db.scalars(select(Runbook).limit(500))).all())
    out: list[dict[str, Any]] = []
    for entry in candidates:
        if any(_rule_link_match(rb, entry["rule_name"]) for rb in runbooks):
            continue
        entry["dominant_verdict"] = _dominant_verdict(entry)
        out.append(entry)

    # Newest activity first; the ULID tiebreak keeps same-second bursts stable.
    out.sort(key=lambda e: (e["last_activity"] or datetime.min, e["newest_id"]), reverse=True)
    return out


def _investigation_lines(invs: list[Investigation]) -> list[str]:
    """One compact prompt line per investigation (digest, never a full report)."""
    lines: list[str] = []
    for inv in invs:
        when = inv.created_at.date().isoformat() if inv.created_at else "?"
        conf = f" conf={inv.confidence:.2f}" if inv.confidence is not None else ""
        flow = ""
        if inv.src_ip or inv.dest_ip:
            flow = f" [{inv.src_ip or '?'} → {inv.dest_ip or '?'}]"
        digest = _digest_rationale(inv.rationale) or "(no rationale recorded)"
        lines.append(f"- {when} {inv.verdict}{conf}{flow}: {digest}")
    return lines


def _fp_patterns(invs: list[Investigation]) -> list[str]:
    """Deduped src→dst endpoint pairs from FALSE-POSITIVE verdicts, in order.

    These are the concrete "seen benign HERE" facts the Known-benign section
    must ground in — the whole point of an org-specific runbook.
    """
    seen: set[str] = set()
    out: list[str] = []
    for inv in invs:
        if inv.verdict != "false_positive" or not (inv.src_ip or inv.dest_ip):
            continue
        pair = f"{inv.src_ip or '?'} → {inv.dest_ip or '?'}"
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


def _compose_prompt(
    rule_name: str,
    invs: list[Investigation],
    snippets: list[dict[str, Any]],
    overrides: dict[str, int],
) -> str:
    """The distillation user prompt: observed history + required structure.

    Everything model-facing is composed HERE (one string) so the egress guard
    can sanitize + residue-sweep the FINAL outbound text in one pass, exactly
    like the orchestrator's ``_guard_egress`` contract.
    """
    counts: dict[str, int] = {}
    for inv in invs:
        b = _verdict_bucket(inv.verdict)
        counts[b] = counts.get(b, 0) + 1
    stats = ", ".join(f"{counts.get(v, 0)} {v}" for v in _VERDICT_ORDER)

    parts = [
        f'Write a triage runbook for the detection rule "{rule_name}" on THIS network,',
        "distilled from the observed outcomes below.",
        "",
        f"## Observed outcomes ({len(invs)} completed investigations: {stats})",
        *_investigation_lines(invs),
    ]

    fp_pairs = _fp_patterns(invs)
    if fp_pairs:
        parts += [
            "",
            "## Endpoint pairs seen in FALSE-POSITIVE verdicts (candidate known-benign)",
            *[f"- {p}" for p in fp_pairs],
        ]

    if overrides:
        parts += [
            "",
            "## Analyst corrections (human overrides of AI verdicts — strong signal)",
            f"- overridden to false_positive: {overrides.get('overridden_to_fp', 0)}",
            f"- overridden to true_positive: {overrides.get('overridden_to_tp', 0)}",
        ]

    if snippets:
        parts += [
            "",
            "## Analyst chat excerpts mentioning this rule (context, may be opinion)",
            *[f"- [{s['role']}] {s['snippet']}" for s in snippets],
        ]

    parts += [
        "",
        "## Required structure (use exactly these markdown section headings)",
        "1. `## When this fires` — what the rule detects and the traffic that triggers it here.",
        "2. `## What it has meant here` — the verdict history above, summarized honestly"
        " (include the counts).",
        "3. `## How to triage` — ordered steps grounded in what actually distinguished"
        " true positives from false positives in the outcomes above.",
        "4. `## Known-benign patterns` — the SPECIFIC sources/destinations/hosts seen in"
        " false-positive verdicts above; omit the section if there were none.",
        "5. `## Escalate when` — concrete conditions from the history that should page a human.",
        "",
        "Also return: a short imperative title (e.g. 'Triage: <rule>'), 2-4 lowercase"
        " topic tags, and linked_rules containing the exact rule name.",
    ]
    return "\n".join(parts)


async def _build_guard(db: AsyncSession, settings: Settings) -> EgressGuard:
    """An egress guard over the deployment's EFFECTIVE identifier set.

    Mirrors the orchestrator: prefer env-config union DB-discovered identifiers
    (the session is right here, so no sessionmaker indirection); fall back to
    the raw env tuples on any DB trouble — the sanitizer's reserved-suffix
    floor still applies, we only lose the DB-discovered names.
    """
    try:
        effective = await effective_internal_identifiers(db, settings)
        return EgressGuard(extra_hosts=effective.hosts, extra_suffixes=effective.suffixes)
    except Exception:
        _LOGGER.warning(
            "runbook promotion: effective-identifier resolution failed; "
            "falling back to env-config hosts/suffixes",
            exc_info=True,
        )
        return EgressGuard(
            extra_hosts=tuple(settings.oracle_extra_hosts),
            extra_suffixes=tuple(settings.oracle_internal_suffixes),
        )


async def draft_runbook_for_rule(
    db: AsyncSession,
    settings: Settings,
    rule_name: str,
    *,
    created_by: str = "anonymous",
    audit: AuditLogger | None = None,
) -> DraftRunbook:
    """Distill one rule's history into a stored ``draft=True`` runbook.

    ONE analyst-model call (structured :class:`RunbookDraftOutput`, via the
    same :func:`build_synthesizer_model` builder synthesis uses). The draft is
    invisible to every retrieval tier until approved, and is NOT embedded here
    — the approve endpoint embeds it the moment it becomes retrievable.

    Raises :class:`NoPromotableHistoryError` when the rule has nothing usable,
    and lets :class:`~soc_ai.agent.egress_guard.EgressResidueError` propagate
    when fail-closed redaction blocks the outbound prompt (the model is never
    called; no row is written). Model/validation failures also propagate — the
    route maps them; a failed draft must never store a partial row.
    """
    invs = await _completed_non_fallback(db, rule_name, cap=_MAX_INVESTIGATIONS)
    if not invs:
        raise NoPromotableHistoryError(rule_name)

    # Rule tokens as OR terms + the full name as one phrase — the phrase is
    # precise when analysts quoted the rule verbatim, the tokens keep recall
    # when they paraphrased ("that nmap thing").
    snippets = await chat_memory.relevant_chat_snippets(
        db,
        query_terms=[rule_name, *rule_name.split()],
        exclude_thread=None,
        window_days=_CHAT_WINDOW_DAYS,
        limit=_MAX_CHAT_SNIPPETS,
    )
    overrides = (await override_counts_by_rule(db, [rule_name])).get(rule_name, {})

    prompt = _compose_prompt(rule_name, invs, snippets, overrides)

    # ── Egress guard: sanitize → fail-closed sweep → call → DESANITIZE ────────
    # `is True` (not truthiness) so a non-Settings test double can never flip
    # redaction on — same guard-rail the orchestrator uses.
    guard: EgressGuard | None = None
    if settings.analyst_cloud_redaction is True:
        guard = await _build_guard(db, settings)
        prompt = guard.sanitize_text(prompt)
        # Independent residue sweep on the FINAL outbound string; raises
        # EgressResidueError (caller maps it) when fail-closed is on and an
        # identifier survived — the model call below never happens.
        guard.check_or_raise(prompt, fail_closed=settings.analyst_redaction_fail_closed)

    agent: Agent[None, RunbookDraftOutput] = Agent(
        build_synthesizer_model(settings),
        system_prompt=_SYSTEM_PROMPT,
        output_type=RunbookDraftOutput,
        retries=3,
    )
    result = await agent.run(prompt)
    out = result.output

    if guard is not None:
        # The model answered in label-space (HOST_01, IP_02, …). The stored
        # draft is LOCAL — restore the real identifiers or the runbook is
        # useless to the operator. Round-trip through model_dump/validate so
        # every string field (incl. list items) is restored uniformly.
        out = RunbookDraftOutput.model_validate(guard.desanitize_obj(out.model_dump(mode="json")))

    # Force the promoted rule into linked_rules regardless of what the model
    # returned: discovery ("already covered") and retrieval (rule-link boost
    # after approval) both key on this link — it is structural, not advisory.
    linked = list(out.linked_rules)
    if not any(r.strip().lower() == rule_name.strip().lower() for r in linked):
        linked.append(rule_name)

    runbook = await runbooks_svc.create(
        db,
        title=out.title,
        content=out.content,
        tags=out.tags,
        linked_rules=linked,
        created_by=created_by,
        draft=True,
    )

    # Best-effort audit (the model_fitness idiom): a failed audit write must
    # never fail a landed draft. Light payload — rule + counts + row id only.
    if audit is not None:
        try:
            await audit.log_kind(
                session_id=f"runbook-promotion:{rule_name[:64]}",
                kind="runbook_promotion",
                payload={
                    "rule_name": rule_name,
                    "investigations": len(invs),
                    "chat_snippets": len(snippets),
                    "runbook_id": runbook.id,
                    "redacted": guard is not None,
                },
                user=created_by,
                model_alias=settings.analyst_model,
            )
        except Exception:
            _LOGGER.warning("runbook_promotion audit write failed (continuing)", exc_info=True)

    return DraftRunbook(
        runbook=runbook,
        investigations_used=len(invs),
        chat_snippets_used=len(snippets),
    )
