"""Validate a chat verdict proposal against the evidence the chat actually pulled.

A proposal is only applyable when its verdict is a terminal TP/FP AND at least one
citation is grounded in the chat session's own tool activity — the tool was invoked,
or the cited token appears in a tool's result. This is the chat-side analogue of the
orchestrator's evidence-backed gate; it deliberately does not trust a proposal that
merely re-states the alert (a self-referential `alert.*` citation is not evidence).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_TERMINAL = {"true_positive", "false_positive"}
# Tokens worth matching against tool results: ids, community ids, dotted paths,
# long alphanumerics — strip the (path ...)/(id ...) wrappers first.
_WRAP = re.compile(r"^\((?:path|id|tool)\s+(.*)\)$", re.IGNORECASE)
_ALERT_SELF = re.compile(r"^alert\.", re.IGNORECASE)


@dataclass
class Proposal:
    verdict: str
    confidence: float
    rationale: str
    citations: list[str] = field(default_factory=list)
    recommended_actions: list[dict[str, object]] = field(default_factory=list)


@dataclass
class ProposalValidation:
    ok: bool
    objection: str | None = None


def _unwrap(citation: str) -> str:
    m = _WRAP.match(citation.strip())
    return (m.group(1) if m else citation).strip()


def validate_proposal(
    proposal: Proposal,
    *,
    tool_evidence: list[dict[str, object]],
) -> ProposalValidation:
    """``tool_evidence`` is a list of ``{"tool": name, "result": text}`` from the chat run."""
    if proposal.verdict not in _TERMINAL:
        return ProposalValidation(
            ok=False,
            objection=f"verdict {proposal.verdict!r} is not a terminal decision (TP/FP).",
        )
    if not proposal.citations:
        return ProposalValidation(ok=False, objection="proposal cites no evidence.")

    tool_names = {str(e.get("tool", "")).lower() for e in tool_evidence}
    results_blob = "\n".join(str(e.get("result", "")) for e in tool_evidence).lower()

    for raw in proposal.citations:
        token = _unwrap(raw)
        if not token or _ALERT_SELF.match(token):
            continue  # empty or self-referential — not evidence the chat fetched
        low = token.lower()
        # grounded if it names an invoked tool (exact, or the tool name appears
        # inside a prose citation), or the cited token is in a tool result. Note
        # we deliberately do NOT match a citation that is merely a *substring* of
        # a tool name — that let junk like "in" pass the gate.
        if low in tool_names or any(tn in low for tn in tool_names if tn):
            return ProposalValidation(ok=True)
        if len(low) >= 4 and low in results_blob:
            return ProposalValidation(ok=True)

    return ProposalValidation(
        ok=False,
        objection="no citation is grounded in evidence the chat actually fetched.",
    )
