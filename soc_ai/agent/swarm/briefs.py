"""The brief: what one swarm agent hands the judge.

An advocate brief and a plane brief share one shape
(docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md, "An advocate
brief"): the claim the agent argued, the evidence for it as document ids with
one quoted line each, the strongest point against it, a confidence word, and
the gaps it could not check.

The ``error`` field belongs to the pipeline. A model that writes it has the
text removed (:func:`model_brief`). The pipeline sets it when an agent failed,
so the judge reads the failure as a gap.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, Field

ConfidenceWord = Literal["high", "medium", "low", "none"]


class BriefEvidence(BaseModel):
    """One record that supports the claim of a brief."""

    document_id: str = Field(
        description=(
            "The id of one record: an ES `_id`, a Zeek `uid` or a SOC API id. "
            "One id only, copied exactly from a tool result or the alert."
        )
    )
    line: str = Field(
        description="One line quoted from that record or from the tool result that returned it."
    )


class Brief(BaseModel):
    """The structured output of an advocate or a plane worker."""

    claim: str = Field(
        description=(
            "The claim you argued, in one sentence. When you found no evidence for it, say so here."
        )
    )
    evidence: list[BriefEvidence] = Field(
        default_factory=list,
        description=(
            "The records that support the claim. One entry per record. Leave the "
            "list empty when no record supports it."
        ),
    )
    counterpoint: str = Field(
        default="",
        description="The strongest fact against the claim, in one or two sentences.",
    )
    confidence: ConfidenceWord = Field(
        default="low",
        description="How strongly the evidence supports the claim: high, medium, low or none.",
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="The checks you could not make, one per entry.",
    )
    error: str | None = Field(
        default=None,
        description="Leave this empty. The pipeline sets it when an agent fails.",
    )


def model_brief(brief: Brief) -> Brief:
    """A brief the model wrote, with the pipeline's ``error`` field cleared."""
    return brief if brief.error is None else brief.model_copy(update={"error": None})


def empty_brief(claim: str, error: str) -> Brief:
    """The brief of an agent that failed: no evidence, and the error text."""
    return Brief(claim=claim, confidence="none", error=error or "the agent failed")


def brief_document_ids(briefs: Iterable[Brief]) -> list[str]:
    """Every document id the briefs carry, in order, without repeats."""
    seen: set[str] = set()
    ids: list[str] = []
    for brief in briefs:
        for item in brief.evidence:
            doc_id = item.document_id.strip()
            if doc_id and doc_id.lower() not in seen:
                seen.add(doc_id.lower())
                ids.append(doc_id)
    return ids


def render_brief(title: str, brief: Brief) -> str:
    """One brief as a markdown section of the judge's message."""
    lines = [f"### {title}", "", f"Claim: {brief.claim.strip() or '(none)'}"]
    lines.append(f"Confidence: {brief.confidence}")
    if brief.error:
        lines.append(f"Error: this agent failed. {brief.error.strip()}")
    if brief.evidence:
        lines.append("Evidence:")
        lines.extend(
            f"- `{item.document_id.strip()}`: {item.line.strip()}" for item in brief.evidence
        )
    else:
        lines.append("Evidence: none.")
    if brief.counterpoint.strip():
        lines.append(f"Counterpoint: {brief.counterpoint.strip()}")
    if brief.gaps:
        lines.append("Gaps:")
        lines.extend(f"- {gap.strip()}" for gap in brief.gaps if gap.strip())
    return "\n".join(lines) + "\n"


__all__ = [
    "Brief",
    "BriefEvidence",
    "ConfidenceWord",
    "brief_document_ids",
    "empty_brief",
    "model_brief",
    "render_brief",
]
