"""The one outcome of a hunt, and the words every surface prints for it.

The hunt list, the hunt page and the bell each read a hunt. The second dogfood
found a catalog run that could not reach the grid under the headline "No
threat observed" with a green "Complete" chip, and a free-text hunt whose
narrative said the answer "cannot be confirmed or ruled out" under the same
headline and a 0.75 confidence ring. A run that did not test its objective is
not a clean run, so this module names five outcomes and every surface reads
them from here:

* ``threat_found``: at least one finding claims a threat.
* ``no_threat``: the hunt tested its objective and found no threat.
* ``no_answer``: the hunt ran and could not test its objective. Every finding
  is a visibility gap, a part of the run failed, or the narrative says that the
  answer can be neither confirmed nor ruled out.
* ``could_not_run``: the hunt stopped (error, cancel or restart), or every
  finding is the record that a query failed.
* ``running``: the hunt has not ended.

A hunt investigates its subject findings as part of the hunt (2026-10-07,
:mod:`soc_ai.webui.hunt_findings`). Three outcomes come from that phase:

* ``investigating``: the hunt landed its report and the investigations of its
  findings run. The label counts them: "Investigating 2 of 3 findings".
* ``threats_confirmed``: at least one investigation of a finding reached the
  verdict true positive. The label counts them: "2 of 3 findings are threats".
* ``no_threat_confirmed``: the investigations reached verdicts and none is a
  true positive.

A hunt whose investigations reached no verdict keeps the outcome its report
gives. So does a hunt with no subject finding, and a hunt from before the phase.

The lead store keeps its own four codes in :func:`soc_ai.hunting.findings.hunt_outcome`
because a lead settles on them. This module maps them to the public outcomes and
adds the narrative test, which the store does not need.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from soc_ai.hunting.findings import finding_category, hunt_outcome, restate_failure

__all__ = [
    "OUTCOMES",
    "OUTCOME_LABEL",
    "FindingVerdicts",
    "could_not_run_reason",
    "grid_reason",
    "is_run_failure",
    "outcome_headline",
    "outcome_label",
    "public_outcome",
]


@dataclass(frozen=True)
class FindingVerdicts:
    """What the investigations of a hunt's subject findings concluded.

    ``total`` counts the subject findings. ``investigated`` counts those whose
    investigation ended, a failed one included. ``decided`` counts those whose
    investigation reached a verdict. ``threats`` counts the true positives.
    ``findings`` counts every finding of the report, a failed-query record
    excluded. It is 0 when the caller did not read the report.
    """

    total: int = 0
    investigated: int = 0
    decided: int = 0
    threats: int = 0
    findings: int = 0


OUTCOMES: tuple[str, ...] = (
    "threat_found",
    "no_threat",
    "no_answer",
    "could_not_run",
    "running",
    "investigating",
    "threats_confirmed",
    "no_threat_confirmed",
)

# One label per outcome. The list, the hunt page, the lead pill and the bell
# print these words and no others. The three outcomes of the investigation
# phase carry counts: :func:`outcome_label` writes them, and these are the
# words for a surface that holds no count.
OUTCOME_LABEL: dict[str, str] = {
    "threat_found": "Threat found",
    "no_threat": "No threat found",
    "no_answer": "No answer",
    "could_not_run": "Could not run",
    "running": "Running",
    "investigating": "Investigating findings",
    "threats_confirmed": "Threats confirmed",
    "no_threat_confirmed": "No threat confirmed",
}


def _findings(n: int) -> str:
    return f"{n} finding" if n == 1 else f"{n} findings"


def outcome_label(outcome: str, verdicts: FindingVerdicts | None = None) -> str:
    """The words for one outcome, with the counts when the outcome has them.

    ``investigating`` reads "Investigating 2 of 3 findings": the subject
    findings. ``threats_confirmed`` reads "2 of 5 findings are threats": the
    confirmed threat findings over every finding of the report, so the label
    and the list row count one set of findings. Without a summary each reads
    its plain label.
    """
    if verdicts is not None and verdicts.total > 0:
        total = verdicts.total
        if outcome == "investigating":
            return f"Investigating {verdicts.investigated} of {_findings(total)}"
        if outcome == "threats_confirmed":
            every = max(verdicts.findings, total)
            verb = "is a threat" if verdicts.threats == 1 else "are threats"
            return f"{verdicts.threats} of {_findings(every)} {verb}"
    return OUTCOME_LABEL.get(outcome, "")


# The title suffix the catalog composer writes on the finding that records a
# failed query (soc_ai.hunting.findings.candidate_findings).
_RUN_FAILURE_SUFFIX = ": could not run"

_STOPPED = frozenset({"error", "cancelled", "interrupted"})

# A narrative that says it could neither confirm nor rule out its question.
# The pairing is required: "could not rule out" alone also appears in a
# narrative that found a threat and in one that names a residual risk.
_NO_ANSWER_RE = re.compile(
    r"\b(?:can ?not|could not|can't|couldn't|unable to)\s+(?:be\s+)?"
    r"(?:confirm(?:ed)?|establish(?:ed)?|determine[d]?)\s+(?:or|nor)\s+(?:be\s+)?"
    r"rul(?:e|ed)\s+out\b"
    r"|\bneither\s+(?:be\s+)?confirm(?:ed)?\s+nor\s+(?:be\s+)?rul(?:e|ed)\s+out\b"
    r"|\bthe\s+(?:result|answer)\s+is\s+unknown\b",
    re.IGNORECASE,
)

# The sentence boundary used to quote the narrative's own statement of the gap.
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")

# The narrative blames the age of the data or the query window. The hunt tools
# answer 30 days back (soc_ai.tools.query_events._MAX_TIME_RANGE_MINUTES).
_DATA_AGE_RE = re.compile(
    r"\b\d+\s+days?\s+old\b|\bolder than\b|\boutside (?:the|its)\b[^.]*\bwindow\b"
    r"|\bretention\b|\bbeyond (?:the )?\d+\s*(?:-|\s)?days?\b|\bends on\b",
    re.IGNORECASE,
)
GRID_WINDOW_SENTENCE = "The grid answers 30 days back."

# What a failed grid query said, as one plain sentence about the grid. The
# catalog composer already turned the exception into a phrase
# (soc_ai.hunting.findings.plain_error); this maps that phrase to the grid.
_GRID_REASONS: tuple[tuple[str, str], ...] = (
    ("the answer is incomplete", "The grid answered from part of its shards."),
    ("did not accept a connection", "The grid did not accept a connection."),
    ("did not answer in time", "The grid did not answer in time."),
    ("rejected the credentials", "The grid refused the credentials."),
    ("refused the query", "The grid refused the query."),
    ("rejected the query", "The grid refused the query."),
)
_DEFAULT_GRID_REASON = "The grid refused the query."
_HUNT_AGAIN = "Hunt again when the grid is healthy."


def _rows(findings: Any) -> list[Mapping[str, Any]]:
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        return []
    return [f for f in findings if isinstance(f, Mapping)]


def is_run_failure(finding: Mapping[str, Any]) -> bool:
    """True for the finding that records a failed query and nothing else.

    It has no severity an analyst can act on, no evidence to promote and no
    behaviour to draft an analytic from.
    """
    title = str(finding.get("title") or "")
    return finding_category(finding) == "visibility_gap" and title.endswith(_RUN_FAILURE_SUFFIX)


def public_outcome(
    status: str,
    findings: Any,
    narrative: str | None = None,
    verdicts: FindingVerdicts | None = None,
) -> str:
    """The outcome of one hunt, one of :data:`OUTCOMES`.

    ``verdicts`` is the summary of the investigations of the hunt's subject
    findings. When one of them reached a verdict, the verdicts decide the
    outcome of a complete hunt, because an investigated finding is the better
    answer than the hunt's own claim.
    """
    if status == "investigating":
        return "investigating"
    if status in ("running", "queued"):
        return "running"
    if status in _STOPPED or status != "complete":
        return "could_not_run"
    if verdicts is not None and verdicts.decided:
        return "threats_confirmed" if verdicts.threats else "no_threat_confirmed"
    rows = _rows(findings)
    threats, internal = hunt_outcome(status, list(rows))
    if threats:
        return "threat_found"
    if rows and all(is_run_failure(f) for f in rows):
        return "could_not_run"
    if internal in ("gap", "failed"):
        return "no_answer"
    if _NO_ANSWER_RE.search(narrative or ""):
        return "no_answer"
    return "no_threat"


def grid_reason(text: str | None) -> str:
    """One sentence about the grid, from a failed run's stored sentence."""
    lowered = (text or "").lower()
    for needle, sentence in _GRID_REASONS:
        if needle in lowered:
            return sentence
    return _DEFAULT_GRID_REASON


def could_not_run_reason(status: str, findings: Any, narrative: str | None) -> str:
    """Why a hunt could not run, in one or two short sentences.

    A stopped hunt names its stop. A hunt whose every finding is a failed
    query names what the grid did, and the next step.
    """
    if status == "cancelled":
        return "A cancel request stopped this hunt before it finished."
    if status == "interrupted":
        return "A service restart stopped this hunt before it finished."
    if status == "error":
        text = (narrative or "").strip()
        return text or "The hunt ended in an error. The server recorded no reason."
    failures = [f for f in _rows(findings) if is_run_failure(f)]
    # A hunt stored before the plain words keeps the grid client's raw text,
    # and the raw text read as a refused query (V1-H7).
    source = " ".join(restate_failure(f.get("detail")) for f in failures) or (narrative or "")
    return f"{grid_reason(source)} {_HUNT_AGAIN}"


def _gap_sentence(narrative: str | None) -> str | None:
    """The narrative's own sentence that says it could not answer."""
    for sentence in _SENTENCE_RE.split((narrative or "").strip()):
        if _NO_ANSWER_RE.search(sentence):
            return sentence.strip()
    return None


def _gap_titles(findings: Any) -> list[str]:
    return [
        str(f.get("title") or "").strip()
        for f in _rows(findings)
        if finding_category(f) == "visibility_gap"
        and not is_run_failure(f)
        and str(f.get("title") or "").strip()
    ]


def outcome_headline(
    outcome: str, status: str, findings: Any, narrative: str | None = None
) -> str | None:
    """The sentence under the outcome label, or None when the label says it all.

    ``could_not_run`` names the stop or the grid's refusal. ``no_answer`` names
    the gap: the narrative's own sentence when it states one, else the
    telemetry the gap findings name. A gap blamed on the age of the data adds
    how far back the grid answers.
    """
    if outcome == "could_not_run":
        return could_not_run_reason(status, findings, narrative)
    if outcome != "no_answer":
        return None
    sentence = _gap_sentence(narrative)
    if sentence:
        sentence = sentence if sentence.endswith((".", "!", "?")) else f"{sentence}."
        if _DATA_AGE_RE.search(sentence):
            return f"{sentence} {GRID_WINDOW_SENTENCE}"
        return sentence
    titles = _gap_titles(findings)
    if titles:
        named = titles[0].rstrip(".")
        more = len(titles) - 1
        tail = f" The report names {more} more gap{'' if more == 1 else 's'}." if more else ""
        return f"The hunt could not see all of the data it needs. Gap: {named}.{tail}"
    failures = [f for f in _rows(findings) if is_run_failure(f)]
    if failures:
        return "A part of the run could not reach the grid. The result is incomplete."
    return None
