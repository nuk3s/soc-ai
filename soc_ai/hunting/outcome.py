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
  is a visibility gap, a part of the run failed, or the hunt holds no
  observation finding and the narrative says that the answer can be neither
  confirmed nor ruled out.
* ``could_not_run``: the hunt stopped (error, cancel or restart), or every
  finding is the record that a query failed.
* ``running``: the hunt has not ended.

A hunt investigates its subject findings as part of the hunt (2026-10-07,
:mod:`soc_ai.webui.hunt_findings`). Three outcomes come from that phase:

* ``investigating``: the hunt landed its report and the investigations of its
  findings run. The label counts them: "Investigating 2 of 3 findings".
* ``threats_confirmed``: at least one investigation of a finding reached the
  verdict true positive. The label counts them: "2 confirmed · 1 not judged ·
  of 3 threat findings".
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

from soc_ai.hunting.findings import (
    finding_category,
    hunt_outcome,
    plain_error,
    restate_failure,
)

__all__ = [
    "DEGRADED_KEY",
    "DEGRADED_LABEL",
    "NO_REASONING_REASON",
    "OUTCOMES",
    "OUTCOME_LABEL",
    "UNKNOWN_FAILURE",
    "FindingVerdicts",
    "could_not_run_reason",
    "degraded_note",
    "degraded_reason",
    "failure_cause",
    "grid_reason",
    "is_run_failure",
    "outcome_headline",
    "outcome_label",
    "public_outcome",
    "restate_hunt_failure",
    "stored_failure_detail",
    "threat_count_sentence",
]


@dataclass(frozen=True)
class FindingVerdicts:
    """What the investigations of a hunt's subject findings concluded.

    ``total`` counts the subject findings. ``investigated`` counts those whose
    investigation ended, a failed one included. ``decided`` counts those whose
    investigation reached a verdict. ``threats`` counts the true positives.
    ``false_positives`` counts the false positives.
    ``findings`` counts every finding of the report, a failed-query record
    excluded. ``threat_findings`` counts the threat findings of the report, a
    subject or not. Both are 0 when the caller did not read the report.

    ``held`` counts the threat findings that a campaign holds
    (:mod:`soc_ai.hunting.campaign_hold`). Such a finding restates the
    activity of the campaign, and it has no investigation of its own. It is
    in no other count: ``total`` and ``threat_findings`` leave it out, so it
    reads neither as confirmed nor as not judged.
    """

    total: int = 0
    investigated: int = 0
    decided: int = 0
    threats: int = 0
    findings: int = 0
    false_positives: int = 0
    threat_findings: int = 0
    held: int = 0

    @property
    def threat_total(self) -> int:
        """The threat findings the count sentence counts. A subject is a
        threat finding, so the subject count is the floor."""
        return max(self.threat_findings, self.total)

    @property
    def not_judged(self) -> int:
        """The threat findings with no true positive and no false positive:
        a failed or cancelled run, a run that ended in needs more info or
        inconclusive, a finding with no run, and a finding that restates an
        earlier finding that no longer answers for it."""
        return max(0, self.threat_total - self.threats - self.false_positives)


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


def threat_count_sentence(verdicts: FindingVerdicts) -> str:
    """The one threat count format of the console.

    "3 confirmed · 1 not judged · of 4 threat findings". A false positive
    count joins the sentence when there is one, so the parts add up to the
    threat findings: "2 confirmed · 1 false positive · 1 not judged · of 4
    threat findings". The hunt list, the hunt page, the lead pages and the
    bell print these words. A row read "7 · 4 threat" beside "3 of 7
    findings are threats" before this (review 2026-11-12).
    """
    total = verdicts.threat_total
    parts = [f"{verdicts.threats} confirmed"]
    if verdicts.false_positives:
        noun = "false positive" if verdicts.false_positives == 1 else "false positives"
        parts.append(f"{verdicts.false_positives} {noun}")
    parts.append(f"{verdicts.not_judged} not judged")
    parts.append(f"of {total} threat finding" if total == 1 else f"of {total} threat findings")
    return " · ".join(parts)


def outcome_label(outcome: str, verdicts: FindingVerdicts | None = None) -> str:
    """The words for one outcome, with the counts when the outcome has them.

    ``investigating`` reads "Investigating 2 of 3 findings": the subject
    findings. ``threats_confirmed`` reads the count sentence of
    :func:`threat_count_sentence`. ``no_threat_confirmed`` reads it too when a
    threat finding is not judged: "No threat confirmed" over a failed run is
    not a clean answer. Without a summary each reads its plain label.
    """
    if verdicts is not None and verdicts.total > 0:
        total = verdicts.total
        if outcome == "investigating":
            return f"Investigating {verdicts.investigated} of {_findings(total)}"
        if outcome == "threats_confirmed":
            return threat_count_sentence(verdicts)
        if outcome == "no_threat_confirmed" and verdicts.not_judged:
            return threat_count_sentence(verdicts)
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
    # A threat finding that a campaign holds is no new threat of this hunt.
    if threats - (verdicts.held if verdicts is not None else 0) > 0:
        return "threat_found"
    if rows and all(is_run_failure(f) for f in rows):
        return "could_not_run"
    if internal in ("gap", "failed"):
        return "no_answer"
    # The narrative test decides only for a hunt that holds no conclusion of
    # its own. A hunt with an observation finding looked, explained what it
    # saw and found no threat. Its "cannot be confirmed or ruled out" sentence
    # names a coverage limit, the same caveat a gap finding beside an
    # observation is in hunt_outcome. Prod hunt 01M7G85Z... read "No answer"
    # over 8 observations and "found no malicious activity" (dogfood N2).
    concluded = any(finding_category(f) != "visibility_gap" for f in rows)
    if not concluded and _NO_ANSWER_RE.search(narrative or ""):
        return "no_answer"
    return "no_threat"


def grid_reason(text: str | None) -> str:
    """One sentence about the grid, from a failed run's stored sentence."""
    lowered = (text or "").lower()
    for needle, sentence in _GRID_REASONS:
        if needle in lowered:
            return sentence
    return _DEFAULT_GRID_REASON


# ── Why a hunt was lost, in plain words ─────────────────────────────────────
#
# The page of prod hunt 01M69M3FVK9D6KECGCAXJK9F6Z read "The hunt failed:
# UsageLimitExceeded. hunt hit its budget and partial synthesis failed: The
# next tool call(s) would exceed the tool_calls_limit of 0 (tool_calls=2)."
# An analyst cannot act on that text. The page states the cause in plain
# words, and the raw error stays behind a toggle (``HuntOut.errorDetail``).

# The runner's own words for a hunt that reached a limit and then got no
# report (soc_ai.api.hunt_runner._synthesis_failed_event).
_SYNTHESIS_MARK = "partial synthesis failed"
_TIME_LIMIT_MARK = "hit its time limit"

_GATEWAY_NEXT = "Check the model gateway in Settings. Then hunt again."
_HUNT_AGAIN_PLAIN = "Hunt again."
# The cause of an error with a shape this build does not know.
UNKNOWN_FAILURE = "The hunt stopped on an error. The technical detail holds the text of the error."

# The narrative an older build stored for an errored hunt: "The hunt failed:
# <exception name>. <raw message>" (soc_ai.api.hunt_recorder.error_narrative).
_STORED_FAILURE_RE = re.compile(
    r"^The hunt failed: (?P<type>[A-Za-z_][A-Za-z0-9_]*)\.(?:\s+(?P<message>.*))?$", re.DOTALL
)

_STATUS_CODE_RE = re.compile(r"status_code:\s*(\d{3})")


# The marks of an error that the model path raised. The grid client words a
# refused connection the same way, so the gateway causes apply only to an
# error that carries one of these, or to a failed report writer, which calls
# the model and nothing else.
_MODEL_MARKS: tuple[str, ...] = (
    "modelhttperror",
    "modelapierror",
    "apiconnectionerror",
    "apitimeouterror",
    "apistatuserror",
    "ratelimiterror",
    "model_name:",
    "litellm",
)


def _gateway_cause(text: str) -> str | None:
    """What the model gateway did, from the lowered error text, or None.

    The status code decides when the error holds one. A body can quote any
    text, and "rate limit" in the body of a 400 is no rate limit.
    """
    if any(
        needle in text
        for needle in (
            "cannot connect to host",
            "connect call failed",
            "apiconnectionerror",
            "connection error",
            "all connection attempts failed",
        )
    ):
        return "The model backend did not accept a connection."
    status = _STATUS_CODE_RE.search(text)
    code = int(status.group(1)) if status else 0
    if code:
        if code == 429:
            return "The model gateway refused the request. The rate limit or the quota is used up."
        if code in (401, 403):
            return "The model gateway refused the credentials."
        if code >= 500:
            return f"The model gateway returned an error with status {code}."
        if code >= 400:
            return f"The model gateway refused the request with status {code}."
        return None
    if "ratelimiterror" in text:
        return "The model gateway refused the request. The rate limit or the quota is used up."
    if "authenticationerror" in text:
        return "The model gateway refused the credentials."
    if "apitimeouterror" in text or "request timed out" in text:
        return "The model did not answer in time."
    return None


# The redaction guard stopped a prompt (soc_ai.agent.egress_guard.EgressResidueError).
_RESIDUE_MARKS: tuple[str, ...] = ("egressresidueerror", "survived sanitization")
_RESIDUE_FACT = (
    "The text holds an internal name that the redaction cannot remove, so no text went to "
    "the model."
)
_RESIDUE_NEXT = "Check the redaction settings. Then hunt again."
# The marks of an error that the grid client raised.
_GRID_MARKS: tuple[str, ...] = (
    "connectiontimeout",
    "elastic",
    "transporterror",
    "shards",
    "precondition:",
    "undecided:",
    "detection:",
)
_UNNAMED_TIMEOUT = (
    "A request of the hunt did not answer in time. The error text does not name the service. "
    "Hunt again."
)


def _synthesis_cause(text: str, gateway: str | None) -> str:
    """The cause of a hunt that reached a limit and then got no report.

    One sentence for each way the report writer can stop, because each one
    has another remedy: the redaction stopped it before a model call, the
    gateway failed, the model answered with a tool call, the model used up
    its requests, or it wrote nothing that soc-ai can read.
    """
    limit = "its time limit" if _TIME_LIMIT_MARK in text else "its budget"
    head = f"The hunt reached {limit} before it wrote a report."
    trace = "The trace shows what the hunt read."
    if any(mark in text for mark in _RESIDUE_MARKS):
        return (
            f"{head} The redaction then stopped the report writer. {_RESIDUE_FACT} {_RESIDUE_NEXT}"
        )
    if gateway:
        return f"{head} {gateway} The hunt has no report. {_GATEWAY_NEXT}"
    if "tool_calls_limit" in text:
        return (
            f"{head} The model then answered with a tool call and wrote no report. "
            f"{trace} {_HUNT_AGAIN_PLAIN}"
        )
    if "request_limit" in text:
        return (
            f"{head} The model then used every request of the report writer and wrote no "
            f"report. {trace} {_HUNT_AGAIN_PLAIN}"
        )
    return f"{head} The model then wrote no report. {trace} {_HUNT_AGAIN_PLAIN}"


def failure_cause(message: str | None, exc_type: str | None) -> str:
    """Why a hunt was lost, in plain sentences with the next step.

    Reads the exception name and its message. The classes come from the lost
    hunts of prod: a hunt that reached a limit and then got no report, a
    prompt that the redaction stopped, a model gateway that failed, a model
    that wrote no report, and the grid shapes that
    :func:`soc_ai.hunting.findings.plain_error` already words. Each class
    states what happened and nothing else. Any other error gives
    :data:`UNKNOWN_FAILURE`. The raw text is never in the answer.
    """
    raw = (message or "").strip()
    name = (exc_type or "").strip()
    text = f"{name} {raw}".lower()
    from_model = _SYNTHESIS_MARK in text or any(mark in text for mark in _MODEL_MARKS)
    gateway = _gateway_cause(text) if from_model else None
    if _SYNTHESIS_MARK in text:
        return _synthesis_cause(text, gateway)
    if any(mark in text for mark in _RESIDUE_MARKS):
        return (
            "The redaction stopped the hunt before the model read the prompt. "
            f"{_RESIDUE_FACT} {_RESIDUE_NEXT}"
        )
    if gateway:
        return f"{gateway} {_GATEWAY_NEXT}"
    if name == "EmptyResult" or "produced no report" in text:
        return f"The model ended the hunt and wrote no report. {_HUNT_AGAIN_PLAIN}"
    if "unexpectedmodelbehavior" in text:
        return (
            "The model did not write a report that soc-ai can read. "
            f"{_HUNT_AGAIN_PLAIN} If the next hunt fails the same way, check the model in Settings."
        )
    if "usagelimitexceeded" in text:
        return f"The hunt reached its budget and wrote no report. {_HUNT_AGAIN_PLAIN}"
    if ("timeout" in text or "timed out" in text) and not any(m in text for m in _GRID_MARKS):
        # A timeout that names no service. The grid client and the model
        # client both raise one, and the text does not say which.
        return _UNNAMED_TIMEOUT
    plain = plain_error(raw)
    if plain and plain != raw:
        return plain
    return UNKNOWN_FAILURE


def restate_hunt_failure(narrative: str | None) -> str:
    """The stored sentence of an errored hunt, as the page reads it.

    A row stored before the plain causes holds "The hunt failed: <exception
    name>. <raw message>". That one shape is mapped on read
    (:func:`failure_cause`), so an old row reads right with no rewrite of the
    store. Any other text comes back as it was stored.
    """
    text = (narrative or "").strip()
    stored = _STORED_FAILURE_RE.match(text)
    if stored is None:
        return text
    return failure_cause(stored.group("message"), stored.group("type"))


def stored_failure_detail(narrative: str | None) -> str | None:
    """The raw error an older build stored in the narrative, or None.

    The technical detail of a row that holds no ``error`` event.
    """
    stored = _STORED_FAILURE_RE.match((narrative or "").strip())
    if stored is None:
        return None
    message = (stored.group("message") or "").strip()
    return f"{stored.group('type')}: {message}" if message else stored.group("type")


# ── The degraded mark of a hunt that completed (C4) ─────────────────────────
#
# A hunt can complete and still be weaker than a normal run. The runner
# records that on the stored report under DEGRADED_KEY, as
# ``{"reason": <code>, ...}``. It is apart from the blind run of the
# evidence-count gate, which finalizes as an error.

DEGRADED_KEY = "degraded"
# The model responses of the hunt carried no reasoning trace, and the earlier
# hunts of this deployment carried one.
NO_REASONING_REASON = "no_reasoning_trace"
DEGRADED_LABEL = "Degraded"
_DEGRADED_NOTES: dict[str, str] = {
    NO_REASONING_REASON: (
        "The model returned no reasoning trace in this hunt. Earlier hunts carried one. "
        "Check each finding against its evidence."
    ),
}
_DEGRADED_DEFAULT_NOTE = (
    "This hunt ran in a degraded state. Check each finding against its evidence."
)


def degraded_reason(report: Any) -> str | None:
    """The reason code of a completed hunt's degraded mark, or None."""
    if not isinstance(report, Mapping):
        return None
    mark = report.get(DEGRADED_KEY)
    if not isinstance(mark, Mapping):
        return None
    reason = str(mark.get("reason") or "").strip()
    return reason or None


def degraded_note(reason: str | None) -> str | None:
    """The sentence the page prints for a degraded mark, or None with no mark."""
    if not reason:
        return None
    return _DEGRADED_NOTES.get(reason, _DEGRADED_DEFAULT_NOTE)


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
        text = restate_hunt_failure(narrative)
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
