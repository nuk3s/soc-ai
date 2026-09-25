"""Turn spec candidates into findings, with no model call.

A candidate already knows everything a finding needs: what fired, on which
entity, over which documents. Asking a language model to restate that would add
cost, latency and a chance of embellishment, and would make continuous hunting
unaffordable — which is the whole reason the declarative catalog exists.

So the narrative here is composed from the spec's OWN prose. The title comes
from the spec's title, the detail from its description, and every sentence a
reader sees was written by a human and reviewed in a merge request. A finding
from this path cannot hallucinate, because nothing generative runs.

The findings are the same shape the hunt agent emits, so everything downstream
works unchanged: the same store, the same UI, and the same promotion route that
resolves a citation to a real document and runs the normal triage pipeline on it.

Every finding composed here is two things joined: the spec's prose, written and
reviewed when the detection was authored, and one or two sentences about THIS
run. Read as one paragraph the author's measurements pass for fresh ones and go
quietly false as the grid moves, so the detail page sets them apart. It used to
find the seam by matching the sentence a candidate finding ends with, which no
visibility-gap finding contains, and on a quiet grid every catalog finding is a
visibility gap. The composer knows exactly where the seam is, because it is the
one that appended the second half, so it carries it: ``spec_rationale`` is the
authored half, and it is always the head of ``detail``. Extra keys on the dict
rather than a narrowed ``detail``, so every other reader of a report keeps the
whole sentence it has always had.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from soc_ai.hunting.execute import SpecRun
from soc_ai.hunting.spec import HuntSpec

# A spec's own severity maps straight through. The catalog levels were chosen
# per detection with its false-positive profile in mind, so re-deriving one here
# would be second-guessing the author with less information.
_LEVEL_TO_SEVERITY = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


# HuntFinding's own style rule: ~8 words / 60 characters, scannable in a list.
_TITLE_BUDGET = 60


# The runner records the exception as it was raised ("precondition:
# ConnectionTimeout caused by ..."). An analyst reading a hunt page should get
# the sentence, not the stack: the raw text stays in the log.
_ERROR_PHRASES: tuple[tuple[str, str], ...] = (
    ("timeout", "the data source did not answer in time"),
    ("timed out", "the data source did not answer in time"),
    ("connectionerror", "the data source did not accept a connection"),
    ("connection refused", "the data source did not accept a connection"),
    ("authenticationexception", "the data source rejected the credentials"),
    ("authorizationexception", "the data source refused the query"),
    ("search_phase_execution", "the data source rejected the query"),
)
_STAGES = ("precondition", "undecided", "detection")


def plain_error(text: str | None) -> str:
    """Say what went wrong in one plain sentence, or return the text unchanged."""
    raw = (text or "").strip()
    if not raw:
        return ""
    stage = next((s for s in _STAGES if raw.lower().startswith(s + ":")), None)
    lowered = raw.lower()
    for needle, phrase in _ERROR_PHRASES:
        if needle in lowered:
            where = f" during the {stage} query" if stage else ""
            return f"{phrase[0].upper()}{phrase[1:]}{where}."
    return raw


def _title(spec: HuntSpec, scope_key: str) -> str:
    """``<spec title> — <entity>``, trimming the TITLE rather than the entity.

    The entity is the most identifying part: two findings from the same spec are
    told apart only by it. A first version truncated the composed string, which
    cut ``localuser`` down to ``local`` and made the two indistinguishable.
    """
    tail = f" — {scope_key}"
    room = _TITLE_BUDGET - len(tail)
    if room < 12:
        # A pathologically long entity gets the whole budget; a truncated title
        # is recoverable from the finding body, a truncated entity is not.
        return scope_key[:_TITLE_BUDGET]
    head = spec.title if len(spec.title) <= room else spec.title[: room - 1].rstrip() + "…"
    return f"{head}{tail}"


def _sentence(spec: HuntSpec) -> str:
    """The spec's description, collapsed to prose for a finding body."""
    text = " ".join((spec.description or spec.title).split())
    return text or spec.title


def _span(minutes: int) -> str:
    """A look-back in the largest whole unit it divides into."""
    for unit, size in (("day", 24 * 60), ("hour", 60)):
        if minutes % size == 0:
            count = minutes // size
            return f"{count} {unit}" if count == 1 else f"{count} {unit}s"
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


def _precondition_window(spec: HuntSpec, run: SpecRun) -> str:
    """The window the precondition asked about, as a phrase for a sentence.

    The RUN decides whether the window was widened and the spec supplies the
    readable duration. Composing it from the spec alone would describe a window
    that run never asked about the moment somebody edits the look-back, and the
    sentence is the whole point: "no decoy telemetry in the last hour" is false
    about a spec that asked about ninety days, and it is the sentence an analyst
    reads about the one marker meant to be believed.
    """
    if run.precondition_since and run.precondition_since != run.since:
        if spec.precondition_lookback_minutes:
            return f"in the {_span(spec.precondition_lookback_minutes)} to {run.until}"
        # The run widened and the spec no longer says by how much, so the bound
        # it queried is stated as it was queried rather than described.
        return f"between {run.precondition_since} and {run.until}"
    return f"between {run.since} and {run.until}"


def _undecided_clause(spec: HuntSpec, run: SpecRun) -> str:
    """What was actually missing from the documents nothing could decide.

    The undecided query asks for documents missing AT LEAST ONE of the fields
    the exclusions read, so a sentence that joins every one of them and says
    the documents carry no value for all of them is false the moment a spec has
    two. Measured on a range with a reconstructed two-exclusion spec: 52
    undecided documents, all 52 carrying the first field the sentence named.
    The remedy the product offers is a per-clause declaration, so naming the
    wrong clause sends the analyst to change a line that will not move the
    number, and the gap looks handled when it is not.

    So the run's per-field counts decide the wording:

    * exactly one field missing, which is every shipped spec: name it, plainly.
    * several: name each with how many of the documents lacked it, and say "at
      least one", because the populations overlap and a document lacking both
      is counted in both.
    * no breakdown from the grid: fall back to the weakest claim the query
      itself guarantees, naming no field as absent on its own.
    """
    missing = [(f, n) for f, n in run.undecided_by_field if n > 0]
    if len(missing) == 1:
        return f"carry no value for {missing[0][0]}, and one of the spec's exclusions reads it"
    if missing:
        counted = ", ".join(f"{f} on {n}" for f, n in missing)
        return f"are each missing at least one of the fields the exclusions read: {counted}"
    # A ``profile`` spec carries no detection block and so names no exclusion.
    # It cannot produce an undecided document either, because the sweep answers
    # it from a stored baseline. This builder still reads the empty list rather
    # than raising: a findings builder must not be the thing that fails a
    # sweep, and the sentence below states only what is true.
    fields = spec.detection.exclusion_fields() if spec.detection is not None else []
    if len(fields) == 1:
        return f"carry no value for {fields[0]}, and one of the spec's exclusions reads it"
    if not fields:
        # No field list to name, from the run or from the spec. The old
        # sentence ended on a colon with nothing after it.
        return "are each missing a field one of the spec's exclusions reads"
    return (
        "are each missing at least one of these fields, and the grid did not say "
        f"which: {', '.join(fields)}"
    )


def candidate_findings(spec: HuntSpec, run: SpecRun) -> list[dict[str, Any]]:
    """One finding per candidate, in the shape the hunt report already uses.

    A blind run produces a ``visibility_gap`` finding rather than nothing. That
    is the whole reason the precondition exists: "the spec found nothing" and
    "the spec could not see" are opposite facts, and an empty findings list
    would render as the first while meaning the second.
    """
    if run.error is not None:
        return [
            {
                "title": f"{spec.title}: could not run",
                "detail": (
                    f"The {spec.id} hunt spec failed against the grid. The result is "
                    f"unknown. {plain_error(run.error)}"
                ),
                "severity": "medium",
                "category": "visibility_gap",
                "hosts": [],
                "citations": [],
            }
        ]

    if run.blind:
        return [
            {
                "title": f"No telemetry for {spec.id}",
                "spec_rationale": _sentence(spec),
                "detail": (
                    f"{_sentence(spec)} This spec found nothing. It also could not see. "
                    "Its precondition matched no documents at all "
                    f"{_precondition_window(spec, run)}. The telemetry it reads is "
                    "absent from this grid. Treat this as a coverage gap. This is not "
                    "an all-clear."
                ),
                "severity": "medium",
                "category": "visibility_gap",
                "hosts": [],
                "citations": [],
            }
        ]

    findings: list[dict[str, Any]] = []

    if run.unattributed_docs:
        # The detection is right and the GROUPING is not: these documents
        # matched but carry no value for the scope field, so they produced no
        # bucket. Reporting them as nothing found would be an all-clear over
        # real evidence — and the DCSync event whose subject principal cannot
        # be attributed is precisely the one worth reading.
        findings.append(
            {
                "title": f"Unattributable matches for {spec.id}"[:60],
                "spec_rationale": _sentence(spec),
                "detail": (
                    f"{_sentence(spec)} {run.unattributed_docs} document(s) matched this "
                    f"detection. The documents carry no value for its scope field "
                    f"{spec.scope_field}. Nothing can group them into a candidate. "
                    "No entity can be named. This is a mapping or coverage problem. "
                    "This is not a clean result."
                ),
                "severity": "medium",
                "category": "visibility_gap",
                "hosts": [],
                "citations": [],
            }
        )

    if run.undecided_docs:
        # Not a match and not a non-match. These documents satisfy the
        # detection's positive clauses and are missing a field one of its
        # exclusions reads, so nothing in the spec can say whether that
        # exclusion applies to them. Reporting the run without them would be an
        # all-clear over the exact population a sparse field hides: on the
        # development range a 4624 spec excluding machine accounts discarded
        # 5,240 network logons this way and its precondition still said it could
        # see.
        findings.append(
            {
                "title": f"Unevaluated exclusions for {spec.id}"[:60],
                "spec_rationale": _sentence(spec),
                "detail": (
                    f"{_sentence(spec)} {run.undecided_docs} document(s) matched this "
                    f"detection's positive clauses. The documents "
                    f"{_undecided_clause(spec, run)}. The spec could not match them and "
                    "could not rule them out. If the grid ships a second copy of this "
                    "event without that field, pin event.dataset in the spec. If this "
                    "event type never populates the field, declare it on that clause "
                    "with absent: match. This is not a clean result."
                ),
                "severity": "medium",
                "category": "visibility_gap",
                "hosts": [],
                "citations": [],
            }
        )

    if run.truncated_docs:
        findings.append(
            {
                "title": f"Too many scopes for {spec.id}"[:60],
                "spec_rationale": _sentence(spec),
                "detail": (
                    f"{_sentence(spec)} Elasticsearch returned the bucket ceiling. It left "
                    f"{run.truncated_docs} further document(s) out of the grouping. This "
                    "run did not read every document. Narrow the spec or the window."
                ),
                "severity": "medium",
                "category": "visibility_gap",
                "hosts": [],
                "citations": [],
            }
        )

    for candidate in run.candidates:
        docs = candidate.doc_count
        span = ""
        if candidate.first_seen and candidate.last_seen:
            span = (
                f" The first is at {candidate.first_seen}. The last is at {candidate.last_seen}."
                if candidate.first_seen != candidate.last_seen
                else f" The match is at {candidate.first_seen}."
            )
        findings.append(
            {
                "title": _title(spec, candidate.scope_key),
                "spec_rationale": _sentence(spec),
                "detail": (
                    f"{_sentence(spec)} The spec matched {docs} document"
                    f"{'' if docs == 1 else 's'} for {candidate.scope_kind} "
                    f"{candidate.scope_key}.{span}"
                ),
                # The card says "3 of 4 matching documents" beside the citation
                # chips, because a bucket over MAX_SAMPLE_IDS cites a sample.
                # It read the 4 back out of the sentence above; the number is
                # right here.
                "matched_docs": docs,
                "severity": _LEVEL_TO_SEVERITY.get(spec.level, "medium"),
                "category": "threat",
                "hosts": [candidate.scope_key] if candidate.scope_kind in {"host", "ip"} else [],
                # Real document ids. The promotion route resolves one of these
                # to an anchor and runs triage on it, so a synthesised or
                # placeholder citation would break the whole path.
                "citations": list(candidate.sample_ids),
                "mitre_techniques": list(spec.attack),
            }
        )
    return findings


def spec_report(spec: HuntSpec, run: SpecRun) -> dict[str, Any]:
    """A HuntReport-shaped dict for a spec run.

    ``confidence`` is deliberately absent rather than set to a number. A
    predicate either matched or it did not; attaching a confidence would invent
    a probability the detection never computed, and this codebase treats an
    asserted number it did not obtain as worse than no number.
    """
    findings = candidate_findings(spec, run)
    hosts = sorted({h for f in findings for h in f.get("hosts", [])})
    if run.blind:
        narrative = (
            f"{spec.title}: no telemetry. The spec's precondition matched nothing "
            f"{_precondition_window(spec, run)}. This is a coverage gap."
        )
    elif run.error is not None:
        narrative = f"{spec.title}: the run failed. The result is unknown. {plain_error(run.error)}"
    elif findings:
        # Only facts this run actually established. The old version summed
        # query truncation, budget pressure and already-handled conditions into
        # one number labelled "held back by the budget", so a run that held back
        # nothing could report three.
        extra = (
            f" The bucket ceiling left {run.truncated_docs} document(s) out of the grouping."
            if run.truncated_docs
            else ""
        )
        extra += (
            f" The spec could not evaluate its exclusions against {run.undecided_docs} "
            "document(s). It did not match them and did not rule them out."
            if run.undecided_docs
            else ""
        )
        narrative = (
            f"{spec.title}: {len(findings)} finding(s) from {run.matched_docs} matching "
            f"document(s) between {run.since} and {run.until}. The spec ran with no "
            f"model call.{extra}"
        )
    else:
        # The precondition's window is stated only when it differs from the
        # detection's, because "it could see" is a claim about a window and a
        # spec with a look-back could see over a longer one than it swept.
        seen_over = (
            ""
            if run.precondition_since in ("", run.since)
            else f" {_precondition_window(spec, run)}"
        )
        narrative = (
            f"{spec.title}: nothing matched between {run.since} and {run.until}. The spec "
            f"could see. Its precondition matched {run.precondition_docs} document(s)"
            f"{seen_over}. This is a clean result."
        )

    return {
        "findings": findings,
        "narrative": narrative,
        "affected_hosts": hosts,
        "mitre_techniques": list(spec.attack),
        "recommended_actions": [],
    }


# Legacy reports predate the finding ``category`` field. A coverage finding
# mis-read as a threat produces the trust-destroying "Malicious activity found"
# headline over a telemetry gap, so the gap category is inferred for old rows.
_GAP_TITLE_RE = re.compile(
    r"visibility gap|telemetry|coverage gap|blind spot|no .*(logs|logging|data)|"
    r"data.source.* (absent|missing|unavailable)|could not run",
    re.IGNORECASE,
)


def finding_category(finding: Mapping[str, Any]) -> str:
    """``threat`` | ``visibility_gap`` | ``observation`` for one finding dict.

    One classifier, owned here, because two surfaces read it: the hunt detail
    page (which already refused to dress a gap up as a threat) and the
    notifications bell, which did not — "Hunt finished — 1 finding: RC4 service
    ticket…" led to a banner reading NO THREAT OBSERVED and a finding titled
    "could not run". The most alarming string in the app, meaning a timed-out
    query.
    """
    raw = str(finding.get("category") or "").strip().lower()
    if raw in ("threat", "visibility_gap", "observation"):
        return raw
    return "visibility_gap" if _GAP_TITLE_RE.search(str(finding.get("title") or "")) else "threat"


def threat_finding_count(findings: Any) -> int:
    """How many of a report's findings are actual threats. Zero for non-lists."""
    if not isinstance(findings, list):
        return 0
    return sum(1 for f in findings if isinstance(f, Mapping) and finding_category(f) == "threat")


def hunt_outcome(status: str, findings: Any) -> tuple[int, str]:
    """(threat findings, outcome) for a hunt row.

    ``outcome`` is empty unless the hunt completed; then ``threats``, ``clean``,
    ``gap`` (the hunt saw nothing but blindness) or ``failed`` (a query raised).
    The Hunts page paints from this, and the lead store settles a lead from
    it, so the two can never disagree about what a hunt found.

    A gap finding beside observation findings is a caveat, not the outcome.
    A hunt that looked at the host, explained what it saw and found no
    threat is clean even when it notes what it could not inspect. Only a hunt
    whose every finding is a gap reads as ``gap``.
    """
    if not isinstance(findings, list):
        return 0, ""
    rows = [f for f in findings if isinstance(f, dict)]
    threats = threat_finding_count(rows)
    if status != "complete":
        return threats, ""
    if threats:
        return threats, "threats"
    gaps = [f for f in rows if finding_category(f) == "visibility_gap"]
    if not gaps:
        return 0, "clean"
    if any(str(f.get("title") or "").endswith(": could not run") for f in gaps):
        return 0, "failed"
    return 0, "gap" if len(gaps) == len(rows) else "clean"


__all__ = [
    "candidate_findings",
    "finding_category",
    "hunt_outcome",
    "spec_report",
    "threat_finding_count",
]
