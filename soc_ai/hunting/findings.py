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

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
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


# A finding title is never cut. The spec title is reviewed YAML and the console
# wraps a long title. The budget was 60 characters, then 500, and the store held
# titles such as "Directory replication requested by a non-machin… — localuser".
# The rest of the title was then nowhere, because the cut happened before the
# store. The owner banned the ellipsis cut (2026-10-07).


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

# The grid client's partial-read error (soc_ai.so_client.elastic). The model
# reads that text as a tool error, so it stays as it is there. The console
# reads this sentence. It carried the index patterns, and the narrative
# renderer read their asterisks as emphasis (R3-D13).
_PARTIAL_SHARDS_RE = re.compile(r"partial search results\b.*?(\d+) of (\d+) shards failed", re.I)


def plain_error(text: str | None) -> str:
    """Say what went wrong in plain sentences, or return the text unchanged."""
    raw = (text or "").strip()
    if not raw:
        return ""
    stage = next((s for s in _STAGES if raw.lower().startswith(s + ":")), None)
    where = f" during the {stage} query" if stage else ""
    partial = _PARTIAL_SHARDS_RE.search(raw)
    if partial:
        failed, total = int(partial.group(1)), int(partial.group(2))
        return (
            f"The grid answered from {max(0, total - failed)} of {total} shards{where}. "
            "The answer is incomplete. An empty answer means that the result is unknown."
        )
    lowered = raw.lower()
    for needle, phrase in _ERROR_PHRASES:
        if needle in lowered:
            return f"{phrase[0].upper()}{phrase[1:]}{where}."
    return raw


# The head of a failed-run finding before 2026-10-19 (R3 STE). The composer
# writes "The analytic <id> could not run on the grid." now.
_OLD_FAILURE_HEAD_RE = re.compile(r"^The (?P<id>\S+) hunt spec failed against the grid\.")
# The sentence that ends the composer's own words in a failed-run text. The
# raw error of the run follows it.
_UNKNOWN_MARK = "The result is unknown. "


def restate_failure(text: str | None) -> str:
    """A stored failed-run sentence of a catalog hunt, in today's words.

    The composer words a failed run in plain sentences since 2026-10-19
    (:func:`plain_error`). A hunt stored before that keeps the grid client's
    raw text: the index patterns, an em dash and "not 'nothing happened'".
    The hunt page maps that text when it reads it (dogfood 2026-10-19, V1-H7).

    Only the two shapes the composer wrote are mapped: the old head of the
    finding detail, and a raw error after "The result is unknown.". Any other
    text comes back as it was stored. The function never raises, so a stored
    value of a shape this build does not know never fails a page.
    """
    try:
        raw = "" if text is None else str(text)
        out = _OLD_FAILURE_HEAD_RE.sub(
            lambda m: f"The analytic {m.group('id')} could not run on the grid.", raw, count=1
        )
        head, mark, tail = out.partition(_UNKNOWN_MARK)
        if mark and tail.strip():
            worded = plain_error(tail)
            if worded != tail.strip():
                out = f"{head}{mark}{worded}"
        return out
    except Exception:  # a read of stored text never fails a page
        return "" if text is None else str(text)


def _title(spec: HuntSpec, scope_key: str) -> str:
    """``<spec title> — <entity>``, both whole.

    The entity is the most identifying part: two findings from the same spec are
    told apart only by it. A first version truncated the composed string, which
    cut ``localuser`` down to ``local`` and made the two indistinguishable.
    """
    return f"{spec.title} — {scope_key}"


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


def detail_sentence(details: Sequence[tuple[str, Sequence[str]]]) -> str:
    """The quoted document fields of one candidate, as one sentence.

    ``threat: Trojan:Win64/Example; action: Quarantine.`` Empty when the
    spec quotes nothing or no sample carried a value.
    """
    parts = [f"{label}: {', '.join(values)}" for label, values in details if values]
    return "; ".join(parts) + "." if parts else ""


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
                    f"The analytic {spec.id} could not run on the grid. The result is "
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
                "title": f"Unattributable matches for {spec.id}",
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
                "title": f"Unevaluated exclusions for {spec.id}",
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

    if run.role_unconfirmed_docs:
        # The role gate could not place these hosts. Dropping their documents
        # would make an unclassified server a safe harbour, and firing on them
        # would undo the scope, so the finding names the hosts and asks for the
        # one fact that decides them.
        hosts = ", ".join(run.role_unconfirmed_hosts) or "unnamed hosts"
        findings.append(
            {
                "title": f"Unconfirmed host role for {spec.id}",
                "spec_rationale": _sentence(spec),
                "detail": (
                    f"{_sentence(spec)} {run.role_unconfirmed_docs} document(s) matched "
                    f"this detection on hosts with no confirmed role: {hosts}. The "
                    f"analytic applies to {', '.join(spec.roles)}. The dossier holds no "
                    f"role for these hosts at confidence {spec.min_role_confidence:.2f} "
                    "or above. Declare the role on the host page. This is not a clean "
                    "result."
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
                "title": f"Too many scopes for {spec.id}",
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
        quoted = detail_sentence(candidate.details)
        findings.append(
            {
                "title": _title(spec, candidate.scope_key),
                "spec_rationale": _sentence(spec),
                "detail": (
                    f"{_sentence(spec)} The spec matched {docs} document"
                    f"{'' if docs == 1 else 's'} for {candidate.scope_kind} "
                    f"{candidate.scope_key}.{span}{' ' + quoted if quoted else ''}"
                ),
                # The card says "3 of 4 matching documents" beside the citation
                # chips, because a bucket over MAX_SAMPLE_IDS cites a sample.
                # It read the 4 back out of the sentence above; the number is
                # right here.
                "matched_docs": docs,
                "severity": _LEVEL_TO_SEVERITY.get(candidate.level or spec.level, "medium"),
                "category": "threat",
                "hosts": [candidate.scope_key] if candidate.scope_kind in {"host", "ip"} else [],
                # The entity the candidate is about, in the scope's own type.
                # ``hosts`` holds only a host or an address, so a user-scoped
                # candidate named its user in the title alone, and the subject
                # rule below could not read it.
                "entities": [{"kind": candidate.scope_kind, "value": candidate.scope_key}],
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
        extra += (
            f" The role gate could not place the hosts of {run.role_unconfirmed_docs} document(s)."
            if run.role_unconfirmed_docs
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


# ── The subject rule: which findings the hunt investigates ──────────────────
#
# The owner's decision (2026-10-07): a hunt investigates its findings as part
# of the hunt. A finding is a subject when it names an entity, cites a
# document, and is not a visibility gap, a failed run or a clean "nothing
# here" result. Every test below reads a structured field. The one exception
# is the clean test, which reads the title of an ``observation`` finding only:
# the schema has no field that says "nothing was found", and a threat finding
# is a subject whatever its title says.

# An Elasticsearch document id, the shape the promotion anchor accepts. A
# finding also cites prose and tool calls, and those are not documents.
DOCUMENT_ID_RE = re.compile(r"^[A-Za-z0-9_\-:.]{12,128}$")
# A tool call that a finding cites, such as 't_host_summary:<address>'. It
# passes DOCUMENT_ID_RE and it is not a document (change E, 2026-10-30). An ES
# auto-id, a Zeek uid and a community id never carry this prefix with a colon.
TOOL_CITATION_RE = re.compile(r"^t_[a-z][a-z0-9_]*:")

# The entity types a subject can name, keyed by the word a finding or a scope
# uses for them. A rule, a dataset and a decoy name no entity to investigate.
_ENTITY_KINDS: dict[str, str] = {
    "host": "host",
    "ip": "address",
    "address": "address",
    "user": "user",
    "cloud_identity": "user",
    "mailbox": "user",
    "domain": "domain",
}

# The title of an observation that states a clean result.
_CLEAN_TITLE_RE = re.compile(
    r"^\s*(?:no|nothing|none)\b"
    r"|\bno (?:evidence|sign|signs|indication|indications|trace|activity)\b"
    r"|\bnot (?:observed|found|detected|seen)\b"
    r"|\bfound nothing\b|\ball[- ]clear\b",
    re.IGNORECASE,
)

# The severity ladder, lowest first. An unknown severity ranks as medium: the
# order only decides which subject waits, never whether one is investigated.
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _address_or_host(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "host"
    return "address"


def _scalar(value: Any) -> str | None:
    """A stripped, lowercased string for a str or int value, else None."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip().lower()
    return text or None


def finding_entities(finding: Mapping[str, Any]) -> list[tuple[str, str]]:
    """The entities one finding names, as ``(type, value)`` pairs without repeats.

    ``hosts`` holds a host name or an address. ``entities`` holds typed pairs,
    as a dict ``{"kind", "value"}`` or a two-item list. ``users`` and
    ``domains`` hold plain values. A value is stripped and lowercased, so two
    findings that name one host in two cases name one entity.
    """
    pairs: list[tuple[str, Any]] = []
    hosts = finding.get("hosts")
    for host in hosts if isinstance(hosts, list) else []:
        text = _scalar(host)
        if text is not None:
            pairs.append((_address_or_host(text), text))
    entities = finding.get("entities")
    for item in entities if isinstance(entities, list) else []:
        if isinstance(item, Mapping):
            raw_kind, value = item.get("kind"), item.get("value")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            raw_kind, value = item[0], item[1]
        else:
            continue
        kind = _ENTITY_KINDS.get(str(raw_kind or "").strip().lower())
        if kind is not None:
            pairs.append((kind, value))
    for key, kind in (("users", "user"), ("domains", "domain")):
        values = finding.get(key)
        for value in values if isinstance(values, list) else []:
            pairs.append((kind, value))
    out: list[tuple[str, str]] = []
    for kind, value in pairs:
        text = _scalar(value)
        if text is not None and (kind, text) not in out:
            out.append((kind, text))
    return out


def finding_document_ids(finding: Mapping[str, Any]) -> list[str]:
    """The document ids a finding cites, in order, without repeats.

    A tool-call citation (:data:`TOOL_CITATION_RE`) is not a document.
    """
    citations = finding.get("citations")
    out: list[str] = []
    for c in citations if isinstance(citations, list) else []:
        if isinstance(c, bool) or not isinstance(c, (str, int)):
            continue
        text = str(c).strip()
        if DOCUMENT_ID_RE.match(text) and not TOOL_CITATION_RE.match(text) and text not in out:
            out.append(text)
    return out


def is_clean_finding(finding: Mapping[str, Any]) -> bool:
    """True for an observation that states a clean "nothing here" result."""
    if finding_category(finding) != "observation":
        return False
    return bool(_CLEAN_TITLE_RE.search(str(finding.get("title") or "")))


def is_run_failure_finding(finding: Mapping[str, Any]) -> bool:
    """True for the finding that records a failed query and nothing else."""
    title = str(finding.get("title") or "")
    return finding_category(finding) == "visibility_gap" and title.endswith(": could not run")


def finding_is_subject(finding: Any) -> bool:
    """Whether the hunt investigates this finding.

    A subject is a threat finding that names at least one entity (a host, an
    address, a user or a domain). A visibility gap, a failed run and an
    observation are never subjects: a gap and a failure name no activity, and
    an observation claims no threat. The range hunt of lead 5 (2026-10-19)
    linked the observation "All abuse is historical" to the investigation of
    a threat on the same hosts, and the card read that verdict as its own.

    A citation is not required. The investigation runs on the document the
    finding cites, else on the evidence of the lead the hunt was started on.
    A finding with no document to run on is still a subject: the phase
    reports that it could not open the investigation, and the analyst sees
    why. A threat the model named without a citation is the one to check,
    not the one to skip (owner, 2026-10-07).
    """
    if not isinstance(finding, Mapping):
        return False
    if finding_category(finding) != "threat" or is_run_failure_finding(finding):
        return False
    return bool(finding_entities(finding))


def subject_fingerprint(finding: Mapping[str, Any]) -> str | None:
    """The hunt-independent identity of a finding's subject, or None.

    The entity set and the cited document ids, sorted, hashed. Two hunts of
    one lead that find the same activity on the same documents share it, so
    the second hunt reuses the first one's investigation.

    None when the finding cites no document (change E, 2026-10-30). Such a
    finding has only its claim as identity, and the entity set alone is not a
    claim: lead 49 linked findings with different claims on one host pair to
    one investigation. A tool call in the citations is not a document.
    """
    entities = sorted({f"{kind}:{value}" for kind, value in finding_entities(finding)})
    documents = sorted(set(finding_document_ids(finding)))
    if not documents:
        return None
    body = json.dumps({"entities": entities, "documents": documents}, sort_keys=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]


def severity_rank(severity: Any) -> int:
    """The rank of a severity on the ladder. An unknown value ranks as medium."""
    return _SEVERITY_RANK.get(str(severity or "").strip().lower(), _SEVERITY_RANK["medium"])


def subject_ordinals(findings: Any) -> list[int]:
    """The ordinals of the subject findings, in priority order.

    The highest severity first, then the report's own order.
    """
    if not isinstance(findings, list):
        return []
    subjects = [
        (i, f) for i, f in enumerate(findings) if isinstance(f, Mapping) and finding_is_subject(f)
    ]
    subjects.sort(key=lambda pair: (-severity_rank(pair[1].get("severity")), pair[0]))
    return [i for i, _f in subjects]


__all__ = [
    "DOCUMENT_ID_RE",
    "TOOL_CITATION_RE",
    "candidate_findings",
    "detail_sentence",
    "finding_category",
    "finding_document_ids",
    "finding_entities",
    "finding_is_subject",
    "hunt_outcome",
    "is_clean_finding",
    "is_run_failure_finding",
    "severity_rank",
    "spec_report",
    "subject_fingerprint",
    "subject_ordinals",
    "threat_finding_count",
]
