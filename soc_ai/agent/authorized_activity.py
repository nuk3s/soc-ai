"""Authorized activity: the match of one run against the analyst's authorizations.

The owner runs exploit tests on the production grid. The analyst records the
test as authorized activity: a label, a scope and an expiry
(:mod:`soc_ai.store.authorized_activity`). This module decides whether one
run is inside a scope.

The decision is deterministic, and the triage model never reads an
authorization. The triage prompt tells the model that "an authorized-scanner
or pentest tag on the source" clears a detection. A model that read the
record would return false positive, and a confident false positive can be
acknowledged with no person in the loop. So the check runs on the finished
report, after the last gate, and it changes no verdict, no confidence and no
sentence of the model.

:func:`match` is pure. It returns one of three answers.

* :class:`Matched`: the run is inside one scope. It keeps its true positive
  verdict and carries the mark. It requests no case, raises no notification
  of its own and forms no lead.
* :class:`Outside`: the run shares an address with one scope and is not
  inside it. It gets normal handling, and one line names the part that failed.
* ``None``: the run has nothing to do with any scope.

A match needs every part, and each part is exact.

* The source address of the alert is one of the stored source addresses,
  and the Hosts data maps that address to the same machine today
  (:func:`entry_matches`). A second address of the same machine that the
  record did not store is outside.
* The destination address is the stored target address, and the Hosts data
  maps it as it did.
* The rule name of the alert equals one of the listed rule names, and the
  alert has the alert class of the scope. No prefix and no pattern matches.
* The alert time is inside the window of the scope.
* The report stays on the machines of the scope (:func:`report_beyond`).
  Each grid document it cites is between a source address and the target
  address (:func:`cited_beyond`). Each address and each known machine name
  in its text is a source or the target (:func:`named_beyond`). A report
  that cites or names a flow from the target to a third host is about more
  than the test.

A hit of a deception sensor never matches. A hunt finding never matches: a
finding has no rule, and soc-ai always judges a finding on its own. A lead
promotion judges a whole hunt and gets no answer.

A record that names a campaign lists machines and no rule. Its rules live in
:mod:`soc_ai.campaigns.authorization`: an alert investigation and a finding
investigation between its listed machines, in its period, are inside. The
match of the rule-list form skips such a record. :func:`mark_report` asks
both forms: a match of the rule-list form wins, then a campaign record, then
an outside answer of the rule-list form, then one of a campaign record.

:func:`mark_report` is the one caller on the run path
(:func:`soc_ai.api.runner.recorded_run`). Any failure there gives no mark:
the run then gets normal handling.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from soc_ai.agent.classifier import classify_alert
from soc_ai.agent.decision_templates import _alert_signals_decoy
from soc_ai.so_client.models import SoAlert
from soc_ai.store import authorized_activity as store
from soc_ai.store.authorized_activity import Scope, ScopeEntry

__all__ = [
    "AUDIT_SESSION",
    "PART_CITED",
    "PART_DECOY",
    "PART_DIRECTION",
    "PART_FINDING",
    "PART_FLOW",
    "PART_RULE",
    "PART_SOURCE",
    "PART_TARGET",
    "PART_TIME",
    "CitedDocument",
    "Matched",
    "Outside",
    "RunFlags",
    "RunMarker",
    "alert_of_run",
    "apply_to_stored_runs",
    "cited_beyond",
    "earlier_matches",
    "entry_matches",
    "evaluate",
    "evaluate_campaigns",
    "event_time",
    "index_documents",
    "mark_report",
    "match",
    "matched_mark",
    "named_beyond",
    "outside_mark",
    "outside_sentence",
    "record_expiries",
    "report_beyond",
    "report_texts",
    "rule_class_of",
    "stored_alerts",
    "stored_run_line",
]

_LOGGER = logging.getLogger(__name__)

# The session of the audit records that belong to no run.
AUDIT_SESSION = "authorized-activity"

TRUE_POSITIVE = "true_positive"

# The parts of a scope that a run can fail, in the order the line names them.
PART_DECOY = "deception_sensor"
PART_FLOW = "flow"
PART_DIRECTION = "direction"
PART_SOURCE = "source"
PART_TARGET = "target"
PART_RULE = "rule"
PART_TIME = "time"
PART_CITED = "cited_evidence"
PART_FINDING = "finding"

_PART_ORDER: tuple[str, ...] = (
    PART_FINDING,
    PART_DECOY,
    PART_FLOW,
    PART_DIRECTION,
    PART_SOURCE,
    PART_TARGET,
    PART_RULE,
    PART_TIME,
    PART_CITED,
)

# One clause for each part. The line of an outside run joins them.
_PART_CLAUSE: dict[str, str] = {
    PART_FINDING: "a finding is always judged on its own",
    PART_DECOY: "the alert is a hit of a deception sensor",
    PART_FLOW: "the alert names no source and destination pair",
    PART_DIRECTION: "the target is the source",
    PART_SOURCE: "the source is new",
    PART_TARGET: "the target is new",
    PART_RULE: "the rule is new",
    PART_TIME: "the alert time is outside the authorized time",
    PART_CITED: "the report cites activity beyond the scope",
}

# The promoted kinds, as :func:`soc_ai.api.webui.action_rules.promoted_kind`
# names them.
PROMOTED_FINDING = "finding"
PROMOTED_LEAD = "lead"

# The event kinds that carry the alert of a run, and the documents a run read.
_ALERT_CONTEXT_KINDS = ("alert_context", "enriched_alert_context")
_EVIDENCE_KINDS = (*_ALERT_CONTEXT_KINDS, "tool_result")
# How much of the recorded evidence the citation check walks. A run past the
# bound has more evidence than the check can read, and it gets no mark.
_WALK_NODES_MAX = 200_000
_JSON_TEXT_MAX = 2_000_000


@dataclass(frozen=True)
class RunFlags:
    """What the match reads about the run and nothing about its alert.

    ``replay`` is a backtest replay and ``synthetic`` is an evaluation run.
    Both are measurements, and a measurement never matches. ``promoted`` is
    "finding" or "lead" for a promoted run, else None.
    """

    replay: bool = False
    synthetic: bool = False
    promoted: str | None = None


@dataclass(frozen=True)
class Matched:
    """The run is inside this scope."""

    scope: Scope


@dataclass(frozen=True)
class Outside:
    """The run shares an address with this scope and fails these parts.

    ``named`` is the address or the machine name in the text of the report
    that is beyond the scope, when that is why the run is outside.
    """

    scope: Scope
    parts: tuple[str, ...]
    named: str | None = None


@dataclass(frozen=True)
class CitedDocument:
    """One document a run read, reduced to its two ends and its id (lower case)."""

    source: str | None
    destination: str | None
    id: str | None = None


# ── Pure rules ─────────────────────────────────────────────────────────────


def _same_address(left: str | None, right: str | None) -> bool:
    """Whether two address strings name one address. A bad string names none."""
    if not left or not right:
        return False
    try:
        return ipaddress.ip_address(left.strip()) == ipaddress.ip_address(right.strip())
    except ValueError:
        return False


def _identity(machine_key: str | None, address: str) -> str:
    """The identity a machine key gives an address.

    An agent or a MAC key is the identity. An address that the Hosts data
    knows only by itself (an ``ip:`` key, or no machine) has the address as
    its identity.
    """
    if machine_key and not machine_key.startswith("ip:"):
        return machine_key
    return f"ip:{address}"


def entry_matches(entry: ScopeEntry, address: str | None, machine_key: str | None) -> bool:
    """Whether an address is this stored address, on the machine it was on.

    ``machine_key`` is the key of the machine that holds ``address`` today,
    or None when the Hosts data holds no machine for it. Two things must
    hold. The address equals the stored address: another address of the same
    machine is not in the scope. And the Hosts data maps the address to the
    same identity as at the decision: a source that left its agent machine,
    and a target that an agent or a MAC claimed since, are other machines.
    """
    if not _same_address(address, entry.address):
        return False
    return _identity(machine_key, entry.address) == _identity(entry.machine_key, entry.address)


def rule_class_of(alert: Any) -> str:
    """The alert class of the rule of an alert."""
    try:
        return str(classify_alert(alert).value)
    except Exception:
        return ""


def event_time(alert: Any) -> datetime | None:
    """The time of the alert as naive UTC, or None when it has none."""
    value = getattr(alert, "timestamp", None)
    if not isinstance(value, datetime):
        return None
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo is not None else value


def _ordered(parts: Collection[str]) -> tuple[str, ...]:
    return tuple(part for part in _PART_ORDER if part in parts)


def _listed(scope: Scope, address: str | None) -> bool:
    """Whether the address is a stored source address of the scope."""
    return any(_same_address(address, entry.address) for entry in scope.sources)


def _touches(scope: Scope, document: Any) -> bool:
    """Whether one end of the document is a stored address of the scope."""
    for address in (
        getattr(document, "source_ip", None),
        getattr(document, "destination_ip", None),
    ):
        if _listed(scope, address) or _same_address(address, scope.target.address):
            return True
    return False


def _alert_parts(
    scope: Scope, alert: Any, memberships: Mapping[str, str | None]
) -> set[str] | None:
    """The parts the alert of an alert run fails, or None when it is unrelated."""
    if not _touches(scope, alert):
        return None
    source = getattr(alert, "source_ip", None)
    destination = getattr(alert, "destination_ip", None)
    parts: set[str] = set()
    if _alert_signals_decoy(alert):
        parts.add(PART_DECOY)
    if not source or not destination:
        parts.add(PART_FLOW)
    elif _same_address(source, scope.target.address) and _listed(scope, destination):
        parts.add(PART_DIRECTION)
    else:
        source_ok = any(
            entry_matches(entry, source, memberships.get(source)) for entry in scope.sources
        )
        if not source_ok:
            parts.add(PART_SOURCE)
        if not entry_matches(scope.target, destination, memberships.get(destination)):
            parts.add(PART_TARGET)
    name = store.rule_name_key(getattr(alert, "rule_name", None))
    if not name or name not in scope.rule_names or rule_class_of(alert) != scope.rule_class:
        parts.add(PART_RULE)
    at = event_time(alert)
    if at is None or not (scope.starts_at <= at <= scope.expires_at):
        parts.add(PART_TIME)
    return parts


def match(
    alert: Any,
    subject_documents: Sequence[Any],
    *,
    verdict: str | None,
    run_flags: RunFlags,
    authorizations: Sequence[Scope],
    memberships: Mapping[str, str | None],
) -> Matched | Outside | None:
    """Decide whether one run is inside an authorized scope. Pure.

    ``alert`` is the alert of the run. ``subject_documents`` are the documents
    of a hunt subject, and are empty on an alert run. ``memberships`` maps
    each address of the alert to the key of the machine that holds it today,
    or to None.

    Only a true positive is judged. A replay and a synthetic run are
    measurements, and a lead promotion judges a whole hunt: none of them
    gets an answer. A revoked authorization is skipped.

    A finding run never matches. When its documents touch an address of a
    scope, the answer is outside with the part :data:`PART_FINDING`.

    An alert run with an empty set of failed parts matches. When more than
    one scope matches, the oldest one takes the run. An outside answer needs
    a shared address and the right time, or a full pair and rule at the
    wrong time. A run that fails both the time and another part of a scope
    has nothing to do with that scope.
    """
    if verdict != TRUE_POSITIVE or run_flags.replay or run_flags.synthetic:
        return None
    if run_flags.promoted is not None and run_flags.promoted != PROMOTED_FINDING:
        return None
    # A campaign record lists machines and no rule. Its rules are in
    # soc_ai.campaigns.authorization.
    live = sorted(
        (s for s in authorizations if s.revoked_at is None and s.campaign_id is None),
        key=lambda s: s.id,
    )
    if run_flags.promoted == PROMOTED_FINDING:
        documents = [d for d in (alert, *subject_documents) if d is not None]
        for scope in live:
            if any(_touches(scope, document) for document in documents):
                return Outside(scope, (PART_FINDING,))
        return None
    if alert is None:
        return None
    outside: list[Outside] = []
    for scope in live:
        parts = _alert_parts(scope, alert, memberships)
        if parts is None:
            continue
        if not parts:
            return Matched(scope)
        if PART_TIME in parts and len(parts) > 1:
            continue
        outside.append(Outside(scope, _ordered(parts)))
    if not outside:
        return None
    return min(outside, key=lambda o: (len(o.parts), o.scope.id))


def outside_sentence(label: str, parts: Sequence[str], named: str | None = None) -> str:
    """The one line of an outside run. It names each part that failed.

    ``named`` is the address or the host in the text of the report that is
    beyond the scope. The clause of the cited evidence then names it.
    """
    clauses = [
        f"the report names {named}, which is beyond the scope"
        if part == PART_CITED and named
        else _PART_CLAUSE[part]
        for part in _ordered(parts)
        if part in _PART_CLAUSE
    ]
    if not clauses:
        clauses = ["one part of the scope does not match"]
    reason = clauses[0] if len(clauses) == 1 else f"{', '.join(clauses[:-1])} and {clauses[-1]}"
    return f"This activity is outside the authorized scope of {label}: {reason}."


# ── The cited evidence ─────────────────────────────────────────────────────


def _between(scope: Scope, document: CitedDocument) -> bool:
    """Whether a document is between a source address and the target, either way."""
    forward = _listed(scope, document.source) and _same_address(
        document.destination, scope.target.address
    )
    back = _same_address(document.source, scope.target.address) and _listed(
        scope, document.destination
    )
    return forward or back


# A citation of a field of the focus alert, or of an event on its session.
# Both are inside by construction: the match already holds the alert to the pair.
_INSIDE_CITATIONS = ("alert", "community_id_events")
# A citation of a tool call or of the alert history of a host names no
# document. The text check below reads what the report says about them.
_NO_DOCUMENT_PREFIXES = ("tool ", "host_alert_profile")
# The id of an investigation: a ULID.
_INVESTIGATION_ID = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")


def _cites_a_document(raw: str) -> bool:
    """Whether a citation names a recorded document that must resolve."""
    text = raw.strip()
    lowered = text.lower()
    for prefix in _INSIDE_CITATIONS:
        if lowered == prefix or lowered.startswith(f"{prefix}."):
            return False
    if lowered.startswith(_NO_DOCUMENT_PREFIXES):
        return False
    return _INVESTIGATION_ID.fullmatch(text) is None


def cited_beyond(
    scope: Scope, citations: Any, documents: Mapping[str, Sequence[CitedDocument]]
) -> bool:
    """Whether the report cites a document that is not inside the scope. Pure.

    ``documents`` maps a cited value to the documents of the run that carry
    it (:func:`index_documents`). A field of the focus alert
    (``alert.payload_printable``) and an event on its session
    (``community_id_events.0.rule_name``) are inside. A tool call
    (``tool t_origin_chain``), the alert history of a host
    (``host_alert_profiles.0.alert_count``) and an investigation id do not
    decide. Each other citation, such as a grid document id, must resolve: to
    the documents with that id, or else to the documents that carry the
    value. Each such document must be between a source address and the
    target address, in either direction. A citation that resolves to no
    document of the run is beyond the scope: nothing shows what it is about.
    A document with one end or none, such as a host log, is beyond it too.
    """
    for raw in citations if isinstance(citations, (list, tuple)) else ():
        text = str(raw) if isinstance(raw, (str, int)) else ""
        if not text.strip() or not _cites_a_document(text):
            continue
        key = text.strip().lower()
        found = documents.get(key) or []
        own = [document for document in found if document.id == key]
        chosen = own or found
        if not chosen or not all(_between(scope, document) for document in chosen):
            return True
    return False


# An IPv4 literal, and a candidate IPv6 literal that ipaddress then checks.
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)")
_IPV6 = re.compile(
    r"(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4})(?![\w:]|\.\w)",
    re.IGNORECASE,
)


def _addresses_in(text: str) -> list[tuple[int, str, str]]:
    """Each address literal in a text: its place, its text and its normal form."""
    found: list[tuple[int, str, str]] = []
    for pattern in (_IPV4, _IPV6):
        for hit in pattern.finditer(text):
            literal = hit.group()
            if not any(char.isalnum() for char in literal):
                continue
            try:
                address = ipaddress.ip_address(literal)
            except ValueError:
                # A time or a MAC address, or no address at all.
                continue
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            found.append((hit.start(), literal, str(address)))
    return found


def _scope_names(scope: Scope, host_names: Mapping[str, Collection[str]]) -> set[str]:
    """The machine names of the sources and the target, lower case."""
    entries = (*scope.sources, scope.target)
    keys = {entry.machine_key for entry in entries if entry.machine_key}
    names = {entry.name.strip().lower() for entry in entries if entry.name}
    names.update(name for name, machines in host_names.items() if keys.intersection(machines))
    return names


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def named_beyond(
    scope: Scope, texts: Iterable[str], host_names: Mapping[str, Collection[str]]
) -> str | None:
    """The first address or machine name in the text that is beyond the scope. Pure.

    ``host_names`` maps each machine name of the Hosts data, lower case, to
    the keys of the machines that carry it (:func:`soc_ai.store.authorized_activity.machine_names`).
    Each IPv4 or IPv6 literal must be a stored source address or the target
    address. Each known machine name, as a whole word in any case, must be a
    name of a source machine or of the target machine. A name inside a
    longer word, such as ``blue`` in ``blueprint`` or in ``sky-blue``, does
    not count. None when the text names only the machines of the scope.
    """
    allowed = _scope_names(scope, host_names)
    others = [name for name in host_names if name not in allowed and not _is_address(name)]
    for text in texts:
        hits: list[tuple[int, str]] = [
            (at, literal)
            for at, literal, normal in _addresses_in(text)
            if not _listed(scope, normal) and not _same_address(normal, scope.target.address)
        ]
        lowered = text.lower()
        for name in others:
            if name not in lowered:
                continue
            pattern = rf"(?<![\w.-]){re.escape(name)}(?![\w-])"
            hit = re.search(pattern, text, re.IGNORECASE)
            if hit is not None:
                hits.append((hit.start(), hit.group()))
        if hits:
            return min(hits)[1]
    return None


def report_texts(report: Mapping[str, Any]) -> list[str]:
    """The text of a report: its summary, its rationale and each action rationale."""
    texts = [report.get("summary"), report.get("rationale")]
    actions = report.get("recommended_actions")
    for action in actions if isinstance(actions, list) else ():
        if isinstance(action, Mapping):
            texts.append(action.get("rationale"))
    return [text for text in texts if isinstance(text, str) and text]


def report_beyond(
    scope: Scope,
    *,
    citations: Any,
    texts: Iterable[str],
    documents: Mapping[str, Sequence[CitedDocument]],
    host_names: Mapping[str, Collection[str]] | None,
) -> Outside | None:
    """The outside answer of a matched run whose report leaves the scope. Pure.

    Two checks. Each cited document is inside (:func:`cited_beyond`). Each
    address and each known machine name in the text is inside
    (:func:`named_beyond`). ``host_names`` is None when the Hosts data could
    not be read: nothing then shows what the names in the text are, so the
    run is outside. None when the report stays on the machines of the scope.
    """
    if host_names is None or cited_beyond(scope, citations, documents):
        return Outside(scope, (PART_CITED,))
    named = named_beyond(scope, texts, host_names)
    if named is not None:
        return Outside(scope, (PART_CITED,), named)
    return None


def _ip_of(side: Any) -> str | None:
    if isinstance(side, Mapping):
        value = side.get("ip")
        return str(value) if isinstance(value, str) and value else None
    return None


def _ends(document: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """The source and the destination of one recorded document."""
    inner = document.get("_source")
    body: Mapping[str, Any] = inner if isinstance(inner, Mapping) else document
    source = body.get("source_ip") or body.get("source.ip") or _ip_of(body.get("source"))
    destination = (
        body.get("destination_ip") or body.get("destination.ip") or _ip_of(body.get("destination"))
    )
    return (
        str(source) if isinstance(source, str) and source else None,
        str(destination) if isinstance(destination, str) and destination else None,
    )


def index_documents(payloads: Iterable[Any]) -> dict[str, list[CitedDocument]] | None:
    """The documents a run recorded, keyed by each value a report can cite.

    ``payloads`` are the payloads of the alert context events and the tool
    result events of the run. A document is a mapping with an ``id`` or an
    ``_id``. It is indexed under its id and under each string it holds, so a
    cited id, a cited hash and a cited session id all resolve to the
    documents that carry them. Keys are lower case.

    None when the evidence is larger than the check can read. The caller
    then gives no mark.
    """
    index: dict[str, list[CitedDocument]] = {}
    budget = [_WALK_NODES_MAX]

    def leaves(node: Any, into: set[str]) -> None:
        budget[0] -= 1
        if budget[0] < 0:
            return
        if isinstance(node, str):
            if node:
                into.add(node.strip().lower())
        elif isinstance(node, Mapping):
            for value in node.values():
                leaves(value, into)
        elif isinstance(node, (list, tuple)):
            for value in node:
                leaves(value, into)

    def walk(node: Any) -> None:
        budget[0] -= 1
        if budget[0] < 0:
            return
        if isinstance(node, str):
            if node[:1] in "{[" and len(node) <= _JSON_TEXT_MAX:
                try:
                    walk(json.loads(node))
                except ValueError:
                    return
            return
        if isinstance(node, Mapping):
            doc_id = node.get("id") if isinstance(node.get("id"), str) else node.get("_id")
            if isinstance(doc_id, str) and doc_id:
                own_key = doc_id.strip().lower()
                document = CitedDocument(*_ends(node), own_key)
                keys: set[str] = set()
                leaves(node, keys)
                keys.add(own_key)
                for key in keys:
                    index.setdefault(key, []).append(document)
            for value in node.values():
                walk(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                walk(value)

    for payload in payloads:
        walk(payload)
    return index if budget[0] >= 0 else None


# ── The display copy in the report ─────────────────────────────────────────


def _iso(value: datetime) -> str:
    return value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def matched_mark(scope: Scope, *, at: datetime, earlier: bool = False) -> dict[str, Any]:
    """``report["authorized_activity"]`` for a run that matched."""
    mark: dict[str, Any] = {
        "state": store.RUN_MATCHED,
        "id": scope.id,
        "label": scope.label,
        "by": scope.created_by,
        "expires_at": _iso(scope.expires_at),
        "matched_at": _iso(at),
    }
    if earlier:
        # The analyst applied the decision to a run made before it.
        mark["earlier"] = True
    if scope.campaign_id is not None:
        mark["campaign_id"] = scope.campaign_id
    return mark


def outside_mark(scope: Scope, parts: Sequence[str], named: str | None = None) -> dict[str, Any]:
    """``report["authorized_activity"]`` for a run outside the scope."""
    if scope.campaign_id is not None:
        from soc_ai.campaigns.authorization import outside_line  # noqa: PLC0415 - light

        why = parts[0] if parts else ""
        return {
            "state": store.RUN_OUTSIDE,
            "id": scope.id,
            "label": scope.label,
            "parts": [why],
            "line": outside_line(scope.label, why),
            "campaign_id": scope.campaign_id,
        }
    return {
        "state": store.RUN_OUTSIDE,
        "id": scope.id,
        "label": scope.label,
        "parts": list(_ordered(parts)),
        "line": outside_sentence(scope.label, parts, named),
    }


# ── The run path ───────────────────────────────────────────────────────────


def _alert_of(payload: Any) -> SoAlert | None:
    if not isinstance(payload, Mapping):
        return None
    try:
        return SoAlert.model_validate(dict(payload))
    except Exception:
        return None


def _promoted(kind: str | None, subject: Any) -> str | None:
    """ "finding" or "lead" for a promoted run, else None.

    ``subject`` is the hunt subject record of the row
    (``HuntSubject.as_record()``). A record with no ``judges`` key judged a
    whole hunt, so it is a lead promotion.
    """
    if not isinstance(subject, Mapping) and kind not in ("hunt", PROMOTED_LEAD):
        return None
    if kind == PROMOTED_LEAD:
        return PROMOTED_LEAD
    if isinstance(subject, Mapping) and subject.get("judges") != PROMOTED_FINDING:
        return PROMOTED_LEAD
    return PROMOTED_FINDING


def _judge(
    scopes: Sequence[Scope],
    alert: SoAlert | None,
    *,
    verdict: str | None,
    flags: RunFlags,
    memberships: Mapping[str, str | None],
    citations: Any,
    texts: Iterable[str],
    evidence: Iterable[Any],
    host_names: Mapping[str, Collection[str]] | None,
    subject_documents: Sequence[Any] = (),
) -> Matched | Outside | None:
    """The match, then the check of the report of a run that matched."""
    answer = match(
        alert,
        subject_documents,
        verdict=verdict,
        run_flags=flags,
        authorizations=scopes,
        memberships=memberships,
    )
    if not isinstance(answer, Matched):
        return answer
    documents = index_documents(evidence)
    if documents is None:
        return Outside(answer.scope, (PART_CITED,))
    beyond = report_beyond(
        answer.scope,
        citations=citations,
        texts=texts,
        documents=documents,
        host_names=host_names,
    )
    return beyond or answer


async def _host_names(db: Any) -> dict[str, frozenset[str]] | None:
    """The machine names of the Hosts data, or None when the read fails."""
    try:
        return await store.machine_names(db)
    except Exception:
        _LOGGER.warning(
            "authorized activity: the machine names are not readable, so a matched run is outside",
            exc_info=True,
        )
        return None


async def evaluate(
    db: Any,
    *,
    enriched_payload: Mapping[str, Any] | None,
    verdict: str | None,
    flags: RunFlags,
    citations: Any = (),
    texts: Iterable[str] = (),
    evidence: Iterable[Any] = (),
    now: datetime | None = None,
) -> Matched | Outside | None:
    """Read what :func:`match` needs from the store, and judge the run.

    ``enriched_payload`` is the alert context event of the run: the alert,
    and the documents of a hunt subject. ``citations`` are the citations of
    the report, ``texts`` its text (:func:`report_texts`), and ``evidence``
    the payloads of the events that recorded the documents the run read. The
    same events are in the store for an earlier run, so one path judges both.
    """
    if verdict != TRUE_POSITIVE or flags.replay or flags.synthetic:
        return None
    if not isinstance(enriched_payload, Mapping):
        return None
    scopes = [s for s in await store.in_force(db, now=now) if s.campaign_id is None]
    if not scopes:
        return None
    alert = _alert_of(enriched_payload.get("alert"))
    documents: list[SoAlert] = []
    memberships: dict[str, str | None] = {}
    if flags.promoted == PROMOTED_FINDING:
        documents = [
            d
            for d in (_alert_of(raw) for raw in enriched_payload.get("subject_documents") or [])
            if d is not None
        ]
    elif alert is None or flags.promoted is not None:
        return None
    else:
        refs = await store.machine_refs(db, [alert.source_ip, alert.destination_ip])
        memberships = {address: store.machine_key_now(ref) for address, ref in refs.items()}
    return _judge(
        scopes,
        alert,
        verdict=verdict,
        flags=flags,
        memberships=memberships,
        citations=citations,
        texts=texts,
        evidence=evidence,
        host_names=await _host_names(db) if flags.promoted is None else None,
        subject_documents=documents,
    )


async def evaluate_campaigns(
    db: Any,
    *,
    investigation_id: str | None,
    report: Mapping[str, Any],
    enriched_payload: Mapping[str, Any] | None,
    flags: RunFlags,
    now: datetime | None = None,
) -> Matched | Outside | None:
    """Judge one finished run against the campaign records in force.

    The run is the row ``investigation_id``, with ``report`` as its finished
    report and ``enriched_payload`` as its alert context. Only a true
    positive alert run and a true positive finding run are judged: a replay,
    a synthetic run and a lead promotion get no answer. The rules are
    :func:`soc_ai.campaigns.authorization.judge`.
    """
    from soc_ai.campaigns import authorization as campaign_auth  # noqa: PLC0415 - cycle
    from soc_ai.store.models import Investigation  # noqa: PLC0415 - light

    if report.get("verdict") != TRUE_POSITIVE or flags.replay or flags.synthetic:
        return None
    if flags.promoted not in (None, PROMOTED_FINDING) or not investigation_id:
        return None
    scopes = await campaign_auth.campaign_scopes(db, now=now)
    if not scopes:
        return None
    inv = await db.get(Investigation, investigation_id)
    if inv is None:
        return None
    contexts = {inv.id: enriched_payload} if isinstance(enriched_payload, Mapping) else None
    ends = (
        await campaign_auth.ends_of(db, [inv], reports={inv.id: report}, contexts=contexts)
    ).get(inv.id)
    if ends is None:
        return None
    found = campaign_auth.judge(scopes, ends)
    if found is None:
        return None
    scope, why = found
    return Matched(scope) if why is None else Outside(scope, (why,))


async def _audit(audit: Any, session_id: str, kind: str, payload: dict[str, Any]) -> None:
    """Write one audit record. A failed write never fails the run."""
    if audit is None:
        return
    try:
        await audit.log_kind(session_id, kind, payload, user="soc-ai")
    except Exception as exc:
        _LOGGER.warning("authorized activity: the audit record %s failed: %s", kind, exc)


async def _campaign_answer(
    db: Any,
    investigation_id: str | None,
    report: Mapping[str, Any],
    enriched_payload: Mapping[str, Any] | None,
    flags: RunFlags,
    now: datetime,
) -> Matched | Outside | None:
    """:func:`evaluate_campaigns`, where a failure gives no answer."""
    try:
        return await evaluate_campaigns(
            db,
            investigation_id=investigation_id,
            report=report,
            enriched_payload=enriched_payload,
            flags=flags,
            now=now,
        )
    except Exception:
        _LOGGER.warning(
            "authorized activity: the campaign check failed, "
            "so the investigation gets normal handling",
            exc_info=True,
        )
        return None


async def mark_report(
    state: Any,
    report: dict[str, Any],
    *,
    enriched_payload: Mapping[str, Any] | None,
    started_by: str,
    kind: str | None,
    synthetic: bool,
    subject: Any = None,
    evidence: Iterable[Any] = (),
    session_id: str = AUDIT_SESSION,
    investigation_id: str | None = None,
) -> dict[str, Any]:
    """The finished report with the authorized activity answer on it.

    The one call on the run path. It runs on the final report, after every
    gate and after the Oracle. It returns a copy with the key
    ``authorized_activity`` when the run is inside or outside a scope, and
    the report itself when no scope has anything to say. No other key
    changes. Any failure returns the report as it is, so the run gets normal
    handling.
    """
    from soc_ai.store import investigations as inv_svc  # noqa: PLC0415 - light import

    try:
        maker = getattr(state, "db_sessionmaker", None)
        if maker is None or report.get("verdict") != TRUE_POSITIVE:
            return report
        flags = RunFlags(
            replay=inv_svc.is_backtest_actor(started_by),
            synthetic=bool(synthetic),
            promoted=_promoted(kind, subject),
        )
        now = datetime.now(UTC).replace(tzinfo=None)
        async with maker() as db:
            answer = await evaluate(
                db,
                enriched_payload=enriched_payload,
                verdict=report.get("verdict"),
                flags=flags,
                citations=report.get("citations"),
                texts=report_texts(report),
                evidence=evidence,
                now=now,
            )
            if not isinstance(answer, Matched):
                # A campaign record. A match of the rule-list form wins, and
                # its outside answer outranks the outside answer of a campaign.
                campaign = await _campaign_answer(
                    db, investigation_id, report, enriched_payload, flags, now
                )
                if isinstance(campaign, Matched) or answer is None:
                    answer = campaign
        if answer is None:
            return report
        audit = getattr(state, "audit", None)
        base = {
            "authorization_id": answer.scope.id,
            "label": answer.scope.label,
            "investigation_id": investigation_id,
        }
        if isinstance(answer, Matched):
            await _audit(audit, session_id, "authorized_activity_matched", base)
            return {**report, store.REPORT_KEY: matched_mark(answer.scope, at=now)}
        await _audit(
            audit,
            session_id,
            "authorized_activity_outside",
            {**base, "parts": list(answer.parts)},
        )
        return {
            **report,
            store.REPORT_KEY: outside_mark(answer.scope, answer.parts, answer.named),
        }
    except Exception:
        _LOGGER.warning(
            "authorized activity: the check failed, so the run gets normal handling",
            exc_info=True,
        )
        return report


class RunMarker:
    """Follows the events of one run and marks its final report.

    :func:`soc_ai.api.runner.recorded_run` hands every event to :meth:`see`.
    The marker keeps the alert context and the tool results when they pass:
    they hold the documents the run read. It returns the marked report when
    the ``triage_report`` event passes. Every payload goes through as it is.
    """

    def __init__(
        self,
        state: Any,
        *,
        started_by: str,
        kind: str | None,
        synthetic: bool,
        subject: Any = None,
        investigation_id: str | None = None,
    ) -> None:
        self._state = state
        self._started_by = started_by
        self._kind = kind
        self._synthetic = synthetic
        self._subject = subject
        self._investigation_id = investigation_id
        self._alert_payload: Mapping[str, Any] | None = None
        self._evidence: list[Any] = []

    async def see(self, kind: str, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if kind in _ALERT_CONTEXT_KINDS:
            self._alert_payload = payload
        if kind in _EVIDENCE_KINDS:
            self._evidence.append(payload)
        if kind != "triage_report":
            return payload
        return await mark_report(
            self._state,
            payload,
            enriched_payload=self._alert_payload,
            started_by=self._started_by,
            kind=self._kind,
            synthetic=self._synthetic,
            subject=self._subject,
            evidence=self._evidence,
            session_id=session_id,
            investigation_id=self._investigation_id,
        )


# ── Stored runs: the earlier runs of a new authorization, and the expiry ───


async def _stored_evidence(db: Any, run_ids: Sequence[str]) -> dict[str, list[Any]]:
    """The recorded evidence payloads of each stored run, in event order."""
    from sqlalchemy import select  # noqa: PLC0415 - the pure half needs no SQL

    from soc_ai.store.models import InvestigationEvent  # noqa: PLC0415

    out: dict[str, list[Any]] = {run_id: [] for run_id in run_ids}
    if not run_ids:
        return out
    events = (
        await db.scalars(
            select(InvestigationEvent)
            .where(
                InvestigationEvent.investigation_id.in_(list(run_ids)),
                InvestigationEvent.kind.in_(_EVIDENCE_KINDS),
            )
            .order_by(InvestigationEvent.sequence, InvestigationEvent.id)
        )
    ).all()
    for event in events:
        out[str(event.investigation_id)].append((event.kind, event.payload))
    return out


def _alert_in(evidence: Sequence[Any]) -> SoAlert | None:
    """The alert of a stored run: the alert of its last alert context event."""
    alert: SoAlert | None = None
    for kind, payload in evidence:
        if kind in _ALERT_CONTEXT_KINDS and isinstance(payload, Mapping):
            found = _alert_of(payload.get("alert"))
            if found is not None:
                alert = found
    return alert


async def stored_alerts(db: Any, run_ids: Sequence[str]) -> dict[str, SoAlert]:
    """The alert of each stored run that recorded one."""
    evidence = await _stored_evidence(db, run_ids)
    out: dict[str, SoAlert] = {}
    for run_id, events in evidence.items():
        alert = _alert_in(events)
        if alert is not None:
            out[run_id] = alert
    return out


async def alert_of_run(db: Any, run_id: str) -> SoAlert | None:
    """The alert of one stored run, or None when the run recorded none."""
    return (await stored_alerts(db, [run_id])).get(run_id)


async def _stored_answers(
    db: Any, scope: Scope, runs: Sequence[Any]
) -> dict[str, Matched | Outside | None]:
    """The answer of this scope for each stored run, keyed by the run id.

    Each run is judged like a new run: by its own stored alert, by the stored
    addresses of the scope with the Hosts data of today, and by the documents
    and the names its report cites. The machine names are read once for all
    runs.
    """
    evidence = await _stored_evidence(db, [run.id for run in runs])
    refs = await store.machine_refs(
        db, [*(entry.address for entry in scope.sources), scope.target.address]
    )
    memberships = {address: store.machine_key_now(ref) for address, ref in refs.items()}
    host_names = await _host_names(db) if runs else None
    out: dict[str, Matched | Outside | None] = {}
    for run in runs:
        events = evidence.get(run.id, [])
        report = run.report if isinstance(run.report, Mapping) else {}
        out[run.id] = _judge(
            [scope],
            _alert_in(events),
            verdict=run.verdict,
            flags=RunFlags(),
            memberships=memberships,
            citations=report.get("citations"),
            texts=report_texts(report),
            evidence=[payload for _kind, payload in events],
            host_names=host_names,
        )
    return out


async def stored_run_line(db: Any, scope: Scope, run: Any) -> str | None:
    """The outside line this scope gives one stored run, or None when the run is inside.

    The dialog shows it for the run of the record, so the analyst knows
    before the save when that run keeps normal handling.
    """
    answer = (await _stored_answers(db, scope, [run])).get(run.id)
    if isinstance(answer, Matched):
        return None
    if isinstance(answer, Outside):
        return outside_sentence(scope.label or "this record", answer.parts, answer.named)
    return outside_sentence(scope.label or "this record", ())


async def earlier_matches(
    db: Any, scope: Scope, *, exclude: Collection[str] = (), limit: int = 500
) -> list[Any]:
    """The stored runs that this scope matches, newest first.

    The dialog counts them before the save, and the create route marks them
    when the analyst asks for it. The rule name and the two addresses are
    checked on the row first, which keeps the read of the stored events to
    the runs that can match.
    """
    addresses = {entry.address for entry in scope.sources}
    candidates = [
        run
        for run in await store.earlier_candidates(db, since=scope.starts_at, limit=limit)
        if run.id not in exclude
        and store.rule_name_key(run.rule_name) in scope.rule_names
        and run.src_ip in addresses
        and run.dest_ip == scope.target.address
    ]
    answers = await _stored_answers(db, scope, candidates)
    return [run for run in candidates if isinstance(answers.get(run.id), Matched)]


async def apply_to_stored_runs(
    db: Any, audit: Any, scope: Scope, runs: Sequence[Any], *, now: datetime | None = None
) -> int:
    """Put the mark of this scope on stored runs. Returns the count.

    The caller chose the runs with :func:`earlier_matches`. Each run gets the
    column, the display copy with ``earlier`` set, and one audit record. The
    verdict and the text of the run stay.
    """
    at = now or datetime.now(UTC).replace(tzinfo=None)
    for run in runs:
        report = dict(run.report or {})
        report[store.REPORT_KEY] = matched_mark(scope, at=at, earlier=True)
        run.report = report
        run.authorization_id = scope.id
    if runs:
        await db.commit()
    for run in runs:
        await _audit(
            audit,
            AUDIT_SESSION,
            "authorized_activity_matched",
            {
                "authorization_id": scope.id,
                "label": scope.label,
                "investigation_id": run.id,
                "earlier": True,
            },
        )
    return len(runs)


async def record_expiries(state: Any, *, now: datetime | None = None) -> int:
    """Write the audit record of each authorization that expired. Returns the count.

    The expiry loop calls this once a minute. A row gets its record one time:
    ``expiry_recorded_at`` holds the time of the write. When the audit write
    fails, the row stays unrecorded and the next wake tries again.
    """
    maker = getattr(state, "db_sessionmaker", None)
    if maker is None:
        return 0
    audit = getattr(state, "audit", None)
    done = 0
    async with maker() as db:
        due = await store.unrecorded_expiries(db, now=now)
        counts = await store.run_counts(db, [int(row.id) for row in due])
        for row in due:
            payload = {
                "authorization_id": int(row.id),
                "label": row.label,
                "expired_at": _iso(row.expires_at),
                "runs": counts.get(int(row.id), store.RunCount()).total,
            }
            if audit is not None:
                try:
                    await audit.log_kind(
                        AUDIT_SESSION, "authorized_activity_expired", payload, user="soc-ai"
                    )
                except Exception as exc:
                    _LOGGER.warning(
                        "authorized activity: the expiry record of %s failed: %s", row.id, exc
                    )
                    continue
            await store.mark_expiry_recorded(db, int(row.id), now=now)
            done += 1
    return done
