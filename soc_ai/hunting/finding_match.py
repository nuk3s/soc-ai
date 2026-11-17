"""The subject of a finding across hunts: the entities it names and what it cites.

Two surfaces compared findings by their words, and the model words one subject
in a new way on each run.

- Prod, 2026-11-12, hunt 01M78GYGVKV84GA91CPWEW0QB9: the "vs last run" strip
  read "7 new, 0 persisting, 5 resolved". Two of the five were the exploit of
  the day before, under two new titles.
- Prod, 2026-11-08 to 2026-11-12: one exploit campaign became 12 threat
  findings and 12 investigations in 5 hunts. The reuse rule matched on the
  exact entity set and the exact document set, and each day cited one more
  document.

This module holds the one rule both surfaces read. :func:`finding_keys` reads
the structured fields of a finding: the entities, the rule citations, the
techniques and the cited documents. It never reads the title or the detail.
:func:`match_score` says whether two findings have one subject.
:func:`restates` is the stricter test of the promotion.

Only a resolved document counts as a document. The citation gate keeps a tool
name and an address in the citations, and both have the shape of a document
id. Two findings that cite ``t_query_events_oql`` share no evidence. A
citation is a document when the tool results that the hunt stored hold a
document with that id (:func:`stored_documents`). Without that answer no
citation is a document.

A host has one identity. "web01" in one run and its address in the next are
one machine where the Hosts data says so (:func:`machine_keys`).

A finding cites a rule as ``rule:<id>``. A finding that cites only documents
names its rules through them: each stored document carries its rule name and
its rule id.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, NamedTuple

from soc_ai.hunting.findings import DOCUMENT_ID_RE, TOOL_CITATION_RE, finding_entities

__all__ = [
    "FindingKeys",
    "StoredDocument",
    "cited_ids",
    "finding_keys",
    "machine_keys",
    "match_score",
    "restates",
    "stored_documents",
]

_LOGGER = logging.getLogger(__name__)

# A rule a finding cites, by its id: 'rule:2036224' or 'rule:<sigma uuid>'.
_RULE_CITATION_RE = re.compile(r"^(?:rule|sid)\s*:\s*(\S.*)$", re.IGNORECASE)
# An ATT&CK technique id, alone or behind a prefix: 'T1190', 'mitre:T1003.006'.
_TECHNIQUE_RE = re.compile(r"^(?:(?:mitre|attack|technique)\s*:\s*)?(T\d{4}(?:\.\d{3})?)$", re.I)

# What a shared key adds to the score. A shared document is the strongest
# link, then a shared rule, then a shared technique. Any score above zero is
# a match.
_DOCUMENT_POINTS = 8
_RULE_POINTS = 4
_TECHNIQUE_POINTS = 2


class StoredDocument(NamedTuple):
    """One cited document that the hunt stored: its own id, its rules and its time.

    ``at`` is the event time of the document as naive UTC, or None when the
    document holds none. The campaign rule reads it
    (:mod:`soc_ai.hunting.campaign_hold`).
    """

    key: str
    rules: frozenset[str] = frozenset()
    at: datetime | None = None


class FindingKeys(NamedTuple):
    """The subject of one finding, from its structured fields."""

    entities: frozenset[str]
    rules: frozenset[str]
    techniques: frozenset[str]
    documents: frozenset[str]

    @property
    def cites(self) -> bool:
        """Whether the finding names a rule, a technique or a document."""
        return bool(self.rules or self.techniques or self.documents)


def _citations(finding: Mapping[str, Any]) -> list[str]:
    raw = finding.get("citations")
    out: list[str] = []
    for c in raw if isinstance(raw, list) else []:
        if isinstance(c, bool) or not isinstance(c, (str, int)):
            continue
        text = str(c).strip()
        if text:
            out.append(text)
    return out


def cited_ids(finding: Mapping[str, Any]) -> list[str]:
    """The citations of a finding that can name a document, in order.

    The shape test only: a rule citation, a technique and a tool call are left
    out. A citation on this list is a document only when the hunt stored a
    document with that id (:func:`stored_documents`).
    """
    out: list[str] = []
    for text in _citations(finding):
        if _RULE_CITATION_RE.match(text) or _TECHNIQUE_RE.match(text):
            continue
        if TOOL_CITATION_RE.match(text) or not DOCUMENT_ID_RE.match(text):
            continue
        if text not in out:
            out.append(text)
    return out


def _fold(value: str) -> str:
    return value.strip().rstrip(".").casefold()


def finding_keys(
    finding: Mapping[str, Any],
    *,
    documents: Mapping[str, StoredDocument] | None = None,
    machines: Mapping[str, str] | None = None,
) -> FindingKeys:
    """The keys of one finding.

    ``documents`` maps a cited id to the stored document it names
    (:func:`stored_documents`). A citation with no entry is no document, so
    without the map a finding has no document at all. ``machines`` maps an
    entity value to the key of its machine (:func:`machine_keys`). A value
    with no entry stands for itself.
    """
    rules: set[str] = set()
    techniques: set[str] = set()
    for citation in _citations(finding):
        rule = _RULE_CITATION_RE.match(citation)
        if rule:
            rules.add(rule.group(1).strip().casefold())
            continue
        technique = _TECHNIQUE_RE.match(citation)
        if technique:
            techniques.add(technique.group(1).upper())
    named = finding.get("mitre_techniques")
    for value in named if isinstance(named, list) else []:
        technique = _TECHNIQUE_RE.match(str(value).strip())
        if technique:
            techniques.add(technique.group(1).upper())
    held: set[str] = set()
    for doc_id in cited_ids(finding):
        stored = (documents or {}).get(doc_id)
        if stored is None:
            continue
        held.add(stored.key)
        rules.update(r for r in stored.rules if r)
    entities = {
        (machines or {}).get(_fold(value), _fold(value))
        for _kind, value in finding_entities(finding)
    }
    return FindingKeys(
        entities=frozenset(e for e in entities if e),
        rules=frozenset(rules),
        techniques=frozenset(techniques),
        documents=frozenset(held),
    )


def match_score(a: FindingKeys, b: FindingKeys) -> int:
    """How strongly two findings name one subject. Zero when they do not.

    The two findings must name one entity in common. Two findings that name
    no entity at all can still match. They must also share a document, a rule
    or a technique. The entity sets need not be equal: a run that names one
    more source of the same exploit reports the same subject.
    """
    if (a.entities or b.entities) and not (a.entities & b.entities):
        return 0
    return (
        _DOCUMENT_POINTS * len(a.documents & b.documents)
        + _RULE_POINTS * len(a.rules & b.rules)
        + _TECHNIQUE_POINTS * len(a.techniques & b.techniques)
    )


def restates(later: FindingKeys, earlier: FindingKeys) -> bool:
    """Whether ``later`` repeats ``earlier`` and adds nothing to it.

    Five conditions, all required:

    - ``later`` cites one resolved document or more.
    - Every document ``later`` cites is a document ``earlier`` cites.
    - The two name the same machines, and one machine or more.
    - Every technique ``later`` names is a technique ``earlier`` names.
    - Every rule ``later`` cites is a rule ``earlier`` cites.

    A document match cannot tell two claims apart, so the test is narrow. A
    finding with one new document, host, technique or rule fails it. So does a
    finding that cites no resolved document: a rule, a technique, a tool name
    and an address are no evidence that the earlier investigation read.
    """
    if not later.documents or not later.documents <= earlier.documents:
        return False
    if not later.entities or later.entities != earlier.entities:
        return False
    return later.techniques <= earlier.techniques and later.rules <= earlier.rules


def stored_documents(
    events: Sequence[Any], candidate_ids: Iterable[str]
) -> dict[str, StoredDocument]:
    """The cited ids that name a document the hunt stored.

    Reads the stored tool results of the hunt through the index the Event
    timeline uses, so a citation by Zeek uid resolves to the same document as
    a citation by its id. An id the hunt never stored has no entry: a tool
    name and an address fall out here. Never raises: a fault logs one line
    and gives an empty answer, and the callers then hold no document.
    """
    wanted = list(dict.fromkeys(d for d in candidate_ids if d))
    if not wanted or not events:
        return {}
    try:
        from soc_ai.api.webui._event_timeline import DocumentIndex  # noqa: PLC0415 - cycle

        index = DocumentIndex(wanted)
        index.read_events(events)
        out: dict[str, StoredDocument] = {}
        for cited, doc in index.found.items():
            rules = {
                value.strip().casefold()
                for value in (doc.fields.get("rule_name"), doc.fields.get("rule_uuid"))
                if isinstance(value, str) and value.strip()
            }
            at = doc.at
            if at is not None and at.tzinfo is not None:
                at = at.astimezone(UTC).replace(tzinfo=None)
            out[cited] = StoredDocument(key=str(doc.key), rules=frozenset(rules), at=at)
        return out
    except Exception:
        _LOGGER.warning(
            "finding match: soc-ai could not read the stored documents of a hunt. "
            "Its findings match on their rules and techniques only.",
            exc_info=True,
        )
        return {}


async def machine_keys(db: Any, findings: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """The machine of each host or address that ``findings`` name.

    Maps the folded value to the key of its machine in the Hosts data. A value
    that names no machine, or that two machines answer to, has no entry and
    stands for itself. Never raises: a read that fails gives no entry.
    """
    from soc_ai.store import host_machines  # noqa: PLC0415 - keeps the import graph light

    values = {
        _fold(value)
        for finding in findings
        for kind, value in finding_entities(finding)
        if kind in ("host", "address")
    }
    out: dict[str, str] = {}
    for value in sorted(v for v in values if v):
        try:
            membership = await host_machines.resolve_membership(db, value)
        except Exception:
            _LOGGER.warning("finding match: the machine of a host did not load", exc_info=True)
            continue
        if membership is not None:
            out[value] = f"machine:{membership.key}"
    return out
