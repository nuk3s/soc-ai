"""The Event timeline section of the investigation page and the hunt page.

Change D. The page timelines list pipeline steps in tool-call order, and no
surface listed the evidence in event time. Three waves of one attack read as
one burst, and an SSH session a day before the first exploit read as its
result. This module builds a list of the documents a run cites, oldest first,
grouped into waves by the one wave gap in :mod:`soc_ai.event_time`.

It reads only what the run already stores: the documents of the enriched alert
context, every hit in a stored tool result, and the source a ``t_get_event_raw``
call returned. The page makes no grid query. A document the run never stored
is counted as untimed and is not on the list.

Kept apart from ``_timeline.py``: that module imports this one for the response
model, and other changes edit it.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel

from soc_ai.event_time import (
    MAX_ENTRIES,
    STORED_DOCUMENT_LISTS,
    WAVE_GAP_MINUTES,
    Point,
    as_utc,
    document_label,
    duration_end,
    group_waves,
)
from soc_ai.secret_scrub import scrub_secrets
from soc_ai.so_client.fields import dataset_of, get_dotted
from soc_ai.so_client.models import SoAlert

_LOGGER = logging.getLogger(__name__)

# A ULID names an investigation or a hunt, never a grid document.
_ULID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")
# Evidence ids that a citation can name and that are not grid documents: an
# MD5, SHA-1 or SHA-256 hash, a CVE id and a rule UUID. A stored document with
# one of these shapes still shows. A missing one is not counted as untimed.
_EVIDENCE_ID_RE = re.compile(
    r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|CVE-\d{4}-\d{4,}"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    re.IGNORECASE,
)
# How deep the walk goes into one stored tool result, and how many nodes it
# reads, so a huge or cyclic payload cannot stall the page.
_MAX_DEPTH = 8
_MAX_NODES = 20000
_RAW_EVENT_TOOL = "t_get_event_raw"
_CONTEXT_KINDS = ("enriched_alert_context", "alert_context")
_RUNNING = frozenset({"running", "queued"})


class EventEntryOut(BaseModel):
    """One document on the Event timeline.

    ``at`` and ``end`` are ISO UTC with a ``Z`` and millisecond precision.
    ``end`` is set when the document lasts, a Zeek conn with a duration.
    ``source`` and ``destination`` are ``address`` or ``address:port``.
    ``findings`` holds the 0-based ordinals of the hunt findings that cite the
    document, counted over the findings the hunt page shows.
    """

    id: str
    at: str
    end: str | None = None
    dataset: str | None = None
    source: str | None = None
    destination: str | None = None
    host: str | None = None
    label: str = ""
    cited: bool = False
    findings: list[int] = []
    wave: int


class EventWaveOut(BaseModel):
    """One wave: its number from 1, its start and end, its document count and
    the addresses of its two ends."""

    n: int
    start: str
    end: str
    documents: int
    sources: list[str] = []
    destinations: list[str] = []


class EventTimelineOut(BaseModel):
    """The documents of a run in event-time order, with the waves.

    ``basis`` tells the page which intro to show: ``finding`` for a run that
    judges one hunt finding, ``hunt_subject`` for a run that judges a whole hunt
    or a lead, ``hunt`` for the hunt page. ``gapMinutes`` is the wave
    gap. ``untimed`` counts the wanted documents with no stored time.
    ``omitted`` counts the later documents past the list cap.
    """

    basis: Literal["alert", "finding", "hunt_subject", "hunt"]
    entries: list[EventEntryOut]
    waves: list[EventWaveOut]
    gapMinutes: int = WAVE_GAP_MINUTES
    untimed: int = 0
    omitted: int = 0


def iso_ms(at: datetime) -> str:
    """ISO UTC with a ``Z`` and millisecond precision."""
    at = at.astimezone(UTC)
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"


@dataclass
class _Doc:
    """One stored document, read by its SoAlert JSON keys."""

    key: str
    at: datetime | None
    end: datetime | None
    fields: Mapping[str, Any]


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _fields_form(hit: Mapping[str, Any]) -> dict[str, Any] | None:
    """The source of a hit, from ``_source`` or from the ``fields`` form."""
    source = hit.get("_source")
    if isinstance(source, dict):
        return source
    flat = hit.get("fields")
    if isinstance(flat, dict):
        return {str(k): _first(v) for k, v in flat.items()}
    return None


def _uids(source: Mapping[str, Any]) -> list[str]:
    """The Zeek uids a raw source carries: log.id.uid, uid and zeek.<ds>.uid."""
    out: list[str] = []
    candidates = [get_dotted(source, "log.id.uid"), source.get("uid")]
    dataset = dataset_of(source)
    if dataset and dataset.startswith("zeek."):
        candidates.append(get_dotted(source, f"{dataset}.uid"))
    for candidate in candidates:
        value = _first(candidate)
        if isinstance(value, str) and value and value not in out:
            out.append(value)
    return out


def _doc_from_source(doc_id: str, source: Mapping[str, Any]) -> _Doc:
    """A raw grid source as a timed document. Never raises."""
    try:
        fields: dict[str, Any] = SoAlert.from_es_hit(
            {"_id": doc_id, "_source": dict(source)}
        ).model_dump(mode="json")
    except Exception:
        fields = {"id": doc_id, "timestamp": source.get("@timestamp")}
    if not fields.get("event_dataset"):
        fields["event_dataset"] = dataset_of(source)
    return _doc_from_fields(doc_id, fields)


def _doc_from_fields(key: str, fields: Mapping[str, Any]) -> _Doc:
    at = as_utc(fields.get("timestamp"))
    end = duration_end(at, fields.get("zeek_conn_duration")) if at is not None else None
    return _Doc(key=key, at=at, end=end, fields=fields)


def _parse_args(args: Any) -> Mapping[str, Any]:
    """Tool-call args as a dict. A model can send them as a JSON string."""
    if isinstance(args, Mapping):
        return args
    if isinstance(args, str):
        try:
            parsed = json.loads(args)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, Mapping) else {}
    return {}


@dataclass
class DocumentIndex:
    """The stored documents of a run, indexed by the ids a page wants.

    The wanted ids are collected first. The index then keeps only the stored
    documents whose ``_id``, or whose Zeek uid, is wanted. The first stored
    copy of a document wins.
    """

    wanted: list[str]
    found: dict[str, _Doc] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._wanted = set(self.wanted)

    def _keep(self, wanted_id: str, doc: _Doc) -> None:
        if wanted_id in self._wanted and wanted_id not in self.found:
            self.found[wanted_id] = doc

    def add_fields(self, fields: Any) -> None:
        """One stored SoAlert JSON document, read by its keys."""
        if not isinstance(fields, Mapping):
            return
        doc_id = fields.get("id")
        if isinstance(doc_id, str) and doc_id in self._wanted and doc_id not in self.found:
            self._keep(doc_id, _doc_from_fields(doc_id, fields))

    def add_context(self, payload: Mapping[str, Any]) -> None:
        """The alert and every document list of an enriched alert context."""
        self.add_fields(payload.get("alert"))
        for name in STORED_DOCUMENT_LISTS:
            items = payload.get(name)
            for item in items if isinstance(items, list) else []:
                self.add_fields(item)

    def add_hit(self, hit: Mapping[str, Any]) -> None:
        doc_id = hit.get("_id")
        if not isinstance(doc_id, str) or not doc_id:
            return
        source = _fields_form(hit)
        if source is None:
            return
        keys = [k for k in (doc_id, *_uids(source)) if k in self._wanted and k not in self.found]
        if not keys:
            return
        doc = _doc_from_source(doc_id, source)
        for key in keys:
            self._keep(key, doc)

    def add_result(self, result: Any) -> None:
        """Every ``{_id, _source}`` or ``{_id, fields}`` hit in a stored tool result."""
        stack: list[tuple[Any, int]] = [(result, 0)]
        nodes = 0
        while stack and nodes < _MAX_NODES:
            node, depth = stack.pop()
            nodes += 1
            if isinstance(node, Mapping):
                if "_id" in node and ("_source" in node or "fields" in node):
                    self.add_hit(node)
                    continue
                if depth < _MAX_DEPTH:
                    stack.extend((v, depth + 1) for v in node.values())
            elif isinstance(node, list) and depth < _MAX_DEPTH:
                stack.extend((v, depth + 1) for v in reversed(node))

    def add_raw(self, args: Any, result: Any) -> None:
        """The source a ``t_get_event_raw`` call returned, under its event id."""
        event_id = _parse_args(args).get("event_id")
        if not isinstance(event_id, str) or not isinstance(result, Mapping):
            return
        if result.get("error") or event_id not in self._wanted or event_id in self.found:
            return
        self._keep(event_id, _doc_from_source(event_id, result))

    def read_events(self, events: Iterable[Any]) -> None:
        """Index every stored document of a run's events."""
        calls: dict[Any, tuple[str, Any]] = {}
        dispatch: tuple[str, Any] | None = None
        for e in events:
            kind = getattr(e, "kind", None)
            payload = getattr(e, "payload", None)
            if not isinstance(payload, Mapping):
                continue
            if kind in _CONTEXT_KINDS:
                self.add_context(payload)
            elif kind == "tool_call":
                calls[payload.get("tool_call_id")] = (
                    str(payload.get("tool_name") or ""),
                    payload.get("args"),
                )
            elif kind == "tool_result":
                name, args = calls.get(payload.get("tool_call_id"), ("", None))
                name = name or str(payload.get("tool_name") or "")
                self._read_result(name, args, payload.get("result"))
            elif kind == "targeted_dispatch":
                dispatch = (str(payload.get("tool_name") or ""), payload.get("tool_args"))
            elif kind == "targeted_tool_result":
                name, args = dispatch or (str(payload.get("tool_name") or ""), None)
                dispatch = None
                self._read_result(name, args, payload.get("result"))

    def _read_result(self, name: str, args: Any, result: Any) -> None:
        if name == _RAW_EVENT_TOOL:
            self.add_raw(args, result)
        self.add_result(result)


@dataclass
class _Row:
    key: str
    at: datetime
    doc: _Doc
    cited: bool = False
    findings: set[int] = field(default_factory=set)


def _end_point(ip: Any, port: Any) -> str | None:
    ip = _first(ip)
    if not isinstance(ip, str) or not ip:
        return None
    port = _first(port)
    if isinstance(port, int) and not isinstance(port, bool):
        return f"{ip}:{port}"
    return ip


def _text(value: Any) -> str | None:
    value = _first(value)
    return value if isinstance(value, str) and value else None


def _timeline(
    index: DocumentIndex,
    *,
    basis: Literal["alert", "finding", "hunt_subject", "hunt"],
    cited: set[str],
    findings_by_id: Mapping[str, Sequence[int]] | None = None,
) -> EventTimelineOut | None:
    rows: dict[str, _Row] = {}
    untimed_keys: set[str] = set()
    for wanted_id in index.wanted:
        doc = index.found.get(wanted_id)
        if doc is None:
            if not _EVIDENCE_ID_RE.fullmatch(wanted_id):
                untimed_keys.add(f"missing:{wanted_id}")
            continue
        if doc.at is None:
            untimed_keys.add(doc.key)
            continue
        row = rows.setdefault(doc.key, _Row(key=doc.key, at=doc.at, doc=doc))
        row.cited = row.cited or wanted_id in cited
        row.findings.update((findings_by_id or {}).get(wanted_id, ()))
    ordered = sorted(rows.values(), key=lambda r: (r.at, r.key))
    if len(ordered) < 2:
        return None
    kept = ordered[:MAX_ENTRIES]
    by_key = {r.key: r for r in kept}
    wave_of: dict[str, int] = {}
    waves: list[EventWaveOut] = []
    points = [Point(key=r.key, start=r.at, end=r.doc.end) for r in kept]
    for span in group_waves(points):
        sources: list[str] = []
        destinations: list[str] = []
        for key in span.keys:
            wave_of[key] = span.n
            f = by_key[key].doc.fields
            src, dst = _text(f.get("source_ip")), _text(f.get("destination_ip"))
            if src and src not in sources:
                sources.append(src)
            if dst and dst not in destinations:
                destinations.append(dst)
        waves.append(
            EventWaveOut(
                n=span.n,
                start=iso_ms(span.start),
                end=iso_ms(span.end),
                documents=len(span.keys),
                sources=sources,
                destinations=destinations,
            )
        )
    entries: list[EventEntryOut] = []
    for r in kept:
        f = r.doc.fields
        host = _text(f.get("host_name"))
        entries.append(
            EventEntryOut(
                id=r.key,
                at=iso_ms(r.at),
                end=iso_ms(r.doc.end) if r.doc.end is not None else None,
                dataset=_text(f.get("event_dataset")),
                source=_end_point(f.get("source_ip"), f.get("source_port")),
                destination=_end_point(f.get("destination_ip"), f.get("destination_port")),
                host=scrub_secrets(host) if host else None,
                label=scrub_secrets(document_label(f)),
                cited=r.cited,
                findings=sorted(r.findings),
                wave=wave_of.get(r.key, 0),
            )
        )
    return EventTimelineOut(
        basis=basis,
        entries=entries,
        waves=waves,
        untimed=len(untimed_keys),
        omitted=len(ordered) - len(kept),
    )


def _context_payload(events: Iterable[Any]) -> Mapping[str, Any]:
    for e in events:
        payload = getattr(e, "payload", None)
        if getattr(e, "kind", None) in _CONTEXT_KINDS and isinstance(payload, Mapping):
            return payload
    return {}


def _cited_ids(citations: Iterable[Any]) -> list[str]:
    """The document ids a verdict cites. A citation the validator refused
    names no document the run holds."""
    out: list[str] = []
    for c in citations:
        kind = c.get("kind") if isinstance(c, Mapping) else getattr(c, "kind", None)
        target = c.get("target") if isinstance(c, Mapping) else getattr(c, "target", None)
        resolved = c.get("resolved") if isinstance(c, Mapping) else getattr(c, "resolved", None)
        if kind != "id" or resolved is False or not isinstance(target, str) or not target:
            continue
        if _ULID_RE.fullmatch(target) or target in out:
            continue
        out.append(target)
    return out


def _build_investigation(
    events: Sequence[Any], citations: Sequence[Any], focus_ids: Sequence[str] | None = None
) -> EventTimelineOut | None:
    payload = _context_payload(events)
    cited = _cited_ids(citations)
    subject_docs = payload.get("subject_documents")
    subject_ids = [
        d["id"]
        for d in (subject_docs if isinstance(subject_docs, list) else [])
        if isinstance(d, Mapping) and isinstance(d.get("id"), str)
    ]
    alert = payload.get("alert")
    alert_id = alert.get("id") if isinstance(alert, Mapping) else None
    anchor = [alert_id] if isinstance(alert_id, str) and alert_id else []
    basis: Literal["alert", "finding", "hunt_subject"]
    if focus_ids is not None:
        focus = set(focus_ids)
        extra = [d for d in subject_ids if d in focus] or anchor
        basis = "finding"
    elif subject_ids:
        extra = subject_ids
        basis = "hunt_subject"
    else:
        extra = anchor
        basis = "hunt_subject" if payload.get("subject") == "hunt" else "alert"
    wanted = list(dict.fromkeys([*cited, *extra]))
    if not wanted:
        return None
    index = DocumentIndex(wanted)
    index.read_events(events)
    return _timeline(index, basis=basis, cited=set(cited))


def _build_hunt(events: Sequence[Any], findings: Sequence[Any]) -> EventTimelineOut | None:
    from soc_ai.agent.evidence import _classify_citation  # noqa: PLC0415 - heavy import
    from soc_ai.hunting.findings import finding_document_ids  # noqa: PLC0415

    findings_by_id: dict[str, list[int]] = {}
    for ordinal, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            continue
        for doc_id in finding_document_ids(finding):
            if _classify_citation(doc_id)[0] != "id" or _ULID_RE.fullmatch(doc_id):
                continue
            ordinals = findings_by_id.setdefault(doc_id, [])
            if ordinal not in ordinals:
                ordinals.append(ordinal)
    if not findings_by_id:
        return None
    index = DocumentIndex(list(findings_by_id))
    index.read_events(events)
    return _timeline(index, basis="hunt", cited=set(findings_by_id), findings_by_id=findings_by_id)


def _run_id(events: Sequence[Any]) -> str:
    for e in events:
        for name in ("investigation_id", "hunt_id"):
            value = getattr(e, name, None)
            if isinstance(value, str) and value:
                return value
    return "this run"


_LOG_LINE = (
    "event timeline: soc-ai could not build the event timeline of %s. "
    "The page shows no event timeline."
)


def investigation_event_timeline(
    events: Sequence[Any],
    citations: Sequence[Any],
    status: str | None,
    *,
    focus_ids: Sequence[str] | None = None,
) -> EventTimelineOut | None:
    """The Event timeline of an investigation, or None.

    None while the run is running, and when fewer than two documents have a
    stored time. The wanted documents are the ones the verdict cites, plus the
    subject documents of a hunt-subject run, else the alert. Never raises: a
    fault logs one line and the page shows no section.

    ``focus_ids`` are the citations of the finding that a finding run judges.
    The run judges that claim only, so the list takes only the subject
    documents that the finding cites, else the anchor. A document of another
    finding is on the list only when the verdict cites it. Before this rule, a
    prod finding run of 2026-10-30 listed an SSH session of another finding as
    a wave of its own story.
    """
    if status in _RUNNING:
        return None
    try:
        return _build_investigation(events, citations, focus_ids)
    except Exception:
        _LOGGER.warning(_LOG_LINE, _run_id(events), exc_info=True)
        return None


def hunt_event_timeline(
    events: Sequence[Any], shown_findings: Sequence[Any], status: str | None
) -> EventTimelineOut | None:
    """The Event timeline of a hunt, or None.

    ``shown_findings`` is the dict-only findings list the hunt page numbers, so
    an entry's finding ordinals match the page. None while the hunt runs, and
    when fewer than two cited documents have a stored time. Never raises.
    """
    if status in _RUNNING:
        return None
    try:
        return _build_hunt(events, shown_findings)
    except Exception:
        _LOGGER.warning(_LOG_LINE, _run_id(events), exc_info=True)
        return None
