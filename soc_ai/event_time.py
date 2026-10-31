"""Event time: the one wave rule for every story soc-ai tells (change D).

No story soc-ai told was in event-time order. A rule that fired in three waves
on one day read as "one 19.7-hour burst", an SSH session a day before the first
exploit read as post-exploitation access, and four counts of one attack (4, 10,
30 and 270 alerts) stood side by side with no unit and no window.

This module holds the parts that every surface shares, so the page, the hunt
subject prompt, ``t_rule_prevalence`` and the writer rule read one constant:

* :data:`WAVE_GAP_MINUTES`, the gap that starts a new wave;
* :func:`group_waves`, which groups timed points into waves. A point with a
  duration (a Zeek conn) holds its wave open until it ends;
* :func:`document_label`, the one-line label of a stored document;
* :data:`EVENT_TIME_RULE`, the time-order rule for every summary and narrative
  writer and for the Oracle;
* :func:`prompt_section`, the time-ordered list of a hunt subject's documents.

Pure: the standard library and ``neutralize_untrusted`` only. The tools, the
Oracle client and the hunt subject import it with no cycle.
"""

from __future__ import annotations

import math
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.detection.untrusted import neutralize_untrusted

# A new wave starts after a gap of more than this many minutes. The owner
# accepted 30 minutes (2026-10-30). It can join two actors close in time and
# split a slow scan; the page, the prompt list, the rule and rule_prevalence
# all read this one value, so a change moves every surface at once.
WAVE_GAP_MINUTES = 30
WAVE_GAP_SECONDS = WAVE_GAP_MINUTES * 60
# The most entries the page section lists. The rest are counted as omitted.
MAX_ENTRIES = 200
# The cap on one attacker-writable value in the prompt list.
MAX_PROMPT_VALUE = 120
# The document lists the enriched alert context stores. The id resolvers of the
# gates and the orchestrator read the same lists; a test holds the three equal.
STORED_DOCUMENT_LISTS: tuple[str, ...] = (
    "community_id_events",
    "host_events",
    "user_events",
    "process_events",
    "file_events",
    "subject_documents",
)


def as_utc(value: Any) -> datetime | None:
    """An ISO string or a datetime as an aware UTC datetime, else None.

    A naive time is UTC: the grid stores ``@timestamp`` in UTC and a shipper
    can drop the zone suffix. Never raises.
    """
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


@dataclass(frozen=True)
class Point:
    """One timed thing to group: a document, or one minute of rule fires.

    ``end`` is the start plus the duration when a duration is known, so a
    50-minute connection holds its wave open. ``count`` is what the point
    adds to its wave: 1 for a document, the fires for a minute bucket.
    """

    key: str
    start: datetime
    end: datetime | None = None
    count: int = 1


@dataclass(frozen=True)
class WaveSpan:
    """One wave: its number from 1, its start and end, its count and its keys."""

    n: int
    start: datetime
    end: datetime
    count: int
    keys: tuple[str, ...]


def group_waves(points: Iterable[Point], gap_seconds: float = WAVE_GAP_SECONDS) -> list[WaveSpan]:
    """Group *points* into waves in time order.

    Sorted by ``(start, key)``. The next point starts a new wave when its start
    is more than *gap_seconds* after the largest end so far. A gap of exactly
    *gap_seconds* keeps one wave.
    """
    waves: list[WaveSpan] = []
    keys: list[str] = []
    start: datetime | None = None
    end: datetime | None = None
    count = 0
    for p in sorted(points, key=lambda p: (p.start, p.key)):
        p_end = max(p.start, p.end) if p.end is not None else p.start
        if start is None or end is None:
            start, end, keys, count = p.start, p_end, [p.key], p.count
            continue
        if (p.start - end).total_seconds() > gap_seconds:
            waves.append(WaveSpan(len(waves) + 1, start, end, count, tuple(keys)))
            start, end, keys, count = p.start, p_end, [p.key], p.count
            continue
        keys.append(p.key)
        count += p.count
        end = max(end, p_end)
    if start is not None and end is not None:
        waves.append(WaveSpan(len(waves) + 1, start, end, count, tuple(keys)))
    return waves


def gap_words(seconds: float) -> str:
    """A span in words: '42 s', '45 min', '22 h 27 min' or '3 days 2 h'."""
    total = max(0, int(seconds))
    if total < 60:
        return f"{total} s"
    minutes = total // 60
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, hours = divmod(hours, 24)
    day_words = "1 day" if days == 1 else f"{days} days"
    return f"{day_words} {hours} h" if hours else day_words


def _text(value: Any) -> str | None:
    """A field as one stripped string, or None. A list reads its first value."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None or isinstance(value, bool | dict):
        return None
    text = str(value).strip()
    return text or None


def document_label(fields: Mapping[str, Any]) -> str:
    """The label of one stored document, from its SoAlert JSON keys.

    In this order: the rule name; the HTTP method, the whole URI and the
    status; the DNS query; the SSH result; the conn state; the file type; the
    event action; the dataset. Empty when the document names none of them.
    """
    rule = _text(fields.get("rule_name"))
    if rule:
        return rule
    method, uri = _text(fields.get("zeek_http_method")), _text(fields.get("zeek_http_uri"))
    if method or uri:
        head = " ".join(x for x in (method, uri) if x)
        status = _text(fields.get("zeek_http_status"))
        return f"{head}, status {status}" if status else head
    query = _text(fields.get("dns_query")) or _text(fields.get("zeek_dns_query"))
    if query:
        return f"DNS query {query}"
    dataset = _text(fields.get("event_dataset"))
    ssh = fields.get("zeek_ssh_auth_success")
    if ssh is True:
        return "SSH login succeeded"
    if ssh is False:
        return "SSH login failed"
    if dataset == "zeek.ssh":
        return "SSH session"
    state = _text(fields.get("zeek_conn_state"))
    if state:
        return f"Connection, state {state}"
    mime = _text(fields.get("zeek_files_mime_type"))
    if mime:
        return f"File {mime}"
    return _text(fields.get("event_action")) or dataset or ""


# The time-order rule for every summary and narrative writer and the Oracle.
# Composed directly after WRITING_STYLE_RULE. It holds no brace: the hunt
# prompts go through str.format. It holds no time value: the model copies an
# example value. Each paragraph is one line, so no phrase splits.
EVENT_TIME_RULE = (
    "\n## Event time\n"
    "Keep the bottom line as the first sentence. Then tell the events in the order "
    "they happened. Give each event its UTC time from the @timestamp of the record "
    "that you cite. Use the times in the records that you already hold. Do not run a "
    "query only to get a time. When the prompt has an Event timeline section, take "
    "the order and the waves from it.\n"
    "\n"
    f"A wave is a run of events with no gap longer than {WAVE_GAP_MINUTES} minutes. "
    "When the events form one wave, give its start and its end in one sentence. When "
    "the events form two or more waves, name each wave. Give each wave its start, its "
    "end and its hosts. State the gap between two waves. A first time and a last time "
    "do not show the gaps between them. Call a span longer than "
    f"{WAVE_GAP_MINUTES} minutes one wave only when the times inside it show no long "
    "gap. A wave groups events by time only. Two hosts in one wave do not show that "
    "one host caused or joined the other. One finding can hold several waves. Name "
    "the waves in the detail of that finding.\n"
    "\n"
    "Give each count its unit. Give a count its window only when the record that gave "
    "the count states the window. When the record states no window, name the record. "
    "Two counts with different windows are different facts.\n"
    "\n"
    "An event can cause only a later event. Never call an earlier event a consequence "
    "of a later event. Access that existed before the first exploit is not a result of "
    "the exploit. Say that the access existed before.\n"
    "\n"
    "When there are no events to tell, skip the time order. These rules fit inside the "
    "length limit of each field. They apply to the summary, the narrative and each "
    "finding.\n"
)


# ── The time-ordered list of a hunt subject ─────────────────────────────────


def stamp(at: datetime) -> str:
    """``YYYY-MM-DD HH:MM:SS`` in UTC."""
    return at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def _fields_of(doc: Any) -> Mapping[str, Any] | None:
    """A document as its SoAlert JSON keys. A Mapping passes through."""
    if isinstance(doc, Mapping):
        return doc
    dump = getattr(doc, "model_dump", None)
    if dump is None:
        return None
    try:
        dumped = dump()
    except Exception:
        return None
    return dumped if isinstance(dumped, Mapping) else None


def _safe(value: Any) -> str:
    return neutralize_untrusted(str(value), cap=MAX_PROMPT_VALUE)


@dataclass(frozen=True)
class _Row:
    key: str
    at: datetime
    end: datetime | None
    fields: Mapping[str, Any]


def duration_end(at: datetime, duration: Any) -> datetime | None:
    """The end of a document that lasts *duration* seconds, or None."""
    if isinstance(duration, bool) or not isinstance(duration, int | float):
        return None
    if duration <= 0 or math.isnan(duration):
        return None
    try:
        return at + timedelta(seconds=float(duration))
    except OverflowError:
        return None


def _end_point(ip: Any, port: Any) -> str | None:
    address = _text(ip)
    if not address:
        return None
    port_text = _text(port)
    return f"{address}:{port_text}" if port_text else address


def _row_line(row: _Row) -> str:
    f = row.fields
    parts = [f"{stamp(row.at)} UTC"]
    dataset = _text(f.get("event_dataset"))
    if dataset:
        parts.append(_safe(dataset))
    src = _end_point(f.get("source_ip"), f.get("source_port"))
    dst = _end_point(f.get("destination_ip"), f.get("destination_port"))
    if src and dst:
        parts.append(f"{_safe(src)} to {_safe(dst)}")
    elif src:
        parts.append(f"from {_safe(src)}")
    elif dst:
        parts.append(f"to {_safe(dst)}")
    elif host := _text(f.get("host_name")):
        parts.append(f"on {_safe(host)}")
    label = document_label(f)
    if label and label != dataset:
        parts.append(_safe(label))
    if row.end is not None:
        parts.append(f"lasted {gap_words((row.end - row.at).total_seconds())}")
    parts.append(f"id {_safe(row.key)}")
    return "- " + ", ".join(parts)


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _timed_rows(documents: Sequence[Any]) -> tuple[list[_Row], int]:
    """The documents with a time, and the count of those with none."""
    rows: list[_Row] = []
    seen: set[str] = set()
    untimed = 0
    for doc in documents:
        fields = _fields_of(doc)
        if fields is None:
            continue
        key = _text(fields.get("id"))
        if key is None or key in seen:
            continue
        seen.add(key)
        at = as_utc(fields.get("timestamp"))
        if at is None:
            untimed += 1
            continue
        rows.append(_Row(key, at, duration_end(at, fields.get("zeek_conn_duration")), fields))
    return rows, untimed


def _wave_lines(rows: Sequence[_Row]) -> list[str]:
    """The wave lines and the row lines of *rows*, wave by wave."""
    lines: list[str] = []
    by_key = {r.key: r for r in rows}
    previous: WaveSpan | None = None
    for wave in group_waves(Point(key=r.key, start=r.at, end=r.end) for r in rows):
        if previous is not None:
            gap = gap_words((wave.start - previous.end).total_seconds())
            lines.append(f"Wave {wave.n} starts {gap} after wave {previous.n} ends.")
        sources: list[str] = []
        for key in wave.keys:
            src = _text(by_key[key].fields.get("source_ip"))
            if src and src not in sources:
                sources.append(src)
        head = (
            f"Wave {wave.n}: {stamp(wave.start)} UTC to {stamp(wave.end)} UTC. "
            f"{_plural(len(wave.keys), 'document', 'documents')}."
        )
        if sources:
            label = "Source" if len(sources) == 1 else "Sources"
            head += f" {label}: {', '.join(_safe(s) for s in sources)}."
        lines.append(head)
        lines.extend(_row_line(by_key[key]) for key in wave.keys)
        previous = wave
    return lines


def prompt_section(
    documents: Sequence[Any],
    *,
    focus_ids: Collection[str] | None,
    omitted: int = 0,
    cap: int = 40,
    lead_ids: Collection[str] | None = None,
) -> str:
    """The Event timeline block of a hunt-subject prompt, or '' with fewer
    than two timed documents.

    *focus_ids* None means no finding is promoted, and the waves cover every
    document. A set names the documents of the finding to judge, and the waves
    cover only those. When none of them has an event time, the list has no
    waves and says so: the documents of the other findings are context, and
    waves over them would ask the writer to retell the hunt. The other
    documents follow under their own heading in time order with no waves.
    *lead_ids* names the documents of the lead's observations, so the heading
    does not say that a finding cites a document that only the lead cites. Every attacker-writable
    value passes through ``neutralize_untrusted``. This list only shows the
    time order; the selection and the order of the JSON block below it stay
    as the fetch gave them.
    """
    rows, untimed = _timed_rows(documents)
    if len(rows) < 2:
        return ""
    if focus_ids is None:
        focus, others = rows, []
    else:
        wanted = set(focus_ids)
        focus = [r for r in rows if r.key in wanted]
        others = [r for r in rows if r.key not in wanted]
    if focus_ids is not None and not focus:
        intro = (
            "The finding to judge cites no document with an event time. This list has no "
            "waves. The times are UTC."
        )
    elif others:
        intro = (
            "This list gives the documents of the finding to judge in the order of their "
            "event time. The times are UTC. A new wave starts after a gap of more than "
            f"{WAVE_GAP_MINUTES} minutes. A wave groups documents by time only."
        )
    else:
        intro = (
            "This list gives the documents below in the order of their event time. The "
            "times are UTC. A new wave starts after a gap of more than "
            f"{WAVE_GAP_MINUTES} minutes. A wave groups documents by time only."
        )
    lines = ["### Event timeline", intro, *(_wave_lines(focus) if focus else [])]
    if others:
        leads = set(lead_ids or ())
        cite = (
            "The other findings of the hunt or the observations of the lead cite these documents."
            if any(r.key in leads for r in others)
            else "The other findings of the hunt cite these documents."
        )
        lines.append("#### Other cited documents")
        lines.append(
            f"{cite} They are context for the finding to judge. The list gives them in "
            "time order, with no waves."
        )
        lines.extend(_row_line(r) for r in sorted(others, key=lambda r: (r.at, r.key)))
    if untimed == 1:
        lines.append("1 document carries no event time. It is not on this list.")
    elif untimed > 1:
        lines.append(f"{untimed} documents carry no event time. They are not on this list.")
    if omitted > 0:
        lines.append(
            f"The cap of {cap} documents left out {_plural(omitted, 'document', 'documents')}. "
            "The first event can be earlier than this list."
        )
    return "\n".join(lines) + "\n"
