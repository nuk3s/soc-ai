"""The steps of a running hunt, in words an analyst reads.

A running hunt showed its elapsed time and one fixed sentence. Four steps said
"Event search: 0 matches", the query was raw JSON behind an expand control, and
a tool error read "time_range_minutes must be <= 43200, got 100000" (dogfood
2026-10-06 W10). This module names each search by what it looked for, states
a tool error as two plain sentences, and says what the hunt does now.

The investigation timeline keeps its own formatter. Only the hunt page reads
this module.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

__all__ = [
    "current_activity",
    "search_title",
    "span_words",
    "translate_tool_error",
]

_SEARCH_TOOLS = frozenset({"t_query_events_oql", "t_query_zeek_logs"})

# The OQL terms that name what a search is about. Quoted or bare values.
_TERM_RE = re.compile(
    r"(?P<field>[a-z_]+(?:\.[a-z_]+)+)\s*:\s*(?:\"(?P<quoted>[^\"]+)\"|(?P<bare>[^\s|()\"]+))",
    re.IGNORECASE,
)

# A cap error from a tool (soc_ai.tools.query_events, prevalence, host summary).
_CAP_RE = re.compile(
    r"(?P<name>time_range_minutes|lookback_days|lookback_hours)\s+must be\s+<=\s*"
    r"(?P<cap>\d+),\s*got\s+(?P<got>-?\d+)"
)
_LENGTH_RE = re.compile(r"query must be <= (?P<cap>\d+) chars")
# The OQL validator's refusal of a pattern that starts with a wildcard
# (soc_ai.so_client.oql). The model reads the validator's text. The page reads
# these sentences (R3 STE 27).
_LEADING_WILDCARD_RE = re.compile(r"leading-wildcard patterns are too expensive", re.I)
_LEADING_WILDCARD_WORDS = (
    "The query starts a pattern with a wildcard. The grid refuses that form. "
    "Write the pattern as foo*, or use field:~value."
)

# Tool sentences the model reads, and the words the page shows for them. The
# tools keep their text, because a change of tool text changes what the model
# does (R3 STE 26).
_PAGE_SENTENCES: tuple[tuple[str, str], ...] = (
    (
        "That is a single episode, not a background rate, so no per-day rate is reported.",
        "That is one wave. soc-ai states no rate for each day.",
    ),
)

# The text soc-ai writes for the model when the grid fails a tool call
# (soc_ai.agent.toolset._GRID_UNAVAILABLE_MESSAGE). It tells the model what to
# do next: "Do not re-send this exact call". The model keeps the text. The
# page states what happened (dogfood 2026-10-19, V1-H8). The stored text of
# an older build carried em dashes, so the match reads the first words only.
_GRID_UNAVAILABLE_RE = re.compile(r"^\s*The Security Onion grid did not answer this query\b", re.I)
_GRID_UNAVAILABLE_WORDS = "The grid did not answer this query. The result is unknown."

_UNIT_MINUTES = {"time_range_minutes": 1, "lookback_hours": 60, "lookback_days": 1440}

# What the agent does while a tool runs, by tool. Any other tool reads as
# "the agent runs <noun>".
_ACTIVITY: dict[str, str] = {
    "t_query_events_oql": "the agent searches the events",
    "t_query_zeek_logs": "the agent reads the Zeek logs",
    "t_get_event_raw": "the agent reads a document",
    "t_host_summary": "the agent reads a host summary",
    "t_host_dossier": "the agent reads the host dossier",
    "t_origin_chain": "the agent reads the origin chain of a host",
    "t_decode_payload": "the agent decodes a payload",
    "t_run_analytic": "the agent runs an analytic",
    "final_result": "the model writes the report",
}


def span_words(minutes: int) -> str:
    """43200 as "30 days", 1440 as "24 h", 90 as "90 min"."""
    if minutes >= 2880 and minutes % 1440 == 0:
        return f"{minutes // 1440} days"
    if minutes >= 2880:
        return f"{round(minutes / 1440)} days"
    if minutes >= 60 and minutes % 60 == 0:
        return f"{minutes // 60} h"
    return f"{minutes} min"


def translate_tool_error(message: str | None, *, retried: bool = False) -> str | None:
    """A tool error as plain sentences, or None when the shape is not known.

    "time_range_minutes must be <= 43200, got 100000" reads "The query asked
    for 69 days. The grid answers 30 days." A later call of the same tool adds
    "The agent tried again."
    """
    text = message or ""
    sentence: str | None = None
    m = _CAP_RE.search(text)
    if m is not None:
        unit = _UNIT_MINUTES[m.group("name")]
        asked = span_words(int(m.group("got")) * unit)
        cap = span_words(int(m.group("cap")) * unit)
        sentence = f"The query asked for {asked}. The grid answers {cap}."
    else:
        length = _LENGTH_RE.search(text)
        if length is not None:
            sentence = f"The query was too long. A query holds {length.group('cap')} characters."
        elif _LEADING_WILDCARD_RE.search(text):
            sentence = _LEADING_WILDCARD_WORDS
        elif _GRID_UNAVAILABLE_RE.search(text):
            sentence = _GRID_UNAVAILABLE_WORDS
        elif "partial search results" in text.lower():
            # The grid client's text is the model's (R3 STE 14). The catalog
            # composer already words it for the page, so the two agree.
            from soc_ai.hunting.findings import plain_error  # noqa: PLC0415 - lazy

            worded = plain_error(text)
            sentence = worded if worded != text.strip() else None
    if sentence is None:
        return None
    return f"{sentence} The agent tried again." if retried else sentence


def _terms(query: str) -> list[tuple[str, str]]:
    return [
        (m.group("field").lower(), m.group("quoted") or m.group("bare") or "")
        for m in _TERM_RE.finditer(query or "")
    ]


def _subject(query: str) -> str:
    """What one OQL search looked for, as a noun phrase."""
    terms = _terms(query)
    first: dict[str, str] = {}
    for field, value in terms:
        first.setdefault(field, value)
    src = first.get("source.ip") or first.get("client.ip")
    dst = first.get("destination.ip") or first.get("server.ip")
    if src and dst:
        subject = f"traffic from {src} to {dst}"
    elif dst:
        subject = f"traffic to {dst}"
    elif src:
        subject = f"traffic from {src}"
    elif first.get("related.ip"):
        subject = f"traffic with {first['related.ip']}"
    elif first.get("dns.query.name"):
        subject = f"DNS queries for {first['dns.query.name']}"
    elif first.get("host.name") or first.get("host.ip"):
        subject = f"events on {first.get('host.name') or first.get('host.ip')}"
    elif first.get("user.name"):
        subject = f"events of the account {first['user.name']}"
    elif first.get("rule.name"):
        subject = f"alerts of the rule {first['rule.name']}"
    elif first.get("event.code"):
        subject = f"events with the code {first['event.code']}"
    else:
        subject = ""
    dataset = first.get("event.dataset")
    if not subject:
        return f"{dataset} events" if dataset else "events that match the query"
    return f"{subject} in {dataset}" if dataset and "dns.query.name" not in first else subject


def _count(result: Any) -> str | None:
    if isinstance(result, list):
        n = len(result)
        return f"{n} record{'' if n == 1 else 's'}"
    if not isinstance(result, Mapping):
        return None
    total = result.get("total")
    if isinstance(total, bool) or not isinstance(total, int):
        return None
    shown = str(result.get("total_display") or total)
    return f"{shown} event{'' if total == 1 else 's'}"


def search_title(
    tool_name: str,
    args: Mapping[str, Any],
    result: Any,
    *,
    running: bool,
    retried: bool = False,
) -> str | None:
    """The title of one search step, or None for a tool that is not a search.

    "Searched for traffic to 10.99.0.30 over 30 days: 0 events". A search
    that failed with a known error states it in plain sentences.
    """
    if tool_name not in _SEARCH_TOOLS:
        return None
    if tool_name == "t_query_zeek_logs":
        flow = str(args.get("community_id") or "").strip()
        what = f"the Zeek logs of the flow {flow}" if flow else "the Zeek logs"
    else:
        what = f"for {_subject(str(args.get('query') or ''))}"
    minutes = args.get("time_range_minutes")
    span = (
        f" over {span_words(minutes)}"
        if isinstance(minutes, int) and not isinstance(minutes, bool) and minutes > 0
        else ""
    )
    if result is None:
        return f"Searching {what}{span}" if running else None
    if isinstance(result, Mapping) and result.get("error"):
        message = result.get("message") or result.get("error")
        plain = translate_tool_error(str(message), retried=retried)
        return f"Search {what}{span} failed. {plain}" if plain else None
    count = _count(result)
    return f"Searched {what}{span}: {count}" if count else None


def page_sentences(text: str) -> str:
    """A tool sentence the model reads, in the words the page shows."""
    for model_text, page_text in _PAGE_SENTENCES:
        text = text.replace(model_text, page_text)
    return text


def prevalence_title(tool_name: str, result: Any) -> str | None:
    """The title of an indicator prevalence step, or None for another step.

    The step read "Indicator prevalence: 10.1.99.5: common - 99976 event(s)
    across 13 distinct day(s)". It now reads "Indicator prevalence: 10.1.99.5
    is common. 99,976 events on 13 days." (R3 STE 28). The tool's own summary
    is the model's text and stays as it is.
    """
    if tool_name != "t_prevalence" or not isinstance(result, Mapping):
        return None
    if result.get("error") or not result.get("observed"):
        return None
    total, days = result.get("total_events"), result.get("distinct_days")
    if not isinstance(total, int) or isinstance(total, bool) or not isinstance(days, int):
        return None
    summary = str(result.get("summary") or "")
    subject = summary.split(":", 1)[0].strip() if ":" in summary else ""
    if not subject:
        return None
    if result.get("is_novel"):
        state = "is new, with no baseline"
    else:
        state = f"is {str(result.get('rarity') or 'seen').strip()}"
    events = f"{total:,} event" + ("" if total == 1 else "s")
    on = "1 day" if days == 1 else f"{days} days"
    return f"Indicator prevalence: {subject} {state}. {events} on {on}."


def current_activity(events: Sequence[Any]) -> str | None:
    """What a running hunt does now, from its newest trace event.

    A tool call with no result yet names the tool's activity. A result the
    model has not answered yet reads "the model reads the results".
    """
    answered: set[Any] = set()
    for e in events:
        if e.kind == "tool_result":
            answered.add((e.payload or {}).get("tool_call_id"))
    for e in reversed(list(events)):
        kind = e.kind
        payload = e.payload or {}
        if kind == "tool_call":
            if payload.get("tool_call_id") in answered:
                return "the model reads the results"
            name = str(payload.get("tool_name") or "")
            return _ACTIVITY.get(
                name, f"the agent runs {name.removeprefix('t_').replace('_', ' ')}"
            )
        if kind in ("tool_result", "model_response"):
            return "the model reads the results"
        if kind == "hunt_started":
            return "the model plans the hunt"
    return None
