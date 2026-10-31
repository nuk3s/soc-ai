"""The plain title of a hunt, written once for every surface.

A catalog run stores its objective as ``[catalog] <spec-id>: <title> (now-1440m
→ now)`` and a lead hunt as ``[lead 6] Investigate domainadmin, 10.1.10.11. The
lead formed from ...``. The Hunts list cleaned the catalog shape at render
time, and the bell and the hunt page printed the raw text. The operator read
the spec id and the date math in every bell notice. This module turns both
shapes into one plain title. The bell, the API and the hunt page read it.

The stored objective does not change. It is the durable record, and a re-hunt
sends it again.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping

__all__ = [
    "ALERT_ONLY_NOTE",
    "catalog_parts",
    "first_sentence",
    "hunt_title",
    "is_operator_step",
    "lead_entities",
    "objective_headline",
    "validator_note",
    "window_phrase",
]

# soc_ai.hunting.sweep.catalog_objective writes the arrow. An older row and a
# hand-typed copy can carry "to" in its place.
_CATALOG_RE = re.compile(
    r"^\[catalog\]\s+(?P<spec>[^\s:]+):\s+(?P<title>.+?)"
    r"(?:\s+\((?P<since>[^()]+?)\s*(?:→|->|\bto\b)\s*(?P<until>[^()]+?)\))?\s*$"
)
_RELATIVE_RE = re.compile(r"^now-(?P<n>\d+)(?P<unit>[mhd])$")

# soc_ai.store.leads.objective_for writes the head sentence. An entity key
# carries dots, so the sentence ends at the first full stop that a space or the
# end of the line follows.
_LEAD_RE = re.compile(r"^\[lead (?P<id>\d+)\] Investigate (?P<entities>.+?)\.(?:\s|$)")


# The end of a sentence: a stop, then space, then a capital, a digit or a quote.
# "e.g. the host" and an address such as 10.1.2.3 do not end one.
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])")


def first_sentence(text: str) -> str:
    """The first sentence of a narrative as plain text, whole.

    A heading line goes, and so do the emphasis marks and a list bullet. The
    sentence is never cut. The console wraps a long one.
    """
    lines = [ln for ln in (text or "").splitlines() if not ln.lstrip().startswith("#")]
    plain = re.sub(r"[*`]+", "", "\n".join(lines))
    plain = re.sub(r"^\s*[-+]\s+", "", plain, flags=re.MULTILINE)
    plain = " ".join(plain.split())
    if not plain:
        return ""
    return _SENTENCE_END.split(plain, maxsplit=1)[0]


def objective_headline(objective: str) -> str:
    """The objective up to the first line break, whole. The line is never cut."""
    return (objective or "").strip().split("\n", 1)[0].strip()


def window_phrase(since: str, until: str) -> str:
    """``now-1440m`` to ``now`` as "last 24 h". Any other window as dates."""
    m = _RELATIVE_RE.match(since.strip())
    if m and until.strip() == "now":
        n, unit = int(m.group("n")), m.group("unit")
        minutes = n * {"m": 1, "h": 60, "d": 1440}[unit]
        if minutes % 1440 == 0 and minutes > 1440:
            days = minutes // 1440
            return f"last {days} days"
        if minutes % 60 == 0:
            return f"last {minutes // 60} h"
        return f"last {minutes} min"
    return f"{since.strip()[:10]} to {until.strip()[:10]}"


def catalog_parts(objective: str) -> tuple[str, str, str | None] | None:
    """(spec id, analytic title, window phrase) of a catalog objective, or None."""
    m = _CATALOG_RE.match(objective_headline(objective))
    if m is None:
        return None
    window = None
    if m.group("since") and m.group("until"):
        window = window_phrase(m.group("since"), m.group("until"))
    return m.group("spec"), m.group("title").strip(), window


def lead_entities(objective: str) -> tuple[int, list[str]] | None:
    """(lead id, entity keys) of a lead hunt objective, or None."""
    m = _LEAD_RE.match(objective_headline(objective))
    if m is None:
        return None
    entities = [e.strip() for e in m.group("entities").split(",") if e.strip()]
    if entities == ["the entity"]:
        entities = []
    return int(m.group("id")), entities


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _lead_title(lead_id: int, entities: list[str], names: Mapping[str, str]) -> str:
    """ "Lead 6 hunt: domainadmin on SR-DC01"."""
    if not entities:
        return f"Lead {lead_id} hunt"
    shown = [names.get(e) or e for e in entities]
    addresses = [i for i, e in enumerate(entities) if _is_address(e)]
    others = [i for i, e in enumerate(entities) if not _is_address(e)]
    if len(entities) == 2 and len(addresses) == 1 and len(others) == 1:
        return f"Lead {lead_id} hunt: {shown[others[0]]} on {shown[addresses[0]]}"
    if len(shown) == 1:
        return f"Lead {lead_id} hunt: {shown[0]}"
    return f"Lead {lead_id} hunt: {', '.join(shown[:-1])} and {shown[-1]}"


def hunt_title(objective: str, *, names: Mapping[str, str] | None = None) -> str:
    """The plain title of a hunt.

    ``names`` maps an address to the host name the dossier holds, so a lead
    hunt reads "on SR-DC01" where the dossier knows the machine. An address
    with no name stays an address.
    """
    parts = catalog_parts(objective)
    if parts is not None:
        _spec, title, window = parts
        return f"{title}, {window}" if window else title
    lead = lead_entities(objective)
    if lead is not None:
        return _lead_title(lead[0], lead[1], names or {})
    return objective_headline(objective)


# The alert-only cap note, in the words the hunt page prints (dogfood
# 2026-10-06 C5 and K2). Two older phrasings sit in stored reports: the first
# carried an em dash, the second named the gate and not the next step.
ALERT_ONLY_NOTE = (
    "Severity held at medium. The finding cites alerts only. An investigation can raise it."
)
_LEGACY_ALERT_ONLY = re.compile(
    r"only detector alerts cited|cites only detector alerts", re.IGNORECASE
)


# The citation gate's notes (soc_ai.agent.hunt_gates). The gate writes the
# stored text. The page reads one fact per sentence (R3 STE 25), and every
# stored row reads the new words with no rewrite of the store.
_UNRESOLVED_CITES = re.compile(
    r"citations did not resolve to gathered evidence.*?severity (?:capped )?to (?P<sev>[a-z]+)",
    re.IGNORECASE,
)
_HIGH_NO_CITES = re.compile(r"high-severity finding has no citations", re.IGNORECASE)


def validator_note(text: str | None) -> str | None:
    """A stored validator note, reworded when an older build wrote it."""
    if not text:
        return None
    if _LEGACY_ALERT_ONLY.search(text):
        return ALERT_ONLY_NOTE
    unresolved = _UNRESOLVED_CITES.search(text)
    if unresolved is not None:
        severity = unresolved.group("sev").lower()
        return (
            f"The citations name no gathered evidence. soc-ai lowered the severity to {severity}."
        )
    if _HIGH_NO_CITES.search(text):
        return "This finding cites no evidence. soc-ai lowered the severity from high to medium."
    return text


# A step that needs the grid, the sensors or the data pipeline. The analyst
# cannot take it from the console, so the hunt page lists it apart. The second
# dogfood read "Re-extend the events window beyond 30 days" and "Review
# imported or replayed corpora" under Recommended actions.
_OPERATOR_STEP = re.compile(
    r"\b(?:re-?extend|extend|widen|increase|raise|lengthen)\b[^.]*"
    r"\b(?:window|retention|range|look-?back|history)\b"
    r"|\b(?:corpus|corpora|replay(?:ed)?|re-?ingest|ingest(?:ion)?|imported)\b"
    r"|\b(?:enable|configure|deploy|install|turn on|onboard)\b[^.]*"
    r"\b(?:logging|logs?|audit(?:ing)?|sensors?|agents?|telemetry|zeek|sysmon|"
    r"beats?|pipelines?|collection)\b",
    re.IGNORECASE,
)


def is_operator_step(title: str) -> bool:
    """True for a recommended action that the console cannot take."""
    return bool(_OPERATOR_STEP.search(title or ""))
