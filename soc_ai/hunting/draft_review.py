"""What an analyst reads about a drafted analytic before soc-ai stores it.

The draft confirm box showed the id and one dry-run line. The definition was
readable only after the save, in the Analytics tab. The second dogfood saved
a draft whose description said "uid equals root" while its logic did not test
uid, whose dry run found nothing because the source documents were older than
the window, and whose logic only repeated two Suricata rule names that raise
alerts already. Each of those is a fact the draft itself holds, so this
module states them in words before the save.
"""

from __future__ import annotations

from typing import Any

from soc_ai.hunting.spec import Clause, Detection, HuntSpec

__all__ = ["alert_rule_repeats", "logic_sentence", "source_sentence"]

# The fields that hold the name or the id of a detector rule. A clause on one
# of them matches the alert that rule already raised.
RULE_FIELDS: frozenset[str] = frozenset(
    {
        "rule.name",
        "rule.uuid",
        "rule.id",
        "rule.rule",
        "rule.signature",
        "rule.signature_id",
        "alert.signature",
        "alert.signature_id",
        "suricata.eve.alert.signature",
        "suricata.eve.alert.signature_id",
    }
)

# The fields that say which source a document came from. A clause on one of
# them narrows the population. It does not describe a behaviour.
SOURCE_FIELDS: frozenset[str] = frozenset(
    {
        "event.dataset",
        "event.module",
        "event.category",
        "event.kind",
        "event.type",
        "observer.name",
        "observer.type",
        "tags",
        "data_stream.dataset",
    }
)

_OP_WORDS: dict[str, str] = {
    "equals": "is",
    "one_of": "is one of",
    "contains": "contains",
    "prefix": "starts with",
    "wildcard": "matches",
    "gt": "is above",
    "gte": "is at least",
    "lt": "is below",
    "lte": "is at most",
}

# A clause list longer than this is counted in the sentence. A clause value
# is never cut. The console wraps a long one.
_CLAUSE_CAP = 4


def _value(value: Any) -> str:
    if isinstance(value, list):
        shown = [_value(v) for v in value[:3]]
        more = len(value) - len(shown)
        return ", ".join(shown) + (f" and {more} more" if more > 0 else "")
    return str(value)


def _clause(c: Clause, *, negate: bool = False) -> str:
    if c.op == "exists":
        return f"{c.field} is {'absent' if negate else 'present'}"
    verb = _OP_WORDS.get(c.op, c.op)
    if negate:
        verb = {"is": "is not", "is one of": "is not one of"}.get(verb, f"not {verb}")
    return f"{c.field} {verb} {_value(c.value)}"


def _join(parts: list[str], word: str) -> str:
    if len(parts) > _CLAUSE_CAP:
        parts = [*parts[:_CLAUSE_CAP], f"{len(parts) - _CLAUSE_CAP} more conditions"]
    if len(parts) <= 1:
        return "".join(parts)
    return f"{', '.join(parts[:-1])} {word} {parts[-1]}"


def logic_sentence(spec: HuntSpec) -> str:
    """The detection of a ``match`` analytic as one sentence.

    A profile or a model analytic has no clause list. Its sentence names the
    method.
    """
    detection: Detection | None = spec.detection
    if detection is None:
        if spec.evaluator == "profile":
            return "The analytic compares each entity with its own baseline."
        return "The analytic runs a learned detector."
    parts: list[str] = []
    if detection.all:
        parts.append(_join([_clause(c) for c in detection.all], "and"))
    if detection.any:
        parts.append("at least one of: " + _join([_clause(c) for c in detection.any], "or"))
    if detection.none:
        parts.append(
            "never when " + _join([_clause(c, negate=False) for c in detection.none], "or")
        )
    body = "; ".join(p for p in parts if p) or "any document"
    return f"It matches a document where {body}, grouped by {spec.scope_field}."


def _source_name(spec: HuntSpec) -> str:
    """The detector the repeated rules belong to, in one word."""
    values: list[str] = []
    for c in spec.detection.all if spec.detection else []:
        if c.field in SOURCE_FIELDS:
            values += [str(v) for v in (c.value if isinstance(c.value, list) else [c.value])]
    text = " ".join(values).lower()
    if "suricata" in text:
        return "Suricata"
    if "sigma" in text:
        return "Sigma"
    if "zeek" in text:
        return "Zeek"
    return "detector"


def alert_rule_repeats(spec: HuntSpec) -> str | None:
    """A warning when the logic only names rules that raise alerts already.

    Every positive clause either picks a source or names a rule, and at least
    one names a rule. Such an analytic finds the alert again, one sweep later.
    None when any clause tests a behaviour of its own.
    """
    detection = spec.detection
    if detection is None:
        return None
    positive = [*detection.all, *detection.any]
    rule_clauses = [c for c in positive if c.field in RULE_FIELDS]
    if not rule_clauses:
        return None
    if any(c.field not in RULE_FIELDS and c.field not in SOURCE_FIELDS for c in positive):
        return None
    names: set[str] = set()
    for c in rule_clauses:
        values = c.value if isinstance(c.value, list) else [c.value]
        names.update(str(v) for v in values if v is not None)
    count = max(1, len(names))
    source = _source_name(spec)
    noun = "rule" if count == 1 else "rules"
    verb = "raises" if count == 1 else "raise"
    return (
        f"This analytic repeats {count} {source} {noun}. "
        f"{'It' if count == 1 else 'They'} {verb} alerts already."
    )


def source_sentence(*, cited: int, matched: int | None, older: int, window_days: int) -> str | None:
    """How the source finding's documents fare against the draft.

    ``matched`` is the count of cited documents the logic matches inside the
    dry-run window, None when the check did not run. ``older`` is the count of
    cited documents older than the window.
    """
    if cited <= 0 or matched is None:
        return None
    line = f"Source finding: {matched} of {cited} document{'' if cited == 1 else 's'} match."
    if older >= cited:
        word = "It is" if cited == 1 else "They are"
        return f"{line} {word} older than the {window_days}-day dry run."
    if older > 0:
        verb = "is" if older == 1 else "are"
        return f"{line} {older} of them {verb} older than the {window_days}-day dry run."
    missed = cited - matched
    if missed > 0:
        return f"{line} The logic misses {missed} of them."
    return line
