"""Analyst words for observation kinds.

``novel_served_port`` is a column name. An analyst reads "new served port".
The bell showed the column names, and a lead announced itself as "Lead 12
formed on 10.1.2.3: novel destination, off hours". One map, used by every
route that shows a kind to a person.

The keys are the values of :class:`soc_ai.hunting.weight.Kind`. They are
identifiers and they do not change. Only the words on the right change.
"""

from __future__ import annotations

KIND_LABEL: dict[str, str] = {
    "novel_destination": "new destination",
    "novel_served_port": "new served port",
    "novel_consumed_port": "new outbound port",
    "novel_process": "new process",
    "novel_process_pair": "new process pair",
    "novel_binding": "first logon here",
    "rare_for_peers": "rare for peers",
    "off_hours": "off hours",
    "below_baseline": "rate collapsed",
    "above_baseline": "rate spiked",
    "scope_count": "across many hosts",
    "alert": "alert",
    "prior_no_baseline": "finding with no benign baseline",
    "catalog_match": "analytic match",
    "hunt_finding": "hunt finding",
}

__all__ = ["KIND_LABEL", "kind_label"]


def kind_label(kind: str | None) -> str:
    """The analyst's words for one kind.

    A kind with no entry reads as itself with the underscores removed. A new
    kind then arrives as readable text rather than as an empty chip, and the
    missing entry is visible in the product.
    """
    key = str(kind or "").strip()
    if not key:
        return ""
    return KIND_LABEL.get(key, key.replace("_", " "))
