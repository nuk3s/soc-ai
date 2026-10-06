"""One behaviour vector per host, from the stored profiles.

The profile build writes one row per host and dimension. This module reduces
the rows of one host to numbers, in a fixed order, with the name of each
number beside it:

* each set dimension: how many members the set holds, and the documents per
  support day behind them;
* the active hours: how many hours of the day the host was ever active in, and
  the share of its activity from 00:00 to 06:00 local time;
* the connection rate: the median connections an hour in each of the three
  cells, work hours, off hours and the weekend;
* one coverage flag per plane: 1 when a dimension of the plane is measured or
  learning for the host, else 0;
* one flag per declared role: 1 when an operator declared that role.

Counts and rates are skewed: one server serves ten thousand flows an hour
where a desk serves ten. They enter the model as ``log1p``. Hours, shares and
flags enter as they are. :mod:`.fit` standardizes every column after that.

A host with no measured or learning dimension has no behaviour to describe.
It gets no vector, and the run counts it as blind.

Pure Python: the doctor and the tests read this without the extra.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.dossier.profile import _CATEGORICAL
from soc_ai.store.models import EntityProfile

__all__ = [
    "BASE_FEATURES",
    "DECLARED",
    "PARTITIONS",
    "PLANES",
    "RATE_CELLS",
    "SET_DIMENSIONS",
    "Feature",
    "HostVector",
    "VectorSet",
    "collect_vectors",
    "feature_list",
    "matrix",
    "model_value",
    "partition_of",
    "reduce_row",
    "render",
    "vectors_from_rows",
]

SET_DIMENSIONS: tuple[str, ...] = tuple(row[0] for row in _CATEGORICAL)

# The two key spaces of the profile store. The flow and DNS planes key a host
# on its address, the process and logon planes on its ``host.name``. A vector
# of one space has zeros in every column of the other, so the model fits each
# space apart, and a host's peers come from its own space.
PARTITIONS: tuple[str, ...] = ("address", "name")
RATE_CELLS: tuple[str, ...] = ("work", "off", "weekend")

# The plane of each dimension. A flag per plane says whether the host ships it.
PLANES: dict[str, tuple[str, ...]] = {
    "flow": ("peers_out", "consumed_ports", "served_ports", "active_hours", "connection_rate"),
    "dns": ("dns_names",),
    "process": ("process_names", "process_parents"),
    "logon": ("logon_users",),
}
_PLANE_OF: dict[str, str] = {dim: plane for plane, dims in PLANES.items() for dim in dims}

# The coverage states that describe what a host does. Blind, behind a proxy
# and unmeasurable describe what soc-ai could not see.
_COVERED = frozenset({"measured", "learning"})

# The local hours the night share counts: 00:00 to 05:59.
_NIGHT_HOURS = frozenset(range(6))

# A declared role carries full confidence (soc_ai.hunting.roles.roles). An
# inference at 0.9 is a belief, not a declaration, and it does not enter the
# vector.
DECLARED = 1.0

# Profile rows per read. A rate vector holds every hour of the window, so a
# page of 1,000 rows is under a million numbers.
_PAGE = 1000

_SET_LABELS: dict[str, tuple[str, str]] = {
    "peers_out": ("peers reached", "flows to peers a day"),
    "consumed_ports": ("outbound ports", "outbound port flows a day"),
    "served_ports": ("served ports", "served port flows a day"),
    "process_names": ("process names", "process starts a day"),
    "process_parents": ("parent process names", "parent process events a day"),
    "dns_names": ("DNS names", "DNS queries a day"),
    "logon_users": ("logon users", "logons a day"),
}
_CELL_LABELS: dict[str, str] = {
    "work": "connections an hour in work hours",
    "off": "connections an hour off hours",
    "weekend": "connections an hour at the weekend",
}
_PLANE_LABELS: dict[str, str] = {
    "flow": "network flow plane",
    "dns": "DNS plane",
    "process": "process plane",
    "logon": "logon plane",
}


@dataclass(frozen=True)
class Feature:
    """One column of the vector.

    ``unit`` says how a value reads to an analyst: ``count``, ``rate``,
    ``hours``, ``share``, ``plane`` or ``role``. ``log`` says the model reads
    the value as ``log1p``.
    """

    name: str
    label: str
    unit: str
    log: bool


def _base_features() -> tuple[Feature, ...]:
    out: list[Feature] = []
    for dim in SET_DIMENSIONS:
        members, per_day = _SET_LABELS.get(dim, (dim.replace("_", " "), f"{dim} events a day"))
        out.append(Feature(f"{dim}.members", members, "count", True))
        out.append(Feature(f"{dim}.per_day", per_day, "rate", True))
    out.append(Feature("active_hours.hours", "active hours of the day", "hours", False))
    out.append(
        Feature("active_hours.night_share", "share of activity from 00:00 to 06:00", "share", False)
    )
    for cell in RATE_CELLS:
        out.append(Feature(f"connection_rate.{cell}", _CELL_LABELS[cell], "rate", True))
    for plane in PLANES:
        out.append(Feature(f"plane.{plane}", _PLANE_LABELS[plane], "plane", False))
    return tuple(out)


BASE_FEATURES: tuple[Feature, ...] = _base_features()


def _role_feature(role: str) -> Feature:
    return Feature(f"role.{role}", f"declared role {role}", "role", False)


@dataclass
class HostVector:
    """The reduced numbers of one host, keyed by feature name, in raw units."""

    entity_key: str
    raw: dict[str, float] = field(default_factory=dict)
    support_days: int = 0
    role: str | None = None


@dataclass(frozen=True)
class VectorSet:
    """Every host vector of one read, and the hosts that had nothing to describe."""

    vectors: list[HostVector]
    blind: int


def partition_of(entity_key: str) -> str:
    """``address`` for a key that is an IP address, ``name`` for any other key."""
    try:
        ipaddress.ip_address(entity_key)
    except ValueError:
        return "name"
    return "address"


def _count(entry: Any) -> float:
    if isinstance(entry, Mapping):
        value = entry.get("count")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0.0, float(value))
    return 0.0


def _median(entry: Any) -> float:
    if isinstance(entry, Mapping):
        value = entry.get("median")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0.0, float(value))
    return 0.0


def reduce_row(
    dimension: str, coverage: str, vector: Any, *, support_days: int
) -> dict[str, float]:
    """The numbers one profile row adds to its host's vector.

    A row that does not cover the host adds nothing. Its plane flag stays 0
    unless another dimension of the plane covers the host.
    """
    if coverage not in _COVERED:
        return {}
    out: dict[str, float] = {}
    plane = _PLANE_OF.get(dimension)
    if plane is not None:
        out[f"plane.{plane}"] = 1.0
    entries: Mapping[str, Any] = vector if isinstance(vector, Mapping) else {}
    if dimension in SET_DIMENSIONS:
        total = sum(_count(entry) for entry in entries.values())
        out[f"{dimension}.members"] = float(len(entries))
        out[f"{dimension}.per_day"] = total / max(1, int(support_days or 0))
    elif dimension == "active_hours":
        counts: dict[int, float] = {}
        for hour, entry in entries.items():
            try:
                counts[int(hour)] = _count(entry)
            except (TypeError, ValueError):
                continue
        active = {h: c for h, c in counts.items() if c > 0}
        total = sum(active.values())
        out["active_hours.hours"] = float(len(active))
        night = sum(c for h, c in active.items() if h in _NIGHT_HOURS)
        out["active_hours.night_share"] = night / total if total > 0 else 0.0
    elif dimension == "connection_rate":
        for cell in RATE_CELLS:
            out[f"connection_rate.{cell}"] = _median(entries.get(cell))
    return out


def vectors_from_rows(
    rows: Iterable[tuple[str, str, str, int | None, str | None, float | None, Any]],
) -> VectorSet:
    """Fold profile rows into one vector per host.

    Each row is ``(entity_key, dimension, coverage, support_days, role,
    role_confidence, vector)``. A host keyed on an address and the same
    machine keyed on its name are two vectors: the profile store keys the
    flow and DNS planes on the address and the process and logon planes on
    ``host.name``.
    """
    hosts: dict[str, HostVector] = {}
    seen: set[str] = set()
    for key, dimension, coverage, support, role, confidence, vector in rows:
        entity = str(key)
        seen.add(entity)
        reduced = reduce_row(str(dimension), str(coverage), vector, support_days=int(support or 0))
        if not reduced:
            continue
        host = hosts.setdefault(entity, HostVector(entity_key=entity))
        host.raw.update(reduced)
        host.support_days = max(host.support_days, int(support or 0))
        if role and confidence is not None and float(confidence) >= DECLARED:
            host.role = str(role)
    ordered = [hosts[key] for key in sorted(hosts)]
    return VectorSet(vectors=ordered, blind=len(seen) - len(hosts))


async def collect_vectors(db: AsyncSession, *, page: int = _PAGE) -> VectorSet:
    """Read every host profile row, a page at a time, and fold it into vectors.

    Keyset pages on the row id. A whole read of the table on an estate of
    20,000 hosts holds 180,000 rows, and the rate rows carry every hour of the
    window.
    """
    rows: list[tuple[str, str, str, int | None, str | None, float | None, Any]] = []
    last = 0
    while True:
        batch = (
            await db.execute(
                select(
                    EntityProfile.id,
                    EntityProfile.entity_key,
                    EntityProfile.dimension,
                    EntityProfile.coverage,
                    EntityProfile.support_days,
                    EntityProfile.role,
                    EntityProfile.role_confidence,
                    EntityProfile.vector_json,
                )
                .where(EntityProfile.entity_kind == "host", EntityProfile.id > last)
                .order_by(EntityProfile.id)
                .limit(page)
            )
        ).all()
        if not batch:
            break
        for row_id, key, dimension, coverage, support, role, confidence, vector in batch:
            last = int(row_id)
            # Reduced at once, so a page of rate vectors is released before the next.
            reduced_vector = (
                {c: vector.get(c) for c in RATE_CELLS}
                if dimension == "connection_rate" and isinstance(vector, dict)
                else vector
            )
            rows.append((key, dimension, coverage, support, role, confidence, reduced_vector))
        if len(batch) < page:
            break
    return vectors_from_rows(rows)


def feature_list(vectors: Sequence[HostVector]) -> list[Feature]:
    """The columns, in order: the base features, then one per declared role."""
    roles = sorted({v.role for v in vectors if v.role})
    return [*BASE_FEATURES, *(_role_feature(role) for role in roles)]


def model_value(feature: Feature, value: float) -> float:
    """The value the model reads: ``log1p`` for counts and rates."""
    return math.log1p(max(0.0, value)) if feature.log else float(value)


def matrix(
    vectors: Sequence[HostVector], features: Sequence[Feature]
) -> tuple[list[list[float]], list[list[float]]]:
    """The raw rows and the model rows, one per host, one column per feature."""
    raw_rows: list[list[float]] = []
    model_rows: list[list[float]] = []
    for host in vectors:
        raw = [
            (1.0 if host.role == f.name[len("role.") :] else 0.0)
            if f.unit == "role"
            else float(host.raw.get(f.name, 0.0))
            for f in features
        ]
        raw_rows.append(raw)
        model_rows.append([model_value(f, v) for f, v in zip(features, raw, strict=True)])
    return raw_rows, model_rows


def render(feature: Feature, value: float) -> str:
    """One value as an analyst reads it."""
    if feature.unit == "plane":
        return "present" if value >= 0.5 else "absent"
    if feature.unit == "role":
        return "yes" if value >= 0.5 else "no"
    if feature.unit == "share":
        return f"{value * 100:.0f} %"
    if feature.unit == "hours":
        return f"{value:.0f} h"
    if feature.unit == "count":
        return f"{round(value):,}"
    return f"{value:,.1f}"
