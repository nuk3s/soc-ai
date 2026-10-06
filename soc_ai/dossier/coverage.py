"""Which telemetry planes one host ships: host coverage as a fact the tools state.

Production held twelve false "no host telemetry" claims about one Linux server
between 2026-08-17 and 2026-09-29. Every probe behind them named the Elastic
Defend datasets ``endpoint.events.process`` and ``endpoint.events.network``.
The host never shipped those. It shipped ``system.syslog``, ``system.auth`` and
``osquery_manager.result`` through Elastic Agent, and no tool said so, so the
model read a zero from the one plane it asked about as a zero from every plane.

This module answers the question once, for one machine:

* :func:`host_coverage` runs ONE aggregation over the events pattern. It
  matches the host on ``agent.id``, ``host.name`` and ``host.hostname`` (each
  name, its short form and its full form) and ``host.ip``, and it counts the
  documents per ``event.dataset`` with the newest timestamp.
* :func:`planes_of` groups a dataset into the planes the design names. A
  dataset may sit in two planes: ``system.security`` is a host log and a
  Windows security log.
* :func:`describe` turns the result into ASD-STE100 sentences. A plane is
  present or absent. Absence is a statement about one plane, never about the
  host as a whole while any plane is present.

A failed or partial read is NOT an absence. :class:`HostCoverage` then carries
``read_ok=False`` and the reason, and :func:`describe` says that soc-ai could
not read the coverage. A false all-clear outranks any error, and a false
"no telemetry" is the same defect pointing the other way.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from soc_ai.tools._provenance import LIVE, Provenance, provenance_must_not
from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "CORE_PLANES",
    "COVERAGE_WINDOW_HOURS",
    "PLANES",
    "DatasetCount",
    "HostAgent",
    "HostCoverage",
    "HostIdentity",
    "PlaneCoverage",
    "coverage_window",
    "describe",
    "host_coverage",
    "host_identity",
    "name_variants",
    "plane_dataset_clause",
    "plane_label",
    "plane_phrase",
    "planes_of",
]

# Every plane the coverage read reports, in render order.
PLANES: tuple[str, ...] = (
    "host_logs",
    "process",
    "endpoint_network",
    "windows_security",
    "osquery",
    "agent_self",
)

# The planes whose absence is worth a sentence on any host. osquery and the
# agent's own logs are optional parts of a deployment, so their absence says
# little. Windows security absence is stated only for a Windows host.
CORE_PLANES: tuple[str, ...] = ("host_logs", "process", "endpoint_network")

# How a present plane reads in a sentence: "This host ships host logs (...)".
_PRESENT_LABEL: dict[str, str] = {
    "host_logs": "host logs",
    "process": "process events",
    "endpoint_network": "endpoint network events",
    "windows_security": "Windows security events",
    "osquery": "osquery",
    "agent_self": "agent self-logs",
}

# How an absent plane reads: "It ships no process events".
_ABSENT_LABEL: dict[str, str] = {
    "host_logs": "host logs",
    "process": "process events",
    "endpoint_network": "endpoint network events",
    "windows_security": "Windows security events",
    "osquery": "osquery results",
    "agent_self": "agent self-logs",
}

# How a plane reads as the noun before "telemetry": "No process telemetry on X".
_PLANE_PHRASE: dict[str, str] = {
    "host_logs": "host log",
    "process": "process",
    "endpoint_network": "endpoint network",
    "windows_security": "Windows security",
    "osquery": "osquery",
    "agent_self": "agent self-log",
}

# dataset -> planes. (exact names, prefixes) per plane. The prefix ends in a
# dot or not: ``journald`` matches ``journald`` and ``journald.audit`` alike.
_PLANE_RULES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "host_logs": ((), ("system.", "journald", "auditd", "linux.")),
    "process": (
        ("endpoint.events.process", "windows.sysmon_operational"),
        ("auditd.",),
    ),
    "endpoint_network": (("endpoint.events.network",), ()),
    "windows_security": (("system.security", "windows.security", "winlog"), ("winlog.",)),
    "osquery": (("osquery",), ("osquery_manager.", "osquery.")),
    "agent_self": (("elastic_agent",), ("elastic_agent.",)),
}

# Bounds on the one aggregation. A host ships tens of datasets, not hundreds.
_DATASET_BUCKETS = 100
_AGENT_BUCKETS = 5
# The most host.name values one read sends. Each given name grows into its
# short form, its full forms and a lower-case copy, so a handful of names is
# already a dozen terms.
_MAX_NAME_TERMS = 24


# The default coverage window: one day, centred on an anchor when there is one.
# An agent that covers a host ships something every few minutes, so a day is
# wide enough to see every plane it ships and narrow enough to stay cheap.
COVERAGE_WINDOW_HOURS = 24


def coverage_window(
    anchor: datetime | None, *, hours: int = COVERAGE_WINDOW_HOURS, now: datetime | None = None
) -> tuple[datetime, datetime]:
    """``(since, until)``: centred on ``anchor``, else the trailing ``hours``.

    The end never passes ``now``. A window that reaches into the future
    measures nothing more, and an anchored window that ends at now reads the
    same documents as one that does not.
    """
    current = now or datetime.now(UTC)
    span = timedelta(hours=max(1, hours))
    if anchor is None:
        return current - span, current
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=UTC)
    until = min(anchor + span / 2, current)
    return anchor - span / 2, until


def planes_of(dataset: str) -> tuple[str, ...]:
    """The planes one dataset belongs to, in :data:`PLANES` order. Empty for none."""
    name = (dataset or "").strip().lower()
    if not name:
        return ()
    out: list[str] = []
    for plane in PLANES:
        exact, prefixes = _PLANE_RULES[plane]
        if name in exact or any(name.startswith(p) for p in prefixes):
            out.append(plane)
    return tuple(out)


def plane_dataset_clause(planes: Sequence[str] = PLANES) -> dict[str, Any]:
    """An Elasticsearch clause that selects the datasets of ``planes``.

    The same rules :func:`planes_of` reads, as a query: the exact names as
    terms, the prefixes as prefix queries, on ``event.dataset``.
    """
    exact: list[str] = []
    should: list[dict[str, Any]] = []
    for plane in planes:
        names, prefixes = _PLANE_RULES[plane]
        exact.extend(n for n in names if n not in exact)
        should.extend({"prefix": {"event.dataset": p}} for p in prefixes)
    if exact:
        should.insert(0, {"terms": {"event.dataset": exact}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def plane_phrase(plane: str) -> str:
    """The plane as the noun before "telemetry": ``process`` -> "process"."""
    return _PLANE_PHRASE.get(plane, plane.replace("_", " "))


def plane_label(plane: str) -> str:
    """The present plane as a sentence names it: ``host_logs`` -> "host logs"."""
    return _PRESENT_LABEL.get(plane, plane.replace("_", " "))


class DatasetCount(BaseModel):
    """One dataset the host ships, with its document count and newest event."""

    dataset: str
    count: int
    newest: str | None = None


class PlaneCoverage(BaseModel):
    """One plane: present when any of its datasets holds a document."""

    plane: str
    present: bool
    count: int = 0
    datasets: list[DatasetCount] = Field(default_factory=list)


class HostAgent(BaseModel):
    """The agent that wrote the host's documents, as the documents name it."""

    id: str | None = None
    name: str | None = None
    os: str | None = None
    count: int = 0


class HostCoverage(BaseModel):
    """The telemetry planes one host ships in one window.

    ``read_ok`` is False when the read failed, timed out, came back partial,
    or had no identifier to search. Every plane is then absent in the data,
    and that absence means "unknown". :func:`describe` and every caller read
    ``read_ok`` before they read a plane.
    """

    read_ok: bool
    reason: str | None = None
    since: str | None = None
    until: str | None = None
    # What the read searched. A reader that doubts the answer can see why.
    addresses: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)
    agent_ids: list[str] = Field(default_factory=list)
    total: int = 0
    planes: list[PlaneCoverage] = Field(default_factory=list)
    other: list[DatasetCount] = Field(default_factory=list)
    agents: list[HostAgent] = Field(default_factory=list)

    def plane(self, plane: str) -> PlaneCoverage | None:
        return next((p for p in self.planes if p.plane == plane), None)

    def ships(self, plane: str) -> bool:
        """True only on a good read that found the plane. Unknown is False."""
        entry = self.plane(plane)
        return bool(self.read_ok and entry is not None and entry.present)

    @property
    def present(self) -> list[str]:
        """The planes the host ships, in render order. Empty on a failed read."""
        if not self.read_ok:
            return []
        return [p.plane for p in self.planes if p.present]

    @property
    def covered(self) -> bool:
        """True when a good read found at least one plane."""
        return bool(self.present)

    @property
    def agent(self) -> HostAgent | None:
        """The agent with the most documents, or None."""
        return self.agents[0] if self.agents else None

    @property
    def is_windows(self) -> bool:
        return any("windows" in (a.os or "").lower() for a in self.agents) or self.ships(
            "windows_security"
        )

    def absent(self) -> list[str]:
        """The core planes the host does not ship. Empty on a failed read."""
        if not self.read_ok:
            return []
        wanted = [*CORE_PLANES, *(("windows_security",) if self.is_windows else ())]
        return [p for p in wanted if not self.ships(p)]

    def agent_payload(self) -> dict[str, str | None] | None:
        """The top agent as ``{id, name, os}``, or None when no agent wrote."""
        agent = self.agent
        if agent is None:
            return None
        return {"id": agent.id, "name": agent.name, "os": agent.os}

    def tool_payload(self) -> dict[str, Any]:
        """The compact form a tool result carries, sentences included.

        A failed read carries no plane at all, so no reader can take an
        unknown plane for an absent one.
        """
        out: dict[str, Any] = {
            "read_ok": self.read_ok,
            "window": {"since": self.since, "until": self.until},
            "searched": {
                "addresses": self.addresses,
                "names": self.names[:8],
                "agent_ids": self.agent_ids,
            },
            "planes": (
                {
                    p.plane: {
                        "present": p.present,
                        "documents": p.count,
                        "datasets": {d.dataset: d.count for d in p.datasets},
                    }
                    for p in self.planes
                }
                if self.read_ok
                else {}
            ),
            "sentences": describe(self),
        }
        if self.read_ok and self.other:
            out["other_datasets"] = {d.dataset: d.count for d in self.other}
        if self.reason:
            out["reason"] = self.reason
        return out

    def host_names(self) -> list[str]:
        """Every name the read searched or the agent reported, lower-cased."""
        out: dict[str, None] = {}
        for name in [*self.names, *(a.name for a in self.agents if a.name)]:
            for variant in name_variants([name]):
                out.setdefault(variant.lower(), None)
        return list(out)


class HostIdentity(BaseModel):
    """The identifiers one host is searched by."""

    addresses: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)
    agent_ids: list[str] = Field(default_factory=list)


def _clean_address(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _is_address(value: str) -> bool:
    return _clean_address(value) is not None


def name_variants(names: Iterable[str]) -> list[str]:
    """Each name, its short form and its full form, plus a lower-case copy.

    ``host.name`` is a keyword: an agent that writes ``app-01`` is invisible to
    a search for ``app-01.example.test``, and the model searched the full form
    a DNS answer gave it. The full form of a short name is built from the
    domains of the full names in the same list, because nothing else here
    knows the local domain.
    """
    cleaned: list[str] = []
    for raw in names:
        text = str(raw or "").strip().rstrip(".")
        if text and not _is_address(text):
            cleaned.append(text)
    domains = {n.partition(".")[2].lower() for n in cleaned if "." in n and n.partition(".")[2]}
    out: dict[str, None] = {}

    def add(value: str) -> None:
        for v in (value, value.lower()):
            if v:
                out.setdefault(v, None)

    for name in cleaned:
        add(name)
        short = name.partition(".")[0]
        add(short)
        for domain in sorted(domains):
            add(f"{short.lower()}.{domain}")
    return list(out)[:_MAX_NAME_TERMS]


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _buckets(aggs: dict[str, Any], key: str) -> list[dict[str, Any]]:
    node = aggs.get(key) or {}
    raw = node.get("buckets") if isinstance(node, dict) else None
    return [b for b in (raw or []) if isinstance(b, dict)]


def _top_key(bucket: dict[str, Any], key: str) -> str | None:
    for sub in _buckets(bucket, key):
        value = sub.get("key")
        if isinstance(value, str) and value:
            return value
    return None


def _newest(bucket: dict[str, Any]) -> str | None:
    node = bucket.get("newest") or {}
    value = node.get("value_as_string") if isinstance(node, dict) else None
    return value if isinstance(value, str) and value else None


def _failed(
    identity: HostIdentity, since: datetime | str | None, until: datetime | str | None, reason: str
) -> HostCoverage:
    return HostCoverage(
        read_ok=False,
        reason=reason,
        since=_iso(since),
        until=_iso(until),
        addresses=identity.addresses,
        names=identity.names,
        agent_ids=identity.agent_ids,
        planes=[PlaneCoverage(plane=p, present=False) for p in PLANES],
    )


async def host_coverage(
    elastic: Any,
    settings: Any,
    *,
    addresses: Sequence[str] = (),
    names: Sequence[str] = (),
    agent_ids: Sequence[str] = (),
    since: datetime | str,
    until: datetime | str,
    include_synth: SynthScope = False,
    provenance: Provenance = LIVE,
    exclude_ids: Sequence[str] = (),
) -> HostCoverage:
    """The planes one host ships between ``since`` and ``until``. Never raises.

    One ``size=0`` search. The host is any document whose ``agent.id`` is one
    of ``agent_ids``, whose ``host.name`` or ``host.hostname`` is one of the
    name variants, or whose ``host.ip`` holds one of ``addresses``. The read
    demands a complete answer: a partial shard read raises inside the client
    and comes back here as ``read_ok=False``, never as an absence.

    ``exclude_ids`` leaves documents out by id. The prefetch passes the alert
    under triage, the same exclusion every other fan-out carries.
    """
    clean_addresses = [a for a in (_clean_address(x) for x in addresses) if a]
    variants = name_variants(names)
    clean_agents = [str(a).strip() for a in agent_ids if str(a or "").strip()]
    identity = HostIdentity(
        addresses=list(dict.fromkeys(clean_addresses)),
        names=variants,
        agent_ids=list(dict.fromkeys(clean_agents)),
    )
    should: list[dict[str, Any]] = []
    if identity.agent_ids:
        should.append({"terms": {"agent.id": identity.agent_ids}})
    if variants:
        should.append({"terms": {"host.name": variants}})
        should.append({"terms": {"host.hostname": variants}})
    if identity.addresses:
        should.append({"terms": {"host.ip": identity.addresses}})
    if not should:
        return _failed(identity, since, until, "no address, name or agent id to search")

    query: dict[str, Any] = {
        "bool": {
            "filter": [{"range": {"@timestamp": {"gte": _iso(since), "lte": _iso(until)}}}],
            "should": should,
            "minimum_should_match": 1,
            "must_not": [
                *([{"ids": {"values": list(exclude_ids)}}] if exclude_ids else []),
                *synth_scope_must_not(include_synth),
                *provenance_must_not(provenance),
            ],
        }
    }
    aggs: dict[str, Any] = {
        "host_datasets": {
            "terms": {"field": "event.dataset", "size": _DATASET_BUCKETS},
            "aggs": {"newest": {"max": {"field": "@timestamp"}}},
        },
        "host_agents": {
            "terms": {"field": "agent.id", "size": _AGENT_BUCKETS},
            "aggs": {
                "names": {"terms": {"field": "agent.name", "size": 1}},
                "os": {"terms": {"field": "host.os.name", "size": 1}},
            },
        },
        # Documents with no agent.id still name a machine. Read only when the
        # agent.id terms come back empty.
        "host_agent_names": {
            "terms": {"field": "agent.name", "size": _AGENT_BUCKETS},
            "aggs": {"os": {"terms": {"field": "host.os.name", "size": 1}}},
        },
    }
    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=0,
            aggs=aggs,
            track_total_hits=True,
            require_complete=True,
        )
    except Exception as exc:  # a failed read is unknown, never absent
        _LOGGER.warning("host coverage read failed: %s", type(exc).__name__)
        reason = f"the coverage read failed ({type(exc).__name__})"
        return _failed(identity, since, until, reason)

    raw_aggs = result.aggregations if isinstance(result.aggregations, dict) else {}
    datasets: list[DatasetCount] = []
    for bucket in _buckets(raw_aggs, "host_datasets"):
        key = bucket.get("key")
        if not isinstance(key, str) or not key:
            continue
        datasets.append(
            DatasetCount(
                dataset=key, count=int(bucket.get("doc_count") or 0), newest=_newest(bucket)
            )
        )
    datasets.sort(key=lambda d: (-d.count, d.dataset))

    planes: list[PlaneCoverage] = []
    for plane in PLANES:
        members = [d for d in datasets if plane in planes_of(d.dataset)]
        planes.append(
            PlaneCoverage(
                plane=plane,
                present=any(d.count > 0 for d in members),
                count=sum(d.count for d in members),
                datasets=members,
            )
        )
    other = [d for d in datasets if not planes_of(d.dataset)]

    agents: list[HostAgent] = []
    for bucket in _buckets(raw_aggs, "host_agents"):
        key = bucket.get("key")
        agents.append(
            HostAgent(
                id=str(key) if key else None,
                name=_top_key(bucket, "names"),
                os=_top_key(bucket, "os"),
                count=int(bucket.get("doc_count") or 0),
            )
        )
    if not agents:
        for bucket in _buckets(raw_aggs, "host_agent_names"):
            key = bucket.get("key")
            if isinstance(key, str) and key:
                agents.append(
                    HostAgent(
                        name=key, os=_top_key(bucket, "os"), count=int(bucket.get("doc_count") or 0)
                    )
                )

    return HostCoverage(
        read_ok=True,
        since=_iso(since),
        until=_iso(until),
        addresses=identity.addresses,
        names=identity.names,
        agent_ids=identity.agent_ids,
        total=result.total if isinstance(result.total, int) else 0,
        planes=planes,
        other=other,
        agents=agents,
    )


def _count(value: int) -> str:
    return f"{value:,}"


def _join(items: Sequence[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def _dataset_list(datasets: Sequence[DatasetCount], *, limit: int = 4) -> str:
    shown = [f"{d.dataset} {_count(d.count)}" for d in datasets[:limit]]
    rest = len(datasets) - limit
    if rest > 0:
        shown.append(f"{rest} more")
    return ", ".join(shown)


def describe(cov: HostCoverage, *, subject: str = "This host") -> list[str]:
    """ASD-STE100 sentences that state what the host ships and does not ship.

    A good read with planes present gives two sentences: the planes with their
    datasets and counts, then the core planes that are absent. A good read
    with no document gives one sentence of absence per core plane. A failed
    read gives one sentence that says soc-ai could not read the coverage, and
    no absence at all.
    """
    if not cov.read_ok:
        why = f" {cov.reason[0].upper()}{cov.reason[1:]}." if cov.reason else ""
        whose = "the host's coverage" if subject == "This host" else f"the coverage of {subject}"
        return [f"soc-ai could not read {whose}.{why}"]
    pronoun = "It" if subject == "This host" else subject
    present = [p for p in cov.planes if p.present]
    absent = cov.absent()
    sentences: list[str] = []
    if present:
        parts = [f"{_PRESENT_LABEL[p.plane]} ({_dataset_list(p.datasets)})" for p in present]
        sentences.append(f"{subject} ships {_join(parts)}.")
        if absent:
            sentences.append(
                f"{pronoun} ships " + _join([f"no {_ABSENT_LABEL[p]}" for p in absent]) + "."
            )
    else:
        sentences.append(
            f"soc-ai found no host document for {_object(subject)} in the window. "
            f"{pronoun} ships " + _join([f"no {_ABSENT_LABEL[p]}" for p in absent]) + "."
        )
    if cov.other:
        sentences.append(f"{pronoun} also ships {_dataset_list(cov.other)}.")
    return sentences


def _object(subject: str) -> str:
    """The subject as the object of a sentence: "This host" -> "this host"."""
    return "this host" if subject == "This host" else subject


# ---------------------------------------------------------------------------
# Identity input.
# ---------------------------------------------------------------------------

# The host-agent lane writes its evidence as "<name> (self-reported, ...)" and
# "<name> reported N hardware addresses ... (from host-agent)". The name before
# the marker is the agent's own host.name.
_SELF_REPORTED = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]{0,252})\s+\(self-reported\b")
_AGENT_REPORTED = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]{0,252})\s+reported\s+\d+\s+hardware\s+addresses\b"
)
_STRONG = "strong"


def _evidence_names(evidence: Any) -> list[str]:
    """Names in one field's evidence: strong lane values and agent self-reports."""
    out: list[str] = []
    if not isinstance(evidence, dict):
        return out
    for lane in evidence.values():
        if not isinstance(lane, dict):
            continue
        for text in lane.get("strings") or []:
            if not isinstance(text, str):
                continue
            for pattern in (_SELF_REPORTED, _AGENT_REPORTED):
                match = pattern.match(text)
                if match:
                    out.append(match.group(1))
    return out


async def host_identity(db: Any, value: str) -> HostIdentity:
    """The addresses, names and agent ids to search one host by.

    The machine resolver replaces this function at merge (host identity
    design, 2026-10-02). Until then it reads the per-address dossier: the
    hostname field's effective and inferred values, the strong values in its
    evidence, the strong aliases the store joins on, and the names the host
    agent reported in any field's evidence. The store keeps no agent id
    today, so ``agent_ids`` stays empty and the read keys on address and name.

    Never raises. A value the store does not know yields the value itself.
    """
    # Imported here: the store imports the dossier package, and the dossier
    # package must import without the store for the pure modules to stay pure.
    from soc_ai.store import host_dossier as dossier_store  # noqa: PLC0415

    text = str(value or "").strip()
    if not text:
        return HostIdentity()
    address = _clean_address(text)
    addresses: list[str] = [address] if address else []
    names: list[str] = [] if address else [text]
    try:
        aliases = await dossier_store.entity_aliases(db, text)
    except Exception:
        _LOGGER.warning("host identity: alias read failed for one host", exc_info=True)
        aliases = []
    for alias in aliases:
        alias_address = _clean_address(alias)
        if alias_address:
            addresses.append(alias_address)
        else:
            names.append(alias)
    for ip in list(addresses):
        try:
            stored = await dossier_store.get_dossier(db, ip)
        except Exception:
            _LOGGER.warning("host identity: dossier read failed for one host", exc_info=True)
            continue
        if stored is None:
            continue
        _host, rows = stored
        for row in rows:
            evidence = getattr(row, "inferred_evidence", None)
            names.extend(_evidence_names(evidence))
            if getattr(row, "field", None) != "hostname":
                continue
            for candidate in (
                getattr(row, "operator_value", None),
                getattr(row, "inferred_value", None),
            ):
                if isinstance(candidate, str) and candidate.strip():
                    names.append(candidate.strip())
            if isinstance(evidence, dict):
                for lane in evidence.values():
                    if (
                        isinstance(lane, dict)
                        and lane.get("strength") == _STRONG
                        and isinstance(lane.get("value"), str)
                        and lane["value"].strip()
                    ):
                        names.append(lane["value"].strip())
    return HostIdentity(
        addresses=list(dict.fromkeys(addresses)),
        names=list(dict.fromkeys(n for n in names if not _is_address(n))),
        agent_ids=[],
    )
