"""The first line of a run: the verdict, the impact and the two hosts by name.

H2 (2026-11-13). On production 46% of the summaries named a host by its bare
address, and 10% stated the verdict first. The first line is a fixed sentence
that the server builds, never the model::

    True positive. Impact: attempted. devbox (workstation) 10.40.50.7 to mainsrv 10.20.30.5.

Each end reads "name (role) address" when the Hosts data has a name or a
role, and the address alone when it has neither. A verdict that is no true
positive leaves the impact part out.

The run stores the line with its report (``report["first_line"]``), with the
two ends (``report["ends"]``) and the time of its event
(``report["event_time"]``). A row that an older release stored has none of
the three, so a reader builds the line from what the row holds
(:func:`of_run`), and the impact then reads "not stated".

The names and the roles come from the Hosts data, through the helpers that
already resolve them: the machine of an address
(:func:`soc_ai.store.authorized_activity.machine_refs`), the machine of a
name (:mod:`soc_ai.store.host_machines`) and the role resolver of the dossier
(:func:`soc_ai.dossier.resolve.resolve_field`). One call resolves every value
of a page, so no list row pays a query of its own.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.dossier.resolve import (
    DEFAULT_MIN_CONFIDENCE,
    DEFAULT_STALENESS_HOURS,
    resolve_field,
)
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store import event_at as event_at_svc
from soc_ai.store import host_machines
from soc_ai.store.host_dossier import ROLE_FIELD
from soc_ai.store.models import HostDossier, HostDossierField, HostMachine
from soc_ai.triage_models import IMPACT_ORDER, TRUE_POSITIVE, is_pipeline_fallback

_LOGGER = logging.getLogger(__name__)

# The verdict as the first words of the line.
VERDICT_WORDS: dict[str, str] = {
    "true_positive": "True positive",
    "false_positive": "False positive",
    "needs_more_info": "Needs more info",
    "inconclusive": "Inconclusive",
}
# The impact of a true positive that an older release stored.
NOT_STATED = "not stated"

# The keys of the stored report that this module writes and reads.
FIRST_LINE_KEY = "first_line"
ENDS_KEY = "ends"
EVENT_TIME_KEY = event_at_svc.EVENT_TIME_KEY


@dataclass(frozen=True)
class HostLabel:
    """What the Hosts data says about one address or one host name.

    ``address`` is the value when it is an address, and the primary address
    of the machine when the value is a name. ``role`` is the role in words,
    "domain controller". Every part is None when the Hosts data has none.
    """

    address: str | None = None
    name: str | None = None
    role: str | None = None
    machine_key: str | None = None


def is_address(value: str | None) -> bool:
    """True when *value* is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return True


def _clean(value: Any) -> str | None:
    text = value.strip() if isinstance(value, str) else ""
    return text or None


def _role_words(row: HostDossierField | None, *, now: datetime, knobs: tuple[float, int]) -> str:
    """The role the resolver asserts for one role row, in words, or empty.

    The rule of the Hosts list: an operator value, else an inferred value that
    is fresh and above the confidence floor. "unknown" is no role.
    """
    if row is None:
        return ""
    resolved = resolve_field(row, now=now, min_confidence=knobs[0], staleness_hours=knobs[1])
    value = (resolved.value or "").strip()
    if not value or value.lower() == "unknown":
        return ""
    if not (resolved.overridden or resolved.inference_assertable):
        return ""
    return value.replace("_", " ")


async def labels_for(
    db: AsyncSession,
    values: Iterable[str | None],
    *,
    now: datetime | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    staleness_hours: int = DEFAULT_STALENESS_HOURS,
) -> dict[str, HostLabel]:
    """The label of each address and each host name in *values*, keyed as given.

    Two reads for a set of addresses: the machine of each address, then the
    name, the primary address and the role row of each machine. A set with a
    host name adds the two reads of the machine names. A value that the Hosts
    data does not hold has no entry. A container address has none either: the
    traffic of a container is its own workload, so the address names no
    machine.
    """
    wanted = sorted({text for v in values if (text := _clean(v)) is not None})
    if not wanted:
        return {}
    key_of: dict[str, str] = {}
    addresses = [v for v in wanted if is_address(v)]
    if addresses:
        refs = await authorized_svc.machine_refs(db, addresses)
        for value, ref in refs.items():
            key = authorized_svc.machine_key_now(ref)
            if key:
                key_of[value] = key
    names = [v for v in wanted if not is_address(v)]
    if names:
        live = await host_machines._live_names(db)
        for value in names:
            # A name that two machines answer to names none of them.
            matched = host_machines._match_named(live, value)
            if len(matched) == 1 and matched[0].machine_key:
                key_of[value] = str(matched[0].machine_key)
    if not key_of:
        return {}
    rows = (
        await db.execute(
            select(
                HostMachine.machine_key,
                HostMachine.name,
                HostMachine.agent_name,
                HostMachine.primary_ip,
                HostDossierField,
            )
            .outerjoin(
                HostDossier,
                and_(
                    HostDossier.machine_id == HostMachine.id,
                    HostDossier.ip == HostMachine.primary_ip,
                ),
            )
            .outerjoin(
                HostDossierField,
                and_(
                    HostDossierField.dossier_id == HostDossier.id,
                    HostDossierField.field == ROLE_FIELD,
                ),
            )
            .where(
                HostMachine.machine_key.in_(sorted(set(key_of.values()))),
                HostMachine.address_count > 0,
            )
        )
    ).all()
    at = now or datetime.now(UTC)
    knobs = (float(min_confidence), int(staleness_hours))
    machines: dict[str, tuple[str | None, str | None, str]] = {}
    for machine_key, name, agent_name, primary_ip, role_row in rows:
        machines[str(machine_key)] = (
            _clean(name) or _clean(agent_name),
            _clean(primary_ip),
            _role_words(role_row, now=at, knobs=knobs),
        )
    out: dict[str, HostLabel] = {}
    for value, key in key_of.items():
        found = machines.get(key)
        if found is None:
            continue
        name, primary_ip, role = found
        out[value] = HostLabel(
            address=value if is_address(value) else primary_ip,
            name=name,
            role=role or None,
            machine_key=key,
        )
    return out


async def labels_for_settings(
    db: AsyncSession, values: Iterable[str | None], settings: Any
) -> dict[str, HostLabel]:
    """:func:`labels_for` with the confidence floor and the staleness of the settings.

    Never raises: the first line of a run must not fail a page or a run. A
    failed read gives no label, and each end then prints as its address.
    """
    try:
        return await labels_for(
            db,
            values,
            min_confidence=float(
                getattr(settings, "dossier_min_confidence", DEFAULT_MIN_CONFIDENCE)
                or DEFAULT_MIN_CONFIDENCE
            ),
            staleness_hours=int(
                getattr(settings, "dossier_staleness_hours", DEFAULT_STALENESS_HOURS)
                or DEFAULT_STALENESS_HOURS
            ),
        )
    except Exception:
        _LOGGER.warning("first line: the Hosts data is not readable", exc_info=True)
        return {}


def end_text(value: str | None, label: HostLabel | None = None) -> str:
    """One end of the line: "name (role) address", or what the Hosts data has of it.

    An address that the Hosts data does not hold prints alone, with no name
    and no brackets. A role with no name follows the address.
    """
    text = _clean(value)
    if text is None:
        return ""
    name = label.name if label is not None else None
    role = label.role if label is not None else None
    if is_address(text):
        address: str | None = text
    else:
        # The value is a host name. It is the name, and the Hosts data may
        # hold the address.
        name = name or text
        address = label.address if label is not None else None
    if name and address and name.casefold() == address.casefold():
        name = None
    if name:
        parts = [name, f"({role})" if role else "", address or ""]
    else:
        parts = [address or "", f"({role})" if role else ""]
    return " ".join(part for part in parts if part)


def build(
    verdict: str | None,
    impact: str | None,
    source: str | None,
    target: str | None,
    labels: Mapping[str, HostLabel] | None = None,
) -> str | None:
    """The first line of a run, or None for a run with no verdict.

    ``impact`` is read only for a true positive. A value that is none of the
    four prints as "not stated".
    """
    words = VERDICT_WORDS.get(str(verdict or ""))
    if words is None:
        return None
    held = labels or {}
    parts = [f"{words}."]
    if verdict == TRUE_POSITIVE:
        stated = impact if isinstance(impact, str) and impact in IMPACT_ORDER else NOT_STATED
        parts.append(f"Impact: {stated}.")
    src, dst = _clean(source), _clean(target)
    src_label = held.get(src) if src else None
    dst_label = held.get(dst) if dst else None
    if (
        src_label is not None
        and dst_label is not None
        and src_label.machine_key
        and src_label.machine_key == dst_label.machine_key
    ):
        # Both values name one machine: a host log that names its own address.
        src = None
    left, right = end_text(src, src_label), end_text(dst, dst_label)
    if left and right:
        parts.append(f"{left} to {right}.")
    elif left or right:
        parts.append(f"{left or right}.")
    return " ".join(parts)


def headline(line: str | None) -> str:
    """The first line without the verdict words: the impact and the hosts."""
    text = (line or "").strip()
    for words in VERDICT_WORDS.values():
        prefix = f"{words}."
        if text.startswith(prefix):
            return text[len(prefix) :].strip()
    return text


def finding_ends(
    src: str | None, dst: str | None, hosts: Sequence[str]
) -> tuple[str | None, str | None]:
    """(attacker, victim) of a finding run, from the finding and its anchor.

    The rule of :func:`soc_ai.api.webui.routes_hunts.promoted_finding_out`.
    The host that the finding names is the victim, and the other end of the
    flow of the anchor document is the attacker: the anchor can be the
    response of the server, with the victim as its source. A finding that
    names both ends keeps the direction of the anchor. A finding that names
    no end of the flow has its first host as the victim and no attacker.
    """
    named_hosts = [str(h) for h in hosts if str(h).strip()]
    source, target = _clean(src), _clean(dst)
    named = [ip for ip in (source, target) if ip and ip in named_hosts]
    if len(named) == 1:
        victim = named[0]
        return (target if victim == source else source), victim
    if len(named) == 2:
        return source, target
    if named_hosts:
        return None, named_hosts[0]
    return source, target


def alert_ends(
    src: str | None, dst: str | None, host_name: str | None
) -> tuple[str | None, str | None]:
    """(source, target) of an alert run.

    The two ends of the flow. An alert with no destination fired on a
    machine, and that machine is the target.
    """
    source, target = _clean(src), _clean(dst)
    if target is None:
        target = _clean(host_name)
    return source, target


def run_ends(inv: Any) -> tuple[str | None, str | None]:
    """(source, target) of a stored run: the stored ends, else the columns of the row."""
    report = getattr(inv, "report", None)
    stored = report.get(ENDS_KEY) if isinstance(report, dict) else None
    if isinstance(stored, dict):
        return _clean(stored.get("source")), _clean(stored.get("target"))
    return alert_ends(
        getattr(inv, "src_ip", None),
        getattr(inv, "dest_ip", None),
        getattr(inv, "host_name", None),
    )


def run_target(inv: Any) -> str | None:
    """The target of a stored run, for a reader that merges runs by target.

    The target end, else the source: a run that names one address is about
    that address.
    """
    source, target = run_ends(inv)
    return target or source


def run_values(inv: Any) -> list[str]:
    """The addresses and names that the first line of a stored run prints."""
    return [value for value in run_ends(inv) if value]


def of_run(inv: Any, labels: Mapping[str, HostLabel] | None = None) -> str | None:
    """The first line of a stored run.

    The stored line, when the run has one and its verdict still stands. An
    analyst can change the verdict after the run, and the line of a row that
    an older release stored does not exist: both are built here, from the
    verdict, the stored impact and the ends of the row. None for a run with
    no verdict and for a pipeline error.
    """
    report = getattr(inv, "report", None)
    held = report if isinstance(report, dict) else {}
    verdict = getattr(inv, "verdict", None)
    words = VERDICT_WORDS.get(str(verdict or ""))
    if words is None or is_pipeline_fallback(held):
        return None
    stored = held.get(FIRST_LINE_KEY)
    if isinstance(stored, str) and stored.startswith(f"{words}.") and not held.get("resolution"):
        return stored
    source, target = run_ends(inv)
    return build(verdict, held.get("impact"), source, target, labels)


def event_time_of(inv: Any) -> datetime | None:
    """The stored event time of a run as naive UTC, or None when it has none."""
    return event_at_svc.stored_event_time(getattr(inv, "report", None))


# The parser of the stored times. One parser for the event time of a run.
parse_time = event_at_svc.parse_time


__all__ = [
    "ENDS_KEY",
    "EVENT_TIME_KEY",
    "FIRST_LINE_KEY",
    "NOT_STATED",
    "VERDICT_WORDS",
    "HostLabel",
    "alert_ends",
    "build",
    "end_text",
    "event_time_of",
    "finding_ends",
    "headline",
    "is_address",
    "labels_for",
    "labels_for_settings",
    "of_run",
    "parse_time",
    "run_ends",
    "run_target",
    "run_values",
]
