"""The machine names in the text of a finding that the finding does not hold.

Dogfood 2026-11-17 (AA2): two finding rows of campaign 2 read "against blue"
for an address that holds no name. The Hosts data gives that name to another
machine. The model wrote the name, and the record does not support it.

A finding whose text names a known machine that is no host of the finding
gets one note for each such name (:data:`soc_ai.hunting.hunt_words.NAME_NOTE`).
The model text stays as it is. The hunt gate writes the note into the
validator note of a new finding. The campaign page and the page of a finding
investigation run the same check at read time, so a stored finding shows it
too.

The match is the one of the authorization (:func:`authorization.mentions_of`):
a machine name of the Hosts data as a whole word, in any case. A short name
inside a longer word is no mention. An address in the text is no name, and
the authorization reads it on its own path.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns.authorization import _host_names, mentions_of
from soc_ai.campaigns.facts import chunked
from soc_ai.hunting.hunt_words import NAME_NOTE
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store.models import Hunt

_LOGGER = logging.getLogger(__name__)


def foreign_names(
    texts: Iterable[str],
    hosts: Sequence[str],
    host_names: Mapping[str, frozenset[str]] | None,
    host_keys: Iterable[str],
) -> list[str]:
    """The known machine names in ``texts`` that name no host of the finding. Pure.

    ``hosts`` holds the hosts of the finding as written. ``host_keys`` holds
    the machine keys of its addresses. A name that is a host of the finding,
    or that a machine of the finding carries, is no foreign name. With no
    Hosts data (``host_names`` None) nothing shows what a name is, so the
    check names nothing.
    """
    if host_names is None:
        return []
    held = {str(h).strip().lower() for h in hosts if str(h).strip()}
    keys = set(host_keys)
    for name in held:
        keys |= host_names.get(name, frozenset())
    out: list[str] = []
    for name, machines in mentions_of(texts, host_names):
        if not machines or name in held or machines & keys:
            continue
        out.append(name)
    return out


def note_of(names: Sequence[str]) -> str | None:
    """The note for the foreign names of one finding, or None."""
    return " ".join(NAME_NOTE.format(name=n) for n in names) or None


def _texts(finding: Mapping[str, Any]) -> list[str]:
    return [str(finding.get(k) or "") for k in ("title", "detail")]


def _hosts(finding: Mapping[str, Any]) -> list[str]:
    hosts = finding.get("hosts")
    return [str(h).strip() for h in (hosts if isinstance(hosts, list) else []) if str(h).strip()]


async def notes_for_findings(
    db: AsyncSession, findings: Sequence[Mapping[str, Any]]
) -> list[str | None]:
    """The name note of each finding, in order. Two reads for all findings.

    Each finding is a mapping with ``title``, ``detail`` and ``hosts``. The
    machine of an address counts by any join of the Hosts data.
    """
    if not findings:
        return []
    host_names = await _host_names(db)
    if host_names is None:
        return [None] * len(findings)
    addresses = sorted({h for f in findings for h in _hosts(f)})
    refs: dict[str, Any] = {}
    for part in chunked(addresses):
        refs.update(await authorized_svc.machine_refs(db, part))
    out: list[str | None] = []
    for finding in findings:
        hosts = _hosts(finding)
        keys = {ref.key for h in hosts if (ref := refs.get(h)) is not None}
        out.append(note_of(foreign_names(_texts(finding), hosts, host_names, keys)))
    return out


async def findings_of_runs(db: AsyncSession, runs: Sequence[Any]) -> dict[str, Mapping[str, Any]]:
    """The stored finding of each finding investigation, by run id. One read.

    A run with a hunt and a finding ordinal reads the finding from the stored
    report of its hunt. A run whose hunt or finding is gone gets no entry.
    """
    wanted = {
        str(r.id): (str(r.hunt_id), int(r.finding_ordinal))
        for r in runs
        if getattr(r, "hunt_id", None) and getattr(r, "finding_ordinal", None) is not None
    }
    if not wanted:
        return {}
    reports: dict[str, Any] = {}
    for ids in chunked(sorted({hunt_id for hunt_id, _o in wanted.values()})):
        rows = await db.execute(select(Hunt.id, Hunt.report).where(Hunt.id.in_(ids)))
        reports.update({str(h_id): report for h_id, report in rows.all()})
    out: dict[str, Mapping[str, Any]] = {}
    for run_id, (hunt_id, ordinal) in wanted.items():
        report = reports.get(hunt_id)
        listed = report.get("findings") if isinstance(report, dict) else None
        if isinstance(listed, list) and 0 <= ordinal < len(listed):
            finding = listed[ordinal]
            if isinstance(finding, Mapping):
                out[run_id] = finding
    return out


def hosts_of(finding: Mapping[str, Any]) -> list[str]:
    """The hosts of a stored finding, as written."""
    return _hosts(finding)


async def notes_for_runs(db: AsyncSession, runs: Sequence[Any]) -> dict[str, str]:
    """The name note of the finding of each finding investigation, by run id.

    A run with no finding, or whose finding has no note, gets no entry.
    """
    keyed = list((await findings_of_runs(db, runs)).items())
    notes = await notes_for_findings(db, [f for _r, f in keyed])
    return {run_id: note for (run_id, _f), note in zip(keyed, notes, strict=True) if note}


__all__ = [
    "findings_of_runs",
    "foreign_names",
    "hosts_of",
    "note_of",
    "notes_for_findings",
    "notes_for_runs",
]
