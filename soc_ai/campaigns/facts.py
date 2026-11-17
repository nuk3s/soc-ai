"""The facts of a stored run: what the campaign engine reads of it.

:func:`extract` reads each run from the store: the row, the stored alert
context, and the stored tool results when the context does not hold a cited
document. It makes no grid query. :func:`load` keeps the facts in
``campaign_run_facts``, so a later rebuild reads one row for each run.

The machine of an address comes from the Hosts data. An address is the end of
a party only when an agent report, a DHCP lease or a network record joins it
to its machine, and when it is on no container bridge. A container address
and a bridge address can be on more than one machine.

The work is bounded. The context events of all runs take one query for each
chunk of :data:`CHUNK` runs. The tool events take one more query for each
chunk, and only for the runs that cite a document that the context does not
hold. The Hosts data takes one machine read for all addresses, and one
bridge read for each address that joined a machine.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import logging
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns.artifacts import cve_ids, http_key, named_hosts, shell_hosts
from soc_ai.campaigns.types import (
    CLASS_FINDING,
    KIND_ALERT,
    KIND_FINDING,
    KIND_LEAD,
    TIER_ALERT,
    TIER_ANALYTIC,
    TIER_HUNT,
    TIER_LEAD_HUNT,
    TIER_SCHEDULED_HUNT,
    DocFacts,
    RunFacts,
    naive_utc,
)
from soc_ai.event_time import document_label
from soc_ai.hunting.findings import finding_document_ids
from soc_ai.so_client.models import SoAlert
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store import first_line
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import CampaignRunFacts, Hunt, Investigation, InvestigationEvent
from soc_ai.triage_models import stored_impact, stored_stage

if TYPE_CHECKING:
    from soc_ai.api.webui._event_timeline import DocumentIndex
    from soc_ai.store.authorized_activity import MachineRef

_LOGGER = logging.getLogger(__name__)

# The version of the facts. A new version reads every run again. Version 2
# adds the label of each document.
FACTS_VERSION = 3
# The joins that make an address the end of a party.
PARTY_JOINS = frozenset({"agent", "dhcp", "network"})
# The most documents that the facts of one run hold.
MAX_DOCUMENTS = 200
# The most ids that one statement binds. SQLite limits the variables of a statement.
CHUNK = 200

_CONTEXT_KINDS = ("alert_context", "enriched_alert_context")
_TOOL_KINDS = ("tool_call", "tool_result", "targeted_dispatch", "targeted_tool_result")
# The hostile alert classes of the classifier. Any other class is no attack.
_ALERT_CLASSES = frozenset({"recon", "exploit_attempt", "post_compromise"})
_SCHEDULED_HUNT = "scheduled"
# A run has a session only with two known ends.
_TWO_ENDS = 2

_SKIP_LINE = (
    "campaigns: soc-ai could not read the facts of run %s. The run is in no campaign until "
    "soc-ai reads its facts."
)


def chunked[T](values: Sequence[T], size: int = CHUNK) -> Iterator[list[T]]:
    """The values in lists of at most ``size``."""
    for start in range(0, len(values), size):
        yield list(values[start : start + size])


def basis_of(inv: Investigation) -> str:
    """``<verdict>|<finished_at ISO>|<resolved_at of report["resolution"]>|v<FACTS_VERSION>``.

    The stored facts of a run hold while this value holds. A Re-run is a new
    run, and an override writes a new resolution time.
    """
    report = inv.report if isinstance(inv.report, dict) else {}
    resolution = report.get("resolution")
    resolved = resolution.get("resolved_at") if isinstance(resolution, dict) else None
    finished = inv.finished_at.isoformat() if inv.finished_at is not None else ""
    resolved_text = str(resolved)[:64] if resolved else ""
    return f"{inv.verdict or ''}|{finished}|{resolved_text}|v{FACTS_VERSION}"


def run_kind(inv: Investigation) -> str:
    """``lead`` for the run of a lead, ``finding`` for a run on a hunt, else ``alert``.

    A lead run has a hunt subject too, so its kind is read first.
    """
    if inv.kind == "lead":
        return KIND_LEAD
    if inv_svc.finding_group_id(inv) is not None or inv_svc.is_hunt_subject(inv):
        return KIND_FINDING
    return KIND_ALERT


def _text(value: Any) -> str | None:
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _address(value: Any) -> str | None:
    """The value when it is an IPv4 or IPv6 address, else None."""
    text = _text(value)
    return text if text is not None and first_line.is_address(text) else None


def _document_index(wanted: list[str]) -> DocumentIndex:
    # The package of the module imports every route, and one route imports this module.
    from soc_ai.api.webui._event_timeline import DocumentIndex  # noqa: PLC0415

    return DocumentIndex(wanted)


def _citation_kind(citation: str) -> tuple[str, str | None]:
    from soc_ai.agent.evidence import _classify_citation  # noqa: PLC0415 - heavy import

    return _classify_citation(citation)


def _rule_class(alert: Mapping[str, Any]) -> str:
    """The hostile class of the rule of an alert document, or empty."""
    from soc_ai.agent.authorized_activity import rule_class_of  # noqa: PLC0415 - heavy import

    try:
        value = rule_class_of(SoAlert.model_validate(dict(alert)))
    except Exception:
        return ""
    return value if value in _ALERT_CLASSES else ""


def _grid_document_id(target: str) -> bool:
    """False for an id that names no grid document: a hash, a CVE id, a rule UUID or a ULID.

    A report can cite such an id. The store never holds a document for it, so
    it must not count as a cited document that is missing.
    """
    from soc_ai.api.webui._event_timeline import _EVIDENCE_ID_RE, _ULID_RE  # noqa: PLC0415

    return not (_EVIDENCE_ID_RE.fullmatch(target) or _ULID_RE.fullmatch(target))


def _cited_ids(inv: Investigation, own: Sequence[str] | None) -> tuple[str, ...]:
    """The document ids that a run cites.

    The id citations of its report, and the documents of its subject. ``own``
    is the documents of the one finding that the run judges. The subject of a
    finding run holds the documents of every finding of its hunt, and the
    other findings can be about other hosts: only the documents of its own
    finding speak for the run. None for a run that judges a whole hunt: all
    documents of the subject are its documents.
    """
    found: dict[str, None] = {}
    report = inv.report if isinstance(inv.report, dict) else {}
    citations = report.get("citations")
    for citation in citations if isinstance(citations, list) else []:
        if not isinstance(citation, str):
            continue
        kind, target = _citation_kind(citation)
        text = target.strip() if isinstance(target, str) else ""
        if kind == "id" and text and _grid_document_id(text):
            found.setdefault(text)
    if own is not None:
        ids: Any = list(own)
    else:
        subject = inv.subject_json if isinstance(inv.subject_json, dict) else {}
        ids = subject.get("document_ids")
    for doc_id in ids if isinstance(ids, list) else []:
        if isinstance(doc_id, str) and doc_id.strip():
            found.setdefault(doc_id.strip())
    return tuple(found)


def _doc_facts(key: str, fields: Mapping[str, Any], *, run_alert: bool, cited: bool) -> DocFacts:
    """One stored document, read by its SoAlert JSON keys. No machine yet."""
    dataset = _text(fields.get("event_dataset"))
    is_alert = run_alert or (dataset is not None and dataset.endswith(".alert"))
    port = fields.get("destination_port")
    return DocFacts(
        id=key,
        at=naive_utc(_text(fields.get("timestamp")) or fields.get("timestamp")),
        community_id=_text(fields.get("network_community_id")),
        source_address=_address(fields.get("source_ip")),
        target_address=_address(fields.get("destination_ip")),
        target_port=port if isinstance(port, int) and not isinstance(port, bool) else None,
        dataset=dataset,
        is_alert=is_alert,
        rule_key=authorized_svc.rule_name_key(_text(fields.get("rule_name"))) if is_alert else "",
        # The URI, and a /dev/tcp path of the payload. A Host header names the
        # target, and a payload holds headers with many URLs.
        named=tuple(
            sorted(
                {
                    *named_hosts(_text(fields.get("zeek_http_uri"))),
                    *shell_hosts(_text(fields.get("payload_printable"))),
                }
            )
        ),
        cited=cited,
        label=document_label(fields),
    )


@dataclass
class _Start:
    """One run with its stored context and the index of its cited documents."""

    inv: Investigation
    context: Mapping[str, Any]
    cited: tuple[str, ...]
    index: DocumentIndex
    # True for a run that judges one finding: only the cited documents of the
    # subject are its documents.
    scoped: bool = False


@dataclass(frozen=True)
class _Read:
    """What one run gives before the Hosts data names its machines."""

    inv: Investigation
    kind: str
    attack_class: str
    source_address: str | None
    target_address: str | None
    documents: tuple[DocFacts, ...]
    cited_ids: tuple[str, ...]
    cited_unresolved: int
    rules: frozenset[str]
    cves: frozenset[str]
    http_keys: frozenset[str]
    # The addresses that the finding of the run names, for a finding run.
    named_addresses: tuple[str, ...] = ()


def _read(start: _Start) -> _Read:
    """The facts of one run that need no other read."""
    inv, index = start.inv, start.index
    kind = run_kind(inv)
    found = index.found
    cited_keys = {found[w].key for w in start.cited if w in found}
    documents: dict[str, DocFacts] = {}
    http_of: dict[str, str] = {}

    def take(fields: Any, *, key: str | None = None, run_alert: bool = False) -> None:
        if not isinstance(fields, Mapping) or len(documents) >= MAX_DOCUMENTS:
            return
        doc_id = key or _text(fields.get("id"))
        if not doc_id or doc_id in documents:
            return
        doc = _doc_facts(doc_id, fields, run_alert=run_alert, cited=doc_id in cited_keys)
        documents[doc_id] = doc
        shared = http_key(_text(fields.get("zeek_http_method")), _text(fields.get("zeek_http_uri")))
        if shared:
            http_of[doc_id] = shared

    alert = start.context.get("alert")
    # The alert of an alert run is an alert. The alert of a finding run is
    # its anchor document: an alert only by its dataset.
    take(alert, run_alert=kind == KIND_ALERT)
    subject_documents = start.context.get("subject_documents")
    wanted_ids = set(start.cited)
    for item in subject_documents if isinstance(subject_documents, list) else []:
        if start.scoped and not (isinstance(item, Mapping) and _text(item.get("id")) in wanted_ids):
            continue
        take(item)
    for wanted in start.cited:
        doc = found.get(wanted)
        if doc is not None:
            take(doc.fields, key=doc.key)
    # A cited id counts as unresolved when no stored event holds it, and when
    # the cap left its document out: the Documents link reads every cited
    # document, so a document it cannot read must not pass.
    unresolved = sum(1 for w in start.cited if w not in found or found[w].key not in documents)

    source, target = first_line.run_ends(inv)
    source_address, target_address = _address(source), _address(target)
    # The artifacts of a run come from the documents between its own two
    # ends. A finding can cite a document of other hosts as context, for
    # example a package update of the target. Two actors that cite the same
    # update share no artifact.
    ends = {a for a in (source_address, target_address) if a}
    own = [
        doc
        for doc in documents.values()
        if len(ends) == _TWO_ENDS and {doc.source_address, doc.target_address} == ends
    ]
    rules = {doc.rule_key for doc in own if doc.is_alert and doc.rule_key}
    http = {http_of[doc.id] for doc in own if doc.id in http_of}
    if kind == KIND_ALERT:
        key = authorized_svc.rule_name_key(inv.rule_name)
        if key:
            rules.add(key)
    if kind in (KIND_FINDING, KIND_LEAD):
        attack_class = CLASS_FINDING
    else:
        attack_class = _rule_class(alert) if isinstance(alert, Mapping) else ""
    return _Read(
        inv=inv,
        kind=kind,
        attack_class=attack_class,
        source_address=source_address,
        target_address=target_address,
        documents=tuple(documents.values()),
        cited_ids=start.cited,
        cited_unresolved=unresolved,
        rules=frozenset(rules),
        cves=cve_ids(*rules),
        http_keys=frozenset(http),
    )


async def _contexts(db: AsyncSession, run_ids: list[str]) -> dict[str, Any]:
    """The payload of the last context event of each run. One query.

    The recorder appends the events of a run in order, so the highest event
    id is the last event.
    """
    last = (
        select(func.max(InvestigationEvent.id))
        .where(
            InvestigationEvent.investigation_id.in_(run_ids),
            InvestigationEvent.kind.in_(_CONTEXT_KINDS),
        )
        .group_by(InvestigationEvent.investigation_id)
    )
    rows = await db.execute(
        select(InvestigationEvent.investigation_id, InvestigationEvent.payload).where(
            InvestigationEvent.id.in_(last)
        )
    )
    return {str(run_id): payload for run_id, payload in rows.all()}


async def _tool_events(db: AsyncSession, run_ids: list[str]) -> dict[str, list[Any]]:
    """The tool events of each run, in order. One query."""
    if not run_ids:
        return {}
    rows = await db.execute(
        select(
            InvestigationEvent.investigation_id,
            InvestigationEvent.kind,
            InvestigationEvent.payload,
        )
        .where(
            InvestigationEvent.investigation_id.in_(run_ids),
            InvestigationEvent.kind.in_(_TOOL_KINDS),
        )
        .order_by(
            InvestigationEvent.investigation_id,
            InvestigationEvent.sequence,
            InvestigationEvent.id,
        )
    )
    out: dict[str, list[Any]] = {}
    for row in rows.all():
        out.setdefault(str(row.investigation_id), []).append(row)
    return out


async def _read_chunk(
    db: AsyncSession, chunk: Sequence[Investigation], own: Mapping[str, tuple[str, ...]]
) -> list[_Read]:
    """The facts of the runs of one chunk that need no other read.

    ``own`` holds the documents of its finding for each run that judges one.
    """
    contexts = await _contexts(db, [inv.id for inv in chunk])
    started: list[_Start] = []
    for inv in chunk:
        try:
            context = contexts.get(inv.id, {})
            if not isinstance(context, Mapping):
                raise TypeError("the stored alert context is no mapping")
            cited = _cited_ids(inv, own.get(inv.id))
            index = _document_index(list(cited))
            index.add_context(context)
            started.append(_Start(inv, context, cited, index, scoped=inv.id in own))
        except Exception:
            _LOGGER.warning(_SKIP_LINE, inv.id, exc_info=True)
    wanting = [s.inv.id for s in started if any(w not in s.index.found for w in s.cited)]
    tools = await _tool_events(db, wanting)
    out: list[_Read] = []
    for start in started:
        try:
            events = tools.get(start.inv.id)
            if events:
                start.index.read_events(events)
            out.append(_read(start))
        except Exception:
            _LOGGER.warning(_SKIP_LINE, start.inv.id, exc_info=True)
    return out


def _tier(kind: str, hunt: tuple[str, int | None] | None) -> str:
    """The detection tier of a run. ``hunt`` is the kind and the lead id of its hunt."""
    if kind == KIND_ALERT:
        return TIER_ALERT
    if kind == KIND_LEAD:
        return TIER_ANALYTIC
    if hunt is None:
        return TIER_HUNT
    hunt_kind, lead_id = hunt
    if lead_id is not None:
        return TIER_LEAD_HUNT
    if hunt_kind == _SCHEDULED_HUNT:
        return TIER_SCHEDULED_HUNT
    # A hunt that a campaign started (kind ``campaign``) is a hunt of soc-ai
    # with no lead and no schedule: TIER_HUNT, like an analyst hunt.
    return TIER_HUNT


def _facts(
    read: _Read,
    event_time: datetime | None,
    tier: str,
    machine: Callable[[str | None], MachineRef | None],
) -> RunFacts:
    inv = read.inv

    def key_of(address: str | None) -> str | None:
        ref = machine(address)
        return ref.key if ref is not None else None

    documents = tuple(
        dataclasses.replace(
            doc, source=key_of(doc.source_address), target=key_of(doc.target_address)
        )
        for doc in read.documents
    )
    # The sessions of a run are the flows between its own two ends. A finding
    # can cite a document of other hosts as context, for example a package
    # update of the target. An alert run on that flow is no part of the
    # activity of the finding.
    ends = {a for a in (read.source_address, read.target_address) if a}
    sessions: dict[tuple[str, datetime], None] = {}
    for doc in documents:
        if not doc.community_id or doc.at is None:
            continue
        if len(ends) == _TWO_ENDS and {doc.source_address, doc.target_address} == ends:
            sessions.setdefault((doc.community_id, doc.at))
    if not documents and inv.community_id and event_time is not None:
        # A run of an older release with no stored context: the session of the row.
        sessions[(inv.community_id, event_time)] = None
    source, target = machine(read.source_address), machine(read.target_address)
    return RunFacts(
        run_id=inv.id,
        kind=read.kind,
        verdict=inv.verdict or "",
        label=inv.rule_name or "",
        event_time=event_time,
        finished_at=naive_utc(inv.finished_at),
        source=source.key if source is not None else None,
        target=target.key if target is not None else None,
        source_address=read.source_address,
        target_address=read.target_address,
        source_name=source.name if source is not None else None,
        target_name=target.name if target is not None else None,
        source_join=source.kind if source is not None else None,
        target_join=target.kind if target is not None else None,
        attack_class=read.attack_class,
        impact=stored_impact(inv.report, inv.verdict),
        stage_claim=stored_stage(inv.report, inv.verdict),
        rules=read.rules,
        cves=read.cves,
        http_keys=read.http_keys,
        sessions=tuple(sessions),
        documents=documents,
        cited_ids=read.cited_ids,
        cited_unresolved=read.cited_unresolved,
        tier=tier,
        hunt_id=inv.hunt_id,
        named_machines=tuple(
            sorted({key for a in read.named_addresses if (key := key_of(a)) is not None})
        ),
    )


def finding_addresses(finding: Mapping[str, Any]) -> tuple[str, ...]:
    """The addresses among the hosts that a hunt finding names.

    A host of a finding is an address or a name. Only an address joins a
    machine here: a name can be the name of two machines.
    """
    hosts = finding.get("hosts")
    out: dict[str, None] = {}
    for host in hosts if isinstance(hosts, list) else []:
        text = host.strip() if isinstance(host, str) else ""
        try:
            out.setdefault(str(ipaddress.ip_address(text)))
        except ValueError:
            continue
    return tuple(out)


async def machine_resolver(
    db: AsyncSession, addresses: Iterable[str]
) -> Callable[[str | None], MachineRef | None]:
    """The machine of each address as a party reads it: one read for all addresses.

    The address must join its machine by a party join (:data:`PARTY_JOINS`),
    and an address on a container bridge names no machine. The facts of a
    run and the authorization of a campaign read the machines this one way,
    so a party key and the key of an investigation end are equal for one
    machine.
    """
    refs: dict[str, MachineRef | None] = {}
    for part in chunked(sorted({a for a in addresses if a})):
        refs.update(await authorized_svc.machine_refs(db, part))
    joined = sorted(a for a, ref in refs.items() if ref is not None and ref.kind in PARTY_JOINS)
    bridges = await authorized_svc.bridge_addresses(db, joined) if joined else set()

    def machine(address: str | None) -> MachineRef | None:
        if not address or address in bridges:
            return None
        ref = refs.get(address)
        return ref if ref is not None and ref.kind in PARTY_JOINS else None

    return machine


async def extract(db: AsyncSession, runs: Sequence[Investigation]) -> dict[str, RunFacts]:
    """The facts of each run, read from the store.

    One run that fails gives no entry and one warning.
    """
    unique = list({inv.id: inv for inv in runs}.values())

    # The hunt of each run: its type for the tier, and the documents of the
    # finding that the run judges.
    hunts: dict[str, tuple[str, int | None]] = {}
    findings: dict[str, list[Any]] = {}
    for ids in chunked(sorted({inv.hunt_id for inv in unique if inv.hunt_id})):
        rows = await db.execute(
            select(Hunt.id, Hunt.kind, Hunt.lead_id, Hunt.report).where(Hunt.id.in_(ids))
        )
        for h_id, kind, lead_id, report in rows.all():
            hunts[str(h_id)] = (str(kind), lead_id)
            listed = report.get("findings") if isinstance(report, dict) else None
            findings[str(h_id)] = listed if isinstance(listed, list) else []
    own: dict[str, tuple[str, ...]] = {}
    named: dict[str, tuple[str, ...]] = {}
    for inv in unique:
        group = inv_svc.finding_group_id(inv)
        if group is None:
            continue
        hunt_id, ordinal = group
        listed = findings.get(hunt_id, [])
        finding = listed[ordinal] if 0 <= ordinal < len(listed) else None
        # A finding that the store no longer holds gives no document. The run
        # then keeps its anchor and the documents that its report cites.
        own[inv.id] = tuple(finding_document_ids(finding)) if isinstance(finding, Mapping) else ()
        named[inv.id] = finding_addresses(finding) if isinstance(finding, Mapping) else ()

    reads: list[_Read] = []
    for start in range(0, len(unique), CHUNK):
        reads.extend(await _read_chunk(db, unique[start : start + CHUNK], own))
    if not reads:
        return {}
    reads = [
        dataclasses.replace(r, named_addresses=named.get(r.inv.id, ()))
        if r.kind == KIND_FINDING
        else r
        for r in reads
    ]

    # The event time: the stored one, else the time of the stored alert.
    stored_times = {r.inv.id: first_line.event_time_of(r.inv) for r in reads}
    alert_times: dict[str, datetime] = {}
    for ids in chunked([run_id for run_id, at in stored_times.items() if at is None]):
        alert_times.update(await inv_svc.alert_event_times(db, ids))

    # The machines: one read for all addresses, and one bridge read for each
    # address that joined a machine by a party join.
    addresses: set[str] = set()
    for r in reads:
        addresses.update(a for a in (r.source_address, r.target_address) if a)
        addresses.update(r.named_addresses)
        for doc in r.documents:
            addresses.update(a for a in (doc.source_address, doc.target_address) if a)
    machine = await machine_resolver(db, addresses)

    out: dict[str, RunFacts] = {}
    for r in reads:
        try:
            at = stored_times[r.inv.id] or alert_times.get(r.inv.id)
            hunt = hunts.get(r.inv.hunt_id) if r.kind == KIND_FINDING and r.inv.hunt_id else None
            out[r.inv.id] = _facts(r, at, _tier(r.kind, hunt), machine)
        except Exception:
            _LOGGER.warning(_SKIP_LINE, r.inv.id, exc_info=True)
    return out


async def read(
    db: AsyncSession, runs: Sequence[Investigation], *, refresh: bool = False
) -> tuple[dict[str, RunFacts], dict[str, RunFacts]]:
    """The facts of each run, and the part of them that this call extracted.

    Reads the stored facts and extracts the facts that are missing or have
    another basis. Writes nothing: a caller holds no write lock on the store
    while it reads. ``refresh`` True extracts every run again: the Hosts data
    changed, and the stored facts hold the machines of the earlier read.
    """
    by_id = {inv.id: inv for inv in runs}
    out: dict[str, RunFacts] = {}
    stale: list[Investigation] = []
    for ids in chunked(sorted(by_id)):
        rows = await db.execute(
            select(CampaignRunFacts.run_id, CampaignRunFacts.basis, CampaignRunFacts.facts).where(
                CampaignRunFacts.run_id.in_(ids)
            )
        )
        for run_id, basis, stored in rows.all():
            if refresh or basis != basis_of(by_id[run_id]) or not isinstance(stored, dict):
                continue
            try:
                out[str(run_id)] = RunFacts.from_json(stored)
            except Exception:
                _LOGGER.warning(_SKIP_LINE, run_id, exc_info=True)
    stale = [inv for run_id, inv in by_id.items() if run_id not in out]
    fresh = await extract(db, stale) if stale else {}
    out.update(fresh)
    return out, fresh


async def store(
    db: AsyncSession, runs: Sequence[Investigation], fresh: Mapping[str, RunFacts]
) -> None:
    """Write the facts that a :func:`read` extracted. Flushes, and the caller commits."""
    by_id = {inv.id: inv for inv in runs}
    wanted = sorted(run_id for run_id in fresh if run_id in by_id)
    if not wanted:
        return
    held: dict[str, CampaignRunFacts] = {}
    for ids in chunked(wanted):
        rows = await db.scalars(select(CampaignRunFacts).where(CampaignRunFacts.run_id.in_(ids)))
        held.update({row.run_id: row for row in rows.all()})
    now = utcnow()
    for run_id in wanted:
        basis = basis_of(by_id[run_id])
        row = held.get(run_id)
        if row is None:
            db.add(
                CampaignRunFacts(
                    run_id=run_id, basis=basis, facts=fresh[run_id].to_json(), built_at=now
                )
            )
        else:
            row.basis = basis
            row.facts = fresh[run_id].to_json()
            row.built_at = now
    await db.flush()


async def load(
    db: AsyncSession,
    runs: Sequence[Investigation],
    *,
    write: bool = True,
    refresh: bool = False,
) -> dict[str, RunFacts]:
    """The stored facts of each run: :func:`read`, then :func:`store` when ``write``.

    ``write`` False stores nothing: a dry run. The rows are flushed, and the
    caller commits.
    """
    out, fresh = await read(db, runs, refresh=refresh)
    if write:
        await store(db, runs, fresh)
    return out


__all__ = [
    "CHUNK",
    "FACTS_VERSION",
    "MAX_DOCUMENTS",
    "PARTY_JOINS",
    "basis_of",
    "chunked",
    "extract",
    "finding_addresses",
    "load",
    "machine_resolver",
    "read",
    "run_kind",
    "store",
]
