"""Open an investigation of a hunt finding: the promotion service.

Three callers open an investigation of a hunt's evidence: the finding
promotion route (``POST /hunts/{id}/findings/{o}/investigate``), the lead
promotion route and the hunt runner, which investigates every subject finding
of a hunt as part of the hunt (:mod:`soc_ai.webui.hunt_findings`). All three
pass through :func:`start_promotion`, so a promotion has one anchor rule, one
focus block and one start path.

The service holds no ``Request``. It reads ``state`` (``app.state``) the way the
background managers do, so the hunt runner calls it from a background task.
A route maps :class:`PromotionRefused` and the grid errors to its HTTP answers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from itertools import combinations
from typing import Any, NamedTuple

from soc_ai.agent.context import HuntSubject, InvestigationContext
from soc_ai.agent.prompts import FocusOrigin
from soc_ai.config import Settings
from soc_ai.dossier.coverage import name_variants
from soc_ai.hunting.earlier import stated_window_hours
from soc_ai.hunting.findings import DOCUMENT_ID_RE
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import get_dotted
from soc_ai.so_client.models import SoAlert
from soc_ai.tools._synth_scope import synth_scope_must_not

_LOGGER = logging.getLogger(__name__)


def investigation_manager(state: Any) -> Any:
    """The app's investigation manager (:mod:`soc_ai.webui.hunt_manager`).

    Imported on call. The manager imports the API package, and the API package
    imports this module through the hunt routes. A module-level import made
    the cycle fail for a caller that imported this module first.
    """
    from soc_ai.webui import hunt_manager  # noqa: PLC0415 - import cycle

    return hunt_manager.get_manager(state)


# Detector-flag datasets: an anchor from these is another detector's CLAIM, not
# raw telemetry. A cited telemetry document wins over them, because a promoted
# finding is investigated from its evidence.
DETECTOR_DATASETS = frozenset({"suricata.alert", "sigma.alert", "zeek.notice"})

# The default window of a hunt query tool, in minutes (role "hunt" in
# soc_ai.agent.toolset.register_read_tools). The window of a hunt reaches at
# least this far back from the start of the hunt.
HUNT_QUERY_WINDOW_MINUTES = 1440
# How many of the newest records the host read takes. Telemetry wins over a
# detector document inside them.
HOST_READ_SIZE = 50
# How many hosts of one finding the host rule reads. Eight hosts make 28 pairs
# in the query of the host read.
MAX_ANCHOR_HOSTS = 8
# The fields of a record that the host read tests: its dataset and its ends.
_HOST_READ_FIELDS = ["event.dataset", "source.ip", "destination.ip", "host.name", "host.ip"]

# A citation of the OQL query tool, in the words of the model: the tool name,
# a space or a colon, then the query. Prod hunt 01M7DNRCRYV7CSHM5PX6K6GC12
# cited 't_query_events_oql zeek.http destination.ip:<address> groupby ...'.
# The other tools take no dataset (t_query_zeek_logs takes a community id).
_QUERY_CITATION_RE = re.compile(r"^t_query_events_oql[:\s]\s*(?P<query>\S.*)$")
# A dataset term in the query: event.dataset:zeek.http, or the value quoted.
_DATASET_TERM_RE = re.compile(
    r"\b(?:event|data_stream)\.dataset\s*:\s*\"?(?P<dataset>[A-Za-z0-9_.]+)\"?"
)
# The shape of a dataset name: a module and one or two names, such as
# zeek.http or endpoint.events.network.
_DATASET_SHAPE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,2}$")
# The modules whose datasets the first word of a query can name. A closed
# list, because 'source.ip' and 'http.uri' have the shape of a dataset too.
_DATASET_MODULES = frozenset(
    {"zeek", "suricata", "sigma", "strelka", "sysmon", "windows", "system", "endpoint"}
)
# How many datasets one finding can name for the host read.
_MAX_NAMED_DATASETS = 8

# The hint of a promotion whose citations resolve to nothing on the grid.
NO_EVIDENCE_HINT = "None of the citations resolve to an event on the grid."
# The hint of a promotion the investigation manager did not start.
COULD_NOT_START_HINT = "The console did not start the run. Check the model gateway in Settings."
# The remedy that a refused re-run of a finding run names. Re-run on the
# investigation page posts the promote route with ``rerun`` (the 409
# hunt_kind_no_rerun of Request more info and of POST /hunt).
FINDING_RERUN_HINT = "Use Re-run on the investigation of the finding."
# The same refusal for the run of a promoted lead. The console has no re-run
# of a lead run, and Resolve in chat is on the investigation page.
LEAD_NO_RERUN_HINT = (
    "Request more info does not apply to a promoted lead. "
    "Use Resolve in chat to settle the verdict."
)


class PromotionRefused(Exception):
    """The promotion did not start. ``status`` is the HTTP code a route answers."""

    def __init__(self, status: int, reason: str, hint: str) -> None:
        super().__init__(hint)
        self.status = status
        self.reason = reason
        self.hint = hint


async def resolve_finding_anchor(
    elastic: ElasticClient, settings: Settings, citations: Sequence[str]
) -> str | None:
    """Pick the finding's anchor document: the cited id the investigation runs on.

    Citation order is kept within each class, and telemetry wins over a
    detector document. None when nothing resolves.

    Only ``event.dataset`` is read from each hit, so the lookup asks for that
    field alone and caps the id list: a report with hundreds of citations must
    not turn one anchor pick into a bulk document fetch.
    """
    ids = [c for c in citations if DOCUMENT_ID_RE.match(c)][:100]
    if not ids:
        return None
    lookup = await elastic.search(
        settings.events_index_pattern,
        {"ids": {"values": ids}},
        size=len(ids),
        source=["event.dataset"],
    )
    hits = list(lookup.hits or [])
    if not hits:
        return None
    by_id = {h.get("_id"): h for h in hits}
    ordered = [by_id[i] for i in ids if i in by_id]
    for h in ordered:
        ds = str(get_dotted(h.get("_source", {}), "event.dataset") or "").lower()
        if ds not in DETECTOR_DATASETS:
            return h.get("_id")
    return ordered[0].get("_id")


def _telemetry_first(docs: Sequence[SoAlert]) -> str | None:
    """The first telemetry document, else the first document, else None."""
    for doc in docs:
        if str(doc.event_dataset or "").lower() not in DETECTOR_DATASETS:
            return doc.id
    return docs[0].id if docs else None


def cited_datasets(citations: Iterable[Any]) -> frozenset[str]:
    """The datasets that the OQL query citations of a finding name.

    Only a ``t_query_events_oql`` citation names a dataset. Its query names
    one in an ``event.dataset:`` term, or in its first word when that word is
    a dataset of a known module, as in ``zeek.http destination.ip:...``. Any
    other citation, and a word of a different shape, names no dataset.
    """
    found: dict[str, None] = {}
    for citation in citations:
        if not isinstance(citation, str):
            continue
        match = _QUERY_CITATION_RE.match(citation.strip())
        if match is None:
            continue
        query = match.group("query")
        for term in _DATASET_TERM_RE.finditer(query):
            dataset = term.group("dataset").casefold()
            if _DATASET_SHAPE_RE.match(dataset):
                found.setdefault(dataset, None)
        first = query.split()[0].strip(",;").casefold()
        if _DATASET_SHAPE_RE.match(first) and first.partition(".")[0] in _DATASET_MODULES:
            found.setdefault(first, None)
    return frozenset(list(found)[:_MAX_NAMED_DATASETS])


def _of_datasets(docs: Sequence[SoAlert], datasets: frozenset[str]) -> list[SoAlert]:
    return [d for d in docs if str(d.event_dataset or "").casefold() in datasets]


def _pick(docs: Sequence[SoAlert], datasets: frozenset[str]) -> str | None:
    """A document of a named dataset first, then any document. Telemetry wins in each."""
    return _telemetry_first(_of_datasets(docs, datasets)) or _telemetry_first(docs)


def _pool_anchor(subject: HuntSubject) -> str | None:
    """The rule of change E, over the pool of documents it names."""
    focus = set(subject.promoted_document_ids())
    pool = [d for d in subject.documents if d.id in focus] or subject.documents
    return _telemetry_first(pool)


def anchor_from_subject(subject: HuntSubject) -> str | None:
    """The anchor document of a hunt-subject run, from the documents it holds.

    Same rule as :func:`resolve_finding_anchor`: telemetry wins over a
    detector's claim. No second grid read, because the subject builder fetched
    these documents already.

    Change E (2026-10-30): on a finding run the pool is the documents that the
    promoted finding cites, in subject order. Telemetry wins inside the pool,
    else the first document of the pool wins. Before, telemetry from ANY
    finding won: run 01M5WRBJZRB348GX4MZTY1GS59 judged a finding that cites two
    suricata alerts and anchored on a Zeek record that another finding cites.
    A lead subject keeps the rule over every document of the subject.

    A finding with no resolved document of its own (2026-11-14) takes a
    document on the hosts it names first (:func:`host_anchor`). Prod hunt
    01M7DNRCRYV7CSHM5PX6K6GC12: a finding that named the web server and one
    client cited two summary queries, and its run anchored on a zeek.ssh
    record between two other machines that another finding cites. When no
    document touches a named host, the rule over every document of the
    subject holds. :func:`promotion_anchor` reads the grid for the named hosts
    before it takes that rule.
    """
    return host_anchor(subject) or _pool_anchor(subject)


class _NamedHost(NamedTuple):
    """One host that the promoted finding names.

    ``addresses`` holds the address as written, or the addresses that the
    subject documents give for a name. ``names`` holds a name as written.
    """

    addresses: frozenset[str]
    names: frozenset[str]


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _fold_name(value: str) -> str:
    return value.strip().rstrip(".").casefold()


def _same_name(a: str, b: str) -> bool:
    """Whether two host names name one machine. ``web-1`` is ``web-1.example.test``."""
    fa, fb = _fold_name(a), _fold_name(b)
    if not fa or not fb or _is_address(fa) or _is_address(fb):
        return False
    if fa == fb:
        return True
    if "." in fa and "." in fb:
        return False
    return fa.partition(".")[0] == fb.partition(".")[0]


def _named_hosts(subject: HuntSubject) -> list[_NamedHost]:
    """The hosts that the promoted finding names, one entry per machine.

    An address matches exactly. A name matches the ``host.name`` of a record,
    and the subject documents that carry the name give its addresses. A
    machine that the finding names twice, by address and by name, is one host.
    """
    hosts: list[_NamedHost] = []
    for raw in subject.promoted_hosts()[:MAX_ANCHOR_HOSTS]:
        text = raw.strip()
        if _is_address(text):
            host = _NamedHost(frozenset({text}), frozenset())
        else:
            resolved = {
                ip
                for d in subject.documents
                if d.host_name and _same_name(text, d.host_name)
                for ip in d.host_ip
                if _is_address(ip)
            }
            host = _NamedHost(frozenset(resolved), frozenset({text}))
        for i, held in enumerate(hosts):
            same = held.addresses & host.addresses or any(
                _same_name(a, b) for a in held.names for b in host.names
            )
            if same:
                hosts[i] = _NamedHost(held.addresses | host.addresses, held.names | host.names)
                break
        else:
            hosts.append(host)
    return hosts


def _is_end(host: _NamedHost, doc: SoAlert) -> bool:
    """Whether ``host`` is an end of ``doc``: its source, its destination or its host."""
    addresses = {a for a in (doc.source_ip, doc.destination_ip, *doc.host_ip) if a}
    if host.addresses & addresses:
        return True
    name = doc.host_name
    return bool(name) and any(_same_name(n, str(name)) for n in host.names)


def _ends_named(doc: SoAlert, hosts: Sequence[_NamedHost]) -> int:
    """How many of the named hosts are ends of ``doc``."""
    return sum(1 for h in hosts if _is_end(h, doc))


def _host_rule_applies(subject: HuntSubject) -> bool:
    """A finding subject whose finding has no resolved document and names a host."""
    return (
        subject.promoted_finding is not None
        and not subject.promoted_document_ids()
        and bool(subject.promoted_hosts())
    )


def host_anchor(subject: HuntSubject) -> str | None:
    """A subject document on the hosts that the promoted finding names, or None.

    Only for a finding that has no resolved document of its own. A document
    with two named hosts as its ends wins first, then a document with one
    named host as an end. Inside each step a document of a dataset that the
    finding cites wins (:func:`cited_datasets`), and telemetry wins over a
    detector document. A lead subject and a finding with its own documents
    get None, so the rule of change E holds for them.
    """
    if not _host_rule_applies(subject):
        return None
    hosts = _named_hosts(subject)
    datasets = _finding_datasets(subject)
    both = [d for d in subject.documents if _ends_named(d, hosts) >= 2]
    one = [d for d in subject.documents if _ends_named(d, hosts) >= 1]
    return _pick(both, datasets) or _pick(one, datasets)


def _finding_datasets(subject: HuntSubject) -> frozenset[str]:
    finding = subject.promoted_finding
    return cited_datasets(finding.citations) if finding is not None else frozenset()


def hunt_window(subject: HuntSubject, *, now: datetime | None = None) -> tuple[datetime, datetime]:
    """The window of the hunt, in UTC. ``subject.started_at`` must be set.

    The hunt queries reach back from the time of each query, so the window
    starts that far before the start of the hunt and ends at its end. A hunt
    that runs still ends now. The width is the window that the objective
    states, and at least the default window of a hunt query.
    """
    if subject.started_at is None:
        raise ValueError("the subject has no start time")
    current = now or datetime.now(UTC)
    start = _as_utc(subject.started_at)
    end = _as_utc(subject.finished_at) if subject.finished_at is not None else current
    stated = stated_window_hours(subject.objective) or 0
    width = max(HUNT_QUERY_WINDOW_MINUTES, stated * 60)
    return start - timedelta(minutes=width), max(end, start)


def _as_utc(at: datetime) -> datetime:
    return at.replace(tzinfo=UTC) if at.tzinfo is None else at.astimezone(UTC)


def _stamp(at: datetime) -> str:
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _end_query(host: _NamedHost) -> dict[str, Any]:
    """The clause of the host read for one host as an end of a record."""
    should: list[dict[str, Any]] = []
    if host.addresses:
        addresses = sorted(host.addresses)
        should.extend(
            {"terms": {field: addresses}} for field in ("source.ip", "destination.ip", "host.ip")
        )
    if host.names:
        should.append({"terms": {"host.name": name_variants(sorted(host.names))}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


async def grid_host_anchor(
    elastic: ElasticClient, settings: Settings, subject: HuntSubject
) -> str | None:
    """The newest grid record on the hosts that the promoted finding names, or None.

    A bounded read inside the window of the hunt, under the grid timeout. With
    two or more named hosts the record is between two of them. With one named
    host the record has that host as an end. Telemetry wins over a detector
    document. Each hit is tested against the named hosts again, so a loose
    match of the grid never becomes the anchor.

    When the citations of the finding name a dataset (:func:`cited_datasets`),
    the first read asks for those datasets only. The pipeline anchors its time
    windows on the anchor, and a zeek.ssh record of another hour is no anchor
    for a finding about HTTP requests. When that read gives no record on the
    named hosts, a second read asks for any dataset. So this step costs at
    most two grid reads.

    None when the rule does not apply, when the subject has no start time and
    when the grid fails. The caller then takes the rule of before, so a grid
    failure here costs no investigation.
    """
    if not _host_rule_applies(subject) or subject.started_at is None:
        return None
    hosts = _named_hosts(subject)
    if len(hosts) >= 2:
        pairs = [
            {"bool": {"filter": [_end_query(a), _end_query(b)]}} for a, b in combinations(hosts, 2)
        ]
        on_hosts: dict[str, Any] = {"bool": {"should": pairs, "minimum_should_match": 1}}
        need = 2
    else:
        on_hosts = _end_query(hosts[0])
        need = 1
    start, end = hunt_window(subject)
    base: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": _stamp(start), "lte": _stamp(end)}}},
        on_hosts,
    ]
    datasets = _finding_datasets(subject)
    reads = [datasets, frozenset[str]()] if datasets else [frozenset[str]()]
    for wanted in reads:
        extra = [{"terms": {"event.dataset": sorted(wanted)}}] if wanted else []
        query = {
            "bool": {
                "filter": [*base, *extra],
                "must_not": synth_scope_must_not(subject.is_synth_eval),
            }
        }
        records = await _host_read(elastic, settings, subject, query)
        if records is None:
            return None
        on_named = [r for r in records if _ends_named(r, hosts) >= need]
        chosen = _telemetry_first(_of_datasets(on_named, wanted) if wanted else on_named)
        if chosen is not None:
            return chosen
    return None


async def _host_read(
    elastic: ElasticClient, settings: Settings, subject: HuntSubject, query: dict[str, Any]
) -> list[SoAlert] | None:
    """One read of the host rule, newest first. None when the grid fails."""
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            result = await elastic.search(
                settings.events_index_pattern,
                query,
                size=HOST_READ_SIZE,
                sort=[{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                source=_HOST_READ_FIELDS,
            )
    except Exception as exc:  # a grid failure falls to the rule of before
        _LOGGER.warning(
            "hunt %s: the grid read for the anchor on the hosts of the finding failed: %r. "
            "The anchor is a document of the hunt.",
            subject.hunt_id,
            exc,
        )
        return None
    records: list[SoAlert] = []
    for hit in result.hits or []:
        try:
            records.append(SoAlert.from_es_hit(hit))
        except Exception:  # one unreadable record must not lose the anchor
            _LOGGER.warning(
                "hunt %s: the anchor rule could not read document %s",
                subject.hunt_id,
                hit.get("_id"),
            )
    return records


def promotion_focus(
    *,
    focus_origin: FocusOrigin,
    title: str,
    detail: str,
    hosts: Sequence[str],
    hunt_subject: bool,
    finding_subject: bool = False,
) -> str:
    """The focus block the investigator reads first.

    ``finding_subject`` (change E): the subject has a promoted finding, and
    the run judges the claim of that finding. A lead promotion judges the hunt.
    """
    host_text = ", ".join(hosts) or "none named"
    lead_in = f"Promoted {focus_origin.replace('_', ' ')}: {title}. {detail} Hosts involved: "
    if hunt_subject and finding_subject:
        return (
            f"{lead_in}{host_text}. The subject of this investigation is this finding. "
            "Judge its claim. Read the rest of the hunt as context. Do not assume the "
            "framing is correct."
        )
    if hunt_subject:
        return (
            f"{lead_in}{host_text}. The subject of this investigation is the hunt, not one "
            "event. Answer the hunt's objective. Do not assume the framing is correct."
        )
    return (
        f"{lead_in}{host_text}. This investigation targets the cited evidence event. Assess "
        "whether the activity is malicious. Do not assume the framing is correct."
    )


async def promotion_anchor(
    *,
    settings: Settings,
    elastic: ElasticClient,
    citations: Sequence[str],
    subject: HuntSubject | None,
) -> str:
    """The anchor document of a promotion, or :class:`PromotionRefused` (422).

    A finding with no resolved document of its own anchors on the hosts it
    names, in this order: a subject document between two named hosts, a
    subject document with one named host as an end, the newest grid record on
    the named hosts (:func:`grid_host_anchor`), and last any document of the
    subject. In the first three steps a record of a dataset that the finding
    cites wins. The grid step runs only when no subject document touches a
    named host, and it makes at most two reads. Its failure falls to the last
    step.

    A grid failure of the citation lookup propagates as ``TimeoutError``,
    ``TransportError`` or ``ApiError``. The caller names the failure in its
    own words.
    """
    anchor_id: str | None = None
    if subject is not None:
        anchor_id = host_anchor(subject)
        if anchor_id is None:
            anchor_id = await grid_host_anchor(elastic, settings, subject)
        if anchor_id is None:
            anchor_id = _pool_anchor(subject)
    if anchor_id is None:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            anchor_id = await resolve_finding_anchor(elastic, settings, citations)
    if anchor_id is None:
        raise PromotionRefused(422, "no_promotable_evidence", NO_EVIDENCE_HINT)
    return anchor_id


async def start_promotion(
    state: Any,
    *,
    anchor_id: str,
    started_by: str,
    title: str,
    detail: str,
    hosts: Sequence[str],
    kind: str,
    hunt_id: str | None,
    finding_ordinal: int | None,
    focus_origin: FocusOrigin,
    is_synth_eval: bool,
    subject: HuntSubject | None = None,
    ctx: InvestigationContext | None = None,
) -> str:
    """Start an investigation of the hunt on ``anchor_id`` and return its id.

    ``subject`` (D2) carries the hunt. The run reads the hunt's objective, its
    findings and every document they cite. The anchor is one document, because
    the pipeline anchors its time windows on one timestamp. A finding promotion
    judges the claim of that finding, and the rest of the hunt is context. A
    lead promotion judges the hunt (change E).

    ``ctx`` is the context the run uses. None builds a fresh one from
    ``state``, which is the route's case. The hunt runner passes a copy of its
    own context, so an investigation of an evaluation hunt sees what the hunt
    saw.

    Raises :class:`PromotionRefused` (503) when the manager did not start it.
    """
    focus = promotion_focus(
        focus_origin=focus_origin,
        title=title,
        detail=detail,
        hosts=hosts,
        hunt_subject=subject is not None,
        finding_subject=subject is not None and subject.promoted_finding is not None,
    )
    kwargs: dict[str, Any] = {
        "alert_id": anchor_id,
        "started_by": started_by,
        "rule_name": title,
        "focus_hint": focus,
        "kind": kind,
        "hunt_id": hunt_id,
        "finding_ordinal": finding_ordinal,
        # A promoted anchor is cited telemetry, not an SO alert. No unattended
        # write can ever apply to it, and its focus text is the promoter's own
        # framing, not a prior investigation's open questions.
        "allow_so_writes": False,
        "focus_origin": focus_origin,
        "is_synth_eval": is_synth_eval,
        "subject": subject,
    }
    if ctx is not None:
        kwargs["ctx"] = ctx
    inv_id = await investigation_manager(state).start(state, **kwargs)
    if inv_id is None:
        raise PromotionRefused(503, "could_not_start", COULD_NOT_START_HINT)
    return str(inv_id)


def fresh_context(ctx: InvestigationContext) -> InvestigationContext:
    """A new context for one investigation, built from a hunt's context.

    The shared clients and the synthetic-evaluation scope carry over. The
    per-run state (the dedup tracker, the time anchor, the visible tools) starts
    empty, because an investigation builds its own.
    """
    return InvestigationContext(
        settings=ctx.settings,
        auth=ctx.auth,
        elastic=ctx.elastic,
        misp=ctx.misp,
        audit=ctx.audit,
        blocklist=ctx.blocklist,
        maxmind=ctx.maxmind,
        cloud=ctx.cloud,
        include_synth=ctx.include_synth,
        db_sessionmaker=ctx.db_sessionmaker,
    )


__all__ = [
    "COULD_NOT_START_HINT",
    "DETECTOR_DATASETS",
    "FINDING_RERUN_HINT",
    "HOST_READ_SIZE",
    "HUNT_QUERY_WINDOW_MINUTES",
    "LEAD_NO_RERUN_HINT",
    "MAX_ANCHOR_HOSTS",
    "NO_EVIDENCE_HINT",
    "PromotionRefused",
    "anchor_from_subject",
    "cited_datasets",
    "fresh_context",
    "grid_host_anchor",
    "host_anchor",
    "hunt_window",
    "promotion_anchor",
    "promotion_focus",
    "resolve_finding_anchor",
    "start_promotion",
]
