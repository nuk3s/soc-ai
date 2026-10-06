"""One daily run of the estate model, in shadow.

The run reads the stored host profiles, fits the model, records the fit,
writes the learned group of every host, hands the model hash to the audit
chain and writes one shadow observation per outlier it can explain and cite.

**Off and absent.** With ``estate_model_enabled`` off the run returns at once
and touches nothing. With the setting on and the ``ml`` extra absent, it logs
one line and returns.

**States.** Each fit records one state:

* ``learning``: fewer than 20 hosts have a profile, or the median host has
  under 7 days of profiles. Under 20 hosts the model does not fit: the run
  records the fit row and returns, with no model file, no group and no audit
  record. With 20 hosts or more the fit writes its groups and no observation.
* ``drifted``: two or more features have a population stability index above
  0.25 against the previous fit. The data changed after the last fit. The fit
  writes its groups and no observation, and no reader takes the groups.
* ``held``: more hosts qualify for an observation than the fire budget
  allows, 1 in 100 hosts with a floor of 10. A score that marks that many
  hosts says more about the model than about the hosts. The fit writes no
  observation.
* ``measured``: none of the above. The fit writes its observations.

**The observation gate.** A host becomes an observation only when all four
hold: its outlier score is at or above the threshold, its largest feature
deviation from its group is 3 or more, fewer than 5 other hosts act the same
way, and the grid returns at least one current document of the host. A host
above the threshold with no stated reason is counted as unexplained. A host
whose behaviour a subgroup shares is counted as shared. A host with a reason
and no document is counted as no document. None of them writes anything.

Every observation is shadow, always. The estate model has no live mode.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import statistics
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from soc_ai.dossier.profile import MIN_SUPPORT_DAYS
from soc_ai.hunting.estate_model import SPEC_ID, STATISTIC, load_ml
from soc_ai.hunting.estate_model.artifact import (
    ModelRefused,
    foreign_files,
    read_verified,
    remove_model,
    write_model,
)
from soc_ai.hunting.estate_model.features import (
    Feature,
    collect_vectors,
    feature_list,
    matrix,
    render,
)
from soc_ai.hunting.leads import MAX_DOCUMENT_IDS, content_fingerprint, record_observation
from soc_ai.hunting.rerun import oql_value
from soc_ai.hunting.weight import Kind
from soc_ai.store import estate_model as store

if TYPE_CHECKING:
    from soc_ai.hunting.estate_model.fit import EstateFit, GroupFit, HostFit

__all__ = [
    "AUDIT_SESSION",
    "FIRE_BUDGET_FLOOR",
    "KEEP_FILES",
    "MIN_HOSTS",
    "PSI_DRIFT",
    "PSI_DRIFT_FEATURES",
    "STATUS_DISABLED",
    "STATUS_FAILED",
    "STATUS_FITTED",
    "STATUS_UNAVAILABLE",
    "UNAVAILABLE_LINE",
    "Document",
    "EstateRun",
    "decide_state",
    "fire_budget",
    "grid_documents",
    "rerun_query_for",
    "run_estate_model",
]

_LOGGER = logging.getLogger(__name__)

STATUS_DISABLED = "disabled"
STATUS_UNAVAILABLE = "unavailable"
STATUS_FITTED = "fitted"
STATUS_FAILED = "failed"

# The one line the run logs when the setting is on and the extra is absent.
UNAVAILABLE_LINE = (
    "estate model: unavailable. The ml extra is not installed. soc-ai fits no estate model."
)

# Below this many hosts with a profile the model does not fit.
MIN_HOSTS = 20
# A feature drifts above this index. Two drifted features mark the fit drifted.
PSI_DRIFT = 0.25
PSI_DRIFT_FEATURES = 2
# The fire budget: one observation per 100 hosts per fit, never fewer than 10.
FIRE_BUDGET_SHARE = 0.01
FIRE_BUDGET_FLOOR = 10
# Model files kept on disk. The store keeps every fit row.
KEEP_FILES = 5
# How far back the document read and the rerun query reach.
DOCUMENT_WINDOW_HOURS = 24
DOCUMENTS_PER_HOST = 3
# The session id the audit record carries.
AUDIT_SESSION = "estate-model"


@dataclass(frozen=True)
class Document:
    """One current document of a host: its id and its time."""

    id: str
    at: datetime | None = None


DocumentReader = Callable[[str], Awaitable[Sequence[Document]]]


@dataclass
class EstateRun:
    """What one run did. ``status`` says whether it ran at all."""

    status: str
    state: str | None = None
    reason: str | None = None
    fit_id: int | None = None
    hosts: int = 0
    blind: int = 0
    groups: int = 0
    outliers: int = 0
    unexplained: int = 0
    shared: int = 0
    no_documents: int = 0
    observations: int = 0
    psi: float | None = None
    drifted: list[str] = field(default_factory=list)
    model_sha256: str | None = None
    model_file: str | None = None
    fitted_at: datetime | None = None
    audited: bool = False
    seconds: float | None = None
    refused: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def line(self) -> str:
        """The one log line of a run that fitted."""
        psi = "none" if self.psi is None else f"{self.psi:.2f}"
        return (
            f"estate model: {self.state}. {self.hosts} hosts in {self.groups} groups. "
            f"{self.outliers} above the threshold, {self.unexplained} with no stated reason, "
            f"{self.shared} shared with a subgroup, {self.no_documents} with no document, "
            f"{self.observations} observations. "
            f"Largest drift index {psi}."
        )


def fire_budget(hosts: int) -> int:
    """The most observations one fit may write before it holds itself."""
    return max(FIRE_BUDGET_FLOOR, math.ceil(max(0, hosts) * FIRE_BUDGET_SHARE))


def decide_state(
    *,
    hosts: int,
    support_days: int,
    drifted: Sequence[str],
    qualified: int,
) -> tuple[str, str | None]:
    """The state of one fit and the reason for it. Learning outranks drift, and drift a hold."""
    if hosts < MIN_HOSTS:
        return (
            store.STATE_LEARNING,
            f"The estate holds {hosts} hosts with a profile. The model needs {MIN_HOSTS}.",
        )
    if support_days < MIN_SUPPORT_DAYS:
        return (
            store.STATE_LEARNING,
            f"Learning, day {support_days} of {MIN_SUPPORT_DAYS}. The median host has "
            f"{support_days} days of profiles.",
        )
    if len(drifted) >= PSI_DRIFT_FEATURES:
        return (
            store.STATE_DRIFTED,
            f"The data changed after the last fit. {len(drifted)} features have a drift "
            f"index above {PSI_DRIFT}: {', '.join(drifted[:5])}.",
        )
    budget = fire_budget(hosts)
    if qualified > budget:
        return (
            store.STATE_HELD,
            f"{qualified} hosts qualified for an observation. The fire budget is {budget}. "
            "The fit wrote no observation.",
        )
    return store.STATE_MEASURED, None


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _iso(at: datetime) -> str:
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)
    return at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC).replace(tzinfo=None) if parsed.tzinfo else parsed


def rerun_query_for(entity_key: str, *, start: datetime, end: datetime) -> str:
    """The OQL query that shows what the host sent in the window, by dataset."""
    value = oql_value(entity_key)
    entity = (
        f"(source.ip:{value} OR destination.ip:{value})"
        if _is_address(entity_key)
        else f"host.name:{value}"
    )
    return f'{entity} AND @timestamp:["{_iso(start)}" TO "{_iso(end)}"] | groupby event.dataset'


def grid_documents(elastic: Any, settings: Any, *, now: datetime) -> DocumentReader:
    """A reader of the newest documents of one host in the last 24 hours."""
    index = str(getattr(settings, "events_index_pattern", "logs-*") or "logs-*")
    start = now - timedelta(hours=DOCUMENT_WINDOW_HOURS)

    async def read(entity_key: str) -> Sequence[Document]:
        if _is_address(entity_key):
            clause: dict[str, Any] = {
                "bool": {
                    "should": [
                        {"term": {"source.ip": entity_key}},
                        {"term": {"destination.ip": entity_key}},
                        {"term": {"host.ip": entity_key}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        else:
            names = sorted({entity_key, entity_key.lower(), entity_key.upper()})
            clause = {"terms": {"host.name": names}}
        query = {
            "bool": {
                "filter": [
                    clause,
                    {"range": {"@timestamp": {"gte": _iso(start), "lte": _iso(now)}}},
                ]
            }
        }
        result = await elastic.search(
            index,
            query,
            size=DOCUMENTS_PER_HOST,
            sort=[{"@timestamp": {"order": "desc"}}],
            source=["@timestamp"],
        )
        out: list[Document] = []
        for hit in result.hits:
            doc_id = hit.get("_id")
            if not doc_id:
                continue
            out.append(
                Document(id=str(doc_id), at=_parse((hit.get("_source") or {}).get("@timestamp")))
            )
        return out

    return read


def _sentence_case(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def _reasons(
    host: HostFit, group: GroupFit | None, features: dict[str, Feature]
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    """The sentences of one observation and the feature block of its evidence."""
    size = group.size if group is not None else 0
    median = group.score_median if group is not None else 0.0
    sentences = [
        f"{host.entity_key} departs from learned group {host.group_id} of {size} hosts.",
        f"Its estate outlier score is {host.score:.2f}. The group median is {median:.2f}.",
    ]
    block: dict[str, dict[str, Any]] = {}
    for item in host.top:
        feature = features[item.name]
        value = render(feature, item.value)
        peer = render(feature, item.peer)
        sentences.append(f"{_sentence_case(feature.label)}: {value}. The peer median is {peer}.")
        block[item.name] = {
            "label": feature.label,
            "value": item.value,
            "peer": item.peer,
            "deviation": round(item.deviation, 2),
        }
    return sentences, block


def _payload(
    fitted: EstateFit, features: Sequence[Feature], *, state: str, at: datetime
) -> dict[str, Any]:
    from soc_ai.hunting.estate_model import fit as fit_mod  # noqa: PLC0415 - the extra

    return {
        "fitted_at": _iso(at),
        "state": state,
        "hosts": len(fitted.hosts),
        "feature_names": list(fitted.feature_names),
        "features": [
            {"name": f.name, "label": f.label, "unit": f.unit, "log": f.log} for f in features
        ],
        "partitions": {
            name: {
                "hosts": part.hosts,
                "mean": part.mean,
                "scale": part.scale,
                "k": part.k,
                "silhouette": part.silhouette,
                "scored": part.scored,
            }
            for name, part in fitted.partitions.items()
        },
        "groups": [
            {
                "id": g.id,
                "partition": g.partition,
                "size": g.size,
                "centroid": g.centroid,
                "median": g.median,
                "score_median": g.score_median,
                "centroid_model": g.centroid_model,
            }
            for g in fitted.groups
        ],
        "histograms": fitted.histograms,
        "forest": {
            "trees": fit_mod.FOREST_TREES,
            "max_samples": fit_mod.FOREST_SAMPLE,
            "random_state": fit_mod.RANDOM_STATE,
            "min_scored_hosts": fit_mod.MIN_SCORED_HOSTS,
        },
        "threshold": fit_mod.SCORE_THRESHOLD,
        "reason_min_deviation": fit_mod.REASON_MIN_DEVIATION,
    }


def _naive_utc(at: datetime | None) -> datetime:
    value = at or datetime.now(UTC)
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


async def run_estate_model(  # noqa: PLR0915 - one procedure, read top to bottom
    *,
    db_sessionmaker: Any,
    settings: Any,
    elastic: Any | None = None,
    audit: Any | None = None,
    documents: DocumentReader | None = None,
    now: datetime | None = None,
) -> EstateRun:
    """Fit the estate model once, record it, and write its shadow observations."""
    if not getattr(settings, "estate_model_enabled", False):
        return EstateRun(status=STATUS_DISABLED)
    if load_ml() is None:
        _LOGGER.warning(UNAVAILABLE_LINE)
        return EstateRun(status=STATUS_UNAVAILABLE)
    from soc_ai.hunting.estate_model import fit as fit_mod  # noqa: PLC0415 - the extra

    at = _naive_utc(now)
    run = EstateRun(status=STATUS_FITTED, fitted_at=at)
    data_dir = Path(settings.soc_ai_data_dir)

    async with db_sessionmaker() as db:
        read = await collect_vectors(db)
        recorded = await store.recorded_files(db)
        previous_fit = await store.latest_model_fit(db)
        await store.promote_challengers(db, now=at)
    run.hosts = len(read.vectors)
    run.blind = read.blind

    for name in foreign_files(data_dir, recorded):
        run.refused.append(f"No fit on record wrote the file {name}. soc-ai does not load it.")
    previous: dict[str, Any] | None = None
    if previous_fit is not None and previous_fit.model_file:
        try:
            previous = read_verified(data_dir, previous_fit.model_file, recorded)
        except ModelRefused as exc:
            run.refused.append(str(exc))
    for line in run.refused:
        _LOGGER.warning("estate model: %s", line)

    support = int(statistics.median([v.support_days for v in read.vectors])) if read.vectors else 0
    if run.hosts < MIN_HOSTS:
        run.state, run.reason = decide_state(
            hosts=run.hosts, support_days=support, drifted=(), qualified=0
        )
        async with db_sessionmaker() as db:
            run.fit_id = await store.record_fit(
                db,
                fitted_at=at,
                state=run.state,
                reason=run.reason,
                hosts=run.hosts,
                support_days=support,
            )
        _LOGGER.info("estate model: %s %s", run.state, run.reason)
        return run

    features = feature_list(read.vectors)
    raw, model = matrix(read.vectors, features)
    keys = [v.entity_key for v in read.vectors]
    try:
        fitted: EstateFit = await asyncio.to_thread(
            fit_mod.fit_estate, keys, features, raw, model, previous=previous
        )
    except Exception as exc:
        run.status = STATUS_FAILED
        run.errors.append(f"the fit failed: {type(exc).__name__}: {exc}")
        _LOGGER.warning("estate model: the fit failed. %s: %s", type(exc).__name__, exc)
        return run
    run.seconds = fitted.seconds
    run.groups = len(fitted.groups)
    run.psi = max(fitted.psi.values()) if fitted.psi else None
    run.drifted = sorted(
        (name for name, value in fitted.psi.items() if value > PSI_DRIFT),
        key=lambda name: -fitted.psi[name],
    )
    above = [h for h in fitted.hosts if h.scored and h.score >= fit_mod.SCORE_THRESHOLD]
    explained = [h for h in above if h.explained]
    qualified = sorted((h for h in explained if not h.shared), key=lambda h: -h.score)
    run.outliers = len(above)
    run.unexplained = len(above) - len(explained)
    run.shared = len(explained) - len(qualified)
    run.state, run.reason = decide_state(
        hosts=run.hosts, support_days=support, drifted=run.drifted, qualified=len(qualified)
    )

    payload = _payload(fitted, features, state=run.state, at=at)
    run.model_file, run.model_sha256 = write_model(data_dir, payload, fitted_at=at)
    groups_detail = [
        {
            "id": g.id,
            "partition": g.partition,
            "size": g.size,
            "centroid": g.centroid,
            "median": g.median,
            "score_median": g.score_median,
        }
        for g in fitted.groups
    ]
    async with db_sessionmaker() as db:
        run.fit_id = await store.record_fit(
            db,
            fitted_at=at,
            state=run.state,
            reason="; ".join([*([run.reason] if run.reason else []), *run.refused]) or None,
            model_sha256=run.model_sha256,
            model_file=run.model_file,
            hosts=run.hosts,
            features=len(features),
            groups=run.groups,
            silhouette=fitted.silhouette,
            support_days=support,
            psi=run.psi,
            drifted=[{"feature": n, "psi": round(fitted.psi[n], 4)} for n in run.drifted],
            groups_detail=groups_detail,
        )
        await store.replace_groups(
            db,
            [
                store.GroupRow(
                    entity_key=h.entity_key, group_id=h.group_id, distance=h.distance, score=h.score
                )
                for h in fitted.hosts
            ],
            model_sha256=run.model_sha256,
            fitted_at=at,
        )
        stale = await store.files_beyond(db, keep=KEEP_FILES)
    for name in stale:
        remove_model(data_dir, name)

    run.audited = await _append_audit(audit, run)

    if run.state == store.STATE_MEASURED and qualified:
        await _observe(
            run,
            qualified,
            fitted=fitted,
            features=features,
            db_sessionmaker=db_sessionmaker,
            reader=documents
            if documents is not None
            else (grid_documents(elastic, settings, now=at) if elastic is not None else None),
            at=at,
            threshold=fit_mod.SCORE_THRESHOLD,
        )

    async with db_sessionmaker() as db:
        await store.update_fit(
            db,
            run.fit_id,
            outliers=run.outliers,
            unexplained=run.unexplained,
            shared=run.shared,
            no_documents=run.no_documents,
            observations=run.observations,
            audited=run.audited,
        )
    _LOGGER.info(run.line())
    return run


async def _append_audit(audit: Any | None, run: EstateRun) -> bool:
    """Hand the model hash to the audit chain. False when there is no chain to hand it to."""
    if audit is None:
        run.notes.append("No audit logger. The model hash is in the store only.")
        return False
    try:
        await audit.log_kind(
            AUDIT_SESSION,
            "estate_model_fit",
            {
                "model_sha256": run.model_sha256,
                "model_file": run.model_file,
                "fitted_at": _iso(run.fitted_at) if run.fitted_at else None,
                "state": run.state,
                "hosts": run.hosts,
                "groups": run.groups,
            },
            user="soc-ai",
        )
    except Exception as exc:
        run.errors.append(f"the audit append failed: {type(exc).__name__}: {exc}")
        _LOGGER.warning("estate model: the audit append failed. %s", exc)
        return False
    return True


async def _observe(
    run: EstateRun,
    qualified: Sequence[HostFit],
    *,
    fitted: EstateFit,
    features: Sequence[Feature],
    db_sessionmaker: Any,
    reader: DocumentReader | None,
    at: datetime,
    threshold: float,
) -> None:
    """Write one shadow observation per qualified host that the grid can cite."""
    by_name = {f.name: f for f in features}
    start = at - timedelta(hours=DOCUMENT_WINDOW_HOURS)
    for host in qualified:
        docs: Sequence[Document] = ()
        if reader is not None:
            try:
                docs = await reader(host.entity_key)
            except Exception as exc:
                run.errors.append(f"{host.entity_key}: the document read failed: {exc}")
                docs = ()
        ids = [d.id for d in docs if d.id][:MAX_DOCUMENT_IDS]
        if not ids:
            # Condition 1: every hit cites at least one document. The lead
            # auto-hunt skips a lead that cites none.
            run.no_documents += 1
            continue
        group = fitted.group(host.group_id)
        sentences, block = _reasons(host, group, by_name)
        times = [d.at for d in docs if d.at is not None]
        async with db_sessionmaker() as db:
            await record_observation(
                db,
                entity_kind="host",
                entity_key=host.entity_key,
                kind=Kind.ESTATE_OUTLIER,
                spec_id=SPEC_ID,
                fingerprint=content_fingerprint(STATISTIC, *sorted(c.name for c in host.top)),
                summary=" ".join(sentences),
                evidence={
                    "sample_ids": ids,
                    "anchor_id": ids[0],
                    "detector": {
                        "id": SPEC_ID,
                        "model_sha256": run.model_sha256,
                        "fitted_at": _iso(at),
                        "method": "isolation forest score, robust deviation from the group",
                    },
                    "group": {
                        "id": host.group_id,
                        "size": group.size if group is not None else 0,
                        "distance": round(host.distance, 4),
                    },
                    "features": block,
                    "reasons": sentences,
                    "score": round(host.score, 4),
                    "threshold": threshold,
                    "threshold_basis": "fixed isolation forest score",
                    "coverage": store.STATE_MEASURED,
                },
                source="model",
                shadow=True,
                observed_at=max(times) if times else None,
                now=at,
                statistic=STATISTIC,
                statistic_value=round(host.score, 4),
                baseline_value=round(group.score_median, 4) if group is not None else None,
                document_ids=ids,
                rerun_query=rerun_query_for(host.entity_key, start=start, end=at),
            )
        run.observations += 1
