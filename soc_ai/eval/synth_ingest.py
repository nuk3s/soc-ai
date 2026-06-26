"""OpenSearch ingestion of rendered synth-TP docs.

Takes :class:`Scenario` objects, renders them to ECS docs via
:mod:`soc_ai.eval.synth_render`, and indexes them into ``logs-synth-*``
OpenSearch indices. Refreshes after writes so the docs are queryable
by the eval harness immediately afterward.

Synth pollution kill-switch: enforces ``logs-synth-`` index prefix at
ingest time, even on programmatically-constructed Scenarios that
bypass the loader's pydantic validation.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from elasticsearch import NotFoundError

from soc_ai.eval.synth_loader import Scenario
from soc_ai.eval.synth_render import RenderedDoc, render_scenario
from soc_ai.so_client.elastic import ElasticClient

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestResult:
    """The triage-target locator returned to the eval runner.

    The runner uses ``triage_doc_id`` (and ``triage_index``) to point the
    harness at the synthetic alert, the same way it would for a real
    sampled alert.
    """

    scenario_id: str
    triage_doc_id: str
    triage_index: str
    doc_count: int


def _check_synth_prefix(docs: list[RenderedDoc], scenario_id: str) -> None:
    """Refuse any doc whose target index is not under ``logs-synth-*``.

    Defense in depth: the Scenario loader already validates this, but
    a programmatic construction (test fixtures, repl) might bypass it.
    """
    bad = [d.index for d in docs if not d.index.startswith("logs-synth-")]
    if bad:
        raise ValueError(
            f"scenario {scenario_id!r} would write to non-synth indices "
            f"{bad}; refusing — synth pollution kill-switch requires "
            f"every index to start with 'logs-synth-'"
        )


async def _index_one(elastic: ElasticClient, doc: RenderedDoc) -> str:
    """Index one doc and return its OpenSearch ``_id``."""
    # `index()` returns an `ObjectApiResponse[Any]`, which is dict-subscriptable.
    response = await elastic._client.index(index=doc.index, body=doc.body)
    return str(response["_id"])


async def _refresh(elastic: ElasticClient, indices: set[str]) -> None:
    """Refresh the touched indices so the docs are immediately searchable.

    SO routes ``logs-synth-*`` writes into ILM-managed datastreams (template
    ``so-logs``). The first write creates the datastream + a backing
    index; the refresh call can race the alias registration and return
    ``NotFoundError`` even though the writes succeeded. Retry once after
    a short sleep; if it still 404s, swallow and rely on ES's default
    refresh interval (1s) — the harness's first prefetch query happens
    seconds later, so the docs will be visible by then.
    """
    target = ",".join(sorted(indices))
    for attempt in range(2):
        try:
            await elastic._client.indices.refresh(index=target)
            return
        except NotFoundError:
            if attempt == 0:
                await asyncio.sleep(0.5)
                continue
            _LOGGER.warning(
                "synth refresh: 404 on %s after retry — datastream alias "
                "not yet registered; relying on default refresh interval",
                target,
            )
            return


async def ingest_scenario(
    scenario: Scenario, *, elastic: ElasticClient, run_time: datetime
) -> IngestResult:
    """Render and ingest one scenario; return the triage-target locator."""
    docs = render_scenario(scenario, run_time=run_time)
    _check_synth_prefix(docs, scenario.id)

    triage_doc_id: str | None = None
    triage_index: str | None = None
    touched: set[str] = set()
    for doc in docs:
        doc_id = await _index_one(elastic, doc)
        touched.add(doc.index)
        if doc.is_triage_target:
            triage_doc_id = doc_id
            triage_index = doc.index

    if triage_doc_id is None or triage_index is None:
        # Defensive — render_scenario enforces exactly-one triage target,
        # but we should still fail loudly if somehow none was indexed.
        raise RuntimeError(
            f"scenario {scenario.id!r} ingested {len(docs)} docs but no triage target was tagged"
        )

    await _refresh(elastic, touched)
    return IngestResult(
        scenario_id=scenario.id,
        triage_doc_id=triage_doc_id,
        triage_index=triage_index,
        doc_count=len(docs),
    )


_SYNTH_INDEX_PATTERN = "logs-synth-*"


async def cleanup_synth_docs(
    elastic: ElasticClient,
    *,
    older_than: datetime | None = None,
) -> int:
    """Delete synthetic-eval docs so ``logs-synth-*`` doesn't accumulate forever.

    Without this, every batch's injected fixtures persist indefinitely; a real
    alert later sharing a pivot value with a stale fixture could pull it into
    a (prod-default-excluded, but still) investigation, and the synth indices
    grow without bound. This deletes only docs carrying ``synth.scenario_id``
    under the ``logs-synth-*`` prefix — the exact marker the prefetch and OQL
    kill-switches exclude on — so it can never touch a real index.

    Args:
        older_than: when set, only delete synth docs whose ``@timestamp`` is
            strictly before this cutoff (a real TTL). When ``None``, delete all
            synth docs.

    Returns the number of docs deleted. Idempotent — a second call deletes 0.
    """
    must: list[dict[str, Any]] = [{"exists": {"field": "synth.scenario_id"}}]
    if older_than is not None:
        must.append({"range": {"@timestamp": {"lt": older_than.isoformat()}}})
    try:
        resp = await elastic._client.delete_by_query(
            index=_SYNTH_INDEX_PATTERN,
            body={"query": {"bool": {"must": must}}},
            conflicts="proceed",
            refresh=True,
        )
    except NotFoundError:
        # No synth indices exist yet — nothing to clean.
        return 0
    return int(resp.get("deleted", 0))


async def ingest_scenarios(
    scenarios: list[Scenario], *, elastic: ElasticClient, run_time: datetime
) -> list[IngestResult]:
    """Render + ingest each scenario sequentially.

    Sequential (not concurrent) on purpose — the catalogue is small (9
    scenarios, up to ~6 events each), and SO ES is rate-sensitive under
    the lab grid's load profile.
    """
    return [await ingest_scenario(s, elastic=elastic, run_time=run_time) for s in scenarios]
