"""OpenSearch ingestion of rendered synth-TP docs.

Takes :class:`Scenario` objects, renders them to ECS docs via
:mod:`soc_ai.eval.synth_render`, and indexes them into ``logs-synth-*``
OpenSearch indices. Refreshes after writes so the docs are queryable
by the eval harness immediately afterward.

Synth pollution kill-switch: enforces ``logs-synth-`` index prefix at
ingest time, even on programmatically-constructed Scenarios that
bypass the loader's pydantic validation. The read-side twin,
:func:`assert_no_synth_in_production`, refuses to ingest at all while a
synthetic document is sitting in a production index.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from elasticsearch import NotFoundError

from soc_ai.config import Settings
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
    # The journey scorer's citation bridge: event ``index`` → the ES ``_id``s
    # ingest assigned to that scenario's docs, in write order. Events carry no
    # id field, so the event's ``index`` is its scenario-local identifier (the
    # same keying as HuntJourney.expected_cited_event_ids); the ``_id``s only
    # exist after ingest, so here — at ingest time — is the one place the two
    # can be joined. ``score_journey`` REFUSES to score when this misses an
    # expected event, and ``triage_doc_id`` alone covers zero of m1's two.
    doc_ids_by_event: dict[str, list[str]] = field(default_factory=dict)
    # The ``synth.scenario_id`` value this plant's docs were stamped with —
    # the run's SynthScope key. Equals ``scenario_id`` for a single plant
    # (repeat 0); repeated plants get :func:`plant_id_for`'s suffixed form so
    # sibling repeats' documents stay mutually invisible. Empty string only on
    # pre-repeats constructions (treated as ``scenario_id`` by the batch runner).
    plant_id: str = ""
    # 0-based repeat index of this plant within its batch.
    repeat: int = 0
    # The address of every document this plant wrote, as ``(index, id)`` in
    # write order. ``index`` is the concrete index the grid stored the document
    # in, taken from the write response. For a data stream that is the backing
    # index, and a delete by id accepts no other address.
    documents: tuple[tuple[str, str], ...] = ()


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


async def assert_no_synth_in_production(elastic: ElasticClient, settings: Settings) -> None:
    """Refuse to proceed if a synthetic document reached a production index.

    A planted scenario outside ``logs-synth-*`` would be shown to a real
    analyst as genuine, and would contaminate every measurement taken after
    it. The synth catalogue README has required this check since the
    catalogue landed; it is the read-side twin of ``_check_synth_prefix``.
    """
    # The production pattern (default ``logs-*``) legitimately matches the
    # ``logs-synth-*`` datastreams too; exclude them in the multi-target
    # expression so only an ESCAPED synth doc can match. size=1 — a single
    # escaped doc is already a refusal.
    index = f"{settings.events_index_pattern},-{_SYNTH_INDEX_PATTERN}"
    try:
        # require_complete: a degraded search that reads only the surviving
        # shards and finds 0 hits proves nothing — the escaped doc may sit on a
        # shard that never answered. The grid-wide es_fail_on_partial_results
        # opt-out (an operator's tolerance for partial ORDINARY reads) must not
        # soften this check, so a partial/timed-out read raises here and lands
        # in the same refusal arm as a transport error.
        result = await elastic.search(
            index, {"exists": {"field": "synth.scenario_id"}}, size=1, require_complete=True
        )
    except Exception as exc:
        # Fail loud, not soft: if containment cannot be VERIFIED, that is
        # itself a refusal — an unverifiable grid must not be treated as
        # clean (a false all-clear outranks any error).
        raise RuntimeError(
            f"synth containment check could not be performed against {index!r}: "
            f"{exc} — refusing to ingest synthetic scenarios on a grid whose "
            f"production indices cannot be proven clean"
        ) from exc
    if result.hits:
        hit = result.hits[0]
        bound = "at least " if result.total_is_lower_bound else ""
        raise RuntimeError(
            f"synthetic document found in production index "
            f"{hit.get('_index', '<unknown>')!r} (doc {hit.get('_id', '<unknown>')!r}, "
            f"{bound}{result.total} matching outside 'logs-synth-'): a planted "
            f"scenario there would be shown to a real analyst as genuine — "
            f"refusing to ingest until docs carrying synth.scenario_id are "
            f"cleaned out of that index"
        )


async def _index_one(elastic: ElasticClient, doc: RenderedDoc) -> tuple[str, str]:
    """Index one doc and return ``(_id, index)`` as the grid stored it.

    The second value is the ``_index`` of the write response: the concrete
    index that holds the document. A caller that must take the document back
    needs exactly this pair, because a delete by id goes to that index.
    """
    # `index()` returns an `ObjectApiResponse[Any]`, which is dict-subscriptable.
    response = await elastic._client.index(index=doc.index, body=doc.body)
    stored_in = response.get("_index", doc.index)
    return str(response["_id"]), str(stored_in)


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


def _no_triage_target(scenario_id: str) -> RuntimeError:
    """The refusal for a scenario with nothing to triage, raised before any write.

    A scenario with no triage target is legal since the catalogue gained its
    second population (see Scenario._at_most_one_triage_target), but it belongs
    to the DECLARATIVE instrument and cannot be triaged: there is no alert for
    the harness to sample. Callers are expected to reject it before planting;
    this is the ingester's own check, made before its first write so a caller
    that did not still leaves nothing on the grid. The message says which
    population the scenario is in rather than implying the render is broken.
    """
    return RuntimeError(
        f"scenario {scenario_id!r} has no triage target, so it cannot be triaged. "
        "It declares a spec_journey and belongs to the declarative population: "
        "score it with `soc-ai spec-run` / the spec_journey coverage gate, not the "
        "triage batch. Nothing was planted."
    )


def plant_id_for(scenario_id: str, repeat: int, tag: str | None = None) -> str:
    """The ``synth.scenario_id`` scope key for one planted copy of a scenario.

    Repeat 0 keeps the bare scenario id, so a single plant (``--repeats 1``,
    the default) stays byte-identical to the pre-repeats stamp. Repeat k >= 1
    appends ``::r<k>``. The per-run ``SynthScope`` filter term-matches this
    exact value, so N plants of one scenario can never retrieve each other's
    documents — the same isolation that already keeps sibling scenarios apart.

    ``tag`` puts a batch of its own between the two: ``<id>::<tag>``, then the
    repeat suffix. The nightly plants the same few scenarios again and again on
    one grid, and without a tag the plant of five nights ago carries the very
    key tonight's run is scoped to. If its cleanup failed, that old plant would
    come back as corroborating evidence. None (the default) leaves every key
    exactly as it was.
    """
    base = f"{scenario_id}::{tag}" if tag else scenario_id
    return base if repeat == 0 else f"{base}::r{repeat}"


async def ingest_scenario(
    scenario: Scenario,
    *,
    elastic: ElasticClient,
    run_time: datetime,
    repeat: int = 0,
    plant_tag: str | None = None,
    written: list[tuple[str, str]] | None = None,
) -> IngestResult:
    """Render and ingest one scenario; return the triage-target locator.

    ``repeat`` selects this plant's :func:`plant_id_for` scope key; 0 (the
    default) reproduces the single-plant stamp exactly. ``plant_tag`` is the
    batch's own key suffix (see :func:`plant_id_for`).

    ``written`` receives the ``(index, id)`` of each document as soon as the
    grid accepts it. A plant that fails part way raises and returns nothing, and
    this list is then the only record of what is on the grid.
    """
    plant_id = plant_id_for(scenario.id, repeat, plant_tag)
    docs = render_scenario(scenario, run_time=run_time, plant_id=plant_id)
    _check_synth_prefix(docs, scenario.id)
    # Decided from the rendered docs, before the first write: the check is
    # cheap, and finding out after the loop would leave the whole plant on the
    # grid with an error saying so.
    target_pos = next((i for i, doc in enumerate(docs) if doc.is_triage_target), None)
    if target_pos is None:
        raise _no_triage_target(scenario.id)

    touched: set[str] = set()
    doc_ids: list[str] = []
    documents: list[tuple[str, str]] = []
    doc_ids_by_event: dict[str, list[str]] = {}
    for doc in docs:
        doc_id, stored_in = await _index_one(elastic, doc)
        documents.append((stored_in, doc_id))
        if written is not None:
            written.append((stored_in, doc_id))
        doc_ids.append(doc_id)
        touched.add(doc.index)
        doc_ids_by_event.setdefault(doc.index, []).append(doc_id)

    await _refresh(elastic, touched)
    return IngestResult(
        scenario_id=scenario.id,
        triage_doc_id=doc_ids[target_pos],
        triage_index=docs[target_pos].index,
        doc_count=len(docs),
        doc_ids_by_event=doc_ids_by_event,
        plant_id=plant_id,
        repeat=repeat,
        documents=tuple(documents),
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


# The marker every synthetic index carries in its name: ``logs-synth-<x>`` for
# the data stream and ``.ds-logs-synth-<x>-<date>-<n>`` for its backing index.
_SYNTH_INDEX_MARKER = "logs-synth-"

# The record a ride-along batch keeps of what it wrote, beside its bundles.
LEDGER_NAME = "synth_documents.json"


async def delete_synth_documents(
    elastic: ElasticClient, documents: Sequence[tuple[str, str]]
) -> tuple[int, list[tuple[str, str, str]]]:
    """Delete the named documents, one request per document, by ``(index, id)``.

    The only way the nightly removes anything from the grid. There is no query
    in it: each request names one document by the id the grid gave it when it
    was written, in the index the grid stored it in. A delete by query selects
    its victims at delete time, and a filter that was assembled wrong, or a
    real document that came to carry a matching field, is then deleted with
    them. A delete by id cannot reach a document this code did not write.

    An address outside a synthetic index is refused and reported, never sent.
    A document that is already gone counts as removed.

    Returns ``(removed, failures)`` where each failure is
    ``(index, id, reason)``. Never raises for a document: one refused delete
    must not stop the rest.
    """
    removed = 0
    failures: list[tuple[str, str, str]] = []
    for index, doc_id in documents:
        if _SYNTH_INDEX_MARKER not in index:
            failures.append((index, doc_id, "refused: the index is not a synthetic index"))
            continue
        try:
            await elastic._client.delete(index=index, id=doc_id)
        except NotFoundError:
            pass
        except Exception as e:
            failures.append((index, doc_id, f"{type(e).__name__}: {e}"[:200]))
            continue
        removed += 1
    return removed, failures


def write_ledger(
    batch_dir: Path, documents: Sequence[tuple[str, str]], *, planted_at: datetime | None
) -> None:
    """Record the documents a batch still has on the grid, in its own directory.

    Written as soon as the plant ends, before the first run, so a batch that is
    killed leaves the addresses behind for the next one. Rewritten after each
    removal with what is left. An empty list is a batch that took everything
    back.
    """
    payload = {
        "planted_at": planted_at.isoformat() if planted_at is not None else None,
        "documents": [[index, doc_id] for index, doc_id in documents],
    }
    (batch_dir / LEDGER_NAME).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def read_ledger(batch_dir: Path) -> tuple[datetime | None, list[tuple[str, str]]]:
    """``(planted_at, documents)`` from a batch's ledger. Empty when it has none.

    A ledger that cannot be read gives no documents: nothing is deleted on the
    strength of a file this code cannot parse.
    """
    try:
        payload = json.loads((batch_dir / LEDGER_NAME).read_text(encoding="utf-8"))
        raw_time = payload.get("planted_at")
        planted_at = datetime.fromisoformat(raw_time) if isinstance(raw_time, str) else None
        documents = [
            (str(entry[0]), str(entry[1]))
            for entry in payload.get("documents") or []
            if isinstance(entry, list | tuple) and len(entry) == len(("index", "id"))
        ]
    except (OSError, ValueError, AttributeError, TypeError):
        return None, []
    return planted_at, documents


async def ingest_scenarios(
    scenarios: list[Scenario],
    *,
    elastic: ElasticClient,
    run_time: datetime,
    repeats: int = 1,
    plant_tag: str | None = None,
    written: list[tuple[str, str]] | None = None,
) -> list[IngestResult]:
    """Render + ingest each scenario sequentially, ``repeats`` copies apiece.

    Two checks run before a single write, and both refuse the whole batch: the
    production-containment check (a synthetic document already sitting outside
    ``logs-synth-*``), and the triage-target check every scenario would fail on
    its own turn. Refusing a no-alert scenario only when its turn came would
    leave every scenario before it planted.

    Each of a scenario's ``repeats`` plants is stamped with its own
    :func:`plant_id_for` scope key (repeat 0 = the bare id), so repeated runs
    of one scenario cannot see each other's documents. ``synth-clean`` is
    unaffected: every copy still carries ``synth.scenario_id`` (the field the
    cleanup's exists-query deletes on), just with a per-repeat value.

    Sequential (not concurrent) on purpose — the catalogue is small (9
    scenarios, up to ~6 events each), and SO ES is rate-sensitive under
    the lab grid's load profile.
    """
    if repeats < 1:
        raise ValueError(f"repeats must be >= 1, got {repeats}")
    # The same decision ingest_scenario makes from its rendered docs, made here
    # from the events, which carry the flag the render copies one to one.
    for scenario in scenarios:
        if not any(event.is_triage_target for event in scenario.events):
            raise _no_triage_target(scenario.id)
    await assert_no_synth_in_production(elastic, elastic._settings)
    return [
        await ingest_scenario(
            s, elastic=elastic, run_time=run_time, repeat=k, plant_tag=plant_tag, written=written
        )
        for s in scenarios
        for k in range(repeats)
    ]
