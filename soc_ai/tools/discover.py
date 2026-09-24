"""On-demand grid-discovery tools for the agent.

Complements the ambient dataset inventory (:mod:`soc_ai.so_client.inventory`) with
drill-down the agent calls when it needs it — dataset-agnostic, so they work for
host logs (endpoint/windows/sysmon) exactly as they do for zeek/suricata:

- :func:`describe_dataset` — sample recent docs of ANY dataset and report the
  fields actually POPULATED on it (+ an example value + coverage). This is how the
  agent learns "what fields does zeek.ssh / endpoint / windows.security have"
  without a static schema.
- :func:`field_values` — a terms aggregation: the top values a field takes
  (optionally within one dataset). "Which rule.names fire", "which host.names exist".

Both are read-only metadata over ``settings.events_index_pattern`` and best-effort
(an ES error returns a structured ``error`` result, never raises into the agent).

Both carry the synthetic-eval kill-switch every other events reader carries: by
default the issued body excludes docs tagged ``synth.scenario_id`` so a live eval
batch's planted scenarios never inflate a described dataset or a field's top
values; an eval-mode context opts in per call with ``include_synth=True``
(mirroring :func:`soc_ai.tools.query_events.query_events_oql`).

**They part company on imported data**, because they answer different kinds of
question (:mod:`soc_ai.tools._provenance`):

- :func:`field_values` is a distribution with counts — "which rule.names fire
  and how often", "which host.names exist" — and that is a claim about a
  network. On a grid where most documents are backfill it ranked an imported
  corpus's hostnames above every machine on the wire, which is the terrain the
  agent then reasons over. It counts live telemetry only by default and reports
  the population it counted.
- :func:`describe_dataset` is not. It answers "what does a document of this
  dataset look like", which is a property of the DATA rather than of the
  network, and its coverage fraction is over its own sample. It is also the
  tool an agent needs precisely when a plane is import-only: the grid inventory
  reports such a plane as present and queryable, so a schema read that came
  back empty for it would contradict the inventory and leave the agent unable
  to query documents it has been told exist. It stays unfiltered, deliberately.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import dataset_name_filter
from soc_ai.so_client.oql import _field_suggestion, get_whitelist
from soc_ai.tools._provenance import LIVE, Provenance, denominator_note, provenance_must_not
from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not

_LOGGER = logging.getLogger(__name__)

_SAMPLE_SIZE = 40
_MAX_FIELDS = 100
_EXAMPLE_CLIP = 120


def _clip(value: Any) -> Any:
    """Truncate a long scalar example so a describe result stays compact."""
    if isinstance(value, str) and len(value) > _EXAMPLE_CLIP:
        return value[:_EXAMPLE_CLIP] + "…"
    return value


def _in_marker_namespace(field_path: str) -> bool:
    """Is ``field_path`` inside the synthetic-eval marker namespace?

    ``synth.*`` (stamped by soc_ai.eval.synth_render) is invisible to the
    model by policy — even under ``include_synth=True``, which admits the
    planted DOCUMENTS into a sample, never their answer-key label. These two
    tools need their own guard because they report field NAMES as values
    (``{"field": "synth.scenario_id", "example": "m1-…"}``), which the
    key-level strip at the tool boundary
    (:func:`soc_ai.agent.toolset.strip_synth_markers`) cannot see.
    """
    return field_path == "synth" or field_path.startswith("synth.")


def _flatten(obj: Any, prefix: str = "") -> Any:
    """Yield ``(dotted_path, scalar)`` leaves of a doc ``_source``.

    Handles both nested (``{"event": {"dataset": …}}``) and flat-dotted
    (``{"event.dataset": …}``) layouts — a flat-dotted key is already a path, a
    nested dict is descended. Lists contribute their first scalar (or the first
    dict element is flattened) so an example value is available without exploding.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            yield from _flatten(v, path)
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, dict):
                yield from _flatten(v, prefix)
                break
            if v not in (None, ""):
                yield (prefix, v)
                break
    elif prefix and obj not in (None, ""):
        yield (prefix, obj)


async def describe_dataset(
    dataset: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    sample_size: int = _SAMPLE_SIZE,
    include_synth: SynthScope = False,
) -> dict[str, Any]:
    """Sample recent docs of ``dataset`` and report its POPULATED fields.

    Returns ``{dataset, sampled, fields:[{field, coverage, example}]}`` sorted by
    how many of the sampled docs carry each field (most-common first). By default
    the sample excludes synthetic-eval docs (``synth.scenario_id``) so planted
    scenarios can't shape a dataset's described schema; an eval-mode caller opts
    in with ``include_synth=True``."""
    ds = str(dataset).strip()
    if not ds:
        return {"error": True, "reason": "empty dataset name"}
    query: dict[str, Any] = {"bool": {"filter": [dataset_name_filter(ds)]}}
    if synth_must_not := synth_scope_must_not(include_synth):
        query["bool"]["must_not"] = synth_must_not
    try:
        result = await elastic.search(
            settings.events_index_pattern,
            query,
            size=max(1, min(sample_size, 100)),
            sort=[{"@timestamp": {"order": "desc"}}],
        )
    except Exception as exc:
        _LOGGER.warning("describe_dataset(%s) failed: %s", ds, exc)
        return {"error": True, "type": type(exc).__name__, "message": str(exc)}

    if not result.hits:
        return {
            "dataset": ds,
            "sampled": 0,
            "fields": [],
            "note": (
                f"no documents named {ds} under event.dataset or data_stream.dataset "
                "— check the exact name against the auto-discovered grid inventory (a "
                "dataset that isn't listed there has no data on this grid)."
            ),
        }

    prevalence: Counter[str] = Counter()
    example: dict[str, Any] = {}
    for h in result.hits:
        src = h.get("_source", {}) or {}
        seen: set[str] = set()
        for path, val in _flatten(src):
            if _in_marker_namespace(path):
                # Never describable: a field report naming synth.scenario_id
                # (with a scenario id as its example) hands the model the
                # answer key of the eval it is running in.
                continue
            if path in seen:
                continue
            seen.add(path)
            prevalence[path] += 1
            example.setdefault(path, val)

    n = len(result.hits)
    ranked = sorted(prevalence.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_FIELDS]
    return {
        "dataset": ds,
        "sampled": n,
        "fields": [
            {"field": p, "coverage": f"{cnt}/{n}", "example": _clip(example[p])}
            for p, cnt in ranked
        ],
    }


async def field_values(
    field: str,
    *,
    elastic: ElasticClient,
    settings: Settings,
    dataset: str | None = None,
    size: int = 25,
    window_minutes: int = 1440,
    include_synth: SynthScope = False,
    provenance: Provenance = LIVE,
) -> dict[str, Any]:
    """Top values of ``field`` (a terms aggregation), optionally within ``dataset``.

    Returns ``{field, dataset, provenance, values:[{value, count}]}``
    newest-window, most-common first. Use this to learn what actually populates
    a field before querying on it.

    By default the aggregation excludes synthetic-eval docs (``synth.scenario_id``)
    so planted scenarios can't inflate a field's top values; an eval-mode caller
    opts in with ``include_synth=True``.

    It excludes imported and replayed documents by default too, for the same
    reason at a much larger scale: these counts are a distribution over a
    population, so "the top host.names on this grid" was answering with an
    imported corpus's machines ranked above the ones on the wire. That ranking
    is what the agent then treats as the terrain. ``provenance="any"`` restores
    the whole-disk view for a caller enumerating what an import contains.
    ``provenance`` is echoed in the result so a ranking is never read without
    knowing whose it is."""
    f = str(field).strip()
    if not f:
        return {"error": True, "reason": "empty field name"}
    if _in_marker_namespace(f) or f == "_index":
        # Active-probe guard: enumerating synth.scenario_id would list every
        # planted scenario id, and enumerating _index every `logs-synth-*`
        # index name. Answer exactly as a nonexistent field does — an empty
        # values list, no ES round-trip — so the refusal itself is not a tell.
        # Unconditional (not gated on include_synth): the same answer in prod
        # and eval mode carries no signal either way.
        #
        # "Exactly" is load-bearing and it is a maintenance hazard: every key
        # the answered path returns has to appear here too, or the shapes
        # diverge and the difference IS the tell. That is why the provenance
        # keys are echoed for a query that was never issued.
        return {
            "field": f,
            "dataset": dataset,
            "provenance": provenance,
            "counted_over": denominator_note(provenance),
            "values": [],
        }
    if not get_whitelist().is_allowed(f):
        # The same field policy the query language enforces. This tool exists
        # to "learn what actually populates a field BEFORE querying on it", so
        # enumerating the values of a field that can never be queried is a
        # disclosure with no legitimate follow-up — and it made the two
        # surfaces disagree: OQL would refuse `winlog.event_data.Foo` while
        # this returned its top values.
        #
        # A NAMED refusal, not the silent empty list above. The whitelist is
        # static and public, so unlike the marker guard there is no oracle to
        # protect, and the reject is the only channel the agent has to
        # self-correct — the same reasoning as OQL's did-you-mean tail, which
        # is reused here verbatim.
        return {
            "error": True,
            "field": f,
            "reason": (f"field {f!r} is not queryable on this deployment{_field_suggestion(f)}"),
        }
    filters: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}}]
    if dataset:
        filters.append(dataset_name_filter(str(dataset).strip()))
    query: dict[str, Any] = {"bool": {"filter": filters}}
    # Both scopes into one list, since a bool has only one ``must_not`` and
    # assigning twice would silently drop whichever went first.
    if must_not := [*synth_scope_must_not(include_synth), *provenance_must_not(provenance)]:
        query["bool"]["must_not"] = must_not
    aggs: dict[str, Any] = {"vals": {"terms": {"field": f, "size": max(1, min(size, 100))}}}
    try:
        result = await elastic.search(settings.events_index_pattern, query, size=0, aggs=aggs)
    except Exception as exc:
        _LOGGER.warning("field_values(%s) failed: %s", f, exc)
        return {
            "error": True,
            "type": type(exc).__name__,
            "message": str(exc),
            "hint": (
                "the field may be text (not aggregatable) or unknown — run "
                "t_describe_dataset first to see the exact populated field names."
            ),
        }
    buckets = ((result.aggregations or {}).get("vals") or {}).get("buckets") or []
    return {
        "field": f,
        "dataset": dataset,
        # Beside the field and the dataset, which is where a reader already
        # looks to find out what this ranking is a ranking OF.
        "provenance": provenance,
        "counted_over": denominator_note(provenance),
        "values": [{"value": b.get("key"), "count": b.get("doc_count")} for b in buckets],
    }


__all__ = ["describe_dataset", "field_values"]
