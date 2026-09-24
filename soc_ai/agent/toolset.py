"""Single source of truth for the read-tool surface of all three agents.

Every ``t_*`` read tool exposed to the investigator, chat, and hunt agents is
defined ONCE here and registered per-role via :func:`register_read_tools`.
All roles get the investigator's richer wrapping: per-investigation dedup
(:func:`_dedup_result`), result clamping to the tool budget
(:func:`_clamp_tool_result`), and structured error dicts (:func:`_tool_error`).

Role deltas are encoded as module constants (:data:`INVESTIGATOR_ONLY`,
:data:`NOT_ON_HUNT`) plus one def-time default: hunt's query tools default to
a 1440-minute window (a hunt looks across time), investigator/chat to 60 —
and the two windowed query tools carry a role-appropriate window docstring
(the hunt variant does not claim to center on an alert's ``@timestamp``).
A caller with no alert to anchor to (the dashboard's general chat) overrides
that default via ``register_read_tools(..., default_window=)``, which moves the
window AND its docstring sentence together; it never changes which tools a role
gets, so the golden per-role surfaces stay pinned.

Settings-gated tools (the online quartet, PCAP, web search, crawl) are gated
at REGISTRATION time in every role, so a disabled tool never appears in the
LLM's schema and can't burn tool-budget slots on "skipped" results.

``propose_verdict`` is NOT here — it stays in
:mod:`soc_ai.agent.chat_agent`, which owns its ``proposal_sink``.

:data:`PHASE_D_TOOLS` is the single source for the Phase-D targeted-dispatch
surface. ``TargetedGap``'s ``tool_name`` Literal in
:mod:`soc_ai.triage_models` is a drift-tested copy of it (a Literal can't be
built from a runtime tuple without losing the static schema);
``tests/test_toolset.py`` pins the two together.
"""

from __future__ import annotations

import contextlib
import functools
import json
import logging
import weakref
from collections.abc import Callable
from datetime import UTC, datetime
from time import monotonic
from typing import TYPE_CHECKING, Any, Literal, cast

from elastic_transport import TransportError
from elasticsearch import ApiError
from pydantic_ai import Agent

from soc_ai.dossier.resolve import (
    ResolvedDossier,
    ResolvedField,
    resolve_dossier_from_settings,
    unknown_dossier,
)
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.hunting.execute import run_spec
from soc_ai.oracle.identifiers import effective_internal_identifiers
from soc_ai.oracle.sanitize import OracleUnknownLabelError
from soc_ai.store import host_dossier as dossier_store
from soc_ai.tools.analytics import beacon_profile, dcerpc_histogram, dns_entropy_scan, first_seen
from soc_ai.tools.crawl_page import crawl_page
from soc_ai.tools.cvedb import cve_lookup
from soc_ai.tools.decode_payload import decode_payload
from soc_ai.tools.discover import describe_dataset, field_values
from soc_ai.tools.enrichment import enrich_domain, enrich_hash, enrich_ip
from soc_ai.tools.get_event_raw import get_event_raw
from soc_ai.tools.get_pcap import get_pcap_facts
from soc_ai.tools.get_playbooks import get_playbooks
from soc_ai.tools.get_rule_content import get_rule_content
from soc_ai.tools.greynoise import greynoise
from soc_ai.tools.host_summary import host_summary
from soc_ai.tools.lookup_runbook import lookup_runbook
from soc_ai.tools.origin_chain import origin_chain
from soc_ai.tools.prevalence import prevalence
from soc_ai.tools.query_cases import query_cases
from soc_ai.tools.query_detections import query_detections
from soc_ai.tools.query_events import WindowMode, query_events_oql
from soc_ai.tools.query_zeek import query_zeek_logs
from soc_ai.tools.rule_prevalence import rule_prevalence
from soc_ai.tools.rule_tuning import suggest_rule_tuning
from soc_ai.tools.shodan_host import shodan_host
from soc_ai.tools.shodan_internetdb import shodan_internetdb
from soc_ai.tools.web_search import web_search

if TYPE_CHECKING:
    from soc_ai.agent.orchestrator import InvestigationContext

_LOGGER = logging.getLogger(__name__)

Role = Literal["investigator", "chat", "hunt", "oracle"]

# Tools only the investigator gets (verdict-adjacent context the chat/hunt
# surfaces never used).
INVESTIGATOR_ONLY = frozenset({"t_query_detections", "t_get_playbooks", "t_lookup_runbook"})

# The Oracle's read-only adjudication surface (2026-08-27 design §2): a POSITIVE
# allowlist, not a CORE-minus-deltas subset — the ``oracle`` role registers
# EXACTLY these 15 closures and nothing else, whatever the settings gates say.
# Deliberately absent, each an on-the-record decision, not an omission:
#   - anything that writes (register_read_tools has none by construction);
#   - the online quartet + t_web_search / t_crawl_page (a SECOND egress the
#     residue gate does not sit in front of — the Oracle recommends a reputation
#     check, the analyst runs it);
#   - t_get_pcap (SSH to the sensor driven by cloud-model args; the local loop's
#     pcap facts already reach the Oracle via loop_tool_results);
#   - t_query_cases / t_query_detections / t_get_playbooks / t_lookup_runbook /
#     t_suggest_rule_tuning (org context, little adjudication value per byte);
#   - the hunt analytics quartet (network-wide; adjudication pivots on one alert).
# The golden per-role surface test (tests/test_tool_surface.py) is the lock: a
# tool cannot join or leave this set without a reviewed diff.
ORACLE_TOOLS = frozenset(
    {
        "t_query_events_oql",
        "t_query_zeek_logs",
        "t_describe_dataset",
        "t_field_values",
        "t_get_event_raw",
        "t_get_rule_content",
        "t_decode_payload",
        "t_host_summary",
        "t_origin_chain",
        "t_host_dossier",
        "t_prevalence",
        "t_rule_prevalence",
        "t_enrich_ip",
        "t_enrich_domain",
        "t_enrich_hash",
    }
)

# Tools every role EXCEPT hunt gets (tuning nominations are per-rule triage
# work, not network-wide hunting).
NOT_ON_HUNT = frozenset({"t_suggest_rule_tuning"})

# Tools ONLY the hunt gets: network-wide behavioral analytics sweeps. Triage
# pivots around ONE alert and already has alert-anchored equivalents
# (t_prevalence, pcap-derived cadence); registering four sweep schemas on
# every role widens each agent's tool prompt for nothing.
HUNT_ONLY = frozenset(
    {
        "t_beacon_profile",
        "t_dns_entropy_scan",
        "t_dcerpc_histogram",
        "t_first_seen",
        # Runs one catalog analytic over a window. Hunt-only for the same
        # reason as the four above: it asks a network-wide question, and
        # triage pivots around one alert.
        "t_run_analytic",
    }
)

# The Phase-D targeted-dispatch surface: the tools a synth round-1
# ``gap_for_investigator`` may name. Single source of truth — TargetedGap's
# ``tool_name`` Literal is a drift-tested copy (tests/test_toolset.py).
PHASE_D_TOOLS: tuple[str, ...] = (
    "t_query_zeek_logs",
    "t_query_events_oql",
    "t_enrich_ip",
    "t_enrich_domain",
    "t_enrich_hash",
    "t_get_playbooks",
    "t_lookup_runbook",
    "t_query_cases",
    "t_query_detections",
    "t_get_rule_content",
    "t_get_event_raw",
    "t_get_pcap",
    "t_web_search",
    "t_crawl_page",
)

# Tools whose answers come FROM the Security Onion grid — every one of them
# reads the SO Elasticsearch cluster (cases, rules and playbooks live in ES
# indices too), except ``t_get_pcap``, which reads the sensor over SSH. A
# SUCCESSFUL call to one of these is proof the run could actually see the
# network; a failed one is a hole in what the run could see.
#
# Consumed by :func:`soc_ai.api.hunt_runner._grid_tool_outcomes`, whose whole
# job is the arithmetic "did this hunt look at the network at all?" — so an
# unclassified new tool would silently stop counting as a look.
# ``tests/test_hunt_outage_report.py`` pins the two sets as a partition of the
# registered surface, forcing that decision at review time.
GRID_BACKED_TOOLS = frozenset(
    {
        "t_query_events_oql",
        "t_query_zeek_logs",
        "t_describe_dataset",
        "t_field_values",
        "t_query_cases",
        "t_query_detections",
        "t_get_event_raw",
        "t_get_rule_content",
        "t_host_summary",
        "t_origin_chain",
        "t_prevalence",
        "t_rule_prevalence",
        "t_suggest_rule_tuning",
        "t_get_playbooks",
        "t_get_pcap",
        "t_beacon_profile",
        "t_dns_entropy_scan",
        "t_dcerpc_histogram",
        "t_first_seen",
        "t_run_analytic",
    }
)

# The complement: tools answered by local computation, the local store, or the
# public internet. None of them says anything about whether the grid is
# readable — a working web search on a blind sensor is still a blind sensor.
OFF_GRID_TOOLS = frozenset(
    {
        "t_decode_payload",
        "t_enrich_ip",
        "t_enrich_domain",
        "t_enrich_hash",
        "t_host_dossier",
        "t_lookup_runbook",
        "t_shodan_internetdb",
        "t_shodan_host",
        "t_greynoise",
        "t_cve_lookup",
        "t_web_search",
        "t_crawl_page",
    }
)

# The ``reason`` stamped on a tool error the grid caused, rather than the
# model's own query. Same vocabulary the HTTP layer uses for the 503
# (``routes_alerts._GRID_UNAVAILABLE``), so one word means one thing across
# the product.
GRID_UNAVAILABLE_REASON = "grid_unavailable"

# What the MODEL is told when the grid fails. Deliberately not the exception
# text: a raw "Connection error caused by ConnectionRefusedError(111)" is a
# string a weak model paraphrases into "no results", and an all-clear written
# off a failed read is the worst output this product has. State the epistemics
# instead — the answer is unknown, and unknown is not empty.
_GRID_UNAVAILABLE_MESSAGE = (
    "The Security Onion grid did not answer this query — it is unreachable, timing "
    "out, or returned only partial results. This result is UNKNOWN, not empty: it is "
    "NOT evidence that nothing matched, and it rules nothing out. Do not describe the "
    "network as quiet, clean or clear on the strength of it. Do not re-send this exact "
    "call — an identical repeat short-circuits as a duplicate instead of re-querying; "
    "to re-check, vary the query, once. If the grid keeps failing, say plainly that "
    "the grid was unavailable and the question could not be answered."
)


def _is_grid_unavailable(exc: BaseException) -> bool:
    """Is ``exc`` the grid failing, rather than the model's query being wrong?

    ``elastic_transport.TransportError`` covers connection refused, connect and
    read timeouts, TLS failures — and, once the partial-shard detection lands,
    ``GridPartialResultsError``, which subclasses it precisely so guards like
    this one pick it up with no edit.

    ``ApiError`` is NOT a ``TransportError``, so it is checked separately and
    split by status the way ``routes_alerts._es_api_error_http`` splits it: a
    4xx is a bad query the model can fix and keeps its own message, anything
    else is the grid. The exceptions to that split are 408 (request timeout)
    and 429 (search queue full / circuit breaker tripped) — 4xx codes that
    describe a struggling grid, not a malformed query.
    """
    if isinstance(exc, ApiError):
        status = getattr(getattr(exc, "meta", None), "status", None)
        if status is None:
            return True
        return status in (408, 429) or status >= 500
    return isinstance(exc, TransportError)


# Cap on the JSON-serialized size of any single tool return. Both Nemotron 3
# models on the lab grid are deployed with 64K context; a single t_query_*
# call returning 100 zeek/event docs can be 20-40K tokens, and a few of those
# back-to-back blow the window. With this clamp every tool returns at most
# ~3K tokens; the model can call the same tool multiple times if it needs
# more breadth, but no single round-trip can dominate the budget.
_TOOL_RESULT_BUDGET_BYTES = 12 * 1024

# ---------------------------------------------------------------------------
# The model boundary for the synthetic-eval marker.
#
# Every planted eval document carries ``synth.scenario_id`` /
# ``synth.scenario_version`` (stamped by soc_ai.eval.synth_render) and lives
# in a ``logs-synth-*`` index. Those markers are load-bearing IN
# Elasticsearch — the prod exclusion filters (``must_not exists
# synth.scenario_id``), the ingest containment check, the ``synth-clean``
# teardown and the journey scorer's document joins all key on them — but to
# the model under test they are an answer key: the 2026-08-26 batch showed
# the model reading it verbatim off a tool result ("This is a synthetic
# scenario m1-cobalt-strike-beacon"). A model that knows it is being graded
# on a planted attack is not the model the eval measures.
#
# So the marker is stripped HERE, at the single point every model-bound tool
# result passes (the interactive wrappers and Phase-D dispatch both funnel
# through :func:`_clamp_tool_result` / :func:`_tool_error`), and nowhere
# deeper: harness code reading through ElasticClient or the tool functions
# still sees everything. UNCONDITIONALLY — there is no legitimate reason for
# the model to see the marker, so no flag can turn the strip off.
#
# The strip covers the MARKER ONLY. Scenarios author their discriminating
# evidence in the same namespace (h1's ``synth.kerberos_profile``, b3's
# ``synth.smb_files_signer``, b5/h6's ``synth.wmi_class``/``wmi_method``,
# e4's ``synth.auth_attempt_profile``, and the ``synth.beacon_profile`` /
# ``synth.dns_profile`` candidate paths in so_client.fields) — that is
# exactly what the model is graded on reasoning over. An earlier revision
# stripped the whole ``synth.*`` namespace and thereby amputated every
# scenario's evidence; two 26-run batches (2026-08-27) measured the strip,
# not the model. Only ``synth.scenario_id`` / ``synth.scenario_version`` —
# the two keys synth_render stamps — are the answer key; everything else
# under the namespace is testimony.
_SYNTH_MARKER_SUBKEYS = frozenset({"scenario_id", "scenario_version"})
_SYNTH_MARKER_KEYS = frozenset({f"synth.{sub}" for sub in _SYNTH_MARKER_SUBKEYS})
_SYNTH_NAMESPACE_KEY = "synth"
# ``_index`` goes with the marker: synth indices are named ``logs-synth-*``,
# so the physical index name alone says "planted". Dropped from every hit —
# dataset identity lives in ``event.dataset`` / ``event.module``; no prompt or
# model-side consumer reads ``_index``. The query side is closed too: the OQL
# whitelist forbids ``_index`` outright (oql_fields.json), because selecting
# by index name (``_index:logs-synth*``) would be a planted-document oracle
# even with every hit stripped. This hit-level drop stays as defense in depth.
_MODEL_HIDDEN_KEYS = frozenset({"_index"})


def _is_model_hidden_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    return key in _MODEL_HIDDEN_KEYS or key in _SYNTH_MARKER_KEYS


def _strip_marker(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            if _is_model_hidden_key(k):
                continue
            if k == _SYNTH_NAMESPACE_KEY:
                # The mapped-object spelling: the marker rides as
                # ``{"synth": {"scenario_id": …}}``. Remove the marker
                # subkeys, keep any evidence subkeys — and if nothing but
                # the marker was there, drop the ``synth`` key entirely (a
                # leftover ``"synth": {}`` would itself say "planted"). A
                # non-dict value under a bare ``synth`` key has no authored
                # meaning (scenarios only ever write ``synth.<name>``), so
                # it is dropped rather than risking a marker-shaped value.
                if isinstance(v, dict):
                    nested = {
                        sk: _strip_marker(sv)
                        for sk, sv in v.items()
                        if sk not in _SYNTH_MARKER_SUBKEYS
                    }
                    if nested:
                        out[k] = nested
                continue
            out[k] = _strip_marker(v)
        return out
    if isinstance(obj, list):
        return [_strip_marker(v) for v in obj]
    if isinstance(obj, str) and "logs-synth" in obj:
        # Index names surface as VALUES too — chiefly ES error messages that
        # name the failing index (``groupby _index`` is refused at OQL
        # validation now, but this value rewrite stays as defense in depth).
        # Rewrite the synth spelling out (``.ds-logs-synth-zeek-conn-…`` →
        # ``.ds-logs-zeek-conn-…``); ``logs-synth-*`` is a reserved namespace
        # (synth_ingest._check_synth_prefix), so the substring cannot occur in
        # honest telemetry values.
        return obj.replace("logs-synth-", "logs-").replace("logs-synth", "logs")
    return obj


def strip_synth_markers[T](value: T) -> T:
    """Strip the synthetic-eval MARKER — and only the marker — from a
    model-bound payload.

    Removed, recursively at every level:

    - the marker keys stamped by :mod:`soc_ai.eval.synth_render`:
      ``synth.scenario_id`` and ``synth.scenario_version`` (dotted
      spelling), and ``scenario_id`` / ``scenario_version`` inside a nested
      ``synth`` object (the mapped-object spelling; the ``synth`` key
      itself goes if nothing else was under it);
    - ``_index`` from every hit (synth indices spell ``logs-synth-*``);
    - the ``logs-synth`` index-namespace spelling inside string values
      (aggregation bucket keys, ES error text).

    Deliberately PRESERVED: every other ``synth.*`` field. Scenarios plant
    their discriminating evidence there (``synth.kerberos_profile``,
    ``synth.smb_files_signer``, ``synth.wmi_class``, …) — stripping it
    makes the eval measure the strip instead of the model, which is exactly
    what happened before this function was narrowed. All non-``synth``
    evidence fields are untouched. See the block comment above for why the
    strip exists and why it is unconditional.
    """
    return cast("T", _strip_marker(value))


def _tool_error(exc: BaseException) -> dict[str, Any]:
    """Render a tool-side exception into a structured result the model can read.

    Tool exceptions used to propagate up and kill the agent run. Now we catch
    them at every tool boundary and surface them as a `{error, type, message}`
    dict — PydanticAI sends that back to the model as a tool result, and the
    model can either retry with corrected args or move on.

    A GRID failure (:func:`_is_grid_unavailable`) is rendered differently from a
    bad query, because the two call for opposite responses. A malformed query
    keeps its own message — that text is how the model fixes it. A grid failure
    is stamped ``reason: "grid_unavailable"`` and carries a fixed message about
    what the result MEANS (unknown, not empty); the exception string is dropped
    rather than passed through, so there is no raw transport text for a weak
    model to paraphrase into "no results found". The ``reason`` is also what the
    hunt runner counts deterministically — see
    :func:`soc_ai.api.hunt_runner._grid_tool_outcomes` — so a hunt that could
    not read the grid cannot land as a clean sweep whatever the model writes.
    """
    if _is_grid_unavailable(exc):
        return {
            "error": True,
            "type": type(exc).__name__,
            "reason": GRID_UNAVAILABLE_REASON,
            "message": _GRID_UNAVAILABLE_MESSAGE,
        }
    payload: dict[str, Any] = {
        "error": True,
        "type": type(exc).__name__,
        "message": str(exc),
    }
    fragment = getattr(exc, "fragment", None)
    if fragment:
        payload["fragment"] = fragment
    # A 4xx keeps its exception text (that text is how the model fixes its
    # query) — but ES error messages name indices, so the synth-index spelling
    # must not ride out on the error path either.
    return strip_synth_markers(payload)


def _clamp_tool_result[T](value: T) -> T:
    """Truncate ``value`` to the per-tool budget, signaling truncation.

    For list returns: slice items off the end until the JSON serialization
    fits.
    For dict returns whose top-level keys include a list under
    ``hits`` / ``items`` / ``rows`` (the ES-style envelope used by
    :class:`EsSearchResult` and similar): bisect that list to fit the
    budget while preserving the wrapper fields (``total``, ``took_ms``,
    ``aggregations``), and tag the dict with ``__truncated__`` /
    ``__total_items__`` / ``__shown_items__``.
    For other dicts: tag with ``__truncated__`` only — we don't slice
    nested fields (that's domain-specific).
    For primitive / string returns: clip to budget chars and signal.
    """
    # The synthetic-eval marker never crosses the model boundary. Applied here
    # because every model-bound tool result — the interactive wrappers AND the
    # Phase-D targeted dispatch — funnels through this clamp.
    value = strip_synth_markers(value)
    try:
        encoded = json.dumps(value)
    except (TypeError, ValueError):
        # Unencodable result — return a stringified form below the budget.
        # Truncation envelopes are always `dict[str, Any]`; cast back to the
        # caller's declared shape (all tool returns accept a dict envelope).
        return cast(
            "T",
            {
                "truncated": True,
                "shown": 0,
                "total": 0,
                "items": [],
                "note": "unencodable result",
            },
        )

    if len(encoded) <= _TOOL_RESULT_BUDGET_BYTES:
        return value

    if isinstance(value, list):
        # Bisect down to a count whose JSON fits.
        lo, hi = 0, len(value)
        # Quick monotone scan: try halves.
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(json.dumps(value[:mid])) <= _TOOL_RESULT_BUDGET_BYTES:
                lo = mid
            else:
                hi = mid - 1
        return cast(
            "T",
            {
                "truncated": True,
                "shown": lo,
                "total": len(value),
                "items": value[:lo],
            },
        )
    if isinstance(value, dict):
        # ES-envelope shape: dict with one big list under hits/items/rows.
        # Slice that list so the wrapper (total / took_ms / aggregations)
        # survives but the bulk shrinks under budget. Bisect against the
        # *full* result shape (wrapper + sliced list + metadata flags) so
        # the final encoded size respects the budget.
        for list_key in ("hits", "items", "rows"):
            inner = value.get(list_key)
            if isinstance(inner, list) and inner:

                def _candidate(
                    n: int,
                    key: str = list_key,
                    items: list[Any] = inner,
                ) -> dict[str, Any]:
                    return {
                        **value,
                        key: items[:n],
                        "__truncated__": True,
                        "__total_items__": len(items),
                        "__shown_items__": n,
                        "__total_bytes__": len(encoded),
                    }

                lo, hi = 0, len(inner)
                while lo < hi:
                    mid = (lo + hi + 1) // 2
                    if len(json.dumps(_candidate(mid))) <= _TOOL_RESULT_BUDGET_BYTES:
                        lo = mid
                    else:
                        hi = mid - 1
                return cast("T", _candidate(lo))
        # Aggregation envelope: a `groupby` response carries its big list under
        # aggregations.<name>.buckets (one terms agg per groupby field, nested).
        # Bisect the OUTERMOST buckets list — dropping an outer bucket drops its
        # nested sub-buckets too, so total size shrinks monotonically — until a
        # multi-field groupby fits the budget. Without this, groupby responses
        # fall through to the flag-only fallback below, which relabels the same
        # oversized payload __truncated__ without shrinking it.
        aggs = value.get("aggregations")
        if isinstance(aggs, dict):
            for agg_name, agg_body in aggs.items():
                if (
                    isinstance(agg_body, dict)
                    and isinstance(agg_body.get("buckets"), list)
                    and agg_body["buckets"]
                ):
                    buckets = agg_body["buckets"]

                    def _agg_candidate(
                        n: int,
                        name: str = agg_name,
                        body: dict[str, Any] = agg_body,
                        bkts: list[Any] = buckets,
                    ) -> dict[str, Any]:
                        return {
                            **value,
                            "aggregations": {**aggs, name: {**body, "buckets": bkts[:n]}},
                            "__truncated__": True,
                            "__total_buckets__": len(bkts),
                            "__shown_buckets__": n,
                            "__total_bytes__": len(encoded),
                        }

                    lo, hi = 0, len(buckets)
                    while lo < hi:
                        mid = (lo + hi + 1) // 2
                        if len(json.dumps(_agg_candidate(mid))) <= _TOOL_RESULT_BUDGET_BYTES:
                            lo = mid
                        else:
                            hi = mid - 1
                    return cast("T", _agg_candidate(lo))
        # No recognized list field — fall back to flag-only.
        return cast("T", {**value, "__truncated__": True, "__total_bytes__": len(encoded)})
    # Strings / numbers — stringify + clip.
    text = str(value)
    return cast("T", text[: _TOOL_RESULT_BUDGET_BYTES - 100] + " …[truncated]")


# Framing carried on every t_host_dossier result. The dossier is inferred from
# telemetry a host can influence (the name it announces over DHCP, the banner it
# serves), so the payload says what it is every time rather than relying on the
# tool description having been read.
_DOSSIER_NOTE = (
    "System-inferred asset context. An operator value outranks an inferred one; "
    "an inferred value is only as good as its strength, and an unknown field "
    "carries the reason it is unknown."
)
_DOSSIER_ABSENT_NOTE = (
    "Absence is an answer, not evidence: the network sweep has no record of this "
    "address (external, or never observed). It is not a finding that the host is "
    "benign — check whether the address is internal at all before reading into it."
)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _host_dossier_field_payload(field: ResolvedField) -> dict[str, Any]:
    """One resolved field, with everything a reader needs to weigh it.

    Optional keys are omitted rather than sent as nulls: twelve fields x a dozen
    always-present nulls is a third of the tool-result budget spent saying
    nothing. The inference lane is reported ALONGSIDE a winning operator value —
    an override suppresses effect, never observation, and a reader deciding
    whether the override is still right needs to see what it is suppressing.
    """
    payload: dict[str, Any] = {
        "value": field.value,
        "source": field.source,
        "confidence": round(field.confidence, 2),
        "strength": field.strength,
    }
    if field.value_json is not None:
        payload["value_json"] = field.value_json
    if field.reason is not None:
        payload["unknown_reason"] = field.reason
    if field.evidence:
        payload["evidence"] = field.evidence
    if field.observed_at is not None:
        payload["last_confirmed"] = _iso(field.observed_at)
    if field.last_run_at is not None:
        payload["last_evaluated"] = _iso(field.last_run_at)
    if field.overridden:
        payload["operator_actor"] = field.operator_actor
        payload["operator_note"] = field.operator_note
        payload["operator_set_at"] = _iso(field.operator_set_at)
        if field.inferred_value is not None or field.inferred_value_json is not None:
            payload["inferred_value"] = field.inferred_value
            payload["inferred_source"] = field.inferred_source
            payload["inferred_confidence"] = field.inferred_confidence
    if field.conflict is not None:
        payload["conflict"] = {
            "kind": field.conflict.kind,
            "since": _iso(field.conflict.first_seen_at),
            "disagreeing_builds": field.conflict.observations,
        }
    return payload


def _host_dossier_payload(entry: ResolvedDossier, *, asked_as: str) -> dict[str, Any]:
    """Render a resolved dossier for the model, absence included.

    The answer echoes ``asked_as`` — the spelling the CALLER used — not
    ``entry.ip``, which for a stored host is the key the store canonicalised
    through ``ipaddress`` (``FD00:0:0:0:0:0:0:1`` is filed as ``fd00::1``). The
    egress guard allocates a redaction label per literal string, so returning the
    canonical spelling earns the host a second label and the model sees two
    machines where the investigation has one. Same host, same name, every time.
    """
    if not entry.found:
        return {
            "ip": asked_as,
            "found": False,
            "reason": "no dossier — the network sweep has no record of this address",
            "note": _DOSSIER_ABSENT_NOTE,
        }
    payload: dict[str, Any] = {
        "ip": asked_as,
        "found": True,
        "fields": {
            name: _host_dossier_field_payload(field) for name, field in entry.fields.items()
        },
        "first_seen": _iso(entry.first_seen),
        "last_seen": _iso(entry.last_seen),
        "last_built_at": _iso(entry.last_built_at),
        "event_count": entry.event_count,
        "note": _DOSSIER_NOTE,
    }
    if entry.identity_rebound_at is not None:
        payload["identity_rebound_at"] = _iso(entry.identity_rebound_at)
        payload["identity_rebound_warning"] = (
            "A different machine appears to hold this address now; an operator "
            "value set before that date may describe a host that has moved on."
        )
    if entry.build_error:
        payload["build_error"] = entry.build_error
    return payload


_DUPLICATE_HINT = (
    "Same args were already called this investigation. Result hasn't changed; "
    "calling again wastes the budget. Pivot to a different field, time window, "
    "or tool — or proceed to emitting the transcript."
)


def _dedup_result(
    ctx: InvestigationContext, tool_name: str, args: dict[str, Any]
) -> dict[str, Any] | None:
    """Return a structured duplicate-call payload if this exact call was seen.

    None when not a duplicate. The tool wrappers consult this and
    short-circuit on duplicates rather than running the underlying tool
    again.
    """
    if not ctx.dedup.is_duplicate(tool_name, args):
        return None
    return {
        "duplicate_call": True,
        "tool_name": tool_name,
        "args": args,
        "hint": _DUPLICATE_HINT,
    }


async def _egress_tool_idents(
    ctx: InvestigationContext,
) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None]:
    """Resolve the effective (suffixes, hosts) for the online egress tool guards
    (web_search / crawl_page), ONCE per run, cached on ``ctx``.

    The orchestrator pre-seeds ``ctx.effective_internal_*`` from the set it already
    resolved for EgressGuard (no second DB round-trip); other entrypoints leave
    them unset and we resolve them lazily here on first tool use. ``(None, None)``
    ⇒ no DB session (CLI / eval / tests) — the tool guard then falls back to the
    raw ``settings`` tuples, so behaviour is unchanged for a db-less path.
    """
    if ctx._egress_idents_resolved:
        return ctx.effective_internal_suffixes, ctx.effective_internal_hosts
    maker = ctx.db_sessionmaker
    if maker is not None:
        try:
            async with maker() as db:
                effective = await effective_internal_identifiers(db, ctx.settings)
            ctx.effective_internal_suffixes = effective.suffixes
            ctx.effective_internal_hosts = effective.hosts
        except Exception:  # never block a tool on a DB hiccup — fall back to settings
            _LOGGER.warning(
                "toolset: failed to resolve effective internal identifiers for the "
                "egress tool guard; falling back to settings",
                exc_info=True,
            )
    ctx._egress_idents_resolved = True
    return ctx.effective_internal_suffixes, ctx.effective_internal_hosts


def _progress[F: Callable[..., Any]](ctx: InvestigationContext, fn: F) -> F:
    """Report each tool START through ``ctx.on_tool_call``, if a caller set one.

    Single choke point: every tool registration routes through here, so live
    progress needs no per-tool wiring. Fire-and-forget by contract — a progress
    sink that raises must never turn into a failed tool call, so the callback is
    fully guarded. Absent a callback the closure is returned unchanged, keeping
    the default path free of an extra frame.
    """
    sink = ctx.on_tool_call
    if sink is None:
        return fn

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            sink(getattr(fn, "__name__", "tool"))
        except Exception:  # progress is cosmetic; never break the tool
            _LOGGER.debug("tool progress sink failed", exc_info=True)
        return await fn(*args, **kwargs)

    return cast("F", wrapper)


def _guarded[F: Callable[..., Any]](ctx: InvestigationContext, fn: F) -> F:
    """When the ctx carries an EgressGuard, wrap a tool closure so the model
    only ever sees sanitized results, and label-bearing arguments it sends
    back (e.g. query strings citing HOST_01) are restored to real values
    before execution. functools.wraps preserves the signature pydantic-ai
    reads for the tool schema."""
    guard = ctx.egress_guard
    if guard is None:
        # No redaction configured — hand pydantic-ai the original closure so
        # the default path stays byte-identical (no wrapper in the stack).
        return fn

    @functools.wraps(fn)
    async def _wrapped(*args: Any, **kwargs: Any) -> Any:
        # INBOUND (model → tool): the model reasons over opaque labels, so any
        # label it echoes into an argument must become the real value before
        # the tool queries Elasticsearch / enrichment sources.
        try:
            real_args = tuple(guard.desanitize_obj(a) for a in args)
            real_kwargs = {k: guard.desanitize_obj(v) for k, v in kwargs.items()}
        except OracleUnknownLabelError as exc:
            # The Oracle tool guard refuses a hallucinated label (design §3): the
            # model named an identifier no case allocated. Do NOT run the query
            # against a literal placeholder — a silent empty result reads as "no
            # data" and drives a confidently wrong adjudication. Hand back a
            # structured, self-correcting tool error instead of executing. The
            # analyst EgressGuard never raises this, so this arm is inert on the
            # analyst path.
            return exc.tool_error()
        result = await fn(*real_args, **real_kwargs)
        # OUTBOUND (tool → model): the result is the egress payload — redact it
        # with the run's shared mapping so labels stay stable across tools. Thread
        # the tool NAME so the Oracle guard can re-key a known envelope's
        # identifiers onto classifiable ECS paths before the field-aware harvest
        # (finding oracle-tool-result-leak); the analyst guard ignores it.
        return guard.sanitize_obj(result, tool_name=getattr(fn, "__name__", None))

    return cast("F", _wrapped)


def _in_role(tool_name: str, role: Role) -> bool:
    """Whether ``tool_name`` belongs to ``role``'s surface (settings gates aside)."""
    # The oracle role is a POSITIVE allowlist — it is the sole arbiter of its own
    # surface, so it short-circuits the delta logic. A tool absent from
    # ORACLE_TOOLS is out-of-role even when a settings gate would otherwise
    # register it (this is what keeps the online / pcap tools off the Oracle).
    if role == "oracle":
        return tool_name in ORACLE_TOOLS
    if tool_name in INVESTIGATOR_ONLY and role != "investigator":
        return False
    if tool_name in HUNT_ONLY and role != "hunt":
        return False
    return not (tool_name in NOT_ON_HUNT and role == "hunt")


# Per-role docstrings for the two time-windowed query tools. Only the window
# sentence differs between roles — the investigator/chat window is centered on
# the alert's @timestamp, but a hunt has NO alert to center on (its anchor is
# "now", looking back across time). Everything else in the doc is identical.
_OQL_DOC_BASE = (
    "Run a validated OQL query against the SO events index.\n\n"
    "OQL works across ALL datasets, including RFC1918 addresses; narrow "
    "with `AND event.dataset:...`. "
)
_OQL_ALERT_WINDOW_NOTE = (
    "The window is anchored on the alert's `@timestamp` automatically "
    "(without this, tools default to now-1h, return empty for batch "
    "alerts, and burn a wasted round). `time_range_minutes` is the total "
    "window width. `window_mode` decides WHICH QUESTION you are asking:\n"
    "- `around` (default): centred, half before the alert and half after "
    "(60 = ±30 min, 1440 = ±12h). Use it for 'what happened around this "
    "alert' — the setup before it and what followed after.\n"
    "- `before`: the whole width sits BEHIND the alert (1440 = the 24 hours "
    "up to it). Use it for EVERY how-often / how-many / is-this-normal "
    "question. Asking one of those with `around` answers it over half the "
    "span you named, so a day's prevalence comes back as half a day's.\n"
    "The result carries a `window` block naming the span it counted over. "
    "Read it before quoting any number as 'in the last N hours'."
)
_OQL_HUNT_WINDOW_NOTE = (
    "The default window is WIDE (1440 = 24h) because a hunt looks across "
    "time rather than pivoting around one alert. `time_range_minutes` is "
    "the total window width; pass a larger value for a broader sweep or a "
    "smaller one to focus on a burst. A hunt has no alert to anchor on, so "
    "the window is counted back from now and `window_mode` changes nothing."
)
_ZEEK_DOC_BASE = "Pivot into Zeek logs by network.community_id (conn/dns/http/ssl/files/ssh).\n\n"
_ZEEK_ALERT_WINDOW_NOTE = (
    "Window centered on the alert's `@timestamp`; `time_range_minutes` "
    "is the total width (60 = ±30 min). Widen only if you need "
    "longer-tail correlation."
)
_ZEEK_HUNT_WINDOW_NOTE = (
    "The default window is wide (1440 = 24h) because a hunt looks across "
    "time; `time_range_minutes` is the total width. Narrow it when you "
    "only need the immediate surroundings of one flow."
)
# Third flavor, for a caller that overrode the window (see `default_window`):
# it is not anchored to an alert, so the alert-centered note above would be a
# false description of the tool's own behaviour — with no `time_anchor` the
# window is `[now - width, now]`, not `[anchor ± width/2]` — and its "60 = ±30
# min" example would sit next to a 1440 default. `{minutes}` is filled with the
# override at registration time.
_OQL_WIDE_WINDOW_NOTE = (
    "The default window is WIDE ({minutes} minutes) and is counted BACK FROM "
    "NOW: this agent is not anchored to a single alert. `time_range_minutes` "
    "is the total window width; pass a larger value to look further back or a "
    "smaller one to focus on a burst. With no alert to anchor on, "
    "`window_mode` changes nothing."
)
_ZEEK_WIDE_WINDOW_NOTE = (
    "The default window is wide ({minutes} minutes), counted back from now — "
    "there is no alert to center on. `time_range_minutes` is the total width; "
    "narrow it when you only need the immediate surroundings of one flow."
)


_ANALYTIC_WINDOW_MAX_DAYS = 90
_ANALYTIC_CANDIDATES_MAX = 25


async def run_analytic_for_agent(*, ctx: Any, analytic_id: str, window_days: int) -> dict[str, Any]:
    """Run one live or shadow analytic over the last ``window_days`` days.

    Returns the candidates with live provenance. A candidate's sample ids are
    document ids the agent can cite. A retired or unknown analytic returns the
    list of analytics it can run instead, so the model corrects itself rather
    than reading an empty result as "nothing is there".
    """
    days = max(1, min(int(window_days or 1), _ANALYTIC_WINDOW_MAX_DAYS))
    maker = getattr(ctx, "db_sessionmaker", None)
    if maker is not None:
        async with maker() as db:
            cat = await effective_catalog(db)
    else:
        # CLI / eval callers with no store: the catalog is the shipped tier.
        cat = await effective_catalog(None)
    spec = cat.specs.get(analytic_id)
    if spec is None:
        listed = getattr(cat, "listed", cat.specs)
        return {
            "error": "unknown_analytic",
            "hint": "This analytic is not live or in shadow. Choose one from the list.",
            "available": [f"{sid}: {s.title}" for sid, s in listed.items()][:40],
        }
    tier, status = cat.status_of(analytic_id)
    run = await run_spec(
        spec,
        elastic=ctx.elastic,
        settings=ctx.settings,
        since=f"now-{days}d",
        until="now",
        include_synth=getattr(ctx, "include_synth", False),
    )
    if run.error is not None:
        # An errored run is reported as an error, never as an empty candidate
        # list. The two must not look the same to the model.
        return {
            "analytic": analytic_id,
            "status": status,
            "error": "could_not_run",
            "detail": run.error,
            "provenance": "live",
        }
    return {
        "analytic": analytic_id,
        "title": spec.title,
        "tier": tier,
        "status": status,
        "window_days": days,
        "blind": run.blind,
        "precondition_docs": run.precondition_docs,
        "matched_docs": run.matched_docs,
        "candidates": [
            {
                "entity": c.scope_key,
                "entity_kind": c.scope_kind,
                "doc_count": c.doc_count,
                "sample_ids": list(c.sample_ids),
                "anchor_id": c.anchor_id,
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
            }
            for c in run.candidates[:_ANALYTIC_CANDIDATES_MAX]
        ],
        "provenance": "live",
    }


# ---------------------------------------------------------------------------
# A tool that cannot answer is not offered.
#
# Every registered tool is a turn the model can spend: 18 s on production, 30 s
# on the range, plus the whole prompt re-sent. The 2026-09-19 reasoning-turn
# audit counted 75 of 233 production tool calls returning nothing, and
# `t_get_playbooks` returning `[]` on all 24 of its calls, because the
# deployment links no playbook to any rule.
#
# The probe is one `size=1` search per grid per hour, cached against the
# ElasticClient itself (one client is one grid; a weak key lets a retired client
# and its answer go together). It FAILS OPEN in both directions: an unprobed run
# and a grid that did not answer both keep the tool, because "the grid did not
# say" is not "there are none". `require_complete=True` makes a partial read
# raise rather than read as empty.
# ---------------------------------------------------------------------------

_PLAYBOOK_PRESENCE_TTL_S = 3600.0
_playbook_presence: weakref.WeakKeyDictionary[Any, tuple[float, bool]] = weakref.WeakKeyDictionary()


def reset_playbook_presence_cache() -> None:
    """Forget every probed answer. For tests and for a settings hot-apply."""
    _playbook_presence.clear()


def _playbooks_known_absent(ctx: InvestigationContext) -> bool:
    cached = _playbook_presence.get(ctx.elastic)
    if cached is None:
        return False
    deadline, present = cached
    return monotonic() <= deadline and not present


async def prime_playbook_presence(ctx: InvestigationContext) -> bool:
    """Does this deployment hold any playbook at all? Probe once per hour.

    Returns True unless the grid answered and answered empty. Call it before
    the investigator agent is built: :func:`register_read_tools` reads the
    cached answer, and an unprimed cache registers ``t_get_playbooks`` exactly
    as before.
    """
    cached = _playbook_presence.get(ctx.elastic)
    if cached is not None and monotonic() <= cached[0]:
        return cached[1]
    try:
        result = await ctx.elastic.search(
            ctx.settings.playbooks_index_pattern,
            {"match_all": {}},
            size=1,
            require_complete=True,
        )
        present = bool(getattr(result, "hits", None))
    except Exception as e:
        _LOGGER.info("playbook probe did not answer (%s); the tool stays registered", e)
        return True
    # A client that holds no weak reference simply goes uncached.
    with contextlib.suppress(TypeError):
        _playbook_presence[ctx.elastic] = (monotonic() + _PLAYBOOK_PRESENCE_TTL_S, present)
    return present


def prefetched_community_ids(enriched: Any) -> set[str]:
    """The community_ids the prefetch holds RECORDS for.

    ``t_query_zeek_logs`` answers "prefetch already has this" from this set, so
    membership has to mean the record is in the user message. It used to include
    the alert's own community_id whether or not the pivot returned anything:
    01M2WG06 asked for a flow the prefetch had missed and was told to read a
    block that was empty. Only an id carried by a prefetched event joins the set.
    """
    events = getattr(enriched, "community_id_events", None) or []
    return {
        cid
        for cid in (getattr(event, "network_community_id", None) for event in events)
        if isinstance(cid, str) and cid
    }


def register_read_tools(  # noqa: PLR0915 - tool registrations are inherently long
    agent: Agent[Any, Any],
    ctx: InvestigationContext,
    *,
    role: Role,
    default_window: int | None = None,
) -> None:
    """Register the full read-tool surface for ``role`` on ``agent``.

    Closures capture ``ctx`` so the LLM-facing tool signatures stay
    semantic-only (no auth/elastic/etc. parameters in the schema). Settings-
    gated tools are skipped entirely when their flag is off, so the model
    never sees a tool it can't use.

    ``default_window`` overrides the role-derived implicit window (minutes) on
    the two time-windowed query tools. Pass it only when the run has NO alert
    to anchor to — the dashboard's general chat asks network-wide, over-a-day
    questions, and the chat role's implicit 60 minutes would silently answer a
    different question than the one asked. It moves the window default and the
    window sentence in the two tool descriptions; it does not add, remove or
    rename a tool, so the per-role surface pinned by tests/test_tool_surface.py
    is unaffected.
    """
    s = ctx.settings
    # Defaults bind at def time, so the LLM-visible schema advertises the
    # role's real window: a hunt looks across time (24h), the investigator
    # and chat pivot around one alert (±30 min).
    window = default_window if default_window is not None else (1440 if role == "hunt" else 60)

    def _register[F: Callable[..., Any]](fn: F) -> F:
        # The role's surface is the arbiter: a closure whose name is out-of-role
        # for THIS role is handed back unregistered (the model never sees it).
        # This is what trims the unconditionally-defined reads (t_query_cases)
        # and every settings-gated online / pcap tool off the read-only "oracle"
        # surface — enforced, not left to omission, and pinned by
        # tests/test_tool_surface.py. For the three original roles _in_role
        # returns True for every tool they already registered, so their surfaces
        # are byte-identical.
        if not _in_role(getattr(fn, "__name__", ""), role):
            return fn
        # EVERY registered tool routes through the egress guard so a cloud
        # analyst / oracle model never sees a raw tool result (and its
        # label-bearing arguments are restored before execution). With no guard
        # on the ctx (the default), _guarded returns fn unchanged and this is
        # exactly agent.tool_plain(fn). The cast mirrors _guarded's: tool_plain
        # hands back the (wrapped) function it was given.
        return cast("F", agent.tool_plain(_progress(ctx, _guarded(ctx, fn))))

    async def t_query_events_oql(
        query: str,
        time_range_minutes: int = window,
        max_results: int = 25,
        window_mode: WindowMode = "around",
    ) -> dict[str, Any]:
        # Hard ceiling BEFORE the dedup key — defends the 64K window, and
        # makes max_results=100 and max_results=25 dedup to the same call.
        max_results = min(max_results, 25)
        if dup := _dedup_result(
            ctx,
            "t_query_events_oql",
            {
                "query": query,
                "time_range_minutes": time_range_minutes,
                "max_results": max_results,
                # In the dedup key: the same OQL over two different spans is
                # two different questions, and answering the second from the
                # first's cache is how a prevalence count inherits a pivot's
                # half-window.
                "window_mode": window_mode,
            },
        ):
            return dup
        try:
            result = await query_events_oql(
                query,
                elastic=ctx.elastic,
                settings=ctx.settings,
                time_range_minutes=time_range_minutes,
                max_results=max_results,
                time_anchor=ctx.default_time_anchor,
                window_mode=window_mode,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_query_events_oql failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result.model_dump(mode="json"))

    # The docstring is the LLM-visible tool description, so assign the
    # role-appropriate window note BEFORE registering (pydantic_ai captures
    # the doc at registration time).
    if default_window is not None:
        oql_window_note = _OQL_WIDE_WINDOW_NOTE.format(minutes=window)
    elif role == "hunt":
        oql_window_note = _OQL_HUNT_WINDOW_NOTE
    else:
        oql_window_note = _OQL_ALERT_WINDOW_NOTE
    t_query_events_oql.__doc__ = _OQL_DOC_BASE + oql_window_note
    _register(t_query_events_oql)

    async def t_query_zeek_logs(
        community_id: str,
        log_types: list[str] | None = None,
        time_range_minutes: int = window,
        max_results: int = 25,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        # Read-prefetch-first rule: answer from the prefetch only when the
        # prefetch HOLDS a record for this community_id. The set is built by
        # prefetched_community_ids() from the events themselves, so membership
        # means the block above is not empty. A pivot that ran and returned
        # nothing leaves the id out, and the query below runs (audit R6).
        if community_id in ctx.prefetched_community_ids:
            return {
                "prefetch_already_has_this": True,
                "community_id": community_id,
                "hint": (
                    "The orchestrator already pre-fetched events sharing this "
                    "community_id; they're in the `community_id_events` block "
                    "of the alert context above. Read those instead of "
                    "re-querying. If you need a wider time window or different "
                    "log_types, call this tool with a different community_id."
                ),
            }
        # Clamp before the dedup key so 100 and 25 dedup to the same call.
        max_results = min(max_results, 25)
        if dup := _dedup_result(
            ctx,
            "t_query_zeek_logs",
            {
                "community_id": community_id,
                "log_types": log_types,
                "time_range_minutes": time_range_minutes,
                "max_results": max_results,
            },
        ):
            return dup
        try:
            zeek_rows = await query_zeek_logs(
                community_id,
                elastic=ctx.elastic,
                settings=ctx.settings,
                log_types=log_types,
                time_range_minutes=time_range_minutes,
                max_results=max_results,
                time_anchor=ctx.default_time_anchor,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_query_zeek_logs failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(zeek_rows)

    if default_window is not None:
        zeek_window_note = _ZEEK_WIDE_WINDOW_NOTE.format(minutes=window)
    elif role == "hunt":
        zeek_window_note = _ZEEK_HUNT_WINDOW_NOTE
    else:
        zeek_window_note = _ZEEK_ALERT_WINDOW_NOTE
    t_query_zeek_logs.__doc__ = _ZEEK_DOC_BASE + zeek_window_note
    _register(t_query_zeek_logs)

    if role == "hunt":

        async def t_run_analytic(analytic_id: str, window_days: int = 7) -> dict[str, Any]:
            """Run one analytic from the catalog over the last window_days days.

            Use it to test a hypothesis with a query the product already
            trusts. The result lists the entities that matched and the
            document ids you can cite. Ask for the list with an unknown id.
            """
            window_days = max(1, min(int(window_days), _ANALYTIC_WINDOW_MAX_DAYS))
            if dup := _dedup_result(
                ctx,
                "t_run_analytic",
                {"analytic_id": analytic_id, "window_days": window_days},
            ):
                return dup
            try:
                out = await run_analytic_for_agent(
                    ctx=ctx, analytic_id=analytic_id, window_days=window_days
                )
            except Exception as e:  # a tool never raises into the loop
                _LOGGER.warning("t_run_analytic failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(out)

        _register(t_run_analytic)

    @_register
    async def t_describe_dataset(dataset: str) -> dict[str, Any]:
        """Discover the fields POPULATED on a dataset (e.g. `zeek.ssh`, `endpoint`,
        `windows.security`) by sampling its recent docs. Returns each field + an
        example value + coverage. Use this to learn a dataset's schema before
        querying it — works for network AND host datasets."""
        if dup := _dedup_result(ctx, "t_describe_dataset", {"dataset": dataset}):
            return dup
        try:
            result = await describe_dataset(
                dataset,
                elastic=ctx.elastic,
                settings=ctx.settings,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_describe_dataset failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_field_values(
        field: str, dataset: str | None = None, size: int = 25
    ) -> dict[str, Any]:
        """List the top VALUES a field takes (a terms aggregation), optionally within
        one dataset. E.g. what `rule.name`s fire, what `host.name`s exist, what
        `event.dataset`s (and `data_stream.dataset`s) are present. Use it to see what
        actually populates a field. A `dataset` name matches under either field."""
        # Clamp before the dedup key so over-asked sizes dedup to the same call.
        size = min(size, 50)
        if dup := _dedup_result(
            ctx, "t_field_values", {"field": field, "dataset": dataset, "size": size}
        ):
            return dup
        try:
            result = await field_values(
                field,
                elastic=ctx.elastic,
                settings=ctx.settings,
                dataset=dataset,
                size=size,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_field_values failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_query_cases(
        query: str,
        status: str | None = None,
        max_results: int = 25,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search SOC cases by free-text + optional status filter."""
        max_results = min(max_results, 10)
        if dup := _dedup_result(
            ctx,
            "t_query_cases",
            {"query": query, "status": status, "max_results": max_results},
        ):
            return dup
        try:
            cases = await query_cases(
                query,
                elastic=ctx.elastic,
                settings=ctx.settings,
                status=status,
                max_results=max_results,
            )
        except Exception as e:
            _LOGGER.warning("t_query_cases failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result([c.model_dump(mode="json") for c in cases])

    if _in_role("t_query_detections", role):

        @_register
        async def t_query_detections(
            query: str, max_results: int = 25
        ) -> list[dict[str, Any]] | dict[str, Any]:
            """Search SOC detection rules by free-text."""
            max_results = min(max_results, 10)
            if dup := _dedup_result(
                ctx, "t_query_detections", {"query": query, "max_results": max_results}
            ):
                return dup
            try:
                dets = await query_detections(
                    query,
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    max_results=max_results,
                )
            except Exception as e:
                _LOGGER.warning("t_query_detections failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result([d.model_dump(mode="json") for d in dets])

    # Skipped for the investigation loop when the alert message already carries
    # this rule's body (soc_ai.agent.prompts.rule_body_in_alert sets the flag).
    # Production spent 11 turns fetching text the prompt was already holding.
    # Every other role keeps the tool: only the loop has the alert in its prompt.
    if not (role == "investigator" and getattr(ctx, "rule_body_in_prompt", False)):

        @_register
        async def t_get_rule_content(rule_id: str) -> dict[str, Any]:
            """Fetch the FULL RULE TEXT of a detection — what the signature actually
            matches (content strings, ports, dsize, PCRE), not just its name. Pass
            the alert's `rule.uuid` (Suricata SID) or the exact `rule.name`. Read
            this BEFORE trusting a rule label: a loose generic content match is weak
            corroboration; a tight family-specific token match is strong."""
            if dup := _dedup_result(ctx, "t_get_rule_content", {"rule_id": rule_id}):
                return dup
            try:
                rule = await get_rule_content(rule_id, elastic=ctx.elastic, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_get_rule_content failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(rule)

    @_register
    async def t_decode_payload(data: str, encoding: str = "auto") -> dict[str, Any]:
        """Decode payload bytes ALREADY in evidence (Suricata `payload` base64,
        a hex dump, or `payload_printable` text) into concrete facts: printable
        strings, embedded domains/URLs/IPs, entropy, and protocol hints (DNS
        qname / HTTP host / TLS SNI). Local compute, no egress — works even
        after the PCAP ring buffer has rotated. Use it instead of eyeballing
        raw bytes; cite the decoded strings/indicators it returns. Fetch the
        raw bytes first with t_get_event_raw if needed."""
        # No dedup: pure local compute (no remote cost), so a repeat costs nothing.
        try:
            facts = await decode_payload(data, encoding=encoding)
        except Exception as e:
            _LOGGER.warning("t_decode_payload failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(facts.model_dump(mode="json"))

    @_register
    async def t_get_event_raw(event_id: str) -> dict[str, Any]:
        """Fetch a single event's full raw _source by ES _id. Use when the
        prefetched context or a pivot summary omitted a field you need (e.g.
        the raw base64 `payload` bytes, all zeek fields, full suricata
        metadata). For host characterisation prefer t_query_events_oql; use
        this for single-event deep-dives."""
        if dup := _dedup_result(ctx, "t_get_event_raw", {"event_id": event_id}):
            return dup
        try:
            raw = await get_event_raw(
                event_id,
                elastic=ctx.elastic,
                settings=ctx.settings,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_get_event_raw failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(raw)

    @_register
    async def t_host_summary(ip: str, lookback_hours: int = 24) -> dict[str, Any]:
        """Identify an internal host by IP from Security Onion data.

        Returns its hostname, a device/OS guess PARSED from the host's HTTP
        User-Agents (so an iPhone reads as an iPhone, not a Mac), a
        server-vs-workstation role guess, first/last seen, and its top
        peers/ports/DNS — each with the raw evidence string behind it.

        Call this whenever the verdict depends on WHAT a host is (device type,
        OS, role) rather than inferring identity from a rule label or a UA seen
        in passing. The window is centered on the alert's `@timestamp`.
        """
        if dup := _dedup_result(
            ctx, "t_host_summary", {"ip": ip, "lookback_hours": lookback_hours}
        ):
            return dup
        try:
            result = await host_summary(
                ip,
                elastic=ctx.elastic,
                settings=ctx.settings,
                lookback_hours=lookback_hours,
                time_anchor=ctx.default_time_anchor,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_host_summary failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_origin_chain(ip: str, lookback_minutes: int = 30) -> dict[str, Any]:
        """Who was DRIVING this internal host? Inbound remote-access sessions.

        Returns the SSH/RDP/WinRM/SMB sessions that arrived AT `ip` in the
        window before the activity, time-ordered, with `closest_preceding` —
        the session nearest before the alert, i.e. the most likely driver.

        Call this whenever an INTERNAL host appears to be the source of hostile
        or unexpected behavior, BEFORE attributing that behavior to it. A host
        with an inbound session is a waypoint, not an origin: the real actor is
        upstream, and you should pivot again on that source. An empty result is
        equally decisive — it means the host acted on its own, which is a
        different and usually more serious finding.

        `t_host_summary` cannot answer this: its `top_peers` is a volume-ranked
        aggregation, so a brief session is invisible beside routine traffic, and
        it carries no ordering.
        """
        if dup := _dedup_result(
            ctx, "t_origin_chain", {"ip": ip, "lookback_minutes": lookback_minutes}
        ):
            return dup
        try:
            result = await origin_chain(
                ip,
                elastic=ctx.elastic,
                settings=ctx.settings,
                lookback_minutes=lookback_minutes,
                time_anchor=ctx.default_time_anchor,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_origin_chain failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_host_dossier(ip: str) -> dict[str, Any]:
        """What IS this host, and is this behaviour normal FOR IT?

        The durable asset record the network sweep keeps for an internal IP:
        hostname, OS, inferred role (hypervisor / domain controller / security
        appliance / server / workstation / network device / IoT), the services
        it offers, its behavioural baseline (what it normally does, and what it
        has never done), and any operator-set criticality and site policy.

        Call it whenever the verdict turns on what the host IS rather than on
        what happened — "outbound SSH from a hypervisor whose policy forbids
        interactive SSH" is a different finding from "outbound SSH from a
        workstation". `t_host_summary` recomputes a 24h snapshot; this is the
        stored record, built over a much wider window, and its role inference
        is far stronger.

        Reading the result: `source: "operator"` means a human asserted the
        value and it OUTRANKS any inference — `inferred_value` beside it is
        what the builder still believes underneath. An inferred value carries a
        `strength`; weak is a lead, not a fact. A null `value` carries an
        `unknown_reason`, and none of the three means "no": `no_signal` = a
        build looked and found nothing in its window (with no `last_evaluated`,
        nothing has looked yet), `low_confidence` = too weak to assert, `stale`
        = nobody has re-confirmed it lately. `found: false` means the sweep has
        no record of this address at all — not that it is benign.
        """
        if dup := _dedup_result(ctx, "t_host_dossier", {"ip": ip}):
            return dup
        # Answered rather than unregistered when off: a tool that vanishes
        # leaves the model guessing why it cannot ask, and this is a local DB
        # read, so there is no egress to gate.
        if getattr(ctx.settings, "dossier_enabled", False) is not True:
            return {"available": False, "reason": "host dossier disabled"}
        maker = ctx.db_sessionmaker
        if maker is None:
            return {
                "available": False,
                "reason": "host dossier unavailable — this run has no database",
            }
        try:
            async with maker() as db:
                stored = await dossier_store.get_dossier(db, ip)
            if stored is None:
                entry = unknown_dossier(ip)
            else:
                host, rows = stored
                entry = resolve_dossier_from_settings(
                    host, rows, now=datetime.now(UTC), settings=ctx.settings
                )
        except Exception as e:
            _LOGGER.warning("t_host_dossier failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(_host_dossier_payload(entry, asked_as=ip))

    @_register
    async def t_prevalence(
        ip: str,
        peer_ip: str | None = None,
        domain: str | None = None,
        lookback_days: int = 90,
    ) -> dict[str, Any]:
        """Has THIS host talked to THIS dest/domain before, and how rare is it?

        Local first-seen / novelty oracle, learned from the events index only
        (no external calls). Pass `peer_ip` to scope to a host pair, `domain`
        to scope to a domain (DNS/SNI/HTTP), or neither to summarize the host's
        overall activity. Returns first/last seen, distinct-day count, an
        `is_novel` flag and a `rarity` label ('first-seen' | 'rare' | 'common').
        """
        if dup := _dedup_result(
            ctx,
            "t_prevalence",
            {
                "ip": ip,
                "peer_ip": peer_ip,
                "domain": domain,
                "lookback_days": lookback_days,
            },
        ):
            return dup
        try:
            result = await prevalence(
                ip,
                elastic=ctx.elastic,
                settings=ctx.settings,
                peer_ip=peer_ip,
                domain=domain,
                lookback_days=lookback_days,
                time_anchor=ctx.default_time_anchor,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_prevalence failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_rule_prevalence(rule_name: str, lookback_days: int = 30) -> dict[str, Any]:
        """Base-rate / burstiness of a detection rule across the network.

        Covers every dataset that carries detections (Suricata alerts, Sigma
        alerts, Zeek notices, endpoint alerts) and says in `searched_datasets`
        which ones it looked in, so a `first-seen` answer can be read for what it
        is. Answers whether this rule is NOISY (fires constantly across many
        hosts — so its next firing is likely benign HERE and is weak evidence),
        RARE / FIRST-SEEN (a firing is notable), or a BURST (every fire packed
        into one short episode — that is not a background rate, and if the alert
        you are triaging sits inside the burst, the burst may BE the incident).
        Call this whenever the verdict leans on a rule label: before trusting the
        signature name, check whether that signature is a constant-firing
        nuisance on this grid. Read `summary` as the headline, not any single
        number. Returns
        total_fires, distinct src/dest hosts and source ports, first/last seen,
        the observed span, active_days, is_burst, a noisiness bucket,
        fires_per_day measured over the span actually observed — which is null
        for a burst, because a per-day rate is meaningless for one episode. It
        also returns fires_per_active_day, measured over the days the rule fired
        on, which is the larger number when the rule was quiet inside its span.
        READ-ONLY and zero-egress.
        """
        if dup := _dedup_result(
            ctx, "t_rule_prevalence", {"rule_name": rule_name, "lookback_days": lookback_days}
        ):
            return dup
        try:
            result = await rule_prevalence(
                rule_name,
                elastic=ctx.elastic,
                settings=ctx.settings,
                lookback_days=lookback_days,
                include_synth=ctx.include_synth,
            )
        except Exception as e:
            _LOGGER.warning("t_rule_prevalence failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    # Hunt-only behavioral analytics sweeps (1.3 slice 2, soc_ai.tools.analytics):
    # network-wide measurements a hunt runs when it has no seed alert to pivot
    # around. Gated the same way t_suggest_rule_tuning is below (_in_role wraps
    # the definition+registration; the golden surface test in
    # tests/test_tool_surface.py is the arbiter of whether the gate matches
    # HUNT_ONLY).
    if _in_role("t_beacon_profile", role):

        @_register
        async def t_beacon_profile(
            window_minutes: int = window,
            src: str | None = None,
            dst: str | None = None,
            min_events: int = 8,
            include_internal: bool = False,
        ) -> dict[str, Any]:
            """Measure inter-arrival cadence (coefficient of variation) per
            src→dst pair over `zeek.conn`, network-wide — a low CV is the
            measured signature of a periodic beacon. Use this to CONFIRM a
            beacon before claiming one; the measured cadence is the evidence,
            not any alert title. Narrow to a known pair with `src`/`dst`, or
            leave both unset to sweep the grid.
            """
            if dup := _dedup_result(
                ctx,
                "t_beacon_profile",
                {
                    "window_minutes": window_minutes,
                    "src": src,
                    "dst": dst,
                    "min_events": min_events,
                    "include_internal": include_internal,
                },
            ):
                return dup
            try:
                result = await beacon_profile(
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    window_minutes=window_minutes,
                    src=src,
                    dst=dst,
                    min_events=min_events,
                    include_internal=include_internal,
                    # The full SynthScope passes through: prod (False) sees no
                    # plants, the hunt-journey eval (True) sees them all, and a
                    # scenario-scoped batch run sees its OWN plants only —
                    # never a sibling scenario's (analytics._hunt_must_not).
                    include_synth=ctx.include_synth,
                )
            except Exception as e:
                _LOGGER.warning("t_beacon_profile failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if _in_role("t_dns_entropy_scan", role):

        @_register
        async def t_dns_entropy_scan(
            window_minutes: int = window,
            parent_domain: str | None = None,
            min_queries: int = 50,
        ) -> dict[str, Any]:
            """Measure per-parent-domain qname entropy and volume over
            `zeek.dns`, network-wide — high mean subdomain entropy together
            with volume is the measured signature of a DGA or DNS-tunnel
            channel. Use this to CONFIRM a DGA/tunnel before claiming one;
            the measured entropy is the evidence, not an eyeballed "these
            subdomains look random" read of raw rows.
            """
            if dup := _dedup_result(
                ctx,
                "t_dns_entropy_scan",
                {
                    "window_minutes": window_minutes,
                    "parent_domain": parent_domain,
                    "min_queries": min_queries,
                },
            ):
                return dup
            try:
                result = await dns_entropy_scan(
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    window_minutes=window_minutes,
                    parent_domain=parent_domain,
                    min_queries=min_queries,
                    # Full SynthScope passthrough (see t_beacon_profile).
                    include_synth=ctx.include_synth,
                )
            except Exception as e:
                _LOGGER.warning("t_dns_entropy_scan failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if _in_role("t_dcerpc_histogram", role):

        @_register
        async def t_dcerpc_histogram(
            window_minutes: int = window,
            rare_max: int = 5,
        ) -> dict[str, Any]:
            """Histogram DCE-RPC operations over `zeek.dce_rpc`, network-wide,
            and flag individually-dangerous ops (Zerologon-style
            `NetrServerAuthenticate*`, DCSync's `DRSGetNCChanges`/
            `DsGetNCChanges`, remote service creation) plus ops rare against a
            busy baseline. Use this to CONFIRM a domain-controller attack
            pattern before claiming one; a flagged or rare operation is the
            evidence, not the alert that pointed here.
            """
            if dup := _dedup_result(
                ctx,
                "t_dcerpc_histogram",
                {"window_minutes": window_minutes, "rare_max": rare_max},
            ):
                return dup
            try:
                result = await dcerpc_histogram(
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    window_minutes=window_minutes,
                    rare_max=rare_max,
                    # Full SynthScope passthrough (see t_beacon_profile).
                    include_synth=ctx.include_synth,
                )
            except Exception as e:
                _LOGGER.warning("t_dcerpc_histogram failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if _in_role("t_first_seen", role):

        @_register
        async def t_first_seen(
            recent_minutes: int = window,
            baseline_days: int = 30,
            dataset: str = "zeek.conn",
        ) -> dict[str, Any]:
            """Diff destinations seen in a recent window against a trailing
            baseline (ending exactly where the recent window begins) to
            surface novel EXTERNAL destinations — no prior sighting in the
            baseline is the measured signature of a new external service or
            C2 channel. Use this to CONFIRM a destination is genuinely new
            before claiming it, rather than assuming novelty from one alert.
            """
            if dup := _dedup_result(
                ctx,
                "t_first_seen",
                {
                    "recent_minutes": recent_minutes,
                    "baseline_days": baseline_days,
                    "dataset": dataset,
                },
            ):
                return dup
            try:
                result = await first_seen(
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    recent_minutes=recent_minutes,
                    baseline_days=baseline_days,
                    dataset=dataset,
                    # Full SynthScope passthrough (see t_beacon_profile).
                    include_synth=ctx.include_synth,
                )
            except Exception as e:
                _LOGGER.warning("t_first_seen failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if _in_role("t_suggest_rule_tuning", role):

        @_register
        async def t_suggest_rule_tuning(rule_name: str, lookback_days: int = 7) -> dict[str, Any]:
            """Detection tuning: is this Suricata rule a noisy FP nuisance to mute?

            Answers the operator's tuning question — is this rule mostly-benign noise
            that should be muted / re-tuned, or is it pulling its weight? Returns the
            rule's alert volume, its acknowledged-vs-escalated disposition trend (the
            ES proxy for false-positive vs true-positive), and a mute/monitor/none
            recommendation with a one-line reason. Cite it when a verdict leans on a
            rule label and you want to know whether that signature keeps coming back
            benign here. READ-ONLY — it nominates, it does not change Security Onion.
            """
            if dup := _dedup_result(
                ctx,
                "t_suggest_rule_tuning",
                {"rule_name": rule_name, "lookback_days": lookback_days},
            ):
                return dup
            try:
                result = await suggest_rule_tuning(
                    rule_name,
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    lookback_days=lookback_days,
                )
            except Exception as e:
                _LOGGER.warning("t_suggest_rule_tuning failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    # The four ONLINE-enrichment tools (Shodan InternetDB / GreyNoise / full
    # Shodan / CVEDB) are only registered when the master egress toggle
    # (`allow_online_enrichment`) is on. Registering them while the toggle is
    # off just invites the model to burn tool-budget slots on "skipped (online
    # enrichment off)" results (observed 4x GreyNoise + 4x Shodan in one run).
    # InternetDB + CVEDB are keyless but still egress, so they sit behind the
    # same toggle. The underlying tool functions keep their own runtime gates.
    if s.allow_online_enrichment:

        @_register
        async def t_shodan_internetdb(ip: str) -> dict[str, Any]:
            """External-asset view of a PUBLIC IP from Shodan InternetDB (free, no key).

            Returns the open ports, software CPEs, reverse-DNS hostnames, tags
            (cdn/cloud/self-signed) and known CVEs Shodan last observed on that
            address. Call it to corroborate WHAT an unknown EXTERNAL IP is — exposed
            service, hosting class, known vulns — when the verdict turns on the
            nature of the public peer.

            ONLINE tool: private/reserved IPs are skipped (never sent off-box).
            Pass a PUBLIC IP only.
            """
            if dup := _dedup_result(ctx, "t_shodan_internetdb", {"ip": ip}):
                return dup
            try:
                result = await shodan_internetdb(ip, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_shodan_internetdb failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

        @_register
        async def t_greynoise(ip: str) -> dict[str, Any]:
            """Look up an EXTERNAL IP in GreyNoise (Community API): is it scanning the
            internet indiscriminately (noise), a known-benign service (riot), and its
            classification.

            Strong fit when the alert involves an unfamiliar external IP and you need
            to know whether it is a mass-scanner / benign crawler (de-escalate) vs. a
            targeted actor. EXTERNAL IPs only — internal/non-routable IPs are skipped.
            ONLINE tool: returns a clean not_configured dict (no I/O) when the API
            key is unset.
            """
            if dup := _dedup_result(ctx, "t_greynoise", {"ip": ip}):
                return dup
            try:
                result = await greynoise(ip, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_greynoise failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

        @_register
        async def t_shodan_host(ip: str) -> dict[str, Any]:
            """FULL Shodan host lookup for a PUBLIC IP (needs the operator's API key).

            Deeper than t_shodan_internetdb: adds the network owner (org/isp/asn),
            geolocation, guessed OS, and the per-service BANNERS Shodan collected
            (product + version + module per open port), plus the union of known
            CVEs. Reach for it when the verdict turns on WHAT an unknown external
            host is actually running and WHO owns it.

            ONLINE tool: returns a clean not_configured dict (no I/O) when
            SHODAN_API_KEY is unset; private/internal IPs are skipped (never
            sent off-box). PUBLIC IPs only.
            """
            if dup := _dedup_result(ctx, "t_shodan_host", {"ip": ip}):
                return dup
            try:
                result = await shodan_host(ip, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_shodan_host failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

        @_register
        async def t_cve_lookup(cve_id: str) -> dict[str, Any]:
            """Score a named CVE via Shodan CVEDB (free, no key): CVSS base score,
            EPSS exploit-probability + ranking, CISA KEV (actively-exploited) flag,
            a short summary and references.

            Call it whenever an alert, rule, or a Shodan host result names a CVE and
            the verdict depends on HOW SEVERE / HOW LIKELY-EXPLOITED it is — KEV or a
            high EPSS argues for escalation; an old, low-EPSS, non-KEV CVE does not.

            ONLINE tool (no API key needed).
            """
            if dup := _dedup_result(ctx, "t_cve_lookup", {"cve_id": cve_id}):
                return dup
            try:
                result = await cve_lookup(cve_id, settings=ctx.settings)
            except Exception as e:
                _LOGGER.warning("t_cve_lookup failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if s.pcap_enabled:

        @_register
        async def t_get_pcap(
            src_ip: str | None = None,
            dst_ip: str | None = None,
            src_port: int | None = None,
            dst_port: int | None = None,
            window_minutes: int = 2,
        ) -> dict[str, Any]:
            """Fetch + decode the REAL packets for a flow from the Security Onion sensor.

            Returns five-tuples, SNI, DNS qnames, HTTP hosts, connection stats and
            beacon inter-arrival timing decoded from the raw pcap ring buffer.

            BIDIRECTIONAL — the BPF matches packets in BOTH directions between the two
            IPs, so pass BOTH src_ip and dst_ip from the alert; do not pre-decide
            which is client and which is server.

            HEAVIER than Elastic queries — call ONLY when packet-level or
            protocol-level confirmation is the deciding evidence:
            - C2 beacon / exfil (confirm SNI / DNS / periodic inter-arrival)
            - ET MALWARE / TROJAN / EXPLOIT / HUNTING rules (validate the payload)
            - Kerberoast / psexec lateral movement (confirm the wire protocol)

            DO NOT call for clean-internal informational alerts
            (signature_severity=Informational, internal-internal, alert_action=allowed)
            where the prefetch is already sufficient.
            """
            if dup := _dedup_result(
                ctx,
                "t_get_pcap",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "window_minutes": window_minutes,
                },
            ):
                return dup
            try:
                result = await get_pcap_facts(
                    settings=ctx.settings,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    window_minutes=window_minutes,
                    alert_ts=ctx.default_time_anchor,
                )
            except Exception as e:
                _LOGGER.warning("t_get_pcap failed: %s", e)
                return _tool_error(e)
            if hasattr(result, "model_dump"):
                return _clamp_tool_result(result.model_dump(mode="json"))
            return _clamp_tool_result(result)

    if s.web_search_enabled:

        @_register
        async def t_web_search(query: str) -> dict[str, Any]:
            """Search the web (SearXNG) to research an EXTERNAL indicator.

            Use this to settle "is this domain/IP/host legit or malicious?" with
            outside evidence instead of guessing — e.g. domain reputation, what a
            service is, known-abuse reports. Strong fit for ET INFO/abused-hosting,
            unknown-ASN, newly-seen-domain, and "looks informational but unverified"
            alerts where the operator needs corroboration to agree with the verdict.

            Pass a focused query string, e.g. ``"pushplanet.azurewebsites.net"`` or
            ``"<domain> malware OR phishing"``.

            PRIVACY: the query goes to public search engines via SearXNG. Search
            ONLY external indicators (domains, public IPs, file hashes, URLs). NEVER
            put an internal IP/hostname/username in the query — a query containing an
            internal IP is refused.
            """
            if dup := _dedup_result(ctx, "t_web_search", {"query": query}):
                return dup
            try:
                sfx, hosts = await _egress_tool_idents(ctx)
                result = await web_search(
                    query, settings=ctx.settings, suffixes=sfx, extra_hosts=hosts
                )
            except Exception as e:
                _LOGGER.warning("t_web_search failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    if s.crawl4ai_enabled:

        @_register
        async def t_crawl_page(url: str) -> dict[str, Any]:
            """Deep-read the full content of an EXTERNAL web page (via crawl4ai).

            Use this AFTER web_search to read a promising result in full when the
            snippet isn't enough — e.g. open the reputation/abuse/threat-intel page
            for a domain or IP and read what it actually says. Returns the page's
            readable content (markdown), title, and a truncation flag.

            Pass a single external URL (typically one returned by web_search).

            SAFETY: crawl4ai fetches the URL server-side, so EXTERNAL URLs ONLY —
            an internal IP/host/localhost is refused (don't be steered into reading
            an internal service).
            """
            if dup := _dedup_result(ctx, "t_crawl_page", {"url": url}):
                return dup
            try:
                sfx, hosts = await _egress_tool_idents(ctx)
                result = await crawl_page(
                    url, settings=ctx.settings, suffixes=sfx, extra_hosts=hosts
                )
            except Exception as e:
                _LOGGER.warning("t_crawl_page failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(result)

    # Registered only when this deployment actually holds a playbook (see
    # prime_playbook_presence). An unprimed or unanswered probe keeps the tool.
    if _in_role("t_get_playbooks", role) and not _playbooks_known_absent(ctx):

        @_register
        async def t_get_playbooks(
            alert_id: str | None = None,
            max_results: int = 25,
        ) -> list[dict[str, Any]] | dict[str, Any]:
            """Pull playbooks; optionally scoped to a given alert's linked rule."""
            max_results = min(max_results, 10)
            if dup := _dedup_result(
                ctx, "t_get_playbooks", {"alert_id": alert_id, "max_results": max_results}
            ):
                return dup
            try:
                pbs = await get_playbooks(
                    elastic=ctx.elastic,
                    settings=ctx.settings,
                    alert_id=alert_id,
                    max_results=max_results,
                )
            except Exception as e:
                _LOGGER.warning("t_get_playbooks failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result([p.model_dump(mode="json") for p in pbs])

    @_register
    async def t_enrich_ip(ip: str) -> dict[str, Any]:
        """Local IP enrichment: internal-CIDR check + blocklists + MaxMind
        ASN/Geo + cloud-provider tag + optional MISP lookup."""
        if dup := _dedup_result(ctx, "t_enrich_ip", {"ip": ip}):
            return dup
        try:
            result_obj = await enrich_ip(
                ip,
                settings=ctx.settings,
                misp=ctx.misp,
                blocklist=ctx.blocklist,
                maxmind=ctx.maxmind,
                cloud=ctx.cloud,
            )
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_ip failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_enrich_domain(domain: str) -> dict[str, Any]:
        """Local domain enrichment (blocklists + optional MISP lookup)."""
        if dup := _dedup_result(ctx, "t_enrich_domain", {"domain": domain}):
            return dup
        try:
            result_obj = await enrich_domain(
                domain, settings=ctx.settings, misp=ctx.misp, blocklist=ctx.blocklist
            )
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_domain failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @_register
    async def t_enrich_hash(hash_value: str, algo: str = "sha256") -> dict[str, Any]:
        """Local file-hash enrichment (blocklists + optional MISP lookup)."""
        if dup := _dedup_result(ctx, "t_enrich_hash", {"hash_value": hash_value, "algo": algo}):
            return dup
        try:
            result_obj = await enrich_hash(
                hash_value, algo, settings=ctx.settings, misp=ctx.misp, blocklist=ctx.blocklist
            )
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_hash failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    if _in_role("t_lookup_runbook", role):

        @_register
        async def t_lookup_runbook(query: str, k: int = 5) -> list[dict[str, Any]] | dict[str, Any]:
            """Search the operator's own runbooks (keyword/tag/rule-linked)."""
            k = min(k, 5)
            if dup := _dedup_result(ctx, "t_lookup_runbook", {"query": query, "k": k}):
                return dup
            try:
                # ctx.settings enables the opt-in semantic tier (rag_embed_model);
                # with the tier unconfigured, retrieval stays 100% local (FTS5).
                rows = await lookup_runbook(
                    query, k=k, db_sessionmaker=ctx.db_sessionmaker, settings=ctx.settings
                )
            except Exception as e:
                _LOGGER.warning("t_lookup_runbook failed: %s", e)
                return _tool_error(e)
            return _clamp_tool_result(rows)
