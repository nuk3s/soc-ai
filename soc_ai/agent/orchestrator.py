"""Investigation orchestrator: PydanticAI Agent + read-tool wiring + SSE event stream.

For each :func:`investigate` call:

1. Build a PydanticAI :class:`Agent` bound to the heavy model with
   ``output_type=TriageReport`` and the system prompt assembled from
   :func:`build_system_prompt`.
2. Register every read tool from :func:`list_tools` as an Agent tool
   (closures over the runtime ``ctx`` so the LLM only sees semantic args).
3. Run the agent, yielding :class:`StepEvent` objects as tool calls and
   the final report land. Write tools surface via
   :attr:`TriageReport.recommended_actions` only - the orchestrator emits
   one ``approval_required`` event per action and the
   :class:`~soc_ai.tools._registry.ApprovalGate` resumes execution when
   ``POST /approve`` arrives.

Construction of the model + provider is in :func:`build_agent` so the API
layer (step 7) can lifecycle-manage it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import uuid
from collections import Counter
from collections.abc import AsyncGenerator, AsyncIterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, cast

from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models import Model
from pydantic_ai.usage import UsageLimits
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai import metrics
from soc_ai.agent.classifier import AlertClass, classify_alert, is_fast_path_eligible
from soc_ai.agent.models import (
    build_investigator_model,
    build_model,
    build_synthesizer_model,
)
from soc_ai.agent.prompts import (
    INVESTIGATOR_PROMPT,
    SYNTHESIZER_PROMPT,
    build_fast_path_synth_user_message,
)
from soc_ai.agent.reasoning import extract_reasoning_trace
from soc_ai.agent.triage import InvestigationTranscript, RecommendedAction, TriageReport
from soc_ai.audit.logger import AuditLogger
from soc_ai.config import Settings
from soc_ai.enrichment.blocklists import BlocklistDB
from soc_ai.enrichment.cloud_tags import CloudPrefixDB
from soc_ai.enrichment.maxmind import MaxmindReader
from soc_ai.errors import OqlValidationError, SoApiError

# Module import (not `from ... import adjudicate`) so tests patching
# `soc_ai.oracle.client.adjudicate` keep intercepting the escalation call.
from soc_ai.oracle import client as _oracle_client
from soc_ai.oracle.identifiers import EffectiveIdentifiers, effective_internal_identifiers
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.inventory import inventory_prompt_block
from soc_ai.so_client.models import SoAlert
from soc_ai.tools._registry import ApprovalGate
from soc_ai.tools.crawl_page import crawl_page
from soc_ai.tools.cvedb import cve_lookup
from soc_ai.tools.discover import describe_dataset, field_values
from soc_ai.tools.enrichment import (
    MispClient,
    build_local_enrichment_context,
    enrich_domain,
    enrich_hash,
    enrich_ip,
)
from soc_ai.tools.get_alert_context import get_alert_context
from soc_ai.tools.get_pcap import get_pcap_facts
from soc_ai.tools.get_playbooks import get_playbooks
from soc_ai.tools.greynoise import greynoise
from soc_ai.tools.host_summary import host_summary
from soc_ai.tools.lookup_runbook import lookup_runbook
from soc_ai.tools.prevalence import prevalence
from soc_ai.tools.query_cases import query_cases
from soc_ai.tools.query_detections import query_detections
from soc_ai.tools.query_events import query_events_oql
from soc_ai.tools.query_zeek import query_zeek_logs
from soc_ai.tools.rule_prevalence import rule_prevalence
from soc_ai.tools.rule_tuning import suggest_rule_tuning
from soc_ai.tools.shodan_host import shodan_host
from soc_ai.tools.shodan_internetdb import shodan_internetdb
from soc_ai.tools.web_search import web_search
from soc_ai.tools.write_exec import execute_write_tool

_LOGGER = logging.getLogger(__name__)


# =====================================================================
# Runtime context + SSE events
# =====================================================================


class _DedupTracker:
    """Per-investigation tool-call dedup gate.

    Tracks ``(tool_name, normalized_args)`` tuples seen during the run.
    The investigator's tool wrappers consult :meth:`is_duplicate` and
    short-circuit with a structured ``{"duplicate_call": True, ...}``
    payload instead of re-running the underlying tool. This stops the
    "10 identical t_query_zeek_logs calls in a row" failure mode that
    analysis surfaced as the top driver of long-tail
    investigation latency.
    """

    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()

    def _key(self, tool_name: str, args: dict[str, Any]) -> tuple[str, str]:
        # Sort keys so {"a": 1, "b": 2} and {"b": 2, "a": 1} hash the same.
        return tool_name, json.dumps(args, sort_keys=True, default=str)

    def is_duplicate(self, tool_name: str, args: dict[str, Any]) -> bool:
        key = self._key(tool_name, args)
        if key in self._seen:
            return True
        self._seen.add(key)
        return False


@dataclass
class InvestigationContext:
    """Runtime dependencies shared by all tools in one investigation."""

    settings: Settings
    auth: SoAuthClient
    elastic: ElasticClient
    misp: MispClient | None = None
    gate: ApprovalGate = field(default_factory=ApprovalGate)
    audit: AuditLogger | None = None
    # Default time-window anchor for query tools. Set by the
    # orchestrator to ``alert.timestamp`` immediately after prefetch, so
    # the investigator's `t_query_*` tools center their search on the
    # alert's @timestamp instead of "last N minutes from now". Direct
    # callers (CLI / WebUI / tests) leave this ``None`` for live-monitor
    # behavior. Tools fall back to now-relative when this is absent.
    default_time_anchor: datetime | None = None
    # Dedup tracker. Per-investigation set of seen tool-call
    # signatures. The orchestrator builds a fresh one per `investigate()`
    # call so dedup state never leaks across runs.
    dedup: _DedupTracker = field(default_factory=_DedupTracker)
    # Pre-fetched community_ids (prefetch-first rule). The
    # orchestrator populates this from the alert's `community_id_events`
    # right after prefetch. The `t_query_zeek_logs` wrapper short-circuits
    # when the requested community_id is already covered by the prefetch.
    prefetched_community_ids: set[str] = field(default_factory=set)
    # Local enrichment sources (Task 15 of synth-first redesign). The
    # synth-first pipeline path constructs these from settings.blocklist_data_dir
    # / settings.maxmind_data_dir / settings.cloud_prefix_data_dir at startup.
    # Legacy callers pass empty defaults — the new t_enrich_* tools degrade
    # gracefully when blocklist/maxmind/cloud are empty.
    blocklist: BlocklistDB = field(default_factory=BlocklistDB)
    maxmind: MaxmindReader = field(default_factory=MaxmindReader)
    cloud: CloudPrefixDB = field(default_factory=CloudPrefixDB)
    # When True, the prefetch pivots are allowed to see synthetic
    # eval docs (`synth.scenario_id`). Prod leaves this False so synth
    # fixtures can never contaminate a real investigation; the eval harness
    # sets it True only when triaging a known synth alert.
    include_synth: bool = False
    # Internal-identifier discovery (increment 2c). The session factory for the
    # local store, threaded so the Oracle escalation path can resolve the
    # *effective* internal-identifier set (env-config union active detected/manual
    # identifiers, minus muted) from the ``internal_identifier`` table before
    # sanitizing the egress payload. ``None`` for direct callers (CLI / eval /
    # tests) that have no DB — the Oracle path then falls back to the raw
    # ``settings.oracle_internal_suffixes`` / ``oracle_extra_hosts`` tuples, so
    # behavior is unchanged when no DB (or an empty table) is present.
    db_sessionmaker: async_sessionmaker[AsyncSession] | None = None


class StepEvent(BaseModel):
    """One event emitted to the SSE stream."""

    kind: str
    session_id: str
    sequence: int
    payload: dict[str, Any]


# =====================================================================
# Agent factory
# =====================================================================


# The model + provider builders — ``build_investigator_model``,
# ``build_synthesizer_model``, ``build_model`` and their ``_build_provider`` /
# ``_nemotron_profile`` helpers — now live in :mod:`soc_ai.agent.models`. They
# are re-imported at the top of this module so every existing call site, the
# ``agent`` package re-exports, and the tests that patch
# ``soc_ai.agent.orchestrator.build_*_model`` keep working unchanged.


# `build_local_enrichment_context` now lives in `soc_ai.tools.enrichment`
# (so the MCP server can build the same local sources without importing this
# heavy module); it is re-imported above and re-exported below for the
# existing `soc_ai.agent.orchestrator.build_local_enrichment_context` callers.


def _tool_error(exc: BaseException) -> dict[str, Any]:
    """Render a tool-side exception into a structured result the model can read.

    Tool exceptions used to propagate up and kill the agent run. Now we catch
    them at every tool boundary and surface them as a `{error, type, message}`
    dict — PydanticAI sends that back to the model as a tool result, and the
    model can either retry with corrected args or move on.
    """
    payload: dict[str, Any] = {
        "error": True,
        "type": type(exc).__name__,
        "message": str(exc),
    }
    fragment = getattr(exc, "fragment", None)
    if fragment:
        payload["fragment"] = fragment
    return payload


# Cap on the JSON-serialized size of any single tool return. Both Nemotron 3
# models on the lab grid are deployed with 64K context; a single t_query_*
# call returning 100 zeek/event docs can be 20-40K tokens, and a few of those
# back-to-back blow the window. With this clamp every tool returns at most
# ~3K tokens; the model can call the same tool multiple times if it needs
# more breadth, but no single round-trip can dominate the budget.
_TOOL_RESULT_BUDGET_BYTES = 12 * 1024


# Citation validator. Synthesizer prompts allow three citation
# kinds:
#   - "(id <es_id>)" or "(id sB86B...)"   — ES / SOC API id
#   - "(path alert.<dotted.path>)"        — typed field on the prefetch
#   - "(tool <name>:<key>=<value>)"       — tool-call result already in
#                                           the transcript (key optional)
# We classify + validate paths/tools against the bundle. Hallucinated
# citations don't block the synth output — we emit a `citation_validation`
# event so the audit trail and eval pipeline can track drift.
_CITE_PATH_RE = re.compile(r"\(?\s*path\s+([A-Za-z0-9_.\[\]]+)\s*\)?")
_CITE_TOOL_RE = re.compile(r"\(?\s*tool\s+([A-Za-z0-9_.]+)(?:\s*:\s*[^)]+)?\s*\)?")
_CITE_ID_RE = re.compile(r"\(?\s*id\s+([A-Za-z0-9_-]{6,})\s*\)?")


_PLAIN_PATH_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
_PLAIN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{12,}$")


def _classify_citation(citation: str) -> tuple[str, str | None]:
    """Return (kind, target) where kind is 'path' | 'tool' | 'id' | 'unknown'.

    The target is the dotted-path / tool-name / id-string respectively,
    or None for ``unknown``. Citation strings come from the model, so
    we accept several formatting variants:

    - explicit prefix: ``(path foo.bar)`` / ``(tool t_enrich_ip)`` /
      ``(id sB86B...)``;
    - prefix without parens: ``path foo.bar`` / ``id sB86B...``;
    - **plain form** (preferred by the model in practice): bare dotted
      path ``alert.rule_metadata.signature_severity`` (classified as
      `path`), or bare long alphanumeric ``sB86B54BVBs3R9hX_qZR``
      (classified as `id`).

    The plain-form fallbacks were added after early smoke testing
    showed the model emits plain forms most of
    the time. The validator's job is metric collection, not strict
    grammar enforcement, so accept the natural shape.
    """
    s = citation.strip()
    # Explicit-prefix forms first (most specific).
    if m := _CITE_PATH_RE.search(s):
        return "path", m.group(1)
    if m := _CITE_TOOL_RE.search(s):
        return "tool", m.group(1)
    if m := _CITE_ID_RE.search(s):
        return "id", m.group(1)
    # Plain forms.
    if _PLAIN_PATH_RE.match(s):
        return "path", s
    if _PLAIN_ID_RE.match(s):
        return "id", s
    return "unknown", None


def _path_exists_in_alert(alert_ctx: Any, dotted: str) -> bool:
    """Walk a dotted path against an AlertContext / SoAlert dump.

    ``dotted`` may begin with ``alert.`` (the typed fields on the
    pre-loaded alert) or with a top-level pivot key like
    ``community_id_events`` (less common but legal).
    """
    try:
        dump = alert_ctx.model_dump(mode="json")
    except Exception:
        return False
    cur: Any = dump
    for part in dotted.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return False
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return False
        else:
            return False
    return cur is not None


def _tool_was_invoked(
    transcripts: list[Any],
    tool_name: str,
    *,
    messages: list[Any] | None = None,
) -> bool:
    """True iff the named tool was actually called.

    F7: when ``messages`` is provided (the
    PydanticAI ``all_messages()`` history), walks the actual
    ``ToolCallPart`` events. This is the authoritative source — a
    citation that names a tool which was never called is a fabricated
    citation. The previous substring-on-evidence-text fallback was
    spoofable: the model could write "ran t_enrich_ip" in evidence
    without ever calling it.

    Falls back to evidence-text substring match when ``messages`` is
    None (legacy callers and tests that don't have the message history).
    """
    if messages is not None:
        for msg in messages:
            for part in getattr(msg, "parts", []) or []:
                if getattr(part, "tool_name", None) == tool_name and hasattr(part, "args"):
                    # ToolCallPart carries args; ToolReturnPart carries content.
                    # Both have tool_name, but only ToolCallPart proves the tool
                    # actually ran (well, was *called* — it could have errored).
                    return True
        return False
    # Legacy fallback: substring in evidence text. Used by tests that
    # don't pass `messages` and by code paths where the message history
    # isn't accessible.
    for tr in transcripts:
        for item in getattr(tr, "evidence", []) or []:
            if tool_name in item:
                return True
    return False


def _loop_evidence_marker(
    ran_investigation_loop: bool, loop_messages: list[Any] | None
) -> str | None:
    """Return the ``targeted_tool_called`` evidence marker for the investigation-loop path.

    The marker (``"investigation_loop"``) exempts a verdict from the hard evidence
    gate and GATE A, so it must be returned ONLY when the loop actually gathered
    evidence — at least one SUCCESSFUL tool call. The budget/timeout fallback path
    leaves ``loop_messages`` None (the round-1 verdict simply stands), and a loop
    whose every tool call errored gathered nothing; neither is tool evidence, so
    both return None and let the gate downgrade an unevidenced verdict.
    """
    if ran_investigation_loop and count_successful_tool_calls(loop_messages) >= 1:
        return "investigation_loop"
    return None


def count_successful_tool_calls(messages: list[Any] | None) -> int:
    """Count tool calls that returned NON-error DATA in a PydanticAI history.

    A ``ToolReturnPart`` (duck-typed: has ``content``, lacks ``args``) is counted
    only when its content is usable — an error result (``{"error": True}``), a
    dedup short-circuit (``{"duplicate_call": True}``) or a prefetch short-circuit
    (``{"prefetch_already_has_this": True}``) does NOT count, because none of them
    gathered new evidence. Counting returns (not call parts) sidesteps the
    fragile call/return pairing by ``tool_call_id``. Returns 0 for None/empty.
    This is the signal behind the hard evidence gate: did the agent actually
    investigate, or just reason over prefetch?
    """
    if not messages:
        return 0
    n = 0
    for msg in messages:
        for part in getattr(msg, "parts", []) or []:
            # Discriminate on ``part_kind`` — NOT on the presence of ``content`` /
            # absence of ``args``. TextPart ('text'), ThinkingPart ('thinking') and
            # RetryPromptPart ('retry-prompt') all carry ``.content`` and lack
            # ``.args`` too, so the old duck-type test miscounted the model's final
            # text, its <think> trace, and even a FAILED tool-arg retry as tool
            # evidence — silently defeating the hard evidence gate (a zero-tool
            # verdict would score >=1 and skip the downgrade). Only an actual tool
            # RESULT is evidence.
            if getattr(part, "part_kind", None) not in ("tool-return", "builtin-tool-return"):
                continue
            c = part.content
            if c is None:
                continue  # a tool that returned nothing is not evidence
            if isinstance(c, dict) and (
                c.get("error") or c.get("duplicate_call") or c.get("prefetch_already_has_this")
            ):
                continue
            n += 1
    return n


_RUBRIC_FIELD_TO_TOOLS: dict[str, tuple[str, ...]] = {
    "enrichment_called": ("t_enrich_ip", "t_enrich_domain", "t_enrich_hash"),
    "dns_or_sni_pivoted": ("t_query_zeek_logs",),
    "related_alerts_checked": ("t_query_events_oql",),
    "playbook_consulted": ("t_get_playbooks", "t_lookup_runbook"),
    # `payload_inspected_if_banner_rule` is satisfied by READING the field,
    # not by a tool call — intentionally not mapped (no closeable tool).
}


def _has_closeable_rubric_gap(missing_rubric: list[str], messages: list[Any]) -> bool:
    """True iff at least one missing rubric field maps to a
    tool the agent has NOT yet called.

    The F4 retask trigger fires on ``rubric_gap`` whenever ≥2 fields
    are missing, but evaluation showed most retasked runs still landed at
    'partial' — retasking doesn't help when the missing fields can't
    actually be closed by a tool call (e.g. ``related_alerts_checked``
    on an alert without a host.name to pivot on, or
    ``playbook_consulted`` when no runbook exists for the rule).

    Walking the message history for actual ``ToolCallPart`` events
    tells us which tools the agent already used. If every closeable
    tool for every missing field has been called, retask is wasted
    budget — better to accept the floor and stop.
    """
    if not missing_rubric:
        return False
    called: set[str] = set()
    for msg in messages or []:
        for part in getattr(msg, "parts", []) or []:
            tn = getattr(part, "tool_name", None)
            if tn and hasattr(part, "args"):
                called.add(str(tn))
    for rubric_field in missing_rubric:
        tools = _RUBRIC_FIELD_TO_TOOLS.get(rubric_field, ())
        if not tools:
            # Field has no tool-call closure path (e.g. payload_inspected) —
            # not closeable by retasking at all.
            continue
        unused = [t for t in tools if t not in called]
        if unused:
            return True
    return False


def _fast_path_external_indicator(alert_ctx: Any) -> str | None:
    """Return the highest-priority external IOC for fast-path enrichment.

    Returns the destination IP if external, else the
    source IP if external, else None. Internal-internal traffic doesn't
    need enrichment.
    """
    from ipaddress import ip_address  # noqa: PLC0415

    alert = getattr(alert_ctx, "alert", None)
    if alert is None:
        return None
    for attr in ("destination_ip", "source_ip"):
        v = getattr(alert, attr, None)
        if not isinstance(v, str):
            continue
        try:
            addr = ip_address(v)
        except (ValueError, TypeError):
            continue
        if not (addr.is_private or addr.is_loopback or addr.is_link_local):
            return v
    return None


def _enrichment_has_threat_signal(result: Any) -> bool:
    """True iff the enrichment result includes a MISP IOC match or blocklist hit.

    Supports both the legacy ``EnrichmentResult`` shape (``result.findings``)
    and the new ``IndicatorEnrichment`` shape (``result.misp_hits`` /
    ``result.blocklist_hits``). Drives the fast-path escalation decision.
    """
    # New IndicatorEnrichment shape — misp_hits + blocklist_hits
    misp_hits = getattr(result, "misp_hits", None) or []
    if misp_hits:
        return True
    blocklist_hits = getattr(result, "blocklist_hits", None) or []
    if blocklist_hits:
        return True
    # Legacy EnrichmentResult shape — findings list
    findings = getattr(result, "findings", None) or []
    for f in findings:
        src = getattr(f, "source", "")
        cat = getattr(f, "category", "")
        if src == "misp" or cat == "ioc_match":
            return True
    return False


def _summarize_enrichment_for_evidence(ip: str, result: Any) -> str:
    """One-line evidence summary of an enrichment result, with citation.

    Supports both the legacy ``EnrichmentResult`` shape (``result.findings``)
    and the new ``IndicatorEnrichment`` shape.
    """
    # New IndicatorEnrichment shape
    misp_hits = getattr(result, "misp_hits", None) or []
    blocklist_hits = getattr(result, "blocklist_hits", None) or []
    cloud_provider = getattr(result, "cloud_provider", None)
    is_new_shape = hasattr(result, "misp_hits") or hasattr(result, "blocklist_hits")
    if is_new_shape:
        parts: list[str] = []
        if getattr(result, "internal", False):
            parts.append("internal")
        for h in blocklist_hits[:2]:
            src = getattr(h, "source", "blocklist")
            parts.append(f"blocklist:{src}")
        for f in misp_hits[:2]:
            desc = (getattr(f, "description", None) or "").strip()
            if desc:
                parts.append(desc[:60])
        if cloud_provider:
            parts.append(f"cloud:{cloud_provider}")
        if not parts:
            return f"t_enrich_ip({ip})=no findings (tool t_enrich_ip)"
        return f"t_enrich_ip({ip})={'; '.join(parts)} (tool t_enrich_ip)"
    # Legacy EnrichmentResult shape
    findings = getattr(result, "findings", None) or []
    if not findings:
        return f"t_enrich_ip({ip})=no findings (tool t_enrich_ip)"
    legacy_parts: list[str] = []
    for f in findings[:3]:
        desc = (getattr(f, "description", None) or "").strip()
        if desc:
            legacy_parts.append(desc[:80])
    summary = "; ".join(legacy_parts) if legacy_parts else f"{len(findings)} findings"
    return f"t_enrich_ip({ip})={summary} (tool t_enrich_ip)"


def _pivot_decisive_evidence(ev: Any, ev_id: str) -> list[str]:
    """Surface the DECISIVE typed protocol field(s) a Zeek pivot carries as
    explicit, citable evidence bullets — the JA3/JA3S pair (C2 framework), the RC4
    Kerberos ticket (Kerberoasting), the SMB/DCE-RPC service-creation chain
    (PsExec), the delivered PE (malware delivery), the exfil byte-asymmetry, and
    TXT-heavy DNS (tunnel). Returns ``[]`` when the pivot has no decisive typed
    field, so the caller falls back to a bare ``(id ...)`` cite.
    """

    def g(attr: str) -> Any:
        return getattr(ev, attr, None)

    out: list[str] = []
    ja3, ja3s = g("zeek_ssl_ja3"), g("zeek_ssl_ja3s")
    if ja3 and ja3s:
        out.append(
            f"TLS JA3/JA3S pair ja3={ja3} ja3s={ja3s} (id {ev_id}) — a client+server "
            "TLS fingerprint pair identifies a specific C2/beacon framework even behind "
            "CDN fronting"
        )
    elif ja3:
        out.append(f"TLS JA3={ja3} (id {ev_id}) — client TLS fingerprint")
    cipher = g("zeek_kerberos_cipher")
    if cipher:
        svc = g("zeek_kerberos_service")
        low = str(cipher).lower()
        rc4 = "rc4" in low or low in ("23", "0x17")
        note = " — RC4 ticket encryption on a TGS is the Kerberoasting signature" if rc4 else ""
        out.append(
            f"Kerberos ticket cipher={cipher}"
            + (f" for service={svc}" if svc else "")
            + f" (id {ev_id}){note}"
        )
    smb_name, smb_action = g("zeek_smb_name"), g("zeek_smb_action")
    if smb_name or smb_action:
        share = g("zeek_smb_mapping_service")
        out.append(
            f"SMB {smb_action or 'access'} of {smb_name or 'a file'}"
            + (f" to {share}" if share else "")
            + f" (id {ev_id}) — a service-binary write to an admin share is the PsExec pattern"
        )
    endpoint, op = g("zeek_dce_rpc_endpoint"), g("zeek_dce_rpc_operation")
    if endpoint or op:
        out.append(
            f"DCE-RPC {endpoint or ''} {op or ''} (id {ev_id}) — remote service-control RPC "
            "(svcctl / CreateServiceW) executes code on the target"
        )
    mime, sha = g("zeek_files_mime_type"), g("zeek_files_sha256")
    if mime or sha:
        exe = bool(mime) and any(m in str(mime) for m in ("dosexec", "executable", "x-msdownload"))
        note = " — an executable delivered over the wire" if exe else ""
        out.append(
            f"transferred file mime={mime or '?'}"
            + (f" sha256={sha}" if sha else "")
            + f" (id {ev_id}){note}"
        )
    orig, resp = g("zeek_conn_orig_bytes"), g("zeek_conn_resp_bytes")
    dur = g("zeek_conn_duration")
    if (
        isinstance(orig, int)
        and isinstance(resp, int)
        and orig > 1_000_000
        and orig > 10 * max(resp, 1)
    ):
        # Fold in DURATION so a low-and-slow multi-hour exfil is distinguished from
        # a quick bulk upload — a 4 GB transfer trickled over 9h is the classic
        # low-and-slow shape, more suspicious than the same bytes in a burst.
        slow = ""
        if isinstance(dur, (int, float)) and dur >= 3600:
            slow = f", sustained over {int(dur // 3600)}h (low-and-slow)"
        out.append(
            f"outbound-dominant transfer orig_bytes={orig} resp_bytes={resp}{slow} (id {ev_id}) "
            "— a long connection sending far more than it receives is the data-exfil shape"
        )
    ssh_ok = g("zeek_ssh_auth_success")
    if ssh_ok:
        attempts = g("zeek_ssh_auth_attempts")
        att = f" in {attempts} attempt(s)" if isinstance(attempts, int) else ""
        out.append(
            f"completed SSH login (auth_success=true{att}) (id {ev_id}) — an interactive shell "
            "was established; a successful SSH auth from a bad-reputation / external source into "
            "an internal asset is a confirmed intrusion, not policy noise"
        )
    qtype = g("zeek_dns_qtype")
    if qtype and str(qtype).upper() in ("TXT", "NULL"):
        out.append(
            f"DNS qtype={qtype} (id {ev_id}) — TXT/NULL-heavy DNS is the covert-tunnel channel"
        )
    out.extend(_beacon_profile_bullet(g("zeek_beacon_profile"), ev_id))
    out.extend(_dns_tunnel_profile_bullet(g("zeek_dns_profile"), ev_id))
    return out


def _num(d: dict[str, Any], *keys: str) -> float | None:
    """First numeric value among ``keys`` in ``d`` (tolerates RITA vs eval naming)."""
    for k in keys:
        v = d.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return float(v)
    return None


def _beacon_profile_bullet(profile: Any, ev_id: str) -> list[str]:
    """A RITA-style beacon profile is decisive C2 evidence: regular inter-arrival
    timing (high interval similarity / low stddev) with near-constant payload sizes
    over many connections is a machine, not a human — even behind CDN fronting and
    even when the alert is only an ET HUNTING/Minor rule."""
    if not isinstance(profile, dict):
        return []
    similarity = _num(profile, "interval_similarity", "score", "beacon_score")
    orig_cv = _num(profile, "orig_bytes_cv", "src_bytes_cv")
    resp_cv = _num(profile, "resp_bytes_cv", "dst_bytes_cv")
    low_byte_variance = (orig_cv is not None and orig_cv <= 0.15) or (
        resp_cv is not None and resp_cv <= 0.15
    )
    if not ((similarity is not None and similarity >= 0.75) or low_byte_variance):
        return []
    count = _num(profile, "connection_count", "total_connections")
    mean_int = _num(profile, "mean_interval_seconds", "interval_mean_seconds")
    parts = []
    if count is not None:
        parts.append(f"{int(count)} connections")
    if mean_int is not None:
        parts.append(f"~{mean_int:g}s mean interval")
    if similarity is not None:
        parts.append(f"{similarity:.0%} interval similarity")
    if orig_cv is not None or resp_cv is not None:
        parts.append(
            f"near-constant payload (orig cv={orig_cv:.2f}, resp cv={resp_cv:.2f})"
            if orig_cv is not None and resp_cv is not None
            else "near-constant payload size"
        )
    detail = "; ".join(parts) or "regular timing with constant payloads"
    return [
        f"periodic beacon profile: {detail} (id {ev_id}) — RITA-style regularity is an "
        "automated C2 beacon, decisive even when the signature is only ET HUNTING"
    ]


def _dns_tunnel_profile_bullet(profile: Any, ev_id: str) -> list[str]:
    """A DNS aggregate with high query volume, high subdomain cardinality/entropy,
    and a TXT/NULL-dominant qtype mix under one parent domain is a covert DNS tunnel
    — the data channel is the DNS itself, so a single low-severity alert plus this
    profile is a confirmed exfil/C2 channel."""
    if not isinstance(profile, dict):
        return []
    entropy = _num(profile, "qname_label_entropy_mean", "qname_entropy", "entropy")
    query_count = _num(profile, "query_count", "queries")
    unique_sub = _num(profile, "unique_subdomains", "distinct_subdomains")
    qtypes = profile.get("qtype_distribution")
    txt_null = 0.0
    total_q = 0.0
    if isinstance(qtypes, dict):
        for k, v in qtypes.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                total_q += float(v)
                if str(k).upper() in ("TXT", "NULL"):
                    txt_null += float(v)
    txt_dominant = total_q > 0 and (txt_null / total_q) >= 0.5
    high_entropy = entropy is not None and entropy >= 3.5
    high_volume = (query_count is not None and query_count >= 500) or (
        unique_sub is not None and unique_sub >= 200
    )
    if not (high_entropy and (high_volume or txt_dominant)):
        return []
    parent = profile.get("parent_domain") or profile.get("domain")
    parts = []
    if query_count is not None:
        parts.append(f"{int(query_count)} queries")
    if unique_sub is not None:
        parts.append(f"{int(unique_sub)} unique subdomains")
    if entropy is not None:
        parts.append(f"label entropy {entropy:g}")
    if txt_dominant:
        parts.append(f"{txt_null / total_q:.0%} TXT/NULL")
    detail = ", ".join(parts) or "high-volume high-entropy queries"
    dom = f" under {parent}" if parent else ""
    return [
        f"DNS-tunnel aggregate{dom}: {detail} (id {ev_id}) — high-entropy, high-volume, "
        "TXT/NULL-dominant DNS is a covert exfil/C2 channel, not name resolution"
    ]


def _materialize_prefetch_evidence(alert_ctx: Any) -> list[str]:
    """Build a list of cited evidence items from the prefetched context.

    The fast-path was emitting ``evidence=[]`` and
    relying on the synth to cite from the alert dump alone — the oracle
    flagged this as the dominant disagreement axis (most verdicts
    came back ``partial`` specifically because the fast-path didn't
    surface prefetched community_id pivots as evidence). This helper
    materializes typed alert fields + community_id_events / host_events
    / etc. as ``Evidence`` items with concrete ``(path ...)`` or
    ``(id ...)`` citations the validator can check.

    Returns a bounded list (max ~10 items) so the synth's user message
    stays compact. Picks the highest-signal fields first.
    """
    evidence: list[str] = []
    alert = getattr(alert_ctx, "alert", None)
    if alert is None:
        return evidence

    # Alert-level typed fields. Each citation is a path the validator
    # can resolve against the prefetch dump.
    rm = getattr(alert, "rule_metadata", None)
    if rm is not None and getattr(rm, "signature_severity", None):
        evidence.append(
            f"signature_severity={rm.signature_severity} "
            f"(path alert.rule_metadata.signature_severity)"
        )
    if getattr(alert, "alert_action", None):
        evidence.append(f"alert_action={alert.alert_action} (path alert.alert_action)")
    if getattr(alert, "classtype", None):
        evidence.append(f"classtype={alert.classtype} (path alert.classtype)")
    if getattr(alert, "severity_label", None):
        evidence.append(f"severity_label={alert.severity_label} (path alert.severity_label)")
    if getattr(alert, "rule_name", None):
        evidence.append(f"rule_name={alert.rule_name!r} (path alert.rule_name)")
    payload = getattr(alert, "payload_printable", None)
    if payload:
        # Clip to a short excerpt — keeps the evidence list dense.
        excerpt = payload[:80] + "…" if len(payload) > 80 else payload
        evidence.append(f"payload_printable contains {excerpt!r} (path alert.payload_printable)")

    # Community-id pivots — cite each by its ES _id, AND surface the DECISIVE
    # typed protocol field(s) the pivot carries. Citing only "a zeek.ssl record
    # (id X)" left the JA3/JA3S pair, the RC4 Kerberos ticket, the PsExec SMB/RPC
    # chain, and the delivered PE's mime/hash buried in the JSON dump — the recall
    # root cause. Materializing them as explicit bullets makes the model read them
    # and the validator resolve them. Up to 3 events (already capped at 5 upstream).
    pivots = getattr(alert_ctx, "community_id_events", None) or []
    for ev in pivots[:3]:
        dataset = getattr(ev, "event_dataset", None) or "unknown dataset"
        ev_id = getattr(ev, "id", None)
        if not ev_id:
            continue
        decisive = _pivot_decisive_evidence(ev, ev_id)
        if decisive:
            evidence.extend(decisive)
        else:
            evidence.append(f"community_id pivot: {dataset} record (id {ev_id})")

    # Host pivots — same idea, one entry for the existence of related
    # host events.
    host_pivots = getattr(alert_ctx, "host_events", None) or []
    if host_pivots:
        ev_id = getattr(host_pivots[0], "id", None)
        if ev_id:
            evidence.append(f"host has {len(host_pivots)} related event(s) (id {ev_id})")

    # Indicator enrichments. EnrichedAlertContext carries
    # an ``enrichments: dict[str, IndicatorEnrichment]`` populated by
    # Phase A. Blocklist hits and MISP hits are the strongest single
    # signals the synth has — surface them by name + indicator so the
    # synth cites them directly instead of digging through the
    # alert_ctx JSON. Without this, alerts with strong blocklist
    # matches hedged because materialized_evidence didn't name the
    # hit explicitly.
    enrichments = getattr(alert_ctx, "enrichments", None) or {}
    for indicator, enrich in enrichments.items():
        for hit in getattr(enrich, "blocklist_hits", None) or []:
            tags = list(getattr(hit, "tags", ()) or ())
            tags_str = f" tags={tags}" if tags else ""
            evidence.append(
                f"blocklist hit on {indicator}: source={getattr(hit, 'source', '?')}"
                f"{tags_str} (path enrichments.{indicator}.blocklist_hits)"
            )
        for misp in getattr(enrich, "misp_hits", None) or []:
            desc = getattr(misp, "description", "") or "(no description)"
            evidence.append(
                f"MISP hit on {indicator}: {desc[:120]} (path enrichments.{indicator}.misp_hits)"
            )

    return evidence


def _required_rubric_fields(alert_ctx: Any) -> set[str]:
    """Determine which RubricCoverage fields are REQUIRED for this alert.

    The synth caps confidence at 0.6 if any required field
    is False. Required-for-class is per-alert:

    - **External-IOC alerts** (any external IP / domain / hash referenced
      anywhere in the alert or its pivots): require ``enrichment_called``
      and ``dns_or_sni_pivoted``.
    - **Banner/content-class rules** (most ET INFO/POLICY rules; any
      Suricata rule whose `signature_severity` is ``Informational`` or
      whose payload_printable is non-empty): require
      ``payload_inspected_if_banner_rule``.
    - **Always recommended (not strictly required):**
      ``related_alerts_checked``, ``playbook_consulted``. We don't
      require these by default since they're correlation hints rather
      than evidence; later analysis can promote them.

    Pure-internal-traffic alerts skip the IOC-class requirements (no
    external indicator → enrichment is moot).
    """
    required: set[str] = set()
    alert = getattr(alert_ctx, "alert", None)
    if alert is None:
        return required

    # External-IOC detection: do any of the IPs reachable from the alert
    # look external? Use settings.internal_cidrs to gate.
    ips: list[str] = []
    for attr in ("source_ip", "destination_ip"):
        v = getattr(alert, attr, None)
        if isinstance(v, str):
            ips.append(v)
    has_external_ip = False
    for ip in ips:
        try:
            from ipaddress import ip_address  # noqa: PLC0415

            addr = ip_address(ip)
            if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                has_external_ip = True
                break
        except (ValueError, TypeError):
            continue
    # An IOC requirement needs a concrete external indicator the agent can
    # actually look up: an external IP, a file hash, or a parsed dns_query
    # (Zeek-only — Suricata alerts have dns_query=None by design).
    # `payload_printable` is NOT included here: it's matched packet bytes
    # that often contain a literal domain or URL, but the field's content is
    # unconstrained, so forcing the gate on payload_printable presence
    # punishes ET INFO alerts where the whole point of the fast path is
    # "answer from prefetched fields without reaching for tools".
    has_indicator = bool(
        has_external_ip
        or getattr(alert, "file_hash_sha256", None)
        or getattr(alert, "dns_query", None)
    )
    if has_indicator:
        required.add("enrichment_called")
    # F3: `dns_or_sni_pivoted` only required when the alert
    # actually has a DNS/SNI signal to pivot on. Decoupled from the
    # generic "external indicator" check above — a remote IP without a
    # DNS query / SNI / payload domain doesn't NEED a DNS pivot.
    has_dns_or_sni_signal = bool(
        getattr(alert, "dns_query", None)
        or getattr(alert, "payload_printable", None)
        or getattr(alert, "zeek_dns_query", None)
        or getattr(alert, "zeek_ssl_server_name", None)
    )
    if has_indicator and has_dns_or_sni_signal:
        required.add("dns_or_sni_pivoted")

    # Banner-class trigger: rule_metadata says Informational OR payload
    # is non-empty (suggesting a content-match rule).
    rm = getattr(alert, "rule_metadata", None)
    is_banner_class = bool(rm and getattr(rm, "is_informational", False)) or bool(
        getattr(alert, "payload_printable", None)
    )
    if is_banner_class:
        required.add("payload_inspected_if_banner_rule")

    return required


def _credit_prefetch_coverage(out: Any, alert_ctx: Any) -> None:
    """Credit rubric coverage the enriched-prefetch pipeline already provided.

    The prefetch runs enrichment on every indicator and fans out the community_id /
    host pivots BEFORE the agent loop, then hands the result to the model. A verdict
    that used that prefetched evidence must NOT be capped by the coverage gate for
    failing to re-issue the same work as explicit tool calls — the orchestrator
    already did it. This is what lets the synth-first path (where the prefetch IS the
    primary evidence gathering) reach full confidence on a well-grounded escalation.
    """
    if alert_ctx is None:
        return
    if getattr(alert_ctx, "enrichments", None):
        out.enrichment_called = True
    if getattr(alert_ctx, "host_events", None) or getattr(alert_ctx, "host_alert_profile", None):
        out.related_alerts_checked = True
    # A community_id pivot that already retrieved a zeek.dns / zeek.ssl / zeek.http
    # record IS the dns/sni pivot — the orchestrator performed it.
    for ev in getattr(alert_ctx, "community_id_events", None) or []:
        ds = (getattr(ev, "event_dataset", "") or "").lower()
        if ds in ("zeek.dns", "zeek.ssl", "zeek.http"):
            out.dns_or_sni_pivoted = True
            break


def _derive_rubric_coverage(
    messages: list[Any],
    alert_ctx: Any,
    *,
    seed: Any = None,
) -> Any:
    """F3: derive coverage from actual tool calls.

    Walks PydanticAI's ``all_messages()`` history looking for
    ``ToolCallPart`` events and sets rubric fields based on what tools
    actually fired (and with what args). This replaces the model's
    self-reported rubric, which analysis flagged as
    routinely fabricated / over-claimed.

    Class-aware auto-satisfactions:
    - ``dns_or_sni_pivoted`` is auto-True when the alert has no
      DNS/SNI signal at all (``dns_query`` is None and
      ``payload_printable`` is empty).
    - ``payload_inspected_if_banner_rule`` is auto-True when the rule
      isn't banner-class (existing rubric contract).

    For OR-merge across retask rounds, pass the round-1 derived rubric
    as ``seed``; the round-2 derivation OR-merges into it so a field
    satisfied by round-1 isn't re-failed by round-2's narrower message
    history.
    """
    from soc_ai.agent.triage import RubricCoverage  # noqa: PLC0415

    out: RubricCoverage = (
        seed.model_copy(deep=True) if isinstance(seed, RubricCoverage) else RubricCoverage()
    )

    for msg in messages or []:
        for part in getattr(msg, "parts", []) or []:
            # Duck-typed: PydanticAI's ToolCallPart has tool_name + args.
            # Class-name check (`type(part).__name__ == "ToolCallPart"`)
            # would be more strict but breaks tests using stand-in classes.
            tool_name_attr = getattr(part, "tool_name", None)
            if tool_name_attr is None:
                continue
            tool_name = str(tool_name_attr)
            raw_args = getattr(part, "args", {}) or {}
            args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}
            if isinstance(raw_args, str):
                try:
                    parsed = json.loads(raw_args)
                except (json.JSONDecodeError, TypeError):
                    parsed = {}
                if isinstance(parsed, dict):
                    args = parsed

            if tool_name.startswith("t_enrich_"):
                out.enrichment_called = True
            elif tool_name == "t_query_zeek_logs":
                log_types = args.get("log_types") or []
                if isinstance(log_types, list) and any(
                    isinstance(t, str) and t.lower() in ("dns", "ssl", "http") for t in log_types
                ):
                    out.dns_or_sni_pivoted = True
            elif tool_name == "t_query_events_oql":
                query = args.get("query") or ""
                if isinstance(query, str):
                    # F8: related_alerts_checked requires a
                    # filter on host/user/process. Bare community_id =
                    # the SAME alert (not "related"); host/user/process
                    # filters look at OTHER events on the same actor.
                    # Calibration found the
                    # `event.kind` co-requirement was too strict — the
                    # model issued valid pivot queries like
                    # `host.name:"foo" AND dns.query.name:*` that the
                    # rule rejected, forcing wasted retasks.
                    pivot_field_present = any(
                        f in query for f in ("host.name", "user.name", "process.entity_id")
                    )
                    if pivot_field_present:
                        out.related_alerts_checked = True
            elif tool_name in ("t_get_playbooks", "t_lookup_runbook"):
                out.playbook_consulted = True

    _credit_prefetch_coverage(out, alert_ctx)

    # Class-aware auto-True: alerts with no DNS/SNI signal can't be
    # pivoted on — the rubric field is N/A.
    alert = getattr(alert_ctx, "alert", None) if alert_ctx is not None else None
    if alert is not None:
        has_dns_or_sni_signal = bool(
            getattr(alert, "dns_query", None)
            or getattr(alert, "payload_printable", None)
            or getattr(alert, "zeek_dns_query", None)
            or getattr(alert, "zeek_ssl_server_name", None)
        )
        if not has_dns_or_sni_signal:
            out.dns_or_sni_pivoted = True

        # `payload_inspected_if_banner_rule` is True iff the rule is
        # banner-class AND payload bytes actually reached the model.
        # Existing contract: auto-True for non-banner rules.
        # B5: derived MECHANICALLY — the model's self-report is no longer
        # consulted anywhere (analysis flagged self-reports as
        # routinely fabricated; the field stays in the
        # InvestigationTranscript schema so old transcripts parse, but it
        # cannot satisfy this gate any more — it's only surfaced un-merged
        # via the rubric_derivation event's `model_reported` for audit).
        # "Inspected" can't be proven from the message history, but
        # "received" can: the prompt embeds the compacted prefetch
        # (payload_printable survives `_compact_alert_context`'s slimming),
        # and tool returns in the history may carry payload_printable
        # values from pivoted records.
        rm = getattr(alert, "rule_metadata", None)
        is_banner_class = bool(rm and getattr(rm, "is_informational", False)) or bool(
            getattr(alert, "payload_printable", None)
        )
        if not is_banner_class or _payload_printable_reached_model(messages, alert_ctx):
            out.payload_inspected_if_banner_rule = True

    return out


# Per-pivot event cap shared by the prompt compactor and the payload-receipt
# derivation — must stay in sync.
_COMPACT_PIVOT_CAP = 3


def _payload_printable_reached_model(messages: list[Any], alert_ctx: Any) -> bool:
    """B5: did any content the model actually received carry a non-empty
    ``payload_printable``?

    Three mechanical sources, all things the orchestrator can prove were
    in front of the model:

    - ``alert.payload_printable`` — embedded in every prompt via the
      compacted prefetch (`_compact_alert_context` keeps the field).
    - The first 3 events of each pivot list — `_compact_alert_context`
      caps each pivot at 3 events, so only those reached the prompt.
    - Tool-return parts in the message history whose content contains a
      non-empty ``payload_printable`` value (pivoted Suricata records).
    """
    alert = getattr(alert_ctx, "alert", None) if alert_ctx is not None else None
    if alert is not None and bool(getattr(alert, "payload_printable", None)):
        return True
    if alert_ctx is not None:
        for pivot_attr in (
            "community_id_events",
            "host_events",
            "user_events",
            "process_events",
            "file_events",
        ):
            events = getattr(alert_ctx, pivot_attr, None) or []
            # Mirror `_compact_alert_context`'s _COMPACT_PIVOT_CAP event prompt cap.
            for e in list(events)[:_COMPACT_PIVOT_CAP]:
                if bool(getattr(e, "payload_printable", None)):
                    return True
    for msg in messages or []:
        for part in getattr(msg, "parts", []) or []:
            # Duck-typed ToolReturnPart: has tool_name + content (ToolCallPart
            # has tool_name + args but no content — skipped by the None check).
            if getattr(part, "tool_name", None) is None:
                continue
            content = getattr(part, "content", None)
            if content is not None and _content_has_payload_printable(content):
                return True
    return False


# Matches a non-empty payload_printable value inside a JSON-encoded string
# (tool returns are sometimes serialized rather than structured).
_PAYLOAD_PRINTABLE_JSON_RE = re.compile(r'"payload_printable"\s*:\s*"[^"]')


def _content_has_payload_printable(obj: Any, depth: int = 0) -> bool:
    """Recursively walk tool-return content for a non-empty
    ``payload_printable`` value (B5).

    Tool returns can be pydantic models, dicts, lists, or JSON-encoded
    strings depending on the tool and PydanticAI version — handle all
    four shapes, conservatively returning False on anything unwalkable.
    """
    if depth > 10:
        return False
    if hasattr(obj, "model_dump"):
        try:
            obj = obj.model_dump(mode="json")
        except Exception:
            return False
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "payload_printable" and isinstance(v, str) and v.strip():
                return True
            if _content_has_payload_printable(v, depth + 1):
                return True
        return False
    if isinstance(obj, (list, tuple)):
        return any(_content_has_payload_printable(v, depth + 1) for v in obj)
    if isinstance(obj, str):
        if "payload_printable" not in obj:
            return False
        try:
            parsed = json.loads(obj)
        except (json.JSONDecodeError, TypeError):
            return bool(_PAYLOAD_PRINTABLE_JSON_RE.search(obj))
        return _content_has_payload_printable(parsed, depth + 1)
    return False


def _coverage_cap(
    confidence: float,
    rubric: Any,
    required: set[str],
    cap: float = 0.6,
) -> tuple[float, list[str]]:
    """Apply the coverage cap.

    Returns ``(capped_confidence, missing_fields)``. ``missing_fields``
    is the list of required rubric fields that were False; empty when
    coverage is complete.

    Confidence is reduced ONLY when below-floor coverage is detected
    AND the original confidence was above the cap. Already-low-
    confidence reports pass through unchanged so we don't lift their
    floor accidentally.
    """
    if rubric is None:
        return confidence, []
    missing: list[str] = []
    for field_name in required:
        value = getattr(rubric, field_name, False)
        if not bool(value):
            missing.append(field_name)
    if missing and confidence > cap:
        return cap, missing
    return confidence, missing


# Substantive-token regex for semantic citation resolution.
# A token is alphanumeric-led + 2+ chars of word/dot/slash/dash. Colons
# and `=` are NOT in the class so they split tokens — necessary for
# forms like ``community_id:1:abc=`` to yield separate tokens that each
# can be checked independently against the bundle JSON.
_FUZZY_TOKEN_RE = re.compile(r"[A-Za-z0-9][\w./\-]{2,}")

# GATE C: generic tokens that must never, on their own, resolve a citation
# semantically. A citation that "matches" the bundle only on one of these (or on
# a short generic substring) is hollow — it proves the model echoed a common word,
# not that it cited a specific piece of evidence. Distinctive values (JA3 hashes,
# IPs, domains, SPNs, file names) are long and/or unambiguous and still resolve.
_CITATION_STOP_WORDS: frozenset[str] = frozenset(
    {
        "rule",
        "name",
        "tag",
        "alert",
        "event",
        "true",
        "false",
        "the",
        "and",
        "for",
        "with",
        "dataset",
        "suricata",
        "zeek",
        "type",
        "field",
        "value",
        "source",
        "dest",
        "destination",
        "host",
        "port",
        "proto",
        "protocol",
        "src",
        "dst",
        "flow",
        "conn",
        "data",
        "info",
        "note",
        "metadata",
        "signature",
        "category",
        "severity",
        "message",
        "http",
        "dns",
        "null",
    }
)


def _bundle_dump_text(alert_ctx: Any) -> str:
    """Lower-cased JSON dump of the prefetch bundle for substring matching."""
    try:
        import json as _json  # noqa: PLC0415

        return _json.dumps(alert_ctx.model_dump(mode="json"), default=str).lower()
    except Exception:
        return ""


def _resolve_citations(
    citations: list[str],
    alert_ctx: Any,
    transcripts: list[Any],
    *,
    messages: list[Any] | None = None,
) -> dict[str, Any]:
    """Semantic citation resolution — returns continuous coverage_ratio.

    Replaces the legacy `_validate_citations` shape-strict
    gatekeeper. The old logic classified each citation into
    path/tool/id/unknown and required path-strict walks against
    ``alert_ctx.model_dump()``. Some reasoning models emit citations as
    bare IPs, ``host.name=foo`` forms, free-text quotes, and other
    shapes that the strict classifier rejected wholesale — which then
    cascaded through the multiplicative confidence cap and the floor
    rewrite to erase valid verdicts. This was the
    dominant failure mode for those models.

    The new resolver tries (in order):

    1. **Strict path** — same dotted-path walk against alert_ctx.
    2. **Strict tool** — same ToolCallPart-history check.
    3. **Strict id** — same long-alphanumeric check (model-trusted).
    4. **Semantic substring** — any substantive token from the citation
       (≥3 chars of `[A-Za-z0-9][\\w./:\\-]+`) must appear (case-
       insensitive) in the bundle's JSON dump.

    Resolutions through (4) count as valid; the per_citation entry
    records `kind="semantic"` so audit can distinguish them. Empty
    citation lists return coverage_ratio=1.0 (vacuous truth — no
    missing evidence to penalize).

    Returns:
        ``{counts, total, invalid_examples, valid_citations,
        coverage_ratio, invalid_ratio, per_citation}``. ``invalid_ratio``
        is preserved (= 1.0 - coverage_ratio) for downstream-consumer
        backward compat. ``valid_citations`` retains ALL citations
        (resolved or not) so the published TriageReport doesn't lose
        the model's narrative — the cap reflects coverage instead.
    """
    counts = {"valid": 0, "strict": 0, "semantic": 0, "unresolved": 0}
    invalid_examples: list[str] = []
    per_citation: list[dict[str, Any]] = []

    bundle_text: str | None = None  # lazy

    for c in citations:
        kind, target = _classify_citation(c)
        resolved = False
        resolution_kind = "unresolved"

        if kind == "id":
            resolved = True
            resolution_kind = "strict_id"
        elif kind == "path":
            if target and _path_exists_in_alert(alert_ctx, target):
                resolved = True
                resolution_kind = "strict_path"
        elif kind == "tool":
            if target and _tool_was_invoked(transcripts, target, messages=messages):
                resolved = True
                resolution_kind = "strict_tool"

        if not resolved:
            # Fall back to semantic substring match: any substantive
            # token from the citation appearing in the bundle dump
            # counts as a resolution.
            if bundle_text is None:
                bundle_text = _bundle_dump_text(alert_ctx)
            tokens = _FUZZY_TOKEN_RE.findall(c)
            for tok in tokens:
                low = tok.lower()
                # GATE C: a citation may resolve semantically only on a
                # DISTINCTIVE token — never a stop-word, and never a bare short
                # generic substring. A token qualifies when it is either
                #   (a) long (>= 8 chars — JA3 hashes, sha256, full IPs, SPNs):
                #       a substring match is enough, OR
                #   (b) medium (>= 5 chars — a domain label like "c2.xyz", a
                #       hyphenated host "evil-server", a short FQDN): it must match
                #       on WORD BOUNDARIES, not as a fragment of a longer word.
                # Tokens carry dots/hyphens/slashes (_FUZZY_TOKEN_RE), so the (b)
                # path must NOT require ``isalnum`` — that would drop every domain
                # and dotted IP. This kills hollow <=4-char / generic-word
                # "resolutions" while preserving resolution of specific values.
                if low in _CITATION_STOP_WORDS:
                    continue
                if len(tok) >= 8 and low in bundle_text:
                    resolved = True
                    resolution_kind = "semantic"
                    break
                if len(tok) >= 5 and re.search(rf"\b{re.escape(low)}\b", bundle_text):
                    resolved = True
                    resolution_kind = "semantic"
                    break

        if resolved:
            counts["valid"] += 1
            if resolution_kind == "semantic":
                counts["semantic"] += 1
            else:
                counts["strict"] += 1
        else:
            counts["unresolved"] += 1
            if len(invalid_examples) < 5:
                invalid_examples.append(c[:160])

        per_citation.append(
            {"citation": c, "kind": kind, "resolved": resolved, "resolution_kind": resolution_kind}
        )

    total = len(citations)
    coverage_ratio = counts["valid"] / total if total > 0 else 1.0
    invalid_ratio = 1.0 - coverage_ratio
    return {
        "counts": counts,
        "total": total,
        "invalid_examples": invalid_examples,
        # `valid_citations` retains the full list — we don't strip in v2.
        "valid_citations": list(citations),
        "coverage_ratio": coverage_ratio,
        "invalid_ratio": invalid_ratio,
        "per_citation": per_citation,
    }


# Backward-compat alias for any external callers / tests still using the
# old name. New code should use `_resolve_citations` directly.
_validate_citations = _resolve_citations

# The confidence a CONFIRMED escalation (true_positive grounded in a concrete IOC
# hit or a cited decisive pivot) is floored to — so a correct catch the model
# reported at 0.60-0.68 isn't scored as an under-confident near-miss.
_ESCALATION_CONF_FLOOR = 0.70


def _citation_confidence_cap(
    confidence: float,
    coverage_ratio: float | None = None,
    floor: float = 0.4,
    *,
    invalid_ratio: float | None = None,
) -> float:
    """Banded-penalty confidence cap based on citation coverage.

    Replaces the legacy multiplicative-to-zero scaling that erased
    valid verdicts when citation shape didn't match the strict
    classifier. New behavior: banded multipliers based on the
    semantic ``coverage_ratio`` from :func:`_resolve_citations`, with
    a hard ``floor`` so confidence never drops below 0.4 due to
    citation issues alone.

    Bands:

    - ``coverage_ratio >= 0.75`` → 1.0x (no penalty)
    - ``coverage_ratio >= 0.50`` → 0.9x
    - ``coverage_ratio >= 0.25`` → 0.75x
    - ``coverage_ratio  < 0.25`` → 0.5x

    The ``floor`` parameter (default 0.4) is the absolute lower bound
    on the capped confidence — the cap pipeline can shave confidence
    but cannot zero it out. The verdict floor (synthesis_confidence_
    floor, default 0.6) is a separate concept handled by the floor
    rewrite, which is now evidence-conditional.

    Backward compatibility: callers passing the legacy ``invalid_ratio``
    kwarg get auto-converted (coverage = 1 - invalid_ratio).
    """
    if coverage_ratio is None:
        coverage_ratio = 1.0 - invalid_ratio if invalid_ratio is not None else 1.0

    if coverage_ratio >= 0.75:
        multiplier = 1.0
    elif coverage_ratio >= 0.5:
        multiplier = 0.9
    elif coverage_ratio >= 0.25:
        multiplier = 0.75
    else:
        multiplier = 0.5

    capped = confidence * multiplier
    # Floor caps the REDUCTION, not the original. If the original
    # confidence is already below ``floor``, we don't promote it up to
    # ``floor`` — the floor's purpose is to prevent the cap from
    # erasing confidence, not to inflate genuine low-confidence
    # reports.
    effective_floor = min(floor, confidence)
    return max(capped, effective_floor)


def _no_semantic_evidence(report: Any, coverage_ratio: float) -> bool:
    """True when the report carries no semantic citation evidence.

    Either no citations at all, OR the citation coverage_ratio from
    `_resolve_citations` is below 0.25 (catastrophic unresolvable
    evidence). B3: shared by the synth-first AND legacy verdict-floor
    rewrites so both pipelines apply the same evidence-conditional gate —
    a well-evidenced verdict must survive low confidence on either path.
    """
    return len(report.citations) == 0 or coverage_ratio < 0.25


def _synth_first_post_validate(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext
    candidate: Any,  # CandidateVerdict | None — from decision_templates.match_decision_template
    *,
    targeted_messages: list[Any] | None = None,
    targeted_tool_called: str | None = None,
    synthesis_confidence_floor: float = 0.6,
    blocklist: BlocklistDB | None = None,
    internal_cidrs: Sequence[Any] | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Apply citation + floor validators to a synth-first TriageReport.

    Returns (validated_report, audit_dict). The audit_dict carries the
    intermediate validator results so the orchestrator can emit SSE events
    (citation_validation, citation_cap, verdict_floor_rewrite) in order.

    The validators applied:

    1. Citation validation — same ``_validate_citations`` as legacy, walking
       paths against ``enriched_ctx`` and IDs against the prefetch
       pivots. Tool refs only valid if matching the Phase-D targeted call
       (when one ran).
    2. Citation cap — same ``_citation_confidence_cap`` scaling by invalid_ratio.
    3. Verdict floor rewrite — if final confidence < synthesis_confidence_floor
       (0.6 default), set verdict=needs_more_info and clear recommended_actions.

    Coverage cap is NOT applied to synth-first runs because the orchestrator
    didn't run an investigator — there's no tool-call ledger to compute
    rubric coverage from. (The template-confidence ceiling that used to fill
    that role was removed — see the note in the body.)

    ``blocklist`` / ``internal_cidrs`` are forwarded to
    :func:`_apply_targeted_downgrades` (solicited-ICMP downgrade): the
    singleton BlocklistDB backs the explicit IOC lookup on contexts without
    enrichments, and ``internal_cidrs`` is the *effective* internal CIDR set
    (``settings.internal_cidrs`` union active ``cidr`` identifier rows minus muted,
    resolved once per investigation; falls back to ``settings.internal_cidrs``
    when there is no DB) so the internal-IP fallback aligns with the enriched
    path. Defaults (``None``) preserve the historical behavior for callers that
    don't thread the resolved set.
    """
    from soc_ai.agent.triage import InvestigationTranscript  # noqa: PLC0415

    audit: dict[str, Any] = {}

    # Citation resolution. No investigator transcripts exist
    # for synth-first; tool refs only valid for the Phase-D targeted call.
    synthetic_transcripts: list[Any] = []
    if targeted_tool_called is not None:
        synthetic_transcripts.append(
            InvestigationTranscript(
                evidence=[f"targeted dispatch: {targeted_tool_called}"],
                tentative_summary="",
                open_questions=[],
            )
        )
    citation_validation = _resolve_citations(
        report.citations, enriched_ctx, synthetic_transcripts, messages=targeted_messages
    )
    audit["citation_validation"] = citation_validation

    # Banded confidence cap. Always apply (cap is a no-op when coverage
    # is full); never zero-out. Preserves all citations — we don't
    # strip in v2; the cap reflects coverage instead.
    coverage_ratio = citation_validation["coverage_ratio"]
    original_conf = report.confidence
    new_conf = _citation_confidence_cap(original_conf, coverage_ratio=coverage_ratio)
    if new_conf != original_conf:
        report = report.model_copy(update={"confidence": new_conf})
        audit["citation_cap"] = {
            "original_confidence": original_conf,
            "capped_confidence": new_conf,
            "coverage_ratio": coverage_ratio,
            "invalid_ratio": 1.0 - coverage_ratio,  # legacy field
        }

    # Template-confidence ceiling REMOVED. The synthesizer
    # LLM reasons over the real alert + enrichments even on the fast path, so the
    # confidence it reports is its actual assessment — clamping it to the generic
    # template constant overrode real signal. Confidence stays the model's own,
    # still grounded by the citation cap above and the verdict floor below.

    # Evidence-conditional confidence FLOOR (recall-v2 calibration).
    # A settled true_positive grounded in a CONCRETE decisive signal — a
    # blocklist/MISP IOC hit, or a cited decisive pivot record (JA3 pair, RC4
    # Kerberos ticket, PE delivery, exfil asymmetry, completed SSH login, beacon/
    # tunnel profile) — is not a hedge case. The model routinely lands a correct
    # escalation at 0.60-0.68; that under-confidence then reads as a detection miss
    # (and can trip the verdict-floor rewrite below). Floor it to the escalation
    # confidence. Only RAISES, only for true_positive, only when real gathered
    # evidence is present — so it can never manufacture a false escalation
    # (precision is measured on benign scenarios, which are never true_positive).
    if (
        report.verdict == "true_positive"
        and report.confidence < _ESCALATION_CONF_FLOOR
        and (
            _has_ioc_hit(enriched_ctx) or _verdict_cites_decisive_pivot_value(report, enriched_ctx)
        )
    ):
        audit["confidence_floor_raise"] = {
            "original_confidence": report.confidence,
            "floored_confidence": _ESCALATION_CONF_FLOOR,
            "grounded_by": "ioc_hit" if _has_ioc_hit(enriched_ctx) else "decisive_pivot_value",
            "reason": (
                "true_positive grounded in a concrete IOC / decisive pivot — a "
                "confirmed catch, floored to escalation confidence rather than "
                "left as an under-confident hedge"
            ),
        }
        report = report.model_copy(update={"confidence": _ESCALATION_CONF_FLOOR})

    # Evidence-conditional verdict floor rewrite.
    # Coerce verdict to needs_more_info ONLY when:
    #   - confidence is strictly below floor, AND
    #   - there is no semantic evidence: either no citations at all, OR
    #     the citation coverage_ratio is below 0.25 (catastrophic
    #     unresolvable evidence).
    # Otherwise keep the verdict label — citation-shape brittleness in
    # the validator must not erase a verdict whose reasoning is sound.
    # Previously the floor rewrite fired on confidence alone, which under
    # some models' varied citation shapes turned valid verdicts into
    # `unknown`/`needs_more_info`.
    no_evidence = _no_semantic_evidence(report, coverage_ratio)
    # `inconclusive` (the self-consistency split outcome) is already a terminal
    # non-committed verdict — like needs_more_info, it is never rewritten here.
    if (
        report.confidence < synthesis_confidence_floor
        and report.verdict not in ("needs_more_info", "inconclusive")
        and no_evidence
    ):
        audit["verdict_floor_rewrite"] = {
            "original_verdict": report.verdict,
            "capped_verdict": "needs_more_info",
            "confidence": report.confidence,
            "floor": synthesis_confidence_floor,
            "coverage_ratio": coverage_ratio,
            "n_citations": len(report.citations),
            "reason": (
                "confidence below floor AND no semantic citation coverage; "
                "verdict label coerced to needs_more_info"
            ),
        }
        report = report.model_copy(
            update={
                "verdict": "needs_more_info",
                "recommended_actions": [],
            }
        )

    # ----- Targeted verdict downgrades -----
    # Shared with the legacy pipeline's finalization (B2) so both paths
    # apply the same evidence-aware overrides.
    report = _apply_targeted_downgrades(
        report, enriched_ctx, audit, blocklist=blocklist, internal_cidrs=internal_cidrs
    )

    # ----- GATE A: malware-rule-name payload gate (#21) -----
    # "Content match is not corroboration." A true_positive on an alert whose
    # rule name / metadata SIGNALS a malware family (ET MALWARE, a named-tool
    # signature, a malware_family tag) must be grounded in a CONCRETE IOC hit OR
    # a cited decisive typed pivot VALUE (JA3/JA3S, file hash, Kerberos SPN, SMB
    # name, DCE-RPC endpoint) — never the rule label alone. Anchoring a TP on the
    # signature name is the BPFDoor false-escalation pattern (a benign gateway↔Mac
    # ping called TP because the rule said "BPFDoor"). When neither corroboration
    # is present, downgrade to needs_more_info so the alert is investigated rather
    # than rationalized from its own label.
    #
    # Runs AFTER _apply_targeted_downgrades so the deterministic solicited-internal
    # -ICMP-echo TP→FP downgrade is already applied and its verdict is no longer
    # true_positive here — that FP defense is preserved. The malware predicate is
    # evaluated defensively: if it can't be assessed for this context (e.g. a
    # partial/mock ctx that only backs model_dump), the gate fails OPEN and leaves
    # the verdict unchanged rather than manufacturing a downgrade.
    #
    # A TP that survived a REAL investigation — a successful tool call in the loop
    # transcript, or a Phase-D targeted dispatch — is corroborated beyond the rule
    # label and is exempt (mirrors the hard evidence gate). The gate targets the
    # zero-investigation "rule name says malware → TP" rationalization.
    has_tool_evidence = (
        count_successful_tool_calls(targeted_messages) >= 1 or targeted_tool_called is not None
    )
    if report.verdict == "true_positive" and not has_tool_evidence:
        try:
            from soc_ai.agent.decision_templates import (  # noqa: PLC0415
                _rule_signals_malware,
            )

            rule_is_malware = _rule_signals_malware(enriched_ctx)
        except Exception:
            rule_is_malware = False
        if (
            rule_is_malware
            and not _has_ioc_hit(enriched_ctx)
            and not _verdict_cites_decisive_pivot_value(report, enriched_ctx)
        ):
            audit["malware_rule_name_ungrounded_downgrade"] = {
                "original_verdict": report.verdict,
                "capped_verdict": "needs_more_info",
                "original_confidence": report.confidence,
                "reason": (
                    "true_positive on a malware-signalling rule name with no "
                    "concrete IOC hit and no cited decisive pivot value — the rule "
                    "label is not corroboration; coerced to needs_more_info for "
                    "investigation"
                ),
            }
            report = report.model_copy(
                update={
                    "verdict": "needs_more_info",
                    "confidence": min(report.confidence, 0.4),
                }
            )

    # ----- Ungrounded host-anchored TP downgrade -----
    # Catches the defect where the LLM escalates to TP solely because the
    # host_alert_profile lists malware/C2 rules (which may themselves be FPs)
    # and the external IP has no reputation — with zero per-alert evidence.
    report = _downgrade_ungrounded_host_anchored_tp(report, enriched_ctx, audit)

    # ----- Hard evidence gate (zero-tool-verdict defense) -----
    # FINAL backstop: a settled TP/FP that rests on prefetched fields with no
    # successful tool call and no strong rule-grounded template is a
    # rationalization, not a finding — coerce it to needs_more_info. Runs LAST so
    # the deterministic, prefetch-grounded downgrades above (the solicited-ICMP
    # FP) are already applied and exempt.
    report = _downgrade_unevidenced_verdict(
        report,
        enriched_ctx,
        candidate,
        audit,
        targeted_messages=targeted_messages,
        targeted_tool_called=targeted_tool_called,
    )

    return report, audit


# Module-level frozenset so it is built once rather than per call.
# Lowercase tokens — matched against lower-cased summary + citations.
# C2-vocabulary additions (M2): heartbeat, keep-alive, interval variants, timed.
_GROUNDED_EVIDENCE_TOKENS: frozenset[str] = frozenset(
    {
        "beacon",
        "payload",
        "lateral",
        "exfil",
        "c2 traffic",
        "c2 session",
        "command and control traffic",
        "pcap",
        "encoded",
        "periodic",
        "cadence",
        "mimikatz",
        "powershell",
        "meterpreter",
        "cobalt",
        # C2-vocabulary additions (M2) — reduce recall gap on timing-based C2
        "heartbeat",
        "keep-alive",
        "keepalive",
        "interval",
        "regular interval",
        "timed",
    }
)


def _downgrade_ungrounded_host_anchored_tp(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext | AlertContext
    audit: dict[str, Any],
) -> Any:
    """Downgrade a TP that rests solely on host_alert_profile + absence of reputation.

    Catches the systemic false-positive escalation pattern (BPFDoor / VPN ICMP,
    confirmed on both Qwen and DeepSeek) where the LLM escalates to
    true_positive because:
      (a) host_alert_profile lists a malware/C2 rule (which may itself be a FP), AND
      (b) the external IP has no reputation ("novel C2" inference from silence).

    Downgrade conditions — ALL must hold (conservative: when in doubt, leave TP):
      1. verdict is true_positive
      2. host_alert_profile is non-empty (the anchor exists)
      3. No per-alert malicious evidence:
         a. No blocklist_hits or misp_hits on ANY indicator in enrichments
         b. The focus alert's own signature is NOT a malware/exploit/attack class
            (checked via _alert_signals_malware + _ATTACK_CLASSTYPES) — if THIS
            alert is itself a confirmed-malware-class signature we leave the TP
         c. No concrete beacon/payload/lateral evidence cited in summary or
            citations (conservative keyword scan; false negative preferred over
            false positive here)

    When ALL conditions hold the verdict is downgraded to needs_more_info at
    confidence 0.5 with recommended_actions cleared and a corrective prefix on
    the summary.
    """
    if report.verdict != "true_positive":
        return report

    # Gate 2: host_alert_profile must be non-empty (the anchor).
    try:
        host_profile = getattr(enriched_ctx, "host_alert_profile", None) or {}
    except Exception:
        return report
    if not host_profile:
        return report

    # Gate 3a: any enrichment IOC hit → leave the TP.
    try:
        d = enriched_ctx.model_dump(mode="json")
    except Exception:
        return report
    enrichments = d.get("enrichments") or {}
    for e in enrichments.values():
        if isinstance(e, dict) and (e.get("blocklist_hits") or e.get("misp_hits")):
            return report  # has real IOC evidence — do not downgrade

    # Gate 3b: focus alert is itself a malware/exploit/attack-class signature
    # (i.e. the TP rests on THIS alert's own malware signal, not just context).
    try:
        from soc_ai.agent.decision_templates import (  # noqa: PLC0415
            _ATTACK_CLASSTYPES,
            _alert_signals_malware,
        )

        alert_obj = getattr(enriched_ctx, "alert", None)
        if alert_obj is not None:
            if _alert_signals_malware(alert_obj):
                return report  # this alert IS malware-class — leave the TP
            classtype = (getattr(alert_obj, "classtype", None) or "").lower()
            if classtype in _ATTACK_CLASSTYPES:
                return report  # attack-class classtype — leave the TP
    except Exception:
        return report  # import or attribute failure → conservatively leave TP

    # Gate 3c: conservative scan of summary + citations for concrete payload/
    # beacon/lateral evidence. If found, we leave the TP to protect recall.
    # Uses the module-level _GROUNDED_EVIDENCE_TOKENS frozenset (built once).
    summary_lower = (report.summary or "").lower()
    citations_text = " ".join(str(c) for c in (report.citations or [])).lower()
    combined = summary_lower + " " + citations_text
    for token in _GROUNDED_EVIDENCE_TOKENS:
        if token in combined:
            return report  # concrete evidence cited — leave the TP

    # All gates passed: downgrade to needs_more_info.
    original_summary = report.summary or ""
    downgrade_reason = (
        "TP rested solely on host_alert_profile context and/or absence of "
        "reputation (no per-alert IOC hit, focus alert is not malware-class, "
        "no beacon/payload/lateral evidence cited)"
    )
    audit["ungrounded_host_anchored_tp_downgrade"] = {
        "original_verdict": "true_positive",
        "downgraded_verdict": "needs_more_info",
        "reason": downgrade_reason,
        "original_summary": original_summary,
    }
    # Lead with the correct conclusion; the agent's original text and the
    # override reason move to validator_note. No confusing inline bracket.
    corrected_summary = (
        "Insufficient per-alert evidence to confirm this as a true positive. "
        "The verdict rested on the host's alert history and absence of "
        "reputation, not on direct evidence in this alert. "
        "Re-investigate to ground a verdict in per-alert evidence."
    )
    validator_note = (
        "Verdict auto-corrected true_positive→needs_more_info by the "
        "ungrounded-host-anchored-TP validator. "
        + downgrade_reason
        + " Original agent summary: "
        + original_summary
    )
    return report.model_copy(
        update={
            "verdict": "needs_more_info",
            "confidence": min(report.confidence, 0.5),
            "recommended_actions": [],
            "summary": corrected_summary,
            "validator_note": validator_note,
        }
    )


def _apply_targeted_downgrades(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext | AlertContext
    audit: dict[str, Any],
    *,
    blocklist: BlocklistDB | None = None,
    internal_cidrs: Sequence[Any] | None = None,
) -> Any:
    """Apply final verdict-level targeted downgrades; returns the report.

    B2: extracted from `_synth_first_post_validate` so the LEGACY pipeline
    (still used when ``synth_first_pipeline`` is off) applies
    the identical overrides — it previously reproduced the BPFDoor false
    escalation unmitigated. Audit entries are written into ``audit`` under
    the same keys both pipelines emit as SSE events
    (``icmp_solicited_downgrade``).

    Solicited-ICMP-echo TP downgrade: a true_positive resting
    on a solicited internal ICMP echo reply (Zeek type-8 request → type-0
    reply, both RFC1918, no IOC hit) is a noisy-signature false escalation
    (e.g. the "ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat" FP cluster),
    not C2. Downgrade to false_positive. Scoped strictly to solicited ICMP
    echo so it cannot regress internal lateral-movement TPs (SMB/Kerberos),
    which are not ping exchanges.

    ``blocklist`` is the per-process singleton :class:`BlocklistDB` (the
    same one the enrich_* tools receive — ``ctx.blocklist``); it backs the
    EXPLICIT IOC lookup required on contexts that carry no enrichments
    (legacy ``AlertContext``). ``internal_cidrs`` is the *effective* internal
    CIDR set (``settings.internal_cidrs`` union active ``cidr`` identifier rows minus
    muted, resolved once per investigation; falls back to
    ``settings.internal_cidrs`` when there is no DB) so the no-enrichment
    internal fallback uses the operator's effective definition of "internal",
    matching the enriched path. The audit ``reason`` names the verification that
    actually ran on the path taken — enrichment-derived vs explicit lookup.
    """
    ioc_verification = (
        _is_solicited_internal_icmp_echo(
            enriched_ctx, blocklist=blocklist, internal_cidrs=internal_cidrs
        )
        if report.verdict == "true_positive"
        else None
    )
    if ioc_verification is not None:
        if ioc_verification == "explicit_blocklist_lookup":
            # Legacy/no-enrichment path: state ONLY what ran — an explicit
            # blocklist probe on both endpoints. No MISP/enrichment check
            # happened here, so the reason must not claim one.
            reason = (
                "solicited internal ICMP echo reply (ping response: Zeek "
                "type-8 request → type-0 reply, both internal; explicit "
                "blocklist lookup clean on both endpoints — no enrichment "
                "context on this path, MISP not consulted) — not a covert "
                "beacon; the malware rule label is an uncorroborated "
                "content match"
            )
        else:
            reason = (
                "solicited internal ICMP echo reply (ping response: Zeek "
                "type-8 request → type-0 reply, both internal, no blocklist/"
                "MISP hit) — not a covert beacon; the malware rule label is "
                "an uncorroborated content match"
            )
        original_summary = report.summary or ""
        audit["icmp_solicited_downgrade"] = {
            "original_verdict": "true_positive",
            "downgraded_verdict": "false_positive",
            "reason": reason,
            "original_summary": original_summary,
        }
        # Lead the summary with the correct conclusion; move the override
        # explanation and the agent's original text to validator_note so
        # nothing is lost, just relocated. This avoids the confusing pattern
        # of a "[Auto-corrected…]" bracket followed by the agent's wrong
        # narrative still narrating C2 under an FP verdict.
        corrected_summary = (
            "Solicited internal ICMP echo request/reply between two internal "
            "hosts — a benign ping exchange. The ET MALWARE signature matched "
            "on packet content only; there are no corroborating C2 indicators "
            "(no beacon cadence, blocklist/MISP hit, or payload evidence)."
        )
        validator_note = (
            "Verdict auto-corrected true_positive→false_positive by the "
            "solicited-ICMP-echo validator. "
            + reason
            + " Original agent summary: "
            + original_summary
        )
        report = report.model_copy(
            update={
                "verdict": "false_positive",
                "recommended_actions": [],
                "confidence": min(report.confidence, 0.8),
                "summary": corrected_summary,
                "validator_note": validator_note,
            }
        )

    return report


def _is_strong_grounded_template(candidate: Any, enriched_ctx: Any) -> bool:
    """True iff *candidate* is a STRONG, rule-grounded BENIGN template match that
    is safe to settle WITHOUT an investigation.

    A strong benign template (clean-internal / STUN-QUIC / NTP / DNSSEC / benign-
    cloud, confidence ≥ 0.8) is a deterministic verdict grounded in the rule +
    locality — not the model's reading of prefetch — so it is an acceptable
    evidence-substitute for the hard evidence gate. Explicitly excluded:
    EXTERNAL-reputation templates (which force investigation), and any
    malware/attack-class rule (a dangerous rule is never fast-settled benign).
    The 0.8 floor keeps the weaker TP templates (e.g. C2-classtype @ 0.65) out —
    those rules also signal malware/attack and are force-investigated anyway.

    NOTE: ``informational_external_clean_benign_cloud`` is confidence exactly 0.8
    and PASSES this threshold — its exclusion relies entirely on the
    ``EXTERNAL_REPUTATION_TEMPLATES`` guard below. Do not remove that guard
    without also tightening this threshold to ``> 0.8``.
    """
    if candidate is None:
        return False
    if getattr(candidate, "confidence", 0.0) < 0.8:
        return False
    from soc_ai.agent.decision_templates import (  # noqa: PLC0415 — avoid circular import
        EXTERNAL_REPUTATION_TEMPLATES,
        _rule_signals_attack,
        _rule_signals_malware,
    )

    if getattr(candidate, "template_id", None) in EXTERNAL_REPUTATION_TEMPLATES:
        return False
    return not (_rule_signals_malware(enriched_ctx) or _rule_signals_attack(enriched_ctx))


def _has_ioc_hit(enriched_ctx: Any) -> bool:
    """True iff any enrichment indicator carries a blocklist or MISP hit.

    A concrete IOC match is real evidence that GROUNDS a verdict — the
    enrichment layer matched a known-bad indicator, not the model reading alert
    metadata. So it exempts the hard evidence gate (same signal the
    ungrounded-host-anchored-TP downgrade uses to leave a TP alone).
    """
    try:
        d = enriched_ctx.model_dump(mode="json")
    except Exception:
        return False
    for e in (d.get("enrichments") or {}).values():
        if isinstance(e, dict) and (e.get("blocklist_hits") or e.get("misp_hits")):
            return True
    return False


# Pivot event attributes whose values are distinctive enough to prove a verdict was
# grounded in correlated evidence when cited (a JA3, a file hash, a Kerberos SPN, a
# service binary name, an RPC endpoint — not generic fields like a port or state).
_PIVOT_DECISIVE_ATTRS: tuple[str, ...] = (
    "zeek_ssl_ja3",
    "zeek_ssl_ja3s",
    "zeek_files_sha256",
    "zeek_files_md5",
    "zeek_kerberos_service",
    "zeek_kerberos_cipher",
    "zeek_smb_name",
    "zeek_dce_rpc_endpoint",
    "zeek_dce_rpc_operation",
)
_PIVOT_ATTRS: tuple[str, ...] = (
    "community_id_events",
    "host_events",
    "user_events",
    "process_events",
    "file_events",
)


def _pivot_evidence_tokens(enriched_ctx: Any) -> set[str]:
    """Distinctive lowercased tokens from prefetched PIVOT documents — their ES ids
    plus decisive typed values (JA3/JA3S, file hashes, Kerberos SPN, SMB file name,
    DCE-RPC endpoint). A verdict that cites one of these is grounded in correlated
    evidence the orchestrator gathered, not in the alert's own label."""
    tokens: set[str] = set()
    for attr in _PIVOT_ATTRS:
        for ev in getattr(enriched_ctx, attr, None) or []:
            eid = getattr(ev, "id", None)
            if eid:
                tokens.add(str(eid).lower())
            for f in _PIVOT_DECISIVE_ATTRS:
                v = getattr(ev, f, None)
                if isinstance(v, str) and len(v) >= 4:
                    tokens.add(v.lower())
    return tokens


def _verdict_grounded_in_pivot(report: Any, enriched_ctx: Any) -> bool:
    """True iff the settled verdict CITES correlated pivot evidence the orchestrator
    prefetched — a pivot doc's ES id, or one of its decisive typed values, appears in
    the report's citations.

    Prefetch pivots ARE gathered evidence: the orchestrator ran the community_id /
    host fan-out as a tool call on the agent's behalf, so a verdict grounded in a
    pivot record is not a zero-investigation rationalization. A verdict that cites
    only the alert's own fields matches nothing here and stays gated — the QVOD
    zero-tool-verdict defense is preserved. The value match is unforgeable: a cited
    JA3/hash/SPN can only match a pivot the model was actually shown."""
    tokens = _pivot_evidence_tokens(enriched_ctx)
    if not tokens:
        return False
    cited = " ".join(str(c) for c in (getattr(report, "citations", None) or [])).lower()
    if not cited:
        return False
    return any(tok in cited for tok in tokens)


def _verdict_cites_decisive_pivot_value(report: Any, enriched_ctx: Any) -> bool:
    """Stricter cousin of :func:`_verdict_grounded_in_pivot`: the verdict must cite a
    decisive typed pivot VALUE (a JA3/JA3S, a file hash, a Kerberos SPN, an SMB file
    name, a DCE-RPC endpoint) — NOT merely a pivot doc's ES id.

    The id-inclusive check is right for the anti-hallucination hard gate ("did the
    agent use gathered evidence?"), but for RAISING confidence a bare doc id is not
    enough — every alert has correlated pivots, so citing one proves nothing about
    maliciousness. Flooring confidence to the escalation level requires a concrete
    malicious-leaning signal the model actually cited."""
    values: set[str] = set()
    for attr in _PIVOT_ATTRS:
        for ev in getattr(enriched_ctx, attr, None) or []:
            for f in _PIVOT_DECISIVE_ATTRS:
                v = getattr(ev, f, None)
                if isinstance(v, str) and len(v) >= 4:
                    values.add(v.lower())
    if not values:
        return False
    cited = " ".join(str(c) for c in (getattr(report, "citations", None) or [])).lower()
    return bool(cited) and any(v in cited for v in values)


# Keys on a tool result that are bookkeeping / classification flags, NOT gathered
# evidence — a result carrying only these did not discriminate anything.
_NON_EVIDENCE_RESULT_KEYS = frozenset(
    {
        "error",
        "ok",
        "available",
        "reason",
        "hint",
        "internal",
        "indicator",
        "indicator_type",
        "query",
        "ip",
        "domain",
        "hash",
        "algo",
        "note",
    }
)


def _targeted_result_has_data(result: Any) -> bool:
    """True iff a Phase-D targeted-tool result carries DISCRIMINATING evidence.

    Mirrors :func:`count_successful_tool_calls`' "non-error DATA" semantics: an
    empty-but-non-error dict — an OQL/zeek query with zero hits, ``enrich_ip`` on
    an internal IP with no blocklist/MISP hit — gathered nothing and must NOT
    exempt the hard evidence gate.

    Rather than enumerate every data-bearing field (fragile — tools return many
    shapes: hits, sni_servers, dns_queries, asn, prevalence flags…), a result has
    data iff it carries ANY truthy value under a key that is not a bookkeeping /
    classification flag. Search-shaped results (``total``/``hits``) are judged on
    hit count so a zero-hit query is correctly empty.
    """
    if not isinstance(result, dict) or result.get("error"):
        return False
    # Search-shaped result (OQL / zeek / cases): data iff there are hits.
    if "total" in result or "hits" in result:
        return bool(result.get("total")) or bool(result.get("hits"))
    # Otherwise: any non-bookkeeping key with a truthy value is gathered evidence.
    return any(v for k, v in result.items() if k not in _NON_EVIDENCE_RESULT_KEYS)


def _downgrade_unevidenced_verdict(
    report: Any,  # TriageReport
    enriched_ctx: Any,  # EnrichedAlertContext
    candidate: Any,  # CandidateVerdict | None
    audit: dict[str, Any],
    *,
    targeted_messages: list[Any] | None,
    targeted_tool_called: str | None,
) -> Any:
    """HARD evidence gate — the zero-tool-verdict defense.

    A settled verdict (``true_positive`` / ``false_positive``) must rest on REAL
    evidence:

    * at least one SUCCESSFUL tool call from the investigation loop
      (``count_successful_tool_calls(targeted_messages) >= 1``), OR
    * a Phase-D targeted-tool dispatch (``targeted_tool_called is not None``), OR
    * a strong, rule-grounded benign template (:func:`_is_strong_grounded_template`).

    Otherwise the verdict is a rationalization of prefetched alert fields with no
    investigation behind it (the QVOD / zero-tool-TP defect) and is coerced to
    ``needs_more_info`` — the honest "not yet investigated" state — with
    confidence capped and recommended actions cleared. Records ``audit
    ['evidence_gate_downgrade']`` when it fires.

    Runs LAST in the validator chain so the deterministic, prefetch-grounded
    downgrades that PRODUCE a settled verdict (the solicited-ICMP-echo TP→FP) are
    already applied and exempt — that FP is grounded in typed Zeek, not a guess.
    """
    if report.verdict not in ("true_positive", "false_positive"):
        return report
    # Exempt a verdict that a deterministic, prefetch-grounded validator produced
    # (the solicited-ICMP-echo FP). The audit key is code-set, so it can't be
    # spoofed by the model populating a report field.
    if "icmp_solicited_downgrade" in audit:
        return report
    tool_calls = count_successful_tool_calls(targeted_messages)
    has_tool_evidence = tool_calls >= 1 or targeted_tool_called is not None
    # A strong template only grounds a verdict that AGREES with it — a synth that
    # OVERRODE a strong benign template (e.g. escalated a clean-internal alert to
    # TP) is not grounded by that template and must still be gated.
    strong_template = _is_strong_grounded_template(candidate, enriched_ctx) and (
        getattr(candidate, "verdict", None) == report.verdict
    )
    grounded_in_pivot = _verdict_grounded_in_pivot(report, enriched_ctx)
    if (
        has_tool_evidence
        or strong_template
        or _has_ioc_hit(enriched_ctx)  # grounded in a concrete blocklist/MISP IOC
        or grounded_in_pivot  # grounded in a cited, orchestrator-prefetched pivot record
    ):
        if grounded_in_pivot and not (has_tool_evidence or strong_template):
            audit["evidence_gate_pivot_exemption"] = {
                "reason": (
                    "verdict cites correlated pivot evidence the orchestrator "
                    "prefetched (community_id/host fan-out) — gathered evidence, "
                    "not a zero-investigation rationalization"
                ),
            }
        return report

    capped_conf = min(report.confidence, 0.4)
    audit["evidence_gate_downgrade"] = {
        "original_verdict": report.verdict,
        "capped_verdict": "needs_more_info",
        "original_confidence": report.confidence,
        "capped_confidence": capped_conf,
        "successful_tool_calls": tool_calls,
        "targeted_tool_called": targeted_tool_called,
        "reason": (
            "settled verdict with no investigation evidence — no successful tool "
            "call and no strong rule-grounded template; a prefetch-only "
            "rationalization, coerced to needs_more_info"
        ),
    }
    note = (
        " (Downgraded to needs_more_info by the evidence gate: this verdict rested "
        "on prefetched alert fields with no investigation — no tool was run to "
        "confirm it. Re-run to investigate.)"
    )
    return report.model_copy(
        update={
            "verdict": "needs_more_info",
            "confidence": capped_conf,
            "recommended_actions": [],
            "summary": (getattr(report, "summary", "") or "") + note,
        }
    )


def _is_solicited_internal_icmp_echo(
    enriched_ctx: Any,
    *,
    blocklist: BlocklistDB | None = None,
    internal_cidrs: Sequence[Any] | None = None,
) -> Literal["enrichment", "explicit_blocklist_lookup"] | None:
    """If the alert is a solicited ICMP echo exchange between two internal
    hosts with a verified-clean IOC posture, return WHICH
    verification ran; else ``None`` (no downgrade).

    Return values:
      - ``"enrichment"`` — the context carried per-indicator enrichments
        and none had ``blocklist_hits`` / ``misp_hits`` (synth-first path).
      - ``"explicit_blocklist_lookup"`` — the context carried NO
        enrichments (legacy ``AlertContext``), so both endpoint IPs were
        explicitly probed clean against ``blocklist`` (the same singleton
        :class:`BlocklistDB` the enrich_* tools use — covers the
        operator-curated ``internal_seed.yaml`` known-bad internal hosts).
      - ``None`` — any gate failed, including: blocklist unavailable
        (``None`` / zero loaded sources) or its lookup raising on the
        no-enrichment path. Absence of proof is not proof; wrongly
        suppressing a real TP is worse than letting a false escalation
        through.

    Reads the prefetch via ``model_dump`` (consistent with the citation
    resolver) so it works against both real EnrichedAlertContext objects
    and test doubles. Requires ALL of:
      - typed_zeek.icmp_echo_request_reply (Zeek saw type-8 → type-0), AND
      - both alert endpoints internal, AND
      - a clean IOC verification per the modes above.
    Conservative by construction: a missing zeek.conn pivot, an external
    endpoint, or any IOC hit all return ``None`` (we never suppress
    without positive benign evidence).

    B2: the legacy pipeline's prefetch is a plain ``AlertContext`` — typed
    Zeek fields are never materialized on it (only the synth-first
    ``EnrichedAlertContext`` carries them). When the dump has no
    ``typed_zeek`` block at all, derive it on the fly from the
    community_id pivot's Zeek conn records via the same
    ``parse_typed_zeek_fields`` the enriched prefetch uses, so both
    pipelines see the identical ICMP-echo signal.

    "Internal" for an IP WITHOUT an enrichment entry means membership in
    ``internal_cidrs`` (``settings.internal_cidrs``) when provided — the
    same definition ``enrich_ip`` uses — so a deployment with
    internal_cidrs narrower than RFC1918 gets identical semantics on both
    pipelines. The ipaddress ``is_private|is_loopback|is_link_local``
    fallback applies ONLY when ``internal_cidrs`` is empty/unset.
    """
    try:
        d = enriched_ctx.model_dump(mode="json")
    except Exception:
        return None
    typed_zeek = d.get("typed_zeek") or {}
    if not typed_zeek:
        from soc_ai.enrichment.zeek_parser import parse_typed_zeek_fields  # noqa: PLC0415

        try:
            pivots = getattr(enriched_ctx, "community_id_events", None) or []
            typed_zeek = parse_typed_zeek_fields(pivots).model_dump(mode="json")
        except Exception:
            return None
    if not typed_zeek.get("icmp_echo_request_reply"):
        return None
    alert = d.get("alert") or {}
    enrichments = d.get("enrichments") or {}

    def _internal(ip: str | None) -> bool:
        if not ip:
            return False
        e = enrichments.get(ip)
        if isinstance(e, dict) and "internal" in e:
            return bool(e["internal"])
        try:
            from ipaddress import ip_address  # noqa: PLC0415

            addr = ip_address(ip)
        except ValueError:
            return False
        if internal_cidrs:
            return any(addr in net for net in internal_cidrs)
        return bool(addr.is_private or addr.is_loopback or addr.is_link_local)

    src_ip = alert.get("source_ip")
    dst_ip = alert.get("destination_ip")
    if not (_internal(src_ip) and _internal(dst_ip)):
        return None
    if enrichments:
        for e in enrichments.values():
            if isinstance(e, dict) and (e.get("blocklist_hits") or e.get("misp_hits")):
                return None
        return "enrichment"
    # No enrichment entries (legacy AlertContext): the IOC loop above would
    # be vacuous, so demand EXPLICIT proof — both endpoints clean in the
    # same blocklist source the enrichment tools consult. Unavailable or
    # erroring blocklist → no downgrade (fail toward keeping the TP).
    if blocklist is None:
        _LOGGER.debug("icmp downgrade skipped: no blocklist available for explicit proof")
        return None
    try:
        if not blocklist.loaded_sources:
            _LOGGER.debug("icmp downgrade skipped: blocklist has zero loaded sources")
            return None
        if src_ip is None or dst_ip is None:
            _LOGGER.debug("icmp downgrade skipped: endpoint IP missing from alert")
            return None
        if blocklist.lookup_ip(src_ip) or blocklist.lookup_ip(dst_ip):
            return None
    except Exception:
        return None
    return "explicit_blocklist_lookup"


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
        # No recognized list field — fall back to flag-only.
        return cast("T", {**value, "__truncated__": True, "__total_bytes__": len(encoded)})
    # Strings / numbers — stringify + clip.
    text = str(value)
    return cast("T", text[: _TOOL_RESULT_BUDGET_BYTES - 100] + " …[truncated]")


_DUPLICATE_HINT = (
    "Same args were already called this investigation. Result hasn't changed; "
    "calling again wastes the budget. Pivot to a different field, time window, "
    "or tool — or proceed to emitting the transcript."
)


def _dedup_result(
    ctx: InvestigationContext, tool_name: str, args: dict[str, Any]
) -> dict[str, Any] | None:
    """Return a structured duplicate-call payload if this exact call was seen.

    None when not a duplicate. The investigator's tool wrappers consult
    this and short-circuit on duplicates rather than running the
    underlying tool again.
    """
    if not ctx.dedup.is_duplicate(tool_name, args):
        return None
    return {
        "duplicate_call": True,
        "tool_name": tool_name,
        "args": args,
        "hint": _DUPLICATE_HINT,
    }


def build_investigator(  # noqa: PLR0915 - tool registrations are inherently long
    model: Model,
    ctx: InvestigationContext,
    *,
    system_prompt: str | None = None,
) -> Agent[None, InvestigationTranscript]:
    """Investigator agent: fast model + read tools + InvestigationTranscript output.

    Closures capture ``ctx`` so the LLM-facing tool signatures stay
    semantic-only (no auth/elastic/etc. parameters in the schema).

    ``system_prompt`` overrides the default :data:`INVESTIGATOR_PROMPT`.

    The coverage gate previously lived here as an
    ``output_validator`` raising ``ModelRetry``. Smoke testing surfaced a
    pathological interaction: PydanticAI's ``retries`` budget is shared
    between schema-validation retries (Nemotron-30B routinely needs 2-3
    attempts to land a schema-valid InvestigationTranscript) AND
    output_validator retries. The combined retry budget exhausted before
    the model could produce a schema-valid transcript. The coverage gate
    was removed; the existing ``coverage_cap`` (which downgrades
    confidence + the synthesis-floor retask) already produces equivalent
    behavior — missing enrichment caps confidence below the floor and
    triggers retask. ``retries=5`` gives schema validation room.
    """
    agent: Agent[None, InvestigationTranscript] = Agent(
        model,
        output_type=InvestigationTranscript,
        system_prompt=system_prompt or INVESTIGATOR_PROMPT,
        # 10 retries is generous on a per-output basis but Nemotron-30B's
        # schema-format wobble is genuinely stochastic (some runs land in
        # 2 attempts, others need 8+). The per-investigation request_limit
        # still bounds the worst case, and a failed alert burns ~10 quick
        # retries (each emitting almost no output) which is cheaper than
        # an unrecoverable run.
        retries=10,
    )

    @agent.tool_plain
    async def t_query_events_oql(
        query: str,
        time_range_minutes: int = 60,
        max_results: int = 100,
    ) -> dict[str, Any]:
        """Run a validated OQL query against the SO events index.

        The window is centered on the alert's `@timestamp` automatically
        (without this, tools default to now-1h, return empty for batch
        alerts, and burn a retask round). Default `time_range_minutes`
        of 60 means ±30 min around the alert. Pass a larger value if you
        need wider context (e.g. 360 = ±3h).
        """
        if dup := _dedup_result(
            ctx,
            "t_query_events_oql",
            {"query": query, "time_range_minutes": time_range_minutes, "max_results": max_results},
        ):
            return dup
        # Hard ceiling — defends the 64K window even when the model asks for
        # a larger result set than makes sense.
        max_results = min(max_results, 25)
        try:
            result = await query_events_oql(
                query,
                elastic=ctx.elastic,
                settings=ctx.settings,
                time_range_minutes=time_range_minutes,
                max_results=max_results,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            _LOGGER.warning("t_query_events_oql failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result.model_dump(mode="json"))

    # Note: no `t_get_alert_context` tool is registered for the investigator
    # since the orchestrator pre-fetches the alert context and embeds it in
    # the user prompt. The fast 30B was unable to consistently honor a
    # "do not call this tool" rubric — removing the tool entirely is the
    # only reliable way to enforce the contract. If a future iteration
    # needs secondary-alert context, expose it through a renamed tool
    # (`t_get_other_alert_context(alert_id)`) so the model can't
    # accidentally re-fetch the alert under triage.

    @agent.tool_plain
    async def t_describe_dataset(dataset: str) -> dict[str, Any]:
        """Discover the fields POPULATED on a dataset (e.g. `zeek.ssh`, `endpoint`,
        `windows.security`) by sampling recent docs — field names + example values +
        coverage. Use it to learn a dataset's schema before querying it (network or
        host)."""
        return await describe_dataset(dataset, elastic=ctx.elastic, settings=ctx.settings)

    @agent.tool_plain
    async def t_field_values(
        field: str, dataset: str | None = None, size: int = 25
    ) -> dict[str, Any]:
        """List the top VALUES a field takes (terms aggregation), optionally within one
        dataset — e.g. what `rule.name`s fire or which `event.dataset`s are present."""
        return await field_values(
            field, elastic=ctx.elastic, settings=ctx.settings, dataset=dataset, size=size
        )

    @agent.tool_plain
    async def t_query_cases(
        query: str,
        status: str | None = None,
        max_results: int = 25,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search SOC cases by free-text + optional status filter."""
        if dup := _dedup_result(
            ctx,
            "t_query_cases",
            {"query": query, "status": status, "max_results": max_results},
        ):
            return dup
        max_results = min(max_results, 10)
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

    @agent.tool_plain
    async def t_query_detections(
        query: str, max_results: int = 25
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search SOC detection rules by free-text."""
        if dup := _dedup_result(
            ctx, "t_query_detections", {"query": query, "max_results": max_results}
        ):
            return dup
        max_results = min(max_results, 10)
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

    @agent.tool_plain
    async def t_query_zeek_logs(
        community_id: str,
        log_types: list[str] | None = None,
        time_range_minutes: int = 60,
        max_results: int = 100,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Pivot into Zeek logs by network.community_id.

        Window centered on the alert's `@timestamp`. Default
        `time_range_minutes=60` means ±30 min around the alert; widen
        only if the agent needs longer-tail correlation.
        """
        # Read-prefetch-first rule: if this community_id is
        # already in the prefetched community_id_events, don't re-query.
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
        max_results = min(max_results, 25)
        try:
            zeek_rows = await query_zeek_logs(
                community_id,
                elastic=ctx.elastic,
                settings=ctx.settings,
                log_types=log_types,
                time_range_minutes=time_range_minutes,
                max_results=max_results,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            _LOGGER.warning("t_query_zeek_logs failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(zeek_rows)

    @agent.tool_plain
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
            )
        except Exception as e:
            _LOGGER.warning("t_host_summary failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @agent.tool_plain
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
            )
        except Exception as e:
            _LOGGER.warning("t_prevalence failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @agent.tool_plain
    async def t_rule_prevalence(rule_name: str, lookback_days: int = 30) -> dict[str, Any]:
        """Base-rate / noisiness of a Suricata detection rule across the estate.

        Answers whether this rule is NOISY (fires constantly across many hosts —
        so its next firing is likely benign HERE and is weak evidence) or RARE /
        FIRST-SEEN (a firing is notable). Call this whenever the verdict leans on
        a rule label: before trusting the signature name, check whether that
        signature is a constant-firing nuisance on this grid. Returns
        total_fires, distinct src/dest hosts, first/last seen, fires_per_day, and
        a noisiness bucket. READ-ONLY and zero-egress.
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
            )
        except Exception as e:
            _LOGGER.warning("t_rule_prevalence failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @agent.tool_plain
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
            ctx, "t_suggest_rule_tuning", {"rule_name": rule_name, "lookback_days": lookback_days}
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
    if ctx.settings.allow_online_enrichment:

        @agent.tool_plain
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

        @agent.tool_plain
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

        @agent.tool_plain
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

        @agent.tool_plain
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

    @agent.tool_plain
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

        When pcap_enabled=False (the default) this returns a descriptive error
        dict immediately without any network I/O.
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

    @agent.tool_plain
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
        internal IP is refused. When web_search_enabled=False this returns a
        descriptive error without any network I/O.
        """
        if dup := _dedup_result(ctx, "t_web_search", {"query": query}):
            return dup
        try:
            result = await web_search(query, settings=ctx.settings)
        except Exception as e:
            _LOGGER.warning("t_web_search failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @agent.tool_plain
    async def t_crawl_page(url: str) -> dict[str, Any]:
        """Deep-read the full content of an EXTERNAL web page (via crawl4ai).

        Use this AFTER web_search to read a promising result in full when the
        snippet isn't enough — e.g. open the reputation/abuse/threat-intel page
        for a domain or IP and read what it actually says. Returns the page's
        readable content (markdown), title, and a truncation flag.

        Pass a single external URL (typically one returned by web_search).

        SAFETY: crawl4ai fetches the URL server-side, so EXTERNAL URLs ONLY —
        an internal IP/host/localhost is refused (don't be steered into reading
        an internal service). When crawl4ai_enabled=False this returns a
        descriptive error without any network I/O.
        """
        if dup := _dedup_result(ctx, "t_crawl_page", {"url": url}):
            return dup
        try:
            result = await crawl_page(url, settings=ctx.settings)
        except Exception as e:
            _LOGGER.warning("t_crawl_page failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(result)

    @agent.tool_plain
    async def t_get_playbooks(
        alert_id: str | None = None,
        max_results: int = 25,
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Pull playbooks; optionally scoped to a given alert's linked rule."""
        if dup := _dedup_result(
            ctx, "t_get_playbooks", {"alert_id": alert_id, "max_results": max_results}
        ):
            return dup
        max_results = min(max_results, 10)
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

    @agent.tool_plain
    async def t_enrich_ip(ip: str) -> dict[str, Any]:
        """Enrich an IP via internal-CIDR check + optional MISP lookup."""
        if dup := _dedup_result(ctx, "t_enrich_ip", {"ip": ip}):
            return dup
        try:
            result_obj = await enrich_ip(ip, settings=ctx.settings, misp=ctx.misp)
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_ip failed: %s", e)
            return _tool_error(e)
        # Record successful enrichment in the global cache so a
        # subsequent alert can satisfy the fast-path eligibility gate.
        try:
            from soc_ai.agent.enrichment_cache import get_global_cache  # noqa: PLC0415

            get_global_cache().put(ip, result_obj)
        except Exception as cache_err:
            _LOGGER.warning("enrichment cache put (t_enrich_ip) failed: %s", cache_err)
        return _clamp_tool_result(result)

    @agent.tool_plain
    async def t_enrich_domain(domain: str) -> dict[str, Any]:
        """Enrich a domain via optional MISP lookup."""
        if dup := _dedup_result(ctx, "t_enrich_domain", {"domain": domain}):
            return dup
        try:
            result_obj = await enrich_domain(domain, settings=ctx.settings, misp=ctx.misp)
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_domain failed: %s", e)
            return _tool_error(e)
        # Parity with t_enrich_ip's cache write.
        # Note: is_fast_path_eligible only ever probes destination IPs, so
        # domain entries serve cross-alert enrichment reuse, not gating.
        try:
            from soc_ai.agent.enrichment_cache import get_global_cache  # noqa: PLC0415

            get_global_cache().put(domain, result_obj)
        except Exception as cache_err:
            _LOGGER.warning("enrichment cache put (t_enrich_domain) failed: %s", cache_err)
        return _clamp_tool_result(result)

    @agent.tool_plain
    async def t_enrich_hash(hash_value: str, algo: str) -> dict[str, Any]:
        """Enrich a file hash via optional MISP lookup."""
        if dup := _dedup_result(ctx, "t_enrich_hash", {"hash_value": hash_value, "algo": algo}):
            return dup
        try:
            result_obj = await enrich_hash(hash_value, algo, settings=ctx.settings, misp=ctx.misp)
            result = result_obj.model_dump(mode="json")
        except Exception as e:
            _LOGGER.warning("t_enrich_hash failed: %s", e)
            return _tool_error(e)
        # Parity with t_enrich_ip's cache write.
        # Note: is_fast_path_eligible only ever probes destination IPs, so
        # hash entries serve cross-alert enrichment reuse, not gating.
        try:
            from soc_ai.agent.enrichment_cache import get_global_cache  # noqa: PLC0415

            get_global_cache().put(hash_value, result_obj)
        except Exception as cache_err:
            _LOGGER.warning("enrichment cache put (t_enrich_hash) failed: %s", cache_err)
        return _clamp_tool_result(result)

    @agent.tool_plain
    async def t_lookup_runbook(query: str, k: int = 5) -> list[dict[str, Any]] | dict[str, Any]:
        """Search the operator's own runbooks (keyword/tag/rule-linked)."""
        if dup := _dedup_result(ctx, "t_lookup_runbook", {"query": query, "k": k}):
            return dup
        k = min(k, 5)
        try:
            rows = await lookup_runbook(query, k=k, db_sessionmaker=ctx.db_sessionmaker)
        except Exception as e:
            _LOGGER.warning("t_lookup_runbook failed: %s", e)
            return _tool_error(e)
        return _clamp_tool_result(rows)

    return agent


def build_synthesizer(model: Model) -> Agent[None, TriageReport]:
    """Synthesizer agent: heavy model, no tools, TriageReport output.

    The synthesizer reads the investigator's transcript (passed as the user
    message) and emits a TriageReport. It has no tools — synthesis happens
    entirely from the gathered evidence.
    """
    return Agent(
        model,
        output_type=TriageReport,
        system_prompt=SYNTHESIZER_PROMPT,
    )


def build_synth_first_agent(model: Model) -> Agent[None, TriageReport]:
    """Build the synth Agent for the synth-first pipeline (no tools).

    Identical to build_synthesizer except it uses the synth-first system
    prompt that includes the gap_for_investigator + decision-template
    rules.

    ``retries=3`` (vs pydantic_ai's default of 1) gives some reasoning
    models multiple chances to emit valid
    TriageReport JSON. Repeated batches showed a recurring fraction of
    synth alerts failing with ``UnexpectedModelBehavior: Exceeded maximum
    retries (1) for output validation`` — the same scenarios across runs,
    so the schema-validation retry budget was the bottleneck, not a
    transient model fault.
    """
    from soc_ai.agent.prompts import SYNTH_FIRST_SYSTEM_PROMPT  # noqa: PLC0415

    return Agent(
        model=model,
        system_prompt=SYNTH_FIRST_SYSTEM_PROMPT,
        output_type=TriageReport,
        retries=3,
    )


def _synth_failure_fallback_report(alert_id: str, phase: str, exc: BaseException) -> Any:
    """Build a fallback TriageReport when the synth-first model raises.

    When the synth fails schema-validation
    retries (UnexpectedModelBehavior) or any other exception, the
    pipeline previously emitted an ``error`` event and returned without
    a ``triage_report``. That produced ``verdict=None`` rows in
    ``index.jsonl`` that were unscoreable. Now we synthesize a low-
    confidence ``needs_more_info`` report from the failure so the row is
    structured and the downstream post-validators + audit run uniformly.

    The fallback report:

    - ``verdict='needs_more_info'`` (correct: we genuinely don't know)
    - ``confidence=0.3`` (visibly low — analyst sees it's a fallback)
    - ``summary`` names the failure phase + exception type
    - ``citations=['synth_first_failure']`` (single audit-trail marker)
    - ``gap_for_investigator=None`` (don't recurse into Phase D)
    """
    from soc_ai.agent.triage import TriageReport  # noqa: PLC0415

    return TriageReport(
        verdict="needs_more_info",
        confidence=0.3,
        summary=(
            f"Synth-first pipeline fallback: {phase} raised "
            f"{type(exc).__name__}. The alert is recorded as "
            f"needs_more_info pending investigator-path retry. "
            f"Underlying error: {str(exc)[:200]}"
        ),
        citations=["synth_first_failure"],
        recommended_actions=[],
        gap_for_investigator=None,
    )


def _round2_failure_fallback(alert_id: str, round1: Any, exc: BaseException) -> Any:
    """Fallback verdict when the round-2 investigation loop / synth crashes.

    The agent already reached a round-1 verdict before the (expensive, flakier)
    round-2 path ran — don't discard it on a round-2 crash. If round-1 settled on
    a confident verdict, land THAT (annotated in the summary so the operator sees
    round-2 didn't finish) rather than erroring the whole run with no verdict. If
    round-1 was itself inconclusive (skipped / untriaged), fall back to the
    needs_more_info synth-failure report.
    """
    settled = {"true_positive", "false_positive"}
    verdict = getattr(round1, "verdict", None)
    if round1 is not None and verdict in settled:
        note = (
            f" (Round-2 deep investigation did not complete: {type(exc).__name__}; "
            "showing the round-1 verdict.)"
        )
        try:
            return round1.model_copy(
                update={"summary": (getattr(round1, "summary", "") or "") + note}
            )
        except Exception:
            return round1
    return _synth_failure_fallback_report(alert_id, "investigation_loop_synth", exc)


# Backwards-compat shim — pre-split callers used `build_agent(model, ctx)`
# and assumed Agent[None, TriageReport]. Their tests build a single agent
# manually; route to the synthesizer (no tools) since that produces the
# TriageReport. Tests that need tool-calling now build the investigator
# directly.
def build_agent(  # pragma: no cover - thin alias
    model: Model, ctx: InvestigationContext
) -> Agent[None, TriageReport]:
    """Deprecated: use build_investigator + build_synthesizer."""
    return build_synthesizer(model)


# =====================================================================
# Investigation runner
# =====================================================================


def _hint_for(exc: BaseException) -> str | None:
    """Return a short, actionable hint string for the analyst, or None."""
    if isinstance(exc, OqlValidationError):
        frag = getattr(exc, "fragment", None)
        base = "OQL validator rejected the query"
        if frag:
            return (
                f"{base}; offending fragment: {frag!r}. "
                "Common pitfall: use full ECS field names like 'destination.ip', "
                "not shortened ones like 'dest.ip'."
            )
        return f"{base}; check field names against the OQL primer."
    if isinstance(exc, SoApiError):
        return "alert id may be wrong; verify it exists in ES."
    msg = str(exc).lower()
    # Pattern-match on the LiteLLM/PydanticAI error strings.
    if "contextwindowexceeded" in msg or "context length" in msg:
        return (
            "context window exceeded; transcript or prompt is too large. "
            "If this happened on retask, the round-1 transcript may be huge; "
            "if on round 1, the alert context may exceed the model's window."
        )
    if "timed out" in msg or "timeout" in msg:
        return "LiteLLM gateway slow or unreachable; retry."
    # Generic transport-layer "can't reach the host" — fires when SO/ES is
    # restarting, the network is down, etc.
    if "cannot connect to host" in msg or "connection error" in msg or "connection refused" in msg:
        return (
            "elasticsearch / Security Onion unreachable. Verify the SO grid is "
            "online and ES_HOSTS in soc-ai's .env points at the right node."
        )
    return None


def _error_payload(exc: BaseException, *, phase: str, round_num: int) -> dict[str, Any]:
    """Typed error event payload with phase/round/type/message + optional hint."""
    payload: dict[str, Any] = {
        "phase": phase,
        "round": round_num,
        "type": type(exc).__name__,
        "message": str(exc),
    }
    hint = _hint_for(exc)
    if hint:
        payload["hint"] = hint
    return payload


def _compact_alert_context(ac: Any) -> dict[str, Any]:
    """Slim an AlertContext for embedding in the fast model's user prompt.

    Three reductions, all bounded:

    - **Drop `message` from each SoAlert.** That field carries the full
      Suricata/Zeek JSON payload (often 1-2 KB per event). We pre-parse the high-signal
      bits (``rule_metadata``, ``dns_query``, ``alert_action``) into
      first-class typed fields BEFORE this function runs, so the agent
      gets the signal without paying the bytes.
    - **Drop empty optional fields from each pivot event.** Suricata/Zeek
      schemas have ~20 nullable fields per doc; serializing all of them
      doubles the per-event footprint with zero signal. We keep only the
      fields the typed view actually populated.
    - **Cap each pivot at 3 events.** The investigator can still call
      `t_query_zeek_logs` if it needs to enumerate further; the prompt
      only seeds the picture.

    The full AlertContext is still surfaced unmodified via the
    `alert_context` SSE event for analyst visibility — only the prompt copy
    is slimmed.
    """

    def _slim(a: Any) -> dict[str, Any]:
        d = a.model_dump(mode="json", exclude_none=True)
        # `message` already replaced by typed fields (rule_metadata,
        # dns_query, alert_action) at SoAlert construction time;
        # dropping the raw blob keeps the prompt under budget.
        d.pop("message", None)
        # Empty list / empty-string fields are noise for the model.
        return {k: v for k, v in d.items() if v not in ([], "", {})}

    return {
        "alert": _slim(ac.alert),
        "community_id_events": [_slim(e) for e in ac.community_id_events[:_COMPACT_PIVOT_CAP]],
        "host_events": [_slim(e) for e in ac.host_events[:_COMPACT_PIVOT_CAP]],
        "user_events": [_slim(e) for e in ac.user_events[:_COMPACT_PIVOT_CAP]],
        "process_events": [_slim(e) for e in ac.process_events[:_COMPACT_PIVOT_CAP]],
        "file_events": [_slim(e) for e in ac.file_events[:_COMPACT_PIVOT_CAP]],
        "pivot_summary": ac.pivot_summary,
        # Wide host-risk profile: the endpoint IPs' recent alert histogram
        # (rule_name → count over ±host_risk_window_hours). Surfaces a
        # compromised host the ±5-min pivots miss — if this lists RAT/C2/malware
        # signatures, the host is implicated and this alert is post-exploitation
        # context, not isolated east-west traffic.
        "host_alert_profile": getattr(ac, "host_alert_profile", {}) or {},
    }


def _format_investigator_prompt(
    alert_id: str, alert_context_json: str, focus_hint: str | None = None
) -> str:
    """Investigator user message including pre-fetched alert context.

    Removes one source of non-determinism: the fast model used to skip
    `t_get_alert_context` and hallucinate alert details. With the context
    pre-loaded, every run starts from the same factual base.

    The header explicitly names the typed fields the orchestrator
    pre-parses (``rule_metadata.signature_severity``,
    ``dns_query``, ``alert_action``, ``event_module``) so the agent
    consults them before reaching for tools — many ET INFO alerts can
    be evaluated almost entirely from these fields.
    """
    from soc_ai.agent.prompts import format_focus_hint_block  # noqa: PLC0415

    return (
        f"Triage alert {alert_id}.\n\n"
        f"{format_focus_hint_block(focus_hint)}"
        f"## Pre-fetched alert context\n\n"
        f"```json\n{alert_context_json}\n```\n\n"
        f"## Read these typed fields FIRST\n\n"
        f"The orchestrator has already parsed Suricata's nested fields and "
        f"any Zeek pivot fields. Before reaching for tools, consult:\n\n"
        f"- `alert.rule_metadata.signature_severity` — `Informational` / "
        f"`Minor` / `Major` / `Critical`. Informational + clean pivots is "
        f"a strong false-positive signal on its own; cite this field by "
        f"path in your evidence.\n"
        f"- `alert.rule_metadata.attack_target` / `confidence` / "
        f"`deployment` — secondary classifiers; cite by path when "
        f"relevant.\n"
        f"- `alert.alert_action` / `alert.event_action` — what the "
        f"detection actually did (`allowed` vs `blocked`). Already-blocked "
        f"alerts rarely need escalation.\n"
        f"- `alert.payload_printable` — the actual matched packet bytes "
        f"rendered as text. For DNS rules this is the queried domain; "
        f"for SSL the SNI; for HTTP the request line + headers. Read this "
        f"BEFORE inferring intent from rule_name. NOTE: do NOT cite "
        f"`alert.dns_query` for Suricata alerts — that field is None on "
        f"Suricata events because SO's pipeline pollutes it with the "
        f"rule's `content:` match.\n"
        f"- `alert.event_module` / `event.dataset` — module + dataset that "
        f"fired (e.g. `suricata` / `suricata.alert`).\n"
        f"- For each entry in `community_id_events` whose dataset starts "
        f"with `zeek.`, typed fields `zeek_conn_state`, `zeek_conn_history`, "
        f"`zeek_dns_query`, `zeek_dns_rcode_name`, `zeek_dns_rejected`, "
        f"`zeek_ssl_server_name`, `zeek_http_method`, `zeek_http_host`, "
        f"`zeek_http_status` carry the protocol-specific signal directly. "
        f"Cite these by path (e.g. `community_id_events.0.zeek_ssl_server_name`). "
        f"(These typed fields are ALREADY resolved ECS-first from the live grid: "
        f"on a modern SO the data lives in ECS names — `dns.query.name`, "
        f"`client.bytes`/`server.bytes`, `connection.state`, `hash.ja3s`, "
        f"`ssl.server_name`, `http.virtual_host` — with the `zeek.*` names as the "
        f"fallback; prefer the ECS names when writing an OQL pivot.)\n"
        f"- If `prefetch_parse_errors` is non-empty, fall back to `raw` "
        f"on those fields.\n\n"
        f"## Your job\n\n"
        f"The alert and its initial pivots (community_id, host, user, "
        f"process, file) are already gathered above. Use the OTHER read "
        f"tools to enrich indicators (`t_enrich_ip`, `t_enrich_domain`, "
        f"`t_enrich_hash`), query Zeek logs by community_id "
        f"(`t_query_zeek_logs`), look up related cases or detections, and "
        f"consult playbooks. Do NOT call `t_get_alert_context` for this "
        f"alert — its context is already above.\n"
    )


def _format_transcript_for_synthesizer(
    alert_id: str,
    rounds: list[InvestigationTranscript],
    candidate: Any = None,
) -> str:
    """Render investigator transcripts into the synthesizer's user message.

    When a decision-template *candidate* is supplied, render it as a PRIOR the
    synthesizer anchors on — keeping the verdict stable unless the gathered
    evidence directly contradicts it. This prevents over-calling a benign
    external host ``true_positive`` on rule-name suspicion alone (the verdict
    swing seen on repeated hunts) while preserving the loop's ability to overturn
    the prior when the investigation actually finds contradicting evidence.
    """
    parts: list[str] = [f"Alert under triage: {alert_id}", ""]
    if candidate is not None:
        parts.append("## Decision-template prior (heuristic, NOT a mandate)")
        parts.append(
            f"- verdict=`{getattr(candidate, 'verdict', '?')}` "
            f"confidence={getattr(candidate, 'confidence', '?')} "
            f"template=`{getattr(candidate, 'template_id', '?')}`"
        )
        rationale = getattr(candidate, "rationale", None)
        if rationale:
            parts.append(f"- rationale: {rationale}")
        parts.append("")
        parts.append(
            "Anchor on this prior: KEEP it unless the investigation evidence below "
            "DIRECTLY contradicts it (e.g. web_search/enrichment shows the indicator is "
            "flagged malicious, or the packets show attack behaviour). Do NOT overturn a "
            "benign prior to true_positive on rule-name suspicion alone — the rule name is "
            "a claim; the gathered evidence is what decides."
        )
        parts.append("")
    for i, t in enumerate(rounds, start=1):
        label = (
            "Investigation transcript"
            if len(rounds) == 1
            else f"Investigation transcript (round {i})"
        )
        parts.append(f"## {label}")
        parts.append("")
        parts.append("### evidence")
        if t.evidence:
            parts.extend(f"- {item}" for item in t.evidence)
        else:
            parts.append("- (none)")
        parts.append("")
        parts.append("### tentative_summary")
        parts.append(t.tentative_summary or "(empty)")
        parts.append("")
        parts.append("### open_questions")
        if t.open_questions:
            parts.extend(f"- {q}" for q in t.open_questions)
        else:
            parts.append("- (none)")
        parts.append("")
    parts.append("Produce the final TriageReport now.")
    return "\n".join(parts)


_RETASK_MAX_EVIDENCE = 10
_RETASK_MAX_OPEN_QUESTIONS = 5
_RETASK_MAX_EVIDENCE_LEN = 240


def _format_retask_prompt(
    alert_id: str,
    prior: InvestigationTranscript,
    *,
    missing_rubric: list[str] | None = None,
    alert_ctx: Any = None,
    reason: str = "synthesis_below_floor",
) -> str:
    """Render the retask user message for the investigator's second pass.

    F4: when ``missing_rubric`` is non-empty, name each
    missing field AND the specific tool call that would satisfy it,
    pre-filled with the alert's actual identifiers (community_id, host,
    external IP, etc.). Earlier analysis flagged the previous
    "close the open questions" prompt as ineffective — round-2
    typically retread the same evidence.

    Bounded transcript injection: cap evidence and open_questions to
    keep the round-2 user message under ~3KB.
    """

    def _clip(text: str) -> str:
        text = text.strip()
        return (
            text
            if len(text) <= _RETASK_MAX_EVIDENCE_LEN
            else text[: _RETASK_MAX_EVIDENCE_LEN - 1] + "…"
        )

    evidence = [_clip(e) for e in (prior.evidence or [])][:_RETASK_MAX_EVIDENCE]
    if len(prior.evidence or []) > _RETASK_MAX_EVIDENCE:
        evidence.append(
            f"(… {len(prior.evidence) - _RETASK_MAX_EVIDENCE} more evidence items "
            "from round 1 omitted to fit the round-2 prompt budget)"
        )
    open_qs = [_clip(q) for q in (prior.open_questions or [])][:_RETASK_MAX_OPEN_QUESTIONS]

    lines = [
        f"Re-investigate alert {alert_id} (round 2; reason: {reason}).",
        "",
        "Your prior round produced this transcript:",
        "",
        "### evidence",
    ]
    lines.extend(f"- {item}" for item in (evidence or ["(none)"]))
    lines += ["", "### open_questions"]
    lines.extend(f"- {q}" for q in (open_qs or ["(none)"]))

    # F4 targeted retask: name missing fields + specific tool calls.
    if missing_rubric:
        lines += ["", "### missing rubric coverage (close these in round 2)"]
        for field_name in missing_rubric:
            hint = _retask_tool_hint(field_name, alert_ctx)
            lines.append(f"- `{field_name}=False` → {hint}")

    lines += [
        "",
        "Close the gaps above by calling the suggested tools. **Do NOT repeat",
        "tool calls whose results are already captured in `evidence`** — the",
        "orchestrator's dedup gate will short-circuit duplicates with a",
        "structured 'duplicate_call' result. Return a fresh",
        "InvestigationTranscript covering only the new findings; the",
        "synthesizer will OR-merge them with round 1.",
    ]
    return "\n".join(lines)


def _retask_tool_hint(field_name: str, alert_ctx: Any) -> str:
    """Return a tool-call hint string for a missing rubric field, with the
    alert's actual identifiers pre-filled where possible.

    F4: earlier analysis showed generic "gather more
    evidence" prompts didn't move the needle on round-2. Naming the
    specific tool + args gives the model a concrete next step.
    """
    alert = getattr(alert_ctx, "alert", None) if alert_ctx is not None else None
    community_id = getattr(alert, "network_community_id", None) if alert else None
    host_name = getattr(alert, "host_name", None) if alert else None
    dest_ip = getattr(alert, "destination_ip", None) if alert else None
    src_ip = getattr(alert, "source_ip", None) if alert else None
    payload = getattr(alert, "payload_printable", None) if alert else None
    file_hash = getattr(alert, "file_hash_sha256", None) if alert else None

    # Pick the most likely external-facing IP for enrichment hints.
    external_ip: str | None = None
    for cand in (dest_ip, src_ip):
        if not cand:
            continue
        try:
            from ipaddress import ip_address  # noqa: PLC0415

            addr = ip_address(cand)
            if not (addr.is_private or addr.is_loopback or addr.is_link_local):
                external_ip = cand
                break
        except (ValueError, TypeError):
            continue

    if field_name == "enrichment_called":
        if external_ip:
            return f"call `t_enrich_ip(ip={external_ip!r})` for the external IP"
        if file_hash:
            return f"call `t_enrich_hash(hash_value={file_hash!r}, algo='sha256')`"
        if payload:
            return (
                "extract any domain from `alert.payload_printable` "
                "and call `t_enrich_domain(domain='...')`"
            )
        return (
            "call `t_enrich_ip` / `t_enrich_domain` / `t_enrich_hash` "
            "on any external indicator the alert references"
        )

    if field_name == "dns_or_sni_pivoted":
        if community_id:
            return (
                f"call `t_query_zeek_logs(community_id={community_id!r}, "
                f"log_types=['dns','ssl'])` to pivot the conn's DNS/SSL records"
            )
        return (
            "call `t_query_zeek_logs(community_id=..., log_types=['dns','ssl'])` "
            "or read `alert.payload_printable` for the queried domain / SNI"
        )

    if field_name == "related_alerts_checked":
        if host_name:
            return (
                f'call `t_query_events_oql(query=\'host.name:"{host_name}" '
                f"AND event.kind:alert', time_range_minutes=1440)` — pivot on "
                f"host.name (NOT community_id, that's the same conn)"
            )
        return (
            'call `t_query_events_oql(query=\'host.name:"<host>" AND '
            "event.kind:alert', time_range_minutes=1440)` — pivot on host.name "
            "or user.name (NOT community_id, that's the same conn)"
        )

    if field_name == "playbook_consulted":
        return "call `t_get_playbooks(alert_id=...)` to retrieve the rule's runbook checklist"

    if field_name == "payload_inspected_if_banner_rule":
        return (
            "read `alert.payload_printable` and quote a relevant fragment "
            "in your evidence (cite as `(path alert.payload_printable)`)"
        )

    return f"satisfy the `{field_name}` rubric field"


def _is_high_stakes_alert(alert: SoAlert) -> bool:
    """Whether an alert is too high-stakes to auto-ack, even on a confident FP.

    Reuses the existing deterministic rule-class signals (no new classifier):

    - :func:`classify_alert` lands the alert in EXPLOIT_ATTEMPT / POST_COMPROMISE
      when its Suricata ``classtype`` or ``signature_severity`` declares an
      exploit / attack / malware / C2 family.
    - :func:`_alert_signals_malware` (from :mod:`decision_templates`) catches the
      malware/exploit token case where ``classtype`` is absent but the rule name
      or ``rule_metadata.metadata_tags`` carry a malware-family signal (the
      BPFDoor-style ET MALWARE label).
    - SO's own severity: ``severity_label`` of critical/high, or
      ``severity_score`` >= 3 (SO buckets 3=high, 4=critical).

    Any one of these makes the alert high-stakes. The verdict still stands —
    we just refuse to *auto-write* an ack on it.
    """
    from soc_ai.agent.decision_templates import _alert_signals_malware  # noqa: PLC0415 — circular

    if classify_alert(alert) in (AlertClass.EXPLOIT_ATTEMPT, AlertClass.POST_COMPROMISE):
        return True
    if _alert_signals_malware(alert):
        return True
    sev_label = (alert.severity_label or "").strip().lower()
    if sev_label in ("critical", "high"):
        return True
    return alert.severity_score is not None and alert.severity_score >= 3


async def maybe_auto_ack_fp(
    report: TriageReport,
    es_id: str,
    *,
    alert: SoAlert,
    ctx: InvestigationContext,
    emit_ev: Any,
    audit_ev: Any,
) -> StepEvent | None:
    """Auto-acknowledge a high-confidence FP alert in Security Onion.

    Called from both the synth-first and legacy finalization paths after the
    final verdict and confidence are settled (including Oracle adjudication).

    Gating (all must be true):
    - ``settings.auto_ack_fp_enabled`` is True
    - ``report.verdict == "false_positive"``
    - ``report.confidence >= settings.auto_ack_fp_threshold``
    - the alert is NOT high-stakes (see :func:`_is_high_stakes_alert`)

    The high-stakes guard is a blast-radius cap: a prompt-injected confident
    ``false_positive`` must never auto-ack a critical/high-severity or
    malware/exploit/attack-class alert. We skip the auto-write (the verdict is
    unchanged) and leave the ack to a human.

    Best-effort: any write error is logged as a warning and does NOT propagate.
    The investigation is never failed by auto-ack.

    The ack is written DIRECTLY (via :func:`execute_write_tool`) — it does NOT
    go through the human-approval gate. That is the whole point of the opt-in:
    ``auto_ack_fp_enabled`` is an explicit operator decision to let confident,
    low-stakes FP acks write to SO unattended. The audit logger is routed
    through so the unattended write is always recorded (fail-closed on intent).

    Coupling: this only runs from investigation finalisation, so an alert is
    auto-acked ONLY if it is investigated while the toggle is on — there is no
    retroactive backlog sweep. See ``Settings.auto_ack_fp_enabled`` for how this
    interacts with the auto-triage floor.

    Returns the ``auto_ack`` StepEvent (for the caller to yield into the stream)
    when the write was attempted, or ``None`` when any gate condition is unmet.
    """
    settings = ctx.settings
    if not settings.auto_ack_fp_enabled:
        return None
    if report.verdict != "false_positive":
        return None
    if (report.confidence or 0.0) < settings.auto_ack_fp_threshold:
        return None
    if _is_high_stakes_alert(alert):
        # Blast-radius cap: never auto-write an ack on a high-stakes alert, even
        # on a confident FP. The verdict stands; a human must ack it.
        _LOGGER.info(
            "auto-ack suppressed for high-stakes alert %s "
            "(class/severity gate) despite verdict=false_positive conf=%.2f",
            es_id,
            report.confidence or 0.0,
        )
        return None

    _LOGGER.info(
        "auto-acking FP alert %s (confidence=%.2f >= threshold=%.2f)",
        es_id,
        report.confidence or 0.0,
        settings.auto_ack_fp_threshold,
    )
    success: bool
    try:
        # Auto-ack is an unattended write. Route the audit logger through so the
        # ack is recorded as a mutating tool_call intent BEFORE the SO write
        # (fail-closed under audit_fail_closed) and a result record after — an
        # analyst-review-free write must always land in the audit trail.
        _result, error = await execute_write_tool(
            "ack_alert",
            {"alert_id": es_id},
            auth=ctx.auth,
            settings=settings,
            audit=ctx.audit,
            session_id=f"auto-ack:{es_id}",
            user="auto-ack",
        )
        if error:
            _LOGGER.warning("auto-ack write failed for alert %s: %s", es_id, error)
            success = False
        else:
            success = True
    except Exception as exc:
        _LOGGER.warning("auto-ack unexpected error for alert %s: %s", es_id, exc)
        success = False

    ack_ev: StepEvent = emit_ev(
        "auto_ack",
        {
            "es_id": es_id,
            "confidence": report.confidence,
            "threshold": settings.auto_ack_fp_threshold,
            "success": success,
        },
    )
    try:
        await audit_ev(ack_ev)
    except Exception as exc:
        _LOGGER.warning("auto-ack audit log failed for alert %s: %s", es_id, exc)
    # Yield is caller's responsibility — we return the event for the caller to yield.
    # (Generators can't be called from non-generator helpers in Python.)
    return ack_ev


async def investigate(  # noqa: PLR0912, PLR0915 - two-phase flow with retask is naturally long
    alert_id: str,
    *,
    ctx: InvestigationContext,
    agent: Agent[None, TriageReport]
    | None = None,  # backwards-compat: ignored when investigator+synthesizer are constructed below
    investigator: Agent[None, InvestigationTranscript] | None = None,
    synthesizer: Agent[None, TriageReport] | None = None,
    session_id: str | None = None,
    focus_hint: str | None = None,
) -> AsyncIterator[StepEvent]:
    """Run a two-stage triage investigation, yielding SSE events.

    ``focus_hint`` (optional): when this run was launched to close a prior
    ``needs_more_info`` verdict (the "request more info" action), the prior
    open questions are passed here and woven into the investigator/synth seed
    prompt so the fresh run TARGETS those gaps. ``None`` ⇒ normal cold run.

    The pipeline is:

    1. **Classification** (deterministic, no LLM). Tags the alert with one of
       :class:`~soc_ai.agent.classifier.AlertClass`. ``informational_visibility``
       + ``severity_label==low`` may take the **fast path** — a stripped-down
       investigator prompt with reduced tool budget and a relaxed
       (``fast_path_synthesis_floor``) retask floor.
    2. **Investigator** (fast model) gathers evidence with read tools, emits
       an :class:`InvestigationTranscript`.
    3. **Synthesizer** (heavy model) reads the transcript, emits a
       :class:`TriageReport`.
    4. If ``report.confidence < <effective floor>``, retask the investigator
       ONCE with the prior transcript + open questions, then re-synthesize on
       the combined evidence.

    Per-phase ``usage`` SSE events expose real token / tool-call counts so we
    can right-size limits and the confidence floor with audit data.

    Investigator + synthesizer construction is deferred until AFTER
    classification so the fast-path can swap the system prompt.
    """
    if ctx.settings.synth_first_pipeline:
        async for ev in _run_synth_first_pipeline(
            alert_id=alert_id,
            ctx=ctx,
            focus_hint=focus_hint,
        ):
            yield ev
        return

    if synthesizer is None:
        synthesizer = build_synthesizer(build_synthesizer_model(ctx.settings))

    sid = session_id or uuid.uuid4().hex[:12]
    sequence = 0

    usage_limits = UsageLimits(
        request_limit=ctx.settings.agent_request_limit,
        tool_calls_limit=ctx.settings.agent_tool_calls_limit,
    )
    fast_path_usage_limits = UsageLimits(
        request_limit=ctx.settings.fast_path_request_limit,
        tool_calls_limit=ctx.settings.fast_path_tool_calls_limit,
    )

    def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        nonlocal sequence
        sequence += 1
        return StepEvent(kind=kind, session_id=sid, sequence=sequence, payload=payload)

    async def _audit(ev: StepEvent) -> None:
        # Audit must never crash the in-flight investigation. The audit logger
        # already swallows ES errors, but a Pydantic ValidationError on
        # AuditKind would propagate before the ES call - catch it here too.
        # Also feed the per-process Prometheus counters so /metrics reflects
        # this run.
        try:
            await metrics.get_metrics().record_event(ev.kind, ev.payload)
        except Exception as e:
            _LOGGER.warning("metrics record failed (kind=%s): %s", ev.kind, e)
        if ctx.audit is None:
            return
        try:
            await ctx.audit.log_kind(sid, ev.kind, ev.payload)
        except Exception as e:
            _LOGGER.warning("audit dropped event (kind=%s): %s", ev.kind, e)

    def _build_usage_event(phase: str, round_num: int, run_result: Any) -> StepEvent | None:
        try:
            u = run_result.usage()
        except Exception:
            _LOGGER.exception("could not extract usage from %s round %s", phase, round_num)
            return None
        _LOGGER.info(
            "agent usage: alert=%s phase=%s round=%s tool_calls=%s "
            "requests=%s tokens(in/out/total)=%s/%s/%s",
            alert_id,
            phase,
            round_num,
            u.tool_calls,
            u.requests,
            u.input_tokens,
            u.output_tokens,
            u.total_tokens,
        )
        return _ev(
            "usage",
            {
                "phase": phase,
                "round": round_num,
                "tool_calls": u.tool_calls,
                "requests": u.requests,
                "input_tokens": u.input_tokens,
                "output_tokens": u.output_tokens,
                "total_tokens": u.total_tokens,
            },
        )

    start_ev = _ev("session_start", {"alert_id": alert_id})
    await _audit(start_ev)
    yield start_ev

    # ----- Pre-fetch: alert context -----
    # The fast investigator used to skip `t_get_alert_context` and hallucinate
    # alert details. Pre-fetching here removes that source of variance and
    # saves a tool round-trip. We also cap max_per_pivot at 5 (vs the tool
    # default of 10) so the embedded context stays within the fast 30B's
    # 64K window even for pivot-rich alerts.
    try:
        alert_ctx = await get_alert_context(
            alert_id,
            elastic=ctx.elastic,
            settings=ctx.settings,
            max_per_pivot=5,
            include_synth=ctx.include_synth,
        )
    except Exception as e:
        _LOGGER.exception("alert-context prefetch failed")
        err_ev = _ev("error", _error_payload(e, phase="prefetch", round_num=0))
        await _audit(err_ev)
        yield err_ev
        # Emit a synthetic TriageReport so the supervisor doesn't go
        # silent on terminal upstream failure. Verdict ``needs_more_info``
        # with confidence 0.0 is the right signal: the orchestrator
        # genuinely doesn't know, the eval pipeline still has something
        # for the oracle to evaluate, and the cross-batch aggregator can
        # identify "X% of runs died at prefetch" as a class instead of
        # silently dropping them. No recommended_actions — there's
        # nothing to act on without evidence.
        synth_payload = TriageReport(
            verdict="needs_more_info",
            confidence=0.0,
            summary=(
                f"Alert prefetch failed before any evidence could be gathered: "
                f"{type(e).__name__}: {str(e)[:200]}. The agent did not run. "
                f"Treat this as an infrastructure incident, not a triage finding."
            ),
            citations=[],
            recommended_actions=[],
        ).model_dump(mode="json")
        synth_ev = _ev("triage_report", synth_payload)
        await _audit(synth_ev)
        yield synth_ev
        done_ev = _ev(
            "done",
            {
                "recommended_count": 0,
                "rounds": 0,
                "synthetic": True,
                "reason": "prefetch_failed",
            },
        )
        await _audit(done_ev)
        yield done_ev
        return

    # Full context goes to the SSE consumer (analyst-visible); a slim copy
    # goes into the model prompt to stay under the 30B's context window.
    full_ctx_dump = alert_ctx.model_dump(mode="json")
    slim_ctx_dump = _compact_alert_context(alert_ctx)
    alert_ctx_json = json.dumps(slim_ctx_dump, indent=2)

    # Plumb the alert's @timestamp into the runtime context so all
    # subsequent `t_query_*` tool calls anchor their search window on
    # the alert. Tools fall back to now-relative when this
    # is None (CLI / WebUI / test paths that don't pre-fetch).
    ctx.default_time_anchor = alert_ctx.alert.timestamp

    # Reset per-investigation tool-call dedup state. The
    # InvestigationContext can be reused across investigate() calls in
    # the long-running server; a fresh tracker per call prevents state
    # leakage. Same logic for the prefetched community_ids set: rebuilt
    # from the current alert's pivot.
    ctx.dedup = _DedupTracker()
    ctx.prefetched_community_ids = {
        cid
        for cid in (
            getattr(alert_ctx.alert, "network_community_id", None),
            *(getattr(e, "network_community_id", None) for e in alert_ctx.community_id_events),
        )
        if isinstance(cid, str) and cid
    }

    prefetch_ev = _ev("alert_context", full_ctx_dump)
    await _audit(prefetch_ev)
    yield prefetch_ev

    # ----- Classification + fast-path routing -----
    alert_class = classify_alert(alert_ctx.alert)
    # Pass the global enrichment cache to the eligibility check —
    # external destinations require a prior cache hit to fast-path.
    from soc_ai.agent.enrichment_cache import get_global_cache  # noqa: PLC0415

    enrichment_cache = get_global_cache()
    fast_path_eligible = ctx.settings.enable_rule_class_fast_path and is_fast_path_eligible(
        alert_ctx.alert,
        alert_class,
        enrichment_cache=enrichment_cache,
        blocklist=ctx.blocklist,
    )
    sampled_to_full = (
        fast_path_eligible
        and ctx.settings.fast_path_sampling_rate > 0.0
        # Drift-monitoring sample (not crypto). PRNG quality is not load-bearing.
        and random.random() < ctx.settings.fast_path_sampling_rate  # noqa: S311
    )
    fast_path_taken = fast_path_eligible and not sampled_to_full
    classification_ev = _ev(
        "classification",
        {
            "alert_class": alert_class.value,
            "fast_path_eligible": fast_path_eligible,
            "fast_path_taken": fast_path_taken,
            "sampled_to_full": sampled_to_full,
        },
    )
    await _audit(classification_ev)
    yield classification_ev

    # Effective floor + tool budget depend on whether we took the fast path.
    effective_floor = (
        ctx.settings.fast_path_synthesis_floor
        if fast_path_taken
        else ctx.settings.synthesis_confidence_floor
    )
    effective_usage_limits = fast_path_usage_limits if fast_path_taken else usage_limits

    transcripts: list[InvestigationTranscript] = []
    transcript: InvestigationTranscript
    inv_result: Any = None  # set in standard path; remains None on fast-path

    # ----- fast-path preflight: mandatory enrichment + escalation -----
    # Done BEFORE the fast-path-vs-standard branch so the escalation can
    # flip fast_path_taken=False and the standard pipeline below picks up.
    materialized_evidence: list[str] = []
    if fast_path_taken:
        materialized_evidence = _materialize_prefetch_evidence(alert_ctx)
        external_ip = _fast_path_external_indicator(alert_ctx)
        enrich_result: Any = None
        if external_ip:
            try:
                enrich_result = await asyncio.wait_for(
                    enrich_ip(external_ip, settings=ctx.settings, misp=ctx.misp),
                    timeout=ctx.settings.fast_path_enrichment_timeout_s,
                )
            except (TimeoutError, Exception) as enrich_err:
                _LOGGER.warning("fast-path enrichment failed for %s: %s", external_ip, enrich_err)
                materialized_evidence.append(
                    f"t_enrich_ip({external_ip})=lookup failed: "
                    f"{type(enrich_err).__name__} (tool t_enrich_ip)"
                )
            else:
                materialized_evidence.append(
                    _summarize_enrichment_for_evidence(external_ip, enrich_result)
                )
                # Record the enrichment in the global cache so future
                # alerts targeting the same IP can fast-path on first
                # encounter satisfying the cache-hit gate.
                try:
                    enrichment_cache.put(external_ip, enrich_result)
                except Exception as cache_err:
                    _LOGGER.warning("enrichment cache put failed: %s", cache_err)
                # Synthesize tool_call + tool_result events for the audit
                # trail so the bundle's events.jsonl reflects the call.
                tc_ev = _ev(
                    "tool_call",
                    {
                        "tool_name": "t_enrich_ip",
                        "args": {"ip": external_ip},
                        "phase": "fast_path",
                        "round": 1,
                    },
                )
                await _audit(tc_ev)
                yield tc_ev
                tr_ev = _ev(
                    "tool_result",
                    {
                        "tool_name": "t_enrich_ip",
                        "result": enrich_result.model_dump(mode="json"),
                        "phase": "fast_path",
                        "round": 1,
                    },
                )
                await _audit(tr_ev)
                yield tr_ev
        # Escalate to full pipeline on MISP hit / flagged ASN.
        if enrich_result is not None and _enrichment_has_threat_signal(enrich_result):
            esc_ev = _ev(
                "fast_path_escalation",
                {
                    "reason": (
                        f"mandatory enrichment on {external_ip} returned a "
                        f"threat-signal finding; escalating to full investigator"
                    ),
                    "external_ip": external_ip,
                },
            )
            await _audit(esc_ev)
            yield esc_ev
            fast_path_taken = False
            effective_floor = ctx.settings.synthesis_confidence_floor
            effective_usage_limits = usage_limits

    if fast_path_taken:
        # ----- F1: fast-path branch (no investigator) -----
        transcript = InvestigationTranscript(
            evidence=materialized_evidence,
            tentative_summary=(
                f"Fast-path short-circuit: orchestrator's classifier tagged this "
                f"alert as {alert_class.value} + severity_label=low. Investigator "
                f"was skipped; mandatory enrichment ran on the external indicator "
                f"and the synth produces verdict from the materialized evidence."
            ),
            open_questions=[],
        )
        transcripts.append(transcript)
        transcript_ev = _ev(
            "investigation_transcript",
            {
                "round": 1,
                "fast_path_skipped": True,
                "evidence_materialized": len(materialized_evidence),
                **transcript.model_dump(mode="json"),
            },
        )
        await _audit(transcript_ev)
        yield transcript_ev

        # Run synth with the fast-path-specific user message.
        # Use effective_usage_limits (which equals fast_path_usage_limits when
        # fast_path_taken=True) — the tighter token/request budget defined for
        # the fast path.  Previously this mistakenly passed the full usage_limits,
        # making fast_path_usage_limits defined but never wired here.
        try:
            async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                synth_result = await synthesizer.run(
                    build_fast_path_synth_user_message(
                        alert_id,
                        alert_class.value,
                        alert_ctx_json,
                        materialized_evidence=materialized_evidence,
                    ),
                    usage_limits=effective_usage_limits,
                )
        except Exception as e:
            _LOGGER.exception("synthesizer run (fast-path round 1) failed")
            err_ev = _ev("error", _error_payload(e, phase="synthesizer", round_num=1))
            await _audit(err_ev)
            yield err_ev
            return
    else:
        # ----- Standard pipeline: investigator → synthesizer -----
        # Build the investigator. Tests can pass a pre-built investigator
        # (TestModel path); when they do, we honor it as-is.
        if investigator is None:
            investigator = build_investigator(
                build_investigator_model(ctx.settings),
                ctx,
            )

        investigator_user_message = _format_investigator_prompt(
            alert_id, alert_ctx_json, focus_hint=focus_hint
        ) + await inventory_prompt_block(ctx.elastic, ctx.settings)

        # ----- Round 1: investigator -----
        try:
            async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                inv_result = await investigator.run(
                    investigator_user_message,
                    usage_limits=effective_usage_limits,
                )
        except Exception as e:
            # Don't bail out — emit an `error` event for the audit trail and
            # fabricate a synthetic transcript so the synthesizer can still
            # produce a needs_more_info verdict. Smoke testing surfaced cases
            # where Nemotron-30B's structured output is stochastic (passes 8
            # times in 10, fails 2). Aborting wastes the eval batch.
            _LOGGER.exception("investigator run (round 1) failed; using synthetic transcript")
            err_ev = _ev("error", _error_payload(e, phase="investigator", round_num=1))
            await _audit(err_ev)
            yield err_ev

        if inv_result is None:
            transcript = InvestigationTranscript(
                evidence=[],
                tentative_summary=(
                    "Investigator did not produce a structured transcript "
                    "(model retry budget exhausted on schema validation). "
                    "Synthesizer should emit `needs_more_info`."
                ),
                open_questions=[
                    "Investigator was unable to complete; rerun on this alert.",
                ],
            )
        else:
            transcript = inv_result.output

        transcripts.append(transcript)

        # Stream the investigator's tool-call/result/model messages.
        if inv_result is not None:
            for msg in inv_result.all_messages():
                async for ev in _walk_message(msg, _ev, phase="investigator", round_num=1):
                    await _audit(ev)
                    yield ev

            inv_usage_ev = _build_usage_event("investigator", 1, inv_result)
            if inv_usage_ev is not None:
                await _audit(inv_usage_ev)
                yield inv_usage_ev

        transcript_ev = _ev(
            "investigation_transcript",
            {"round": 1, **transcript.model_dump(mode="json")},
        )
        await _audit(transcript_ev)
        yield transcript_ev

        # ----- Round 1: synthesizer (standard path) -----
        try:
            async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                synth_result = await synthesizer.run(
                    _format_transcript_for_synthesizer(alert_id, transcripts),
                    usage_limits=usage_limits,
                )
        except Exception as e:
            _LOGGER.exception("synthesizer run (round 1) failed")
            err_ev = _ev("error", _error_payload(e, phase="synthesizer", round_num=1))
            await _audit(err_ev)
            yield err_ev
            return

    for msg in synth_result.all_messages():
        async for ev in _walk_message(msg, _ev, phase="synthesizer", round_num=1):
            await _audit(ev)
            yield ev

    synth_usage_ev = _build_usage_event("synthesizer", 1, synth_result)
    if synth_usage_ev is not None:
        await _audit(synth_usage_ev)
        yield synth_usage_ev

    report: TriageReport = synth_result.output

    # ----- F1 verdict ceiling: fast-path NEVER emits true_positive.
    # If the synth disagrees with the classifier and emits true_positive,
    # downgrade to needs_more_info — the orchestrator surfaces the disagreement
    # via the SSE event so the analyst can re-investigate manually.
    if fast_path_taken and report.verdict == "true_positive":
        cap_ev = _ev(
            "fast_path_verdict_cap",
            {
                "round": 1,
                "original_verdict": "true_positive",
                "capped_verdict": "needs_more_info",
                "reason": (
                    "fast-path classifier should not emit true_positive; "
                    "downgrading to needs_more_info for human re-investigation"
                ),
            },
        )
        await _audit(cap_ev)
        yield cap_ev
        report = report.model_copy(update={"verdict": "needs_more_info"})

    # ----- Evidence guard: fast-path with non-empty prefetch
    # MUST emit non-empty evidence. If the synth ignores the materialized
    # evidence we surfaced, force-downgrade to needs_more_info — a
    # false_positive verdict with no cited evidence at all is exactly the
    # "rubber-stamp without positive signal" failure mode.
    if fast_path_taken and not report.citations:
        prefetch_had_pivots = bool(
            getattr(alert_ctx, "community_id_events", None)
            or getattr(alert_ctx, "host_events", None)
        )
        if prefetch_had_pivots and report.verdict != "needs_more_info":
            guard_ev = _ev(
                "fast_path_evidence_guard",
                {
                    "round": 1,
                    "original_verdict": report.verdict,
                    "capped_verdict": "needs_more_info",
                    "reason": (
                        "fast-path synth emitted no citations despite "
                        "non-empty prefetch pivots; can't justify a "
                        "non-NMI verdict without cited evidence"
                    ),
                },
            )
            await _audit(guard_ev)
            yield guard_ev
            report = report.model_copy(
                update={
                    "verdict": "needs_more_info",
                    "recommended_actions": [],
                }
            )

    # ----- Citation validation + hard-gate (F7). Strip
    # invalid citations from the published report, then scale confidence
    # by (1 - invalid_ratio). Drift surfaces in citation_validation +
    # citation_cap SSE events. F7 walks the actual ToolCallPart
    # history for tool-ref citations instead of a substring match on
    # evidence text — catches "claims to have called t_enrich_ip but
    # never did".
    inv_messages_for_cite: list[Any] = []
    if not fast_path_taken and inv_result is not None:
        inv_messages_for_cite = inv_result.all_messages()
    citation_validation = _resolve_citations(
        report.citations, alert_ctx, transcripts, messages=inv_messages_for_cite
    )
    cite_ev = _ev("citation_validation", {"round": 1, **citation_validation})
    await _audit(cite_ev)
    yield cite_ev

    coverage_ratio = citation_validation["coverage_ratio"]
    original_conf = report.confidence
    new_conf = _citation_confidence_cap(original_conf, coverage_ratio=coverage_ratio)
    if new_conf != original_conf:
        report = report.model_copy(update={"confidence": new_conf})
        cap_ev = _ev(
            "citation_cap",
            {
                "round": 1,
                "original_confidence": original_conf,
                "capped_confidence": new_conf,
                "coverage_ratio": coverage_ratio,
                "invalid_ratio": 1.0 - coverage_ratio,  # legacy field
            },
        )
        await _audit(cap_ev)
        yield cap_ev

    # ----- Coverage cap (derived per F3) -----
    # Confidence is bounded above by the rubric DERIVED from the actual
    # tool calls in the investigator's message history (NOT the model's
    # self-report — analysis flagged that as routinely
    # fabricated). Skipped on fast-path because no investigator ran.
    derived_round1_rubric: Any = None
    missing_rubric: list[str] = []
    if not fast_path_taken:
        inv_messages = inv_result.all_messages() if inv_result is not None else []
        derived_round1_rubric = _derive_rubric_coverage(inv_messages, alert_ctx)
        # Also OR-merge any model-reported fields without an authoritative
        # derivation (currently just `enrichment_skipped_reason`). Model
        # can over-claim, so the derived value stays the source of truth
        # everywhere the orchestrator CAN derive it. B5:
        # `payload_inspected_if_banner_rule` is no longer taken from the
        # self-report — `_derive_rubric_coverage` derives it from the
        # payload evidence the model actually received (analysis
        # flagged self-reports as routinely fabricated).
        # The claimed value still surfaces, un-merged, in the
        # rubric_derivation event's `model_reported` for audit.
        if transcript.rubric_coverage is not None:
            mr = transcript.rubric_coverage
            if getattr(mr, "enrichment_skipped_reason", None):
                derived_round1_rubric.enrichment_skipped_reason = mr.enrichment_skipped_reason
        required = _required_rubric_fields(alert_ctx)
        capped_confidence, missing_rubric = _coverage_cap(
            report.confidence, derived_round1_rubric, required
        )
        # Emit a derivation event so the audit trail / aggregator can show
        # how often the model's self-report disagreed with the derived one.
        derived_ev = _ev(
            "rubric_derivation",
            {
                "round": 1,
                "model_reported": (
                    transcript.rubric_coverage.model_dump(mode="json")
                    if transcript.rubric_coverage is not None
                    else None
                ),
                "orchestrator_derived": derived_round1_rubric.model_dump(mode="json"),
                "required_fields": sorted(required),
            },
        )
        await _audit(derived_ev)
        yield derived_ev
        if missing_rubric:
            cap_ev = _ev(
                "coverage_cap",
                {
                    "round": 1,
                    "original_confidence": report.confidence,
                    "capped_confidence": capped_confidence,
                    "missing_fields": missing_rubric,
                    "required_fields": sorted(required),
                },
            )
            await _audit(cap_ev)
            yield cap_ev
            report = report.model_copy(update={"confidence": capped_confidence})

    # ----- Conditional retask (F4) -----
    # SKIPPED on fast-path. Otherwise fire on EITHER:
    # - synthesis_below_floor (existing trigger), OR
    # - rubric_gap AND closeable: ≥2 required rubric fields are
    #   missing AND at least one maps to an UNUSED-but-available tool
    #   call. Evaluation showed retasks on non-closeable gaps still landed at
    #   'partial' — better to accept the floor and stop than burn another
    #   round on something we can't fix.
    confidence_below_floor = (not fast_path_taken) and report.confidence < effective_floor
    rubric_gap = (not fast_path_taken) and len(missing_rubric or []) >= 2
    round1_messages_for_close = (
        inv_result.all_messages() if (inv_result is not None and not fast_path_taken) else []
    )
    closeable = rubric_gap and _has_closeable_rubric_gap(missing_rubric, round1_messages_for_close)
    if rubric_gap and not closeable and not confidence_below_floor:
        # Skip the retask — wasted budget. Surface why in the audit trail.
        skip_ev = _ev(
            "retask_skipped_no_closeable_gap",
            {
                "missing_rubric": missing_rubric,
                "reason": (
                    "rubric_gap detected but every missing field's tool was "
                    "already called (or has no tool-call closure path); "
                    "retasking would not improve coverage"
                ),
            },
        )
        await _audit(skip_ev)
        yield skip_ev
    if confidence_below_floor or (rubric_gap and closeable):
        retask_reason = "synthesis_below_floor" if confidence_below_floor else "rubric_gap"
        retask_ev = _ev(
            "retask",
            {
                "reason": retask_reason,
                "confidence": report.confidence,
                "floor": effective_floor,
                "open_questions": transcript.open_questions,
                "missing_rubric": missing_rubric or [],
            },
        )
        await _audit(retask_ev)
        yield retask_ev

        # Round 2: investigator with prior transcript + open questions.
        # Route to the heavy 120B because it's stronger at focused gap-closing
        # synthesis. Both fast and heavy are deployed with 64K context on this
        # grid, so context size alone isn't the differentiator. To prevent
        # round-2 tool-result accumulation from blowing the window, also cap
        # round 2 with a TIGHTER usage_limits than round 1.
        retask_investigator = build_investigator(
            build_synthesizer_model(ctx.settings),
            ctx,
        )
        retask_usage_limits = UsageLimits(
            request_limit=ctx.settings.agent_retask_request_limit,
            tool_calls_limit=ctx.settings.agent_retask_tool_calls_limit,
        )
        try:
            async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                inv2_result = await retask_investigator.run(
                    _format_retask_prompt(
                        alert_id,
                        transcript,
                        missing_rubric=missing_rubric or [],
                        alert_ctx=alert_ctx,
                        reason=retask_reason,
                    ),
                    usage_limits=retask_usage_limits,
                )
        except Exception as e:
            _LOGGER.exception("investigator run (round 2 / retask) failed")
            err_ev = _ev(
                "error",
                _error_payload(e, phase="investigator", round_num=2),
            )
            await _audit(err_ev)
            yield err_ev
            # Fall back to the round-1 report rather than aborting — the user
            # still gets the low-confidence answer.
        else:
            transcript_2: InvestigationTranscript = inv2_result.output
            transcripts.append(transcript_2)

            for msg in inv2_result.all_messages():
                async for ev in _walk_message(msg, _ev, phase="investigator", round_num=2):
                    await _audit(ev)
                    yield ev

            inv2_usage_ev = _build_usage_event("investigator", 2, inv2_result)
            if inv2_usage_ev is not None:
                await _audit(inv2_usage_ev)
                yield inv2_usage_ev

            transcript2_ev = _ev(
                "investigation_transcript",
                {"round": 2, **transcript_2.model_dump(mode="json")},
            )
            await _audit(transcript2_ev)
            yield transcript2_ev

            # Round 2 synthesizer over BOTH transcripts.
            try:
                async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                    synth2_result = await synthesizer.run(
                        _format_transcript_for_synthesizer(alert_id, transcripts),
                        usage_limits=usage_limits,
                    )
            except Exception as e:
                _LOGGER.exception("synthesizer run (round 2) failed")
                err_ev = _ev(
                    "error",
                    _error_payload(e, phase="synthesizer", round_num=2),
                )
                await _audit(err_ev)
                yield err_ev
                # Keep the round-1 report.
            else:
                for msg in synth2_result.all_messages():
                    async for ev in _walk_message(msg, _ev, phase="synthesizer", round_num=2):
                        await _audit(ev)
                        yield ev

                synth2_usage_ev = _build_usage_event("synthesizer", 2, synth2_result)
                if synth2_usage_ev is not None:
                    await _audit(synth2_usage_ev)
                    yield synth2_usage_ev

                report = synth2_result.output

                # Round-2 citation validation + hard-gate. F7: tool-ref
                # citations now check the COMBINED message history of
                # both rounds.
                combined_messages = list(inv_messages_for_cite) + list(inv2_result.all_messages())
                citation_validation = _resolve_citations(
                    report.citations, alert_ctx, transcripts, messages=combined_messages
                )
                cite_ev = _ev(
                    "citation_validation",
                    {"round": 2, **citation_validation},
                )
                await _audit(cite_ev)
                yield cite_ev

                coverage_ratio2 = citation_validation["coverage_ratio"]
                original_conf2 = report.confidence
                new_conf2 = _citation_confidence_cap(original_conf2, coverage_ratio=coverage_ratio2)
                if new_conf2 != original_conf2:
                    report = report.model_copy(update={"confidence": new_conf2})
                    cap_ev = _ev(
                        "citation_cap",
                        {
                            "round": 2,
                            "original_confidence": original_conf2,
                            "capped_confidence": new_conf2,
                            "coverage_ratio": coverage_ratio2,
                            "invalid_ratio": 1.0 - coverage_ratio2,  # legacy field
                        },
                    )
                    await _audit(cap_ev)
                    yield cap_ev

                # Round-2 coverage cap (derived per F3).
                # OR-merge round-2's derived rubric INTO round-1's so a
                # field satisfied by round-1 isn't re-failed by round-2.
                # `derived_round1_rubric` was built above on the standard
                # path; on retask we extend it with round-2's tool calls.
                inv2_messages = inv2_result.all_messages()
                derived_round2_rubric = _derive_rubric_coverage(
                    inv2_messages, alert_ctx, seed=derived_round1_rubric
                )
                # OR-merge any model-set fields the orchestrator can't
                # infer (just `enrichment_skipped_reason` — B5 dropped
                # the self-reported payload_inspected_if_banner_rule;
                # see the round-1 merge above).
                tr2 = transcripts[-1].rubric_coverage if transcripts else None
                if tr2 is not None and getattr(tr2, "enrichment_skipped_reason", None):
                    derived_round2_rubric.enrichment_skipped_reason = tr2.enrichment_skipped_reason
                required2 = _required_rubric_fields(alert_ctx)
                capped2, missing2 = _coverage_cap(
                    report.confidence, derived_round2_rubric, required2
                )
                derived2_ev = _ev(
                    "rubric_derivation",
                    {
                        "round": 2,
                        "model_reported": (
                            tr2.model_dump(mode="json") if tr2 is not None else None
                        ),
                        "orchestrator_derived": derived_round2_rubric.model_dump(mode="json"),
                        "required_fields": sorted(required2),
                    },
                )
                await _audit(derived2_ev)
                yield derived2_ev
                if missing2:
                    cap_ev = _ev(
                        "coverage_cap",
                        {
                            "round": 2,
                            "original_confidence": report.confidence,
                            "capped_confidence": capped2,
                            "missing_fields": missing2,
                            "required_fields": sorted(required2),
                        },
                    )
                    await _audit(cap_ev)
                    yield cap_ev
                    report = report.model_copy(update={"confidence": capped2})

    # ----- Recommended-actions guard -----
    # Block all recommended_actions when the verdict rests on no
    # INVESTIGATOR evidence AND confidence is at-or-below the synthesis
    # floor. The fast-path's templated synth was emitting `ack_alert`
    # at confidence=0.6 with `evidence=[]`, which is rubber-stamping
    # under uncertainty. Synth prompt says "NEVER recommend writes
    # when verdict is needs_more_info" but didn't cover the
    # fast-path-floor case; this guard closes that.
    #
    # Update: the fast-path transcript now has orchestrator-
    # MATERIALIZED evidence (prefetch fields), so checking
    # `transcript.evidence == []` no longer means "no real investigation".
    # The right semantic is "fast-path was taken (no investigator)
    # AND confidence at-or-below floor". The materialized evidence is
    # context for the synth, not investigator findings.
    no_investigator_evidence = fast_path_taken or all(not (t.evidence or []) for t in transcripts)
    at_floor = report.confidence <= ctx.settings.synthesis_confidence_floor
    if report.recommended_actions and no_investigator_evidence and at_floor:
        guard_ev = _ev(
            "recommended_actions_blocked",
            {
                "reason": "no_evidence_at_or_below_floor",
                "verdict": report.verdict,
                "confidence": report.confidence,
                "floor": ctx.settings.synthesis_confidence_floor,
                "blocked_count": len(report.recommended_actions),
            },
        )
        await _audit(guard_ev)
        yield guard_ev
        report = report.model_copy(update={"recommended_actions": []})

    # ----- Mechanically enforce confidence floor -----
    # If final confidence is STRICTLY below the synthesis floor and the
    # verdict isn't already `needs_more_info`, rewrite it. Review
    # flagged the agent as "overconfident-FP-with-thin-evidence":
    # the synth emits `false_positive @ 0.55` after the citation_cap or
    # coverage_cap drags confidence down, but the verdict label remains FP.
    # This makes the output internally inconsistent — a low-confidence FP
    # is operationally `needs_more_info`. Mechanically enforce that.
    #
    # B3 (citation parity): like `_synth_first_post_validate`, the rewrite is
    # evidence-conditional — it ALSO requires `_no_semantic_evidence`
    # (zero citations, or coverage_ratio < 0.25 from the latest
    # `_resolve_citations` round). A well-evidenced verdict survives low
    # confidence; citation-shape brittleness must not erase a verdict
    # whose reasoning is sound. This evidence-conditional fix previously
    # landed on the synth-first path only.
    coverage_ratio_final = citation_validation["coverage_ratio"]
    # `inconclusive` (self-consistency split) is terminal non-committed — never
    # rewritten, mirroring the synth-first floor rewrite.
    if (
        report.confidence < ctx.settings.synthesis_confidence_floor
        and report.verdict not in ("needs_more_info", "inconclusive")
        and _no_semantic_evidence(report, coverage_ratio_final)
    ):
        rewrite_ev = _ev(
            "verdict_floor_rewrite",
            {
                "original_verdict": report.verdict,
                "capped_verdict": "needs_more_info",
                "confidence": report.confidence,
                "floor": ctx.settings.synthesis_confidence_floor,
                "coverage_ratio": coverage_ratio_final,
                "n_citations": len(report.citations),
                "reason": (
                    "confidence below floor AND no semantic citation coverage; "
                    "verdict label coerced to needs_more_info"
                ),
            },
        )
        await _audit(rewrite_ev)
        yield rewrite_ev
        report = report.model_copy(
            update={
                "verdict": "needs_more_info",
                "recommended_actions": [],
            }
        )

    # ----- Targeted verdict downgrades (B2 parity) -----
    # Same shared `_apply_targeted_downgrades` the synth-first post-
    # validator runs (solicited-ICMP-echo TP downgrade). The legacy
    # pipeline still runs when the synth-first flag is off — without
    # this it reproduced the BPFDoor false escalation
    # the synth-first path already mitigates. Ordering mirrors
    # `_synth_first_post_validate`: floor rewrite first, downgrade last.
    # `alert_ctx` carries no enrichments, so the downgrade demands an
    # explicit clean lookup against ctx.blocklist (the same singleton DB
    # the enrich_* tools use) and internal-ness per the EFFECTIVE CIDR set
    # (settings.internal_cidrs union active 'cidr' rows minus muted). With no
    # active 'cidr' rows — and on any db-less/failure path — this is identical to
    # settings.internal_cidrs (behavior unchanged).
    legacy_effective = await _resolve_effective_identifiers(ctx)
    legacy_cidrs = _classification_cidrs(ctx, legacy_effective)
    downgrade_audit: dict[str, Any] = {}
    report = _apply_targeted_downgrades(
        report,
        alert_ctx,
        downgrade_audit,
        blocklist=ctx.blocklist,
        internal_cidrs=legacy_cidrs,
    )
    # I1: ungrounded host-anchored TP guard — legacy path parity with synth-first.
    # alert_ctx is an AlertContext: has .alert + .host_alert_profile but no
    # .enrichments (that's EnrichedAlertContext-only). Gate 3a conservatively
    # passes (empty enrichments dict) so gates 3b/3c still run. Safe no-op when
    # host_alert_profile is absent or empty (returns report unchanged).
    report = _downgrade_ungrounded_host_anchored_tp(report, alert_ctx, downgrade_audit)
    if "icmp_solicited_downgrade" in downgrade_audit:
        dg_ev = _ev("icmp_solicited_downgrade", downgrade_audit["icmp_solicited_downgrade"])
        await _audit(dg_ev)
        yield dg_ev

    # I2: hard evidence gate — legacy-path parity with the synth-first pipeline.
    # The primary path runs this inside _synth_first_post_validate; the legacy
    # fallback never did, so a prefetch-only TP/FP on the non-fast-path could
    # settle with no tool evidence behind it (the QVOD/zero-tool defect). Gate it
    # too. The fast path is intentionally exempt — it settles FP verdicts from
    # materialized prefetch and carries its own TP ceiling + evidence guard.
    if not fast_path_taken:
        report = _downgrade_unevidenced_verdict(
            report,
            alert_ctx,
            None,  # no CandidateVerdict on the legacy path → template exemption off
            downgrade_audit,
            targeted_messages=inv_messages_for_cite or None,
            targeted_tool_called=None,
        )
        if "evidence_gate_downgrade" in downgrade_audit:
            eg_ev = _ev("evidence_gate_downgrade", downgrade_audit["evidence_gate_downgrade"])
            await _audit(eg_ev)
            yield eg_ev

    # ----- Final report + approvals -----
    report_ev = _ev(
        "triage_report",
        {
            "verdict": report.verdict,
            "confidence": report.confidence,
            "summary": report.summary,
            "citations": report.citations,
            "recommended_actions": [a.model_dump(mode="json") for a in report.recommended_actions],
            # open_questions live on the investigator transcripts, not the synthesizer TriageReport
            "open_questions": [q for t in transcripts for q in (t.open_questions or [])],
            "field_reconciliation": report.field_reconciliation,
            "validator_note": report.validator_note,
        },
    )
    await _audit(report_ev)
    yield report_ev

    # ----- Auto-acknowledge high-confidence false positives (opt-in) -----
    auto_ack_ev = await maybe_auto_ack_fp(
        report, alert_id, alert=alert_ctx.alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
    )
    if auto_ack_ev is not None:
        yield auto_ack_ev

    for action in report.recommended_actions:
        # Backstop: the synthesizer occasionally emits tool_args={} for write
        # tools that operate on the alert under triage. The orchestrator
        # already knows the alert_id, so inject it when missing rather than
        # failing the approval at exec time.
        tool_args = dict(action.tool_args)
        if action.tool_name in ("ack_alert", "escalate_to_case") and "alert_id" not in tool_args:
            tool_args["alert_id"] = alert_id
        token = await ctx.gate.request(action.tool_name, tool_args)
        appr_ev = _ev(
            "approval_required",
            {
                "token": token,
                "tool_name": action.tool_name,
                "tool_args": tool_args,
                "rationale": action.rationale,
            },
        )
        await _audit(appr_ev)
        yield appr_ev

    done_ev = _ev(
        "done",
        {
            "recommended_count": len(report.recommended_actions),
            "rounds": len(transcripts),
        },
    )
    await _audit(done_ev)
    yield done_ev


# Citation-path prefixes that point at REAL gathered evidence (tool returns,
# enrichment results, or pivot events) rather than the alert's own fields.
# A verdict cited only against `alert.*` paths is self-referential — it
# restates the alert rather than investigating it. The QVOD beacon false-FP
# cited 5 `alert.*` paths (rule_name, payload_printable, classtype,
# rule_metadata.*) and called a Cobalt Strike beacon benign on that basis.
_EVIDENCE_PATH_PREFIXES: tuple[str, ...] = (
    "community_id_events",
    "host_events",
    "user_events",
    "process_events",
    "file_events",
    "enrichments",
    "typed_zeek",
)


def _pivot_event_ids(alert_ctx: Any) -> set[str]:
    """Collect the ES ``_id`` of every prefetched pivot event.

    An ``id``-shaped citation only counts as real evidence when it matches a
    pivot event the orchestrator actually pulled — otherwise the model could
    fabricate a long-alphanumeric string and have it trusted by
    :func:`_classify_citation`'s id branch.
    """
    ids: set[str] = set()
    for pivot_attr in _EVIDENCE_PATH_PREFIXES[:5]:  # the *_events pivot lists
        for ev in getattr(alert_ctx, pivot_attr, None) or []:
            ev_id = getattr(ev, "id", None)
            if isinstance(ev_id, str) and ev_id:
                ids.add(ev_id)
    return ids


def _is_evidence_backed(report: Any, enriched: Any, *, messages: list[Any] | None = None) -> bool:
    """True only when the verdict rests on REAL gathered evidence.

    Theme-1 Task 1. "Real evidence" means at least one citation resolves to
    an actual tool/enrichment result or a prefetched pivot event — NOT merely
    to a self-referential field on the alert under triage
    (``alert.rule_name``, ``alert.payload_printable``, ``alert.classtype``,
    ``alert.rule_metadata.*``, …). A citation qualifies when:

    - it names a tool (``(tool t_query_zeek_logs)`` / bare ``t_…``) that was
      actually invoked in the loop's message history, OR
    - it is a path into a pivot list / enrichment / typed-Zeek block
      (``community_id_events.0.…``, ``enrichments.1.2.3.4.…``, …) that
      resolves against the bundle, OR
    - it is an id that matches a prefetched pivot event's ``_id``.

    Pure ``alert.*`` paths (and bare ``alert.*`` field names) are
    self-referential and never count. An empty citation list is, by
    definition, not evidence-backed.

    ``messages`` is the loop's ``all_messages()`` history when available
    (lets tool citations resolve against real ``ToolCallPart`` events). At
    round-1 there is no message history, so tool citations can't be proven —
    which is correct: a zero-tool round-1 guess naming a tool it never
    called is exactly what this gate exists to catch.
    """
    citations = list(getattr(report, "citations", None) or [])
    if not citations:
        return False

    pivot_ids = _pivot_event_ids(enriched)
    for c in citations:
        kind, target = _classify_citation(c)
        if kind == "tool":
            if target and _tool_was_invoked([], target, messages=messages):
                return True
        elif kind == "path":
            if not target:
                continue
            head = target.split(".", 1)[0]
            # `alert.*` is self-referential; only non-alert evidence paths count.
            # Fix A: path citations into pivot/enrichment lists only count when
            # messages is not None — i.e. a real investigation loop ran. At
            # round 1 (messages=None) these paths come from _materialize_prefetch_evidence;
            # citing them is restating the prefetch, not investigation.
            if (
                head in _EVIDENCE_PATH_PREFIXES
                and messages is not None
                and _path_exists_in_alert(enriched, target)
            ):
                return True
        elif (
            kind == "id"
            and target
            and target in pivot_ids
            # Fix A: id citations matching prefetched pivot events only count when
            # messages is not None. At round 1 the synth was given these ids via
            # _materialize_prefetch_evidence; a zero-tool citation of a prefetched
            # id is not evidence of investigation.
            and messages is not None
        ):
            return True
    return False


def _definitely_investigate(enriched: Any, candidate: Any) -> bool:
    """Report-INDEPENDENT investigate triggers.

    True when the case will run the investigation loop REGARDLESS of the round-1
    verdict — a malware/exploit-signalled rule (the QVOD/beacon/BPFDoor failure
    mode: a zero-tool synth citing prefetched pivots is not evidence of
    benignness), or an external-reputation decision template (e.g.
    pushplanet settled FP on an unknown external host with zero tools).

    Because these don't depend on the round-1 report, the pipeline pre-checks
    this BEFORE Phase C and skips the ~10-15s round-1 synth call when True — that
    verdict would be discarded the moment the loop runs.
    """
    from soc_ai.agent.decision_templates import (  # noqa: PLC0415
        EXTERNAL_REPUTATION_TEMPLATES,
        _host_has_concurrent_threat,
        _rule_signals_malware,
    )

    if _rule_signals_malware(enriched):
        return True
    # Host-context trigger: the focus alert may look benign
    # (internal east-west, INFO) while its host is concurrently beaconing to a
    # C2 — the "context not being considered" failure. A threat-signalling pivot
    # alert on the same host/flow forces a real investigation of this leg.
    if _host_has_concurrent_threat(enriched):
        return True
    return (
        candidate is not None
        and getattr(candidate, "template_id", None) in EXTERNAL_REPUTATION_TEMPLATES
    )


def _should_investigate(report: Any, enriched: Any, candidate: Any) -> bool:
    """Decide whether to run the real investigation loop after round 1.

    Theme-1 Task 1. True when ALL hold:

    - ``investigate_when_unsure`` is on (settings flag is read by the
      caller, passed positionally via ``report``'s pipeline — see below),
    - the round-1 verdict is NOT evidence-backed
      (:func:`_is_evidence_backed`), AND
    - the alert is non-trivial — i.e. NOT a clean-internal benign that a
      decision template already cleared without any malware signal.

    "Trivially benign" = a non-malware-signalling alert whose decision
    template landed a benign verdict (``false_positive`` /
    ``needs_more_info`` is treated as non-benign; only ``false_positive``
    from a template on a non-malware rule short-circuits). Such alerts keep
    the fast zero-tool path; everything else that lacks evidence gets the
    loop.

    Note: the ``investigate_when_unsure`` flag check lives at the call site
    (it needs ``ctx.settings``); this helper assumes it has already passed
    and concerns itself only with the evidence + triviality gates.
    """
    # Report-INDEPENDENT triggers (malware/exploit signal, external-reputation
    # template). Extracted to _definitely_investigate so the pipeline can
    # pre-check them BEFORE Phase C and skip the wasted round-1 synth. Checked
    # before _is_evidence_backed because a template's own cited evidence (or a
    # round-1 FP citing a prefetched pivot) would otherwise read as "backed".
    if _definitely_investigate(enriched, candidate):
        return True

    if _is_evidence_backed(report, enriched):
        return False
    # Clean-internal benign: a decision template cleared it false_positive on
    # a rule with no malware signal → keep the fast path. Everything else that
    # lacks evidence gets the loop.
    return not (
        candidate is not None
        and getattr(candidate, "verdict", None) == "false_positive"
        and getattr(report, "verdict", None) == "false_positive"
    )


def _synth_reasoning_payload(run_result: Any) -> dict[str, Any] | None:
    """Project a synthesizer run's thinking into a ``model_response`` payload.

    The synth-first synthesizer runs (round-1 / loop-synth / Phase-D round-2)
    complete via ``agent.run`` — nothing walks their messages, so their
    ThinkingParts (deepseek ``reasoning_content`` bound via the model profile)
    were silently dropped and a no-loop investigation surfaced NO "Model
    reasoning" panel. Same part projection as :func:`_walk_message` (named
    ThinkingPart content, plus inline ``<think>`` blocks in TextParts), but
    collapsed to ONE payload for the whole run since a no-tools synthesis is a
    single model turn. Returns None when there is no non-empty trace (emit
    nothing) or on any message-shape surprise (defensive: never fail a verdict
    over explainability bookkeeping).
    """
    try:
        messages = run_result.all_messages()
    except Exception:
        return None
    traces: list[str] = []
    texts: list[str] = []
    try:
        for msg in messages or []:
            for part in getattr(msg, "parts", []) or []:
                ptype = type(part).__name__
                if ptype == "ThinkingPart":
                    content = getattr(part, "content", "") or ""
                    if content.strip():
                        traces.append(content.strip())
                elif ptype == "TextPart":
                    content = getattr(part, "content", "") or ""
                    trace, cleaned = extract_reasoning_trace(content)
                    if trace and trace.strip():
                        traces.append(trace.strip())
                    if cleaned.strip():
                        texts.append(cleaned.strip())
    except Exception:
        return None
    if not traces:
        return None
    return {"content": "\n\n".join(texts), "reasoning_trace": "\n\n".join(traces)}


async def _walk_message(
    msg: Any,
    ev_factory: Any,
    *,
    phase: str | None = None,
    round_num: int | None = None,
) -> AsyncIterator[StepEvent]:
    """Yield StepEvent records for every interesting part of a PydanticAI message.

    PydanticAI's message objects are a structured (model_request, model_response,
    tool_call, tool_return) sequence; we project only what the SSE consumer cares
    about and capture the ``<think>`` trace separately for audit. ``phase`` /
    ``round_num`` are stamped onto every emitted payload so consumers can
    distinguish investigator-vs-synthesizer events and round 1 vs round 2.
    """

    def _stamp(payload: dict[str, Any]) -> dict[str, Any]:
        if phase is not None:
            payload["phase"] = phase
        if round_num is not None:
            payload["round"] = round_num
        return payload

    parts = getattr(msg, "parts", []) or []
    # Track the most-recent ThinkingPart so we can attach it to the next
    # TextPart (or emit it standalone if no TextPart follows in this message).
    pending_trace: str | None = None
    for part in parts:
        ptype = type(part).__name__
        if ptype == "ThinkingPart":
            content = getattr(part, "content", "") or ""
            if content:
                pending_trace = (pending_trace + "\n\n" + content) if pending_trace else content
            continue
        if ptype == "TextPart":
            content = getattr(part, "content", "") or ""
            trace, cleaned = extract_reasoning_trace(content)
            payload: dict[str, Any] = {"content": cleaned}
            # Prefer a same-message ThinkingPart trace; fall back to inline
            # <think>...</think> if the model embedded the trace in text.
            if pending_trace:
                payload["reasoning_trace"] = pending_trace
                pending_trace = None
            elif trace:
                payload["reasoning_trace"] = trace
            yield ev_factory("model_response", _stamp(payload))
        elif ptype == "ToolCallPart":
            yield ev_factory(
                "tool_call",
                _stamp(
                    {
                        "tool_name": getattr(part, "tool_name", ""),
                        "args": getattr(part, "args", {}),
                        "tool_call_id": getattr(part, "tool_call_id", ""),
                    }
                ),
            )
        elif ptype == "ToolReturnPart":
            yield ev_factory(
                "tool_result",
                _stamp(
                    {
                        "tool_name": getattr(part, "tool_name", ""),
                        "result": getattr(part, "content", None),
                        "tool_call_id": getattr(part, "tool_call_id", ""),
                    }
                ),
            )
    # Trace without a follow-up TextPart in the same message — emit it as a
    # standalone reasoning-only model_response so it isn't lost.
    if pending_trace:
        yield ev_factory(
            "model_response",
            _stamp({"content": "", "reasoning_trace": pending_trace}),
        )


def _should_escalate_to_oracle(
    report: TriageReport,
    enriched: Any,
    settings: Settings,
    *,
    ran_loop: bool = False,
) -> bool:
    """Return True when the local verdict should be escalated to the Oracle.

    The Oracle is for cases the local path got WRONG or could not resolve — not
    for re-confirming correct verdicts. Policy (oracle_enabled is a mandatory
    prerequisite for any escalation):

    0. SHORT-CIRCUIT: a malware/attack-signalled rule the local path flagged
       ``true_positive`` is correct regardless of its confidence number — keep it
       LOCAL. Observed failure: correct local malware TPs were bouncing
       to the Oracle only because a citation_cap pushed confidence below 0.7/0.6.
    1. ``oracle_escalate_needs_more_info`` AND verdict == needs_more_info.
    2. ``oracle_escalate_malware_non_tp`` AND the rule signals malware/exploit OR
       attack-class (classtype in ``_ATTACK_CLASSTYPES``) AND the local verdict is
       NOT true_positive (i.e. cleared false_positive) — the wrongly-cleared-
       malware safety net (QVOD/BPFDoor). Attack-class rules (kerberoast, psexec
       lateral movement, data exfil, DNS tunnel) don't carry malware tokens, so
       ``_rule_signals_malware`` alone was too narrow.
       COST GATE: skipped when the investigation ``ran_loop`` AND
       ``report.confidence >= oracle_skip_after_confident_loop`` — a confident
       verdict after a real tool-driven investigation is trustworthy. The
       zero-tool fast path (``ran_loop`` False) still escalates here.
    3. confidence < ``oracle_escalate_below_confidence`` (any remaining verdict).

    Confident-benign verdicts on non-malware, non-attack rules are NOT escalated.
    """
    if not settings.oracle_enabled:
        return False

    from soc_ai.agent.decision_templates import (  # noqa: PLC0415
        _rule_signals_attack,
        _rule_signals_malware,
    )

    malware_or_attack = _rule_signals_malware(enriched) or _rule_signals_attack(enriched)

    # Condition 1: local model genuinely uncertain.
    if settings.oracle_escalate_needs_more_info and report.verdict == "needs_more_info":
        return True

    # A malware/attack-signalled rule that the local path flagged TRUE_POSITIVE is
    # already correctly handled — a flagged-malicious verdict is the right call
    # regardless of the confidence number, and the Oracle cannot improve "this
    # malware is malicious." Observed failure (CryptoWall, DNS-PowerShell
    # scenarios): the loop reached TP, but a citation_cap dragged confidence to 0.54,
    # which tripped BOTH the malware-non-TP gate and the low-confidence floor and
    # bounced a correct local verdict to the Oracle. The user's bar: "if we
    # cannot adjudicate that locally there is something wrong with the path." Keep
    # flagged-malicious verdicts local; the Oracle is for cases the local path
    # got WRONG or could not resolve, not for re-confirming correct TPs.
    if malware_or_attack and report.verdict == "true_positive":
        return False

    # Condition 2: a malware/attack-signalled rule the local path did NOT flag TP
    # (i.e. cleared false_positive) — the QVOD/BPFDoor wrongly-cleared-malware
    # safety net — UNLESS a real investigation loop already resolved it
    # confidently. The zero-tool fast path (``ran_loop`` False) still escalates.
    resolved_by_confident_loop = (
        ran_loop and report.confidence >= settings.oracle_skip_after_confident_loop
    )
    if (
        settings.oracle_escalate_malware_non_tp
        and malware_or_attack
        and not resolved_by_confident_loop
    ):
        return True

    # Condition 3: below-floor confidence on any remaining verdict / rule.
    return report.confidence < settings.oracle_escalate_below_confidence


async def _resolve_effective_identifiers(
    ctx: InvestigationContext,
) -> EffectiveIdentifiers | None:
    """Resolve the full effective internal-identifier set ONCE per investigation.

    Opens a one-off session from ``ctx.db_sessionmaker`` and computes the merged
    *effective* set (env-config union active detected/manual identifiers, minus
    muted) via
    :func:`~soc_ai.oracle.identifiers.effective_internal_identifiers`. The
    returned :class:`EffectiveIdentifiers` carries ``.suffixes``/``.hosts`` (for
    the Oracle egress sanitizer) and ``.cidrs`` (for internal-IP classification).

    Returns ``None`` when:

    * no ``db_sessionmaker`` is on ``ctx`` (CLI / eval / direct callers), or
    * resolution raised (DB error, missing table).

    A ``None`` return is the BACKWARD-COMPAT escape hatch: callers fall back to
    the raw ``settings`` values (``oracle_internal_suffixes`` / ``oracle_extra_hosts``
    for redaction, ``internal_cidrs`` for classification), so a db-less path — or
    any failure — leaves both redaction and classification behavior unchanged.

    SECURITY (redaction): threading this can never under-redact relative to
    today's settings-only behavior. The effective suffix/host set is
    ``(settings/reserved, always) + (active detected/manual) - (muted)``, and the
    sanitizer always re-adds ``settings.oracle_internal_suffixes`` (plus the
    reserved ``.lan/.local/.internal/.corp`` floor), so reserved/env defaults
    cannot be muted away — relative to raw settings this only ever *adds*.

    CLASSIFICATION (cidrs): with NO active ``cidr`` rows the effective cidrs ==
    ``settings.internal_cidrs`` (a muted detected CIDR is suppressed, an active
    one is added) — so classification is byte-identical to today until an
    operator un-mutes a suggested subnet. Detected CIDRs are always muted, so
    discovery alone never reclassifies a host.
    """
    maker = ctx.db_sessionmaker
    if maker is None:
        return None
    try:
        async with maker() as db:
            return await effective_internal_identifiers(db, ctx.settings)
    except Exception:  # pragma: no cover - defensive; never block egress on a DB hiccup
        _LOGGER.warning(
            "orchestrator: failed to resolve effective internal-identifier set; "
            "falling back to settings (oracle suffixes/hosts + internal_cidrs)",
            exc_info=True,
        )
        return None


def _classification_cidrs(
    ctx: InvestigationContext, effective: EffectiveIdentifiers | None
) -> Sequence[Any]:
    """The internal CIDR set internal-IP classification should use.

    ``effective.cidrs`` when the effective set resolved (env ``internal_cidrs``
    union active ``cidr`` rows minus muted), else ``settings.internal_cidrs``
    (db-less path / resolution failure). With no active ``cidr`` rows the two are
    identical, so classification is unchanged until an operator un-mutes a
    suggested subnet.
    """
    if effective is not None:
        return effective.cidrs
    return ctx.settings.internal_cidrs


async def _resolve_oracle_identifiers(
    ctx: InvestigationContext,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Resolve the effective (suffixes, hosts) for the Oracle egress sanitizer.

    Thin wrapper over :func:`_resolve_effective_identifiers` preserving the
    historical ``(suffixes, hosts)`` shape the Oracle client consumes. ``None``
    ⇒ fall back to the raw settings tuples (redaction unchanged). See
    :func:`_resolve_effective_identifiers` for the full contract.
    """
    effective = await _resolve_effective_identifiers(ctx)
    if effective is None:
        return None
    return effective.suffixes, effective.hosts


def _round1_skipped_report(alert_id: str) -> TriageReport:
    """Placeholder round-1 verdict for cases that skip the round-1 synth and
    route straight to the investigation loop. Always overwritten by the loop's
    synthesizer output — it only serves as the ``triage_final`` default."""
    return TriageReport(
        verdict="needs_more_info",
        confidence=0.0,
        summary="Round-1 synth skipped — routed directly to the investigation loop.",
        citations=[],
    )


def _self_consistency_vote(reports: list[Any]) -> tuple[str, float, str]:
    """Majority-vote a verdict across N independent final-synthesis samples.

    Pure helper for the flag-gated self-consistency vote
    (``settings.verdict_consistency_samples > 1``). Given the TriageReports
    from N runs of the SAME final synthesis call, returns
    ``(verdict, confidence, note)``:

    - STRICT majority (count > N/2): that verdict wins; confidence is the mean
      of the confidences of the samples that voted for it (3 dp); note =
      ``"self-consistency K/N agreed on <verdict>"``.
    - No strict majority (tie or 3-way split): ``("inconclusive", mean
      confidence of ALL samples capped at 0.5, "self-consistency split M ways:
      <tally> — inconclusive")``.
    - Single report (defensive — the caller guards N>1): passthrough of that
      report's verdict/confidence unchanged.
    """
    if len(reports) == 1:
        r = reports[0]
        return r.verdict, r.confidence, "self-consistency: single sample — no vote"
    n = len(reports)
    tally = Counter(r.verdict for r in reports)
    top_verdict, top_count = tally.most_common(1)[0]
    if top_count > n / 2:
        confs = [r.confidence for r in reports if r.verdict == top_verdict]
        mean_conf = round(sum(confs) / len(confs), 3)
        return (
            top_verdict,
            mean_conf,
            f"self-consistency {top_count}/{n} agreed on {top_verdict}",
        )
    conf = round(min(sum(r.confidence for r in reports) / n, 0.5), 3)
    tally_str = ", ".join(
        f"{v}={c}" for v, c in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return (
        "inconclusive",
        conf,
        f"self-consistency split {len(tally)} ways: {tally_str} — inconclusive",
    )


async def _run_synth_first_pipeline(  # noqa: PLR0912, PLR0915 - multi-phase pipeline is inherently long
    *,
    alert_id: str,
    ctx: InvestigationContext,
    focus_hint: str | None = None,
) -> AsyncGenerator[StepEvent, None]:
    """Phase A → B → C → optional D → C round 2 → done.

    The synth-first pipeline. Defaults OFF until v8 measurement validates.

    ``focus_hint`` (optional): prior open questions from a re-launched
    ``needs_more_info`` investigation, woven into the round-1 seed + the
    investigation-loop investigator prompt so this run targets those gaps.
    """
    from soc_ai.agent.decision_templates import match_decision_template  # noqa: PLC0415
    from soc_ai.agent.prompts import (  # noqa: PLC0415
        build_synth_first_round2_user_message,
        build_synth_first_user_message,
    )
    from soc_ai.agent.targeted_investigator import (  # noqa: PLC0415
        run_targeted_investigation,
    )
    from soc_ai.tools.enrichment import EnrichmentContext  # noqa: PLC0415
    from soc_ai.tools.get_alert_context import get_enriched_alert_context  # noqa: PLC0415

    session_id = uuid.uuid4().hex
    sequence_counter = [0]

    def _ev(kind: str, payload: dict[str, Any]) -> StepEvent:
        sequence_counter[0] += 1
        return StepEvent(
            kind=kind, session_id=session_id, sequence=sequence_counter[0], payload=payload
        )

    async def _audit(ev: StepEvent) -> None:
        # Audit must never crash the in-flight investigation. The audit logger
        # already swallows ES errors, but a Pydantic ValidationError on
        # AuditKind would propagate before the ES call - catch it here too.
        # Also feed the per-process Prometheus counters so /metrics reflects this
        # run — the synth-first pipeline is the DEFAULT path, and without this the
        # /metrics counters stay frozen at 0 in production (mirrors the legacy
        # investigate() _audit).
        try:
            await metrics.get_metrics().record_event(ev.kind, ev.payload)
        except Exception as e:
            _LOGGER.warning("metrics record failed (kind=%s): %s", ev.kind, e)
        if ctx.audit is None:
            return
        try:
            await ctx.audit.log_kind(session_id, ev.kind, ev.payload)
        except Exception as e:  # audit must never crash the investigation
            _LOGGER.warning("audit log_kind failed: %s", e)

    def _usage_ev(round_num: int, run_result: Any) -> StepEvent | None:
        """Build a ``usage`` event from a pydantic_ai result.

        The synth-first pipeline previously emitted NO usage events (only
        the legacy investigate() path did), so the UI's token KPI /
        sparkline / context meter stayed dead at 0. Mirror the legacy
        `_build_usage_event` shape so the panel populates.
        """
        try:
            u = run_result.usage()
        except Exception:
            return None
        return _ev(
            "usage",
            {
                "phase": "synthesizer",
                "round": round_num,
                "tool_calls": u.tool_calls,
                "requests": u.requests,
                "input_tokens": u.input_tokens,
                "output_tokens": u.output_tokens,
                "total_tokens": u.total_tokens,
            },
        )

    def _reasoning_ev(round_num: int, run_result: Any) -> StepEvent | None:
        """``model_response`` event carrying the synthesizer's reasoning trace.

        The loop's investigator turns already stream model_response via
        ``_walk_message``; the synthesizer ``agent.run`` calls did not, so a
        round-1/round-2-settled investigation had an empty "Model reasoning"
        panel. None when the run produced no trace — no event is emitted.
        Called ONLY for the primary/final synthesis runs, never for the
        self-consistency extra samples.
        """
        payload = _synth_reasoning_payload(run_result)
        if payload is None:
            return None
        return _ev("model_response", {**payload, "phase": "synthesizer", "round": round_num})

    yield _ev("session_start", {"alert_id": alert_id, "pipeline": "synth_first"})

    # Resolve the effective internal-identifier set ONCE per investigation
    # (env-config union active detected/manual identifiers, minus muted). Used
    # for BOTH internal-IP classification (``.cidrs`` → the targeted downgrades /
    # post-validator below) and the Oracle egress sanitizer (``.suffixes`` /
    # ``.hosts`` at the adjudication call). ``None`` ⇒ no DB on ctx (CLI / eval /
    # tests) or a resolution failure → classification falls back to
    # ``settings.internal_cidrs`` and redaction to the raw settings tuples
    # (behavior unchanged). With no active ``cidr`` rows the effective cidrs ==
    # ``settings.internal_cidrs``, so classification is byte-identical to today.
    effective_idents = await _resolve_effective_identifiers(ctx)
    classification_cidrs = _classification_cidrs(ctx, effective_idents)

    # ----- Phase A: rich precompute -----
    enrichment_ctx = EnrichmentContext(
        blocklist=ctx.blocklist,
        maxmind=ctx.maxmind,
        cloud=ctx.cloud,
    )
    try:
        enriched = await get_enriched_alert_context(
            alert_id,
            elastic=ctx.elastic,
            settings=ctx.settings,
            enrichment=enrichment_ctx,
            misp=ctx.misp,
            include_synth=ctx.include_synth,
            # Thread the effective CIDR set (settings.internal_cidrs union active
            # 'cidr' rows minus muted, resolved once above) into Phase-A enrichment
            # so an activated CIDR marks hosts internal here too — consistent
            # with the ICMP-downgrade classification path. No active cidr rows /
            # no DB ⇒ classification_cidrs == settings.internal_cidrs (unchanged).
            internal_cidrs=classification_cidrs,
        )
    except Exception as e:
        err_ev = _ev("error", _error_payload(e, phase="prefetch", round_num=0))
        await _audit(err_ev)
        yield err_ev
        return
    enriched_ev = _ev("enriched_alert_context", enriched.model_dump(mode="json"))
    await _audit(enriched_ev)
    yield enriched_ev

    # ----- Phase B: decision template -----
    candidate = match_decision_template(enriched)
    template_ev = _ev(
        "decision_template_match",
        {
            "matched": candidate is not None,
            "template_id": candidate.template_id if candidate else None,
            "verdict": candidate.verdict if candidate else None,
            "confidence": candidate.confidence if candidate else None,
            "rationale": candidate.rationale if candidate else None,
        },
    )
    await _audit(template_ev)
    yield template_ev

    # ----- Phase C: synth round 1 -----
    # Speed: when the case will investigate REGARDLESS of the round-1 verdict
    # (malware/exploit signal or external-reputation template), skip the round-1
    # synth entirely — it's a ~10-15s HEAVY call whose verdict the loop discards.
    enriched_json = enriched.model_dump_json()
    definitely_investigate = ctx.settings.investigate_when_unsure and _definitely_investigate(
        enriched, candidate
    )
    round1_ok = False
    # (agent, user_message, usage_limits|None) describing how to RE-RUN the
    # final verdict synthesis — consumed by the flag-gated self-consistency
    # vote below. Set at each site whose output becomes ``triage_final``;
    # cleared (None) on every fallback path so a vote never re-runs a call
    # that just failed.
    final_synth_rerun: tuple[Any, str, Any] | None = None
    if definitely_investigate:
        triage_round1 = _round1_skipped_report(alert_id)
        skip_ev = _ev("synth_round1_skipped", {"reason": "definitely_investigate"})
        await _audit(skip_ev)
        yield skip_ev
    else:
        materialized = _materialize_prefetch_evidence(enriched)
        user_msg_round1 = build_synth_first_user_message(
            alert_id=alert_id,
            enriched_ctx_json=enriched_json,
            materialized_evidence=materialized,
            candidate=candidate,
            focus_hint=focus_hint,
        )
        synth_agent = build_synth_first_agent(
            build_synthesizer_model(ctx.settings, temperature=ctx.settings.synthesizer_temperature)
        )
        try:
            async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                synth_result_round1 = await synth_agent.run(user_msg_round1)
        except Exception as e:
            # Emit error event for the audit trail, then
            # fall through with a fallback NMI TriageReport so the row in
            # index.jsonl is structured (not verdict=None). The post-validators
            # + triage_report emission below run uniformly on the fallback.
            err_ev = _ev("error", _error_payload(e, phase="synth_first_round1", round_num=1))
            await _audit(err_ev)
            yield err_ev
            triage_round1 = _synth_failure_fallback_report(alert_id, "synth_first_round1", e)
            await metrics.get_metrics().record_event("fallback_verdict", {})
        else:
            triage_round1 = synth_result_round1.output
            round1_ok = True
            # Round-1 IS the final synthesis when neither the loop nor Phase D
            # supersedes it below (each overwrites/clears this on its own path).
            final_synth_rerun = (synth_agent, user_msg_round1, None)
            # Surface the synthesizer's thinking — without this a round-1-settled
            # run stored NO model_response event and the reasoning panel was empty.
            r1_reasoning_ev = _reasoning_ev(1, synth_result_round1)
            if r1_reasoning_ev is not None:
                await _audit(r1_reasoning_ev)
                yield r1_reasoning_ev
            usage_ev = _usage_ev(1, synth_result_round1)
            if usage_ev is not None:
                await _audit(usage_ev)
                yield usage_ev

    triage_final = triage_round1

    # ----- Bounded investigation loop (Theme-1 Task 1) -----
    # The Phase C synth is a NO-tools structured-output guess that
    # rationalizes the prefetch. When its verdict isn't evidence-backed and
    # the alert isn't trivially benign, run a REAL investigation loop: the
    # tool-bound investigator (on the HEAVY model) chooses which read tools
    # to call, then the synthesizer concludes from the gathered transcript.
    # This replaces the zero-tool synthesis that scored 1-4/9 on synth-TP
    # (confidently clearing a Cobalt Strike beacon). Reversible via the
    # investigate_when_unsure flag.
    ran_investigation_loop = False
    loop_messages: list[Any] | None = None
    # fast_triage_enabled=False forces the tool-driven loop regardless of how
    # confident round-1 was ("agent does agent things"): deeper but slower.
    force_investigate = not ctx.settings.fast_triage_enabled
    if force_investigate or (
        ctx.settings.investigate_when_unsure
        and (
            definitely_investigate
            or (round1_ok and _should_investigate(triage_round1, enriched, candidate))
        )
    ):
        ran_investigation_loop = True
        if definitely_investigate:
            loop_reason = "definitely_investigate"
        elif force_investigate:
            loop_reason = "fast_triage_disabled"
        else:
            loop_reason = "verdict_not_evidence_backed"
        loop_ev = _ev(
            "investigation_loop_entered",
            {
                "reason": loop_reason,
                "round1_verdict": None if definitely_investigate else triage_round1.verdict,
                "round1_confidence": None if definitely_investigate else triage_round1.confidence,
            },
        )
        await _audit(loop_ev)
        yield loop_ev

        # Reset per-investigation tool state so the investigator's tools
        # anchor on THIS alert (mirrors the legacy investigate() prefetch
        # block): time anchor, dedup tracker, prefetched community_ids.
        ctx.default_time_anchor = enriched.alert.timestamp
        ctx.dedup = _DedupTracker()
        ctx.prefetched_community_ids = {
            cid
            for cid in (
                getattr(enriched.alert, "network_community_id", None),
                *(getattr(e, "network_community_id", None) for e in enriched.community_id_events),
            )
            if isinstance(cid, str) and cid
        }

        loop_usage_limits = UsageLimits(
            request_limit=ctx.settings.agent_request_limit,
            tool_calls_limit=ctx.settings.agent_tool_calls_limit,
        )
        # HEAVY model (build_synthesizer_model), NOT the fast investigator
        # model — the loop must reason on the strong model. The Nemotron
        # profile on the heavy builder already carries the tool_choice
        # workaround so tool-calling works. Moderate temperature: keep some
        # pivot exploration while staying broadly reproducible.
        investigator = build_investigator(
            build_synthesizer_model(
                ctx.settings, temperature=ctx.settings.investigator_temperature
            ),
            ctx,
        )
        inv_user_msg = _format_investigator_prompt(
            alert_id, enriched_json, focus_hint=focus_hint
        ) + await inventory_prompt_block(ctx.elastic, ctx.settings)
        inv_result: Any = None
        budget_exc: BaseException | None = None
        try:
            # Stream the run NODE-BY-NODE via agent.iter() so each tool_call /
            # tool_result / model_response lands in the timeline THE MOMENT it
            # happens (the recorder persists every event immediately, FLUSH_EVERY=1)
            # instead of replaying the whole investigation in one burst at the end.
            # CallToolsNode carries the model's response (text + tool requests);
            # the following ModelRequestNode carries that step's tool results.
            node_msg: Any = None
            async with investigator.iter(inv_user_msg, usage_limits=loop_usage_limits) as inv_run:
                # Advance NODE-BY-NODE with a PER-TURN wall-clock timeout on each
                # iterator step (the model-run await that produces the next node),
                # NOT one timeout spanning the whole multi-turn loop. Event
                # projection + yielding stays outside the timeout so streaming is
                # unchanged. A per-turn TimeoutError propagates to the same
                # except-handlers below (error event + honest stop) as any other
                # investigator failure.
                node_iter = inv_run.__aiter__()
                while True:
                    async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                        try:
                            node = await node_iter.__anext__()
                        except StopAsyncIteration:
                            break
                    # CallToolsNode carries the model's response (text + tool
                    # requests); the following ModelRequestNode carries that
                    # step's tool results. Detect by attribute so the message is
                    # projected the moment its node arrives.
                    node_msg = getattr(node, "model_response", None)
                    if node_msg is None:
                        node_msg = getattr(node, "request", None)
                    if node_msg is not None:
                        async for ev in _walk_message(
                            node_msg, _ev, phase="investigation_loop", round_num=1
                        ):
                            await _audit(ev)
                            yield ev
            inv_result = inv_run.result
        except asyncio.CancelledError:
            raise  # cooperative cancel — propagate, never swallow
        except UsageLimitExceeded as e:
            # Budget exhaustion is an EXPECTED outcome of a thorough investigation,
            # NOT an infrastructure failure. The tool calls + model responses
            # already streamed live above, so don't discard them with status=error
            # and no verdict: land the round-1 verdict via the same fallback used
            # when the loop-synth crashes. (This is the "conclude gracefully at the
            # budget boundary" behaviour, vs. the old "error out" one.)
            _LOGGER.warning("investigation loop hit budget limit: %s", e)
            err_ev = _ev("error", _error_payload(e, phase="investigation_loop_budget", round_num=1))
            await _audit(err_ev)
            yield err_ev
            budget_exc = e
        except TimeoutError as e:
            # A per-turn wall-clock timeout (investigation_turn_timeout_s) fired
            # while advancing the investigator on a slow stack. The evidence
            # gathered before the hung turn already streamed live, so conclude
            # GRACEFULLY with the round-1 verdict via the same budget-boundary
            # fallback as UsageLimitExceeded — do NOT discard the run with
            # status=error. (Mirrors the hunt runner's timeout→partial-report
            # behaviour; a slow stack is the expected trigger, not an infra fault.)
            _LOGGER.warning("investigation loop turn timed out: %s", e)
            err_ev = _ev(
                "error", _error_payload(e, phase="investigation_loop_timeout", round_num=1)
            )
            await _audit(err_ev)
            yield err_ev
            budget_exc = e
        except BaseException as e:
            # The investigator could not gather evidence — most often a transient
            # LLM-gateway connection drop (the openai client has already retried
            # litellm_max_retries times). Do NOT fabricate a needs_more_info
            # verdict from an empty transcript: that reads as if the agent
            # investigated and was unsure. Surface an honest error and stop — the
            # recorder marks the run 'error' (retryable), not a fake verdict.
            _LOGGER.exception("investigation loop investigator run failed")
            err_ev = _ev("error", _error_payload(e, phase="investigation_loop", round_num=1))
            await _audit(err_ev)
            yield err_ev
            return

        if budget_exc is not None:
            # Round-1 verdict stands (evidence gathered pre-budget is preserved in
            # the streamed timeline). loop_messages stays None — the downstream
            # evidence/citation checks already handle that.
            triage_final = _round2_failure_fallback(alert_id, triage_round1, budget_exc)
            final_synth_rerun = None  # fallback verdict — never vote on it
            await metrics.get_metrics().record_event("fallback_verdict", {})
        elif inv_result is None:
            # The agent run ended without a final result (no End node reached, and
            # no exception raised). Emit an honest error instead of crashing with an
            # UnboundLocalError on loop_transcript below.
            err_ev = _ev(
                "error",
                _error_payload(
                    RuntimeError("investigation loop returned no result"),
                    phase="investigation_loop",
                    round_num=1,
                ),
            )
            await _audit(err_ev)
            yield err_ev
            return
        else:
            # Events already streamed live above; land the transcript + usage, and
            # keep the full message history for the downstream citation/evidence
            # check (loop_messages feeds _is_evidence_backed / targeted-cite check).
            loop_transcript = inv_result.output
            loop_messages = inv_result.all_messages()
            inv_usage_ev = _usage_ev(1, inv_result)
            if inv_usage_ev is not None:
                await _audit(inv_usage_ev)
                yield inv_usage_ev

            transcript_ev = _ev(
                "investigation_transcript",
                {
                    "round": 1,
                    "phase": "investigation_loop",
                    **loop_transcript.model_dump(mode="json"),
                },
            )
            await _audit(transcript_ev)
            yield transcript_ev

            # Synthesize over the gathered evidence — REUSE the legacy
            # synthesizer-over-transcript (build_synthesizer + the transcript
            # user-message formatter). HEAVY model, no tools.
            loop_synth = build_synthesizer(
                build_synthesizer_model(
                    ctx.settings, temperature=ctx.settings.synthesizer_temperature
                )
            )
            loop_synth_msg = _format_transcript_for_synthesizer(
                alert_id, [loop_transcript], candidate=candidate
            )
            try:
                async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                    loop_synth_result = await loop_synth.run(
                        loop_synth_msg,
                        usage_limits=loop_usage_limits,
                    )
            except asyncio.CancelledError:
                raise  # cooperative cancel — propagate, never swallow
            except BaseException as e:
                # A BaseException here (e.g. a gateway timeout/cancel that escaped
                # the client retries) previously propagated past the recorder,
                # landing status=error with NO verdict + no recorded error event.
                # Catch it, record the error, and DON'T discard the round-1 verdict.
                err_ev = _ev(
                    "error", _error_payload(e, phase="investigation_loop_synth", round_num=2)
                )
                await _audit(err_ev)
                yield err_ev
                triage_final = _round2_failure_fallback(alert_id, triage_round1, e)
                final_synth_rerun = None  # fallback verdict — never vote on it
                await metrics.get_metrics().record_event("fallback_verdict", {})
            else:
                triage_final = loop_synth_result.output
                # The loop synth is now the final synthesis (supersedes round-1).
                final_synth_rerun = (loop_synth, loop_synth_msg, loop_usage_limits)
                # The loop's investigator turns streamed their own reasoning via
                # _walk_message above; this covers only the concluding synth run.
                loop_reasoning_ev = _reasoning_ev(2, loop_synth_result)
                if loop_reasoning_ev is not None:
                    await _audit(loop_reasoning_ev)
                    yield loop_reasoning_ev
                loop_synth_usage_ev = _usage_ev(2, loop_synth_result)
                if loop_synth_usage_ev is not None:
                    await _audit(loop_synth_usage_ev)
                    yield loop_synth_usage_ev
                # The loop replaces Phase D — strip any gap so we don't also
                # dispatch a single-tool targeted round on top of it.
                if triage_final.gap_for_investigator is not None:
                    triage_final = triage_final.model_copy(update={"gap_for_investigator": None})

    # ----- Phase D (optional): targeted investigator -----
    # Skipped when the investigation loop ran — the loop already gathered
    # evidence agentically (it supersedes the deterministic single-tool
    # dispatch).
    targeted_result: dict[str, Any] | str | None = None
    if not ran_investigation_loop and triage_round1.gap_for_investigator is not None:
        gap = triage_round1.gap_for_investigator
        # Co-emit `retask` so eval/batch.py:read_retask_count
        # picks up Phase D dispatches under SYNTH_FIRST_PIPELINE=true. Without
        # this the metric is mathematically guaranteed 0 even when Phase D
        # fires every alert. retask precedes targeted_dispatch — semantic
        # ordering: "agent asked for more" then "here's the specific call".
        retask_ev = _ev(
            "retask",
            {
                "reason": "phase_d_targeted_dispatch",
                "tool_name": gap.tool_name,
                "gap_question": gap.question,
                "gap_why_this_matters": gap.why_this_matters,
                "confidence": triage_round1.confidence,
            },
        )
        await _audit(retask_ev)
        yield retask_ev

        dispatch_ev = _ev(
            "targeted_dispatch",
            {
                "question": gap.question,
                "tool_name": gap.tool_name,
                "tool_args": gap.tool_args,
                "why_this_matters": gap.why_this_matters,
            },
        )
        await _audit(dispatch_ev)
        yield dispatch_ev

        targeted_result = await run_targeted_investigation(gap, ctx=ctx)
        targeted_result_ev = _ev(
            "targeted_tool_result",
            {"tool_name": gap.tool_name, "result": targeted_result},
        )
        await _audit(targeted_result_ev)
        yield targeted_result_ev

        # Synth round 2 with the targeted result.
        user_msg_round2 = build_synth_first_round2_user_message(
            alert_id=alert_id,
            enriched_ctx_json=enriched_json,
            materialized_evidence=materialized,
            candidate=candidate,
            round1_gap=gap,
            targeted_tool_result=targeted_result,
            focus_hint=focus_hint,
        )
        try:
            async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                synth_result_round2 = await synth_agent.run(user_msg_round2)
        except asyncio.CancelledError:
            raise  # cooperative cancel — propagate, never swallow
        except BaseException as e:
            # Emit a recorded error, then fall back to the round-1 verdict (or a
            # scoreable NMI) so the row is never a silent status=error.
            err_ev = _ev("error", _error_payload(e, phase="synth_first_round2", round_num=2))
            await _audit(err_ev)
            yield err_ev
            triage_final = _round2_failure_fallback(alert_id, triage_round1, e)
            final_synth_rerun = None  # fallback verdict — never vote on it
            await metrics.get_metrics().record_event("fallback_verdict", {})
        else:
            triage_final = synth_result_round2.output
            # Round-2 is now the final synthesis (supersedes round-1).
            final_synth_rerun = (synth_agent, user_msg_round2, None)
            r2_reasoning_ev = _reasoning_ev(2, synth_result_round2)
            if r2_reasoning_ev is not None:
                await _audit(r2_reasoning_ev)
                yield r2_reasoning_ev
            usage2_ev = _usage_ev(2, synth_result_round2)
            if usage2_ev is not None:
                await _audit(usage2_ev)
                yield usage2_ev
            # Defensive: enforce single Phase D dispatch — synth round 2 must NOT emit a gap.
            if triage_final.gap_for_investigator is not None:
                triage_final = triage_final.model_copy(update={"gap_for_investigator": None})

    # ----- Self-consistency vote (flag-gated; OFF by default) -----
    # verdict_consistency_samples=1 (the default) skips this entirely: single
    # synthesis call, no vote, `inconclusive` never produced — byte-identical
    # to the pre-vote pipeline. When >1, re-run the SAME final synthesis
    # (same agent + prompt) N-1 more times and majority-vote the verdict
    # BEFORE the deterministic post-validators (the evidence/citation guards
    # below still apply to the voted report). Defensive: a failed sample is
    # dropped; fewer than 2 surviving samples ⇒ no vote (the single available
    # report stands). Fallback-produced verdicts never vote (rerun is None).
    vote_samples = int(getattr(ctx.settings, "verdict_consistency_samples", 1) or 1)
    if vote_samples > 1 and final_synth_rerun is not None:
        sample_agent, sample_msg, sample_limits = final_synth_rerun
        sample_reports: list[TriageReport] = [triage_final]
        for _ in range(vote_samples - 1):
            try:
                async with asyncio.timeout(ctx.settings.investigation_turn_timeout_s):
                    if sample_limits is not None:
                        extra_result = await sample_agent.run(
                            sample_msg, usage_limits=sample_limits
                        )
                    else:
                        extra_result = await sample_agent.run(sample_msg)
            except asyncio.CancelledError:
                raise  # cooperative cancel — propagate, never swallow
            except BaseException as e:
                _LOGGER.warning("self-consistency sample failed (dropped): %s", e)
                continue
            extra_report = extra_result.output
            # Samples never trigger Phase D — strip any gap defensively.
            if extra_report.gap_for_investigator is not None:
                extra_report = extra_report.model_copy(update={"gap_for_investigator": None})
            sample_reports.append(extra_report)
        if len(sample_reports) >= 2:
            voted_verdict, voted_conf, vote_note = _self_consistency_vote(sample_reports)
            vote_tally = dict(Counter(r.verdict for r in sample_reports))
            # Representative sample: first report matching the winning verdict;
            # for an inconclusive split, the highest-confidence sample (its
            # summary/citations/actions are kept — only verdict+confidence are
            # overwritten by the vote, and the note is appended).
            if voted_verdict == "inconclusive":
                representative = max(sample_reports, key=lambda r: r.confidence)
            else:
                representative = next(r for r in sample_reports if r.verdict == voted_verdict)
            triage_final = representative.model_copy(
                update={
                    "verdict": voted_verdict,
                    "confidence": voted_conf,
                    "summary": f"{representative.summary}\n\n[{vote_note}]",
                }
            )
            vote_ev = _ev(
                "self_consistency_vote",
                {
                    "samples": len(sample_reports),
                    "tally": vote_tally,
                    "chosen_verdict": voted_verdict,
                    "note": vote_note,
                },
            )
            await _audit(vote_ev)
            yield vote_ev

    # ----- Post-synth validators -----
    # Mirror the legacy post-synth validator chain: citation validation,
    # citation cap, and verdict floor rewrite. Coverage cap is NOT
    # applied — no investigator ran, so there's no tool-call ledger.
    # When the investigation loop ran, it supersedes Phase D: thread the
    # loop's real message history into citation resolution (so tool/pivot
    # citations resolve against actual ToolCallParts) and treat it like an
    # investigator round — gathered evidence legitimately grounds the
    # verdict, same as a Phase-D round-2. Otherwise keep the existing
    # synth-first behavior.
    targeted_tool: str | None = None
    targeted_messages: list[Any] | None = None
    if ran_investigation_loop:
        targeted_messages = loop_messages
        # Mark "an investigation gathered evidence" — which exempts the verdict
        # from the hard evidence gate + GATE A — ONLY when the loop produced at
        # least one SUCCESSFUL tool call. On the budget/timeout fallback path
        # ``loop_messages`` is None (the round-1 verdict just stands), and a loop
        # whose every call errored gathered nothing; treating either as tool
        # evidence would launder a non-evidence-backed round-1 TP/FP straight
        # past the gate. ``targeted_messages`` is still threaded for tool/pivot
        # citation resolution regardless.
        targeted_tool = _loop_evidence_marker(ran_investigation_loop, loop_messages)
    elif (
        triage_round1.gap_for_investigator is not None
        # Only a SUCCESSFUL Phase-D dispatch that returned DISCRIMINATING DATA
        # counts as evidence. An errored dispatch (error string / tool error dict)
        # OR an empty-but-non-error result (zero OQL hits, internal IP with no
        # blocklist/MISP hit) must NOT exempt the hard evidence gate.
        and _targeted_result_has_data(targeted_result)
    ):
        targeted_tool = triage_round1.gap_for_investigator.tool_name
    triage_final, validation_audit = _synth_first_post_validate(
        triage_final,
        enriched,
        candidate,
        targeted_messages=targeted_messages,
        targeted_tool_called=targeted_tool,
        synthesis_confidence_floor=ctx.settings.synthesis_confidence_floor,
        blocklist=ctx.blocklist,
        internal_cidrs=classification_cidrs,
    )

    # Emit validator events in order.
    if "citation_validation" in validation_audit:
        ev = _ev("citation_validation", {"round": 1, **validation_audit["citation_validation"]})
        await _audit(ev)
        yield ev
    if "citation_cap" in validation_audit:
        ev = _ev("citation_cap", {"round": 1, **validation_audit["citation_cap"]})
        await _audit(ev)
        yield ev
    if "verdict_floor_rewrite" in validation_audit:
        ev = _ev("verdict_floor_rewrite", validation_audit["verdict_floor_rewrite"])
        await _audit(ev)
        yield ev
    if "icmp_solicited_downgrade" in validation_audit:
        ev = _ev("icmp_solicited_downgrade", validation_audit["icmp_solicited_downgrade"])
        await _audit(ev)
        yield ev
    if "ungrounded_host_anchored_tp_downgrade" in validation_audit:
        ev = _ev(
            "ungrounded_host_anchored_tp_downgrade",
            validation_audit["ungrounded_host_anchored_tp_downgrade"],
        )
        await _audit(ev)
        yield ev

    if "malware_rule_name_ungrounded_downgrade" in validation_audit:
        ev = _ev(
            "malware_rule_name_ungrounded_downgrade",
            validation_audit["malware_rule_name_ungrounded_downgrade"],
        )
        await _audit(ev)
        yield ev

    if "evidence_gate_downgrade" in validation_audit:
        ev = _ev("evidence_gate_downgrade", validation_audit["evidence_gate_downgrade"])
        await _audit(ev)
        yield ev
        # Metric: a zero-tool TP/FP was coerced to needs_more_info by the hard
        # evidence gate. Counts how often the gate fires (reliability signal).
        await metrics.get_metrics().record_event("zero_tool_verdict_blocked", {})

    # ----- Oracle escalation (optional, explicit opt-in) -----
    # After all post-validators, escalate to the frontier Oracle when the local
    # triage needs it (uncertain, malware non-TP, or below-floor confidence).
    # The local verdict is preserved in the audit via `local_verdict` in the
    # oracle_escalation event so evaluators can compare both.
    local_triage_final = triage_final  # snapshot before any Oracle override
    if _should_escalate_to_oracle(
        triage_final, enriched, ctx.settings, ran_loop=ran_investigation_loop
    ):
        from soc_ai.agent.decision_templates import (  # noqa: PLC0415
            _rule_signals_attack,
            _rule_signals_malware,
        )

        # Derive the audit reason to match the ACTUAL gate that fired in
        # _should_escalate_to_oracle (same flag + predicate order as above).
        # Previously only _rule_signals_malware was checked here, so an
        # attack-class escalation was mis-labelled "below_confidence".
        if (
            ctx.settings.oracle_escalate_needs_more_info
            and triage_final.verdict == "needs_more_info"
        ):
            escalation_reason = "needs_more_info"
        elif (
            ctx.settings.oracle_escalate_malware_non_tp
            and (_rule_signals_malware(enriched) or _rule_signals_attack(enriched))
            and not (triage_final.verdict == "true_positive" and triage_final.confidence >= 0.7)
            and not (
                ran_investigation_loop
                and triage_final.confidence >= ctx.settings.oracle_skip_after_confident_loop
            )
        ):
            escalation_reason = "malware_non_tp"
        else:
            escalation_reason = "below_confidence"

        esc_ev = _ev(
            "oracle_escalation",
            {
                "reason": escalation_reason,
                "local_verdict": triage_final.verdict,
                "local_confidence": triage_final.confidence,
            },
        )
        await _audit(esc_ev)
        yield esc_ev

        # Build a compact text transcript for the Oracle payload.
        transcript_text = ""
        if loop_messages is not None:
            # Extract evidence text from the investigation loop messages where available.
            parts: list[str] = []
            for msg in loop_messages:
                for part in getattr(msg, "parts", []) or []:
                    content = getattr(part, "content", None)
                    if isinstance(content, str) and content.strip():
                        parts.append(content.strip())
            transcript_text = "\n".join(parts)

        # Reuse the effective internal-identifier set resolved ONCE at the top of
        # the pipeline (env-config union active detected/manual identifiers, minus
        # muted) for the Oracle egress sanitizer's suffixes/hosts. DB access stays
        # in the caller; the sanitizer stays pure. None ⇒ no DB on ctx (CLI / eval
        # / tests) or a resolution failure → the client falls back to the raw
        # settings tuples (behavior unchanged).
        oracle_suffixes = effective_idents.suffixes if effective_idents is not None else None
        oracle_hosts = effective_idents.hosts if effective_idents is not None else None

        oracle_result = await _oracle_client.adjudicate(
            ctx,
            enriched=enriched,
            local_report=triage_final,
            transcript_text=transcript_text,
            extra_hosts=oracle_hosts,
            extra_suffixes=oracle_suffixes,
        )

        if oracle_result is not None:
            # Fix M2: post-validate the Oracle's output with the same
            # deterministic targeted downgrades that ran on the local verdict.
            # Closes the path where the Oracle re-introduces a
            # solicited-internal-ICMP-echo true_positive that the local
            # BPFDoor guard already corrected.  Zero egress — deterministic.
            oracle_audit: dict[str, Any] = {}
            oracle_report = _apply_targeted_downgrades(
                oracle_result.report,
                enriched,
                oracle_audit,
                blocklist=ctx.blocklist,
                internal_cidrs=classification_cidrs,
            )
            # I2: ungrounded host-anchored TP guard — Oracle path parity.
            # Prevents the Oracle from re-escalating to TP solely on host_alert_profile
            # context that the local path already downgraded. enriched is an
            # EnrichedAlertContext: carries .alert, .enrichments, .host_alert_profile.
            oracle_report = _downgrade_ungrounded_host_anchored_tp(
                oracle_report, enriched, oracle_audit
            )

            adj_ev = _ev(
                "oracle_adjudication",
                {
                    "oracle_verdict": oracle_report.verdict,
                    "oracle_confidence": oracle_report.confidence,
                    "redaction": oracle_result.redaction_summary,
                    "oracle_model": oracle_result.oracle_model,
                    **({"oracle_targeted_downgrades": oracle_audit} if oracle_audit else {}),
                },
            )
            await _audit(adj_ev)
            yield adj_ev

            # Mark the Oracle report so UI/audit shows it was adjudicated.
            adjudicated_summary = f"[Oracle adjudicated] {oracle_report.summary}"
            triage_final = oracle_report.model_copy(update={"summary": adjudicated_summary})
        # If oracle_result is None (refusal or failure), triage_final stays
        # unchanged and the local verdict stands.

    # ----- Final triage emit -----
    triage_ev = _ev(
        "triage_report",
        {
            "verdict": triage_final.verdict,
            "confidence": triage_final.confidence,
            "summary": triage_final.summary,
            "citations": triage_final.citations,
            "recommended_actions": [
                a.model_dump(mode="json") for a in triage_final.recommended_actions
            ],
            "field_reconciliation": triage_final.field_reconciliation,
            "validator_note": triage_final.validator_note,
            # Preserve local verdict in the audit when Oracle overrode it.
            "local_verdict": local_triage_final.verdict
            if triage_final is not local_triage_final
            else None,
        },
    )
    await _audit(triage_ev)
    yield triage_ev

    # ----- Auto-acknowledge high-confidence false positives (opt-in) -----
    auto_ack_ev = await maybe_auto_ack_fp(
        triage_final, alert_id, alert=enriched.alert, ctx=ctx, emit_ev=_ev, audit_ev=_audit
    )
    if auto_ack_ev is not None:
        yield auto_ack_ev

    yield _ev("done", {"recommended_count": len(triage_final.recommended_actions)})


__all__ = [
    "InvestigationContext",
    "InvestigationTranscript",
    "RecommendedAction",
    "StepEvent",
    "TriageReport",
    "_should_escalate_to_oracle",
    "build_agent",
    "build_investigator",
    "build_investigator_model",
    "build_local_enrichment_context",
    "build_model",
    "build_synth_first_agent",
    "build_synthesizer",
    "build_synthesizer_model",
    "investigate",
    "maybe_auto_ack_fp",
]
