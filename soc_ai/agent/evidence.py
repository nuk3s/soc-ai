"""Evidence materialization and citation-target helpers.

Turns prefetched context into citable bullets and resolves what a citation
points at.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from soc_ai.tools.get_alert_context import (
    ENDPOINT_COVERAGE_DATASET_ABSENT as _ENDPOINT_COVERAGE_DATASET_ABSENT,
)
from soc_ai.tools.get_alert_context import (
    ENDPOINT_COVERAGE_GAP_KEY as _ENDPOINT_COVERAGE_KEY,
)
from soc_ai.tools.get_alert_context import (
    ENDPOINT_COVERAGE_HOST_UNCOVERED as _ENDPOINT_COVERAGE_HOST_UNCOVERED,
)

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
# Bare tool name, prefix dropped (`t_enrich_ip`), with the same optional
# `:key` qualifier the prefixed form already accepts. All-lowercase with
# the `t_` prefix, so it can't collide with a mixed-case Elasticsearch _id.
_PLAIN_TOOL_RE = re.compile(r"^(t_[a-z0-9_]+)(?:\s*:.*)?$")
# Plain path with the observed value appended (`alert.dns_query=example.com`).
_PLAIN_PATH_EQ_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)\s*=")


def _alert_context_fields() -> frozenset[str]:
    """Top-level field names of the alert-context bundle.

    Bare, underscored, and long enough that ``_PLAIN_ID_RE`` claims them —
    ``host_alert_profile`` classified as an Elasticsearch document id, and an id
    resolves ONLY by membership in the retrieved-id set, where a field name can
    never appear. So it failed to resolve on every investigation that cited it,
    which is every investigation that followed the triage prompt: the prompt
    says "Check `host_alert_profile`" in as many words. Measured on the range,
    that capped otherwise-clean runs at 87.5-90% citation coverage.

    Derived from the model rather than listed here so it cannot drift the day a
    field is added. Read lazily: this module is imported by the orchestrator and
    the tool package imports back through it at module scope.
    """
    from soc_ai.tools.get_alert_context import EnrichedAlertContext  # noqa: PLC0415

    return frozenset(EnrichedAlertContext.model_fields)


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
    # Plain forms. Tool names are checked before the id fallback: a bare
    # `t_web_search` is 12+ chars and would otherwise match _PLAIN_ID_RE,
    # then fail to resolve because tool names never appear in the alert
    # bundle the id branch searches.
    if m := _PLAIN_TOOL_RE.match(s):
        return "tool", m.group(1)
    if _PLAIN_PATH_RE.match(s):
        return "path", s
    if m := _PLAIN_PATH_EQ_RE.match(s):
        return "path", m.group(1)
    # Before the id fallback, and for the same reason tool names are: a name the
    # alert-context bundle actually has is not a document id, and calling it one
    # sends it to a resolver where it can never match. See _alert_context_fields.
    # Classified as a `path` so it resolves the way every other bundle field
    # does — structurally, against the enriched alert — rather than by substring.
    if s in _alert_context_fields():
        return "path", s
    if _PLAIN_ID_RE.match(s):
        return "id", s
    return "unknown", None


# Document-identity keys (M2, 2026-08-25 audit). An id-shaped citation must name
# EVIDENCE the run actually RETRIEVED, so the resolvers collect values from the
# real STRUCTURE of retrieved payloads — never by substring-searching dumped
# text, which an attacker can seed through any plantable field (a DNS label,
# TLS SNI, URI, User-Agent). Keys are matched on the LEAF segment
# (``log.id.uid`` in ES fields-form counts as ``uid``):
#   * ``_id``  — the ES hit id
#   * ``uid``  — the Zeek connection/log uid (zeek rows carry no ``_id``)
#   * ``sid`` / ``uuid`` — detector rule identifiers (t_get_rule_content)
#   * ``sample_ids`` — the analytics tools' per-aggregate ES ``_id`` samples
#     (soc_ai.tools.analytics collects them from top_hits ``_id``s, documented
#     as the citable anchor for a hunt finding)
# Bare ``id`` is deliberately absent: ECS leaves like ``user.id`` can carry
# attacker-supplied text (a probed username), while the contexts that use ``id``
# for document identity (SoAlert / pivot events) are collected explicitly by
# attribute in :func:`soc_ai.agent.gates._retrieved_evidence_tokens`. Embedded
# JSON *strings* are never parsed here — an attacker-controlled payload that
# happens to be valid JSON must not mint identifiers.
_DOC_IDENTITY_KEYS: frozenset[str] = frozenset({"_id", "uid", "sid", "uuid", "sample_ids"})

# The pivot attrs whose values may ALSO satisfy an id-shaped citation (see
# `_TYPED_EVIDENCE_KEYS` below): sensor-computed hashes/fingerprints and a
# fixed-vocabulary cipher enum. An attacker can influence WHICH such value
# appears (by sending different traffic), never mint an arbitrary chosen token.
_PIVOT_ID_SAFE_ATTRS: tuple[str, ...] = (
    "zeek_ssl_ja3",
    "zeek_ssl_ja3s",
    "zeek_files_sha256",
    "zeek_files_md5",
    "zeek_kerberos_cipher",
)

# Pivot event attributes whose values are distinctive enough to prove a verdict
# was grounded in correlated evidence when cited (a JA3, a file hash, a Kerberos
# SPN, a service binary name, an RPC endpoint — not generic fields like a port
# or state). Shared with :mod:`soc_ai.agent.gates` (`_pivot_evidence_tokens` for
# the id-safe subset, `_pivot_wire_string_cited` for the wire-string leaves).
#
# Beyond the id-safe subset above, this set carries four attacker-chosen
# free-form WIRE strings — an SMB file name, a client-requested Kerberos SPN,
# a DCE-RPC endpoint and operation. Citing one of those is legitimate
# GROUNDING (it proves the model read the pivot the orchestrator prefetched),
# but they must never feed id-citation RESOLUTION: the attacker's own flow
# raises the alert, community-id prefetch normalizes that same flow's
# smb/kerberos/dce_rpc rows, and a token planted there would resolve as a
# strict document id (the M2 forgery, reopened through a typed slot).
_PIVOT_DECISIVE_ATTRS: tuple[str, ...] = (
    *_PIVOT_ID_SAFE_ATTRS,
    "zeek_kerberos_service",
    "zeek_smb_name",
    "zeek_dce_rpc_endpoint",
    "zeek_dce_rpc_operation",
)

# Typed-evidence keys (D1, pre-merge review of the M2 fix). `_classify_citation`
# reads ANY bare 12+-char token as id-shaped, which covers a lot of legitimate
# evidence beyond document ids: MD5/SHA-* file hashes, JA3/JA3S fingerprints,
# and long bare detector-metadata values ("Informational", "policy-violation").
# Wave 2 removed the (forgeable) substring fallback those relied on, so every
# such citation became an unforgeable identity claim with no route to
# resolution — a correctly-grounded TP got its severity capped / verdict
# floored. The fix keeps the M2 discipline (STRUCTURAL key membership, never a
# scan of dumped text) and simply widens WHICH leaves count as evidence:
#   * hash leaves — ``file.hash.md5``/``sha1``/``sha256``/``sha512``/``ssdeep``
#     and Zeek/SO ``hash.ja3``/``ja3s`` (also ECS ``tls.client.ja3``): computed
#     by the sensor over observed content; citing one cites the real artifact.
#   * the :data:`_PIVOT_ID_SAFE_ATTRS` leaves — the hash/fingerprint/enum
#     SUBSET of the decisive pivot values. NOT the full
#     :data:`_PIVOT_DECISIVE_ATTRS`: its other four leaves
#     (``zeek_smb_name``, ``zeek_kerberos_service``, ``zeek_dce_rpc_endpoint``,
#     ``zeek_dce_rpc_operation``) are attacker-chosen free-form wire strings
#     that ride the attacker's own flow into the community-id prefetch, so
#     admitting them here reopened M2 through a typed slot. They stay citable
#     GROUNDING evidence in the gates (``_pivot_wire_string_cited``, banded for
#     distinctiveness) — they just
#     cannot satisfy an id-shaped citation's identity claim.
#   * detector-assigned rule metadata — ``signature_severity`` / ``classtype``
#     / ``severity_label`` / ``alert_action``: written by the matched RULE, not
#     by wire content an attacker controls.
# Deliberately absent: every leaf whose VALUE is a free-form string the
# attacker composes — content leaves planted through traffic
# (``dns.query.name`` / ``question.name`` (leaf ``name``), TLS SNI
# (``server_name``), URIs (``full``/``original``/``path``), User-Agent
# (``original``), usernames) and the four wire-string pivot leaves above.
# A token planted in any of them still resolves to nothing.
_TYPED_EVIDENCE_KEYS: frozenset[str] = frozenset(
    {
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "ssdeep",
        "ja3",
        "ja3s",
        "signature_severity",
        "classtype",
        "severity_label",
        "alert_action",
        *_PIVOT_ID_SAFE_ATTRS,
    }
)

# The full evidence-key set a bare id-shaped citation may resolve against:
# document identity plus decisive typed values. Membership-only — the VALUES
# under these keys are harvested; nothing is ever substring-matched.
_EVIDENCE_KEYS: frozenset[str] = _DOC_IDENTITY_KEYS | _TYPED_EVIDENCE_KEYS

# The value classes that may earn the confidence FLOOR-RAISE when the verdict
# asserts one (soc_ai.agent.gates, `confidence_floor_raise`). Raising is on the
# dangerous side of the M2 boundary — a credited value LIFTS a true_positive to
# escalation confidence — so this set is strictly narrower than
# :data:`_EVIDENCE_KEYS`:
#   * sensor-computed digests and fingerprints (``md5``/``sha1``/``sha256``/
#     ``sha512``/``ssdeep``, ``ja3``/``ja3s``): computed by the sensor over
#     observed content. An attacker can influence WHICH value appears (by
#     varying their client or file bytes) but the value is then a true digest
#     of their own observed activity — never an arbitrary minted token.
#   * ``cipher`` — the fixed-vocabulary protocol enum leaf (Kerberos etype,
#     TLS/SSH suite) as raw ES rows spell it (``zeek.kerberos.cipher``); the
#     typed-attr spelling is covered by :data:`_PIVOT_ID_SAFE_ATTRS` below.
#     Same class the M2 audit declared id-safe: choose-from-a-menu, not mint.
#   * the :data:`_PIVOT_ID_SAFE_ATTRS` leaves — the SoAlert typed-attr
#     spellings of the same hash/fingerprint/enum classes.
# Deliberately absent, beyond the free-form content leaves `_EVIDENCE_KEYS`
# already refuses:
#   * document-identity keys (:data:`_DOC_IDENTITY_KEYS`) — a doc id proves
#     the run RETRIEVED a document, not that anything malicious was observed;
#     bare-id citing must never raise confidence (the pinned doctrine in
#     tests/test_recall_fix.py::test_confidence_floor_raise_requires_decisive_value_not_bare_id);
#   * detector rule metadata (``signature_severity``/``classtype``/
#     ``severity_label``/``alert_action``) — crediting the rule's own labels
#     for a confidence raise is rule-label anchoring, the BPFDoor pattern the
#     malware-rule-name gate exists to stop.
_RAISE_SAFE_EVIDENCE_KEYS: frozenset[str] = frozenset(
    {
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "ssdeep",
        "ja3",
        "ja3s",
        "cipher",
        *_PIVOT_ID_SAFE_ATTRS,
    }
)

_MAX_IDENTITY_WALK_DEPTH = 12


def _collect_evidence_values(
    node: Any, out: set[str], depth: int = 0, *, keys: frozenset[str] = _EVIDENCE_KEYS
) -> None:
    """Collect lowercased document-id / typed-evidence strings from real structure.

    Walks dicts/lists only (never parses strings), harvesting string values —
    including fields-form list-wrapped values — whose key's leaf segment is in
    ``keys`` (default :data:`_EVIDENCE_KEYS`; the confidence floor-raise passes
    the narrower :data:`_RAISE_SAFE_EVIDENCE_KEYS`). Depth-bounded and never
    raises on shape surprises; a malformed payload just contributes nothing.
    """
    if depth > _MAX_IDENTITY_WALK_DEPTH:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            leaf = key.rsplit(".", 1)[-1] if isinstance(key, str) else ""
            if leaf in keys:
                if isinstance(value, str) and value:
                    out.add(value.lower())
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item:
                            out.add(item.lower())
            _collect_evidence_values(value, out, depth + 1, keys=keys)
    elif isinstance(node, list):
        for item in node:
            _collect_evidence_values(item, out, depth + 1, keys=keys)


def _path_exists_in_alert(alert_ctx: Any, dotted: str) -> bool:
    """Walk a dotted path against an AlertContext / SoAlert dump.

    ``dotted`` may begin with ``alert.`` (the typed fields on the
    pre-loaded alert) or with a top-level pivot key like
    ``community_id_events`` (less common but legal).

    Zeek/Suricata ``message`` fields arrive as embedded JSON *strings*
    rather than dicts, so the walk parses a string that holds a JSON
    object and keeps descending. Without that, every citation into a
    message body (``alert.message.app_proto``) read as unresolved.

    Some real keys CONTAIN dots — ``enrichments`` is keyed by indicator,
    so an IP-keyed enrichment lives under ``"10.0.0.55"`` — and a true
    citation like ``enrichments.10.0.0.55.internal`` splits into segments
    no single key matches. At each dict level the walk therefore takes the
    LONGEST dot-joined prefix of the remaining segments that is literally
    a key at that level (greedy — it never backtracks to a shorter prefix
    if the longest one later dead-ends). This stays STRUCTURAL: a segment
    run only resolves by exact key membership in the retrieved dump, never
    by scanning dumped text, so a path whose key does not exist in the
    retrieved structure still cannot resolve (the M2 boundary,
    2026-08-25 audit). When no key at a level contains a dot, the longest
    joinable prefix is the single segment and the walk is unchanged.
    """
    try:
        dump = alert_ctx.model_dump(mode="json")
    except Exception:
        return False
    parts = dotted.split(".")
    cur: Any = dump
    i = 0
    while i < len(parts):
        if isinstance(cur, str):
            # Embedded JSON object — parse once and keep walking.
            try:
                parsed = json.loads(cur)
            except (ValueError, TypeError):
                return False
            if not isinstance(parsed, dict | list):
                return False
            cur = parsed
        if isinstance(cur, dict):
            for j in range(len(parts), i, -1):
                candidate = ".".join(parts[i:j])
                if candidate in cur:
                    cur = cur[candidate]
                    i = j
                    break
            else:
                return False
        elif isinstance(cur, list):
            try:
                cur = cur[int(parts[i])]
            except (ValueError, IndexError):
                return False
            i += 1
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


# Tools whose result is soc-ai's own INFERENCE, not an observation — available to
# the agent as context, never as the thing that unlocks a settled verdict.
#
# `t_host_dossier` returns conclusions ("hypervisor, 0.9, from behavioural
# signals") drawn by an earlier build job from telemetry the host itself can
# influence: the name it announces over DHCP, the banner it serves. Its payload is
# dense with truthy, non-bookkeeping keys, so :func:`_targeted_result_has_data`
# reads it as discriminating data and one dossier call was enough to satisfy the
# hard evidence gate — a one-call route to a confident true_positive /
# false_positive having observed nothing this run. That is the failure this
# project has fought repeatedly (the QVOD zero-tool verdict; the fabricated
# `auth.success` of 2026-08-05): inference presented as observation. Excluded here
# rather than by sniffing the payload shape, because the shape is the dossier's
# API and would drift; the tool name is the contract.
#
# `t_decode_payload` is in-process COMPUTE over model-supplied bytes: it decodes
# a base64/hex string the model hands it and reports the entropy/strings/L7 sniff.
# It observes nothing on the grid, so — like the dossier — it must not, on its
# own, count as an investigation. On the Oracle tool surface this matters twice:
# a decode of a string the model INVENTED could otherwise satisfy the override
# gate's "back a flip with ≥1 successful tool call" and flip a verdict class with
# zero grid access. Same argument, same fix: the tool name is the contract.
NON_EVIDENTIAL_TOOLS = frozenset({"t_host_dossier", "t_decode_payload"})


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
    """True iff a tool result carries DISCRIMINATING evidence.

    Backs both the Phase-D targeted-dispatch check and (via
    :func:`count_successful_tool_calls`) the investigation-loop hard gate: an
    empty-but-non-error dict — an OQL/zeek query with zero hits, ``enrich_ip`` on
    an internal IP with no blocklist/MISP hit — gathered nothing and must NOT
    exempt the hard evidence gate.

    Rather than enumerate every data-bearing field (fragile — tools return many
    shapes: hits, sni_servers, dns_queries, asn, prevalence flags…), a result has
    data iff it carries ANY truthy value under a key that is not a bookkeeping /
    classification flag. Search-shaped results (``total``/``hits``) are judged on
    hit count so a zero-hit query is correctly empty.

    Content-only, deliberately: it cannot tell an OBSERVATION from an INFERENCE
    that happens to be richly populated. Whether the tool observes anything at all
    is decided by name, ahead of this call — see :data:`NON_EVIDENTIAL_TOOLS`.
    """
    if not isinstance(result, dict) or result.get("error"):
        return False
    # Search-shaped result (OQL / zeek / cases): data iff there are hits.
    if "total" in result or "hits" in result:
        return bool(result.get("total")) or bool(result.get("hits"))
    # Otherwise: any non-bookkeeping key with a truthy value is gathered evidence.
    return any(v for k, v in result.items() if k not in _NON_EVIDENCE_RESULT_KEYS)


def tool_return_is_evidence(tool_name: Any, content: Any) -> bool:
    """Whether one tool RETURN counts as gathered evidence.

    The single definition behind both readings of a run:
    :func:`count_successful_tool_calls` walks a live PydanticAI history, and
    :func:`recorded_run_retrieved_evidence` walks the same run after it has been
    written to the investigation store. They used to be one implementation and
    no implementation: the recorded side did not exist, so the auto-triage
    inheritance path had no way to ask whether the verdict it was about to
    acknowledge on the analyst's grid rested on anything, and it never asked.

    An error result, a dedup or prefetch short-circuit, an empty list, an
    empty-but-non-error dict, and a return from a :data:`NON_EVIDENTIAL_TOOLS`
    tool (soc-ai's own inference rather than an observation) are all NOT
    evidence.
    """
    if tool_name in NON_EVIDENTIAL_TOOLS:
        return False
    if content is None:
        return False  # a tool that returned nothing is not evidence
    if isinstance(content, dict):
        if (
            content.get("error")
            or content.get("duplicate_call")
            or content.get("prefetch_already_has_this")
        ):
            return False
        # A NON-error dict is only evidence when it carries DISCRIMINATING
        # data. A zero-hit OQL loop message or a clean-internal enrich made
        # a call but discovered nothing; counting it would let one throwaway
        # call satisfy the hard evidence gate (the QVOD zero-tool defect,
        # one call away). Same standard as the Phase-D dispatch.
        return _targeted_result_has_data(content)
    # An empty list (zero hits / no matches) from a list-returning tool —
    # t_query_zeek_logs, t_query_cases, t_query_detections, t_get_playbooks,
    # t_lookup_runbook — gathered nothing. Held to the same standard as an empty
    # dict so one throwaway call cannot exempt the hard evidence gate (the QVOD
    # zero-tool defect).
    return not (isinstance(content, list) and not content)


# Recorded event kinds that can carry a retrieval. Anything else in the store is
# bookkeeping, prompt assembly or a verdict, and says nothing about whether the
# run looked at the world.
RETRIEVAL_EVENT_KINDS: tuple[str, ...] = (
    "tool_result",
    "targeted_tool_result",
    "oracle_adjudication",
)


def recorded_run_retrieved_evidence(events: Iterable[tuple[str, Any]]) -> bool:
    """Whether a run that is already ON DISK retrieved anything.

    Reads the persisted ``(kind, payload)`` pairs a completed investigation left
    behind and answers the same question ``run_retrieved_evidence`` answers live
    in the orchestrator: did a successful tool call, a Phase-D targeted dispatch
    that returned discriminating data, or the Oracle's own tool loop stand
    behind this verdict?

    Needed because a verdict outlives the run that produced it. Auto-triage
    inheritance hands one investigation's false positive to every sibling alert
    on the same rule and address pair, and acknowledges them in Security Onion —
    on production that is roughly 200 grid writes per investigation. Only the
    recorded events can say whether the verdict at the top of that fan-out was
    ever grounded.
    """
    for kind, payload in events:
        p = payload if isinstance(payload, dict) else {}
        if kind == "oracle_adjudication":
            try:
                if int(p.get("oracle_tool_calls") or 0) >= 1:
                    return True
            except (TypeError, ValueError):
                continue
        elif kind == "targeted_tool_result":
            if _targeted_result_has_data(p.get("result")):
                return True
        elif kind == "tool_result" and tool_return_is_evidence(p.get("tool_name"), p.get("result")):
            return True
    return False


def count_successful_tool_calls(messages: list[Any] | None) -> int:
    """Count tool calls that returned NON-error DISCRIMINATING DATA in a PydanticAI history.

    A ``ToolReturnPart`` (duck-typed: has ``content``, lacks ``args``) is counted
    only when its content is usable — an error result (``{"error": True}``), a
    dedup short-circuit (``{"duplicate_call": True}``) or a prefetch short-circuit
    (``{"prefetch_already_has_this": True}``) does NOT count, because none of them
    gathered new evidence. Nor does an empty-but-non-error result (a zero-hit OQL
    query, a clean-internal enrich): it made a call but discovered nothing, so it
    is held to the same discriminating-data standard as the Phase-D path
    (:func:`_targeted_result_has_data`). Nor does a return from a tool in
    :data:`NON_EVIDENTIAL_TOOLS`, whose content is soc-ai's own inference rather
    than an observation. Counting returns (not call parts) sidesteps the fragile
    call/return pairing by ``tool_call_id``. Returns 0 for None/empty. This is the
    signal behind the hard evidence gate: did the agent actually investigate, or
    just reason over prefetch?
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
            # Content tests live in tool_return_is_evidence so the recorded
            # reading of the same run cannot drift from this one.
            if tool_return_is_evidence(getattr(part, "tool_name", None), part.content):
                n += 1
    return n


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

    # Blocklist coverage. Same shape and the same reasoning as the endpoint
    # coverage gap below: when the feeds loaded nothing, every lookup missed and
    # the miss says nothing. Handed over as a citable fact so the synthesizer
    # can name it, instead of a silence it reads as a clean reputation check.
    # ONE bullet for the run, not one per indicator, and only on an explicit
    # False — an unrecorded enrichment makes no claim. Constant wording apart
    # from the citation path.
    unchecked = next(
        (i for i, e in enrichments.items() if getattr(e, "blocklist_checked", None) is False),
        None,
    )
    if unchecked is not None:
        evidence.append(
            "blocklist coverage gap: no local threat-intel feed was loaded, so no indicator "
            "was checked against one — every empty blocklist_hits in this bundle is an "
            "absence of data, not a clean reputation result; not exoneration and not guilt "
            f"(path enrichments.{unchecked}.blocklist_sources)"
        )

    # Endpoint coverage. When the prefetch established that the alert's hosts
    # ship no endpoint telemetry (or the grid holds none at all), hand the
    # synthesizer that fact as a CITABLE negative finding — otherwise it can
    # only hedge around the missing process/file evidence, or return NMI
    # naming an endpoint query that is guaranteed empty. The citation resolves
    # against the bundle (prefetch_gaps carries the reason token). Constant
    # wording, no per-run values: identical for a real uncovered host and a
    # planted one.
    coverage = (getattr(alert_ctx, "prefetch_gaps", None) or {}).get(_ENDPOINT_COVERAGE_KEY)
    if coverage == _ENDPOINT_COVERAGE_HOST_UNCOVERED:
        evidence.append(
            "endpoint coverage gap: the grid ships endpoint telemetry, but this alert's "
            "hosts have no endpoint documents in the surrounding window — no endpoint "
            "agent covers them, so endpoint evidence cannot exist for them; a coverage "
            "gap, not exoneration and not guilt (path prefetch_gaps.endpoint.coverage)"
        )
    elif coverage == _ENDPOINT_COVERAGE_DATASET_ABSENT:
        evidence.append(
            "endpoint coverage gap: the grid holds no endpoint/host-agent telemetry at "
            "all in the surrounding window — endpoint evidence cannot exist for any host "
            "here; a coverage gap, not exoneration (path prefetch_gaps.endpoint.coverage)"
        )

    return evidence


def _bundle_dump_text(alert_ctx: Any) -> str:
    """Lower-cased JSON dump of the prefetch bundle for substring matching."""
    try:
        import json as _json  # noqa: PLC0415

        return _json.dumps(alert_ctx.model_dump(mode="json"), default=str).lower()
    except Exception:
        return ""
