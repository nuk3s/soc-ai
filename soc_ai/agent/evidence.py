"""Evidence materialization and citation-target helpers.

Turns prefetched context into citable bullets and resolves what a citation
points at.
"""

from __future__ import annotations

import re
from typing import Any

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
    """
    if not isinstance(result, dict) or result.get("error"):
        return False
    # Search-shaped result (OQL / zeek / cases): data iff there are hits.
    if "total" in result or "hits" in result:
        return bool(result.get("total")) or bool(result.get("hits"))
    # Otherwise: any non-bookkeeping key with a truthy value is gathered evidence.
    return any(v for k, v in result.items() if k not in _NON_EVIDENCE_RESULT_KEYS)


def count_successful_tool_calls(messages: list[Any] | None) -> int:
    """Count tool calls that returned NON-error DISCRIMINATING DATA in a PydanticAI history.

    A ``ToolReturnPart`` (duck-typed: has ``content``, lacks ``args``) is counted
    only when its content is usable — an error result (``{"error": True}``), a
    dedup short-circuit (``{"duplicate_call": True}``) or a prefetch short-circuit
    (``{"prefetch_already_has_this": True}``) does NOT count, because none of them
    gathered new evidence. Nor does an empty-but-non-error result (a zero-hit OQL
    query, a clean-internal enrich): it made a call but discovered nothing, so it
    is held to the same discriminating-data standard as the Phase-D path
    (:func:`_targeted_result_has_data`). Counting returns (not call parts)
    sidesteps the fragile call/return pairing by ``tool_call_id``. Returns 0 for
    None/empty. This is the signal behind the hard evidence gate: did the agent
    actually investigate, or just reason over prefetch?
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
            if isinstance(c, dict):
                if c.get("error") or c.get("duplicate_call") or c.get("prefetch_already_has_this"):
                    continue
                # A NON-error dict is only evidence when it carries DISCRIMINATING
                # data. A zero-hit OQL loop message or a clean-internal enrich made
                # a call but discovered nothing; counting it would let one throwaway
                # call satisfy the hard evidence gate (the QVOD zero-tool defect,
                # one call away). Same standard as the Phase-D dispatch.
                if not _targeted_result_has_data(c):
                    continue
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

    return evidence


def _bundle_dump_text(alert_ctx: Any) -> str:
    """Lower-cased JSON dump of the prefetch bundle for substring matching."""
    try:
        import json as _json  # noqa: PLC0415

        return _json.dumps(alert_ctx.model_dump(mode="json"), default=str).lower()
    except Exception:
        return ""
