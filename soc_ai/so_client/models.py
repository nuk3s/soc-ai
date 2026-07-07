"""Pydantic models for Security Onion entities.

These are typed *views* over SO documents - they preserve the original payload
in :attr:`raw` so tools can pivot to fields the model doesn't surface, and
expose the most commonly-accessed fields as named attributes.

ECS-formatted documents (Zeek, Suricata) come from Elasticsearch and use either
nested (``{"rule": {"name": "..."}}``) or flat-dotted (``{"rule.name": "..."}``)
layouts. The :func:`get_dotted` helper handles both.

Case/Detection/Playbook documents come from the SOC Web API and are flat JSON.

**Typed Suricata fields.** (issue #10) The orchestrator
pre-parses Suricata's rich-but-buried fields into first-class attributes:

- :attr:`SoAlert.rule_metadata` — Suricata rule metadata (signature_severity,
  attack_target, confidence, deployment) flattened from
  ``rule.metadata.<field>[0]``.
- :attr:`SoAlert.dns_query` / :attr:`SoAlert.dns_rcode_name` — DNS context
  for DNS-rule alerts.
- :attr:`SoAlert.alert_action` / :attr:`SoAlert.event_action` — what the
  detection actually did (``allowed`` / ``blocked``) and what the action
  was tagged as in ECS.
- :attr:`SoAlert.event_module` / :attr:`SoAlert.event_dataset` — the
  module/dataset that fired (``suricata`` / ``suricata.alert``).

This eliminates a class of "model dug through `message` JSON and missed the
obvious" failures surfaced in the Phase 3 v3 meta-analysis.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# `get_dotted` is defined canonically in `fields.py` (which must be importable
# by this module without a cycle — fields.py never imports models.py). Re-export
# it here so existing callers (`from soc_ai.so_client.models import get_dotted`)
# keep working. `first_present` + the candidate tables drive ECS-first reads with
# a zeek.* fallback (see `_extract_zeek_typed`).
from soc_ai.so_client import fields
from soc_ai.so_client.fields import first_present, get_dotted

__all__ = [
    "RuleMetadata",
    "SoAlert",
    "SoCase",
    "SoDetection",
    "SoPlaybook",
    "SoPlaybookQuestion",
    "get_dotted",
]


def _parse_iso(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp, accepting trailing ``Z``.

    Naive timestamps (no timezone suffix) are treated as UTC — SO clusters
    typically store ``@timestamp`` in UTC but Filebeat / Logstash may omit
    the ``Z`` suffix.  Without this coercion, pivot windows computed as
    ``alert.timestamp ± half`` would shift by the local process timezone,
    causing the agent to miss evidence in the cluster.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    return None


def _first(value: Any) -> Any:
    """Suricata stuffs single-string scalars into single-element lists in
    ``rule.metadata.*``. This helper returns ``v[0]`` when ``v`` is a list,
    ``v`` otherwise, ``None`` when missing/empty."""
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _extract_zeek_typed(source: dict[str, Any], parse_errors: list[str]) -> dict[str, Any]:
    """Pull typed Zeek protocol fields off a Zeek/ECS event _source.

    Issue #20 — surfaces dns/ssl/conn/http details the investigator
    used to dig out of stringified JSON. Each field is best-effort:
    type errors append a note to ``parse_errors`` and the field stays
    None so the agent knows to fall back to ``raw``.

    **ECS-first resolution (prefetch-drops-payload root cause).** Modern SO
    (Elastic-Agent 9.x) populates ECS field names — ``client.bytes``,
    ``hash.ja3s``, ``ssl.server_name``, ``http.virtual_host`` — and leaves the
    ``zeek.*`` fields *mapped but empty*. Reading ``zeek.*`` directly therefore
    returned None on the live grid, blinding the agent to the very payload
    this prefetch exists to surface (synth recall=0). Every field below now
    resolves through :func:`first_present` against an ECS-first candidate list
    (see :mod:`soc_ai.so_client.fields`) with the legacy ``zeek.*`` name LAST,
    so modern ECS docs *and* the synth fixtures / older SO both populate.

    Field names on the model keep the ``zeek_*`` prefix for schema stability;
    only WHICH ES field feeds them changed.
    """
    out: dict[str, Any] = {}

    def _coerce(name: str, value: Any, kind: type) -> Any:
        if value is None:
            return None
        try:
            return kind(value)
        except (TypeError, ValueError):
            parse_errors.append(f"{name}: expected {kind.__name__}, got {type(value).__name__}")
            return None

    # conn state/history/duration — ECS connection.* / event.duration first.
    out["zeek_conn_state"] = first_present(source, fields.CONN_STATE)
    out["zeek_conn_history"] = first_present(source, fields.CONN_HISTORY)
    out["zeek_conn_duration"] = _coerce(
        "conn.duration", first_present(source, fields.CONN_DURATION), float
    )
    # conn byte volumes — the exfil-asymmetry signal. A long-lived connection
    # with orig_bytes >> resp_bytes (e.g. 4.2 GB out / 4.1 MB in) is the
    # textbook data-exfil shape; on modern SO these live at client.bytes /
    # server.bytes (the prefetch used to read empty zeek.conn.*_bytes and drop
    # them, blinding the agent to large outbound transfers). first_present
    # preserves a literal 0 byte-count (not treated as missing).
    out["zeek_conn_orig_bytes"] = _coerce(
        "conn.orig_bytes", first_present(source, fields.CONN_ORIG_BYTES), int
    )
    out["zeek_conn_resp_bytes"] = _coerce(
        "conn.resp_bytes", first_present(source, fields.CONN_RESP_BYTES), int
    )
    # dns.* — ECS dns.query.name / dns.response.code_name first; zeek.dns.query
    # is list-wrapped so keep the `_first` unwrap (harmless on ECS scalars).
    out["zeek_dns_query"] = _first(first_present(source, fields.DNS_QUERY))
    out["zeek_dns_rcode_name"] = first_present(source, fields.DNS_RCODE)
    # rejected has no ECS equivalent — read the zeek.* field directly.
    rejected = get_dotted(source, "zeek.dns.rejected")
    out["zeek_dns_rejected"] = bool(rejected) if rejected is not None else None
    # ssl/tls.* — ECS ssl.server_name / hash.ja3 / hash.ja3s first. Keep the
    # legacy zeek.ssl.*_hash fallback (not in the candidate tables) so older
    # ingest layouts that wrote *_hash still resolve.
    out["zeek_ssl_server_name"] = first_present(source, fields.SSL_SNI)
    out["zeek_ssl_ja3"] = first_present(source, fields.SSL_JA3) or get_dotted(
        source, "zeek.ssl.ja3_hash"
    )
    # ja3s is the SERVER-side TLS fingerprint — complements ja3 (client) for
    # identifying C2/beacon frameworks (e.g. a Cobalt Strike team-server ja3s).
    out["zeek_ssl_ja3s"] = first_present(source, fields.SSL_JA3S) or get_dotted(
        source, "zeek.ssl.ja3s_hash"
    )
    # files.* — transferred-file metadata (MIME + hashes + size). A PE
    # (`application/x-dosexec`) pulled over HTTP, with a hash to pivot on, is
    # the single strongest malware-delivery signal; on modern SO these live at
    # file.mime_type / file.hash.* / file.size. Surface it on the prefetch so
    # the agent sees WHAT was downloaded without calling t_query_zeek_logs.
    out["zeek_files_mime_type"] = first_present(source, fields.FILE_MIME)
    out["zeek_files_md5"] = first_present(source, fields.FILE_MD5)
    out["zeek_files_sha256"] = first_present(source, fields.FILE_SHA256)
    out["zeek_files_total_bytes"] = _coerce(
        "files.total_bytes", first_present(source, fields.FILE_SIZE), int
    )
    # http.* — ECS http.method / http.virtual_host / http.uri / http.status_code
    # / user_agent.original first.
    out["zeek_http_method"] = first_present(source, fields.HTTP_METHOD)
    out["zeek_http_host"] = first_present(source, fields.HTTP_HOST)
    out["zeek_http_uri"] = first_present(source, fields.HTTP_URI)
    out["zeek_http_status"] = _coerce(
        "http.status_code", first_present(source, fields.HTTP_STATUS), int
    )
    out["zeek_http_user_agent"] = first_present(source, fields.HTTP_USER_AGENT)
    # dns qtype / ssl established / conn service — candidate tables existed but
    # were never surfaced. qtype (e.g. TXT-heavy) is the DNS-tunnel corroborator;
    # ssl established distinguishes a completed TLS session from a scan.
    out["zeek_dns_qtype"] = first_present(source, fields.DNS_QTYPE)
    established = first_present(source, fields.SSL_ESTABLISHED)
    out["zeek_ssl_established"] = bool(established) if established is not None else None
    out["zeek_conn_service"] = first_present(source, fields.CONN_SERVICE)
    # kerberos (Kerberoasting): cipher carries the ticket encryption — RC4-HMAC is
    # the decisive roast signature; service is the requested SPN.
    out["zeek_kerberos_cipher"] = first_present(source, fields.KERBEROS_CIPHER)
    out["zeek_kerberos_service"] = first_present(source, fields.KERBEROS_SERVICE)
    out["zeek_kerberos_request_type"] = first_present(source, fields.KERBEROS_REQUEST_TYPE)
    # smb / dce-rpc (PsExec-style lateral): a file write of a service binary to
    # ADMIN$, then an svcctl CreateServiceW — the classic remote-exec chain.
    out["zeek_smb_action"] = first_present(source, fields.SMB_FILE_ACTION)
    out["zeek_smb_name"] = first_present(source, fields.SMB_FILE_NAME)
    out["zeek_smb_mapping_service"] = first_present(source, fields.SMB_MAPPING_SERVICE)
    out["zeek_dce_rpc_endpoint"] = first_present(source, fields.DCE_RPC_ENDPOINT)
    out["zeek_dce_rpc_operation"] = first_present(source, fields.DCE_RPC_OPERATION)
    # ssh — a COMPLETED authentication (auth_success) is the decisive lateral /
    # intrusion signal; combined with a bad-reputation source it's a confirmed login.
    ssh_auth = first_present(source, fields.SSH_AUTH_SUCCESS)
    out["zeek_ssh_auth_success"] = bool(ssh_auth) if ssh_auth is not None else None
    out["zeek_ssh_auth_attempts"] = _coerce(
        "ssh.auth_attempts", first_present(source, fields.SSH_AUTH_ATTEMPTS), int
    )
    out["zeek_ssh_client"] = first_present(source, fields.SSH_CLIENT)
    out["zeek_ssh_server"] = first_present(source, fields.SSH_SERVER)
    # behavioral-summary pivots — read the whole profile object (a nested dict)
    # when a derived beacon/DNS-tunnel summary doc is present; None otherwise.
    beacon = first_present(source, fields.BEACON_PROFILE)
    out["zeek_beacon_profile"] = beacon if isinstance(beacon, dict) else None
    dns_profile = first_present(source, fields.DNS_TUNNEL_PROFILE)
    out["zeek_dns_profile"] = dns_profile if isinstance(dns_profile, dict) else None
    return out


def _parse_message_json(message: str | None) -> dict[str, Any]:
    """Parse Suricata's `message` blob (a JSON string carrying alert details).

    Returns ``{}`` on missing / malformed input. Suricata writes alert
    metadata twice — once as native ECS top-level fields (``rule.*``,
    ``dns.*``, etc.) and once as a JSON string inside ``message`` — and
    different deployments populate these inconsistently. We pull from
    both.
    """
    if not message or not isinstance(message, str):
        return {}
    try:
        parsed = json.loads(message)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


class RuleMetadata(BaseModel):
    """Suricata rule metadata, flattened from ``rule.metadata.<field>[0]``.

    Suricata wraps every metadata key as a single-element list (because
    multiple rules can contribute the same key). We unpack the first
    element since the typical case is one-rule-one-value.
    """

    model_config = ConfigDict(extra="forbid")

    signature_severity: str | None = None  # "Informational" | "Minor" | "Major" | "Critical"
    attack_target: str | None = None  # "Client_Endpoint" | "Server_*" | ...
    confidence: str | None = None  # "Low" | "Medium" | "High"
    deployment: str | None = None  # "Perimeter" | "Internal" | "SSLDecrypt"
    performance_impact: str | None = None  # "Low" | "Medium" | "High"
    metadata_tags: list[str] = Field(default_factory=list)  # rule.metadata.tag[]

    @property
    def is_informational(self) -> bool:
        """``True`` when Suricata classifies the signature as Informational.

        Used by the orchestrator's fast-path routing (issue #13) to
        short-circuit ET INFO / policy-only alerts before the heavy
        investigator runs.
        """
        return (self.signature_severity or "").strip().lower() == "informational"

    @classmethod
    def from_rule_metadata_block(cls, metadata: Any) -> RuleMetadata | None:
        """Extract typed fields from a ``rule.metadata`` block.

        Returns ``None`` if the input isn't a dict or has no recognized
        keys, so callers can keep ``rule_metadata`` as ``None`` rather
        than emitting a wholly-empty model.
        """
        if not isinstance(metadata, dict):
            return None
        sig_sev = _first(metadata.get("signature_severity"))
        attack_target = _first(metadata.get("attack_target"))
        confidence = _first(metadata.get("confidence"))
        deployment = _first(metadata.get("deployment"))
        perf_impact = _first(metadata.get("performance_impact"))
        tags_raw = metadata.get("tag") or []
        if isinstance(tags_raw, str):
            tags_raw = [tags_raw]
        if not any([sig_sev, attack_target, confidence, deployment, perf_impact, tags_raw]):
            return None
        return cls(
            signature_severity=sig_sev,
            attack_target=attack_target,
            confidence=confidence,
            deployment=deployment,
            performance_impact=perf_impact,
            metadata_tags=[str(t) for t in tags_raw],
        )


class SoAlert(BaseModel):
    """A Security Onion alert (typed view over an ES document from ``so-events-*``)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    timestamp: datetime | None = None
    rule_name: str | None = None
    rule_uuid: str | None = None
    severity_label: str | None = None
    severity_score: int | None = None
    network_community_id: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    host_name: str | None = None
    host_ip: list[str] = Field(default_factory=list)
    user_name: str | None = None
    process_entity_id: str | None = None
    file_hash_sha256: str | None = None
    message: str | None = None
    tags: list[str] = Field(default_factory=list)
    # --- Typed Suricata fields (issue #10) ---
    # Pre-parsed in `from_es_hit` so the agent never has to dig through
    # the nested rule.metadata blob or the message JSON string.
    rule_metadata: RuleMetadata | None = None
    dns_query: str | None = None
    dns_rcode_name: str | None = None
    # Action the detection took / will take. From either ECS event.action
    # OR the alert.action field inside the message JSON.
    event_action: str | None = None
    alert_action: str | None = None
    # Suricata classtype (e.g. ``trojan-activity``, ``misc-activity``,
    # ``attempted-recon``). Parsed from the message JSON's
    # ``alert.category`` field. Used by the rule-class classifier
    # (issue #18) as the strongest routing signal — rule-author-declared
    # metadata about what kind of activity the signature targets.
    classtype: str | None = None
    # ECS event.module / event.dataset / event.category — the source-of-truth
    # routing keys for batch eval queries and fast-path routing.
    event_module: str | None = None
    event_dataset: str | None = None
    event_category: str | None = None
    # --- Suricata payload (issue #20) ---
    # The actual packet bytes Suricata's `content:` matched against,
    # rendered as printable text. For DNS rules this is the queried
    # domain (e.g. `a-us.storyblok.com`); for SSL rules the SNI; for
    # banner/HTTP rules the request line + headers. The model should
    # consult this BEFORE inferring intent from rule_name alone.
    payload_printable: str | None = None
    # --- Typed Zeek fields (issue #20) ---
    # Only populated when the underlying ES document is a Zeek event
    # (event.dataset starts with "zeek."). For Suricata alerts these
    # remain None — the SO ingest pipeline pollutes Suricata's top-
    # level `dns.*` block with the rule's `content:` match string, so
    # we deliberately do NOT cross-populate.
    zeek_conn_state: str | None = None
    zeek_conn_duration: float | None = None
    zeek_conn_history: str | None = None
    # Byte volumes — orig_bytes >> resp_bytes on a long conn = exfil shape.
    zeek_conn_orig_bytes: int | None = None
    zeek_conn_resp_bytes: int | None = None
    zeek_dns_query: str | None = None
    zeek_dns_rcode_name: str | None = None
    zeek_dns_rejected: bool | None = None
    zeek_ssl_server_name: str | None = None
    zeek_ssl_ja3: str | None = None
    zeek_ssl_ja3s: str | None = None
    # Transferred-file metadata (zeek.files) — MIME + hashes + size. A PE
    # over HTTP (`application/x-dosexec`) is a top-tier malware-delivery IOC.
    zeek_files_mime_type: str | None = None
    zeek_files_md5: str | None = None
    zeek_files_sha256: str | None = None
    zeek_files_total_bytes: int | None = None
    zeek_http_method: str | None = None
    zeek_http_host: str | None = None
    zeek_http_uri: str | None = None
    zeek_http_status: int | None = None
    zeek_http_user_agent: str | None = None
    # DNS query type (TXT-heavy = tunnel corroborator), TLS established flag,
    # and the conn service label. Tables existed; now surfaced.
    zeek_dns_qtype: str | None = None
    zeek_ssl_established: bool | None = None
    zeek_conn_service: str | None = None
    # Kerberos (Kerberoasting): ticket cipher (RC4-HMAC = decisive), requested
    # service principal (SPN), and request type (TGS vs AS).
    zeek_kerberos_cipher: str | None = None
    zeek_kerberos_service: str | None = None
    zeek_kerberos_request_type: str | None = None
    # SMB / DCE-RPC (PsExec-style lateral movement): the file-write action + name
    # (e.g. PSEXESVC.exe), the target share service (ADMIN$), and the RPC
    # endpoint/operation (svcctl / CreateServiceW).
    zeek_smb_action: str | None = None
    zeek_smb_name: str | None = None
    zeek_smb_mapping_service: str | None = None
    zeek_dce_rpc_endpoint: str | None = None
    zeek_dce_rpc_operation: str | None = None
    # SSH — a completed auth (auth_success=true) is the decisive interactive-login
    # signal; combined with a bad-reputation source it is a confirmed intrusion.
    zeek_ssh_auth_success: bool | None = None
    zeek_ssh_auth_attempts: int | None = None
    zeek_ssh_client: str | None = None
    zeek_ssh_server: str | None = None
    # Behavioral-summary pivots (derived/aggregated docs, when the deployment
    # surfaces them): a RITA-style beacon profile (interval + payload-size
    # consistency over a window) and a DNS-tunnel aggregate (query volume +
    # subdomain entropy + qtype mix). Each is the whole profile object; the
    # decisive-evidence surfacer reads the scoring keys off it. None on
    # ordinary per-connection docs.
    zeek_beacon_profile: dict[str, Any] | None = None
    zeek_dns_profile: dict[str, Any] | None = None
    # Best-effort parsing surface: when typed extraction fails on a
    # field (schema drift, missing block, type mismatch), append a
    # short note here so the investigator knows to fall back to `raw`.
    prefetch_parse_errors: list[str] = Field(default_factory=list)
    # ---
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @classmethod
    def from_es_hit(cls, hit: dict[str, Any]) -> SoAlert:
        """Construct a typed :class:`SoAlert` from a raw ``hits.hits[i]`` entry."""
        source = hit.get("_source", {}) or {}
        parse_errors: list[str] = []
        host_ip_raw = get_dotted(source, "host.ip") or []
        if isinstance(host_ip_raw, str):
            host_ip_raw = [host_ip_raw]
        # rule.metadata is a nested dict of single-element lists.
        rule_metadata = RuleMetadata.from_rule_metadata_block(get_dotted(source, "rule.metadata"))
        # message is a JSON string with alert/flow/event_type details. We pull
        # action from inside it as a fallback when ECS event.action is absent.
        message_raw = source.get("message")
        message_parsed = _parse_message_json(message_raw)
        if isinstance(message_raw, str) and message_raw and not message_parsed:
            # message looked like JSON but failed to parse — surface so the
            # agent knows to fall back to raw `message` instead of the
            # typed fields below.
            parse_errors.append("message: failed to parse as JSON")
        # event.category is sometimes a list; flatten to first.
        event_category = _first(get_dotted(source, "event.category"))
        event_dataset = get_dotted(source, "event.dataset")

        # ---- DNS extraction with the polluted-source guard (issue #20) ----
        # Suricata's SO ingest pipeline pollutes the top-level `dns` block
        # with the rule's `content:` match string regardless of rule type.
        # That field is NOT a real DNS query, so we ONLY trust it on
        # documents that are actually Zeek DNS records.
        dns_query: str | None = None
        dns_rcode_name: str | None = None
        is_zeek_dns = isinstance(event_dataset, str) and event_dataset == "zeek.dns"
        if is_zeek_dns:
            # ECS-first (dns.query.name / dns.response.code_name on modern SO),
            # then the legacy dns.query_name / zeek.dns.* names. zeek.dns.query
            # is list-wrapped, so unwrap with `_first` (harmless on scalars).
            dns_query = _first(get_dotted(source, "dns.query_name")) or _first(
                first_present(source, fields.DNS_QUERY)
            )
            dns_rcode_name = get_dotted(source, "dns.rcode_name") or first_present(
                source, fields.DNS_RCODE
            )
        # For Suricata + other event types: leave dns_query/dns_rcode_name
        # as None. The agent should consult `payload_printable` instead.

        # ---- Typed Zeek fields (issue #20) ----
        # Populated only for Zeek datasets so non-Zeek events don't have
        # bogus zero values. Wrapped in try/except to keep prefetch
        # robust to schema drift (note added to prefetch_parse_errors).
        zeek_typed: dict[str, Any] = {}
        if isinstance(event_dataset, str) and event_dataset.startswith("zeek."):
            zeek_typed = _extract_zeek_typed(source, parse_errors)

        return cls(
            id=hit["_id"],
            timestamp=_parse_iso(source.get("@timestamp")),
            rule_name=get_dotted(source, "rule.name"),
            rule_uuid=get_dotted(source, "rule.uuid"),
            severity_label=get_dotted(source, "event.severity_label")
            or get_dotted(source, "rule.severity"),
            severity_score=get_dotted(source, "event.severity"),
            network_community_id=get_dotted(source, "network.community_id"),
            source_ip=get_dotted(source, "source.ip"),
            source_port=get_dotted(source, "source.port"),
            destination_ip=get_dotted(source, "destination.ip"),
            destination_port=get_dotted(source, "destination.port"),
            host_name=get_dotted(source, "host.name"),
            host_ip=list(host_ip_raw),
            user_name=get_dotted(source, "user.name"),
            process_entity_id=get_dotted(source, "process.entity_id"),
            file_hash_sha256=get_dotted(source, "file.hash.sha256"),
            message=message_raw if isinstance(message_raw, str) else None,
            tags=list(source.get("tags") or []),
            rule_metadata=rule_metadata,
            dns_query=dns_query,
            dns_rcode_name=dns_rcode_name,
            event_action=get_dotted(source, "event.action"),
            alert_action=get_dotted(message_parsed, "alert.action"),
            # Suricata writes the classtype (e.g. ``trojan-activity``,
            # ``misc-activity``) as ``alert.category`` inside the
            # message JSON. We surface it as ``classtype`` because
            # that's the upstream Suricata terminology and avoids
            # collision with ECS ``event.category``.
            classtype=get_dotted(message_parsed, "alert.category"),
            event_module=get_dotted(source, "event.module"),
            event_dataset=event_dataset,
            event_category=event_category,
            # Suricata writes the actual matched packet bytes here. For
            # DNS-rule alerts this carries the queried domain (e.g.
            # `a-us.storyblok.com`); for SSL the SNI; for HTTP the
            # request line + headers. Most useful single field on the
            # alert payload, full stop.
            payload_printable=get_dotted(message_parsed, "payload_printable")
            or source.get("payload_printable"),
            **zeek_typed,
            prefetch_parse_errors=parse_errors,
            raw=source,
        )


class SoCase(BaseModel):
    """A SOC case document from the ``/connect/case/*`` endpoints."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str | None = None
    status: str
    severity: str | None = None
    priority: str | None = None
    assignee_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    created: datetime | None = None
    updated: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @classmethod
    def from_so_doc(cls, doc: dict[str, Any]) -> SoCase:
        """Construct from a raw SOC API case JSON object."""
        return cls(
            id=doc["id"],
            title=doc.get("title", ""),
            description=doc.get("description"),
            status=doc.get("status", "unknown"),
            severity=doc.get("severity"),
            priority=doc.get("priority"),
            assignee_id=doc.get("assigneeId"),
            tags=list(doc.get("tags") or []),
            created=_parse_iso(doc.get("createTime")),
            updated=_parse_iso(doc.get("updateTime")),
            raw=doc,
        )


class SoDetection(BaseModel):
    """A SOC detection document (Suricata/Strelka/etc.) from ``/connect/detection/*``."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    publicId: str | None = None
    severity: str | None = None
    engine: str | None = None
    is_enabled: bool = True
    author: str | None = None
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @classmethod
    def from_so_doc(cls, doc: dict[str, Any]) -> SoDetection:
        # Live SO 3.x nests the detection under `so_detection.*`; older/flat
        # docs (and the SO /connect API) keep the fields top-level.
        det = doc.get("so_detection")
        if not isinstance(det, dict):
            det = doc
        return cls(
            id=str(det.get("id") or det.get("publicId") or ""),
            title=det.get("title", ""),
            publicId=det.get("publicId"),
            severity=det.get("severity"),
            engine=det.get("engine"),
            is_enabled=bool(det.get("isEnabled", True)),
            author=det.get("author"),
            tags=list(det.get("tags") or []),
            raw=doc,
        )


class SoPlaybookQuestion(BaseModel):
    """A single question within a playbook (analyst checklist item)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    question: str
    answer: str | None = None
    is_required: bool = False


class SoPlaybook(BaseModel):
    """A SOC playbook document from ``/connect/playbook/*``."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    description: str | None = None
    questions: list[SoPlaybookQuestion] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @classmethod
    def from_so_doc(cls, doc: dict[str, Any]) -> SoPlaybook:
        questions = [
            SoPlaybookQuestion(
                id=q["id"],
                question=q.get("question", ""),
                answer=q.get("answer"),
                is_required=bool(q.get("isRequired", False)),
            )
            for q in (doc.get("questions") or [])
        ]
        return cls(
            id=doc["id"],
            title=doc.get("title", ""),
            description=doc.get("description"),
            questions=questions,
            raw=doc,
        )
