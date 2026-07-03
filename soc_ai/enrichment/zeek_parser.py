"""Aggregate typed Zeek protocol evidence across the prefetched pivots.

The synth-first pipeline hands the model a ``TypedZeekFields`` roll-up of the
decisive protocol signals found across the ``community_id`` / host pivots, so the
model sees the JA3 pair, the exfil byte-asymmetry, the delivered PE's hash, and the
Kerberos/SMB attack chain WITHOUT having to issue a tool call.

**Read the typed attributes, not the raw message (recall-fix 2026-07-02).** Every
pivoted Zeek doc is a :class:`SoAlert` whose ``zeek_*`` attributes were already
resolved ECS-first by :func:`SoAlert._extract_zeek_typed`. The previous version
re-parsed each pivot's raw ``message`` JSON with a narrow key set — it surfaced SNI
but dropped ja3/ja3s, conn byte-volumes, and file mime/hash, blinding the model to
the very evidence the TP scenarios turn on (synth recall ≈ 0). We now roll up
straight from the typed attributes, and keep a small ``message`` parse only for the
two things not carried on the typed model: the DNS answer list and the
solicited-ICMP-echo detection.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field

from soc_ai.so_client.models import SoAlert

_LOGGER = logging.getLogger(__name__)


class TypedZeekFields(BaseModel):
    dns_queries: list[str] = Field(default_factory=list)
    dns_answers: list[str] = Field(default_factory=list)
    dns_rcode_names: list[str] = Field(default_factory=list)
    dns_qtypes: list[str] = Field(default_factory=list)
    sni_servers: list[str] = Field(default_factory=list)
    http_hosts: list[str] = Field(default_factory=list)
    http_uris: list[str] = Field(default_factory=list)
    http_methods: list[str] = Field(default_factory=list)
    http_status_codes: list[int] = Field(default_factory=list)
    conn_states: list[str] = Field(default_factory=list)
    app_protos: list[str] = Field(default_factory=list)
    # --- decisive C2 / exfil / delivery / lateral evidence (recall-fix) ---
    # TLS fingerprints — a JA3 (client) + JA3S (server) pair identifies a C2
    # framework (e.g. Cobalt Strike) even when the destination is CDN-fronted.
    ja3_hashes: list[str] = Field(default_factory=list)
    ja3s_hashes: list[str] = Field(default_factory=list)
    # Conn byte volumes per pivoted flow — orig_bytes >> resp_bytes on a long
    # connection is the textbook exfil-asymmetry / large-outbound-transfer shape.
    conn_orig_bytes: list[int] = Field(default_factory=list)
    conn_resp_bytes: list[int] = Field(default_factory=list)
    # Transferred-file metadata — a PE (application/x-dosexec) pulled over HTTP,
    # with a hash to pivot on, is the strongest malware-delivery signal.
    file_mime_types: list[str] = Field(default_factory=list)
    file_sha256s: list[str] = Field(default_factory=list)
    file_md5s: list[str] = Field(default_factory=list)
    # Kerberos (Kerberoasting) — cipher RC4-HMAC on a TGS for a service SPN.
    kerberos_ciphers: list[str] = Field(default_factory=list)
    kerberos_services: list[str] = Field(default_factory=list)
    # SMB / DCE-RPC (PsExec-style lateral) — service-binary write to ADMIN$ +
    # svcctl CreateServiceW.
    smb_actions: list[str] = Field(default_factory=list)
    smb_file_names: list[str] = Field(default_factory=list)
    smb_mapping_services: list[str] = Field(default_factory=list)
    dce_rpc_endpoints: list[str] = Field(default_factory=list)
    dce_rpc_operations: list[str] = Field(default_factory=list)
    # True when a zeek.conn ICMP record is a solicited echo
    # exchange (Zeek encodes ICMP type in the pseudo-ports: orig_p=8 echo
    # request → resp_p=0 echo reply). A solicited ping reply is not a
    # covert beacon — the post-synth validator uses this to downgrade
    # false "BPFDoor ICMP heartbeat" escalations.
    icmp_echo_request_reply: bool = False


def parse_typed_zeek_fields(pivots: Iterable[SoAlert]) -> TypedZeekFields:
    """Roll up decisive typed Zeek evidence across the pivoted Zeek records.

    HYBRID read: each field prefers the pivot's typed ``zeek_*`` attribute (which
    ``_extract_zeek_typed`` resolved ECS-first on the real ``from_es_hit`` path),
    and falls back to the raw ``message`` JSON's zeek-native key when the typed
    attribute is absent — so a doc whose Zeek log is only in ``message`` still
    yields its evidence.
    """
    typed = TypedZeekFields()
    for pivot in pivots:
        ds = (pivot.event_dataset or "").lower()
        if not ds.startswith("zeek."):
            continue
        data = _message_dict(pivot.message)

        _maybe_append_str(typed.dns_queries, _pick(pivot.zeek_dns_query, data, "query"))
        _maybe_append_str(
            typed.dns_rcode_names, _pick(pivot.zeek_dns_rcode_name, data, "rcode_name")
        )
        _maybe_append_str(typed.dns_qtypes, _pick(pivot.zeek_dns_qtype, data, "qtype_name"))
        _maybe_append_str(typed.sni_servers, _pick(pivot.zeek_ssl_server_name, data, "server_name"))
        _maybe_append_str(typed.ja3_hashes, _pick(pivot.zeek_ssl_ja3, data, "ja3"))
        _maybe_append_str(typed.ja3s_hashes, _pick(pivot.zeek_ssl_ja3s, data, "ja3s"))
        _maybe_append_str(typed.http_hosts, _pick(pivot.zeek_http_host, data, "host"))
        _maybe_append_str(typed.http_uris, _pick(pivot.zeek_http_uri, data, "uri"))
        _maybe_append_str(typed.http_methods, _pick(pivot.zeek_http_method, data, "method"))
        _append_int(typed.http_status_codes, _pick(pivot.zeek_http_status, data, "status_code"))
        _maybe_append_str(typed.conn_states, _pick(pivot.zeek_conn_state, data, "conn_state"))
        _maybe_append_str(typed.app_protos, _pick(pivot.zeek_conn_service, data, "service"))
        _append_int(typed.conn_orig_bytes, _pick(pivot.zeek_conn_orig_bytes, data, "orig_bytes"))
        _append_int(typed.conn_resp_bytes, _pick(pivot.zeek_conn_resp_bytes, data, "resp_bytes"))
        _maybe_append_str(
            typed.file_mime_types, _pick(pivot.zeek_files_mime_type, data, "mime_type")
        )
        _maybe_append_str(typed.file_sha256s, _pick(pivot.zeek_files_sha256, data, "sha256"))
        _maybe_append_str(typed.file_md5s, _pick(pivot.zeek_files_md5, data, "md5"))
        _maybe_append_str(typed.kerberos_ciphers, _pick(pivot.zeek_kerberos_cipher, data, "cipher"))
        _maybe_append_str(
            typed.kerberos_services, _pick(pivot.zeek_kerberos_service, data, "service")
        )
        _maybe_append_str(typed.smb_actions, _pick(pivot.zeek_smb_action, data, "action"))
        _maybe_append_str(typed.smb_file_names, _pick(pivot.zeek_smb_name, data, "name"))
        _maybe_append_str(
            typed.smb_mapping_services,
            _pick(pivot.zeek_smb_mapping_service, data, "share_service"),
        )
        _maybe_append_str(
            typed.dce_rpc_endpoints, _pick(pivot.zeek_dce_rpc_endpoint, data, "endpoint")
        )
        _maybe_append_str(
            typed.dce_rpc_operations, _pick(pivot.zeek_dce_rpc_operation, data, "operation")
        )

        # Signals not carried on the typed model: the DNS answer LIST and the
        # solicited-ICMP-echo pseudo-ports (both only in the raw message JSON).
        _parse_message_only_signals(typed, ds, data)
    return typed


def _message_dict(msg: str | None) -> dict[str, Any]:
    """Parse a pivot's ``message`` JSON to a dict, or ``{}`` on missing/malformed."""
    if not msg:
        return {}
    try:
        data = json.loads(msg)
    except (json.JSONDecodeError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _pick(attr: Any, data: dict[str, Any], key: str) -> Any:
    """The typed attribute if it's a non-empty value, else the message ``key``."""
    if attr not in (None, "", []):
        return attr
    v = data.get(key)
    return v if v not in (None, "", []) else None


def _append_int(target: list[int], value: object) -> None:
    if isinstance(value, int) and not isinstance(value, bool):
        target.append(value)


def _parse_message_only_signals(typed: TypedZeekFields, ds: str, data: dict[str, Any]) -> None:
    """Pull the two signals not on the typed model from the parsed ``message`` dict:
    the DNS answers list and the solicited-ICMP-echo pseudo-ports."""
    if not data:
        return
    if ds == "zeek.dns":
        for ans in data.get("answers") or []:
            _maybe_append_str(typed.dns_answers, ans)
    elif ds == "zeek.conn" and (data.get("proto") or "").lower() == "icmp":
        # Zeek encodes the ICMP type in id.orig_p / id.resp_p (flat dotted keys in
        # SO's JSON): orig_p=8 (echo request) + resp_p=0 (echo reply) is a
        # solicited ping exchange, not a beacon. Fallback order mirrors the SO 3.0
        # Filebeat mapping: flat id.orig_p → nested id.orig_p → flat source.port →
        # nested source.port (same for resp/destination).
        _id_raw = data.get("id")
        id_block: dict[str, Any] = _id_raw if isinstance(_id_raw, dict) else {}
        _src_raw = data.get("source")
        src_block: dict[str, Any] = _src_raw if isinstance(_src_raw, dict) else {}
        _dst_raw = data.get("destination")
        dst_block: dict[str, Any] = _dst_raw if isinstance(_dst_raw, dict) else {}
        orig_p = (
            data.get("id.orig_p")
            if data.get("id.orig_p") is not None
            else id_block.get("orig_p")
            if id_block.get("orig_p") is not None
            else data.get("source.port")
            if data.get("source.port") is not None
            else src_block.get("port")
        )
        resp_p = (
            data.get("id.resp_p")
            if data.get("id.resp_p") is not None
            else id_block.get("resp_p")
            if id_block.get("resp_p") is not None
            else data.get("destination.port")
            if data.get("destination.port") is not None
            else dst_block.get("port")
        )
        if orig_p == 8 and resp_p == 0:
            typed.icmp_echo_request_reply = True


def _maybe_append_str(target: list[str], value: object) -> None:
    if isinstance(value, str) and value:
        target.append(value)


__all__ = ["TypedZeekFields", "parse_typed_zeek_fields"]
