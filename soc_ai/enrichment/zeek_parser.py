"""Parse Zeek pivot records' embedded ``message`` JSON into typed fields.

Security Onion stores the raw Zeek log as a JSON-string in the SoAlert's
``message`` field. The synth-first synth wants typed access to common
protocol fields (DNS query, SSL SNI, HTTP host) without re-parsing the
JSON every time. This module produces a ``TypedZeekFields`` view from
the orchestrator's prefetched pivots.
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
    sni_servers: list[str] = Field(default_factory=list)
    http_hosts: list[str] = Field(default_factory=list)
    http_uris: list[str] = Field(default_factory=list)
    http_methods: list[str] = Field(default_factory=list)
    http_status_codes: list[int] = Field(default_factory=list)
    conn_states: list[str] = Field(default_factory=list)
    app_protos: list[str] = Field(default_factory=list)
    # True when a zeek.conn ICMP record is a solicited echo
    # exchange (Zeek encodes ICMP type in the pseudo-ports: orig_p=8 echo
    # request → resp_p=0 echo reply). A solicited ping reply is not a
    # covert beacon — the post-synth validator uses this to downgrade
    # false "BPFDoor ICMP heartbeat" escalations.
    icmp_echo_request_reply: bool = False


def parse_typed_zeek_fields(pivots: Iterable[SoAlert]) -> TypedZeekFields:
    """Walk pivots, parse each one's message JSON if it's a Zeek dataset."""
    typed = TypedZeekFields()
    for pivot in pivots:
        ds = (pivot.event_dataset or "").lower()
        if not ds.startswith("zeek."):
            continue
        msg = pivot.message
        if not msg:
            continue
        try:
            data = json.loads(msg)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        if ds == "zeek.dns":
            _maybe_append_str(typed.dns_queries, data.get("query"))
            for ans in data.get("answers") or []:
                _maybe_append_str(typed.dns_answers, ans)
            _maybe_append_str(typed.dns_rcode_names, data.get("rcode_name"))
        elif ds == "zeek.ssl":
            _maybe_append_str(typed.sni_servers, data.get("server_name"))
        elif ds == "zeek.http":
            _maybe_append_str(typed.http_hosts, data.get("host"))
            _maybe_append_str(typed.http_uris, data.get("uri"))
            _maybe_append_str(typed.http_methods, data.get("method"))
            sc = data.get("status_code")
            if isinstance(sc, int):
                typed.http_status_codes.append(sc)
        elif ds == "zeek.conn":
            _maybe_append_str(typed.conn_states, data.get("conn_state"))
            _maybe_append_str(typed.app_protos, data.get("service"))
            # ICMP echo request/reply detection. Zeek encodes
            # the ICMP type in id.orig_p / id.resp_p (flat dotted keys in
            # SO's JSON): orig_p=8 (echo request) + resp_p=0 (echo reply)
            # is a solicited ping exchange, not a beacon.
            # B6: also check ECS source.port / destination.port as fallbacks —
            # SO 3.0 Filebeat module may map Zeek ICMP pseudo-ports to ECS
            # fields instead of the Zeek-native id.orig_p / id.resp_p paths.
            # Fallback order: flat id.orig_p → nested id.orig_p → flat
            # source.port → nested source.port (same for resp/destination).
            if (data.get("proto") or "").lower() == "icmp":
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
    return typed


def _maybe_append_str(target: list[str], value: object) -> None:
    if isinstance(value, str) and value:
        target.append(value)


__all__ = ["TypedZeekFields", "parse_typed_zeek_fields"]
