"""Scenario → ECS-doc rendering for synthetic-TP eval.

Substitutes placeholders in :class:`Scenario` event templates, computes
Community ID v1 for the triage target, and stamps synth.* metadata on
every doc so the prod kill-switch can detect synth pollution.

Placeholder grammar (intentionally minimal — not Jinja):
- ``{{ run_time }}`` → run_time ISO8601
- ``{{ run_time | offset_seconds(N) }}`` → (run_time + N seconds) ISO8601
- ``{{ community_id(src_ip, src_port, dst_ip, dst_port, 'proto') }}`` →
  Community ID v1 hash for the named fields of THIS event (only valid on
  the triage-target event in practice)
- ``{{ same_as_triage }}`` → the triage target's community_id, joining
  supporting Zeek events back to the alert
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from soc_ai.eval.synth_loader import EventTemplate, Scenario

_PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "sctp": 132}

_RUN_TIME_PLAIN_RE = re.compile(r"^\s*\{\{\s*run_time\s*\}\}\s*$")
_RUN_TIME_OFFSET_RE = re.compile(
    r"^\s*\{\{\s*run_time\s*\|\s*offset_seconds\(\s*(?P<offset>[^)]+)\s*\)\s*\}\}\s*$"
)
_COMMUNITY_ID_RE = re.compile(r"^\s*\{\{\s*community_id\(\s*(?P<args>.+?)\s*\)\s*\}\}\s*$")
_SAME_AS_TRIAGE_RE = re.compile(r"^\s*\{\{\s*same_as_triage\s*\}\}\s*$")


@dataclass(frozen=True)
class RenderedDoc:
    """One ECS-shaped document ready for OpenSearch ingestion."""

    index: str
    body: dict[str, Any]
    is_triage_target: bool


def community_id_v1(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> str:
    """Compute Community ID v1 — a canonical, bidirectional flow hash.

    Spec: https://github.com/corelight/community-id-spec.
    Format: ``1:<base64(sha1(seed + lo_addr + hi_addr + proto + 0 + lo_port + hi_port))>``
    where (lo, hi) are the canonical endpoint ordering (smaller addr/port
    first by lexical comparison).
    """
    proto_num = _PROTOCOL_NUMBERS.get(proto.lower())
    if proto_num is None:
        raise ValueError(f"unsupported protocol {proto!r}")

    sa_bytes = ipaddress.ip_address(src_ip).packed
    da_bytes = ipaddress.ip_address(dst_ip).packed
    a_pair = (sa_bytes, int(src_port))
    b_pair = (da_bytes, int(dst_port))
    if a_pair <= b_pair:
        lo_addr, lo_port = a_pair
        hi_addr, hi_port = b_pair
    else:
        lo_addr, lo_port = b_pair
        hi_addr, hi_port = a_pair

    seed = struct.pack("!H", 0)
    payload = (
        seed
        + lo_addr
        + hi_addr
        + struct.pack("!BB", proto_num, 0)
        + struct.pack("!HH", lo_port, hi_port)
    )
    digest = hashlib.sha1(payload).digest()  # noqa: S324 - flow hash, not security
    return "1:" + base64.b64encode(digest).decode("ascii")


def _format_iso(t: datetime) -> str:
    """Stable ISO8601 with explicit UTC offset (+00:00)."""
    return t.isoformat()


def _parse_offset_arg(arg: str) -> int:
    try:
        return int(arg.strip())
    except (TypeError, ValueError) as e:
        raise ValueError(f"offset_seconds requires an integer argument, got {arg!r}") from e


def _resolve_community_id_call(args: str, event_fields: dict[str, Any]) -> str:
    """Resolve `community_id(src_ip, src_port, dst_ip, dst_port, 'proto')`.

    The first four args are field paths read from the current event's
    pre-rendered fields. The fifth is a quoted literal protocol.
    """
    parts = [p.strip() for p in args.split(",")]
    if len(parts) != 5:
        raise ValueError(f"community_id() takes 5 args, got {len(parts)}: {args!r}")
    *field_paths, proto_lit = parts
    if not (
        (proto_lit.startswith("'") and proto_lit.endswith("'"))
        or (proto_lit.startswith('"') and proto_lit.endswith('"'))
    ):
        raise ValueError(f"community_id protocol must be a string literal: {proto_lit!r}")
    proto = proto_lit[1:-1]

    raw_values = [event_fields.get(p) for p in field_paths]
    missing = [p for p, v in zip(field_paths, raw_values, strict=True) if v is None]
    if missing:
        raise ValueError(
            f"community_id() refers to missing field(s): {missing} (have: {sorted(event_fields)})"
        )
    # The None-guard above raises before we get here; rebuild the list as
    # non-Optional so the int()/str() coercions below see real values.
    field_values: list[Any] = [v for v in raw_values if v is not None]
    src_ip, src_port, dst_ip, dst_port = field_values
    return community_id_v1(str(src_ip), int(src_port), str(dst_ip), int(dst_port), proto)


def _substitute_one(
    value: Any,
    *,
    run_time: datetime,
    event_fields: dict[str, Any],
    triage_community_id: str | None,
) -> Any:
    """Recursively substitute placeholders in a single value."""
    if isinstance(value, dict):
        return {
            k: _substitute_one(
                v,
                run_time=run_time,
                event_fields=event_fields,
                triage_community_id=triage_community_id,
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [
            _substitute_one(
                v,
                run_time=run_time,
                event_fields=event_fields,
                triage_community_id=triage_community_id,
            )
            for v in value
        ]
    if not isinstance(value, str):
        return value

    if _RUN_TIME_PLAIN_RE.match(value):
        return _format_iso(run_time)
    m = _RUN_TIME_OFFSET_RE.match(value)
    if m:
        offset = _parse_offset_arg(m.group("offset"))
        return _format_iso(run_time + timedelta(seconds=offset))
    m = _COMMUNITY_ID_RE.match(value)
    if m:
        return _resolve_community_id_call(m.group("args"), event_fields)
    if _SAME_AS_TRIAGE_RE.match(value):
        if triage_community_id is None:
            raise ValueError(
                "{{ same_as_triage }} used before triage_community_id was "
                "computed — supporting events render only after the triage "
                "target"
            )
        return triage_community_id
    return value


def _stamp_synth_metadata(body: dict[str, Any], scenario: Scenario) -> None:
    """Stamp synth.* fields so prod queries can filter them out.

    Only stamps scenario_id + scenario_version — the answer key
    (expected_verdict) is intentionally NOT stamped because the agent
    under test can query these docs via OpenSearch. Scoring reads
    ground truth from the Scenario object, not this field.
    """
    body.setdefault("synth.scenario_id", scenario.id)
    body.setdefault("synth.scenario_version", scenario.version)


def _render_event(
    event: EventTemplate,
    *,
    scenario: Scenario,
    run_time: datetime,
    triage_community_id: str | None,
) -> RenderedDoc:
    # First pass: substitute non-community-id placeholders.
    pre_rendered: dict[str, Any] = {}
    for key, value in event.fields.items():
        if isinstance(value, str) and _COMMUNITY_ID_RE.match(value):
            # Defer — needs other fields rendered first.
            pre_rendered[key] = value
            continue
        pre_rendered[key] = _substitute_one(
            value,
            run_time=run_time,
            event_fields=pre_rendered,
            triage_community_id=triage_community_id,
        )

    # Second pass: now that ip/port etc. are concrete, resolve community_id().
    body: dict[str, Any] = {}
    for key, value in pre_rendered.items():
        body[key] = _substitute_one(
            value,
            run_time=run_time,
            event_fields=pre_rendered,
            triage_community_id=triage_community_id,
        )

    _stamp_synth_metadata(body, scenario)
    return RenderedDoc(index=event.index, body=body, is_triage_target=event.is_triage_target)


def render_scenario(scenario: Scenario, *, run_time: datetime) -> list[RenderedDoc]:
    """Render every event in ``scenario`` into a list of ECS-shaped docs.

    The triage-target event is rendered first so its community_id is
    available when supporting events resolve ``{{ same_as_triage }}``.
    The returned list preserves the scenario's authored event order.
    """
    triage_idx = next((i for i, e in enumerate(scenario.events) if e.is_triage_target), None)
    if triage_idx is None:
        # The Scenario validator already enforces exactly-one triage target,
        # so this is defensive.
        raise ValueError(f"scenario {scenario.id!r} has no triage-target event")

    docs: list[RenderedDoc | None] = [None] * len(scenario.events)
    triage_event = scenario.events[triage_idx]
    triage_doc = _render_event(
        triage_event,
        scenario=scenario,
        run_time=run_time,
        triage_community_id=None,
    )
    triage_community_id = triage_doc.body.get("network.community_id")
    docs[triage_idx] = triage_doc

    for i, event in enumerate(scenario.events):
        if i == triage_idx:
            continue
        docs[i] = _render_event(
            event,
            scenario=scenario,
            run_time=run_time,
            triage_community_id=triage_community_id,
        )

    return [d for d in docs if d is not None]
