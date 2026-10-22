#!/usr/bin/env python3
"""Build ``soc_ai/demo/fixtures.json`` (version 2) from the recorded runs and the story.

Usage::

    .venv/bin/python scripts/demo/build_story.py           # write the fixture file
    .venv/bin/python scripts/demo/build_story.py --check   # exit 1 when the file is stale

Inputs:

* ``scripts/demo/recorded_runs.json``: the version 1 set that
  ``build_fixtures.py`` and ``enrich_demo_fixtures.py`` wrote. It holds the
  investigations soc-ai ran on a test grid, sanitized at capture, plus the
  replays, the two recorded hunts, the backtest and the canned chats.
* ``scripts/demo/story.py``: the estate, the label map and the timeline.

The build gives every sanitized label a machine of the estate, places each
recorded run on the timeline, and adds what the recorded runs never held:
the host estate (written through the store's own sweep functions), profiles,
observations, leads in every state, a closed grid gap with its review hits, a
held analytic, lead hunts, the alert and telemetry documents of the mock
grid, and the host traffic the host page draws.

Every timestamp is written against ``story.ANCHOR``. The app and the mock
move the anchor to the seed instant at startup (``soc_ai/demo/fixtures.py``).

The output passes two leak gates before it is written: the mirror patterns of
``scripts/build-public-mirror.sh`` and the residue sweep of
``soc_ai.oracle.sanitize.unsafe_residue``, with the story's own synthetic
addresses and names allowed. A hit writes nothing and exits non-zero.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import re
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.demo import story as st  # noqa: E402
from scripts.demo.build_fixtures import (  # noqa: E402
    _raw_strings,
    leak_patterns,
    scan_for_leaks,
)
from soc_ai.demo.fixtures import FIXTURES_VERSION, SEEDED_TABLES, shift_tree  # noqa: E402

RECORDED = REPO / "scripts" / "demo" / "recorded_runs.json"
OUT = REPO / "soc_ai" / "demo" / "fixtures.json"

# Crockford base32, the ULID alphabet: deterministic row ids.
_ULID = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def demo_id(seed: str) -> str:
    """A stable 26-character ULID-shaped id ("01DEMO" + 20 hash characters)."""
    digest = hashlib.sha256(f"demo-story:{seed}".encode()).digest()
    return "01DEMO" + "".join(_ULID[b % 32] for b in digest[:20])


def es_id(seed: str) -> str:
    """A stable 20-character Elasticsearch-style document id."""
    digest = hashlib.sha256(f"demo-doc:{seed}".encode()).digest()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(alphabet[b % 62] for b in digest[:20])


def community_id(seed: str) -> str:
    """A stable community id in the ``1:<base64>`` form Zeek and Suricata write."""
    import base64

    digest = hashlib.sha1(f"demo-flow:{seed}".encode()).digest()
    return "1:" + base64.b64encode(digest).decode()


def _parse(value: str) -> datetime:
    """An ISO-8601 string as a naive-UTC datetime."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


ago = st.ago
iso = st.iso


# ---------------------------------------------------------------------------
# The recorded runs
# ---------------------------------------------------------------------------

_LABEL = re.compile(r"\b(?:IP|HOST)_\d+\b")


def relabel(doc: dict[str, Any]) -> dict[str, Any]:
    """Give every sanitized label its machine. Keys and values alike."""
    text = json.dumps(doc, ensure_ascii=False)
    text = re.sub(st.HOST_FLAG_PATTERN, st.HOST_FLAG_TEXT, text)

    def _sub(match: re.Match[str]) -> str:
        label = match.group(0)
        table = st.IP_LABELS if label.startswith("IP_") else st.HOST_LABELS
        if label not in table:
            sys.exit(f"story.py gives no value to the label {label}")
        return table[label]

    text = _LABEL.sub(_sub, text)
    out: dict[str, Any] = json.loads(text)
    left = _LABEL.findall(json.dumps(out))
    if left:
        sys.exit(f"labels left after the relabel: {sorted(set(left))}")
    return out


# Hours before the anchor at which each recorded investigation started. The
# record moves as one piece, so its alert and its tool results keep their
# distance from the run.
INVESTIGATION_AGO: dict[str, float] = {
    "01DEMOP3XD42HDDHRAK52AD0PH": 29.0,  # ws-sales-02 downloads an executable
    "01DEMOPGZVMA2X3SZFE25S10GS": 19.0,  # ws-sales-04 Emotet check-in
    "01DEMOMN84EQQ566EMY50AFMFS": 13.5,  # jump01 PsExec to fs01
    "01DEMO8GD7CWRX6QSRMFWGQX8S": 11.5,  # bkp01 upload to cloud storage
    "01DEMOJPTBNRKE8YPZR83GJQ1R": 7.5,  # ws-fin-02 certificate list download
    "01DEMOW495Q7GD3D8WTEJ934AY": 5.5,  # ws-mkt-01 IP lookup
    "01DEMOQ4AEYPXS2WFB1DGEAD7G": 4.5,  # scan01 probes web01
    "01DEMOP0S0DBWC0EW342F59G08": 2.5,  # mac-design-01 Bonjour query
    "01DEMOFA11BACKSYNTHERR0000": 1.75,  # ws-eng-05 Cobalt Strike, pipeline error
}

# Hours before the anchor of the alert behind each recorded replay.
REPLAY_ALERT_AGO: dict[str, float] = {
    "9N6cTp8BwxVkvmc70vrs": 0.9,  # Quasar RAT on ws-eng-03
    "8N6cTp8BwxVkvmc70vrZ": 0.6,  # .click lookup from ws-hr-01
    "9F4kTp8BwxVkvmc70zZ9": 2.0,  # Cobalt Strike beacon from ws-eng-05
}

# Who started each recorded run. The test grid recorded "demo".
_AUTO = "auto-triage"

EMOTET_INV = "01DEMOPGZVMA2X3SZFE25S10GS"
BZAR_INV = "01DEMOMN84EQQ566EMY50AFMFS"
NMI_INV = "01DEMO8GD7CWRX6QSRMFWGQX8S"
URLHAUS_INV = "01DEMOP3XD42HDDHRAK52AD0PH"
CTL_INV = "01DEMOJPTBNRKE8YPZR83GJQ1R"
BONJOUR_INV = "01DEMOP0S0DBWC0EW342F59G08"
FALLBACK_INV = "01DEMOFA11BACKSYNTHERR0000"


def _alert_of(record: dict[str, Any]) -> dict[str, Any] | None:
    for ev in record.get("events") or []:
        if ev.get("kind") == "enriched_alert_context":
            alert = (ev.get("payload") or {}).get("alert")
            return alert if isinstance(alert, dict) else None
    return None


def place_investigation(inv: dict[str, Any]) -> dict[str, Any]:
    target = ago(hours=INVESTIGATION_AGO[inv["id"]])
    delta = target - _parse(inv["created_at"])
    out: dict[str, Any] = shift_tree(inv, delta)
    out["created_at"] = iso(target)
    out["finished_at"] = iso(_parse(inv["finished_at"]) + delta)
    alert = _alert_of(out)
    out["community_id"] = (alert or {}).get("network_community_id")
    out["started_by"] = _AUTO
    out["is_fallback"] = inv["id"] == FALLBACK_INV
    return out


def place_replay(replay: dict[str, Any]) -> dict[str, Any]:
    alert = _alert_of(replay)
    target = ago(hours=REPLAY_ALERT_AGO[replay["alert_es_id"]])
    if alert is None or not alert.get("timestamp"):
        anchor_ts = None
        for ev in replay.get("events") or []:
            ts = (ev.get("payload") or {}).get("timestamp")
            if isinstance(ts, str):
                anchor_ts = ts
                break
        delta = target - _parse(anchor_ts) if anchor_ts else timedelta(0)
    else:
        delta = target - _parse(alert["timestamp"])
    out: dict[str, Any] = shift_tree(replay, delta)
    return out


# ---------------------------------------------------------------------------
# Authored investigations
# ---------------------------------------------------------------------------


def _flat_alert(
    alert_id: str,
    at: datetime,
    rule: str,
    src: str,
    dst: str,
    dport: int,
    *,
    sport: int,
    flow: str,
    severity: int = 3,
    dataset: str = "suricata.alert",
    **extra: Any,
) -> dict[str, Any]:
    """The flat alert record the pipeline's prefetch writes (SoAlert fields)."""
    base: dict[str, Any] = {
        "id": alert_id,
        "timestamp": st.es_time(at),
        "rule_name": rule,
        "rule_uuid": None,
        "severity_label": {1: "low", 2: "medium", 3: "high"}.get(severity, "high"),
        "severity_score": severity,
        "network_community_id": flow,
        "source_ip": src,
        "source_port": sport,
        "destination_ip": dst,
        "destination_port": dport,
        "host_name": st.SENSOR,
        "host_ip": [],
        "user_name": None,
        "message": None,
        "tags": [],
        "event_action": None,
        "alert_action": "allowed",
        "classtype": None,
        "event_module": dataset.split(".", maxsplit=1)[0],
        "event_dataset": dataset,
        "event_category": "network",
    }
    base.update(extra)
    return base


def authored_run(
    *,
    inv_id: str,
    alert: dict[str, Any],
    started: datetime,
    minutes: float,
    verdict: str,
    confidence: float,
    summary: str,
    opening: str,
    steps: list[tuple[str, dict[str, Any], dict[str, Any]]],
    evidence: list[str],
    citations: list[str],
    actions: list[dict[str, Any]],
    started_by: str = _AUTO,
    community_events: list[dict[str, Any]] | None = None,
    extra_events: list[dict[str, Any]] | None = None,
    report_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One investigation row with the event stream a run of the pipeline writes."""
    events: list[dict[str, Any]] = []

    def add(kind: str, payload: dict[str, Any]) -> None:
        events.append({"kind": kind, "sequence": len(events) + 1, "payload": payload})

    add("session_start", {"alert_id": alert["id"], "pipeline": "synth_first"})
    add(
        "enriched_alert_context",
        {
            "alert": alert,
            "community_id_events": community_events or [],
            "host_events": [],
            "user_events": [],
            "process_events": [],
            "file_events": [],
            "pivot_summary": None,
            "host_alert_profile": None,
            "prefetch_gaps": [],
            "typed_zeek": None,
            "enrichments": {},
        },
    )
    add("decision_template_match", {"matched": False, "template_id": None, "verdict": None})
    add("synth_round1_skipped", {"reason": "definitely_investigate"})
    add(
        "investigation_loop_entered",
        {"reason": "definitely_investigate", "round1_verdict": None, "round1_confidence": None},
    )
    add("model_response", {"content": opening, "reasoning_trace": ""})
    for n, (tool, args, result) in enumerate(steps, start=1):
        call_id = f"call-{inv_id[-6:].lower()}-{n}"
        add(
            "tool_call",
            {
                "tool_name": tool,
                "args": json.dumps(args),
                "tool_call_id": call_id,
                "phase": "investigation_loop",
                "round": 1,
            },
        )
        add(
            "tool_result",
            {
                "tool_name": tool,
                "result": result,
                "tool_call_id": call_id,
                "phase": "investigation_loop",
                "round": 1,
            },
        )
    add(
        "investigation_transcript",
        {
            "round": 1,
            "phase": "investigation_loop",
            "evidence": evidence,
            "tentative_verdict": verdict,
            "tentative_summary": summary,
        },
    )
    add(
        "citation_validation",
        {
            "round": 1,
            "counts": {"valid": len(citations), "strict": len(citations), "semantic": 0},
            "total": len(citations),
            "invalid_examples": [],
            "valid_citations": citations,
            "coverage_ratio": 1.0,
            "invalid_ratio": 0.0,
            "per_citation": [
                {
                    "citation": c,
                    "kind": "tool"
                    if c.startswith("tool ")
                    else "path"
                    if c.startswith("path ")
                    else "id",
                    "resolved": True,
                    "resolution_kind": "strict_tool"
                    if c.startswith("tool ")
                    else "strict_path"
                    if c.startswith("path ")
                    else "strict_id",
                }
                for c in citations
            ],
        },
    )
    report: dict[str, Any] = {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "citations": citations,
        "recommended_actions": actions,
        "field_reconciliation": None,
        "validator_note": None,
        "local_verdict": None,
    }
    report.update(report_extra or {})
    add("triage_report", dict(report))
    for ev in extra_events or []:
        add(ev["kind"], ev["payload"])
    add("done", {"recommended_count": len(actions)})
    return {
        "id": inv_id,
        "alert_es_id": alert["id"],
        "rule_name": alert["rule_name"],
        "verdict": verdict,
        "confidence": confidence,
        "rationale": None,
        "summary": summary,
        "report": report,
        "src_ip": alert["source_ip"],
        "dest_ip": alert["destination_ip"],
        "community_id": alert["network_community_id"],
        "status": "complete",
        "started_by": started_by,
        "is_fallback": False,
        "created_at": iso(started),
        "finished_at": iso(started + timedelta(minutes=minutes)),
        "events": events,
    }


# The beacon on ws-sales-04: the same rule as the certificate download on
# ws-fin-02, the opposite verdict. The Alerts page shows the mix.
BEACON_INV = demo_id("beacon-ws-sales-04")
BEACON_ALERT = es_id("beacon-ws-sales-04")
BEACON_RULE = "ET HUNTING Periodic Outbound HTTPS Connection Possible Beacon"
BEACON_FLOW = community_id("beacon-ws-sales-04")

# The SMB transfer on the PsExec flow: soc-ai reads it as an admin push. The
# PsExec alert on the same flow is a true positive.
SMB_INV = demo_id("smb-exe-jump01")
SMB_ALERT = es_id("smb-exe-jump01")
SMB_RULE = "ET POLICY SMB2 NT Create AndX Request For an Executable File"

# The follow-up run on the bkp01 upload, after the analyst answered.
FOLLOWUP_INV = demo_id("followup-bkp01")


def authored_investigations(recorded: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    sales04, c2 = st.ip_of("ws-sales-04"), st.EMOTET_C2
    started = ago(hours=18, minutes=10)
    alert = _flat_alert(
        BEACON_ALERT,
        started - timedelta(minutes=6),
        BEACON_RULE,
        sales04,
        c2,
        443,
        sport=50644,
        flow=BEACON_FLOW,
        severity=2,
        zeek_ssl_server_name="cdn-fronted-host.example.com",
        zeek_conn_duration=0.6,
    )
    out.append(
        authored_run(
            inv_id=BEACON_INV,
            alert=alert,
            started=started,
            minutes=3.4,
            verdict="true_positive",
            confidence=0.86,
            summary=(
                f"ws-sales-04 ({sales04}) connects to {c2}:443 every 300 seconds. The same "
                "address is the Emotet command server of the alert one hour earlier on this "
                "host. The cadence holds for 61 connections, each under 2 KB. This is the "
                "Emotet beacon."
            ),
            opening="The destination is the Emotet server of the earlier alert. I check the cadence.",
            steps=[
                (
                    "t_prevalence",
                    {"ip": sales04, "peer_ip": c2},
                    {
                        "observed": True,
                        "total_events": 61,
                        "distinct_days": 1,
                        "rarity": "first-seen",
                        "summary": f"{sales04} and {c2}: 61 connections, first seen today.",
                    },
                ),
                (
                    "t_beacon_profile",
                    {"src_ip": sales04, "dst_ip": c2},
                    {
                        "connections": 61,
                        "median_interval_s": 300,
                        "jitter_ratio": 0.04,
                        "median_bytes_out": 1480,
                        "verdict_hint": "periodic",
                    },
                ),
                (
                    "t_enrich_ip",
                    {"ip": c2},
                    {
                        "indicator": c2,
                        "indicator_type": "ip",
                        "internal": False,
                        "blocklist_hits": [{"source": "feodo", "label": "Emotet C2"}],
                        "misp_hits": [],
                        "errors": [],
                    },
                ),
            ],
            evidence=[
                f"61 connections from {sales04} to {c2} at a 300 s interval "
                "(tool t_beacon_profile:median_interval_s=300)",
                f"{c2} is on the Feodo list as an Emotet C2 (tool t_enrich_ip:blocklist_hits)",
            ],
            citations=[
                "tool t_beacon_profile:median_interval_s=300",
                "tool t_enrich_ip:result.blocklist_hits=[feodo]",
                "tool t_prevalence:rarity=first-seen",
            ],
            actions=[
                {
                    "tool_name": "escalate_to_case",
                    "tool_args": {
                        "alert_id": BEACON_ALERT,
                        "case_title": "Emotet beacon from ws-sales-04",
                        "case_description": (
                            f"ws-sales-04 beacons to the Emotet C2 {c2} every 300 seconds. "
                            "Isolate the host and reset the credentials of its user."
                        ),
                    },
                    "rationale": "A periodic beacon to a known Emotet C2 is an active infection.",
                }
            ],
        )
    )

    # The SMB transfer. Same community id as the PsExec alert, minutes apart.
    bzar = recorded[BZAR_INV]
    bzar_alert = _alert_of(bzar) or {}
    jump, fs = st.ip_of("jump01"), st.ip_of("fs01")
    bzar_ts = _parse(bzar_alert["timestamp"])
    started = _parse(bzar["created_at"]) + timedelta(minutes=4)
    alert = _flat_alert(
        SMB_ALERT,
        bzar_ts - timedelta(seconds=40),
        SMB_RULE,
        jump,
        fs,
        445,
        sport=int(bzar_alert.get("source_port") or 50321),
        flow=str(bzar_alert["network_community_id"]),
        severity=1,
        zeek_smb_name="PSEXESVC.exe",
        zeek_smb_action="SMB::FILE_WRITE",
    )
    out.append(
        authored_run(
            inv_id=SMB_INV,
            alert=alert,
            started=started,
            minutes=2.1,
            verdict="false_positive",
            confidence=0.62,
            summary=(
                f"jump01 ({jump}) wrote PSEXESVC.exe to the ADMIN$ share of fs01 ({fs}). "
                "jump01 is the jump host of the IT team, and the IT team pushes tools with "
                "PsExec. The write alone matches an administrator task."
            ),
            opening="jump01 is the jump host. I check whether IT pushes tools from it.",
            steps=[
                (
                    "t_host_summary",
                    {"ip": jump},
                    {
                        "ip": jump,
                        "hostname": "jump01",
                        "role_guess": "server",
                        "summary": "jump01 serves RDP to the IT team and opens SMB to servers.",
                    },
                ),
                (
                    "t_lookup_runbook",
                    {"query": "PsExec from the jump host"},
                    {"matches": [{"title": "Lateral movement with PsExec", "score": 0.71}]},
                ),
            ],
            evidence=[
                "jump01 is the administration host of the IT team (tool t_host_summary)",
                "PSEXESVC.exe on an ADMIN$ share is the PsExec service binary",
            ],
            citations=["tool t_host_summary:role_guess=server", "path alert.zeek_smb_name"],
            actions=[
                {
                    "tool_name": "ack_alert",
                    "tool_args": {
                        "alert_id": SMB_ALERT,
                        "comment": "PsExec service write from the IT jump host.",
                    },
                    "rationale": "An administrator push from the jump host.",
                }
            ],
        )
    )

    # The follow-up on the bkp01 upload. Same alert, newer run, after the
    # analyst's answer.
    nmi = recorded[NMI_INV]
    nmi_alert = copy.deepcopy(_alert_of(nmi) or {})
    bkp = st.ip_of("bkp01")
    started = ago(hours=9, minutes=40)
    run = authored_run(
        inv_id=FOLLOWUP_INV,
        alert=nmi_alert,
        started=started,
        minutes=4.2,
        verdict="true_positive",
        confidence=0.81,
        summary=(
            f"bkp01 ({bkp}) uploaded 4.2 GB to {st.R2_STORAGE} over 9 hours. The backup job "
            "of bkp01 writes to a different provider on a nightly schedule, and this upload "
            f"ran outside it. {st.ADMIN_ACCOUNT} logged on to bkp01 over SSH 20 minutes before the "
            "upload, and that account runs no backup job. Data left the estate. Treat it as "
            "exfiltration."
        ),
        opening="The first run left two questions open. I read the backup job and the logons.",
        steps=[
            (
                "t_query_events_oql",
                {
                    "query": f"source.ip:{bkp} AND destination.ip:{st.R2_STORAGE}",
                    "time_range_minutes": 1440,
                },
                {"total": 1, "summary": "one 9-hour session, 4.2 GB out, 4.1 MB in"},
            ),
            (
                "t_query_events_oql",
                {
                    "query": f"host.ip:{bkp} AND event.dataset:system.auth",
                    "time_range_minutes": 1440,
                },
                {
                    "total": 3,
                    "summary": f"{st.ADMIN_ACCOUNT} logged on to bkp01 over SSH 20 minutes "
                    "before the upload",
                },
            ),
        ],
        evidence=[
            "The backup job of bkp01 writes to another provider at night (tool t_query_events_oql)",
            f"{st.ADMIN_ACCOUNT} logged on to bkp01 before the upload (tool t_query_events_oql)",
        ],
        citations=[
            "tool t_query_events_oql returned 1 hits",
            "tool t_query_events_oql returned 3 hits",
        ],
        actions=[
            {
                "tool_name": "escalate_to_case",
                "tool_args": {
                    "alert_id": nmi_alert.get("id"),
                    "case_title": "Upload of 4.2 GB from bkp01 to unknown cloud storage",
                    "case_description": (
                        "bkp01 uploaded 4.2 GB to a bucket nobody owns, after a logon by "
                        f"{st.ADMIN_ACCOUNT}. Join this case to the PsExec case."
                    ),
                },
                "rationale": "Data left the estate through an account the attacker holds.",
            },
            {
                "tool_name": "add_case_comment",
                "tool_args": {
                    "comment": f"The same account, {st.ADMIN_ACCOUNT}, ran DCSync two days ago.",
                },
                "rationale": "Link the upload to the DCSync finding.",
            },
        ],
        started_by="r.patel",
    )
    out.append(run)
    return out


# ---------------------------------------------------------------------------
# The mock grid: alert documents
# ---------------------------------------------------------------------------

# Severity label per rule, where the recorded alert carried none.
_SEVERITY: dict[str, str] = {
    "ETPRO TROJAN Win32/Emotet CnC Activity (POST)": "high",
    "ET DROP urlhaus.abuse.ch malware distribution URL": "high",
    "BZAR ATTACK::Execution_Service_Creation": "high",
    "ET MALWARE Quasar RAT CnC Checkin": "high",
    "ET MALWARE Possible Cobalt Strike Beacon (GET)": "high",
    "SOC-AI ANALYTIC Long Connection Asymmetric Bytes First-Seen FQDN": "medium",
    "ET WEB_SPECIFIC_APPS Possible SQL Injection UNION SELECT": "medium",
    "ET MALWARE Potential DNS Command and Control via TXT queries": "medium",
    "SIGMA Kerberos Network Traffic RC4 Ticket Encryption": "high",
    SMB_RULE: "low",
}


def alert_doc(
    flat: dict[str, Any],
    *,
    at: datetime | None = None,
    doc_id: str | None = None,
    src: str | None = None,
    sport: int | None = None,
    flow: str | None = None,
    acked: bool = False,
    escalated: bool = False,
) -> dict[str, Any]:
    """One alert document of the mock grid, from a flat alert record."""
    rule = str(flat.get("rule_name") or "")
    dataset = str(flat.get("event_dataset") or "suricata.alert")
    when = at or _parse(str(flat["timestamp"]))
    label = flat.get("severity_label") or _SEVERITY.get(rule, "low")
    source: dict[str, Any] = {
        "@timestamp": st.es_time(when),
        "event": {
            "kind": "alert",
            "dataset": dataset,
            "module": dataset.split(".", maxsplit=1)[0],
            "category": "network",
            "severity": {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(label), 1),
            "severity_label": label,
            "acknowledged": acked,
            "escalated": escalated,
        },
        "tags": ["alert"],
        "rule": {"name": rule, "uuid": flat.get("rule_uuid"), "category": flat.get("classtype")},
        "source": {"ip": src or flat.get("source_ip"), "port": sport or flat.get("source_port")},
        "destination": {"ip": flat.get("destination_ip"), "port": flat.get("destination_port")},
        "network": {
            "community_id": flow or flat.get("network_community_id"),
            "transport": "udp" if flat.get("destination_port") in (53, 123) else "tcp",
        },
        "host": {"name": st.SENSOR},
        "observer": {"name": st.SENSOR},
    }
    if flat.get("message"):
        source["message"] = flat["message"]
    return {
        "_index": f"logs-{dataset}-default",
        "_id": doc_id or str(flat["id"]),
        "_source": source,
    }


# Repeat firings of a rule on the grid, beside the alert a run investigated:
# (investigation id, how many more, spread in hours, newest hours before the
# investigated alert or None for after it, extra sources).
_REPEATS: tuple[tuple[str, int, float, tuple[str, ...]], ...] = (
    # The IP lookup fires all week, from the marketing host and two others.
    ("01DEMOW495Q7GD3D8WTEJ934AY", 17, 160.0, ("ws-mkt-01", "ws-ops-01", "ws-hr-01")),
    # The certificate download fires on every Windows host once a day or so.
    ("01DEMOJPTBNRKE8YPZR83GJQ1R", 11, 150.0, ("ws-fin-02", "ws-mkt-01", "ws-it-02")),
    # The scanner sweeps web01 for half an hour.
    ("01DEMOQ4AEYPXS2WFB1DGEAD7G", 24, 0.5, ("scan01",)),
    # Bonjour discovery from the design Mac, 22 times in the week.
    ("01DEMOP0S0DBWC0EW342F59G08", 21, 150.0, ("mac-design-01",)),
    # The Emotet POST check-in repeats a few times.
    (EMOTET_INV, 3, 1.5, ("ws-sales-04",)),
)


def alert_documents(
    investigations: list[dict[str, Any]], replays: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    by_id = {inv["id"]: inv for inv in investigations}
    escalated_alerts = {str((_alert_of(by_id[BZAR_INV]) or {}).get("id"))}
    for inv in investigations:
        if inv.get("started_by") == "backtest":
            continue
        flat = _alert_of(inv)
        if flat is None:
            continue
        if any(d["_id"] == flat["id"] for d in docs):
            continue  # the follow-up run shares its alert with the first run
        docs.append(alert_doc(flat, escalated=str(flat["id"]) in escalated_alerts))
    for replay in replays:
        flat = _alert_of(replay)
        if flat is not None:
            docs.append(alert_doc(flat))
    # The pipeline-error run has no prefetch context: its alert is the Cobalt
    # Strike replay's alert, already in the list above.
    for inv_id, count, spread, hosts in _REPEATS:
        flat = _alert_of(by_id[inv_id])
        assert flat is not None
        first = _parse(str(flat["timestamp"]))
        for n in range(1, count + 1):
            host = hosts[n % len(hosts)]
            when = first - timedelta(hours=spread * n / (count + 1))
            if inv_id == "01DEMOQ4AEYPXS2WFB1DGEAD7G":
                when = first - timedelta(minutes=75 * n / count)
            docs.append(
                alert_doc(
                    flat,
                    at=when,
                    doc_id=es_id(f"{inv_id}:{n}"),
                    src=st.ip_of(host),
                    sport=40000 + n * 37,
                    flow=community_id(f"{inv_id}:{n}"),
                )
            )
    # The Quasar check-in repeats while it waits for a verdict.
    quasar = next(r for r in replays if r["alert_es_id"] == "9N6cTp8BwxVkvmc70vrs")
    flat = _alert_of(quasar)
    assert flat is not None
    for n in range(1, 4):
        docs.append(
            alert_doc(
                flat,
                at=_parse(str(flat["timestamp"])) - timedelta(minutes=12 * n),
                doc_id=es_id(f"quasar:{n}"),
                sport=51000 + n,
                flow=community_id(f"quasar:{n}"),
            )
        )
    # Alerts the story names that no run investigated.
    jump, dc01 = st.ip_of("jump01"), st.ip_of("dc01")
    bzar_flat = _alert_of(by_id[BZAR_INV]) or {}
    bzar_ts = _parse(str(bzar_flat["timestamp"]))
    kerberoast = _flat_alert(
        "3N6cTp8BwxVkvmc70vqd",
        bzar_ts - timedelta(minutes=35),
        "SIGMA Kerberos Network Traffic RC4 Ticket Encryption",
        jump,
        dc01,
        88,
        sport=50290,
        flow=community_id("kerberoast"),
        dataset="sigma.alert",
    )
    docs.append(alert_doc(kerberoast, acked=True, escalated=True))
    # The same rule six hours earlier: ws-it-02 started a service on app01. No
    # run investigated it, and it is not on the case, so the group stays in the
    # queue with one escalated alert of two.
    older = _flat_alert(
        "yd6cTp8BwxVkvmc70vpY",
        ago(hours=20, minutes=30),
        "BZAR ATTACK::Execution_Service_Creation",
        st.ip_of("ws-it-02"),
        st.ip_of("app01"),
        445,
        sport=49882,
        flow=community_id("bzar-ws-it-02"),
    )
    docs.append(alert_doc(older))
    # The SMB write on the PsExec flow, with its own run (see SMB_INV).
    tor = _flat_alert(
        "2d6cTp8BwxVkvmc70vqR",
        ago(hours=16),
        "ET TOR Known Tor Exit Node Traffic group 1",
        "185.220.101.182",
        st.ip_of("vpn01"),
        22,
        sport=41022,
        flow=community_id("tor"),
        severity=1,
    )
    for n in range(4):
        docs.append(
            alert_doc(
                tor,
                at=ago(hours=16 + 9 * n),
                doc_id="2d6cTp8BwxVkvmc70vqR" if n == 0 else es_id(f"tor:{n}"),
                acked=True,
            )
        )
    whitespace = _flat_alert(
        "7N6cTp8BwxVkvmc70vrO",
        ago(hours=40),
        "ET HUNTING Possible Cobalt Strike Extra Whitespace HTTP Response",
        "104.18.42.69",
        st.ip_of("ws-ops-01"),
        51200,
        sport=443,
        flow=community_id("whitespace"),
        severity=1,
    )
    docs.append(alert_doc(whitespace, acked=True))
    return docs


def smb_alert_document(smb_run: dict[str, Any]) -> dict[str, Any]:
    flat = _alert_of(smb_run)
    assert flat is not None
    return alert_doc(flat)


# ---------------------------------------------------------------------------
# The mock grid: telemetry documents
# ---------------------------------------------------------------------------


def _flat_to_doc(flat: dict[str, Any]) -> dict[str, Any]:
    """A prefetched event record (flat SoAlert fields) as the grid document it came from."""
    dataset = str(flat.get("event_dataset") or "zeek.conn")
    source: dict[str, Any] = {
        "@timestamp": flat.get("timestamp"),
        "event": {
            "dataset": dataset,
            "module": flat.get("event_module") or dataset.split(".", maxsplit=1)[0],
            "category": flat.get("event_category") or "network",
            "action": flat.get("event_action"),
        },
        "source": {"ip": flat.get("source_ip"), "port": flat.get("source_port")},
        "destination": {"ip": flat.get("destination_ip"), "port": flat.get("destination_port")},
        "network": {"community_id": flat.get("network_community_id")},
        "host": {"name": flat.get("host_name") or st.SENSOR},
        "observer": {"name": st.SENSOR},
    }
    if flat.get("rule_name"):
        source["rule"] = {"name": flat["rule_name"]}
        source["event"]["kind"] = "alert"
        source["tags"] = ["alert"]
    if flat.get("user_name"):
        source["user"] = {"name": flat["user_name"]}
    zeek: dict[str, Any] = {}
    for key, value in flat.items():
        if key.startswith("zeek_") and value not in (None, [], ""):
            zeek[key[len("zeek_") :]] = value
    if zeek:
        source["zeek"] = zeek
    if flat.get("message"):
        source["message"] = flat["message"]
    return {"_index": f"logs-{dataset}-default", "_id": str(flat["id"]), "_source": source}


def cited_documents(investigations: list[dict[str, Any]], known: set[str]) -> list[dict[str, Any]]:
    """The grid documents the recorded runs cite by id, rebuilt from their prefetch."""
    out: list[dict[str, Any]] = []
    for inv in investigations:
        cites = {
            str(c)
            for c in ((inv.get("report") or {}).get("citations") or [])
            if re.fullmatch(r"[A-Za-z0-9_-]{18,24}", str(c))
        }
        if not cites:
            continue
        for ev in inv.get("events") or []:
            payload = ev.get("payload") or {}
            if ev.get("kind") != "enriched_alert_context":
                continue
            for group in ("community_id_events", "host_events"):
                for flat in payload.get(group) or []:
                    fid = str(flat.get("id") or "")
                    if fid in cites and fid not in known:
                        known.add(fid)
                        out.append(_flat_to_doc(flat))
    return out


# The two DCSync documents the catalog trail's hunt cites
# (soc_ai/demo/catalog_trail.py, _FIRED_SAMPLE_IDS). The trail fires about two
# days back.
_DCSYNC_IDS = ("demo-4662-000001", "demo-4662-000002")


def windows_documents() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    fired = ago(hours=48, minutes=61)
    for n, doc_id in enumerate(_DCSYNC_IDS):
        out.append(
            {
                "_index": "logs-windows.forwarded-default",
                "_id": doc_id,
                "_source": {
                    "@timestamp": st.es_time(fired + timedelta(minutes=3 * n)),
                    "event": {
                        "dataset": "windows.security",
                        "module": "windows",
                        "code": "4662",
                        "action": "directory-service-object-access",
                        "category": "iam",
                    },
                    "host": {"name": f"dc01.{st.ORG_DOMAIN}", "ip": [st.ip_of("dc01")]},
                    "user": {"name": st.ADMIN_ACCOUNT, "domain": "DEMO"},
                    "source": {"ip": st.ip_of("ws-it-02")},
                    "winlog": {
                        "event_id": "4662",
                        "channel": "Security",
                        "event_data": {
                            "SubjectUserName": st.ADMIN_ACCOUNT,
                            "AccessMask": "0x100",
                            "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
                            "ObjectType": "domainDNS",
                        },
                    },
                    "message": (
                        "An operation was performed on an object. Replicating Directory "
                        "Changes, requested by a user account."
                    ),
                },
            }
        )
    # Logons the host pages and the hunts name.
    logons = (
        (st.ip_of("bkp01"), "bkp01", st.ADMIN_ACCOUNT, ago(hours=12, minutes=50), "system.auth"),
        (
            st.ip_of("jump01"),
            "jump01",
            st.KERBEROAST_ACCOUNT,
            ago(hours=14, minutes=45),
            "windows.security",
        ),
        (
            st.ip_of("fs01"),
            "fs01",
            st.KERBEROAST_ACCOUNT,
            ago(hours=14, minutes=31),
            "windows.security",
        ),
    )
    for n, (ip, host, user, when, dataset) in enumerate(logons):
        out.append(
            {
                "_index": f"logs-{dataset}-default",
                "_id": es_id(f"logon:{n}"),
                "_source": {
                    "@timestamp": st.es_time(when),
                    "event": {
                        "dataset": dataset,
                        "category": "authentication",
                        "outcome": "success",
                        "code": "4624" if dataset == "windows.security" else None,
                    },
                    "host": {"name": host, "ip": [ip]},
                    "user": {"name": user},
                    "source": {"ip": st.ip_of("ws-it-02")},
                },
            }
        )
    return out


def network_documents() -> list[dict[str, Any]]:
    """A thin slice of Zeek telemetry, so the dataset inventory reads like a grid.

    The host page draws its traffic from ``traffic`` (an aggregate the mock
    answers), so these documents only need to exist per dataset.
    """
    out: list[dict[str, Any]] = []
    samples = (
        ("zeek.conn", "ws-mkt-01", "dc01", 53, {"conn": {"state": "SF", "duration": 0.01}}),
        ("zeek.conn", "ws-sales-04", st.EMOTET_C2, 443, {"conn": {"state": "SF", "duration": 0.6}}),
        ("zeek.conn", "bkp01", st.R2_STORAGE, 443, {"conn": {"state": "SF", "duration": 32411.0}}),
        ("zeek.dns", "ws-hr-01", "dc02", 53, {"dns": {"query": f"intranet.{st.ORG_DOMAIN}"}}),
        ("zeek.dns", "prn-02", "dc01", 53, {"dns": {"query": "updates.example.com"}}),
        (
            "zeek.ssl",
            "ws-fin-02",
            "151.101.65.67",
            443,
            {"ssl": {"server_name": "ctldl.windowsupdate.com"}},
        ),
        ("zeek.http", "ws-sales-02", st.DROPPER_HOST, 80, {"http": {"uri": "/img/preview.png"}}),
        ("zeek.smb_mapping", "jump01", "fs01", 445, {"smb_mapping": {"path": "\\\\fs01\\ADMIN$"}}),
        ("zeek.dce_rpc", "jump01", "fs01", 445, {"dce_rpc": {"operation": "CreateServiceWOW64W"}}),
        ("zeek.kerberos", "jump01", "dc01", 88, {"kerberos": {"cipher": "rc4-hmac"}}),
        ("zeek.ssh", "ws-it-02", "bkp01", 22, {"ssh": {"auth_success": True}}),
        (
            "zeek.files",
            "ws-sales-02",
            st.DROPPER_HOST,
            80,
            {"files": {"mime_type": "application/x-dosexec"}},
        ),
    )
    for n, (dataset, src, dst, port, zeek) in enumerate(samples):
        src_ip = st.ip_of(src) if src in st.BY_NAME else src
        dst_ip = st.ip_of(dst) if dst in st.BY_NAME else dst
        for k in range(3):
            out.append(
                {
                    "_index": f"logs-{dataset}-default",
                    "_id": es_id(f"net:{n}:{k}"),
                    "_source": {
                        "@timestamp": st.es_time(ago(hours=1 + 7 * k + n)),
                        "event": {"dataset": dataset, "module": "zeek", "category": "network"},
                        "source": {"ip": src_ip, "port": 49152 + n * 11 + k},
                        "destination": {"ip": dst_ip, "port": port},
                        "network": {"community_id": community_id(f"net:{n}:{k}")},
                        "host": {"name": st.SENSOR},
                        "zeek": zeek,
                    },
                }
            )
    return out


# ---------------------------------------------------------------------------
# The mock grid: host traffic for the host page
# ---------------------------------------------------------------------------


def _peer(
    ip: str, direction: str, port: int, per_day: int, *, since: datetime | None = None
) -> dict[str, Any]:
    out: dict[str, Any] = {"ip": ip, "direction": direction, "port": port, "per_day": per_day}
    if since is not None:
        out["since"] = st.es_time(since)
    return out


def traffic() -> dict[str, Any]:
    dc01, dc02, fs01, app01, web01 = (
        st.ip_of(n) for n in ("dc01", "dc02", "fs01", "app01", "web01")
    )
    hosts: dict[str, Any] = {}
    office_out = [
        _peer(dc01, "out", 53, 820),
        _peer(dc01, "out", 88, 140),
        _peer(fs01, "out", 445, 310),
        _peer(web01, "out", 443, 220),
        _peer(app01, "out", 443, 90),
        _peer("151.101.65.67", "out", 443, 380),
        _peer(st.CLOUD_SYNC, "out", 443, 260),
    ]
    for m in st.MACHINES:
        if m.kind != "workstation":
            continue
        peers = [dict(p) for p in office_out]
        if m.name == "ws-sales-04":
            peers.append(_peer(st.EMOTET_C2, "out", 443, 288, since=ago(hours=20, minutes=10)))
        if m.name == "ws-sales-02":
            peers.append(_peer(st.DROPPER_HOST, "out", 80, 4, since=ago(hours=29, minutes=55)))
        if m.name == "ws-eng-03":
            peers.append(_peer(st.QUASAR_C2, "out", 4782, 96, since=ago(hours=1, minutes=10)))
        if m.name == "ws-it-02":
            peers.append(_peer(st.ip_of("jump01"), "out", 3389, 30))
        hosts[m.ip] = {
            "pattern": "office",
            "peers": peers,
            "agent": m.name,
            "users": [[m.owner, 46]] if m.owner else [],
        }
    hosts[dc01] = {
        "pattern": "server",
        "peers": [
            _peer(st.ip_of("ws-mkt-01"), "in", 53, 820),
            _peer(st.ip_of("ws-sales-04"), "in", 53, 790),
            _peer(st.ip_of("ws-fin-02"), "in", 53, 760),
            _peer(st.ip_of("jump01"), "in", 88, 120),
            _peer(st.ip_of("ws-it-02"), "in", 389, 210),
            _peer(dc02, "out", 389, 400),
        ],
        "agent": "dc01",
        "users": [[st.ADMIN_ACCOUNT, 31], [st.KERBEROAST_ACCOUNT, 12], [st.BACKUP_ACCOUNT, 7]],
    }
    hosts[fs01] = {
        "pattern": "office",
        "peers": [
            _peer(st.ip_of("ws-fin-02"), "in", 445, 310),
            _peer(st.ip_of("ws-sales-04"), "in", 445, 290),
            _peer(st.ip_of("ws-mkt-01"), "in", 445, 270),
            _peer(st.ip_of("jump01"), "in", 445, 40, since=ago(hours=14, minutes=40)),
            _peer(st.ip_of("bkp01"), "in", 873, 24),
            _peer(dc01, "out", 88, 160),
        ],
        "agent": "fs01",
        "users": [[st.BACKUP_ACCOUNT, 28], [st.KERBEROAST_ACCOUNT, 3]],
    }
    hosts[st.ip_of("jump01")] = {
        "pattern": "office",
        "peers": [
            _peer(st.ip_of("ws-it-02"), "in", 3389, 30),
            _peer(dc01, "out", 88, 120),
            _peer(fs01, "out", 445, 40, since=ago(hours=14, minutes=40)),
            _peer(app01, "out", 3389, 6),
        ],
        "agent": "jump01",
        "users": [[st.ADMIN_ACCOUNT, 19], [st.KERBEROAST_ACCOUNT, 4], ["l.nguyen", 6]],
    }
    hosts[st.ip_of("bkp01")] = {
        "pattern": "server",
        "peers": [
            _peer(fs01, "out", 873, 24),
            _peer(st.BACKUP_PROVIDER, "out", 443, 18),
            _peer(
                st.R2_STORAGE,
                "out",
                443,
                3,
                since=ago(hours=12, minutes=45),
            ),
            _peer(st.ip_of("ws-it-02"), "in", 22, 8),
        ],
        "agent": "bkp01",
        "users": [[st.BACKUP_ACCOUNT, 42], [st.ADMIN_ACCOUNT, 2]],
    }
    hosts[web01] = {
        "pattern": "office",
        "peers": [
            _peer(st.ip_of("ws-mkt-01"), "in", 443, 220),
            _peer(st.ip_of("ws-sales-04"), "in", 443, 210),
            _peer(st.ip_of("scan01"), "in", 443, 30),
            _peer(dc01, "out", 53, 300),
        ],
        "agent": "web01",
        "users": [["deploy", 9]],
    }
    hosts[st.ip_of("prn-02")] = {
        "pattern": "office",
        "peers": [
            _peer(dc01, "out", 53, 288),
            _peer(st.FIRMWARE_CDN, "out", 443, 2, since=ago(hours=31)),
            _peer(st.ip_of("ws-fin-02"), "in", 9100, 22),
        ],
    }
    return {
        "silent": [{"start": st.es_time(st.GAP_START), "end": st.es_time(st.GAP_END)}],
        "hosts": hosts,
    }


# ---------------------------------------------------------------------------
# The host estate, written through the sweep's own store functions
# ---------------------------------------------------------------------------


def _mac(m: st.Machine) -> str | None:
    return st.mac_of(m)


def _agent_id(m: st.Machine) -> str | None:
    if not m.agent or m.name is None:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{m.name}.{st.ORG_DOMAIN}"))


def _facts(m: st.Machine, observed: datetime) -> list[Any]:
    from soc_ai.dossier.types import STRENGTH_CONFIDENCE, Fact

    def fact(name: str, value: str, source: str, evidence: str, strength: str = "strong") -> Fact:
        return Fact(
            field=name,
            value=value,
            confidence=STRENGTH_CONFIDENCE[strength],  # type: ignore[index]
            strength=strength,  # type: ignore[arg-type]
            source=source,  # type: ignore[arg-type]
            evidence=[evidence],
            observed_at=observed,
        )

    out: list[Fact] = []
    if m.name and m.agent:
        out.append(fact("hostname", m.name, "hostlog", f"{m.name} (from hostlog)"))
    elif m.name and m.dhcp:
        out.append(fact("hostname", m.name, "banner", f"{m.name} (from dhcp)"))
    elif m.dns_only:
        name = f"hv01.{st.ORG_DOMAIN}"
        out.append(fact("hostname", name, "telemetry", f"{name} (from dns, 188 answers agree)"))
    else:
        out.append(Fact(field="hostname", evidence=["no hostname signal in window"]))
    if m.os_family:
        source = "hostlog" if m.agent else "banner"
        out.append(fact("os_family", m.os_family, source, f"{m.os_family} (from {source})"))
    if m.os_detail:
        source = "hostlog" if m.agent else "banner"
        out.append(fact("os_detail", m.os_detail, source, f"{m.os_detail} (from {source})"))
    if m.role:
        source = "hostlog" if m.kind == "workstation" else "behaviour"
        out.append(fact("role", m.role, source, m.role_evidence or m.role, m.role_strength))
    mac = _mac(m)
    if mac:
        source = "hostlog" if m.agent else "banner"
        label = "hostlog" if m.agent else "dhcp"
        out.append(fact("mac", mac, source, f"{mac} (from {label})"))
    if m.services:
        out.append(
            Fact(
                field="services_offered",
                value=", ".join(f"{proto}/{port}" for proto, port, _ in m.services),
                value_json=[
                    {"port": port, "proto": proto, "count": count, "service": None}
                    for proto, port, count in m.services
                ],
                confidence=STRENGTH_CONFIDENCE["strong"],
                strength="strong",
                source="behaviour",
                evidence=[m.role_evidence or "answered ports"],
                observed_at=observed,
            )
        )
    if m.agent and m.os_family == "windows":
        out.append(
            fact(
                "domain_membership",
                st.ORG_DOMAIN,
                "hostlog",
                f"{st.ORG_DOMAIN} (from hostlog: the agent reports the domain)",
            )
        )
    return out


# Table rows the estate writes, dumped from the scratch store in this order.
_ESTATE_TABLES = ("host_machine", "host_dossier", "host_dossier_field", "dossier_run")


async def _build_estate(data_dir: Path) -> dict[str, list[dict[str, Any]]]:
    from soc_ai.config import Settings
    from soc_ai.dossier.types import DhcpLease
    from soc_ai.store import host_dossier as dossier_store
    from soc_ai.store import host_machines
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
    from soc_ai.store.models import Base, DossierRun
    from sqlalchemy import select

    settings = Settings(
        so_host="https://so.example.com",
        so_username="demo",
        so_password="demo-placeholder-unused",
        es_hosts=["http://127.0.0.1:9200"],
        litellm_base_url="http://127.0.0.1:9200",
        soc_ai_data_dir=data_dir,
        _env_file=None,  # type: ignore[call-arg]
    )
    engine = make_engine(settings)
    await run_migrations(engine)
    sm = make_sessionmaker(engine)
    now = st.ANCHOR
    built = now - timedelta(minutes=38)
    agents: list[Any] = []
    leases: list[Any] = []
    dns_names: dict[str, str] = {}
    written = 0
    async with sm() as db:
        for m in st.MACHINES:
            last = now - timedelta(minutes=m.last_minutes)
            host = await dossier_store.upsert_host(
                db,
                m.ip,
                first_seen=now - timedelta(days=m.first_days),
                last_seen=last,
                last_observed_at=last,
                event_count=m.events_per_day * 7,
                last_built_at=built,
                build_error=None,
                now=built,
            )
            if m.dns_only:
                dns_names[m.ip] = f"hv01.{st.ORG_DOMAIN}"
            for fact in _facts(m, last):
                await dossier_store.upsert_inferred(db, host, fact, now=built)
                written += 1
            agent_id, mac = _agent_id(m), _mac(m)
            if agent_id and m.name:
                agents.append(
                    host_machines.AgentClaim(
                        agent_id=agent_id,
                        name=m.name,
                        os=m.os_detail,
                        macs=(mac,) if mac else (),
                        addresses=(m.ip,),
                        last_report=last,
                        docs=m.events_per_day * 2,
                    )
                )
            if m.dhcp and mac:
                leases.append(
                    DhcpLease(
                        ip=m.ip,
                        mac=mac,
                        hostname=m.name,
                        first_seen=now - timedelta(days=m.first_days),
                        last_seen=last,
                    )
                )
        db.add(
            DossierRun(
                started_at=built - timedelta(minutes=3),
                finished_at=built,
                trigger="schedule",
                hosts_seen=len(st.MACHINES),
                hosts_built=len(st.MACHINES),
                fields_written=written,
            )
        )
        await db.commit()
    async with sm() as db:
        for m in st.MACHINES:
            for name, value in m.declared.items():
                await dossier_store.set_override(
                    db,
                    m.ip,
                    name,
                    value,
                    actor=st.ANALYSTS[1],
                    note="Declared at onboarding.",
                    now=built - timedelta(days=20),
                )
    async with sm() as db:
        facts = await host_machines.load_address_facts(
            db,
            dns_names=dns_names,
            now=now,
            min_confidence=dossier_store.DEFAULT_MIN_CONFIDENCE,
            staleness_hours=dossier_store.DEFAULT_STALENESS_HOURS,
        )
    clustering = host_machines.cluster_machines(facts, agents=agents, leases=leases)
    async with sm() as db:
        await host_machines.persist_clustering(db, clustering, facts, now=built)

    out: dict[str, list[dict[str, Any]]] = {}
    tables = {t.name: t for t in Base.metadata.sorted_tables}
    async with sm() as db:
        for name in _ESTATE_TABLES:
            table = tables[name]
            rows = (await db.execute(select(table).order_by(*table.primary_key.columns))).all()
            out[name] = [dict(row._mapping) for row in rows]
    await engine.dispose()
    return out


def _clamp(value: Any) -> Any:
    """A row value as fixture JSON. A datetime past the anchor is a server
    default the scratch store stamped at build time; it becomes the anchor."""
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(UTC).replace(tzinfo=None)
        return iso(min(value, st.ANCHOR))
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*", value):
        try:
            parsed = _parse(value)
        except ValueError:
            return value
        return iso(min(parsed, st.ANCHOR)) if parsed > st.ANCHOR else value
    if isinstance(value, dict):
        return {k: _clamp(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clamp(v) for v in value]
    return value


def estate_tables() -> dict[str, list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="soc-ai-story-") as tmp:
        raw = asyncio.run(_build_estate(Path(tmp)))
    tables = {name: [_clamp(row) for row in rows] for name, rows in raw.items()}
    _shape_estate(tables)
    return tables


def _shape_estate(tables: dict[str, list[dict[str, Any]]]) -> None:
    """Give the estate the states a real sweep shows over time.

    One role guess the sweep has not confirmed for five days (stale), one
    address the sweep failed to build, one declaration the evidence keeps
    disagreeing with (a conflict that prompts the operator), and one machine
    the sweep last built four days ago.
    """
    dossiers = {row["ip"]: row for row in tables["host_dossier"]}
    by_dossier: dict[int, dict[str, dict[str, Any]]] = {}
    for row in tables["host_dossier_field"]:
        by_dossier.setdefault(row["dossier_id"], {})[row["field"]] = row
    # build01: the role guess is five days old.
    build01 = dossiers[st.ip_of("build01")]
    role = by_dossier[build01["id"]]["role"]
    role["inferred_last_run_at"] = iso(ago(days=5))
    role["inferred_last_seen"] = iso(ago(days=5))
    # cam-lobby: the last build failed.
    cam = dossiers[st.ip_of("cam-lobby")]
    cam["build_error"] = "The grid timed out on the services pass for this address."
    # vpn01: the last clean build is four days old.
    vpn = dossiers[st.ip_of("vpn01")]
    vpn["last_built_at"] = iso(ago(days=4, hours=2))
    # scan01: declared a security appliance. Every build reads a server, so
    # the console asks the operator to confirm the declaration.
    scan = dossiers[st.ip_of("scan01")]
    role = by_dossier[scan["id"]]["role"]
    role["conflict_kind"] = "mismatch"
    role["conflict_first_seen_at"] = iso(ago(days=3))
    role["conflict_observations"] = 3
    role["conflict_last_prompted_at"] = iso(ago(hours=5))
    role["conflict_prompt_count"] = 1


# ---------------------------------------------------------------------------
# Profiles: what is normal for each host
# ---------------------------------------------------------------------------

_HOUR_SHAPE = {
    "office": [1, 0, 0, 0, 0, 1, 3, 7, 11, 12, 12, 11, 9, 11, 12, 12, 11, 9, 5, 3, 2, 2, 1, 1],
    "server": [9, 14, 14, 9, 5, 5, 6, 7, 8, 9, 9, 9, 9, 9, 9, 9, 9, 8, 8, 7, 7, 6, 6, 6],
    "always": [6] * 24,
}


def _hourly_series(m: st.Machine, traffic_hosts: dict[str, Any]) -> dict[str, Any]:
    """Seven days of connections per hour, ending at the anchor. The gap hours hold null."""
    per_day = sum(int(p["per_day"]) for p in traffic_hosts.get(m.ip, {}).get("peers", [])) or max(
        40, m.events_per_day // 20
    )
    shape = _HOUR_SHAPE[m.pattern]
    total = sum(shape)
    start = (st.ANCHOR - timedelta(days=7)).replace(minute=0, second=0, microsecond=0)
    counts: list[int | None] = []
    for n in range(7 * 24):
        at = start + timedelta(hours=n)
        if st.GAP_START <= at < st.GAP_END:
            counts.append(None)
            continue
        scale = 0.25 if (m.pattern == "office" and at.weekday() >= 5) else 1.0
        counts.append(round(per_day * shape[at.hour] / total * scale))
    return {"start": at_iso(start), "counts": counts}


def at_iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat() + "+00:00"


def _cells(series: list[int | None], pattern: str) -> dict[str, Any]:
    vals = [v for v in series if v is not None]
    base = sorted(vals)[len(vals) // 2] if vals else 0
    work = max(base, 1)
    off = max(round(work * (0.15 if pattern == "office" else 0.8)), 0)
    weekend = max(round(work * (0.2 if pattern == "office" else 0.9)), 0)
    return {
        "work": {
            "median": float(work),
            "dispersion": round(work * 0.22, 2),
            "support_days": 30,
            "samples": 470,
        },
        "off": {
            "median": float(off),
            "dispersion": round(max(off, 1) * 0.4, 2),
            "support_days": 30,
            "samples": 190,
        },
        "weekend": {
            "median": float(weekend),
            "dispersion": round(max(weekend, 1) * 0.3, 2),
            "support_days": 8,
            "samples": 192,
        },
    }


def profile_rows(
    estate: dict[str, list[dict[str, Any]]], traffic_hosts: dict[str, Any]
) -> list[dict[str, Any]]:
    fingerprints = {row["ip"]: row.get("identity_fingerprint") for row in estate["host_dossier"]}
    built = iso(ago(minutes=50))
    rows: list[dict[str, Any]] = []
    next_id = 1

    def add(m: st.Machine, dimension: str, shape: str, vector: Any, **kw: Any) -> None:
        nonlocal next_id
        new = m.first_days < 7
        row = {
            "id": next_id,
            "entity_kind": "host",
            "entity_key": m.ip,
            "dimension": dimension,
            "shape": shape,
            "vector_json": vector,
            "coverage": "learning" if new else "measured",
            "coverage_reason": None,
            "support_days": int(min(m.first_days, 30)),
            "role": m.declared.get("role") or m.role,
            "role_confidence": 0.9 if (m.role and m.role_strength == "strong") else 0.5,
            "identity_fingerprint": fingerprints.get(m.ip),
            "window_days": 30,
            "first_seen": iso(ago(days=min(m.first_days, 30))),
            "last_seen": iso(ago(minutes=m.last_minutes)),
            "built_at": built,
            "shape_version": 2,
        }
        row.update(kw)
        rows.append(row)
        next_id += 1

    for m in st.MACHINES:
        peers = traffic_hosts.get(m.ip, {}).get("peers", [])
        seen = iso(ago(days=min(m.first_days, 30)))
        recent = iso(ago(minutes=m.last_minutes))

        def member(
            count: int, since: str | None = None, seen: str = seen, recent: str = recent
        ) -> dict[str, Any]:
            return {"count": count, "first_seen": since or seen, "last_seen": recent}

        # The story's new destinations are not in the baseline: the profile
        # holds what was normal before them.
        old_peers = [p for p in peers if "since" not in p]
        add(
            m,
            "peers_out",
            "categorical",
            {p["ip"]: member(int(p["per_day"]) * 30) for p in old_peers if p["direction"] == "out"},
        )
        consumed: dict[str, Any] = {}
        for p in old_peers:
            if p["direction"] != "out":
                continue
            key = str(p["port"])
            consumed.setdefault(key, {**member(0), "peers": 0, "days": 30, "transport": "tcp"})
            consumed[key]["count"] += int(p["per_day"]) * 30
            consumed[key]["peers"] += 1
        add(m, "consumed_ports", "categorical", consumed)
        served = {
            str(port): {**member(count * 30), "peers": 6, "days": 30, "transport": proto}
            for proto, port, count in m.services
        }
        add(m, "served_ports", "categorical", served)
        dns = {f"intranet.{st.ORG_DOMAIN}": member(900), "ctldl.windowsupdate.com": member(60)}
        if m.kind == "iot":
            dns = {"updates.example.com": member(8_640)}
        add(m, "dns_names", "categorical", dns)
        series = _hourly_series(m, traffic_hosts)
        hours = {
            str(h): {"count": int(c * 30)} for h, c in enumerate(_HOUR_SHAPE[m.pattern]) if c > 0
        }
        add(m, "active_hours", "active_hours", hours)
        add(
            m,
            "connection_rate",
            "numeric",
            {**_cells(series["counts"], m.pattern), "hourly": series},
        )
        if m.agent and m.os_family == "windows":
            procs = {
                "explorer.exe": member(900),
                "msedge.exe": member(2_400),
                "svchost.exe": member(30_000),
            }
            if m.kind == "server":
                procs = {"svchost.exe": member(40_000), "wmiprvse.exe": member(1_200)}
            add(m, "process_names", "categorical", procs)
            users = [m.owner] if m.owner else [st.ADMIN_ACCOUNT, st.BACKUP_ACCOUNT]
            add(m, "logon_users", "categorical", {u: member(140) for u in users if u})
        elif m.agent:
            add(m, "process_names", "categorical", {"sshd": member(600), "cron": member(720)})
            add(
                m,
                "logon_users",
                "categorical",
                {"deploy": member(40), st.BACKUP_ACCOUNT: member(60)},
            )
        else:
            for dim in ("process_names", "logon_users"):
                add(
                    m,
                    dim,
                    "categorical",
                    None,
                    coverage="blind",
                    coverage_reason="No agent ships endpoint or logon records from this host.",
                )
    return rows


# ---------------------------------------------------------------------------
# Observations, leads, the grid gap and the held analytic
# ---------------------------------------------------------------------------

GAP_ID = 1
HELD_ANALYTIC = "profile-connection-rate-collapsed"
SPIKE_ANALYTIC = "profile-connection-rate-spiked"

# Lead ids, in the order the leads formed.
L_BUILD, L_PRINTER, L_BEACON, L_JUMP, L_IT, L_ENG = 1, 2, 3, 4, 5, 6

H_JUMP = demo_id("lead-hunt-jump01")
H_BEACON = demo_id("lead-hunt-ws-sales-04")
H_ENG = demo_id("lead-hunt-ws-eng-03")
H_BUILD = demo_id("lead-hunt-build01")


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def _obs(
    oid: int,
    *,
    entity: tuple[str, str],
    kind: str,
    spec: str,
    source: str,
    born: datetime,
    summary: str,
    weight: float,
    shadow: bool = False,
    lead: int | None = None,
    observed: datetime | None = None,
    read_at: datetime | None = None,
    evidence: dict[str, Any] | None = None,
    statistic: tuple[str, float, float] | None = None,
    document_ids: list[str] | None = None,
    occurrences: int = 1,
    dismissed: tuple[str, str, str, datetime] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": oid,
        "entity_kind": entity[0],
        "entity_key": entity[1],
        "kind": kind,
        "spec_id": spec,
        "fingerprint": _fp(spec, entity[1], summary),
        "birth_weight": weight,
        "born_at": iso(born),
        "first_seen_at": iso(born),
        "observed_at": iso(observed or born),
        "occurrences": occurrences,
        "summary": summary,
        "evidence_json": evidence,
        "source": source,
        "shadow": shadow,
        "read_at": iso(read_at) if read_at else None,
        "lead_id": lead,
        "document_ids": document_ids,
    }
    if statistic:
        row["statistic"], row["statistic_value"], row["baseline_value"] = statistic
    if dismissed:
        reason, note, by, at = dismissed
        row.update(
            dismissed_reason=reason, dismissed_note=note, dismissed_by=by, dismissed_at=iso(at)
        )
    return row


def _receipts(ids: list[str], fields: list[str], fires: int, entities: list[str]) -> dict[str, Any]:
    return {
        "receipts": {
            "matched_ids": ids,
            "matched_fields": fields,
            "dry_run": {"window_days": 30, "fires": fires, "entities": entities},
            "overlap": [],
            "baseline": None,
            "complete": True,
            "missing": [],
        },
        "sample_ids": ids,
    }


def observation_rows(alert_ids: dict[str, str]) -> list[dict[str, Any]]:
    """Every observation of the story. ``alert_ids`` maps a run id to its alert id."""
    ip = st.ip_of
    rows: list[dict[str, Any]] = []
    # The grid gap: the profile analytic reads a quiet sensor as quiet hosts.
    gap_hosts = ("fs01", "web01", "app01", "dc02", "jump01")
    for n, name in enumerate(gap_hosts):
        born = st.GAP_START + timedelta(hours=1, minutes=20 * n)
        window = {
            "start": at_iso(st.GAP_START + timedelta(minutes=10 * n)),
            "end": at_iso(born),
        }
        baseline = {"fs01": 310, "web01": 220, "app01": 90, "dc02": 400, "jump01": 40}[name]
        dismissed = None
        lead = None
        if name == "jump01":
            lead = L_JUMP
            dismissed = (
                "grid_gap",
                "The grid held no data in this window. The sensor was down for 6 hours",
                st.ANALYSTS[0],
                ago(hours=13, minutes=20),
            )
        rows.append(
            _obs(
                1 + n,
                entity=("host", ip(name)),
                kind="below_baseline",
                spec=HELD_ANALYTIC,
                source="profile",
                born=born,
                observed=born,
                summary=f"{name} made 0 connections in an hour. Its baseline is {baseline}.",
                weight=0.35,
                lead=lead,
                statistic=("connections_per_hour", 0.0, float(baseline)),
                evidence={"window": window, "baseline": {"median": baseline, "cell": "work"}},
                dismissed=dismissed,
            )
        )
    # The sensor's backlog after the restart reads as a spike on dc01.
    spike_at = st.GAP_END + timedelta(minutes=25)
    rows.append(
        _obs(
            6,
            entity=("host", ip("dc01")),
            kind="above_baseline",
            spec=SPIKE_ANALYTIC,
            source="profile",
            born=spike_at,
            summary="dc01 made 5,820 connections in an hour. Its baseline is 2,150.",
            weight=0.35,
            statistic=("connections_per_hour", 5820.0, 2150.0),
            evidence={
                "window": {
                    "start": at_iso(st.GAP_END - timedelta(minutes=30)),
                    "end": at_iso(spike_at),
                },
                "baseline": {"median": 2150, "cell": "work"},
            },
        )
    )
    # Lead: the printer's firmware update. An analyst closed it.
    rows += [
        _obs(
            7,
            entity=("host", ip("prn-02")),
            kind="novel_served_port",
            spec="prior-workstation-to-network-device-novel-port",
            source="profile",
            born=ago(hours=31, minutes=20),
            summary="ws-fin-02 reached prn-02 on tcp/8443, a port prn-02 has never served.",
            weight=0.5,
            lead=L_PRINTER,
        ),
        _obs(
            8,
            entity=("host", ip("prn-02")),
            kind="off_hours",
            spec="profile-activity-outside-measured-hours",
            source="profile",
            born=ago(hours=31),
            summary="prn-02 was active in an hour it has not used in 30 days.",
            weight=0.3,
            lead=L_PRINTER,
        ),
    ]
    # Lead: the build server. Its hunt found nothing, and soc-ai closed it.
    rows += [
        _obs(
            9,
            entity=("host", ip("build01")),
            kind="novel_consumed_port",
            spec="prior-server-internet-nonweb-novel-port",
            source="profile",
            born=ago(hours=40, minutes=30),
            summary=f"build01 connected to {st.PYPI_MIRROR} on tcp/3141, a port it has never used.",
            weight=0.5,
            lead=L_BUILD,
        ),
        _obs(
            10,
            entity=("host", ip("build01")),
            kind="off_hours",
            spec="profile-activity-outside-measured-hours",
            source="profile",
            born=ago(hours=40),
            summary="build01 was active in an hour it has not used in 30 days.",
            weight=0.3,
            lead=L_BUILD,
        ),
    ]
    # Lead: ws-sales-04 and the Emotet beacon. Its hunt confirmed it, and
    # soc-ai closed it on the verdicts.
    rows += [
        _obs(
            11,
            entity=("host", ip("ws-sales-04")),
            kind="alert",
            spec="alert",
            source="alert",
            born=ago(hours=19),
            summary="ETPRO TROJAN Win32/Emotet CnC Activity (POST): true positive at 0.75",
            weight=1.0,
            lead=L_BEACON,
            evidence={
                "alert_id": alert_ids[EMOTET_INV],
                "verdict": "true_positive",
                "confidence": 0.75,
                "rule_name": "ETPRO TROJAN Win32/Emotet CnC Activity (POST)",
            },
            document_ids=[alert_ids[EMOTET_INV]],
        ),
        _obs(
            12,
            entity=("host", ip("ws-sales-04")),
            kind="off_hours",
            spec="profile-activity-outside-measured-hours",
            source="profile",
            born=ago(hours=18, minutes=40),
            summary="ws-sales-04 was active in an hour it has not used in 30 days.",
            weight=0.3,
            lead=L_BEACON,
        ),
        _obs(
            13,
            entity=("host", ip("ws-sales-04")),
            kind="alert",
            spec="alert",
            source="alert",
            born=ago(hours=18, minutes=5),
            summary=f"{BEACON_RULE}: true positive at 0.86",
            weight=1.0,
            lead=L_BEACON,
            evidence={
                "alert_id": BEACON_ALERT,
                "verdict": "true_positive",
                "confidence": 0.86,
                "rule_name": BEACON_RULE,
            },
            document_ids=[BEACON_ALERT],
        ),
    ]
    # Lead: jump01. Its hunt found a threat, and the lead waits for a decision.
    rows += [
        _obs(
            14,
            entity=("user", st.KERBEROAST_ACCOUNT),
            kind="catalog_match",
            spec="identity-4769-rc4-service-ticket",
            source="catalog",
            born=ago(hours=14, minutes=50),
            summary=(
                f"{st.KERBEROAST_ACCOUNT} requested an RC4 service ticket for "
                "MSSQLSvc/app01 from jump01."
            ),
            weight=0.7,
            lead=L_JUMP,
            evidence={"sample_ids": ["3N6cTp8BwxVkvmc70vqd"]},
            document_ids=["3N6cTp8BwxVkvmc70vqd"],
        ),
        _obs(
            15,
            entity=("host", ip("jump01")),
            kind="off_hours",
            spec="profile-activity-outside-measured-hours",
            source="profile",
            born=ago(hours=14, minutes=25),
            summary="jump01 was active in an hour it has not used in 30 days.",
            weight=0.3,
            lead=L_JUMP,
        ),
        _obs(
            16,
            entity=("host", ip("jump01")),
            kind="logon_chain",
            spec="model-logon-chain",
            source="model",
            born=ago(hours=14, minutes=20),
            summary="jump01 took an RDP session from ws-it-02, then logged on to fs01 for the first time.",
            weight=0.7,
            shadow=True,
            evidence=_receipts(
                ["4d6cTp8BwxVkvmc70vqw", "4t6cTp8BwxVkvmc70vqy"],
                ["source.ip", "destination.ip", "zeek.smb_mapping.path"],
                2,
                ["jump01"],
            ),
        ),
    ]
    # Lead: ws-it-02, from two shadow analytics. New, and it waits for a decision.
    rows += [
        _obs(
            17,
            entity=("host", ip("ws-it-02")),
            kind="logon_chain",
            spec="model-logon-chain",
            source="model",
            born=ago(hours=2, minutes=50),
            summary="ws-it-02 took an RDP session from vpn01, then made its first SSH logon to bkp01.",
            weight=0.7,
            shadow=True,
            lead=L_IT,
            evidence=_receipts(
                [es_id("logon:0")], ["source.ip", "host.ip", "user.name"], 1, ["ws-it-02"]
            ),
        ),
        _obs(
            18,
            entity=("host", ip("ws-it-02")),
            kind="telemetry_silence",
            spec="model-cross-plane-silence",
            source="model",
            born=ago(hours=2, minutes=40),
            summary=(
                "ws-it-02 sent no endpoint records for 3 hours. The sensor saw 412 "
                "connections from it in the same hours."
            ),
            weight=0.45,
            shadow=True,
            lead=L_IT,
            evidence=_receipts([], ["agent.id", "source.ip"], 1, ["ws-it-02"]),
        ),
        # A shadow hit an analyst already read.
        _obs(
            19,
            entity=("host", ip("bkp01")),
            kind="telemetry_silence",
            spec="model-cross-plane-silence",
            source="model",
            born=ago(hours=11, minutes=50),
            summary=(
                "bkp01 sent no endpoint records for 40 minutes during the upload. "
                "The sensor kept seeing its traffic."
            ),
            weight=0.45,
            shadow=True,
            read_at=ago(hours=9, minutes=30),
            evidence=_receipts([], ["agent.id", "source.ip"], 1, ["bkp01"]),
        ),
    ]
    # Lead: ws-eng-03 and the Quasar client. Its hunt is in progress.
    rows += [
        _obs(
            20,
            entity=("host", ip("ws-eng-03")),
            kind="novel_process",
            spec="prior-workstation-remote-execution-tooling",
            source="profile",
            born=ago(minutes=52),
            summary="ws-eng-03 ran Client.exe, a remote administration tool, for the first time.",
            weight=0.5,
            lead=L_ENG,
        ),
        _obs(
            21,
            entity=("host", ip("ws-eng-03")),
            kind="above_baseline",
            spec=SPIKE_ANALYTIC,
            source="profile",
            born=ago(minutes=38),
            summary=f"ws-eng-03 made 96 connections in an hour to {st.QUASAR_C2}. Its baseline is 14.",
            weight=0.35,
            lead=L_ENG,
            statistic=("connections_per_hour", 96.0, 14.0),
        ),
    ]
    # The DCSync analytic on the admin account, two days back.
    rows.append(
        _obs(
            22,
            entity=("user", st.ADMIN_ACCOUNT),
            kind="prior_no_baseline",
            spec="identity-4662-dcsync-nonmachine",
            source="catalog",
            born=ago(hours=48, minutes=21),
            summary=(
                f"{st.ADMIN_ACCOUNT} requested directory replication from dc01. "
                "A user account does not replicate a directory."
            ),
            weight=1.0,
            evidence={"sample_ids": list(_DCSYNC_IDS)},
            document_ids=list(_DCSYNC_IDS),
        )
    )
    # Triaged alerts on their internal hosts (the host page's alert card).
    alert_rows = (
        (
            23,
            URLHAUS_INV,
            "ws-sales-02",
            "ET DROP urlhaus.abuse.ch malware distribution URL",
            0.85,
            29.0,
        ),
        (24, BZAR_INV, "jump01", "BZAR ATTACK::Execution_Service_Creation", 0.92, 13.5),
        (25, BZAR_INV, "fs01", "BZAR ATTACK::Execution_Service_Creation", 0.92, 13.5),
        (
            26,
            FOLLOWUP_INV,
            "bkp01",
            "SOC-AI ANALYTIC Long Connection Asymmetric Bytes First-Seen FQDN",
            0.81,
            9.6,
        ),
    )
    for oid, inv_id, host, rule, conf, hours in alert_rows:
        rows.append(
            _obs(
                oid,
                entity=("host", ip(host)),
                kind="alert",
                spec="alert",
                source="alert",
                born=ago(hours=hours),
                summary=f"{rule}: true positive at {conf:.2f}",
                weight=1.0,
                lead=L_JUMP if host == "jump01" else None,
                evidence={
                    "alert_id": alert_ids[inv_id],
                    "verdict": "true_positive",
                    "confidence": conf,
                    "rule_name": rule,
                },
                document_ids=[alert_ids[inv_id]],
            )
        )
    return rows


def lead_rows(emotet_alert: str) -> list[dict[str, Any]]:
    ip = st.ip_of

    def lead(
        lid: int,
        *,
        status: str,
        formed: datetime,
        entities: list[list[str]],
        kinds: list[str],
        weight: float,
        hunt: str | None = None,
        shadow: bool = False,
        decisions: list[dict[str, Any]] | None = None,
        updated: datetime | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        return {
            "id": lid,
            "status": status,
            "formed_at": iso(formed),
            "updated_at": iso(updated or formed),
            "entities_json": entities,
            "kinds_json": kinds,
            "weight_at_formation": weight,
            "scope_count": len(entities),
            "hunt_id": hunt,
            "shadow": shadow,
            "single_signal": False,
            "decisions_json": decisions or [],
            **extra,
        }

    return [
        lead(
            L_PRINTER,
            status="dismissed",
            formed=ago(hours=31),
            entities=[["host", ip("prn-02")]],
            kinds=["novel_served_port", "off_hours"],
            weight=0.8,
            updated=ago(hours=29, minutes=10),
            dismissed_reason="known_change",
            dismissed_note=(
                "The vendor pushed a firmware update. Facilities scheduled it outside office hours."
            ),
            dismissed_by=st.ANALYSTS[1],
            dismissed_at=iso(ago(hours=29, minutes=10)),
            decisions=[
                {
                    "action": "dismissed",
                    "at": at_iso(ago(hours=29, minutes=10)),
                    "by": st.ANALYSTS[1],
                    "reason": "known_change",
                    "note": "The vendor pushed a firmware update. Facilities scheduled it outside office hours.",
                }
            ],
        ),
        lead(
            L_BUILD,
            status="dismissed",
            formed=ago(hours=40),
            entities=[["host", ip("build01")]],
            kinds=["novel_consumed_port", "off_hours"],
            weight=0.8,
            hunt=H_BUILD,
            updated=ago(hours=39, minutes=30),
            dismissed_reason="hunt_clean",
            dismissed_by="auto-hunt",
            dismissed_at=iso(ago(hours=39, minutes=30)),
            decisions=[
                {
                    "action": "closed_by_hunt",
                    "at": at_iso(ago(hours=39, minutes=30)),
                    "by": "auto-hunt",
                    "reason": "hunt_clean",
                    "hunt_id": H_BUILD,
                }
            ],
        ),
        lead(
            L_BEACON,
            status="promoted",
            formed=ago(hours=18, minutes=40),
            entities=[["host", ip("ws-sales-04")]],
            kinds=["alert", "off_hours"],
            weight=1.3,
            hunt=H_BEACON,
            updated=ago(hours=17, minutes=50),
            investigation_id=EMOTET_INV,
            decisions=[
                {
                    "action": "promoted",
                    "at": at_iso(ago(hours=17, minutes=50)),
                    "by": "system:hunt",
                    "reason": "finding_verdict",
                    "investigation_id": EMOTET_INV,
                    "hunt_id": H_BEACON,
                }
            ],
        ),
        lead(
            L_JUMP,
            status="hunting",
            formed=ago(hours=14, minutes=15),
            entities=[["host", ip("jump01")], ["user", st.KERBEROAST_ACCOUNT]],
            kinds=["catalog_match", "off_hours", "alert"],
            weight=2.0,
            hunt=H_JUMP,
            updated=ago(hours=13, minutes=20),
        ),
        lead(
            L_IT,
            status="open",
            formed=ago(hours=2, minutes=40),
            entities=[["host", ip("ws-it-02")], ["user", st.ADMIN_ACCOUNT]],
            kinds=["logon_chain", "telemetry_silence"],
            weight=1.15,
            shadow=True,
        ),
        lead(
            L_ENG,
            status="hunting",
            formed=ago(minutes=30),
            entities=[["host", ip("ws-eng-03")]],
            kinds=["novel_process", "above_baseline"],
            weight=0.85,
            hunt=H_ENG,
            updated=ago(minutes=6),
        ),
    ]


def gap_rows() -> list[dict[str, Any]]:
    return [
        {
            "id": GAP_ID,
            "source": "sweep",
            "plane": "connection_rate",
            "started_at": iso(st.GAP_START),
            "ended_at": iso(st.GAP_END),
            "detail": "The sensor stopped. Most hosts sent no network flow documents for 6 hours.",
            "created_at": iso(st.GAP_START + timedelta(minutes=10)),
        }
    ]


def analytic_rows() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The held analytic: soc-ai moved it to shadow after the gap's false hits."""
    held_at = st.GAP_END - timedelta(minutes=50)
    start = held_at - timedelta(hours=24)
    why = "The analytic wrote 5 hits in 24 hours. Its daily hit limit is 3."
    spec_text = (REPO / "soc_ai" / "hunting" / "catalog" / f"{HELD_ANALYTIC}.yaml").read_text()
    state = [
        {
            "analytic_id": HELD_ANALYTIC,
            "tier": "shipped",
            "status": "shadow",
            "spec_text": None,
            "created_by": "system:self-heal",
            "created_at": iso(held_at),
            "updated_at": iso(held_at),
            "reason": why,
        }
    ]
    versions = [
        {
            # A high id: the startup seeds version rows for the analytics that
            # ship in shadow before the demo seed runs, from id 1 up.
            "id": 1001,
            "analytic_id": HELD_ANALYTIC,
            "from_status": "live",
            "to_status": "shadow",
            "who": "system:self-heal",
            "at": iso(held_at),
            "why": why,
            "spec_before": spec_text,
            "spec_after": spec_text,
            "receipts_json": {
                "evidence": {
                    "breaches": [
                        {
                            "rule": "fire_budget",
                            "hits": 5,
                            "budget": 3,
                            "window_hours": 24,
                            "window_start": at_iso(start).replace("+00:00", "Z"),
                            "window_end": at_iso(held_at).replace("+00:00", "Z"),
                        }
                    ]
                }
            },
        }
    ]
    return state, versions


def failed_sweep_rows() -> list[dict[str, Any]]:
    """One catalog sweep the grid refused, nine hours back: every match analytic failed.

    Explicit low ids, so the catalog trail seeded after it keeps each
    analytic's newest row clean.
    """
    from soc_ai.hunting.spec import CATALOG_DIR, load_catalog

    at = iso(ago(hours=9, minutes=5))
    rows = []
    match_specs = [
        spec_id
        for spec_id, spec in load_catalog(CATALOG_DIR).items()
        if getattr(spec, "evaluator", None) in (None, "query", "match")
        and not getattr(spec, "runs_in_prior_sweep", False)
    ]
    for n, spec_id in enumerate(sorted(match_specs), start=1):
        rows.append(
            {
                "id": n,
                "created_at": at,
                "spec_id": spec_id,
                "shadow": False,
                "blind": False,
                "error": "detection: ConnectionTimeout: Connection timed out",
                "window_since": "now-1440m",
                "window_until": "now",
                "duration_ms": 30_000,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Hunts
# ---------------------------------------------------------------------------


def _hunt(
    hid: str,
    *,
    objective: str,
    kind: str,
    starter: str,
    started_by: str,
    created: datetime,
    minutes: float | None,
    report: dict[str, Any] | None,
    steps: list[tuple[str, dict[str, Any], dict[str, Any] | None]],
    lead_id: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    from soc_ai.store.hunts import _objective_hash

    events: list[dict[str, Any]] = []

    def add(kind_: str, payload: dict[str, Any]) -> None:
        events.append({"kind": kind_, "sequence": len(events) + 1, "payload": payload})

    add("hunt_started", {"objective": objective})
    for n, (tool, args, result) in enumerate(steps, start=1):
        call_id = f"call-{hid[-6:].lower()}-{n}"
        add("tool_call", {"tool_name": tool, "tool_call_id": call_id, "args": args})
        if result is not None:
            add("tool_result", {"tool_call_id": call_id, "result": result})
    findings = (report or {}).get("findings") or []
    threats = sum(1 for f in findings if f.get("category") == "threat")
    if report is not None:
        add("hunt_report", dict(report))
        add("done", {"finding_count": len(findings)})
    row: dict[str, Any] = {
        "id": hid,
        "objective": objective,
        "objective_hash": _objective_hash(objective),
        "kind": kind,
        "status": "complete" if report is not None else "running",
        "narrative": (report or {}).get("narrative"),
        "report": report,
        "findings_count": len(findings) if report is not None else None,
        "threat_findings_count": threats if report is not None else None,
        "started_by": started_by,
        "starter": starter,
        "lead_id": lead_id,
        "created_at": iso(created),
        "finished_at": iso(created + timedelta(minutes=minutes)) if minutes is not None else None,
        "events": events,
    }
    row.update(extra)
    return row


def _report(
    narrative: str,
    findings: list[dict[str, Any]],
    *,
    mitre: list[str] | None = None,
    confidence: float = 0.8,
    actions: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    hosts: list[str] = []
    for f in findings:
        for h in f.get("hosts") or []:
            if h not in hosts:
                hosts.append(h)
    return {
        "findings": findings,
        "narrative": narrative,
        "affected_hosts": hosts,
        "mitre_techniques": mitre or [],
        "recommended_actions": actions or [],
        "confidence": confidence,
        "charts": [],
    }


def _finding(
    title: str,
    detail: str,
    *,
    category: str,
    severity: str,
    hosts: list[str],
    citations: list[str],
    mitre: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "detail": detail,
        "severity": severity,
        "category": category,
        "hosts": hosts,
        "citations": citations,
        "mitre_techniques": mitre or [],
    }


def _lead_objective(lead: dict[str, Any], observations: list[dict[str, Any]]) -> str:
    """The objective the lead hunt starts with, written by the product's own function."""
    from soc_ai.store.leads import evidence_block_for, objective_for
    from soc_ai.store.models import EntityObservation, Lead

    model = Lead(id=lead["id"], entities_json=lead["entities_json"], kinds_json=lead["kinds_json"])
    rows = [
        EntityObservation(
            kind=o["kind"],
            spec_id=o["spec_id"],
            summary=o["summary"],
            document_ids=o.get("document_ids"),
            evidence_json=o.get("evidence_json"),
            statistic=o.get("statistic"),
            statistic_value=o.get("statistic_value"),
            baseline_value=o.get("baseline_value"),
            observed_at=_parse(o["observed_at"]),
            born_at=_parse(o["born_at"]),
        )
        for o in observations
        if o.get("lead_id") == lead["id"] and not o.get("dismissed_at")
    ]
    return objective_for(model, rows) + "\n\n" + evidence_block_for(rows, now=st.ANCHOR)


def hunt_rows(
    leads: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    alert_ids: dict[str, str],
    schedules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_lead = {lead["id"]: lead for lead in leads}
    jump, fs = "jump01", "fs01"
    out: list[dict[str, Any]] = []
    out.append(
        _hunt(
            H_BUILD,
            objective=_lead_objective(by_lead[L_BUILD], observations),
            kind="lead",
            starter="lead",
            started_by="auto-hunt",
            created=ago(hours=39, minutes=58),
            minutes=8,
            lead_id=L_BUILD,
            steps=[
                (
                    "t_query_events_oql",
                    {"oql": f"source.ip:{st.ip_of('build01')} AND destination.port:3141"},
                    {"total": 214, "summary": "build01 pulls Python packages from the new mirror"},
                ),
                (
                    "t_lookup_runbook",
                    {"query": "package mirror"},
                    {"matches": [], "summary": "no runbook names the mirror"},
                ),
            ],
            report=_report(
                f"build01 started to pull Python packages from {st.PYPI_MIRROR} on tcp/3141. "
                "The requests name package files only, at the times of the nightly build. "
                "No threat found.",
                [
                    _finding(
                        "build01 uses a new package mirror",
                        f"build01 downloads package files from {st.PYPI_MIRROR}:3141 during "
                        "the nightly build. The mirror answers with package files only.",
                        category="observation",
                        severity="info",
                        hosts=["build01"],
                        citations=["zeek.conn", "zeek.http"],
                    )
                ],
                confidence=0.82,
            ),
            findings_total=0,
            findings_investigated=0,
        )
    )
    emotet_alert = alert_ids[EMOTET_INV]
    out.append(
        _hunt(
            H_BEACON,
            objective=_lead_objective(by_lead[L_BEACON], observations),
            kind="lead",
            starter="lead",
            started_by="auto-hunt",
            created=ago(hours=18, minutes=35),
            minutes=11,
            lead_id=L_BEACON,
            steps=[
                (
                    "t_beacon_profile",
                    {"src_ip": st.ip_of("ws-sales-04"), "dst_ip": st.EMOTET_C2},
                    {"connections": 61, "median_interval_s": 300, "jitter_ratio": 0.04},
                ),
                (
                    "t_query_events_oql",
                    {"oql": f"destination.ip:{st.EMOTET_C2}"},
                    {"total": 64, "summary": "only ws-sales-04 talks to the address"},
                ),
            ],
            report=_report(
                f"ws-sales-04 beacons to {st.EMOTET_C2} every 300 seconds and sends Emotet "
                "check-ins to the same address. No other host of the estate talks to it.",
                [
                    _finding(
                        "Beacon to the Emotet server every 300 s",
                        f"ws-sales-04 opens a TLS session to {st.EMOTET_C2}:443 every 300 "
                        "seconds, 61 times in a row, each under 2 KB.",
                        category="threat",
                        severity="high",
                        hosts=["ws-sales-04"],
                        citations=[BEACON_ALERT, "zeek.conn"],
                        mitre=["T1071.001"],
                    ),
                    _finding(
                        "Emotet check-ins from ws-sales-04",
                        "The Emotet POST rule fired on the same address. The POST bodies "
                        "carry encrypted payloads of 12 KB.",
                        category="threat",
                        severity="high",
                        hosts=["ws-sales-04"],
                        citations=[emotet_alert],
                        mitre=["T1071.001"],
                    ),
                    _finding(
                        "No other host talks to the address",
                        f"No other host of the estate opened a connection to {st.EMOTET_C2} "
                        "in the last 7 days.",
                        category="observation",
                        severity="info",
                        hosts=[],
                        citations=["zeek.conn"],
                    ),
                ],
                mitre=["T1071.001"],
                confidence=0.88,
            ),
            findings_total=2,
            findings_investigated=2,
            finding_investigations={
                "0": {"state": "ended", "investigation_id": EMOTET_INV, "origin": "reused"},
                "1": {"state": "ended", "investigation_id": EMOTET_INV, "origin": "reused"},
            },
        )
    )
    bzar_cites = ["4N6cTp8BwxVkvmc70vqu", "496cTp8BwxVkvmc70vq0", "5N6cTp8BwxVkvmc70vq1"]
    out.append(
        _hunt(
            H_JUMP,
            objective=_lead_objective(by_lead[L_JUMP], observations),
            kind="lead",
            starter="lead",
            started_by="auto-hunt",
            created=ago(hours=13, minutes=55),
            minutes=14,
            lead_id=L_JUMP,
            steps=[
                (
                    "t_query_zeek_logs",
                    {
                        "src_ip": st.ip_of(jump),
                        "log_types": ["smb_mapping", "dce_rpc", "smb_files"],
                    },
                    {
                        "total": 6,
                        "summary": "ADMIN$ mapped, PSEXESVC.exe written, a service created",
                    },
                ),
                (
                    "t_query_events_oql",
                    {"oql": f"user.name:{st.KERBEROAST_ACCOUNT} AND event.dataset:zeek.kerberos"},
                    {"total": 3, "summary": "RC4 service tickets for MSSQLSvc/app01"},
                ),
            ],
            report=_report(
                f"jump01 ran PsExec against fs01 as {st.KERBEROAST_ACCOUNT} in an hour it does "
                "not use, after "
                "an RC4 service ticket request for the same account. jump01 has not run "
                "PsExec in 30 days. No other host received the service.",
                [
                    _finding(
                        "PsExec service on fs01 from jump01",
                        "jump01 mapped ADMIN$ on fs01, wrote PSEXESVC.exe and started it as a "
                        "service, outside the hours jump01 uses.",
                        category="threat",
                        severity="high",
                        hosts=[jump, fs],
                        citations=bzar_cites,
                        mitre=["T1021.002", "T1569.002"],
                    ),
                    _finding(
                        f"RC4 ticket request for {st.KERBEROAST_ACCOUNT}",
                        f"{st.KERBEROAST_ACCOUNT} asked dc01 for an RC4 service ticket from "
                        "jump01 35 minutes before the PsExec run.",
                        category="threat",
                        severity="high",
                        hosts=[jump],
                        citations=["3N6cTp8BwxVkvmc70vqd"],
                        mitre=["T1558.003"],
                    ),
                    _finding(
                        "No other host received the service",
                        "PSEXESVC.exe reached fs01 only.",
                        category="observation",
                        severity="info",
                        hosts=[],
                        citations=["zeek.smb_files"],
                    ),
                ],
                mitre=["T1021.002", "T1569.002", "T1558.003"],
                confidence=0.86,
                actions=[
                    {
                        "title": "Reset the jdoe credentials",
                        "rationale": "The RC4 request suggests a cracked service ticket.",
                    }
                ],
            ),
            findings_total=0,
            findings_investigated=0,
        )
    )
    out.append(
        _hunt(
            H_ENG,
            objective=_lead_objective(by_lead[L_ENG], observations),
            kind="lead",
            starter="lead",
            started_by="auto-hunt",
            created=ago(minutes=6),
            minutes=None,
            lead_id=L_ENG,
            steps=[
                (
                    "t_query_events_oql",
                    {"oql": f"source.ip:{st.ip_of('ws-eng-03')} AND destination.port:4782"},
                    {
                        "total": 96,
                        "summary": f"96 connections to {st.QUASAR_C2}:4782 in the last hour",
                    },
                ),
                ("t_host_summary", {"ip": st.ip_of("ws-eng-03")}, None),
            ],
            report=None,
        )
    )
    # Two schedule runs. Neither found a threat.
    sched = {s["id"]: s for s in schedules}
    out.append(
        _hunt(
            demo_id("schedule-run-beacons"),
            objective=sched[9003]["objective"],
            kind="scheduled",
            starter="schedule",
            started_by="scheduler",
            created=ago(hours=22, minutes=30),
            minutes=9,
            steps=[
                (
                    "t_query_events_oql",
                    {"oql": "event.dataset:zeek.conn AND network.direction:outbound"},
                    {"total": 41_220, "summary": "no regular cadence to a rare external address"},
                )
            ],
            report=_report(
                "No internal host beacons to a rare external address in the last 24 hours. "
                "Two update services poll at a fixed cadence, and both are on the estate "
                "baseline.",
                [
                    _finding(
                        "Two known update pollers",
                        "prn-02 and the Windows hosts poll their update services at a fixed "
                        "cadence. Both destinations are on the baseline of 30 days.",
                        category="observation",
                        severity="info",
                        hosts=["prn-02"],
                        citations=["zeek.conn"],
                    )
                ],
                confidence=0.78,
            ),
            findings_total=0,
            findings_investigated=0,
        )
    )
    out.append(
        _hunt(
            demo_id("schedule-run-kerberos"),
            objective=sched[9001]["objective"],
            kind="scheduled",
            starter="schedule",
            started_by="scheduler",
            created=ago(hours=6, minutes=2),
            minutes=6,
            steps=[
                (
                    "t_query_events_oql",
                    {"oql": "event.dataset:zeek.kerberos AND zeek.kerberos.error_msg:*PREAUTH*"},
                    {"total": 4, "summary": "4 pre-authentication failures, one user each"},
                )
            ],
            report=_report(
                "The VPN pool shows 4 Kerberos pre-authentication failures in 6 hours, one per "
                "user. No address repeats them. No threat found.",
                [
                    _finding(
                        "Four single failures",
                        "Four users mistyped a password once each. No source repeats a failure.",
                        category="observation",
                        severity="info",
                        hosts=["vpn01"],
                        citations=["zeek.kerberos"],
                    )
                ],
                confidence=0.8,
            ),
            findings_total=0,
            findings_investigated=0,
        )
    )
    return out


# Recorded chat hunts: who asked, and when.
RECORDED_HUNTS: dict[str, tuple[float, str]] = {
    "01DEMOHUNT000000000000SSH1": (7.0, st.ANALYSTS[0]),
    "01DEMOHUNT000000000000DNS2": (4.0, st.ANALYSTS[1]),
}


def place_hunt(hunt: dict[str, Any]) -> dict[str, Any]:
    from soc_ai.store.hunts import _objective_hash

    hours, who = RECORDED_HUNTS[hunt["id"]]
    target = ago(hours=hours)
    delta = target - _parse(hunt["created_at"])
    out: dict[str, Any] = shift_tree(hunt, delta)
    out["created_at"] = iso(target)
    out["finished_at"] = iso(_parse(hunt["finished_at"]) + delta)
    findings = (out.get("report") or {}).get("findings") or []
    out["findings_count"] = len(findings)
    out["threat_findings_count"] = sum(1 for f in findings if f.get("category") == "threat")
    out["objective_hash"] = _objective_hash(out["objective"])
    out["started_by"] = who
    out["starter"] = "analyst"
    out["findings_total"] = 0
    out["findings_investigated"] = 0
    return out


def schedule_rows() -> list[dict[str, Any]]:
    return [
        {
            "id": 9001,
            "objective": (
                "Sweep for repeated Kerberos pre-authentication failures across the "
                "remote-access VPN pool"
            ),
            "interval_minutes": 360,
            "enabled": True,
            "last_run_at": iso(ago(hours=6, minutes=2)),
            "created_by": st.ANALYSTS[1],
            "created_at": iso(ago(days=16)),
        },
        {
            "id": 9002,
            "objective": "Review outbound TLS to newly registered domains from the finance network",
            "interval_minutes": 1440,
            "enabled": False,
            "last_run_at": None,
            "created_by": st.ANALYSTS[0],
            "created_at": iso(ago(days=13)),
        },
        {
            "id": 9003,
            "objective": (
                "Hunt for internal hosts that beacon to rare external addresses in the last "
                "24 hours: a regular cadence, a low data volume, a new destination"
            ),
            "interval_minutes": 720,
            "enabled": True,
            "last_run_at": iso(ago(hours=22, minutes=30)),
            "created_by": st.ANALYSTS[0],
            "created_at": iso(ago(days=12)),
        },
    ]


# ---------------------------------------------------------------------------
# Backtests
# ---------------------------------------------------------------------------

_BACKTEST_ROWS: tuple[tuple[str, str, str, float, str], ...] = (
    # rule, analyst disposition, soc-ai verdict, confidence, the summary of the replay
    (
        "ET INFO External IP Lookup Domain (ipify .org) in DNS Lookup",
        "false_positive",
        "false_positive",
        0.9,
        "A workstation asked for its public address. The lookup service is legitimate.",
    ),
    (
        "ET MALWARE Potential DNS Command and Control via TXT queries",
        "false_positive",
        "false_positive",
        0.93,
        "A Mac sent a Bonjour discovery query. The TXT record is a local service lookup.",
    ),
    (
        "ET WEB_SPECIFIC_APPS Possible SQL Injection UNION SELECT",
        "false_positive",
        "false_positive",
        0.88,
        "scan01 probed web01 during the weekly scan. The server answered 404.",
    ),
    (
        "ET HUNTING Periodic Outbound HTTPS Connection Possible Beacon",
        "false_positive",
        "false_positive",
        0.91,
        "A Windows host downloaded the certificate trust list. One short session.",
    ),
    (
        "ET INFO Observed Let's Encrypt Certificate from Active Intermediate, E1",
        "false_positive",
        "false_positive",
        0.95,
        "A browser received a Let's Encrypt certificate. The certificate is valid.",
    ),
    (
        "GPL ICMP Fragment Reassembly Time Exceeded",
        "false_positive",
        "false_positive",
        0.84,
        "A router returned an ICMP time-exceeded message. No payload followed.",
    ),
    (
        "ET TOR Known Tor Exit Node Traffic group 1",
        "false_positive",
        "false_positive",
        0.8,
        "A Tor exit node knocked on the VPN SSH port. The login failed.",
    ),
    (
        "ETPRO TROJAN Win32/Emotet CnC Activity (POST)",
        "true_positive",
        "true_positive",
        0.83,
        "A workstation posted encrypted check-ins to a listed Emotet server.",
    ),
    (
        "ET DROP urlhaus.abuse.ch malware distribution URL",
        "true_positive",
        "true_positive",
        0.86,
        "A workstation downloaded an executable dressed as an image from a listed host.",
    ),
    (
        "ET MALWARE Possible Cobalt Strike Beacon (GET)",
        "true_positive",
        "needs_more_info",
        0.5,
        "A GET to a rare address matched a beacon profile. The payload was not readable.",
    ),
)

BACKTEST_NEW = demo_id("backtest-newest")
BACKTEST_CANCELLED = demo_id("backtest-cancelled")


def backtest_rows(
    recorded: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The newest run with its replays, a cancelled run, and the recorded run a week back."""
    import soc_ai.api.webui  # noqa: F401 - the backtest module needs the API package first
    from soc_ai.webui.backtest import CAVEAT, _completion, score

    started = ago(hours=3, minutes=20)
    rows: list[dict[str, Any]] = []
    replays: list[dict[str, Any]] = []
    for n, (rule, human, verdict, conf, summary) in enumerate(_BACKTEST_ROWS):
        alert_id = es_id(f"backtest:{n}")
        inv_id = demo_id(f"backtest-replay-{n}")
        at = started + timedelta(minutes=2 * n)
        flat = _flat_alert(
            alert_id,
            at - timedelta(days=3 + n),
            rule,
            st.ip_of("ws-mkt-01"),
            st.BACKTEST_PEER,
            443,
            sport=52000 + n,
            flow=community_id(f"backtest:{n}"),
            severity=1,
        )
        action = (
            {
                "tool_name": "ack_alert",
                "tool_args": {"alert_id": alert_id, "comment": summary},
                "rationale": "Benign by the evidence of the replay.",
            }
            if verdict == "false_positive"
            else {
                "tool_name": "escalate_to_case",
                "tool_args": {"alert_id": alert_id, "case_title": rule},
                "rationale": "The replay found the threat again.",
            }
        )
        run = authored_run(
            inv_id=inv_id,
            alert=flat,
            started=at,
            minutes=1.8,
            verdict=verdict,
            confidence=conf,
            summary=summary,
            opening="A backtest replay of an alert an analyst already closed.",
            steps=[
                (
                    "t_rule_prevalence",
                    {"rule_name": rule},
                    {"rule_name": rule, "lookback_days": 30, "total_fires": 6 + 3 * n},
                )
            ],
            evidence=[summary],
            citations=["tool t_rule_prevalence:result.total_fires"],
            actions=[action],
            started_by="backtest",
        )
        replays.append(run)
        rows.append(
            {
                "alert_id": alert_id,
                "rule_name": rule,
                "human_disposition": human,
                "soc_ai_verdict": verdict,
                "match": verdict == human,
                "investigation_id": inv_id,
            }
        )

    def results(rows_: list[dict[str, Any]]) -> dict[str, Any]:
        metrics = score(rows_)
        return {
            "metrics": {
                key: metrics[key]
                for key in (
                    "agreement_rate",
                    "completion_rate",
                    "fp_agreement_rate",
                    "fp_reduction",
                    "missed_tp",
                    "n_needs_more_info",
                    "n_no_verdict",
                    "counts",
                )
            },
            "completion": _completion(metrics),
            "confusion": metrics["confusion"],
            "missed_tp_rows": metrics["missed_tp_rows"],
            "rows": rows_,
            "alert_ids": [r["alert_id"] for r in rows_],
            "caveat": CAVEAT,
        }

    newest = {
        "id": BACKTEST_NEW,
        "params": {
            "window_days": 14,
            "sample_size": 10,
            "requested_sample_size": 10,
            "min_severity": None,
        },
        "status": "complete",
        "sampled": len(rows),
        "results": results(rows),
        "started_by": st.ANALYSTS[1],
        "created_at": iso(started),
        "finished_at": iso(started + timedelta(minutes=22)),
    }
    cancelled_rows = [dict(r, investigation_id=None) for r in rows[:6]]
    cancelled_results = results(cancelled_rows)
    cancelled_results["cancel"] = {"after": 6, "of": 20, "by": st.ANALYSTS[0]}
    cancelled = {
        "id": BACKTEST_CANCELLED,
        "params": {
            "window_days": 30,
            "sample_size": 20,
            "requested_sample_size": 20,
            "min_severity": "high",
        },
        "status": "cancelled",
        "sampled": 6,
        "results": cancelled_results,
        "started_by": st.ANALYSTS[0],
        "created_at": iso(ago(days=4, hours=2)),
        "finished_at": iso(ago(days=4, hours=1, minutes=48)),
    }
    out = [newest, cancelled]
    for bt in recorded:
        delta = ago(days=6, hours=3) - _parse(bt["created_at"])
        moved: dict[str, Any] = shift_tree(bt, delta)
        moved["created_at"] = iso(ago(days=6, hours=3))
        moved["finished_at"] = iso(_parse(bt["finished_at"]) + delta)
        moved["started_by"] = st.ANALYSTS[1]
        out.append(moved)
    return out, replays


# ---------------------------------------------------------------------------
# Escalations, owners, runbooks, chats
# ---------------------------------------------------------------------------

CASE_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, "demo-case:psexec-jump01"))


def escalation_rows(alert_ids: dict[str, str]) -> list[dict[str, Any]]:
    """The PsExec alert and the RC4 alert went to one case. The download's
    escalate got no answer from Security Onion: the Status page lists it."""
    return [
        {
            "id": 1,
            "alert_id": alert_ids[URLHAUS_INV],
            "case_id": None,
            "escalated_by": st.ANALYSTS[0],
            "created_at": iso(ago(hours=28, minutes=40)),
        },
        {
            "id": 2,
            "alert_id": alert_ids[BZAR_INV],
            "case_id": CASE_ID,
            "escalated_by": st.ANALYSTS[1],
            "created_at": iso(ago(hours=13, minutes=2)),
        },
        {
            "id": 3,
            "alert_id": "3N6cTp8BwxVkvmc70vqd",
            "case_id": CASE_ID,
            "escalated_by": st.ANALYSTS[1],
            "created_at": iso(ago(hours=13)),
        },
    ]


def assignment_rows() -> list[dict[str, Any]]:
    return [
        {
            "id": 1,
            "rule_name": "BZAR ATTACK::Execution_Service_Creation",
            "owner": st.ANALYSTS[1],
            "state": "in_review",
            "assigned_at": iso(ago(hours=13, minutes=10)),
        },
        {
            "id": 2,
            "rule_name": "ETPRO TROJAN Win32/Emotet CnC Activity (POST)",
            "owner": st.ANALYSTS[0],
            "state": "done",
            "assigned_at": iso(ago(hours=18)),
        },
        {
            "id": 3,
            "rule_name": "ET MALWARE Quasar RAT CnC Checkin",
            "owner": st.ANALYSTS[0],
            "state": "owned",
            "assigned_at": iso(ago(minutes=40)),
        },
    ]


def runbook_rows() -> list[dict[str, Any]]:
    books = (
        (
            "Lateral movement with PsExec",
            ["lateral-movement", "smb", "windows"],
            ["BZAR ATTACK::Execution_Service_Creation", SMB_RULE],
            False,
            "## When it fires\n\nA host maps ADMIN$ on another host, writes PSEXESVC.exe and "
            "starts it as a service.\n\n## What is normal here\n\nThe IT team runs PsExec from "
            "jump01 inside the change window, Tuesday 18:00 to 20:00 UTC. Every run has a "
            "change ticket.\n\n## Steps\n\n1. Find the account in the Windows logon records of "
            "the target.\n2. Look for the change ticket. No ticket means no approval.\n3. With "
            "no ticket, escalate the alert to a case and isolate the source host.",
        ),
        (
            "Vulnerability scanner noise",
            ["scanner", "false-positive"],
            ["ET WEB_SPECIFIC_APPS Possible SQL Injection UNION SELECT"],
            False,
            "## Scope\n\nscan01 (10.20.0.40) runs the authorized weekly scan on Wednesday from "
            "10:00 UTC.\n\n## Steps\n\n1. Confirm the source is scan01.\n2. Confirm the time "
            "falls in the scan window.\n3. Acknowledge the alert as a false positive. Any other "
            "source is a real probe: investigate it.",
        ),
        (
            "Emotet on a workstation",
            ["malware", "emotet", "workstation"],
            ["ETPRO TROJAN Win32/Emotet CnC Activity (POST)"],
            False,
            "## Steps\n\n1. Isolate the host from the network.\n2. Reset the password of the "
            "user who logs on to it.\n3. Search the mail gateway for the message that carried "
            "the document.\n4. Look for the same C2 address on every other host.",
        ),
        (
            "Data leaving through cloud storage",
            ["exfiltration", "cloud"],
            ["SOC-AI ANALYTIC Long Connection Asymmetric Bytes First-Seen FQDN"],
            False,
            "## What is normal here\n\nbkp01 sends the nightly backup at 01:00 UTC to the "
            "contracted provider only.\n\n## Steps\n\n1. Compare the destination with the "
            "contracted provider.\n2. Compare the start time with the backup schedule.\n3. Find "
            "the account that logged on before the upload.",
        ),
        (
            "Apple Bonjour discovery",
            ["dns", "false-positive", "macos"],
            ["ET MALWARE Potential DNS Command and Control via TXT queries"],
            False,
            "## When it fires\n\nmacOS hosts ask for _dns-sd._udp TXT records to find local "
            "services. The rule matches the query shape.\n\n## Steps\n\n1. Confirm the source "
            "is a Mac.\n2. Confirm the query name ends in _dns-sd._udp.\n3. Acknowledge it as a "
            "false positive.",
        ),
        (
            "IP lookup services",
            ["dns", "draft"],
            ["ET INFO External IP Lookup Domain (ipify .org) in DNS Lookup"],
            True,
            "Draft from history. Eleven verdicts on this rule were false positives. "
            "Applications ask an IP lookup service for the public address of the office. "
            "Approve this draft before the model cites it.",
        ),
    )
    out = []
    for n, (title, tags, rules, draft, content) in enumerate(books, start=1):
        out.append(
            {
                "id": n,
                "title": title,
                "content": content,
                "tags": tags,
                "linked_rules": rules,
                "draft": draft,
                "created_by": "soc-ai" if draft else st.ANALYSTS[n % 2],
                "created_at": iso(ago(days=30 - n)),
                "updated_at": iso(ago(days=10 - n)),
            }
        )
    return out


def chat_entries(recorded_chats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = list(recorded_chats)
    out += [
        {
            "target": "investigation",
            "id": BZAR_INV,
            "messages": [
                {"role": "user", "content": "Did the attacker reach any other server?"},
                {
                    "role": "assistant",
                    "content": (
                        "Recorded demo answer. The recorded run found PSEXESVC.exe on fs01 only. "
                        "jump01 opened SMB to no other server in the window. The same hour, "
                        "jdoe asked dc01 for an RC4 service ticket, so reset that account."
                    ),
                },
            ],
        },
        {
            "target": "investigation",
            "id": FOLLOWUP_INV,
            "messages": [
                {"role": "user", "content": "Which account started the upload?"},
                {
                    "role": "assistant",
                    "content": (
                        f"Recorded demo answer. {st.ADMIN_ACCOUNT} logged on to bkp01 over SSH "
                        "20 minutes before the upload started. The same account ran DCSync "
                        "two days ago."
                    ),
                },
            ],
        },
        {
            "target": "hunt",
            "id": H_JUMP,
            "messages": [
                {"role": "user", "content": "Is this the same attacker as the upload from bkp01?"},
                {
                    "role": "assistant",
                    "content": (
                        "Recorded demo answer. Probably yes. Both chains start from ws-it-02 "
                        f"and both use accounts of the IT team: {st.KERBEROAST_ACCOUNT} here, "
                        f"{st.ADMIN_ACCOUNT} on bkp01. Open the lead on ws-it-02 to see the "
                        "link."
                    ),
                },
            ],
        },
    ]
    return out


def quality_rows(recorded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The nightly quality series, one row a night up to this morning."""
    out = []
    ordered = sorted(recorded, key=lambda r: r["created_at"])
    for n, row in enumerate(ordered):
        days_back = len(ordered) - 1 - n
        moved = dict(row)
        moved["created_at"] = iso(ago(days=days_back, hours=8))
        out.append(moved)
    return out


def autotriage_batch() -> dict[str, Any]:
    return {
        "total": 9,
        "hunted": 7,
        "skipped": 2,
        "failed": 0,
        "finished_at": at_iso(ago(hours=1, minutes=40)),
        "tool_calls": 118,
        "skipped_reasons": {"already_triaged": 1, "inherited": 1},
        "inherited_acked_total": 14,
    }


# ---------------------------------------------------------------------------
# Assembly, gates, output
# ---------------------------------------------------------------------------


def _executed_escalate(inv: dict[str, Any]) -> None:
    """Mark the PsExec run's escalate as executed: it opened the case."""
    events = inv["events"]
    events.insert(
        len(events) - 1,
        {
            "kind": "action_executed",
            "sequence": 0,
            "payload": {
                "index": 0,
                "tool_name": "escalate_to_case",
                "title": "Escalate to case",
                "success": True,
                "by": st.ANALYSTS[1],
                "case_id": CASE_ID,
                "at": at_iso(ago(hours=13, minutes=2)),
            },
        },
    )
    for n, ev in enumerate(events, start=1):
        ev["sequence"] = n


def _analyst_note(inv: dict[str, Any]) -> None:
    """An analyst confirmed the Bonjour verdict by hand, with a note."""
    report = dict(inv["report"])
    report["resolution"] = {
        "original_verdict": inv["verdict"],
        "resolved_via": "manual",
        "resolved_by": st.ANALYSTS[0],
        "resolved_at": at_iso(ago(hours=2, minutes=5)),
    }
    inv["report"] = report
    inv["rationale"] = (
        f"Verdict set by {st.ANALYSTS[0]}: Bonjour discovery from the design Macs. "
        "IT confirmed the new Apple cache server."
    )


def build(recorded_path: Path = RECORDED) -> dict[str, Any]:
    raw = json.loads(recorded_path.read_text())
    if raw.get("version") != 1:
        sys.exit(f"{recorded_path}: expected the version 1 recorded set")
    rec = relabel(raw)

    investigations = [place_investigation(inv) for inv in rec["investigations"]]
    by_id = {inv["id"]: inv for inv in investigations}
    authored = authored_investigations(by_id)
    by_id[NMI_INV]["report"] = {
        **by_id[NMI_INV]["report"],
        "follow_up": {
            "id": FOLLOWUP_INV,
            "requested_by": "r.patel",
            "requested_at": at_iso(ago(hours=9, minutes=41)),
        },
    }
    _executed_escalate(by_id[BZAR_INV])
    _analyst_note(by_id[BONJOUR_INV])
    replays = [place_replay(r) for r in rec["replays"]]
    all_runs = investigations + authored
    alert_ids = {inv["id"]: str(inv["alert_es_id"]) for inv in all_runs if inv.get("alert_es_id")}

    backtests, bt_replays = backtest_rows(rec.get("backtests") or [])
    alerts = alert_documents(all_runs, replays)
    known = {d["_id"] for d in alerts}
    documents = cited_documents(all_runs, known) + windows_documents() + network_documents()
    flows = traffic()

    tables: dict[str, list[dict[str, Any]]] = estate_tables()
    tables["entity_profiles"] = profile_rows(tables, flows["hosts"])
    observations = observation_rows(alert_ids)
    leads = lead_rows(alert_ids[EMOTET_INV])
    tables["leads"] = leads
    tables["entity_observations"] = observations
    tables["grid_gaps"] = gap_rows()
    tables["analytic_state"], tables["analytic_versions"] = analytic_rows()
    tables["hunt_spec_sweeps"] = failed_sweep_rows()
    tables["alert_escalations"] = escalation_rows(alert_ids)
    tables["alert_assignments"] = assignment_rows()
    tables["runbook"] = runbook_rows()

    schedules = schedule_rows()
    hunts = [place_hunt(h) for h in rec.get("hunts") or []]
    hunts += hunt_rows(leads, observations, alert_ids, schedules)

    fixtures: dict[str, Any] = {
        "version": FIXTURES_VERSION,
        "anchor": at_iso(st.ANCHOR),
        "investigations": all_runs + bt_replays,
        "hunts": hunts,
        "backtests": backtests,
        "hunt_schedules": schedules,
        "quality_snapshots": quality_rows(rec.get("quality_snapshots") or []),
        "tables": {name: tables[name] for name in SEEDED_TABLES if name in tables},
        "autotriage": autotriage_batch(),
        "alerts": alerts,
        "documents": documents,
        "traffic": flows,
        "replays": replays,
        "chats": chat_entries(rec.get("chats") or []),
    }
    return fixtures


def gate(fixtures: dict[str, Any], blob: str) -> list[str]:
    """Both leak arms. The story's own synthetic values are allowed by name."""
    from soc_ai.oracle.sanitize import unsafe_residue

    if not leak_patterns():
        return ["cannot parse the leak patterns of scripts/build-public-mirror.sh"]
    problems = [f"mirror pattern {p!r}" for p in scan_for_leaks(blob)]
    parts: list[str] = []
    _raw_strings(fixtures, parts)
    allow = st.story_addresses() | st.story_names()
    problems += [f"residue: {r}" for r in unsafe_residue("\n".join(parts), allowlist=allow)]
    return problems


def render(fixtures: dict[str, Any]) -> str:
    return json.dumps(fixtures, indent=1, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--recorded", type=Path, default=RECORDED)
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="build in memory and exit 1 when the output file differs",
    )
    args = parser.parse_args(argv)
    fixtures = build(args.recorded)
    blob = render(fixtures)
    problems = gate(fixtures, blob)
    if problems:
        for p in problems:
            print(f"LEAK GATE: {p}", file=sys.stderr)
        return 1
    if args.check:
        current = args.out.read_text() if args.out.exists() else ""
        if current != blob:
            print(f"{args.out} is stale. Run scripts/demo/build_story.py.", file=sys.stderr)
            return 1
        print(f"{args.out} is current.")
        return 0
    args.out.write_text(blob, encoding="utf-8")
    counts = {k: len(v) for k, v in fixtures.items() if isinstance(v, list)}
    tables = {k: len(v) for k, v in fixtures["tables"].items()}
    print(f"wrote {args.out} ({len(blob) / 1024:.0f} KB): {counts} tables={tables}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
