"""Seed a throwaway soc-ai store with SYNTHETIC, TEST-NET-only demo data.

README
======
Part of the docs-screenshot harness (see run_demo_capture.sh in this folder).
Creates a fresh SQLite store (migrations → admin user → demo rows) that the
locally-served app renders for the published screenshots. All content is
fictional: RFC 5737 TEST-NET IPs, an RFC 2606 example.com org, invented
signature counts. No real alert, IP, hostname or lab identifier is used.

Usage (normally invoked by run_demo_capture.sh):

    .venv/bin/python scripts/demo/seed_demo.py --data-dir /tmp/soc-ai-demo/data

Writes <data-dir>/../manifest.json with the seeded investigation/hunt ids so
the Playwright capture script can deep-link to them. Idempotent by nuking:
delete the data dir to re-seed from scratch.

What it seeds
-------------
* admin user  (demo-only credentials from demo_dataset.py)
* 10 investigations covering every verdict class AND the failure states:
    - true_positive  0.92  Emotet-style beacon → full timeline (prefetch,
      enrichment, decision-template candidate, E4.2 memory recall events,
      5 tool calls with results, reasoning traces, verdict, citation
      validation) + recommended escalate/comment actions + chat. Its
      enriched_alert_context/decision_template_match payloads VALIDATE
      against the current schema so the E5.2 analyst redaction preview
      rebuilds from it (the demo hostnames are seeded as manual internal
      identifiers so redaction fires on them).
    - 2 older completed Emotet runs (prior outcomes for the E4.2 memory
      timeline events; one carries a chat thread dual-written into the
      chat_memory projection).
    - false_positive 0.88  authorized-scanner Nmap hits, auto-acknowledged.
    - needs_more_info 0.55 suspicious .top DNS with open questions.
    - inconclusive   0.52  Zeek ATTACK::Discovery notice (split vote).
    - false_positive 0.83  curl policy noise (older run → inherited badge)
      + a NEWER errored re-run of the same rule (E2.1 failed-retry hint).
    - needs_more_info 0.3  pipeline-failure fallback on the self-signed-TLS
      group (E1.2 "Pipeline error" chip, excluded from the Needs-info KPI).
    - (untriaged)          stream-retransmission run interrupted by a restart.
* 2 completed hunts with the SAME objective (E3.4 "vs last run" diff strip:
  1 new / 3 persisting / 1 resolved finding) + a daily hunt schedule row.
* 3 starter-pack runbooks (via the shipped loader) so /app/runbooks and the
  lookup_runbook tool demo non-empty.
* alert assignments in every state: Emotet owned, dnstop in_review,
  ATTACK::Discovery done (curl stays unassigned).
* manual internal-identifier rows (demo workstation hostnames + org suffix).
* config overrides: memory_enabled=true, analyst_cloud_redaction=true
  (DEMO-database-only — production defaults are untouched).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
from datetime import timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import demo_dataset as dd  # noqa: E402
from soc_ai.config import Settings  # noqa: E402
from soc_ai.enrichment.blocklists import BlocklistHit  # noqa: E402
from soc_ai.so_client.models import RuleMetadata, SoAlert  # noqa: E402
from soc_ai.store import chat as chat_svc  # noqa: E402
from soc_ai.store import runbook_pack  # noqa: E402
from soc_ai.store import runbooks as runbooks_svc  # noqa: E402
from soc_ai.store.auth import create_user, utcnow  # noqa: E402
from soc_ai.store.config_overrides import set_override  # noqa: E402
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations  # noqa: E402
from soc_ai.store.hunts import _objective_hash  # noqa: E402
from soc_ai.store.models import (  # noqa: E402
    AlertAssignment,
    ChatMemory,
    ChatMessage,
    Hunt,
    HuntEvent,
    HuntSchedule,
    InternalIdentifier,
    Investigation,
    InvestigationEvent,
)
from soc_ai.tools.enrichment import IndicatorEnrichment  # noqa: E402
from soc_ai.tools.get_alert_context import EnrichedAlertContext  # noqa: E402
from sqlalchemy import update  # noqa: E402
from ulid import ULID  # noqa: E402


def demo_settings(data_dir: Path) -> Settings:
    """Settings for the throwaway instance — NEVER reads a .env file."""
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        so_host="https://securityonion.demo.example.com",
        so_username="soc-ai@demo.example.com",
        so_password="demo-password-unused",
        es_hosts=["http://127.0.0.1:19200"],
        litellm_base_url="http://127.0.0.1:19200",
        soc_ai_data_dir=data_dir,
    )


def _mins_ago(minutes: float):
    return utcnow() - timedelta(minutes=minutes)


def _ev(inv_id: str, seq: int, kind: str, payload: dict) -> InvestigationEvent:
    return InvestigationEvent(investigation_id=inv_id, sequence=seq, kind=kind, payload=payload)


def _tool_pair(inv_id: str, seq: int, call_id: str, tool: str, args: dict, result) -> list:
    return [
        _ev(inv_id, seq, "tool_call", {"tool_name": tool, "tool_call_id": call_id, "args": args}),
        _ev(inv_id, seq + 1, "tool_result", {"tool_call_id": call_id, "result": result}),
    ]


def _enriched_payload(
    alert: SoAlert,
    *,
    host_alert_profile: dict[str, int] | None = None,
    enrichments: dict[str, IndicatorEnrichment] | None = None,
) -> dict:
    """A VALIDATING ``enriched_alert_context`` event payload.

    Built through the real models — exactly what the orchestrator persists
    (``model_dump(mode="json")`` of :class:`EnrichedAlertContext`) — so the
    E5.2 analyst redaction preview can rebuild the round-1 prompt from it.
    Hand-rolled dicts drift against the schema and land the preview in
    ``context_unparseable``.
    """
    ctx = EnrichedAlertContext(
        alert=alert,
        host_alert_profile=host_alert_profile or {},
        enrichments=enrichments or {},
    )
    return ctx.model_dump(mode="json")


def _internal_ip(ip: str) -> IndicatorEnrichment:
    return IndicatorEnrichment(indicator=ip, indicator_type="ip", internal=True)


# --------------------------------------------------------------------------
# Investigation builders (each returns (Investigation, [events], [chat rows]))
# --------------------------------------------------------------------------


def build_emotet(inv_id: str, prior_ids: tuple[str, str]) -> tuple[Investigation, list, list]:
    g = dd.group_by_rule("ET MALWARE Win32/Emotet CnC Activity (POST)")
    rule, src, dst, host = g["rule"], g["src"], g["dst"], g["host"]
    alert_id = dd.event_id(g, 1)
    created = _mins_ago(9)
    summary = (
        f"{host} ({src}) has been POSTing to {dst}:8080 every ~7 minutes for the "
        "last 6 hours: 48 small, fixed-size sessions (~2.1 KB up / 640 B down) with "
        "no referer and no user browsing pattern. The destination is listed as an "
        "Emotet/Feodo C2 on the local blocklist and no other internal host talks "
        "to it. This is machine-generated command-and-control beaconing, not user "
        "traffic."
    )
    inv = Investigation(
        id=inv_id,
        alert_es_id=alert_id,
        rule_name=rule,
        verdict="true_positive",
        confidence=0.92,
        rationale=(
            f"Destination {dst} is a known Emotet/Feodo C2 and {host} shows 48 "
            "low-volume periodic sessions over 6h — beaconing cadence, not user traffic."
        ),
        summary=summary,
        report={
            "verdict": "true_positive",
            "confidence": 0.92,
            "summary": summary,
            "recommended_actions": [
                {
                    "tool_name": "escalate_to_case",
                    "rationale": (
                        "Confirmed C2 beaconing from a finance workstation — open a "
                        f"case and isolate {host} before lateral movement starts."
                    ),
                },
                {
                    "tool_name": "add_case_comment",
                    "rationale": (
                        "Attach the Zeek conn evidence (48 sessions, ~7-min interval, "
                        "fixed sizes) so the responder sees the beacon profile."
                    ),
                },
            ],
            "open_questions": [],
        },
        src_ip=src,
        dest_ip=dst,
        status="complete",
        started_by="auto-triage:scheduler",
        created_at=created,
        finished_at=created + timedelta(seconds=74),
    )
    alert = SoAlert(
        id=alert_id,
        rule_name=rule,
        # The detection's own fire time — feeds the "alert time" row on the
        # investigation page (a few minutes before triage started).
        timestamp=created - timedelta(minutes=4),
        rule_uuid="2404302",
        classtype="trojan-activity",
        event_category="network",
        source_ip=src,
        source_port=49812,
        destination_ip=dst,
        destination_port=8080,
        alert_action="allowed",
        host_name=host,
        severity_label="critical",
        # signature_severity Critical + a blocklist hit below reproduce the
        # blocklist_hit_major_severity decision template when the analyst
        # redaction preview re-runs the matcher on this stored context.
        rule_metadata=RuleMetadata(signature_severity="Critical", attack_target="Client_Endpoint"),
    )
    host_profile = {
        rule: 12,
        "SURICATA STREAM excessive retransmissions": 5,
        "ET POLICY curl User-Agent Outbound": 2,
    }
    enrichments = {
        dst: IndicatorEnrichment(
            indicator=dst,
            indicator_type="ip",
            internal=False,
            blocklist_hits=[
                BlocklistHit(indicator=dst, indicator_type="ip", source="feodo_c2", tags=("c2",))
            ],
        ),
        dd.DNS_SERVER: _internal_ip(dd.DNS_SERVER),
    }
    events: list = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
        _ev(
            inv_id,
            2,
            "enriched_alert_context",
            _enriched_payload(alert, host_alert_profile=host_profile, enrichments=enrichments),
        ),
        _ev(
            inv_id,
            3,
            "decision_template_match",
            {
                "matched": True,
                "template_id": "blocklist_hit_major_severity",
                "verdict": "true_positive",
                "confidence": 0.7,
                "rationale": (
                    "Blocklist hit + signature_severity=Critical → strong escalation signal."
                ),
            },
        ),
        # E4.2 memory recall — exactly the light payloads the orchestrator
        # emits (ids/verdicts/tier and source/thread/role; never text).
        _ev(
            inv_id,
            4,
            "prior_outcomes",
            {
                "count": 2,
                "window_days": 90,
                "items": [
                    {"id": prior_ids[0], "verdict": "true_positive", "matched_on": "rule+src+dest"},
                    {"id": prior_ids[1], "verdict": "true_positive", "matched_on": "rule+endpoint"},
                ],
            },
        ),
        _ev(
            inv_id,
            5,
            "chat_memory",
            {
                "count": 2,
                "window_days": 90,
                "items": [
                    {"source": "investigation", "thread_id": prior_ids[0], "role": "user"},
                    {"source": "investigation", "thread_id": prior_ids[0], "role": "assistant"},
                ],
            },
        ),
    ]
    events += _tool_pair(
        inv_id,
        6,
        "c1",
        "t_enrich_ip",
        {"ip": dst},
        {
            "indicator": dst,
            "blocklist_hits": [{"source": "feodo_c2", "indicator": dst}],
            "misp_hits": [],
            "internal": False,
            "asn": {"asn_org": "EXAMPLE-HOSTING BV"},
        },
    )
    events.append(
        _ev(
            inv_id,
            8,
            "model_response",
            {
                "reasoning_trace": (
                    f"The destination {dst} is flagged by the Feodo Tracker C2 feed as Emotet "
                    "infrastructure. Before committing to a verdict I need to check whether the "
                    "traffic pattern looks like automated beaconing or a one-off user visit, and "
                    "whether any other internal host talks to this address."
                )
            },
        )
    )
    events += _tool_pair(
        inv_id,
        9,
        "c2",
        "t_query_zeek_logs",
        {"log": "conn", "filter": f"destination.ip:{dst}"},
        {
            "total": 48,
            "summary": (
                f"48 conn records {host} → {dst}:8080 across the last 6h; median "
                "inter-session gap 442s; per-session bytes ~2.1 KB up / 640 B down "
                "(fixed-size, no keep-alive)."
            ),
        },
    )
    events += _tool_pair(
        inv_id,
        11,
        "c3",
        "t_prevalence",
        {"indicator": dst},
        {
            "summary": f"{dst} was contacted by 1 of 214 internal hosts in the last 7 days "
            f"({src} only)."
        },
    )
    events.append(
        _ev(
            inv_id,
            13,
            "model_response",
            {
                "reasoning_trace": (
                    "The cadence (~7 min with small jitter), fixed payload sizes, and single-host "
                    "prevalence rule out CDN or update traffic. A browser-driven false positive "
                    "would show varied sizes, referers, and more than one client."
                )
            },
        )
    )
    events += _tool_pair(
        inv_id,
        14,
        "c4",
        "t_host_summary",
        {"ip": src},
        {
            "ip": src,
            "event_count": 693,
            "observations": True,
        },
    )
    events += _tool_pair(
        inv_id,
        16,
        "c5",
        "t_query_events_oql",
        {"query": f"event.dataset:suricata.alert AND source.ip:{src} | groupby rule.name"},
        {
            "total": 19,
            "summary": "3 distinct signatures on the host in 24h; the Emotet CnC POST "
            "signature dominates (12 of 19).",
        },
    )
    events.append(
        _ev(
            inv_id,
            18,
            "model_response",
            {
                "reasoning_trace": (
                    "All evidence converges: blocklisted destination, beacon-shaped Zeek conn "
                    "profile, unique prevalence, and a corroborating signature cluster on the "
                    "same host. No competing benign explanation survives — this is a true "
                    "positive with high confidence. Recommended action is escalation, not "
                    "auto-ack."
                )
            },
        )
    )
    events += [
        _ev(
            inv_id,
            19,
            "triage_report",
            {
                "verdict": "true_positive",
                "confidence": 0.92,
                "summary": summary,
            },
        ),
        _ev(
            inv_id,
            20,
            "citation_validation",
            {
                "counts": {"valid": 5},
                "total": 5,
                "coverage_ratio": 1.0,
            },
        ),
    ]
    chat = [
        ChatMessage(
            investigation_id=inv_id,
            role="user",
            content="Could this be a false positive from a software updater?",
            status="done",
            created_at=inv.created_at + timedelta(minutes=3),
        ),
        ChatMessage(
            investigation_id=inv_id,
            role="assistant",
            content=(
                "Unlikely. Updaters resolve vendor CDNs and transfer variable-size "
                "payloads; this host POSTs fixed ~2.1 KB bodies to a bare IP on port "
                "8080 every ~7 minutes, and no other host in the estate talks to it. "
                "That profile matches C2 beaconing, and the destination is on the "
                "Feodo Emotet blocklist."
            ),
            status="done",
            meta={"tools": ["t_query_zeek_logs", "t_prevalence"]},
            created_at=inv.created_at + timedelta(minutes=4),
        ),
    ]
    return inv, events, chat


def build_nmap(inv_id: str) -> tuple[Investigation, list, list]:
    g = dd.group_by_rule("ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE)")
    rule, src, dst, host = g["rule"], g["src"], g["dst"], g["host"]
    alert_id = dd.event_id(g, 1)
    created = _mins_ago(23)
    summary = (
        f"All 38 events originate from {src} ({host}), the security team's "
        "authorized vulnerability scanner, during its documented weekly scan window. "
        "The runbook 'Authorized vulnerability scanning' explicitly lists this host. "
        "Benign, expected traffic — acknowledged."
    )
    inv = Investigation(
        id=inv_id,
        alert_es_id=alert_id,
        rule_name=rule,
        verdict="false_positive",
        confidence=0.88,
        rationale=(
            f"Source {src} is the documented authorized scanner ({host}) inside its "
            "weekly scan window — expected traffic per the team's runbook."
        ),
        summary=summary,
        report={
            "verdict": "false_positive",
            "confidence": 0.88,
            "summary": summary,
            "recommended_actions": [
                {
                    "tool_name": "ack_alert",
                    "rationale": "Authorized scanner traffic matching the documented "
                    "weekly window — acknowledge the group.",
                },
            ],
            "open_questions": [],
        },
        src_ip=src,
        dest_ip=dst,
        status="complete",
        started_by="auto-triage:scheduler",
        created_at=created,
        finished_at=created + timedelta(seconds=41),
    )
    alert = SoAlert(
        id=alert_id,
        rule_name=rule,
        # The detection's own fire time — feeds the "alert time" row on the
        # investigation page (a few minutes before triage started).
        timestamp=created - timedelta(minutes=4),
        rule_uuid="2024364",
        classtype="attempted-recon",
        event_category="network",
        source_ip=src,
        source_port=51820,
        destination_ip=dst,
        destination_port=443,
        alert_action="allowed",
        host_name=host,
        severity_label="medium",
    )
    events: list = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
        _ev(
            inv_id,
            2,
            "enriched_alert_context",
            _enriched_payload(
                alert,
                host_alert_profile={rule: 38},
                enrichments={src: _internal_ip(src)},
            ),
        ),
        _ev(inv_id, 3, "decision_template_match", {"matched": False}),
    ]
    events += _tool_pair(
        inv_id,
        4,
        "c1",
        "t_lookup_runbook",
        {"query": "authorized vulnerability scanning"},
        {
            "summary": (
                "Runbook 'Authorized vulnerability scanning — sec-scan hosts' matches: "
                f"{src} is the team's Nessus/Nmap scanner; expected window Mon "
                "02:00-04:00 UTC across all subnets."
            ),
        },
    )
    events += _tool_pair(
        inv_id,
        6,
        "c2",
        "t_prevalence",
        {"indicator": src},
        {
            "summary": f"{src} triggers this signature against 37 internal hosts on a "
            "weekly cadence; first seen 90 days ago.",
        },
    )
    events.append(
        _ev(
            inv_id,
            8,
            "model_response",
            {
                "reasoning_trace": (
                    "The source is a documented internal scanner and the burst falls inside its "
                    "scheduled window; the fan-out pattern (37 destinations, one source) is the "
                    "opposite of the single-target pattern real NSE abuse would show from a "
                    "compromised host."
                )
            },
        )
    )
    events += [
        _ev(
            inv_id,
            9,
            "triage_report",
            {
                "verdict": "false_positive",
                "confidence": 0.88,
                "summary": summary,
            },
        ),
        _ev(
            inv_id,
            10,
            "citation_validation",
            {
                "counts": {"valid": 3},
                "total": 3,
                "coverage_ratio": 1.0,
            },
        ),
        _ev(inv_id, 11, "auto_ack", {"success": True, "alert_id": alert_id}),
    ]
    return inv, events, []


def build_dnstop(inv_id: str) -> tuple[Investigation, list, list]:
    g = dd.group_by_rule("ET DNS Query to a *.top domain - Likely Hostile")
    rule, src, dst, host = g["rule"], g["src"], g["dst"], g["host"]
    created = _mins_ago(72)
    summary = (
        f"{host} resolved update-cdn-sync[.]top four times in 30 minutes. The domain "
        "is 11 days old and absent from local blocklists; no follow-on connection to "
        "the resolved address was observed in Zeek conn within the window. Not enough "
        "evidence to commit either way — needs proxy-log corroboration."
    )
    inv = Investigation(
        id=inv_id,
        alert_es_id=dd.event_id(g, 1),
        rule_name=rule,
        verdict="needs_more_info",
        confidence=0.55,
        rationale=(
            "Newly-registered .top domain resolved but never contacted — suspicious "
            "age and TLD, yet no observed payload traffic to judge."
        ),
        summary=summary,
        report={
            "verdict": "needs_more_info",
            "confidence": 0.55,
            "summary": summary,
            "recommended_actions": [],
            "open_questions": [
                "Does any proxy or TLS log show an actual connection to "
                "update-cdn-sync[.]top or its resolved IP?",
                f"Did {src} resolve other newly-registered domains in the same window?",
            ],
        },
        src_ip=src,
        dest_ip=dst,
        status="complete",
        started_by="admin",
        created_at=created,
        finished_at=created + timedelta(seconds=58),
    )
    alert = SoAlert(
        id=dd.event_id(g, 1),
        rule_name=rule,
        # The detection's own fire time — feeds the "alert time" row on the
        # investigation page (a few minutes before triage started).
        timestamp=created - timedelta(minutes=4),
        rule_uuid="2028712",
        classtype="bad-unknown",
        event_category="network",
        source_ip=src,
        source_port=58231,
        destination_ip=dst,
        destination_port=53,
        alert_action="allowed",
        host_name=host,
        severity_label="medium",
    )
    events: list = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
        _ev(
            inv_id,
            2,
            "enriched_alert_context",
            _enriched_payload(
                alert,
                host_alert_profile={rule: 4},
                enrichments={dst: _internal_ip(dst)},
            ),
        ),
        _ev(inv_id, 3, "decision_template_match", {"matched": False}),
    ]
    events += _tool_pair(
        inv_id,
        4,
        "c1",
        "t_enrich_domain",
        {"domain": "update-cdn-sync.top"},
        {
            "indicator": "update-cdn-sync.top",
            "blocklist_hits": [],
            "misp_hits": [],
            "internal": False,
            "hint": "domain registered 11 days ago (newly registered)",
        },
    )
    events += _tool_pair(
        inv_id,
        6,
        "c2",
        "t_query_zeek_logs",
        {"log": "conn", "filter": f"source.ip:{src}"},
        {
            "total": 0,
            "summary": "No conn records to the resolved address in the alert window.",
        },
    )
    events.append(
        _ev(
            inv_id,
            8,
            "model_response",
            {
                "reasoning_trace": (
                    "A young .top domain is a weak signal on its own. With zero observed "
                    "follow-on traffic I cannot distinguish sandboxed prefetch/typo from staged "
                    "C2. The honest verdict is needs_more_info with targeted questions."
                )
            },
        )
    )
    events += [
        _ev(
            inv_id,
            9,
            "triage_report",
            {
                "verdict": "needs_more_info",
                "confidence": 0.55,
                "summary": summary,
            },
        ),
        _ev(
            inv_id,
            10,
            "citation_validation",
            {
                "counts": {"valid": 2},
                "total": 2,
                "coverage_ratio": 1.0,
            },
        ),
    ]
    return inv, events, []


def build_attack_discovery(inv_id: str) -> tuple[Investigation, list, list]:
    g = dd.group_by_rule("ATTACK::Discovery")
    rule, src, dst, host = g["rule"], g["src"], g["dst"], g["host"]
    created = _mins_ago(127)
    summary = (
        f"Zeek flagged {host} enumerating SMB shares on {dst}. The burst (3 notices "
        "in 2 minutes) matches both a helpdesk inventory script and hands-on "
        "discovery; the self-consistency vote split 2/2 across samples, so the run "
        "lands inconclusive rather than forcing a verdict."
    )
    inv = Investigation(
        id=inv_id,
        alert_es_id=dd.event_id(g, 1),
        rule_name=rule,
        verdict="inconclusive",
        confidence=0.52,
        rationale=(
            "Discovery-style SMB enumeration explained equally well by the helpdesk "
            "inventory script and by hands-on recon — the verdict vote split."
        ),
        summary=summary,
        report={
            "verdict": "inconclusive",
            "confidence": 0.52,
            "summary": summary,
            "recommended_actions": [],
            "open_questions": [
                f"Was the helpdesk inventory task scheduled on {host} at that time?",
            ],
        },
        src_ip=src,
        dest_ip=dst,
        status="complete",
        started_by="admin",
        created_at=created,
        finished_at=created + timedelta(seconds=66),
    )
    alert = SoAlert(
        id=dd.event_id(g, 1),
        rule_name=rule,
        # The detection's own fire time — feeds the "alert time" row on the
        # investigation page (a few minutes before triage started).
        timestamp=created - timedelta(minutes=4),
        event_category="intrusion_detection",
        source_ip=src,
        source_port=49733,
        destination_ip=dst,
        destination_port=445,
        event_action="notice",
        host_name=host,
        severity_label="medium",
    )
    events: list = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
        _ev(
            inv_id,
            2,
            "enriched_alert_context",
            _enriched_payload(
                alert,
                host_alert_profile={rule: 3},
                enrichments={dst: _internal_ip(dst)},
            ),
        ),
        _ev(inv_id, 3, "decision_template_match", {"matched": False}),
    ]
    events += _tool_pair(
        inv_id,
        4,
        "c1",
        "t_query_events_oql",
        {"query": f"event.dataset:zeek.smb_files AND source.ip:{src}"},
        {
            "total": 41,
            "summary": "41 smb_files reads across 7 shares in 2 minutes — enumeration-"
            "shaped, then silence.",
        },
    )
    events.append(
        _ev(
            inv_id,
            6,
            "model_response",
            {
                "reasoning_trace": (
                    "Enumeration is real but attribution is not: the same access shape is "
                    "produced nightly by the asset-inventory job. Without process telemetry "
                    "both hypotheses stand — sampled verdicts split, so report inconclusive."
                )
            },
        )
    )
    events += [
        _ev(
            inv_id,
            7,
            "triage_report",
            {
                "verdict": "inconclusive",
                "confidence": 0.52,
                "summary": summary,
            },
        ),
    ]
    return inv, events, []


def build_curl(inv_id: str) -> tuple[Investigation, list, list]:
    g = dd.group_by_rule("ET POLICY curl User-Agent Outbound")
    rule, src, dst, host = g["rule"], g["src"], g["dst"], g["host"]
    created = utcnow() - timedelta(hours=26)
    summary = (
        f"Nightly artifact-mirror sync on {host} fetches release archives with curl; "
        "destination is the team's pinned mirror. Routine engineering traffic."
    )
    inv = Investigation(
        id=inv_id,
        # An OLDER event than the group's current latest → the alerts grid shows
        # this verdict as inherited ("same detection, investigated earlier").
        alert_es_id=dd.event_id(g, 4),
        rule_name=rule,
        verdict="false_positive",
        confidence=0.83,
        rationale=(
            "curl user-agent belongs to the documented nightly mirror-sync job on "
            f"{host}; destination and cadence match the runbook."
        ),
        summary=summary,
        report={
            "verdict": "false_positive",
            "confidence": 0.83,
            "summary": summary,
            "recommended_actions": [
                {
                    "tool_name": "ack_alert",
                    "rationale": "Documented nightly sync job — acknowledge.",
                },
            ],
            "open_questions": [],
        },
        src_ip=src,
        dest_ip=dst,
        status="complete",
        started_by="auto-triage:scheduler",
        created_at=created,
        finished_at=created + timedelta(seconds=37),
    )
    alert = SoAlert(
        id=dd.event_id(g, 4),
        rule_name=rule,
        # The detection's own fire time — feeds the "alert time" row on the
        # investigation page (a few minutes before triage started).
        timestamp=created - timedelta(minutes=4),
        rule_uuid="2013028",
        classtype="policy-violation",
        event_category="network",
        source_ip=src,
        source_port=44102,
        destination_ip=dst,
        destination_port=443,
        alert_action="allowed",
        host_name=host,
        severity_label="low",
    )
    events: list = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
        _ev(
            inv_id,
            2,
            "enriched_alert_context",
            _enriched_payload(
                alert,
                host_alert_profile={rule: 9},
                enrichments={dst: IndicatorEnrichment(indicator=dst, indicator_type="ip")},
            ),
        ),
        _ev(inv_id, 3, "decision_template_match", {"matched": False}),
    ]
    events += _tool_pair(
        inv_id,
        4,
        "c1",
        "t_lookup_runbook",
        {"query": "mirror sync curl"},
        {
            "summary": "Runbook 'Nightly artifact mirror sync' documents curl fetches "
            f"from {host} at 01:30 UTC to the pinned mirror.",
        },
    )
    events += [
        _ev(
            inv_id,
            6,
            "triage_report",
            {
                "verdict": "false_positive",
                "confidence": 0.83,
                "summary": summary,
            },
        ),
        _ev(
            inv_id,
            7,
            "citation_validation",
            {
                "counts": {"valid": 2},
                "total": 2,
                "coverage_ratio": 1.0,
            },
        ),
    ]
    return inv, events, []


def build_emotet_prior(
    inv_id: str, *, days_ago: int, src: str, alert_n: int, confidence: float, summary: str
) -> tuple[Investigation, list, list]:
    """An OLDER completed run on the Emotet rule — E4.2 prior-outcome material.

    Two of these share the rule (one also the exact src→dst flow) with the
    current Emotet run, so its timeline's ``prior_outcomes`` event references
    real rows and the memory feature demos honestly.
    """
    g = dd.group_by_rule("ET MALWARE Win32/Emotet CnC Activity (POST)")
    rule, dst = g["rule"], g["dst"]
    created = utcnow() - timedelta(days=days_ago, minutes=17)
    inv = Investigation(
        id=inv_id,
        alert_es_id=dd.event_id(g, alert_n),
        rule_name=rule,
        verdict="true_positive",
        confidence=confidence,
        rationale=summary,
        summary=summary,
        report={
            "verdict": "true_positive",
            "confidence": confidence,
            "summary": summary,
            "recommended_actions": [],
            "open_questions": [],
        },
        src_ip=src,
        dest_ip=dst,
        status="complete",
        started_by="auto-triage:scheduler",
        created_at=created,
        finished_at=created + timedelta(seconds=68),
    )
    events = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
        _ev(
            inv_id,
            2,
            "triage_report",
            {"verdict": "true_positive", "confidence": confidence, "summary": summary},
        ),
    ]
    return inv, events, []


def build_curl_retry(inv_id: str) -> tuple[Investigation, list, list]:
    """A NEWER errored re-run stacked on the curl group's standing FP verdict.

    Drives the E2.1 rerun-visibility hint on the alerts row: the standing
    verdict chip stays primary while "last retry error <ago> ago" + the Retry
    affordance surface that the most recent attempt crashed.
    """
    g = dd.group_by_rule("ET POLICY curl User-Agent Outbound")
    created = _mins_ago(19)
    inv = Investigation(
        id=inv_id,
        alert_es_id=dd.event_id(g, 1),
        rule_name=g["rule"],
        verdict=None,
        confidence=None,
        src_ip=g["src"],
        dest_ip=g["dst"],
        status="error",
        started_by="admin",
        created_at=created,
        finished_at=created + timedelta(seconds=11),
    )
    events = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
        _ev(
            inv_id,
            2,
            "error",
            {"message": "model gateway returned 502 during round-1 synthesis; run aborted"},
        ),
    ]
    return inv, events, []


def build_fallback(inv_id: str) -> tuple[Investigation, list, list]:
    """A pipeline-failure fallback verdict (E1.2) on the self-signed-TLS group.

    ``report.resolution.provenance == "pipeline_fallback"`` — the exact marker
    ``_synth_failure_fallback_report`` persists — so the alerts row renders the
    distinct "Pipeline error" chip, the drawer shows the failure panel, and the
    Dashboard excludes this needs_more_info from the Needs-info KPI.
    """
    g = dd.group_by_rule("ET INFO Observed Self-Signed TLS Certificate (External)")
    rule, src, dst, host = g["rule"], g["src"], g["dst"], g["host"]
    created = _mins_ago(31)
    summary = (
        "Synth-first pipeline fallback: synth_first_round1 raised "
        "UnexpectedModelBehavior. The alert is recorded as needs_more_info "
        "pending investigator-path retry. Underlying error: model output "
        "failed schema validation after 2 retries."
    )
    inv = Investigation(
        id=inv_id,
        alert_es_id=dd.event_id(g, 1),
        rule_name=rule,
        verdict="needs_more_info",
        confidence=0.3,
        rationale=summary,
        summary=summary,
        report={
            "verdict": "needs_more_info",
            "confidence": 0.3,
            "summary": summary,
            "citations": ["synth_first_failure"],
            "recommended_actions": [],
            "open_questions": [],
            "resolution": {
                "provenance": "pipeline_fallback",
                "phase": "synth_first_round1",
                "error_type": "UnexpectedModelBehavior",
                "hint": "Re-run this detection once the model gateway is healthy.",
            },
        },
        src_ip=src,
        dest_ip=dst,
        status="complete",
        started_by="auto-triage:scheduler",
        created_at=created,
        finished_at=created + timedelta(seconds=24),
    )
    alert = SoAlert(
        id=dd.event_id(g, 1),
        rule_name=rule,
        timestamp=created - timedelta(minutes=2),
        rule_uuid="2230002",
        classtype="misc-activity",
        event_category="network",
        source_ip=src,
        source_port=52114,
        destination_ip=dst,
        destination_port=8443,
        alert_action="allowed",
        host_name=host,
        severity_label="medium",
    )
    events = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
        _ev(
            inv_id,
            2,
            "enriched_alert_context",
            _enriched_payload(
                alert,
                host_alert_profile={rule: 6},
                enrichments={dst: IndicatorEnrichment(indicator=dst, indicator_type="ip")},
            ),
        ),
        _ev(inv_id, 3, "decision_template_match", {"matched": False}),
        _ev(
            inv_id,
            4,
            "error",
            {
                "message": (
                    "synth_first_round1: UnexpectedModelBehavior — model output "
                    "failed schema validation after 2 retries"
                )
            },
        ),
        _ev(
            inv_id,
            5,
            "triage_report",
            {"verdict": "needs_more_info", "confidence": 0.3, "summary": summary},
        ),
    ]
    return inv, events, []


def build_interrupted(inv_id: str) -> tuple[Investigation, list, list]:
    g = dd.group_by_rule("SURICATA STREAM excessive retransmissions")
    created = utcnow() - timedelta(hours=3, minutes=12)
    inv = Investigation(
        id=inv_id,
        alert_es_id=dd.event_id(g, 1),
        rule_name=g["rule"],
        verdict=None,
        confidence=None,
        src_ip=g["src"],
        dest_ip=g["dst"],
        status="interrupted",
        started_by="auto-triage:scheduler",
        created_at=created,
        finished_at=created + timedelta(seconds=12),
    )
    events = [
        _ev(inv_id, 1, "session_start", {"pipeline": "agentic"}),
    ]
    return inv, events, []


# Shared objective for BOTH hunt runs — identical text ⇒ identical
# objective_hash ⇒ the newer run's page renders the E3.4 "vs last run" strip.
HUNT_OBJECTIVE = (
    "Sweep the last 24h for lateral movement from fin-ws-041 "
    "(SMB admin shares, new service installs, Kerberos anomalies)."
)


def build_hunt_prev(hunt_id: str) -> tuple[Hunt, list]:
    """The OLDER completed run of the same objective (E3.4 hunt-diff baseline).

    Its findings overlap the newer run's: three persist (same fuzzy identity —
    normalized title + hosts set), one resolves (present here, absent in the
    newer run), and the newer run adds one ("Only new external peer…"), so the
    diff strip shows 1 new · 3 persisting · 1 resolved.
    """
    src = "198.51.100.23"
    created = utcnow() - timedelta(hours=26, minutes=40)
    narrative = (
        "First 24h sweep for lateral movement from fin-ws-041. No admin-share "
        "writes and the Kerberos burst matches the fleet-wide inventory pass, "
        "but an unexplained SMB write burst to the finance file server needs "
        "a follow-up look, and the finance VLAN still has no RDP telemetry."
    )
    report = {
        "findings": [
            {
                "title": "No SMB admin-share access from fin-ws-041",
                "detail": (
                    f"zeek.smb_files shows zero ADMIN$/C$ or IPC$ writes from {src} "
                    "in the window."
                ),
                "severity": "info",
                "category": "observation",
                "hosts": [src],
                "citations": ["zeek.smb_files 24h sweep: 0 admin-share hits"],
            },
            {
                "title": "Kerberos TGS burst matches fleet-wide inventory pass",
                "detail": (
                    "A burst of 14 TGS requests at 09:12 UTC matches the same-minute "
                    "burst on 6 other finance workstations — the logon-script "
                    "inventory job."
                ),
                "severity": "low",
                "category": "observation",
                "hosts": [src, dd.DNS_SERVER],
                "citations": ["demo-krb-3382"],
            },
            {
                # RESOLVED in the newer run: absent from build_hunt's findings.
                "title": "Unexplained SMB write burst to the finance file server",
                "detail": (
                    f"{src} wrote 31 files to fs-fin-02's department share in 4 "
                    "minutes — above its baseline. Could be a user bulk-save; "
                    "re-check on the next sweep."
                ),
                "severity": "low",
                "category": "observation",
                "hosts": [src],
                "citations": ["zeek.smb_files write burst 09:41 UTC"],
            },
            {
                "title": "Visibility gap: no RDP telemetry on the finance segment",
                "detail": (
                    "The grid inventory has no zeek.rdp data for the finance VLAN, "
                    "so RDP lateral movement can be neither confirmed nor ruled out."
                ),
                "severity": "medium",
                "category": "visibility_gap",
                "hosts": [src],
                "citations": ["grid inventory: zeek.rdp absent"],
            },
        ],
        "narrative": narrative,
        "confidence": 0.78,
        "affected_hosts": [src],
        "mitre_techniques": ["T1021.002", "T1558.003"],
        "recommended_actions": [
            {
                "title": "Re-run this sweep tomorrow",
                "rationale": "Confirm the SMB write burst was a one-off before closing it.",
            },
        ],
    }
    hunt = Hunt(
        id=hunt_id,
        objective=HUNT_OBJECTIVE,
        objective_hash=_objective_hash(HUNT_OBJECTIVE),
        kind="chat",
        status="complete",
        narrative=narrative,
        report=report,
        started_by="admin",
        created_at=created,
        finished_at=created + timedelta(minutes=2, seconds=2),
    )
    events = [
        HuntEvent(hunt_id=hunt_id, sequence=1, kind="hunt_started", payload={"objective": HUNT_OBJECTIVE}),
        HuntEvent(
            hunt_id=hunt_id,
            sequence=2,
            kind="hunt_report",
            payload={"findings": report["findings"], "narrative": narrative},
        ),
    ]
    return hunt, events


def build_hunt(hunt_id: str) -> tuple[Hunt, list]:
    src = "198.51.100.23"
    created = _mins_ago(43)
    narrative = (
        "Swept 24h of Zeek SMB, Kerberos and conn data for lateral movement from "
        "fin-ws-041 following the confirmed Emotet beacon. No admin-share writes, "
        "no new service installs, and the only anomalous Kerberos burst matches the "
        "logon-script inventory pass seen fleet-wide. The host's sole new external "
        "peer remains the already-escalated C2. No evidence of spread yet — contain "
        "the host while that is still true."
    )
    report = {
        "findings": [
            {
                "title": "No SMB admin-share access from fin-ws-041",
                "detail": (
                    "zeek.smb_files shows zero ADMIN$/C$ or IPC$ writes from "
                    f"{src} in the window; its only SMB peers are the two file "
                    "servers it has always used."
                ),
                "severity": "info",
                "category": "observation",
                "hosts": [src],
                "citations": ["zeek.smb_files 24h sweep: 0 admin-share hits"],
            },
            {
                "title": "Kerberos TGS burst matches fleet-wide inventory pass",
                "detail": (
                    "A burst of 14 TGS requests to distinct SPNs at 09:12 UTC is "
                    "above this host's baseline (2-3/hr) but occurred in the same "
                    "minute on 6 other finance workstations — consistent with the "
                    "logon-script inventory job, not targeted Kerberoasting."
                ),
                "severity": "low",
                "category": "observation",
                "hosts": [src, dd.DNS_SERVER],
                "citations": ["demo-krb-3382", "demo-krb-3391"],
            },
            {
                "title": "Only new external peer is the known C2",
                "detail": (
                    f"The single new outbound destination for {src} in 24h is "
                    f"{dd.C2_IP} (already escalated). No secondary egress, no DNS "
                    "tunneling indicators, no beaconing from any other host."
                ),
                "severity": "info",
                "category": "observation",
                "hosts": [src],
                "citations": ["conn destination fan-out: 3 total, 1 external"],
            },
            {
                "title": "Visibility gap: no RDP telemetry on the finance segment",
                "detail": (
                    "The grid inventory has no zeek.rdp data for the finance VLAN, "
                    "so lateral movement over RDP from this host can be neither "
                    "confirmed nor ruled out. SMB/Kerberos coverage above is "
                    "unaffected."
                ),
                "severity": "medium",
                "category": "visibility_gap",
                "hosts": [src],
                "citations": ["grid inventory: zeek.rdp absent"],
            },
        ],
        "narrative": narrative,
        "confidence": 0.82,
        "affected_hosts": [src],
        "mitre_techniques": ["T1021.002", "T1558.003", "T1071.001"],
        "recommended_actions": [
            {
                "title": "Isolate fin-ws-041 pending reimage",
                "rationale": "C2 beaconing is confirmed and no spread is observed "
                "yet — contain before that changes.",
            },
            {
                "title": "Re-run this sweep after containment",
                "rationale": "Confirm no delayed persistence or secondary staging "
                "appears once the C2 channel is cut.",
            },
        ],
    }
    hunt = Hunt(
        id=hunt_id,
        objective=HUNT_OBJECTIVE,
        objective_hash=_objective_hash(HUNT_OBJECTIVE),
        kind="chat",
        status="complete",
        narrative=narrative,
        report=report,
        started_by="admin",
        created_at=created,
        finished_at=created + timedelta(minutes=2, seconds=14),
    )

    def hev(seq: int, kind: str, payload: dict) -> HuntEvent:
        return HuntEvent(hunt_id=hunt_id, sequence=seq, kind=kind, payload=payload)

    events = [
        hev(1, "hunt_started", {"objective": hunt.objective}),
        hev(
            2,
            "tool_call",
            {
                "tool_name": "t_describe_dataset",
                "tool_call_id": "h1",
                "args": {"dataset": "zeek.smb_files"},
            },
        ),
        hev(
            3,
            "tool_result",
            {
                "tool_call_id": "h1",
                "result": {
                    "summary": "zeek.smb_files: ~1.2k docs/24h; path, action, source.ip and "
                    "destination.ip consistently populated."
                },
            },
        ),
        hev(
            4,
            "tool_call",
            {
                "tool_name": "t_query_events_oql",
                "tool_call_id": "h2",
                "args": {
                    "query": f"event.dataset:zeek.smb_files AND source.ip:{src} AND smb.path:*$*"
                },
            },
        ),
        hev(
            5,
            "tool_result",
            {
                "tool_call_id": "h2",
                "result": {
                    "total": 0,
                    "summary": "No admin-share (ADMIN$/C$/IPC$) access from the "
                    "host in the window.",
                },
            },
        ),
        hev(
            6,
            "tool_call",
            {
                "tool_name": "t_query_events_oql",
                "tool_call_id": "h3",
                "args": {
                    "query": f"event.dataset:zeek.kerberos AND "
                    f"source.ip:{src} | groupby request_type"
                },
            },
        ),
        hev(
            7,
            "tool_result",
            {
                "tool_call_id": "h3",
                "result": {
                    "total": 14,
                    "summary": "14 TGS requests at 09:12 UTC; identical burst on "
                    "6 other finance workstations the same minute.",
                },
            },
        ),
        hev(
            8,
            "tool_call",
            {
                "tool_name": "t_field_values",
                "tool_call_id": "h4",
                "args": {"field": "destination.ip", "filter": f"source.ip:{src}"},
            },
        ),
        hev(
            9,
            "tool_result",
            {
                "tool_call_id": "h4",
                "result": {
                    "summary": f"3 distinct destinations in 24h; 1 external ({dd.C2_IP}, the "
                    "known C2), 2 internal file servers."
                },
            },
        ),
        hev(10, "hunt_report", {"findings": report["findings"], "narrative": narrative}),
        # A short follow-up thread so the hunts list shows the chat badge and
        # the hunt chat panel opens with history (mirrors the investigation demo).
        hev(
            11,
            "chat_user",
            {"content": "Why is the Kerberos burst not Kerberoasting?", "status": "done"},
        ),
        hev(
            12,
            "chat_assistant",
            {
                "content": (
                    "Kerberoasting targets service accounts from ONE host hunting "
                    "crackable SPN tickets; this burst hit the same 14 SPNs in the "
                    "same minute on 6 other finance workstations — a scheduled "
                    "inventory pass, not a targeted harvest. fin-ws-041's ticket "
                    "mix also matches its weekday baseline."
                ),
                "status": "done",
            },
        ),
    ]
    return hunt, events


async def seed(data_dir: Path) -> dict:
    # Nuke-to-reseed (ignore_errors: a missing dir is the normal first run).
    shutil.rmtree(data_dir, ignore_errors=True)
    settings = demo_settings(data_dir)
    engine = make_engine(settings)
    await run_migrations(engine)
    sm = make_sessionmaker(engine)

    ids = {
        name: str(ULID())
        for name in (
            "emotet",
            "prior1",
            "prior2",
            "nmap",
            "dnstop",
            "attack",
            "curl",
            "curl_retry",
            "fallback",
            "interrupted",
            "hunt",
            "hunt_prev",
        )
    }

    prior1 = build_emotet_prior(
        ids["prior1"],
        days_ago=8,
        src="198.51.100.23",  # same src→dst flow as the current run → tier "rule+src+dest"
        alert_n=6,
        confidence=0.9,
        summary=(
            "fin-ws-041 beaconed to the same Feodo-listed C2 on a ~7-minute "
            "cadence; escalated and the host was reimaged."
        ),
    )
    prior2 = build_emotet_prior(
        ids["prior2"],
        days_ago=3,
        src="198.51.100.62",  # same rule + destination only → tier "rule+endpoint"
        alert_n=5,
        confidence=0.88,
        summary=(
            "eng-ws-233 contacted the known Emotet C2 once after a phishing "
            "attachment; blocked at egress and credentials rotated."
        ),
    )
    builders = [
        build_emotet(ids["emotet"], (ids["prior1"], ids["prior2"])),
        prior1,
        prior2,
        build_nmap(ids["nmap"]),
        build_dnstop(ids["dnstop"]),
        build_attack_discovery(ids["attack"]),
        build_curl(ids["curl"]),
        build_curl_retry(ids["curl_retry"]),
        build_fallback(ids["fallback"]),
        build_interrupted(ids["interrupted"]),
    ]
    hunt, hunt_events = build_hunt(ids["hunt"])
    hunt_prev, hunt_prev_events = build_hunt_prev(ids["hunt_prev"])

    async with sm() as db:
        admin = await create_user(db, dd.DEMO_ADMIN_USER, dd.DEMO_ADMIN_PASSWORD, role="admin")
        # Parents first: no ORM relationships are declared, so SQLAlchemy can't
        # order the flush itself — child rows (events/chat) go in a second flush.
        for inv, _events, _chat in builders:
            db.add(inv)
        db.add(hunt)
        db.add(hunt_prev)
        await db.flush()
        for _inv, events, chat in builders:
            for e in events:
                db.add(e)
            for m in chat:
                db.add(m)
        for e in hunt_events + hunt_prev_events:
            db.add(e)
        # E2.3 assignment states — one group per chip (curl stays unassigned).
        db.add(
            AlertAssignment(
                rule_name="ET MALWARE Win32/Emotet CnC Activity (POST)",
                owner="admin",
                state="owned",
            )
        )
        db.add(
            AlertAssignment(
                rule_name="ET DNS Query to a *.top domain - Likely Hostile",
                owner="admin",
                state="in_review",
            )
        )
        db.add(AlertAssignment(rule_name="ATTACK::Discovery", owner="admin", state="done"))
        # Manual internal identifiers: the demo workstation names are what the
        # E5.2 analyst redaction preview must redact (TEST-NET IPs are already
        # is_private to the sanitizer); also demos the identifiers panel.
        for host in ("fin-ws-041", "eng-ws-112", "hr-ws-023", "it-ws-007", "sec-scan-01", "mkt-ws-019", "eng-ws-233"):
            db.add(InternalIdentifier(kind="host", value=host, source="manual", state="active"))
        db.add(
            InternalIdentifier(
                kind="suffix", value=".demo.example.com", source="manual", state="active"
            )
        )
        # Scheduled re-run of the lateral-movement sweep (display-only row on
        # the Hunts page; the newer hunt above reads as its last firing).
        db.add(
            HuntSchedule(
                objective=HUNT_OBJECTIVE,
                interval_minutes=1440,
                enabled=True,
                last_run_at=hunt.created_at,
                created_by="admin",
            )
        )
        await db.commit()

    # DEMO-database-only config: memory timeline events + redaction preview
    # render with their features "on" (production defaults are untouched —
    # these are override rows in the throwaway store, applied at app startup).
    async with sm() as db:
        await set_override(db, "memory_enabled", True, updated_by=admin.id)
        await set_override(db, "analyst_cloud_redaction", True, updated_by=admin.id)

    # Chat thread on the older prior via the REAL store fns, so the messages
    # dual-write into the chat_memory projection (E4.2 chat-transcript memory).
    async with sm() as db:
        await chat_svc.add_user_message(
            db,
            ids["prior1"],
            "We saw this exact beacon from fin-ws-041 before — did the isolation stick?",
        )
        pending = await chat_svc.create_pending_assistant(db, ids["prior1"])
        await chat_svc.finish_assistant(
            db,
            pending.id,
            content=(
                "The host was isolated and reimaged after this verdict. If the "
                "same beacon recurs from fin-ws-041, treat it as a failed "
                "remediation and re-escalate immediately rather than re-triaging "
                "from scratch."
            ),
            meta={"tools": []},
        )
        # The store fns stamp "now" — backdate the thread (and its projection
        # rows) into the prior's own era so the demo timestamps read honestly.
        thread_ts = prior1[0].created_at + timedelta(hours=2)
        await db.execute(
            update(ChatMessage)
            .where(ChatMessage.investigation_id == ids["prior1"])
            .values(created_at=thread_ts)
        )
        await db.execute(
            update(ChatMemory)
            .where(ChatMemory.thread_id == ids["prior1"])
            .values(created_at=thread_ts)
        )
        await db.commit()

    # 3 starter-pack runbooks through the shipped loader — /app/runbooks and
    # the lookup_runbook tool demo non-empty, with story-relevant picks.
    wanted_titles = {
        "Beaconing / C2 callback triage",
        "Authorized scanner false positives",
        "Lateral movement triage (SMB / PsExec / RDP)",
    }
    picked = [p for p in runbook_pack.load_starter_pack() if p.title in wanted_titles]
    async with sm() as db:
        for p in picked:
            await runbooks_svc.create(
                db,
                title=p.title,
                content=p.content,
                tags=p.tags,
                linked_rules=p.linked_rules,
                created_by="admin",
            )

    await engine.dispose()

    manifest = {
        "inv_emotet": ids["emotet"],
        "inv_nmap": ids["nmap"],
        "inv_dnstop": ids["dnstop"],
        "inv_fallback": ids["fallback"],
        "inv_prior_chat": ids["prior1"],
        "hunt": ids["hunt"],
        "hunt_prev": ids["hunt_prev"],
        "admin_user": dd.DEMO_ADMIN_USER,
        "admin_password": dd.DEMO_ADMIN_PASSWORD,
    }
    manifest_path = data_dir.parent / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", default="/tmp/soc-ai-demo/data", type=Path)
    args = ap.parse_args()
    manifest = asyncio.run(seed(args.data_dir))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
