"""Golden scenarios — the pinned deterministic backtest set (E1.4).

Each :class:`GoldenScenario` is a realistic ES ``_source`` dict (Suricata /
Zeek shape) + a SCRIPTED model double + the EXPECTED outcome (final verdict,
optional confidence bound, and the deterministic gate events that MUST /
MUST NOT fire). The suite replays each through
:func:`soc_ai.agent.orchestrator.investigate` (mocked ES, no model, no
network) and asserts the outcome — pinning the templates, gates, downgrades,
and funnel routing AROUND the model, not the model's quality.

Scenario coverage (initial rock-solid set):

* ``clean_internal_fp`` — clean-internal decision-template FP (zero-tool).
* ``external_info_fp`` — external-reputation template FP, funnel loop entry.
* ``cobalt_beacon_definitely_investigate`` — malware-class rule → round-1
  skipped → investigation loop → grounded TP.
* ``ungrounded_tp_evidence_gate`` — zero-tool TP on self-citations → the hard
  evidence gate coerces it to needs_more_info.
* ``partial_citation_cap`` — an FP whose partial citation coverage caps
  confidence (citation_cap) without flipping the verdict.
* ``low_conf_needs_more_info`` — a low-confidence, un-cited TP → verdict-floor
  rewrite to needs_more_info.
* ``solicited_icmp_echo_fp`` — a solicited internal ICMP echo TP →
  icmp_solicited_downgrade to FP.
* ``bpfdoor_ungrounded_malware_fp`` — the BPFDoor classic: zero-tool TP on a
  malware-signalling rule with no concrete IOC → malware-rule ungrounded
  downgrade.

TODO (loop-path scenarios deferred as a documented follow-on — the zero-tool
synth-first path is the dominant one and is covered solidly here; the
multi-round Phase-D / tool-loop assertions are fiddlier to pin
deterministically and can grow the set toward 12):

* ``qvod_beacon_loop_tp`` — QVOD/Cobalt beacon that enters the loop, the
  investigator pulls a decisive JA3/SNI pivot, and round-2 synth lands a
  grounded TP that survives every gate (needs a citation that resolves against
  the scripted tool-return payload — depends on the exact ``_resolve_citations``
  token match, which is best pinned in a dedicated follow-up).
* A Phase-D single-dispatch scenario (``targeted_dispatch`` without the full
  loop) asserting the ``retask`` + ``targeted_dispatch`` + round-2 events.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from soc_ai.agent.triage import TriageReport

# ---------------------------------------------------------------------------
# Model script — the per-call scripted model outputs for one scenario.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelScript:
    """Deterministic per-call model outputs for a scenario.

    ``synth_reports`` is the ordered list of :class:`TriageReport` the
    synth-first agent returns per ``.run`` call (round 1, then each Phase-D
    round-2). Most golden scenarios are single-report (zero-tool synth-first).

    The loop fields are consulted ONLY when the scenario enters the
    investigation loop (malware/definitely-investigate or forced):

    * ``investigator_tool_calls`` — the scripted tool call/return pairs the
      loop investigator "makes" (each ``{name, args, result}``; the return part
      is what ``count_successful_tool_calls`` counts).
    * ``investigator_evidence`` / ``investigator_summary`` — the loop
      transcript the investigator settles on.
    * ``loop_synth_report`` — the round-2 :class:`TriageReport` the loop
      synthesizer concludes with.
    """

    synth_reports: list[TriageReport]
    investigator_tool_calls: list[dict[str, Any]] = field(default_factory=list)
    investigator_evidence: list[str] = field(default_factory=list)
    investigator_summary: str = "Investigation transcript."
    loop_synth_report: TriageReport | None = None


@dataclass(frozen=True)
class Expected:
    """The pinned expected outcome of a scenario."""

    verdict: str
    min_confidence: float | None = None
    max_confidence: float | None = None
    gates_fired: list[str] = field(default_factory=list)
    gates_absent: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class GoldenScenario:
    id: str
    alert_source: dict[str, Any]
    model_script: ModelScript
    expected: Expected
    alert_id: str = "golden-alert-001"
    community_id_pivots: list[dict[str, Any]] = field(default_factory=list)
    settings_overrides: dict[str, Any] = field(default_factory=dict)
    note: str = ""


# ---------------------------------------------------------------------------
# ES _source helpers — realistic Suricata / Zeek document shapes.
# ---------------------------------------------------------------------------


def _suricata_source(
    *,
    rule_name: str,
    src_ip: str,
    dest_ip: str,
    classtype: str = "misc-activity",
    action: str = "allowed",
    severity_label: str = "low",
    community_id: str = "1:golden000000000000000000000000=",
    signature_severity: str | None = None,
    payload_printable: str | None = None,
) -> dict[str, Any]:
    """A Suricata-alert ``_source`` dict as SO's ES stores it.

    ``classtype`` / ``action`` / ``payload_printable`` live inside the ``message``
    JSON (``alert.category`` / ``alert.action`` / ``payload_printable``), which is
    exactly where ``SoAlert.from_es_hit`` reads them from.
    """
    message = {
        "alert": {"category": classtype, "action": action, "signature": rule_name},
    }
    if payload_printable is not None:
        message["payload_printable"] = payload_printable
    source: dict[str, Any] = {
        "@timestamp": "2026-07-01T12:00:00.000Z",
        "rule": {"name": rule_name, "uuid": "rule-uuid-golden"},
        "event": {
            "dataset": "suricata.alert",
            "category": "network",
            "severity_label": severity_label,
        },
        "source": {"ip": src_ip, "port": 44100},
        "destination": {"ip": dest_ip, "port": 443},
        "network": {"community_id": community_id},
        "message": json.dumps(message),
    }
    if signature_severity is not None:
        source["rule"]["metadata"] = {"signature_severity": [signature_severity]}
    return source


def _zeek_icmp_conn_pivot(
    *,
    src_ip: str,
    dest_ip: str,
    community_id: str,
    pivot_id: str = "pivot-icmp-1",
) -> dict[str, Any]:
    """A zeek.conn pivot encoding a SOLICITED ICMP echo exchange.

    Zeek stores the ICMP type in the pseudo-ports: ``id.orig_p=8`` (echo
    request) + ``id.resp_p=0`` (echo reply). ``parse_typed_zeek_fields`` reads
    these from the pivot's ``message`` JSON and sets
    ``typed_zeek.icmp_echo_request_reply``.
    """
    message = {
        "proto": "icmp",
        "id.orig_p": 8,
        "id.resp_p": 0,
        "conn_state": "SF",
    }
    return {
        "_id": pivot_id,
        "_source": {
            "@timestamp": "2026-07-01T12:00:01.000Z",
            "event": {"dataset": "zeek.conn"},
            "source": {"ip": src_ip},
            "destination": {"ip": dest_ip},
            "network": {"community_id": community_id},
            "message": json.dumps(message),
        },
    }


# ---------------------------------------------------------------------------
# Scenarios.
# ---------------------------------------------------------------------------

_ICMP_CID = "1:icmpgolden0000000000000000000000="


SCENARIOS: list[GoldenScenario] = [
    # (a) Clean-internal decision-template FP. Both endpoints internal, benign
    #     rule, non-attack classtype → clean_internal_traffic (FP @ 0.85). The
    #     strong benign template exempts the zero-tool FP from the hard evidence
    #     gate. Zero-tool path (investigate_when_unsure off).
    GoldenScenario(
        id="clean_internal_fp",
        alert_source=_suricata_source(
            rule_name="GPL ICMP_INFO PING *NIX",
            src_ip="10.0.0.10",
            dest_ip="10.0.0.20",
            classtype="misc-activity",
        ),
        settings_overrides={"investigate_when_unsure": False},
        model_script=ModelScript(
            synth_reports=[
                TriageReport(
                    verdict="false_positive",
                    confidence=0.85,
                    summary="Routine internal east-west ping; both endpoints internal.",
                    citations=[
                        "alert.source_ip=10.0.0.10 (internal)",
                        "alert.destination_ip=10.0.0.20 (internal)",
                        "no blocklist hits across enriched indicators",
                    ],
                )
            ]
        ),
        expected=Expected(
            verdict="false_positive",
            min_confidence=0.6,
            gates_fired=["decision_template_match"],
            gates_absent=["evidence_gate_downgrade", "synth_round1_skipped"],
        ),
        note="clean_internal_traffic template + FP settle.",
    ),
    # (b) External-reputation template FP. Informational + allowed + external
    #     unknown-ASN dest → informational_external_unknown_asn (FP @ 0.7), which
    #     is an EXTERNAL_REPUTATION_TEMPLATE → _definitely_investigate → the
    #     round-1 synth is skipped and the loop is entered. The loop investigator
    #     pulls a reputation check; round-2 synth settles FP.
    GoldenScenario(
        id="external_info_fp",
        alert_source=_suricata_source(
            rule_name="ET INFO Observed DNS Query to .biz TLD",
            src_ip="10.0.0.11",
            dest_ip="203.0.113.55",
            classtype="misc-activity",
            action="allowed",
            severity_label="low",
            signature_severity="Informational",
        ),
        settings_overrides={"investigate_when_unsure": True},
        model_script=ModelScript(
            synth_reports=[
                TriageReport(
                    verdict="needs_more_info",
                    confidence=0.3,
                    summary="round-1 placeholder (skipped when definitely-investigate).",
                    citations=[],
                )
            ],
            investigator_tool_calls=[
                {
                    "name": "t_enrich_ip",
                    "args": {"ip": "203.0.113.55"},
                    "result": {"blocklist_hits": [], "asn": {"org": "Example ISP"}},
                }
            ],
            investigator_evidence=[
                "t_enrich_ip(203.0.113.55) -> no blocklist hits, ASN Example ISP "
                "(tool t_enrich_ip)",
            ],
            investigator_summary="External dest has no reputation hits.",
            loop_synth_report=TriageReport(
                verdict="false_positive",
                confidence=0.7,
                summary="Informational allowed traffic to external IP with no reputation.",
                citations=["(tool t_enrich_ip)"],
            ),
        ),
        expected=Expected(
            verdict="false_positive",
            gates_fired=[
                "decision_template_match",
                "synth_round1_skipped",
                "investigation_loop_entered",
            ],
        ),
        note="EXTERNAL_REPUTATION_TEMPLATE → definitely-investigate loop entry.",
    ),
    # (c) Malware-class rule (Cobalt Strike Beacon) → _rule_signals_malware →
    #     _definitely_investigate → round-1 skipped → loop. The investigator pulls
    #     a decisive JA3 pivot; round-2 synth lands a TP citing that decisive
    #     value, so the malware-rule ungrounded gate + hard evidence gate both
    #     exempt it (real tool evidence).
    GoldenScenario(
        id="cobalt_beacon_definitely_investigate",
        alert_source=_suricata_source(
            rule_name="ET MALWARE Cobalt Strike Beacon Observed",
            src_ip="10.0.0.42",
            dest_ip="45.61.136.10",
            classtype="trojan-activity",
            action="allowed",
            severity_label="high",
            signature_severity="Major",
            payload_printable="GET /api/v2/beacon",
        ),
        settings_overrides={"investigate_when_unsure": True},
        model_script=ModelScript(
            synth_reports=[
                TriageReport(
                    verdict="needs_more_info",
                    confidence=0.3,
                    summary="round-1 placeholder.",
                    citations=[],
                )
            ],
            investigator_tool_calls=[
                {
                    "name": "t_query_zeek_logs",
                    "args": {"community_id": "1:abc"},
                    "result": {"ssl": {"ja3": "72a589da586844d7f0818ce684948eea"}},
                }
            ],
            investigator_evidence=[
                "t_query_zeek_logs -> ssl.ja3=72a589da586844d7f0818ce684948eea "
                "(known Cobalt Strike client) (tool t_query_zeek_logs)",
            ],
            investigator_summary="Zeek SSL JA3 matches a Cobalt Strike client fingerprint.",
            loop_synth_report=TriageReport(
                verdict="true_positive",
                confidence=0.9,
                summary=(
                    "Confirmed Cobalt Strike beacon: periodic C2 with a known-malicious "
                    "JA3 client fingerprint 72a589da586844d7f0818ce684948eea."
                ),
                citations=[
                    "(tool t_query_zeek_logs)",
                    "ssl.ja3=72a589da586844d7f0818ce684948eea",
                ],
            ),
        ),
        expected=Expected(
            verdict="true_positive",
            min_confidence=0.6,
            gates_fired=[
                "synth_round1_skipped",
                "investigation_loop_entered",
            ],
            gates_absent=[
                "evidence_gate_downgrade",
                "malware_rule_name_ungrounded_downgrade",
            ],
        ),
        note="malware-class → definitely-investigate → grounded loop TP.",
    ),
    # (d) Zero-tool TP resting only on self-referential alert.* citations. No
    #     template, no malware signal, no tool evidence, no IOC, no pivot
    #     grounding → the hard evidence gate coerces TP → needs_more_info.
    GoldenScenario(
        id="ungrounded_tp_evidence_gate",
        alert_source=_suricata_source(
            rule_name="ET SCAN Potential VNC Scan",
            src_ip="10.0.0.30",
            dest_ip="198.51.100.7",
            classtype="attempted-recon",
        ),
        settings_overrides={"investigate_when_unsure": False},
        model_script=ModelScript(
            synth_reports=[
                TriageReport(
                    verdict="true_positive",
                    confidence=0.85,
                    summary="Looks like a VNC scan based on the rule name and ports.",
                    citations=[
                        "alert.rule_name",
                        "alert.destination_port",
                        "alert.classtype",
                    ],
                )
            ]
        ),
        expected=Expected(
            verdict="needs_more_info",
            gates_fired=["evidence_gate_downgrade"],
        ),
        note="hard evidence gate — self-citation-only TP → needs_more_info.",
    ),
    # (e) Citation cap — a template-grounded FP whose model citations only
    #     partially resolve (one real internal-IP token + two hollow/unresolvable
    #     tokens) drops coverage_ratio below 0.75, so _citation_confidence_cap
    #     scales confidence down WITHOUT flipping the verdict (strong template
    #     exempts the evidence gate; confidence stays >= 0.6 so no floor rewrite).
    GoldenScenario(
        id="partial_citation_cap",
        alert_source=_suricata_source(
            rule_name="GPL SNMP public access udp",
            src_ip="10.0.0.15",
            dest_ip="10.0.0.25",
            classtype="misc-activity",
        ),
        settings_overrides={"investigate_when_unsure": False},
        model_script=ModelScript(
            synth_reports=[
                TriageReport(
                    verdict="false_positive",
                    confidence=0.9,
                    summary="Internal SNMP polling between management hosts.",
                    citations=[
                        # Resolves: the internal source IP is a distinctive token
                        # present in the enriched bundle.
                        "alert.source_ip=10.0.0.15",
                        # Hollow — a generic stop-word-only citation.
                        "the alert",
                        # Hollow — an unresolvable fabricated marker.
                        "zzznonexistenttoken",
                    ],
                )
            ]
        ),
        expected=Expected(
            verdict="false_positive",
            max_confidence=0.89,  # capped below the reported 0.9
            min_confidence=0.4,
            gates_fired=["citation_cap"],
            gates_absent=["verdict_floor_rewrite", "evidence_gate_downgrade"],
        ),
        note="partial citation coverage → confidence cap, verdict preserved.",
    ),
    # (f) Verdict-floor rewrite — a low-confidence (< 0.6) un-cited TP with no
    #     evidence → coerced to needs_more_info by the floor rewrite (fires before
    #     the hard evidence gate; the assertion is on the needs_more_info verdict).
    GoldenScenario(
        id="low_conf_needs_more_info",
        alert_source=_suricata_source(
            rule_name="ET INFO Suspicious User-Agent",
            src_ip="10.0.0.33",
            dest_ip="192.0.2.44",
            classtype="misc-activity",
        ),
        settings_overrides={"investigate_when_unsure": False},
        model_script=ModelScript(
            synth_reports=[
                TriageReport(
                    verdict="true_positive",
                    confidence=0.45,
                    summary="Unsure — the user-agent is odd but I have no corroboration.",
                    citations=[],
                )
            ]
        ),
        expected=Expected(
            verdict="needs_more_info",
            gates_fired=["verdict_floor_rewrite"],
        ),
        note="below-floor un-cited verdict → floor rewrite to needs_more_info.",
    ),
    # (g) Solicited internal ICMP echo → the deterministic FP defense. A TP on a
    #     ping between two internal hosts whose zeek.conn pivot encodes an echo
    #     request→reply (id.orig_p=8, id.resp_p=0) is downgraded TP→FP by
    #     _apply_targeted_downgrades (icmp_solicited_downgrade).
    GoldenScenario(
        id="solicited_icmp_echo_fp",
        alert_id="golden-icmp-001",
        alert_source=_suricata_source(
            rule_name="ET INFO Ping Sweep Detected",
            src_ip="10.10.0.5",
            dest_ip="10.10.0.9",
            classtype="misc-activity",
            community_id=_ICMP_CID,
        ),
        community_id_pivots=[
            _zeek_icmp_conn_pivot(
                src_ip="10.10.0.5",
                dest_ip="10.10.0.9",
                community_id=_ICMP_CID,
            )
        ],
        settings_overrides={"investigate_when_unsure": False},
        model_script=ModelScript(
            synth_reports=[
                TriageReport(
                    verdict="true_positive",
                    confidence=0.8,
                    summary="ICMP activity between hosts — possible C2 heartbeat.",
                    citations=["alert.rule_name"],
                )
            ]
        ),
        expected=Expected(
            verdict="false_positive",
            gates_fired=["icmp_solicited_downgrade"],
            gates_absent=["evidence_gate_downgrade"],
        ),
        note="solicited internal ICMP echo → TP auto-corrected to FP.",
    ),
    # (h) BPFDoor classic — a zero-tool TP on a malware-signalling rule name with
    #     no concrete IOC and no cited decisive pivot value. The malware-rule
    #     ungrounded gate coerces TP → needs_more_info (the rule label is not
    #     corroboration). Runs the ZERO-tool path (investigate_when_unsure off)
    #     so the malware signal reaches the gate, not the definitely-investigate
    #     loop.
    GoldenScenario(
        id="bpfdoor_ungrounded_malware_fp",
        alert_source=_suricata_source(
            rule_name="ET MALWARE BPFDoor Backdoor Activity",
            src_ip="10.0.0.60",
            dest_ip="10.0.0.61",
            classtype="misc-activity",
            payload_printable="benign gateway ping",
        ),
        settings_overrides={"investigate_when_unsure": False},
        model_script=ModelScript(
            synth_reports=[
                TriageReport(
                    verdict="true_positive",
                    confidence=0.8,
                    summary="Rule name says BPFDoor, so this is likely a backdoor.",
                    citations=["alert.rule_name", "alert.payload_printable"],
                )
            ]
        ),
        expected=Expected(
            verdict="needs_more_info",
            gates_fired=["malware_rule_name_ungrounded_downgrade"],
        ),
        note="malware rule name alone is not corroboration → downgrade.",
    ),
]
