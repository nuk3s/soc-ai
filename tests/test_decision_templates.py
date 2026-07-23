"""Tests for soc_ai.agent.decision_templates."""

from __future__ import annotations

from typing import Any

from soc_ai.agent.decision_templates import match_decision_template
from soc_ai.enrichment.blocklists import BlocklistHit
from soc_ai.enrichment.maxmind import AsnInfo
from soc_ai.enrichment.zeek_parser import TypedZeekFields
from soc_ai.so_client.models import RuleMetadata, SoAlert
from soc_ai.tools.enrichment import IndicatorEnrichment
from soc_ai.tools.get_alert_context import EnrichedAlertContext


def _ctx(alert: SoAlert, **kwargs: Any) -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=alert,
        community_id_events=kwargs.get("community_id_events", []),
        host_events=kwargs.get("host_events", []),
        user_events=kwargs.get("user_events", []),
        process_events=kwargs.get("process_events", []),
        file_events=kwargs.get("file_events", []),
        pivot_summary=kwargs.get("pivot_summary", {}),
        host_alert_profile=kwargs.get("host_alert_profile", {}),
        prefetch_gaps={},
        typed_zeek=kwargs.get("typed_zeek", TypedZeekFields()),
        enrichments=kwargs.get("enrichments", {}),
    )


def test_clean_internal_traffic_template_fires() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO Internal Doh",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        alert_action="allowed",
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(indicator="10.0.0.2", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.verdict == "false_positive"
    assert cv.template_id == "clean_internal_traffic"
    assert cv.confidence >= 0.8


def test_clean_internal_traffic_skips_attack_classtype() -> None:
    """Internal↔internal with an attack-class signature must NOT get the 0.85
    benign anchor — lateral movement (the BPFDoor failure mode generalized).

    No other template should catch attempted-admin between internal hosts, so
    the synth gets no candidate and reasons from the evidence."""
    alert = SoAlert(
        id="a1",
        rule_name="ET EXPLOIT Internal SMB attempted-admin",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="attempted-admin",
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(indicator="10.0.0.2", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is None


def test_blocklist_hit_major_severity_template_fires_true_positive() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET CNC Trojan",
        severity_label="high",
        source_ip="10.0.0.1",
        destination_ip="198.51.100.5",
        rule_metadata=RuleMetadata(signature_severity="Major"),
        classtype="trojan-activity",
    )
    enrich = {
        "198.51.100.5": IndicatorEnrichment(
            indicator="198.51.100.5",
            indicator_type="ip",
            blocklist_hits=[
                BlocklistHit(
                    indicator="198.51.100.5",
                    indicator_type="ip",
                    source="abuse.ch URLhaus",
                    tags=("emotet",),
                )
            ],
        )
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.verdict == "true_positive"
    assert cv.template_id == "blocklist_hit_major_severity"


def test_blocklist_hit_low_severity_forces_synth_to_reason() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO test",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="198.51.100.5",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        "198.51.100.5": IndicatorEnrichment(
            indicator="198.51.100.5",
            indicator_type="ip",
            blocklist_hits=[
                BlocklistHit(
                    indicator="198.51.100.5",
                    indicator_type="ip",
                    source="abuse.ch URLhaus",
                    tags=("emotet",),
                )
            ],
        )
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.template_id == "blocklist_hit_low_severity"
    assert cv.verdict == "needs_more_info"


def test_stun_quic_keepalive_template_fires() -> None:
    # destination must be genuinely public so clean_internal_traffic doesn't fire first.
    # 93.184.216.34 is example.com (IANA-managed, is_private=False in Python 3.12).
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO STUN Binding Request",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="93.184.216.34",
    )
    typed = TypedZeekFields(conn_states=["SF"])
    cv = match_decision_template(_ctx(alert, typed_zeek=typed))
    assert cv is not None
    assert cv.template_id == "stun_quic_keepalive"
    assert cv.verdict == "false_positive"


def test_dns_dnssec_housekeeping_template_fires() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO Outbound RRSIG DNS Query",
        severity_label="low",
    )
    cv = match_decision_template(_ctx(alert))
    assert cv is not None
    assert cv.template_id == "dns_dnssec_housekeeping"


def test_ntp_protocol_housekeeping_template_fires() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO External NTP Server In Use",
        severity_label="low",
    )
    typed = TypedZeekFields(conn_states=["SF"])
    cv = match_decision_template(_ctx(alert, typed_zeek=typed))
    assert cv is not None
    assert cv.template_id == "ntp_protocol_housekeeping"


def test_informational_external_clean_benign_cloud_template_fires() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO test",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="162.159.207.0",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        "162.159.207.0": IndicatorEnrichment(
            indicator="162.159.207.0",
            indicator_type="ip",
            asn=AsnInfo(number=13335, org="Cloudflare, Inc."),
            cloud_provider="Cloudflare",
        ),
    }
    typed = TypedZeekFields(conn_states=["SF"])
    cv = match_decision_template(_ctx(alert, enrichments=enrich, typed_zeek=typed))
    assert cv is not None
    assert cv.template_id == "informational_external_clean_benign_cloud"
    assert cv.verdict == "false_positive"


def test_benign_cloud_matches_uppercase_geolite2_asn_org() -> None:
    """Stock GeoLite2 ASN orgs are uppercase; the benign-cloud match must be
    case-insensitive (regression: the title-case substring list was dead code,
    so Google/Akamai/Fastly-by-ASN traffic fell to the unknown-ASN template)."""
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO test",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="142.250.1.1",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        # Uppercase org, NO cloud_provider tag → only the ASN path can match it.
        "142.250.1.1": IndicatorEnrichment(
            indicator="142.250.1.1",
            indicator_type="ip",
            asn=AsnInfo(number=15169, org="GOOGLE"),
        ),
    }
    typed = TypedZeekFields(conn_states=["SF"])
    cv = match_decision_template(_ctx(alert, enrichments=enrich, typed_zeek=typed))
    assert cv is not None
    assert cv.template_id == "informational_external_clean_benign_cloud"
    assert cv.verdict == "false_positive"


def test_informational_external_unknown_asn_template_fires() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO test",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="198.51.100.50",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        "198.51.100.50": IndicatorEnrichment(
            indicator="198.51.100.50",
            indicator_type="ip",
            asn=AsnInfo(number=99999, org="SomeIspCorp"),
        ),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.template_id == "informational_external_unknown_asn"


def test_policy_violation_internal_template_fires() -> None:
    # A blocklist hit with "Medium" severity dodges both blocklist templates
    # (major needs Major/Critical, low needs Informational) while also blocking
    # clean_internal_traffic (which requires no blocklist hits).
    alert = SoAlert(
        id="a1",
        rule_name="POLICY x",
        severity_label="medium",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="policy-violation",
        rule_metadata=RuleMetadata(signature_severity="Medium"),
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(
            indicator="10.0.0.2",
            indicator_type="ip",
            internal=True,
            blocklist_hits=[
                BlocklistHit(
                    indicator="10.0.0.2",
                    indicator_type="ip",
                    source="operator_internal_seed",
                    tags=("flagged",),
                )
            ],
        ),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.template_id == "policy_violation_internal"


def test_tor_exit_internal_initiator_template_fires() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO test",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="198.51.100.99",
        rule_metadata=None,  # NOT Informational → blocklist_hit_low_severity won't fire
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "198.51.100.99": IndicatorEnrichment(
            indicator="198.51.100.99",
            indicator_type="ip",
            blocklist_hits=[
                BlocklistHit(
                    indicator="198.51.100.99",
                    indicator_type="ip",
                    source="Tor Project exit list",
                    tags=("tor_exit",),
                )
            ],
        ),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.template_id == "tor_exit_internal_initiator"


def test_command_and_control_classtype_template_fires() -> None:
    alert = SoAlert(
        id="a1",
        rule_name="ET CNC Trojan",
        severity_label="high",
        source_ip="10.0.0.1",
        destination_ip="198.51.100.5",
        classtype="command-and-control",
    )
    cv = match_decision_template(_ctx(alert))
    assert cv is not None
    assert cv.template_id == "command_and_control_classtype"
    assert cv.verdict == "true_positive"


def test_no_template_matches_returns_none() -> None:
    """An alert that matches no template — synth must reason from scratch.

    Use a genuinely public source IP (93.184.216.34 / example.com, is_private=False
    in Python 3.12) so that clean_internal_traffic cannot fire (it requires both
    endpoints to be internal).  classtype=web-application-attack is not in the C2
    set, no blocklist hits, sev=Major (not Informational), so every template skips.
    """
    alert = SoAlert(
        id="a1",
        rule_name="ET WEB_SERVER Suspicious POST",
        severity_label="medium",
        source_ip="93.184.216.34",
        destination_ip="10.0.0.50",
        rule_metadata=RuleMetadata(signature_severity="Major"),
        classtype="web-application-attack",
    )
    cv = match_decision_template(_ctx(alert))
    assert cv is None


# ---------------------------------------------------------------------------
# B1: malware/exploit-signal guard (BPFDoor false-escalation finding)
# ---------------------------------------------------------------------------


def test_clean_internal_blocked_by_malware_rule_name() -> None:
    """Internal<->internal, no blocklist hits, classtype=misc-activity, but rule
    name contains 'MALWARE' → clean_internal_traffic must return None.
    This is the exact BPFDoor defect pattern."""
    alert = SoAlert(
        id="a1",
        rule_name="ET MALWARE BPFDoor Covert Channel ICMP",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="misc-activity",
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(indicator="10.0.0.2", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is None


def test_clean_internal_blocked_by_malware_family_metadata() -> None:
    """Rule name is benign-looking but metadata_tags carries 'malware' tag → None.
    No malware_family field exists on the model (rule-name check only per plan);
    this test verifies metadata_tags in RuleMetadata is consulted instead."""
    alert = SoAlert(
        id="a1",
        rule_name="ET POLICY Suspicious ICMP",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="misc-activity",
        rule_metadata=RuleMetadata(metadata_tags=["malware", "backdoor"]),
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(indicator="10.0.0.2", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is None


def test_stun_template_blocked_by_malware_signal() -> None:
    """STUN rule name but also contains 'malware' token → stun_quic_keepalive returns None."""
    alert = SoAlert(
        id="a1",
        rule_name="ET MALWARE STUN Used by Backdoor",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="93.184.216.34",
    )
    typed = TypedZeekFields(conn_states=["SF"])
    cv = match_decision_template(_ctx(alert, typed_zeek=typed))
    assert cv is None


def test_ntp_template_blocked_by_malware_signal() -> None:
    """NTP rule name but also contains 'trojan' token → ntp_protocol_housekeeping returns None."""
    alert = SoAlert(
        id="a1",
        rule_name="ET TROJAN NTP C2 Heartbeat",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="93.184.216.34",
    )
    typed = TypedZeekFields(conn_states=["SF"])
    cv = match_decision_template(_ctx(alert, typed_zeek=typed))
    assert cv is None


def test_clean_internal_still_fires_on_truly_benign() -> None:
    """'ET INFO Session Traversal Utility...' — 'rat' must NOT match 'Traversal'
    because the word-boundary regex requires a full word match.
    The template should still fire for this genuinely benign rule name."""
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO Session Traversal Utility for NAT (STUN Binding Request)",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="misc-activity",
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(indicator="10.0.0.2", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.template_id == "clean_internal_traffic"


# ---------------------------------------------------------------------------
# B1 (extended): malware-signal guard on remaining benign-anchor templates
# ---------------------------------------------------------------------------


def test_dns_dnssec_template_blocked_by_malware_signal() -> None:
    """DNSSEC rule name but also contains 'malware' token →
    t_dns_dnssec_housekeeping must return None."""
    alert = SoAlert(
        id="a1",
        rule_name="ET MALWARE RRSIG Abuse by Botnet DNS Tunneling",
        severity_label="low",
    )
    cv = match_decision_template(_ctx(alert))
    assert cv is None


def test_dns_dnssec_template_still_fires_on_benign_name() -> None:
    """Plain RRSIG housekeeping rule with no malware signal → fires normally."""
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO Outbound RRSIG DNS Query",
        severity_label="low",
    )
    cv = match_decision_template(_ctx(alert))
    assert cv is not None
    assert cv.template_id == "dns_dnssec_housekeeping"
    assert cv.verdict == "false_positive"


def test_informational_external_clean_benign_cloud_blocked_by_malware_signal() -> None:
    """Informational/allowed/benign-cloud-ASN alert but rule name signals malware →
    t_informational_external_clean_benign_cloud must return None."""
    alert = SoAlert(
        id="a1",
        rule_name="ET MALWARE Backdoor Beacon via Cloudflare Tunnel",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="162.159.207.0",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        "162.159.207.0": IndicatorEnrichment(
            indicator="162.159.207.0",
            indicator_type="ip",
            asn=AsnInfo(number=13335, org="Cloudflare, Inc."),
            cloud_provider="Cloudflare",
        ),
    }
    typed = TypedZeekFields(conn_states=["SF"])
    cv = match_decision_template(_ctx(alert, enrichments=enrich, typed_zeek=typed))
    assert cv is None


def test_informational_external_unknown_asn_blocked_by_malware_signal() -> None:
    """Informational/allowed/unknown-ASN alert but rule name signals malware →
    t_informational_external_unknown_asn must return None."""
    alert = SoAlert(
        id="a1",
        rule_name="ET MALWARE Trojan Dropper Outbound",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="198.51.100.50",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        "198.51.100.50": IndicatorEnrichment(
            indicator="198.51.100.50",
            indicator_type="ip",
            asn=AsnInfo(number=99999, org="SomeIspCorp"),
        ),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is None


def test_policy_violation_internal_blocked_by_malware_signal() -> None:
    """Policy-violation between internal endpoints but rule name signals malware →
    t_policy_violation_internal must return None."""
    alert = SoAlert(
        id="a1",
        rule_name="ET MALWARE Policy Violation Ransomware Staging",
        severity_label="medium",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="policy-violation",
        rule_metadata=RuleMetadata(signature_severity="Medium"),
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(
            indicator="10.0.0.2",
            indicator_type="ip",
            internal=True,
            blocklist_hits=[
                BlocklistHit(
                    indicator="10.0.0.2",
                    indicator_type="ip",
                    source="operator_internal_seed",
                    tags=("flagged",),
                )
            ],
        ),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is None


# ---------------------------------------------------------------------------
# B1 (worm word-boundary): "Bookworm"-style compounds must NOT trigger guard
# ---------------------------------------------------------------------------


def test_bookworm_compound_does_not_trigger_malware_guard() -> None:
    """'Bookworm' contains 'worm' as a compound suffix, NOT a standalone token.
    After moving 'worm' to the word-boundary regex, this rule name must NOT
    trigger the malware guard and clean_internal_traffic should still fire."""
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO Bookworm Reader Update Check",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="misc-activity",
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(indicator="10.0.0.2", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.template_id == "clean_internal_traffic"


def test_standalone_worm_token_triggers_malware_guard() -> None:
    """A rule name containing the standalone word 'worm' (not a compound suffix)
    must still trigger the malware guard and suppress a benign template anchor."""
    alert = SoAlert(
        id="a1",
        rule_name="ET MALWARE Worm Propagation Detected",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="misc-activity",
    )
    enrich = {
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
        "10.0.0.2": IndicatorEnrichment(indicator="10.0.0.2", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is None


# ---------------------------------------------------------------------------
# Broadened threat-signal tokens + host-context guard
# ---------------------------------------------------------------------------

_INTERNAL_PAIR = {
    "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
    "10.0.0.2": IndicatorEnrichment(indicator="10.0.0.2", indicator_type="ip", internal=True),
}


def test_attack_response_powershell_dns_skips_clean_internal() -> None:
    """#5: ET ATTACK_RESPONSE PowerShell-in-DNS-TXT was matching
    clean_internal_traffic (the resolver hop is internal→internal) and getting a
    0.85 benign anchor. The broadened token list now signals it as a threat, so
    NO benign template fires and the synth must reason from the encoded payload."""
    alert = SoAlert(
        id="a1",
        rule_name=(
            "ET ATTACK_RESPONSE PowerShell String Base64 Encoded Text.Encoding "
            "(ZXh0LkVuY29k) in DNS TXT Reponse"
        ),
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="bad-unknown",
    )
    assert match_decision_template(_ctx(alert, enrichments=_INTERNAL_PAIR)) is None


def test_remote_access_rat_skips_clean_internal() -> None:
    """#2: ET REMOTE_ACCESS NetSupport (RAT) check-in over an internal leg must
    not get a benign locality anchor — REMOTE_ACCESS is now a threat token."""
    alert = SoAlert(
        id="a1",
        rule_name="ET REMOTE_ACCESS NetSupport Remote Admin Checkin",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="misc-activity",
    )
    assert match_decision_template(_ctx(alert, enrichments=_INTERNAL_PAIR)) is None


def test_host_has_concurrent_threat_detects_pivot_malware() -> None:
    """#2: a benign-looking focus alert (internal SMB Ioctl, INFO) whose HOST is
    concurrently firing a RAT check-in is post-exploitation. The host-context
    helper must see the threat in the pivot even though the focus rule is clean."""
    from soc_ai.agent.decision_templates import _host_has_concurrent_threat

    focus = SoAlert(
        id="focus",
        rule_name="ET INFO SMBv2 Protocol Ioctl Operation Observed",
        severity_label="low",
        source_ip="10.2.28.88",
        destination_ip="10.2.28.2",
        classtype="misc-activity",
    )
    c2_pivot = SoAlert(
        id="c2",
        rule_name="ET REMOTE_ACCESS NetSupport Remote Admin Checkin",
        severity_label="low",
        source_ip="10.2.28.88",
        destination_ip="203.0.113.9",
    )
    # Host pivot carries the concurrent C2 alert → threat detected.
    assert _host_has_concurrent_threat(_ctx(focus, host_events=[c2_pivot])) is True
    # No concurrent threat in the pivots → clean.
    assert _host_has_concurrent_threat(_ctx(focus)) is False


def test_host_has_concurrent_threat_via_wide_profile() -> None:
    """#2 (real path): the tight ±5-min pivots are empty (the C2 fired ~12h away,
    keyed on fields the pivot never queries), but the WIDE host_alert_profile
    aggregation surfaces the RAT signature on the endpoint IP — the primary
    host-risk signal must fire on the profile alone."""
    from soc_ai.agent.decision_templates import _host_has_concurrent_threat

    focus = SoAlert(
        id="focus",
        rule_name="ET INFO SMBv2 Protocol Ioctl Operation Observed",
        severity_label="low",
        source_ip="10.2.28.88",
        destination_ip="10.2.28.2",
        classtype="misc-activity",
    )
    # Empty pivots, but the host's recent histogram shows a RAT + C2.
    profile = {
        "ET REMOTE_ACCESS NetSupport Remote Admin Checkin": 60,
        "ET INFO HTTP POST on unusual Port Possibly Hostile": 46,
        "ET INFO SMBv2 Protocol Tree Connect Observed": 7,
    }
    assert _host_has_concurrent_threat(_ctx(focus, host_alert_profile=profile)) is True
    # A profile of purely benign INFO rules → no threat.
    benign = {"ET INFO SMBv2 Protocol Tree Connect Observed": 7, "ET INFO DNS Query": 3}
    assert _host_has_concurrent_threat(_ctx(focus, host_alert_profile=benign)) is False


def test_worm_guard_unchanged() -> None:
    """Regression anchor: the original standalone-'worm' guard still fires."""
    alert = SoAlert(
        id="a1",
        rule_name="ET MALWARE Worm Propagation Detected",
        severity_label="low",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        classtype="misc-activity",
    )
    cv = match_decision_template(_ctx(alert, enrichments=_INTERNAL_PAIR))
    assert cv is None


def test_informational_benign_cloud_fires_on_reversed_flow_cert_observation() -> None:
    """Server-side observations (TLS cert / JA3S / banner) tag the alert with the
    RESPONSE packet's direction: external SOURCE (the server) -> internal
    DESTINATION (the client). The benign-informational templates must judge the
    external endpoint whichever leg it is, or this whole high-volume ET INFO
    class falls through to a full investigation loop.

    Regression: the templates were hardcoded to destination_ip, so an
    external-source cert observation matched nothing (candidate=None -> loop).
    """
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO Observed Let's Encrypt Certificate from Active Intermediate, E1",
        severity_label="low",
        source_ip="162.159.207.0",  # external server presenting the cert
        destination_ip="10.0.0.1",  # internal client
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        "162.159.207.0": IndicatorEnrichment(
            indicator="162.159.207.0",
            indicator_type="ip",
            asn=AsnInfo(number=13335, org="Cloudflare, Inc."),
            cloud_provider="Cloudflare",
            internal=False,
        ),
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
    }
    typed = TypedZeekFields(conn_states=["SF"])
    cv = match_decision_template(_ctx(alert, enrichments=enrich, typed_zeek=typed))
    assert cv is not None
    assert cv.template_id == "informational_external_clean_benign_cloud"
    assert cv.verdict == "false_positive"


def test_informational_unknown_asn_fires_on_reversed_flow() -> None:
    """Same reversed-flow shape but the external source has no benign-cloud tag
    (ASN unresolved) -> the unknown-ASN template still clears it FP so the loop
    is skipped."""
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO Observed TLS Handshake to External Host",
        severity_label="low",
        source_ip="203.0.113.10",  # external, no benign-cloud tag
        destination_ip="10.0.0.1",  # internal
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        "203.0.113.10": IndicatorEnrichment(
            indicator="203.0.113.10", indicator_type="ip", internal=False
        ),
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    assert cv is not None
    assert cv.template_id == "informational_external_unknown_asn"
    assert cv.verdict == "false_positive"


def test_reversed_flow_blocklist_hit_on_external_source_not_cleared() -> None:
    """The reversed-flow path still honours the guards: a blocklist hit on the
    external source blocks the benign templates (no auto-clear of a flagged
    external server that happens to be on the source leg)."""
    alert = SoAlert(
        id="a1",
        rule_name="ET INFO Observed TLS Handshake to External Host",
        severity_label="low",
        source_ip="203.0.113.66",  # external, flagged
        destination_ip="10.0.0.1",  # internal
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        alert_action="allowed",
    )
    enrich = {
        "203.0.113.66": IndicatorEnrichment(
            indicator="203.0.113.66",
            indicator_type="ip",
            internal=False,
            blocklist_hits=[
                BlocklistHit(
                    indicator="203.0.113.66",
                    indicator_type="ip",
                    source="abuse.ch",
                    tags=("c2",),
                )
            ],
        ),
        "10.0.0.1": IndicatorEnrichment(indicator="10.0.0.1", indicator_type="ip", internal=True),
    }
    cv = match_decision_template(_ctx(alert, enrichments=enrich))
    # A flagged external source must NOT be benign-cleared by the reversed-flow
    # change (it routes to needs_more_info / investigation, never false_positive).
    assert cv is None or cv.verdict != "false_positive"
