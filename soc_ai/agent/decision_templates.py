"""Decision templates — Phase B of the synth-first redesign.

Each template is a callable `(EnrichedAlertContext) -> CandidateVerdict | None`.
On match, the orchestrator passes the candidate to the synth as a default
that the synth can keep, override, or refine. On no-match, the synth gets
no candidate and reasons from the enriched context alone.

Templates are tried in registration order (first-match-wins). The order
encodes priority: more-specific / higher-stakes templates come first so
they can short-circuit a less-specific clean-traffic match.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, Literal, Protocol

from soc_ai.tools.get_alert_context import EnrichedAlertContext

Verdict = Literal["true_positive", "false_positive", "needs_more_info"]


@dataclass(frozen=True)
class CandidateVerdict:
    verdict: Verdict
    confidence: float
    cited_evidence: list[str]
    template_id: str
    rationale: str


class DecisionTemplate(Protocol):
    id: str
    description: str

    def __call__(self, ctx: EnrichedAlertContext) -> CandidateVerdict | None: ...


_BENIGN_CLOUD_ASN_ORGS = (
    "Cloudflare",
    "Google",
    "Akamai",
    "Amazon",
    "Microsoft",
    "Fastly",
    "Apple",
)

# Suricata classtypes that signal active exploitation / attack. East-west
# traffic carrying one of these is NOT routine even when both endpoints are
# internal and no indicator is on a blocklist — internal IPs never appear on
# blocklists, so `_any_blocklist_hit` is vacuous here and the clean-internal
# anchor would mask lateral movement (the BPFDoor failure mode
# generalized). These fall through to the synth with no benign default.
_ATTACK_CLASSTYPES = frozenset(
    {
        "attempted-admin",
        "successful-admin",
        "attempted-user",
        "successful-user",
        "shellcode-detect",
        "web-application-attack",
        "exploit-kit",
        "attempted-dos",
        "denial-of-service",
        "trojan-activity",
        "command-and-control",
        "exfiltration",
    }
)


# Tokens whose presence in a rule name signals malware/exploit activity.
# Compound phrases ("command and control") are matched as substrings.
# Short ambiguous tokens ("c2", "cnc", "rat") use word-boundary regex to avoid
# false positives: "Traversal" must NOT match "rat", "concatenate" must NOT
# match "cnc", etc.
_MALWARE_SIGNAL_TOKENS = (
    "malware",
    "trojan",
    "backdoor",
    "botnet",
    "ransom",
    "exploit",
    "command and control",
    "cobalt",
    "beacon",
    "stealer",
    "rootkit",
    "cve-",
    # Post-exploitation / attack-response evidence + tradecraft. An ET
    # ATTACK_RESPONSE / REMOTE_ACCESS (RAT) / PowerShell / named-tool signature
    # is a real threat signal regardless of internal/external locality, so it
    # must never get a benign template anchor — it gets investigated instead
    # (PowerShell-in-DNS-TXT and NetSupport lateral movement were being
    # cleared by clean_internal_traffic). REMOTE_ACCESS also covers legitimate
    # tools (TeamViewer etc.) — routing those into the loop is correct: the agent
    # decides benign-IT vs malicious-RAT from context rather than auto-clearing.
    "attack_response",
    "remote_access",
    "remote admin",
    "powershell",
    "mimikatz",
    "meterpreter",
    "metasploit",
    "empire",
    "webshell",
    "kerberoast",
    "psexec",
    "exfil",
    "downloader",
    "dropper",
    "coinminer",
    "phishing",
)
# Short tokens / compound-suffix tokens that require whole-word matching to avoid
# false positives: "Traversal" must NOT match "rat", "concatenate" must NOT match
# "cnc", "Bookworm" must NOT match "worm", etc.
_MALWARE_SIGNAL_WORD_BOUNDARY_RE = re.compile(r"\b(?:c2|cnc|rat|worm)\b", re.IGNORECASE)


def _rule_signals_attack(ctx: EnrichedAlertContext) -> bool:
    """Return True when the alert's classtype is in ``_ATTACK_CLASSTYPES``.

    Attack-class rules (kerberoast, psexec lateral movement, data exfil,
    DNS tunnel, etc.) don't necessarily carry malware tokens in their rule
    names, so ``_rule_signals_malware`` misses them. This helper covers the
    exploit/attack-signal half of the approved escalation policy: any alert
    whose Suricata classtype falls in ``_ATTACK_CLASSTYPES`` should escalate
    to the Oracle unless it is already a high-confidence true-positive.
    """
    return (ctx.alert.classtype or "").lower() in _ATTACK_CLASSTYPES


def _name_signals_malware(name: str | None) -> bool:
    """Return True when a bare rule-name string signals malware/exploit/attack.

    The lowest-level token check, usable on a plain ``str`` — so it can score the
    host-risk profile (``{rule_name: count}``) where only names are available, not
    full SoAlert objects.
    """
    n = (name or "").lower()
    # Substring check for unambiguous multi-char tokens.
    if any(tok in n for tok in _MALWARE_SIGNAL_TOKENS):
        return True
    # Word-boundary check for short tokens that could be substrings of benign words.
    return bool(_MALWARE_SIGNAL_WORD_BOUNDARY_RE.search(n))


def _alert_signals_malware(alert: Any) -> bool:
    """Return True when a single alert's rule name / metadata signals malware.

    Pulled out of :func:`_rule_signals_malware` so the same token logic can score
    *pivot* alerts (host/community-id events), not just the focus alert — see
    :func:`_host_has_concurrent_threat`.
    """
    if _name_signals_malware(getattr(alert, "rule_name", None)):
        return True
    # Check metadata_tags on rule_metadata for any malware-signal token.
    # (No malware_family field on SoAlert; metadata_tags is the available surface.)
    rm = getattr(alert, "rule_metadata", None)
    if rm and rm.metadata_tags:
        for tag in rm.metadata_tags:
            if _name_signals_malware(tag):
                return True
    return False


def _rule_signals_malware(ctx: EnrichedAlertContext) -> bool:
    """Return True when the rule name or metadata signals malware/exploit activity.

    A malware/exploit-signaled rule must never receive a benign template anchor
    from locality or name heuristics — the synth must reason from evidence.

    Note: SoAlert has no malware_family field; the closest metadata field is
    rule_metadata.metadata_tags (rule.metadata.tag[]). No dedicated malware_family
    field exists on the model, so we check both rule_name tokens and metadata_tags.
    """
    return _alert_signals_malware(ctx.alert)


def _host_has_concurrent_threat(ctx: EnrichedAlertContext) -> bool:
    """Return True when a *pivot* alert on the same host/flow signals a threat.

    Example (SMBv2 Ioctl): the focus alert can look
    benign on its own (internal→internal east-west, INFO severity) while its
    SOURCE HOST is simultaneously beaconing to a C2 (NetSupport RAT check-ins).
    The locality templates cleared the SMB lateral-movement leg false_positive
    with zero tools because they only inspected the focus rule, never the host's
    *concurrent* activity — the exact "context not being considered" failure
    mode. When any host- or community-id-pivot alert signals malware/attack,
    the focus alert is post-exploitation-adjacent and must be INVESTIGATED, not
    anchored benign.

    The current alert is excluded from these pivots/profile by the prefetch's
    ``must_not`` id filter, so a malware focus alert does not match itself here.
    """
    # PRIMARY signal: the wide host-risk profile (rule_name → count over the
    # endpoint IPs, ±host_risk_window_hours). This is what catches a compromised
    # host whose C2 fired hours from this alert and on fields the tight ±5-min
    # pivots never query (e.g. the SMB leg and the NetSupport check-ins
    # were ~12h apart and keyed differently).
    profile = getattr(ctx, "host_alert_profile", None) or {}
    if any(_name_signals_malware(name) for name in profile):
        return True
    # FALLBACK: a threat-signalling alert in the tight community_id/host pivots.
    pivots = list(ctx.host_events) + list(ctx.community_id_events)
    return any(_alert_signals_malware(ev) for ev in pivots)


def _is_ip_internal(ctx: EnrichedAlertContext, ip: str | None) -> bool:
    if ip is None:
        return False
    enrich = ctx.enrichments.get(ip)
    if enrich is not None:
        return enrich.internal
    try:
        addr = ip_address(ip)
        return bool(addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False


def _any_blocklist_hit(ctx: EnrichedAlertContext) -> bool:
    return any(e.blocklist_hits for e in ctx.enrichments.values())


def _zeek_conn_clean(ctx: EnrichedAlertContext) -> bool:
    if not ctx.typed_zeek.conn_states:
        return False
    return all(s == "SF" for s in ctx.typed_zeek.conn_states)


def _ip_is_benign_cloud(ctx: EnrichedAlertContext, ip: str | None) -> bool:
    if ip is None:
        return False
    enrich = ctx.enrichments.get(ip)
    if enrich is None:
        return False
    if enrich.cloud_provider in {"AWS", "GCP", "Azure", "Cloudflare"}:
        return True
    # Casefold both sides: stock GeoLite2 ASN orgs are uppercase ("GOOGLE",
    # "CLOUDFLARENET", "AKAMAI-AS"), so a case-sensitive substring match against
    # the title-case needles never fired — the whole ASN fallback was dead code,
    # silently dropping Akamai/Apple/Fastly/Google-ASN traffic to a
    # lower-confidence template.
    if not (enrich.asn and enrich.asn.org):
        return False
    org_cf = enrich.asn.org.casefold()
    return any(needle.casefold() in org_cf for needle in _BENIGN_CLOUD_ASN_ORGS)


def t_blocklist_hit_major_severity(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    if not _any_blocklist_hit(ctx):
        return None
    sev = (ctx.alert.rule_metadata.signature_severity if ctx.alert.rule_metadata else "") or ""
    if sev.lower() not in {"major", "critical"}:
        return None
    hits_summary = []
    for ind, e in ctx.enrichments.items():
        for h in e.blocklist_hits:
            hits_summary.append(f"{ind} hit on {h.source} (tags={list(h.tags)})")
    return CandidateVerdict(
        verdict="true_positive",
        confidence=0.7,
        cited_evidence=hits_summary,
        template_id="blocklist_hit_major_severity",
        rationale=f"Blocklist hit + signature_severity={sev} → strong escalation signal.",
    )


def t_blocklist_hit_low_severity(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    if not _any_blocklist_hit(ctx):
        return None
    sev = (ctx.alert.rule_metadata.signature_severity if ctx.alert.rule_metadata else "") or ""
    if sev.lower() != "informational":
        return None
    return CandidateVerdict(
        verdict="needs_more_info",
        confidence=0.5,
        cited_evidence=[],
        template_id="blocklist_hit_low_severity",
        rationale=(
            "Blocklist hit on an Informational signature — could be a stale IOC; "
            "force synth to reason."
        ),
    )


def t_command_and_control_classtype(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    ct = (ctx.alert.classtype or "").lower()
    if ct not in {"command-and-control", "trojan-activity", "exfiltration"}:
        return None
    return CandidateVerdict(
        verdict="true_positive",
        confidence=0.65,
        cited_evidence=[f"alert.classtype={ctx.alert.classtype}"],
        template_id="command_and_control_classtype",
        rationale="Suricata classtype is C2 / trojan / exfil → strong escalation default.",
    )


def t_tor_exit_internal_initiator(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    a = ctx.alert
    if not _is_ip_internal(ctx, a.source_ip):
        return None
    dest_enrich = ctx.enrichments.get(a.destination_ip or "")
    if dest_enrich is None:
        return None
    if not any(h.source == "Tor Project exit list" for h in dest_enrich.blocklist_hits):
        return None
    return CandidateVerdict(
        verdict="needs_more_info",
        confidence=0.5,
        cited_evidence=[
            f"alert.source_ip={a.source_ip} (internal)",
            f"alert.destination_ip={a.destination_ip} (Tor exit node)",
        ],
        template_id="tor_exit_internal_initiator",
        rationale=(
            "Internal host initiated to a Tor exit — may be benign privacy tool or "
            "exfiltration; force synth to reason."
        ),
    )


def t_clean_internal_traffic(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    a = ctx.alert
    if not _is_ip_internal(ctx, a.source_ip):
        return None
    if not _is_ip_internal(ctx, a.destination_ip):
        return None
    if _any_blocklist_hit(ctx):
        return None
    # Lateral-movement guard: an attack-class signature between internal hosts
    # must not get a high-confidence benign anchor (blocklists can't see
    # internal IPs). Let the synth reason from the evidence instead.
    if (a.classtype or "").lower() in _ATTACK_CLASSTYPES:
        return None
    # Malware/exploit-signal guard:
    # a rule whose name or metadata signals malware must never receive a benign
    # locality anchor — force the synth to reason from evidence.
    if _rule_signals_malware(ctx):
        return None
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=[
            f"alert.source_ip={a.source_ip} (internal)",
            f"alert.destination_ip={a.destination_ip} (internal)",
            "no blocklist hits across enriched indicators",
        ],
        template_id="clean_internal_traffic",
        rationale=(
            "Both endpoints internal and no blocklist hits → very likely benign east-west traffic."
        ),
    )


def t_stun_quic_keepalive(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    name = (ctx.alert.rule_name or "").lower()
    if not any(t in name for t in ("stun", "quic")):
        return None
    if _any_blocklist_hit(ctx):
        return None
    # Malware/exploit-signal guard.
    if _rule_signals_malware(ctx):
        return None
    if not _zeek_conn_clean(ctx):
        return None
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=[
            f"alert.rule_name={ctx.alert.rule_name}",
            f"connection.state/zeek.conn.conn_state={ctx.typed_zeek.conn_states}",
        ],
        template_id="stun_quic_keepalive",
        rationale="STUN/QUIC keepalive with clean Zeek SF conn → routine WebRTC/QUIC traffic.",
    )


def t_dns_dnssec_housekeeping(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    name = (ctx.alert.rule_name or "").lower()
    if not any(t in name for t in ("rrsig", "dnskey", " ds ", "dnssec")):
        return None
    if _any_blocklist_hit(ctx):
        return None
    # Malware/exploit-signal guard.
    if _rule_signals_malware(ctx):
        return None
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.8,
        cited_evidence=[f"alert.rule_name={ctx.alert.rule_name}"],
        template_id="dns_dnssec_housekeeping",
        rationale="DNSSEC operational query (RRSIG/DNSKEY/DS) → routine.",
    )


def t_ntp_protocol_housekeeping(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    name = (ctx.alert.rule_name or "").lower()
    if "ntp" not in name:
        return None
    if _any_blocklist_hit(ctx):
        return None
    # Malware/exploit-signal guard.
    if _rule_signals_malware(ctx):
        return None
    if not _zeek_conn_clean(ctx):
        return None
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.8,
        cited_evidence=[
            f"alert.rule_name={ctx.alert.rule_name}",
            f"connection.state/zeek.conn.conn_state={ctx.typed_zeek.conn_states}",
        ],
        template_id="ntp_protocol_housekeeping",
        rationale="NTP traffic with clean Zeek SF conn → time sync.",
    )


def t_informational_external_clean_benign_cloud(
    ctx: EnrichedAlertContext,
) -> CandidateVerdict | None:
    a = ctx.alert
    sev = (a.rule_metadata.signature_severity if a.rule_metadata else "") or ""
    if sev.lower() != "informational":
        return None
    if (a.severity_label or "").lower() != "low":
        return None
    if (a.alert_action or "").lower() != "allowed":
        return None
    if _any_blocklist_hit(ctx):
        return None
    if not _ip_is_benign_cloud(ctx, a.destination_ip):
        return None
    # Malware/exploit-signal guard.
    if _rule_signals_malware(ctx):
        return None
    if not _zeek_conn_clean(ctx):
        return None
    enrich = ctx.enrichments.get(a.destination_ip or "")
    asn_org = enrich.asn.org if enrich and enrich.asn else "?"
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.8,
        cited_evidence=[
            "alert.rule_metadata.signature_severity=Informational",
            "alert.alert_action=allowed",
            f"destination_ip ASN org='{asn_org}'",
            f"connection.state/zeek.conn.conn_state={ctx.typed_zeek.conn_states}",
        ],
        template_id="informational_external_clean_benign_cloud",
        rationale=(
            "Informational allowed traffic to a known benign-cloud ASN with clean conn → routine."
        ),
    )


def t_informational_external_unknown_asn(
    ctx: EnrichedAlertContext,
) -> CandidateVerdict | None:
    a = ctx.alert
    sev = (a.rule_metadata.signature_severity if a.rule_metadata else "") or ""
    if sev.lower() != "informational":
        return None
    if (a.severity_label or "").lower() != "low":
        return None
    if (a.alert_action or "").lower() != "allowed":
        return None
    if _any_blocklist_hit(ctx):
        return None
    if _is_ip_internal(ctx, a.destination_ip):
        return None
    if _ip_is_benign_cloud(ctx, a.destination_ip):
        return None  # benign-cloud handled by the more specific template above
    # Malware/exploit-signal guard.
    if _rule_signals_malware(ctx):
        return None
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.7,
        cited_evidence=[
            "alert.rule_metadata.signature_severity=Informational",
            "alert.alert_action=allowed",
            "no blocklist hits on destination_ip",
        ],
        template_id="informational_external_unknown_asn",
        rationale=(
            "Informational allowed traffic to external IP, no blocklist hits, but ASN is "
            "not in the known-benign-cloud list → likely benign but slightly lower confidence."
        ),
    )


def t_policy_violation_internal(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    if (ctx.alert.classtype or "").lower() != "policy-violation":
        return None
    if not _is_ip_internal(ctx, ctx.alert.source_ip):
        return None
    if not _is_ip_internal(ctx, ctx.alert.destination_ip):
        return None
    # Malware/exploit-signal guard.
    if _rule_signals_malware(ctx):
        return None
    return CandidateVerdict(
        # 0.80: a deterministic internal-only policy verdict, as rule-grounded as
        # the DNSSEC/NTP housekeeping templates — and at/above the hard evidence
        # gate's strong-template exemption floor (0.8), so it auto-clears as FP
        # instead of flooding needs_more_info.
        verdict="false_positive",
        confidence=0.80,
        cited_evidence=[
            "alert.classtype=policy-violation",
            "both endpoints internal",
        ],
        template_id="policy_violation_internal",
        rationale="Policy-only signal between internal endpoints → not a security incident.",
    )


# Registration order encodes priority; higher-stakes templates first.
TEMPLATES: list[Callable[[EnrichedAlertContext], CandidateVerdict | None]] = [
    t_blocklist_hit_major_severity,
    t_blocklist_hit_low_severity,
    t_command_and_control_classtype,
    t_tor_exit_internal_initiator,
    t_clean_internal_traffic,
    t_stun_quic_keepalive,
    t_dns_dnssec_housekeeping,
    t_ntp_protocol_housekeeping,
    t_informational_external_clean_benign_cloud,
    t_informational_external_unknown_asn,
    t_policy_violation_internal,
]


# Templates that settle an alert FP on an EXTERNAL indicator (an external host
# of unknown/uncorroborated reputation) using only locally-available signals.
# These are exactly the cases where web_search + host/temporal context can
# corroborate or overturn the verdict — so when one of them fires, the agent
# should INVESTIGATE rather than short-circuit on the template ceiling
# (e.g. pushplanet.azurewebsites.net settled FP with zero tool calls).
EXTERNAL_REPUTATION_TEMPLATES: frozenset[str] = frozenset(
    {
        "informational_external_unknown_asn",
        "informational_external_clean_benign_cloud",
    }
)


def match_decision_template(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    """Run templates in registration order; return the first match."""
    for tmpl in TEMPLATES:
        result = tmpl(ctx)
        if result is not None:
            return result
    return None


__all__ = [
    "TEMPLATES",
    "CandidateVerdict",
    "DecisionTemplate",
    "Verdict",
    "_rule_signals_attack",
    "_rule_signals_malware",
    "match_decision_template",
]
