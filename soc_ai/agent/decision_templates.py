"""Decision templates — Phase B of the synth-first redesign.

Each template is a callable `(EnrichedAlertContext) -> CandidateVerdict | None`.
On match, the orchestrator passes the candidate to the synth as a default
that the synth can keep, override, or refine. On no-match, the synth gets
no candidate and reasons from the enriched context alone.

Templates are tried in registration order (first-match-wins). The order
encodes priority: more-specific / higher-stakes templates come first so
they can short-circuit a less-specific clean-traffic match.

Every candidate carries an ``authority``, which is the difference between a
template that CLASSIFIES and a template that DISPOSES. See
:class:`CandidateVerdict`.

Every ``rationale`` below is analyst-facing text. The orchestrator records it on
the run's timeline, and the synth reads it as the candidate's grounds, so it is
held to the house style (``soc_ai.agent.prompts.WRITING_STYLE_RULE``, the rules
in the project's ASD-STE100 writing rules):

## Writing style
Write for the analyst in Simplified Technical English. Put one topic in each
sentence. Keep each sentence to 20 words or fewer. Use active voice and present
tense. Name the actor.

Do not join two ideas with a dash, a semicolon or parentheses. Write two
sentences. Do not write "X, not Y" or "X rather than Y". State X. Use one term
for one thing.

State the fact first. State the reason in the next sentence. Cite the evidence
ids this prompt already requires.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, Literal, Protocol

from soc_ai.agent.classifier import normalize_classtype
from soc_ai.tools.get_alert_context import EnrichedAlertContext

# Templates only ever emit the first three; ``inconclusive`` is included so the
# alias stays assignment-compatible with soc_ai.agent.triage.Verdict (it is the
# self-consistency vote's split outcome, never a template verdict).
Verdict = Literal["true_positive", "false_positive", "needs_more_info", "inconclusive"]

# What a template's match is worth once the pipeline has to decide whether the
# case still needs evidence.
#
#   ``dispositive`` — the match is grounded in WHAT THE RULE DETECTED: the
#   signature names a protocol whose ordinary operation is the whole content of
#   the alert (STUN/QUIC keepalives, DNSSEC record queries, NTP), corroborated
#   where possible by a clean typed-Zeek conn. Nothing an investigation could
#   retrieve would change the reading, so the candidate may settle the alert
#   with no tool calls and the fast path is preserved.
#
#   ``provisional`` — the match is grounded in a property of the ENDPOINTS or
#   in the ABSENCE of a reputation hit: both hosts are internal, the external
#   host is on a cloud ASN, no blocklist named anybody. Those are facts about
#   the traffic, not about the detection, so they can classify but they cannot
#   dispose. The candidate is still handed to the synthesizer as a prior, and
#   it still steers routing, but the verdict is not final until the run has
#   retrieved something.
#
# Measured, 2026-09-06: `clean_internal_traffic` settled 13 alerts at 0.85-0.90
# false_positive with zero tool calls over the preceding nine days, nine of them
# the same ET HUNTING OGNL exploitation-attempt signature, every one of them
# auto-acknowledged in Security Onion. Its whole ground was that both endpoints
# were private and no blocklist named a private address, which is vacuously true
# of every east-west flow on a flat network, including an exploit landing on an
# internal service.
TemplateAuthority = Literal["dispositive", "provisional"]


@dataclass(frozen=True)
class CandidateVerdict:
    verdict: Verdict
    confidence: float
    cited_evidence: list[str]
    template_id: str
    rationale: str
    # Defaults to the WEAKER value on purpose: a template added later that never
    # thinks about this question does not inherit the zero-tool fast path by
    # omission. Earning it has to be an explicit act.
    authority: TemplateAuthority = "provisional"


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
        # Recon + credential theft (2026-08-26 batch, h1-kerberoasting).
        # Synthetic alerts used to parse with classtype=None, so this routing
        # never fired on them and the gap stayed invisible; once they parsed,
        # h1 — a Sigma-on-Zeek Kerberoasting detection carrying classtype
        # attempted-recon between two internal hosts — matched
        # clean_internal_traffic (false_positive @0.85) in both measured runs.
        # The recon family (with its "successful" grades, mirroring the
        # attempted/successful-admin pairs above) and credential-theft are
        # attack signals: between internal endpoints the blocklist anchor is
        # vacuous, so they must reach the synth, never the benign default.
        # Deliberately NOT added: network-scan / rpc-portmap-decode —
        # authorized internal scanners are routine IT, and the benign twins
        # (b1-b8: bad-unknown, misc-activity, policy-violation,
        # web-application-attack, attempted-admin) pin that this widening
        # touches no benign scenario's classtype
        # (tests/test_quality_spine.py::test_benign_internal_traffic_still_matches_clean_internal).
        "attempted-recon",
        "successful-recon-limited",
        "successful-recon-largescale",
        "credential-theft",
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

# Tokens whose presence in a rule name marks a behavioural/anomaly ANALYTIC —
# a Zeek analytic surfaced as an alert, a Sigma behavioural detection, the
# SOC-AI ANALYTIC family. These rules are DELIBERATELY informational
# (misc-activity / Informational is their normal dress), so the attack-classtype
# and malware-token guards never fire on them — and "both endpoints internal, no
# blocklist hits" is vacuous for exactly this class: lateral movement, staging
# and internal recon are internal-to-internal by definition, and internal IPs
# never appear on blocklists. An analytic's verdict lives in baseline/aggregate
# evidence (rate vs the user's history, fan-out, what happened downstream) that
# no template predicate can see, so no benign template may anchor one — it falls
# through to the synth/loop and is dispositioned from evidence
# (2026-08-27 batch: h5-ransomware-staging — 1,843 files across 6 shares then a
# 3.2 GB archive — and h6-wmi-remote-exec-cradle both settled false_positive on
# clean_internal_traffic with ZERO tool calls).
#
# The cost is accepted and deliberate: benign twins that share an attack twin's
# exact wire shape (b5 carries h6's identical rule — "the rule cannot tell them
# apart", per the scenario) lose the zero-tool fast path too, because no
# alert-level guard can separate a pair the catalogue built to be
# indistinguishable at the alert level. Routine signature-based ET INFO/POLICY
# internal traffic carries none of these tokens and keeps the fast path.
# Substring match ("analytic" covers ANALYTIC/analytics/analytical); every token
# is long enough that no benign word contains it. Deliberately NOT added:
# "hunting" (ET HUNTING) — no measured miss, and widening past the measured
# hole needs a benign-twin check first (see _ATTACK_CLASSTYPES note above).
_ANALYTIC_SIGNAL_TOKENS = (
    "analytic",
    "anomaly",
    "anomalous",
    "behavioral",
    "behavioural",
)


def _rule_signals_attack(ctx: EnrichedAlertContext) -> bool:
    """Return True when the alert's classtype is in ``_ATTACK_CLASSTYPES``.

    Attack-class rules (kerberoast, psexec lateral movement, data exfil,
    DNS tunnel, etc.) don't necessarily carry malware tokens in their rule
    names, so ``_rule_signals_malware`` misses them. This helper covers the
    exploit/attack-signal half of the approved escalation policy: any alert
    whose Suricata classtype falls in ``_ATTACK_CLASSTYPES`` should escalate
    to the Oracle unless it is already a high-confidence true-positive.
    """
    return normalize_classtype(ctx.alert.classtype) in _ATTACK_CLASSTYPES


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


# Tokens marking a deception sensor. Matched with word boundaries so an
# ordinary rule naming a host or a place ("canaryislands.example") is not read
# as a decoy detection; the dataset and module carry dots and hyphens, which the
# \b boundary handles.
_DECOY_SIGNAL_RE = re.compile(
    r"\b(opencanary|canarytoken|canarytokens|canary|honeypot|honeytoken|honeynet|decoy|tarpit)\b"
)


def _alert_signals_decoy(alert: Any) -> bool:
    """Return True when the alert came from a decoy / deception sensor.

    A decoy advertises services that exist only to be touched. It is not in DNS
    and no real workload routes to it, so unlike every other detection there is
    no benign population to separate from — see the catalog spec at
    ``soc_ai/hunting/catalog/decoy-opencanary-interaction.yaml``, which states
    the property and concludes there is therefore no threshold, no baseline and
    no tuning.

    Keyed on the dataset and module first because OpenCanary alerts carry no
    ``rule.name`` at all (the alert-queue grouping in
    ``soc_ai/webui/alerts_query.py`` had to work around the same absence). The
    rule name is checked too, so a deployment shipping canarytokens or a
    hand-written honeypot rule is recognised without an OpenCanary install.
    """
    for field in ("event_dataset", "event_module", "rule_name"):
        value = getattr(alert, field, None)
        if value and _DECOY_SIGNAL_RE.search(str(value).lower()):
            return True
    return False


def _rule_signals_decoy(ctx: EnrichedAlertContext) -> bool:
    """Context wrapper over :func:`_alert_signals_decoy` for the focus alert."""
    return _alert_signals_decoy(ctx.alert)


def _rule_signals_behavioral_analytic(ctx: EnrichedAlertContext) -> bool:
    """Return True when the rule name marks a behavioural/anomaly analytic.

    Guards every benign template that can short-circuit a case with zero tool
    calls: a behavioural detection's meaning is in evidence a template cannot
    see, so it must be investigated, never dismissed on locality or protocol
    name. See ``_ANALYTIC_SIGNAL_TOKENS`` for the rationale and the measured
    h5/h6 defect this closes.

    Deliberately NOT applied to the two ``EXTERNAL_REPUTATION_TEMPLATES``:
    those never short-circuit (``_definitely_investigate`` always runs the
    loop when they match), so the zero-tool hole does not exist there, and
    stripping their candidate default would change measured behaviour on
    external-leg analytics (b6/b7) with no measured defect to justify it.
    """
    n = (ctx.alert.rule_name or "").lower()
    return any(tok in n for tok in _ANALYTIC_SIGNAL_TOKENS)


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


def _external_endpoint(ctx: EnrichedAlertContext) -> str | None:
    """The external counterparty IP, regardless of flow direction.

    Informational alerts fire on either leg: an outbound client->server flow
    (external = ``destination_ip``) or a server->client observation such as a TLS
    cert / JA3S / server banner, where Suricata tags the alert with the RESPONSE
    packet's direction (external = ``source_ip``, internal = ``destination_ip``).
    The benign-informational templates must judge the EXTERNAL endpoint, not a
    fixed leg -- otherwise every server-side observation slips past them and burns
    a full investigation loop.

    Prefers an external destination (preserving the original outbound behaviour),
    then an external source. Returns ``None`` when neither side is external (a
    purely-internal alert, handled by ``clean_internal_traffic``).
    """
    a = ctx.alert
    if a.destination_ip and not _is_ip_internal(ctx, a.destination_ip):
        return a.destination_ip
    if a.source_ip and not _is_ip_internal(ctx, a.source_ip):
        return a.source_ip
    return None


def _any_blocklist_hit(ctx: EnrichedAlertContext) -> bool:
    return any(e.blocklist_hits for e in ctx.enrichments.values())


def _blocklist_feeds_missing(ctx: EnrichedAlertContext) -> bool:
    """True only when an enrichment AFFIRMS that no feed answered its lookup.

    ``blocklist_checked`` is tri-state: ``None`` means the record predates the
    field and makes no claim, so it is not evidence of a missing feed and does
    not change any template's behaviour. Only an explicit ``False`` does.

    The templates below gate on "no hit", which is vacuously satisfied by a
    database that loaded nothing. That is survivable where the argument is
    about locality or protocol; it is not where the argument IS the reputation
    of an address, and it is never acceptable to WRITE the claim down.
    """
    return any(e.blocklist_checked is False for e in ctx.enrichments.values())


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
        rationale=f"A blocklist hit landed on signature_severity={sev}. Escalate this alert.",
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
            "A blocklist hit landed on an Informational signature. The indicator "
            "can be a stale IOC. The synthesizer decides this alert."
        ),
    )


def t_command_and_control_classtype(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    ct = normalize_classtype(ctx.alert.classtype)
    if ct not in {"command-and-control", "trojan-activity", "exfiltration"}:
        return None
    return CandidateVerdict(
        verdict="true_positive",
        confidence=0.65,
        cited_evidence=[f"alert.classtype={ctx.alert.classtype}"],
        template_id="command_and_control_classtype",
        rationale="The Suricata classtype names C2, trojan or exfil activity. Escalate by default.",
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
            "An internal host started a connection to a Tor exit node. This can be a "
            "privacy tool. This can be exfiltration. The synthesizer decides this alert."
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
    if normalize_classtype(a.classtype) in _ATTACK_CLASSTYPES:
        return None
    # Malware/exploit-signal guard:
    # a rule whose name or metadata signals malware must never receive a benign
    # locality anchor — force the synth to reason from evidence.
    if _rule_signals_malware(ctx):
        return None
    # Behavioural-analytics guard: a deliberately-informational analytic
    # (misc-activity dress, no attack classtype, no malware token) is exactly
    # the class where "both endpoints internal" is LEAST informative — its
    # verdict lives in baseline/aggregate evidence, so it gets investigated,
    # never anchored benign (h5/h6, batch-2026-08-27T021722Z).
    if _rule_signals_behavioral_analytic(ctx):
        return None
    # The locality grounds survive an unloaded feed. The third one does not,
    # and it is the line three triages leaned on to close a false positive.
    unchecked = _blocklist_feeds_missing(ctx)
    reputation_line = (
        "blocklist not loaded, so no reputation check ran on either endpoint"
        if unchecked
        else "no blocklist hits across enriched indicators"
    )
    rationale = (
        "Both endpoints are internal. This is likely benign east-west traffic. The "
        "blocklist was not loaded. No indicator reached threat intel."
        if unchecked
        else "Both endpoints are internal and the blocklist answered with no hit. This "
        "is very likely benign east-west traffic."
    )
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=[
            f"alert.source_ip={a.source_ip} (internal)",
            f"alert.destination_ip={a.destination_ip} (internal)",
            reputation_line,
        ],
        template_id="clean_internal_traffic",
        rationale=rationale,
        # PROVISIONAL by the default, and the reason the default exists. Every
        # ground this template has is a property of the endpoints: an exploit
        # aimed at an internal service satisfies all of them, and on a flat
        # network that is most of what matters. The candidate still reaches the
        # synthesizer; it just cannot end the case on its own.
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
    # Behavioural-analytics guard (see t_clean_internal_traffic).
    if _rule_signals_behavioral_analytic(ctx):
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
        rationale="A STUN or QUIC keepalive carries a clean Zeek SF conn. This is routine traffic.",
        # The rule names the protocol and the protocol's ordinary operation is
        # the entire alert; the SF conn is retrieved corroboration.
        authority="dispositive",
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
    # Behavioural-analytics guard (see t_clean_internal_traffic).
    if _rule_signals_behavioral_analytic(ctx):
        return None
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.8,
        cited_evidence=[f"alert.rule_name={ctx.alert.rule_name}"],
        template_id="dns_dnssec_housekeeping",
        rationale="The rule names a DNSSEC record query of RRSIG, DNSKEY or DS. This is routine.",
        # An RRSIG/DNSKEY/DS query is DNSSEC doing its job; the record type is
        # the detection, and there is nothing behind it to retrieve.
        authority="dispositive",
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
    # Behavioural-analytics guard (see t_clean_internal_traffic): an analytic
    # whose name mentions a housekeeping protocol must not ride its template.
    if _rule_signals_behavioral_analytic(ctx):
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
        rationale="NTP traffic carries a clean Zeek SF conn. The host is syncing its clock.",
        # Same shape as the STUN template: the rule names the protocol and the
        # SF conn is retrieved corroboration.
        authority="dispositive",
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
    ext = _external_endpoint(ctx)
    if ext is None or not _ip_is_benign_cloud(ctx, ext):
        return None
    # Malware/exploit-signal guard.
    if _rule_signals_malware(ctx):
        return None
    if not _zeek_conn_clean(ctx):
        return None
    enrich = ctx.enrichments.get(ext)
    asn_org = enrich.asn.org if enrich and enrich.asn else "?"
    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.8,
        cited_evidence=[
            "alert.rule_metadata.signature_severity=Informational",
            "alert.alert_action=allowed",
            f"external endpoint {ext} ASN org='{asn_org}'",
            f"connection.state/zeek.conn.conn_state={ctx.typed_zeek.conn_states}",
        ],
        template_id="informational_external_clean_benign_cloud",
        rationale=(
            "Informational allowed traffic reached a known benign-cloud ASN. The conn "
            "is clean. This is routine."
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
    # Unlike the locality and protocol templates, this one's only benign ground
    # beyond "informational and allowed" IS the reputation of an external
    # address. With no feed loaded there is no such ground, so the alert goes to
    # investigation rather than to a 0.7 false positive resting on a lookup that
    # did not happen.
    if _blocklist_feeds_missing(ctx):
        return None
    ext = _external_endpoint(ctx)
    if ext is None:
        return None
    if _ip_is_benign_cloud(ctx, ext):
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
            f"no blocklist hits on external endpoint {ext}",
        ],
        template_id="informational_external_unknown_asn",
        rationale=(
            "Informational allowed traffic reached an external IP and the blocklist "
            "answered with no hit. The ASN is absent from the known-benign-cloud list. "
            "This is likely benign at a slightly lower confidence."
        ),
    )


def t_policy_violation_internal(ctx: EnrichedAlertContext) -> CandidateVerdict | None:
    if normalize_classtype(ctx.alert.classtype) != "policy-violation":
        return None
    if not _is_ip_internal(ctx, ctx.alert.source_ip):
        return None
    if not _is_ip_internal(ctx, ctx.alert.destination_ip):
        return None
    # Malware/exploit-signal guard.
    if _rule_signals_malware(ctx):
        return None
    # Behavioural-analytics guard (see t_clean_internal_traffic).
    if _rule_signals_behavioral_analytic(ctx):
        return None
    return CandidateVerdict(
        # 0.80 is the historical anchor, chosen when the hard evidence gate
        # exempted any benign template at 0.8 or above. That exemption is now
        # keyed on ``authority``, not on confidence, and this template is
        # PROVISIONAL: its second leg is "both endpoints internal", the same
        # ground that let clean_internal_traffic clear an exploitation attempt.
        # A policy classtype says the rule author was flagging policy, which is
        # a reason to propose benign, not a reason to stop looking.
        verdict="false_positive",
        confidence=0.80,
        cited_evidence=[
            "alert.classtype=policy-violation",
            "both endpoints internal",
        ],
        template_id="policy_violation_internal",
        rationale="A policy-only signal fired between internal endpoints. This is not an incident.",
    )


# Registration order encodes priority; higher-stakes templates first, then the
# specific benign templates, then the catch-all.
#
# ``t_clean_internal_traffic`` used to sit fifth, ahead of the three protocol-
# housekeeping templates, and it matches ANY internal pair, so it shadowed them
# on every east-west alert. Measured on the production instance: two "ET INFO
# Outbound RRSIG DNS Query Observed" alerts matched clean_internal_traffic
# rather than dns_dnssec_housekeeping. That was invisible while both returned
# false_positive at similar confidence. It stops being invisible now that the
# two carry different authority, because the shadowing would cost the specific
# template its fast path. Least specific goes last.
TEMPLATES: list[Callable[[EnrichedAlertContext], CandidateVerdict | None]] = [
    t_blocklist_hit_major_severity,
    t_blocklist_hit_low_severity,
    t_command_and_control_classtype,
    t_tor_exit_internal_initiator,
    t_stun_quic_keepalive,
    t_dns_dnssec_housekeeping,
    t_ntp_protocol_housekeeping,
    t_informational_external_clean_benign_cloud,
    t_informational_external_unknown_asn,
    t_policy_violation_internal,
    t_clean_internal_traffic,
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
    """Run templates in registration order; return the first match.

    A benign candidate is withheld on a decoy alert. ``clean_internal_traffic``
    matched a live OpenCanary interaction and seeded false_positive at 0.85
    before a single tool ran, on the sole ground that both endpoints were
    internal — which a decoy interaction always is, since the decoy sits on the
    network it is protecting. Every benign template here rests on locality,
    protocol housekeeping or reputation, and none of those separate anything on
    a sensor with no benign population to separate from.

    A benign candidate is likewise withheld on an attack-class alert. The
    protocol-housekeeping templates key on a token in the rule name, and the
    name of an ET DOS NTP amplification rule or an ET SCAN STUN probe carries
    that token too; with the routine SF conn beside it, the alert was settled
    false_positive with dispositive authority before a single tool ran. The
    classtype is the detection, and a protocol named in the rule is not a
    defence against it. ``clean_internal_traffic`` carries the same guard on
    its own, for the lateral-movement case it was written against.

    Withheld at the choke point rather than guarded per template so a template
    added later cannot reintroduce the anchor by forgetting the check. Positive
    candidates pass through untouched: the concern is closure, not escalation.

    Withholding is the harshest of the three settings a benign template can be
    in. The other two are the candidate's ``authority``: dispositive templates
    settle the alert, provisional ones only propose. See
    :data:`TemplateAuthority`.
    """
    withhold_benign = _rule_signals_decoy(ctx) or _rule_signals_attack(ctx)
    for tmpl in TEMPLATES:
        result = tmpl(ctx)
        if result is None:
            continue
        if withhold_benign and result.verdict == "false_positive":
            return None
        return result
    return None


__all__ = [
    "TEMPLATES",
    "CandidateVerdict",
    "DecisionTemplate",
    "TemplateAuthority",
    "Verdict",
    "_alert_signals_decoy",
    "_rule_signals_attack",
    "_rule_signals_behavioral_analytic",
    "_rule_signals_decoy",
    "_rule_signals_malware",
    "match_decision_template",
]
