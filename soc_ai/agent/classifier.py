"""Deterministic alert-class classifier.

Tags every alert with a coarse class. The orchestrator uses it for
high-stakes gating (e.g. an ``exploit_attempt`` / ``post_compromise``
alert is never auto-acked on a confident false-positive verdict).

The classifier is **deterministic** (no LLM call) and operates on the
typed :class:`SoAlert` fields populated by :func:`SoAlert.from_es_hit`.
It must not make any IO.

The classes:

- ``informational_visibility`` — ET INFO / misc-activity / policy-only
  signals. The dominant FP class on this grid.
- ``recon`` — port scans, fingerprinting, attempted-recon classtypes.
  Correlation with related alerts is the deciding factor.
- ``exploit_attempt`` — active exploitation signatures (attempted-admin /
  attempted-user / web-application-attack / shellcode-detect).
- ``post_compromise`` — confirmed C2 / exfil / trojan-activity. Verdict
  bias should never tip toward false-positive without strong evidence.
- ``unknown`` — fallback when no signal matches.

Totality: the classification table (:data:`_CLASSTYPE_DESCRIPTIONS`) and the
routing map (:data:`_CLASSTYPE_MAP`) cover the same ground. Every shortname the
table can produce is either mapped to a class or named in
:data:`_UNROUTED_CLASSTYPES`, and a test enforces it, so a classification can no
longer arrive with nobody having decided what it means.
"""

from __future__ import annotations

from enum import StrEnum

from soc_ai.so_client.models import SoAlert


class AlertClass(StrEnum):
    """Coarse alert class used by the orchestrator's routing layer."""

    INFORMATIONAL_VISIBILITY = "informational_visibility"
    RECON = "recon"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    POST_COMPROMISE = "post_compromise"
    UNKNOWN = "unknown"


# Suricata classtype → AlertClass. Drawn from the upstream
# `classification.config` shipped with Suricata 6/7.
#
# This map and the description table below cover the SAME ground: every
# shortname the table can produce either appears here or is listed in
# ``_UNROUTED_CLASSTYPES``, and a test holds that (see
# ``tests/test_classifier.py::test_every_classification_the_table_knows_has_a_
# routing_decision``). The map used to enumerate only the 20 classifications
# someone had got round to, and the other 23 fell through to UNKNOWN in
# silence, a default that reads as "no opinion" and spends as "safe". That is
# how "GPL SHELLCODE x86 setgid 0" came to be acknowledged unattended: it
# carries the category "A system call was detected", which normalizes to
# system-call-detect, which nothing here had an opinion about. 156 unattended
# acknowledgements across two shellcode rules on the production instance.
#
# So the rule is totality, not a longer list: a classification with no routing
# decision is a defect, and the place to record the decision is here, on the
# field the rule author declared, rather than in a list of substrings to look
# for in rule names.
_CLASSTYPE_MAP: dict[str, AlertClass] = {
    # informational_visibility
    "misc-activity": AlertClass.INFORMATIONAL_VISIBILITY,
    "not-suspicious": AlertClass.INFORMATIONAL_VISIBILITY,
    "policy-violation": AlertClass.INFORMATIONAL_VISIBILITY,
    "protocol-command-decode": AlertClass.INFORMATIONAL_VISIBILITY,
    "external-ip-check": AlertClass.INFORMATIONAL_VISIBILITY,
    "tcp-connection": AlertClass.INFORMATIONAL_VISIBILITY,
    "icmp-event": AlertClass.INFORMATIONAL_VISIBILITY,
    "inappropriate-content": AlertClass.INFORMATIONAL_VISIBILITY,
    # recon
    "attempted-recon": AlertClass.RECON,
    "successful-recon-limited": AlertClass.RECON,
    "successful-recon-largescale": AlertClass.RECON,
    "network-scan": AlertClass.RECON,
    "rpc-portmap-decode": AlertClass.RECON,
    # exploit_attempt: the rule author declared that something was tried.
    "attempted-admin": AlertClass.EXPLOIT_ATTEMPT,
    "attempted-user": AlertClass.EXPLOIT_ATTEMPT,
    "unsuccessful-user": AlertClass.EXPLOIT_ATTEMPT,
    "web-application-attack": AlertClass.EXPLOIT_ATTEMPT,
    "shellcode-detect": AlertClass.EXPLOIT_ATTEMPT,
    # The classification the GPL SHELLCODE family actually ships with. Its
    # description is the mild-sounding "A system call was detected"; the rules
    # carrying it match x86 setgid/setuid/execve stubs in traffic.
    "system-call-detect": AlertClass.EXPLOIT_ATTEMPT,
    "attempted-dos": AlertClass.EXPLOIT_ATTEMPT,
    "successful-dos": AlertClass.EXPLOIT_ATTEMPT,
    "denial-of-service": AlertClass.EXPLOIT_ATTEMPT,
    "exploit-kit": AlertClass.EXPLOIT_ATTEMPT,
    "misc-attack": AlertClass.EXPLOIT_ATTEMPT,
    "suspicious-login": AlertClass.EXPLOIT_ATTEMPT,
    "default-login-attempt": AlertClass.EXPLOIT_ATTEMPT,
    "social-engineering": AlertClass.EXPLOIT_ATTEMPT,
    # post_compromise: the rule author declared that something is running.
    "trojan-activity": AlertClass.POST_COMPROMISE,
    "successful-admin": AlertClass.POST_COMPROMISE,
    "successful-user": AlertClass.POST_COMPROMISE,
    "command-and-control": AlertClass.POST_COMPROMISE,
    "domain-c2": AlertClass.POST_COMPROMISE,
    "exfiltration": AlertClass.POST_COMPROMISE,
    "targeted-activity": AlertClass.POST_COMPROMISE,
    "credential-theft": AlertClass.POST_COMPROMISE,
    "coin-mining": AlertClass.POST_COMPROMISE,
    "pup-activity": AlertClass.POST_COMPROMISE,
}


# Classifications the map deliberately says nothing about, so that "nothing to
# say" is a written decision rather than an oversight. Each of these describes a
# property of the traffic rather than a judgement about it (a string matched, a
# port that was unusual, a protocol that was odd), and the population behind them
# is dominated by ordinary traffic. They fall through to UNKNOWN and get the full
# pipeline, which is the same behaviour as before; the difference is that a new
# classification arriving in the table cannot join them by accident.
_UNROUTED_CLASSTYPES: frozenset[str] = frozenset(
    {
        "unknown",
        "bad-unknown",
        "string-detect",
        "suspicious-filename-detect",
        "unusual-client-port-connection",
        "non-standard-protocol",
        "web-application-activity",
    }
)


# Suricata classification DESCRIPTION → shortname.
#
# ``SoAlert.classtype`` is parsed from Suricata EVE's ``alert.category``, and
# EVE writes the classification's description text, never its shortname. Every
# classtype table in this codebase (the map above, decision_templates'
# _ATTACK_CLASSTYPES, the auto-acknowledge high-stakes guard, three decision
# templates) was keyed on shortnames, so on live Security Onion data none of
# them ever matched anything. It stayed invisible because the synthetic eval
# scenarios render the shortname, so every test agreed with the code and
# disagreed with the grid.
#
# Measured across 180 recorded production runs, the classtype field held only
# these nine values, all of them descriptions: "Misc activity" (77), "Device
# Retrieving External IP Address Detected" (27), "Not Suspicious Traffic" (26),
# "Potentially Bad Traffic" (18), "Potential Corporate Privacy Violation" (17),
# "Attempted Denial of Service" (6), "Attempted Information Leak" (4), "Malware
# Command and Control Activity Detected" (4), "Attempted Administrator
# Privilege Gain" (1). A "GPL MISC Teardrop attack" carrying the denial-of-
# service description was auto-acknowledged twice as a result.
#
# Source: Suricata's own etc/classification.config. The mapping is exact, so an
# unrecognized value is passed through rather than guessed at; a deployment
# running a ruleset with its own classifications keeps whatever it sends, and
# the shortname form (fixtures, rendered synthetic scenarios, Snort-style
# sources) is idempotent under this.
_CLASSTYPE_DESCRIPTIONS: dict[str, str] = {
    "not suspicious traffic": "not-suspicious",
    "unknown traffic": "unknown",
    "potentially bad traffic": "bad-unknown",
    "attempted information leak": "attempted-recon",
    "information leak": "successful-recon-limited",
    "large scale information leak": "successful-recon-largescale",
    "attempted denial of service": "attempted-dos",
    "denial of service": "successful-dos",
    "attempted user privilege gain": "attempted-user",
    "unsuccessful user privilege gain": "unsuccessful-user",
    "successful user privilege gain": "successful-user",
    "attempted administrator privilege gain": "attempted-admin",
    "successful administrator privilege gain": "successful-admin",
    "decode of an rpc query": "rpc-portmap-decode",
    "executable code was detected": "shellcode-detect",
    "a suspicious string was detected": "string-detect",
    "a suspicious filename was detected": "suspicious-filename-detect",
    "an attempted login using a suspicious username was detected": "suspicious-login",
    "a system call was detected": "system-call-detect",
    "a tcp connection was detected": "tcp-connection",
    "a network trojan was detected": "trojan-activity",
    "a client was using an unusual port": "unusual-client-port-connection",
    "detection of a network scan": "network-scan",
    "detection of a denial of service attack": "denial-of-service",
    "detection of a non-standard protocol or event": "non-standard-protocol",
    "generic protocol command decode": "protocol-command-decode",
    "access to a potentially vulnerable web application": "web-application-activity",
    "web application attack": "web-application-attack",
    "misc activity": "misc-activity",
    "misc attack": "misc-attack",
    "generic icmp event": "icmp-event",
    "inappropriate content was detected": "inappropriate-content",
    "potential corporate privacy violation": "policy-violation",
    "attempt to login by a default username and password": "default-login-attempt",
    "targeted malicious activity was detected": "targeted-activity",
    "exploit kit activity detected": "exploit-kit",
    "device retrieving external ip address detected": "external-ip-check",
    "domain observed used for c2 detected": "domain-c2",
    "possibly unwanted program detected": "pup-activity",
    "successful credential theft detected": "credential-theft",
    "possible social engineering attempted": "social-engineering",
    "crypto currency mining activity detected": "coin-mining",
    "malware command and control activity detected": "command-and-control",
    "data exfiltration detected": "exfiltration",
}


def normalize_classtype(classtype: str | None) -> str:
    """Return the Suricata classtype SHORTNAME for whatever the sensor sent.

    Casefolded and whitespace-trimmed. A recognized description maps to its
    shortname; anything else (a shortname already, or a classification a local
    ruleset invented) is returned lowercased and stripped, so this is idempotent
    and never invents a class it does not have evidence for. ``None`` becomes
    the empty string, which matches no table.

    Every classtype comparison in the codebase goes through here. The raw value
    stays on ``SoAlert.classtype`` for display, because that is what the analyst
    will see in Security Onion.
    """
    key = (classtype or "").strip().lower()
    return _CLASSTYPE_DESCRIPTIONS.get(key, key)


def classify_alert(alert: SoAlert) -> AlertClass:
    """Map a typed :class:`SoAlert` to its :class:`AlertClass`.

    Decision order:

    1. Suricata ``classtype`` (when present) is the strongest signal —
       it's rule-author-declared metadata. Normalized through
       :func:`normalize_classtype` first, because the wire carries the
       classification's description text rather than its shortname. A
       classification listed in :data:`_UNROUTED_CLASSTYPES` falls through on
       purpose and the remaining steps decide.
    2. ``signature_severity == "Critical"`` upgrades to POST_COMPROMISE
       even when classtype is missing — Critical signatures are
       rule-author-declared post-compromise indicators.
    3. ``signature_severity == "Major"`` maps to EXPLOIT_ATTEMPT in the
       absence of classtype data.
    4. ``rule_metadata.is_informational`` (Informational severity) maps
       to INFORMATIONAL_VISIBILITY.
    5. Fall through to UNKNOWN.

    The classifier never reads ``rule_name`` strings (mitigation:
    closed allowlist on classtype/metadata, not regex on names).
    """
    classtype = normalize_classtype(alert.classtype)
    if classtype in _CLASSTYPE_MAP:
        return _CLASSTYPE_MAP[classtype]

    rm = alert.rule_metadata
    sig_sev = (rm.signature_severity or "").strip().lower() if rm else ""
    if sig_sev == "critical":
        return AlertClass.POST_COMPROMISE
    if sig_sev == "major":
        return AlertClass.EXPLOIT_ATTEMPT
    if sig_sev == "informational":
        return AlertClass.INFORMATIONAL_VISIBILITY

    return AlertClass.UNKNOWN


__all__ = [
    "AlertClass",
    "classify_alert",
    "normalize_classtype",
]
