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
# `classification.config` shipped with Suricata 6/7. We only enumerate
# the buckets that map to a meaningful routing signal; everything else
# falls through to UNKNOWN and runs the full pipeline.
_CLASSTYPE_MAP: dict[str, AlertClass] = {
    # informational_visibility
    "misc-activity": AlertClass.INFORMATIONAL_VISIBILITY,
    "not-suspicious": AlertClass.INFORMATIONAL_VISIBILITY,
    "policy-violation": AlertClass.INFORMATIONAL_VISIBILITY,
    "protocol-command-decode": AlertClass.INFORMATIONAL_VISIBILITY,
    # recon
    "attempted-recon": AlertClass.RECON,
    "successful-recon-limited": AlertClass.RECON,
    "successful-recon-largescale": AlertClass.RECON,
    "network-scan": AlertClass.RECON,
    "rpc-portmap-decode": AlertClass.RECON,
    # exploit_attempt
    "attempted-admin": AlertClass.EXPLOIT_ATTEMPT,
    "attempted-user": AlertClass.EXPLOIT_ATTEMPT,
    "web-application-attack": AlertClass.EXPLOIT_ATTEMPT,
    "shellcode-detect": AlertClass.EXPLOIT_ATTEMPT,
    "attempted-dos": AlertClass.EXPLOIT_ATTEMPT,
    "successful-dos": AlertClass.EXPLOIT_ATTEMPT,
    # post_compromise
    "trojan-activity": AlertClass.POST_COMPROMISE,
    "successful-admin": AlertClass.POST_COMPROMISE,
    "successful-user": AlertClass.POST_COMPROMISE,
    "command-and-control": AlertClass.POST_COMPROMISE,
    "exfiltration": AlertClass.POST_COMPROMISE,
}


def classify_alert(alert: SoAlert) -> AlertClass:
    """Map a typed :class:`SoAlert` to its :class:`AlertClass`.

    Decision order:

    1. Suricata ``classtype`` (when present) is the strongest signal —
       it's rule-author-declared metadata.
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
    classtype = (alert.classtype or "").strip().lower()
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
]
