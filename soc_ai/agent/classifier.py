"""Deterministic alert-class classifier.

Tags every alert with one of four buckets so the orchestrator can pick
a routing strategy: full pipeline vs fast-path vs heavy-priority.

The classifier is **deterministic** (no LLM call) and operates on the
typed :class:`SoAlert` fields populated by :func:`SoAlert.from_es_hit`.
It must not make any IO — the orchestrator runs it inline between
prefetch and the investigator launch.

The four classes:

- ``informational_visibility`` — ET INFO / misc-activity / policy-only
  signals. The dominant FP class on this grid; safe to fast-path with
  a stripped-down "confirm-or-deny benign hypothesis" prompt and a
  reduced retask floor.
- ``recon`` — port scans, fingerprinting, attempted-recon classtypes.
  Investigator should still run the full pipeline because correlation
  with related alerts is the deciding factor.
- ``exploit_attempt`` — active exploitation signatures (attempted-admin /
  attempted-user / web-application-attack / shellcode-detect). Full
  pipeline + the standard 0.6 floor; never fast-pathed.
- ``post_compromise`` — confirmed C2 / exfil / trojan-activity. Full
  pipeline; verdict bias should never tip toward false-positive without
  strong evidence.
- ``unknown`` — fallback when no signal matches. Full pipeline.

Safe fast-path gating requires that the fast-path be gated on a
**closed allowlist** rather than rule-name regex. We achieve this by
making ``informational_visibility`` membership require BOTH
``signature_severity == "Informational"`` AND
``severity_label in {"low"}``. The combination is an explicit allowlist
on rule-author-declared metadata, not a string match on the rule name.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

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


def is_fast_path_eligible(
    alert: SoAlert,
    alert_class: AlertClass,
    *,
    enrichment_cache: Any = None,
) -> bool:
    """Whether the orchestrator may take the fast-path for this alert.

    Eligibility is the AND of:

    - ``alert_class == INFORMATIONAL_VISIBILITY``
    - ``severity_label`` lowercases to ``low`` (Security Onion's
      configured low-severity bucket — ``severity_score`` thresholds
      vary per deployment, so we trust the SO-side label).
    - If the destination IP is external, it MUST have a
      prior enrichment-cache hit (i.e. we've enriched it once already
      this process). First-encounter external IPs route to the full
      pipeline at least once to establish a verdict baseline. Pass
      ``enrichment_cache=None`` to disable this gate (the default —
      tests and direct callers that don't have a cache).

    This is a stricter gate than the classifier alone — informational
    signatures *can* still warrant the full pipeline when SO has bumped
    their severity (e.g. via correlation rules or analyst-set tags) or
    when we haven't yet seen the destination IP.
    """
    from ipaddress import ip_address  # noqa: PLC0415

    if alert_class is not AlertClass.INFORMATIONAL_VISIBILITY:
        return False
    sev = (alert.severity_label or "").strip().lower()
    if sev != "low":
        return False

    # Cache gate: only apply when a cache is provided (so unit tests
    # that don't construct one keep the legacy behavior).
    if enrichment_cache is not None:
        dest = getattr(alert, "destination_ip", None)
        if isinstance(dest, str):
            try:
                addr = ip_address(dest)
            except (ValueError, TypeError):
                addr = None
            is_external_dest = addr is not None and not (
                addr.is_private or addr.is_loopback or addr.is_link_local
            )
            if is_external_dest and not enrichment_cache.contains(dest):
                # External destination with no prior enrichment → not eligible.
                return False
    return True


__all__ = [
    "AlertClass",
    "classify_alert",
    "is_fast_path_eligible",
]
