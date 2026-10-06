"""Budget classes: how much a triage run may spend, and who decides.

A run has a class. The class is a property of the run, set by the rungs of
the tier 1 ladder above the model, and the console shows it on the run
(docs/dev/specs/2026-10-04-four-tier-detection-methodology.md, "The ladder").

``cheap``
    One synthesis request on the prefetch. No tool loop and no Oracle. The
    round-1 path, entered only where a dispositive decision template cleared
    the alert. A round-1 verdict that is not a false positive, or that a
    verdict gate would change, escalates the run to ``standard``.
``standard``
    The tool loop with today's budget. The default for an analyst's
    Investigate, a re-run, a promotion and a hunt.
``deep``
    The loop with the full budget, the full tool surface and the full prompt,
    then the Oracle when the verdict is uncertain. The analyst's "Deep re-run".
``rule_prior``
    No model call. The rule prior covered the alert with the verdict of the
    rule's latest model-backed run (see :mod:`soc_ai.agent.rule_prior`).

The caller states a request, or none. ``None`` is the scheduler's request:
the rungs decide. An explicit ``standard`` or ``deep`` always runs the loop.
The class the row stores is the class that RAN, read off what the pipeline
did, so a label never claims a loop that did not run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

RunClass = Literal["cheap", "standard", "deep", "rule_prior"]
RequestedClass = Literal["standard", "deep"]

CHEAP: Final = "cheap"
STANDARD: Final = "standard"
DEEP: Final = "deep"
RULE_PRIOR: Final = "rule_prior"

RUN_CLASSES: tuple[str, ...] = (CHEAP, STANDARD, DEEP, RULE_PRIOR)

# The classes that may reach the Oracle. A cheap run never does, and a rule
# prior run makes no model call at all.
ORACLE_CLASSES: frozenset[str] = frozenset({STANDARD, DEEP})


@dataclass(frozen=True)
class ClassPlan:
    """The class a run starts in, and why.

    ``forces_loop`` is True when the request alone demands the loop. A planned
    ``standard`` that comes from the rungs does not force it: the pipeline's
    own loop rule decides, exactly as before the classes existed.
    """

    run_class: RunClass
    reason: str
    forces_loop: bool


def plan_run_class(
    *,
    requested: str | None,
    subject_is_hunt: bool,
    round1_can_settle: bool,
    session_true_positive: bool,
    fast_triage_enabled: bool,
) -> ClassPlan:
    """Plan the class from the request and the rungs above the model.

    Order of the rules, first match wins:

    1. A deep request is deep.
    2. A hunt subject is standard. A hunt is read with the tools.
    3. A standard request is standard: an analyst's Investigate, a re-run, a
       promotion. It runs the loop even where a template could settle the
       alert, because a person asked for an investigation.
    4. With fast triage off, every alert runs the loop.
    5. A true positive already stands on this session. The loop runs.
    6. A dispositive template cleared the alert: cheap.
    7. Otherwise: standard.
    """
    if requested == DEEP:
        return ClassPlan(DEEP, "deep_rerun", forces_loop=True)
    if subject_is_hunt:
        # The pipeline already sends every hunt subject to the loop: round 1
        # cannot settle a hunt. The plan does not force it a second time.
        return ClassPlan(STANDARD, "hunt_subject", forces_loop=False)
    if requested == STANDARD:
        return ClassPlan(STANDARD, "analyst_run", forces_loop=True)
    if not fast_triage_enabled:
        return ClassPlan(STANDARD, "fast_triage_disabled", forces_loop=False)
    if session_true_positive:
        return ClassPlan(STANDARD, "session_true_positive_stands", forces_loop=False)
    if round1_can_settle:
        return ClassPlan(CHEAP, "dispositive_template", forces_loop=False)
    return ClassPlan(STANDARD, "no_dispositive_template", forces_loop=False)


def ran_class(plan: ClassPlan, *, ran_loop: bool) -> RunClass:
    """The class that ran.

    A planned cheap run that never entered the loop is cheap. A planned cheap
    run that entered the loop escalated to standard. A planned standard run is
    standard whether or not the loop ran: with ``investigate_when_unsure`` off
    the operator switched the loop off, and the standard path of that
    deployment is round 1 plus the Oracle. A deep plan always forces the loop.
    """
    if plan.run_class == DEEP:
        return DEEP
    if plan.run_class == CHEAP and not ran_loop:
        return CHEAP
    return STANDARD


# ── Planes: what the alert is made of ───────────────────────────────────────
#
# The standard class sends the loop only the prompt sections and the tool
# schemas the alert's planes make useful (stage 1, item 5). The loop prompt is
# 40,018 characters and the 26 tool schemas add about 7,000 tokens to every
# request; a flow-only alert to the internet has no use for the Kerberos and
# ADMIN$ rule, the decoy rule or the PsExec query example.
#
# A plane is a cheap fact about the prefetch, never a judgement. When in doubt
# a plane is ON: a section the alert does not need costs tokens, a section it
# needs and does not get costs a verdict.

PLANE_NETWORK = "network"  # the alert names a flow: an address or a session
PLANE_EXTERNAL = "external"  # an endpoint or an indicator outside the estate
PLANE_EAST_WEST = "east_west"  # both endpoints inside the estate
PLANE_WINDOWS = "windows"  # host logs, AD protocols or an attack-class rule
PLANE_HOSTILE = "hostile"  # the rule claims malware, an attack or high severity
PLANE_PAYLOAD = "payload"  # the alert carries matched bytes
PLANE_FILE = "file"  # the alert or its session carries a file hash
PLANE_ICMP = "icmp"  # an ICMP alert or a solicited echo exchange
PLANE_DECOY = "decoy"  # a deception sensor

_WINDOWS_MODULES = frozenset(
    {
        "windows",
        "sysmon",
        "endpoint",
        "system",
        "powershell",
        "winlog",
        "kerberos",
        "windows_defender",
    }
)
_WINDOWS_DATASET_PREFIXES = ("windows", "endpoint", "sysmon", "winlog", "system.security")
_AD_RULE_TOKENS = (
    "kerberos",
    "smb",
    "dcerpc",
    "dce_rpc",
    "ntlm",
    "ldap",
    "winrm",
    "psexec",
    "mimikatz",
    "dcsync",
    "active directory",
    "rdp",
    # Lateral movement and remote execution over Windows protocols. The stage
    # 1 eval of 2026-10-05 lost the WMI remote execution scenario (2 of 5 to
    # 0 of 5): the rule said "WMI Remote Method Invocation", the alert was an
    # informational east-west flow, and no token lit the Windows plane, so the
    # loop ran without the lateral-movement section and read the host as calm.
    "wmi",
    "dcom",
    "remote method",
    "remote exec",
    "lateral",
    "admin$",
    "admin share",
    "schtasks",
    "pass the hash",
    "pass-the-hash",
    "golden ticket",
    "kerberoast",
    "powershell",
    "sysmon",
)

# The pivots of the alert's own session that name a Windows protocol. A
# Suricata alert on an internal flow carries none of the AD fields itself; the
# community id pivot does.
_WINDOWS_TYPED_FIELDS = (
    "kerberos_ciphers",
    "kerberos_services",
    "smb_actions",
    "smb_file_names",
    "smb_mapping_services",
    "dce_rpc_endpoints",
    "dce_rpc_operations",
)


def _ip_is_internal(value: str | None, enrichments: dict[str, object]) -> bool | None:
    """Internal per the prefetch enrichment, else per the address itself. None: unknown."""
    import ipaddress  # noqa: PLC0415 - lazy

    if not value:
        return None
    flagged = getattr(enrichments.get(value), "internal", None)
    if isinstance(flagged, bool):
        return flagged
    try:
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        return None


def alert_planes(enriched: object) -> frozenset[str]:
    """The planes of one prefetched alert. Never raises: a fault turns every plane on."""
    try:
        return _alert_planes(enriched)
    except Exception:
        return frozenset(
            {
                PLANE_NETWORK,
                PLANE_EXTERNAL,
                PLANE_EAST_WEST,
                PLANE_WINDOWS,
                PLANE_HOSTILE,
                PLANE_PAYLOAD,
                PLANE_FILE,
                PLANE_ICMP,
                PLANE_DECOY,
            }
        )


def _alert_planes(enriched: object) -> frozenset[str]:
    from soc_ai.agent.decision_templates import (  # noqa: PLC0415 - avoid a cycle
        _alert_signals_decoy,
    )
    from soc_ai.agent.prompts import _rule_claims  # noqa: PLC0415 - avoid a cycle

    alert = getattr(enriched, "alert", None)
    enrichments = dict(getattr(enriched, "enrichments", None) or {})
    typed = getattr(enriched, "typed_zeek", None)
    planes: set[str] = set()

    src = getattr(alert, "source_ip", None)
    dst = getattr(alert, "destination_ip", None)
    if src or dst or getattr(alert, "network_community_id", None):
        planes.add(PLANE_NETWORK)
    sides = [_ip_is_internal(ip, enrichments) for ip in (src, dst) if ip]
    if any(side is False for side in sides) or any(
        getattr(entry, "internal", None) is False for entry in enrichments.values()
    ):
        planes.add(PLANE_EXTERNAL)
    if len(sides) == 2 and all(side is True for side in sides):
        planes.add(PLANE_EAST_WEST)

    module = str(getattr(alert, "event_module", "") or "").lower()
    dataset = str(getattr(alert, "event_dataset", "") or "").lower()
    rule = str(getattr(alert, "rule_name", "") or "").lower()
    claims_malware, claims_hostile = _rule_claims(enriched)
    ad_fields = any(
        getattr(alert, name, None)
        for name in (
            "zeek_kerberos_cipher",
            "zeek_kerberos_service",
            "zeek_smb_action",
            "zeek_smb_name",
            "zeek_dce_rpc_endpoint",
            "user_name",
            "process_entity_id",
        )
    )
    ad_pivots = any(getattr(typed, name, None) for name in _WINDOWS_TYPED_FIELDS)
    if (
        module in _WINDOWS_MODULES
        or dataset.startswith(_WINDOWS_DATASET_PREFIXES)
        or ad_fields
        or ad_pivots
        or any(token in rule for token in _AD_RULE_TOKENS)
        or (claims_hostile and PLANE_EAST_WEST in planes)
        or (claims_hostile and PLANE_NETWORK not in planes)
    ):
        planes.add(PLANE_WINDOWS)
    if claims_malware or claims_hostile:
        planes.add(PLANE_HOSTILE)

    if getattr(alert, "payload_printable", None) or (getattr(alert, "raw", None) or {}).get(
        "payload"
    ):
        planes.add(PLANE_PAYLOAD)
    if (
        getattr(alert, "file_hash_sha256", None)
        or getattr(alert, "zeek_files_sha256", None)
        or getattr(alert, "zeek_files_md5", None)
        or getattr(typed, "file_sha256s", None)
        or getattr(typed, "file_md5s", None)
    ):
        planes.add(PLANE_FILE)
    if "icmp" in rule or getattr(typed, "icmp_echo_request_reply", False):
        planes.add(PLANE_ICMP)
    if alert is not None and _alert_signals_decoy(alert):
        planes.add(PLANE_DECOY)
    return frozenset(planes)


# The read tools the standard loop always sees. Chosen from the tool usage on
# both stores (survey 2026-10-04, section 3.3, and the range store read for
# stage 1): these are the tools a triage loop calls. Every other tool stays
# registered and is one ``search_tools`` call away.
STANDARD_CORE_TOOLS: frozenset[str] = frozenset(
    {
        "t_query_events_oql",
        "t_rule_prevalence",
        "t_prevalence",
        "t_host_dossier",
        "t_host_summary",
        "t_origin_chain",
        "t_get_event_raw",
        "t_field_values",
        "t_query_cases",
        "t_get_rule_content",
        # The not-found hint of t_get_rule_content names it, and 6 of 8
        # search_tools calls on the range eval of 2026-10-05 loaded it.
        "t_query_detections",
        "t_enrich_ip",
        # Registered only where the grid keeps playbooks (W1), and then the
        # conditional-tool block may name it.
        "t_get_playbooks",
    }
)


def standard_visible_tools(planes: frozenset[str]) -> frozenset[str]:
    """The read tools a standard loop sees for an alert with these planes."""
    visible = set(STANDARD_CORE_TOOLS)
    if PLANE_NETWORK in planes:
        visible.add("t_query_zeek_logs")
    if PLANE_EXTERNAL in planes:
        visible.update({"t_web_search", "t_enrich_domain"})
    if PLANE_PAYLOAD in planes:
        visible.add("t_decode_payload")
    if PLANE_FILE in planes:
        visible.add("t_enrich_hash")
    if PLANE_HOSTILE in planes and PLANE_NETWORK in planes:
        # Packet-level confirmation is for a hostile claim on a flow.
        visible.add("t_get_pcap")
    return frozenset(visible)


__all__ = [
    "CHEAP",
    "DEEP",
    "ORACLE_CLASSES",
    "PLANE_DECOY",
    "PLANE_EAST_WEST",
    "PLANE_EXTERNAL",
    "PLANE_FILE",
    "PLANE_HOSTILE",
    "PLANE_ICMP",
    "PLANE_NETWORK",
    "PLANE_PAYLOAD",
    "PLANE_WINDOWS",
    "RULE_PRIOR",
    "RUN_CLASSES",
    "STANDARD",
    "STANDARD_CORE_TOOLS",
    "ClassPlan",
    "RequestedClass",
    "RunClass",
    "alert_planes",
    "plan_run_class",
    "ran_class",
    "standard_visible_tools",
]
