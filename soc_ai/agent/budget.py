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

import re
from dataclasses import dataclass
from typing import Any, Final, Literal

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


# ── The report a run hands the analyst ──────────────────────────────────────
#
# A cheap run is one synthesis request, so the round-1 report IS the report.
# Production, 2026-10-31 to 2026-11-13 (review 2026-11-13, triage finding 8):
# 24 of 29 cheap runs wrote to the prompt, not to the analyst. A summary began
# "Keep the candidate verdict. I refine confidence from 0.85 to 0.80." The row
# headline read "The verdict is decisive and the payload plus clean conn
# provide positive evidence." Seven runs offered a comment on a case that did
# not exist, and none offered Acknowledge.
#
# The prompt carries the contract now (soc_ai.agent.prompts, the round-1
# rubric). A prompt is a request, so the cheap class also settles the report
# in code. The verdict, the confidence and the citations stay the model's.

# A sentence the round-1 model writes to the prompt. Only the exact forms: a
# whole sentence, in the first person or in the imperative the model copies
# from the prompt, that states that it keeps, refines or adjusts the candidate
# verdict or the confidence, and states nothing else. "Keep the candidate
# verdict." and "I refine confidence from 0.85 to 0.80." are the two
# production forms.
#
# The first version matched a phrase anywhere in a sentence, and it deleted
# evidence: "The ICE agent kept the candidate from 10.20.30.20 and sent STUN
# binding requests to 142.250.82.127:19302." went whole (review of the lane).
# A sentence with a reason after it ("I keep the candidate because ...") is no
# exact form and stays. A missed echo costs one odd sentence. A wrong strip
# costs the analyst the evidence.
_PROMPT_TALK = re.compile(
    r"(?:I\s+)?(?:keep|refine|adjust)\s+the\s+candidate(?:\s+verdict)?"
    r"(?:\s+of\s+`?(?:false[_ ]positive|true[_ ]positive|needs[_ ]more[_ ]info)`?)?"
    r"|(?:I\s+)?(?:keep|refine|adjust|raise|lower|reduce|set|increase|decrease)\s+"
    r"(?:the\s+|my\s+)?confidence"
    r"(?:\s+(?:from\s+[01](?:\.\d+)?\s+)?to\s+[01](?:\.\d+)?)?",
    re.IGNORECASE,
)

# What marks a sentence as evidence, whatever else it says: a digit that is no
# confidence value (an address, a port, a count), or a dotted name (a dataset,
# a record name, a domain). Such a sentence is never stripped.
_CONFIDENCE_VALUE = re.compile(r"(?<![\w.])[01](?:\.\d+)?(?![\w.]*\w)")
_EVIDENCE_TOKEN = re.compile(r"\d|\w\.\w")

# The end of the first sentence: a full stop, a question mark or an
# exclamation mark before whitespace. A decimal point has a digit after it.
_FIRST_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def _is_prompt_talk(sentence: str) -> bool:
    """Whether ``sentence`` is an exact form of prompt talk and holds no evidence."""
    text = sentence.strip().rstrip(".!").strip()
    if _EVIDENCE_TOKEN.search(_CONFIDENCE_VALUE.sub("", text)):
        return False
    return _PROMPT_TALK.fullmatch(text) is not None


def _without_prompt_talk(text: str) -> tuple[str, int]:
    """``text`` without the sentences that answer the prompt, and the count removed.

    The text comes back empty when every sentence was prompt talk. The caller
    decides what stands in its place.
    """
    from soc_ai.agent.narrative_grounding import (  # noqa: PLC0415 - lazy
        _split_sentences,
        strip_sentences,
    )

    removed = sum(1 for sentence in _split_sentences(text) if _is_prompt_talk(sentence))
    if not removed:
        return text, 0
    return strip_sentences(text, _is_prompt_talk), removed


def _first_sentence(text: str) -> str:
    return _FIRST_SENTENCE_END.split(text.strip(), maxsplit=1)[0].strip()


# The reason of an Acknowledge that the cheap class adds when the summary has
# no sentence to lend it.
_ACK_REASON = "The verdict is false positive. Acknowledge the alert."


def settle_report_actions(
    report: Any,  # TriageReport
    *,
    alert_id: str,
    run_class: str,
) -> tuple[Any, dict[str, Any] | None]:
    """The report as the analyst gets it, and what changed, or None.

    Every class: a case comment that can have no case goes
    (:func:`soc_ai.triage_models.drop_case_comments_without_a_case`). The
    execute route refuses it, so the card would never run.

    The cheap class only, because its report is one round-1 synthesis:

    * The summary and each action reason lose the sentences that answer the
      prompt (:data:`_PROMPT_TALK`). A summary that was nothing else is kept
      as written: an empty summary reads as a failed run. A reason that was
      nothing else takes the first sentence of the summary, which is the
      headline the row falls back to when a report has no action.
    * A false positive offers Acknowledge. The model's own ``ack_alert`` is
      kept. With none, one is added for the alert of the run, after any action
      the model did write, so the model's first reason stays the headline.

    The acknowledge is an offer on a card. It writes nothing: the analyst
    executes it, or the auto-acknowledge decides on its own gates, which read
    the verdict and never this list. The verdict, the confidence and the
    citations are not touched. An unchanged report comes back as the same
    object, so a caller's identity checks hold.
    """
    from soc_ai.triage_models import (  # noqa: PLC0415 - lazy
        RecommendedAction,
        drop_case_comments_without_a_case,
    )

    actions, dropped = drop_case_comments_without_a_case(list(report.recommended_actions))
    summary = report.summary or ""
    removed = 0
    ack_added = False
    if run_class == CHEAP:
        stripped, cut = _without_prompt_talk(summary)
        if stripped.strip():
            summary, removed = stripped, cut
        first = _first_sentence(summary)
        headline = "" if _is_prompt_talk(first) else first
        for i, action in enumerate(actions):
            reason, cut = _without_prompt_talk(action.rationale or "")
            if not cut:
                continue
            reason = reason.strip() or headline
            if reason:
                removed += cut
                actions[i] = action.model_copy(update={"rationale": reason})
        if report.verdict == "false_positive" and not any(
            a.tool_name == "ack_alert" for a in actions
        ):
            actions.append(
                RecommendedAction(
                    tool_name="ack_alert",
                    tool_args={"alert_id": alert_id},
                    rationale=headline or _ACK_REASON,
                )
            )
            ack_added = True
    if not (dropped or removed or ack_added):
        return report, None
    settled = report.model_copy(update={"summary": summary, "recommended_actions": actions})
    return settled, {
        "dropped_case_comments": dropped,
        "prompt_talk_removed": removed,
        "ack_added": ack_added,
    }


# The reason and the case text of the Escalate that an Oracle true positive
# gets when its summary has no sentence to lend.
_ESCALATE_REASON = "The verdict is true positive. Open a case for this alert."
_ESCALATE_TITLE = "soc-ai investigation"


def oracle_true_positive_action(
    report: Any,  # TriageReport
    *,
    alert_id: str,
    rule_name: str | None,
) -> tuple[Any, bool]:
    """An Oracle true positive with the action a local true positive gets (H3).

    A local true positive recommends one ``escalate_to_case``: the prompt asks
    the model for it, with the alert id, a title and a description. The Oracle
    answers with a verdict and text, and it writes no action. Its report keeps
    the actions of the local report only when both agree on the verdict, so 5
    Oracle true positives on production offered nothing to act on (review
    2026-11-13, triage finding 7).

    The action is built from the run, the way the analyst override builds it
    (``routes_actions._override_actions``): the title is the rule name, the
    description is the summary, and the reason is the first sentence of the
    summary, which is then the row headline. An escalate that the report
    already holds stays, and no second one is added. Every other verdict
    comes back as the same object.

    The action is an offer on a card. It writes nothing: the analyst executes
    it, and the execute route binds the case to this run.
    """
    from soc_ai.tools.escalate_to_case import (  # noqa: PLC0415 - lazy
        fit_case_description,
        fit_case_title,
    )
    from soc_ai.triage_models import RecommendedAction  # noqa: PLC0415 - lazy

    if report.verdict != "true_positive":
        return report, False
    actions = list(report.recommended_actions)
    if any(a.tool_name == "escalate_to_case" for a in actions):
        return report, False
    summary = (report.summary or "").strip()
    actions.append(
        RecommendedAction(
            tool_name="escalate_to_case",
            tool_args={
                "alert_id": alert_id,
                "case_title": fit_case_title((rule_name or "").strip() or _ESCALATE_TITLE),
                "case_description": fit_case_description(summary or _ESCALATE_REASON),
            },
            rationale=_first_sentence(summary) or _ESCALATE_REASON,
        )
    )
    return report.model_copy(update={"recommended_actions": actions}), True


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
    "settle_report_actions",
    "standard_visible_tools",
]
