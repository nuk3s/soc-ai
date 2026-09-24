"""Tests for :mod:`soc_ai.agent.classifier` (issue #18)."""

from __future__ import annotations

from soc_ai.agent.classifier import AlertClass, classify_alert
from soc_ai.so_client.models import RuleMetadata, SoAlert


def test_classify_uses_classtype_first() -> None:
    """Classtype is the strongest signal — it's rule-author-declared."""
    alert = SoAlert(
        id="a1",
        classtype="trojan-activity",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
    )
    # Classtype trumps signature_severity even when they disagree.
    assert classify_alert(alert) is AlertClass.POST_COMPROMISE


def test_classify_misc_activity_is_informational() -> None:
    alert = SoAlert(id="a", classtype="misc-activity")
    assert classify_alert(alert) is AlertClass.INFORMATIONAL_VISIBILITY


def test_classify_attempted_recon_is_recon() -> None:
    alert = SoAlert(id="a", classtype="attempted-recon")
    assert classify_alert(alert) is AlertClass.RECON


def test_classify_web_app_attack_is_exploit() -> None:
    alert = SoAlert(id="a", classtype="web-application-attack")
    assert classify_alert(alert) is AlertClass.EXPLOIT_ATTEMPT


def test_classify_command_and_control_is_post_compromise() -> None:
    alert = SoAlert(id="a", classtype="command-and-control")
    assert classify_alert(alert) is AlertClass.POST_COMPROMISE


def test_classify_falls_back_to_signature_severity() -> None:
    """When no classtype is present, signature_severity drives the bucket."""
    informational = SoAlert(id="a", rule_metadata=RuleMetadata(signature_severity="Informational"))
    assert classify_alert(informational) is AlertClass.INFORMATIONAL_VISIBILITY

    major = SoAlert(id="a", rule_metadata=RuleMetadata(signature_severity="Major"))
    assert classify_alert(major) is AlertClass.EXPLOIT_ATTEMPT

    critical = SoAlert(id="a", rule_metadata=RuleMetadata(signature_severity="Critical"))
    assert classify_alert(critical) is AlertClass.POST_COMPROMISE


def test_classify_unknown_when_no_signal() -> None:
    """No classtype, no rule_metadata → UNKNOWN (full pipeline)."""
    alert = SoAlert(id="a")
    assert classify_alert(alert) is AlertClass.UNKNOWN


def test_classify_does_not_use_rule_name() -> None:
    """Mitigation: classifier never reads rule_name strings (closed allowlist
    on metadata, not regex on names)."""
    # An alert with a misleading "ET INFO" rule name but a malicious classtype
    # must classify as POST_COMPROMISE — never fall back to the name prefix.
    alert = SoAlert(
        id="a",
        rule_name="ET INFO This Looks Benign But Isn't",
        classtype="trojan-activity",
    )
    assert classify_alert(alert) is AlertClass.POST_COMPROMISE


def test_classify_severity_case_insensitive() -> None:
    """Suricata sometimes lowercases the severity label; the classifier
    must not be case-sensitive."""
    alert = SoAlert(id="a", rule_metadata=RuleMetadata(signature_severity="INFORMATIONAL"))
    assert classify_alert(alert) is AlertClass.INFORMATIONAL_VISIBILITY


# ---------------------------------------------------------------------------
# What Security Onion actually puts in the classtype field
# ---------------------------------------------------------------------------
#
# SoAlert.classtype is parsed from Suricata EVE's ``alert.category``, and EVE
# writes the classification DESCRIPTION, not the shortname. Every classtype
# table in this codebase was keyed on shortnames, so on live data none of them
# ever matched. Measured across 180 recorded production runs, the distinct
# values were: "Misc activity" (77), "Device Retrieving External IP Address
# Detected" (27), "Not Suspicious Traffic" (26), "Potentially Bad Traffic" (18),
# "Potential Corporate Privacy Violation" (17), "Attempted Denial of Service"
# (6), "Attempted Information Leak" (4), "Malware Command and Control Activity
# Detected" (4), "Attempted Administrator Privilege Gain" (1). Not one of them
# is a shortname. The descriptions come from Suricata's own
# etc/classification.config, so the mapping is exact rather than heuristic.


def test_eve_description_maps_to_its_shortname() -> None:
    from soc_ai.agent.classifier import normalize_classtype

    assert normalize_classtype("Misc activity") == "misc-activity"
    assert normalize_classtype("Attempted Denial of Service") == "attempted-dos"
    assert normalize_classtype("Attempted Information Leak") == "attempted-recon"
    assert normalize_classtype("Malware Command and Control Activity Detected") == (
        "command-and-control"
    )
    assert normalize_classtype("Attempted Administrator Privilege Gain") == "attempted-admin"
    assert normalize_classtype("Potential Corporate Privacy Violation") == "policy-violation"
    assert normalize_classtype("Potentially Bad Traffic") == "bad-unknown"
    assert normalize_classtype("Not Suspicious Traffic") == "not-suspicious"
    assert normalize_classtype("Device Retrieving External IP Address Detected") == (
        "external-ip-check"
    )


def test_a_shortname_passes_through_unchanged() -> None:
    """NEGATIVE CONTROL. Rendered synthetic alerts and hand-written fixtures
    carry the shortname; normalizing must be idempotent on those."""
    from soc_ai.agent.classifier import normalize_classtype

    for short in ("misc-activity", "attempted-admin", "command-and-control", "policy-violation"):
        assert normalize_classtype(short) == short
    assert normalize_classtype(None) == ""
    assert normalize_classtype("  Misc Activity  ") == "misc-activity"
    assert normalize_classtype("something a ruleset invented") == "something a ruleset invented"


def test_classify_reads_the_eve_description() -> None:
    """The guard that decides whether an alert is too high-stakes to auto-ack
    runs through here. A denial-of-service alert was auto-acknowledged twice on
    the production instance because this returned UNKNOWN."""
    assert classify_alert(SoAlert(id="a", classtype="Attempted Denial of Service")) is (
        AlertClass.EXPLOIT_ATTEMPT
    )
    assert classify_alert(SoAlert(id="a", classtype="Misc activity")) is (
        AlertClass.INFORMATIONAL_VISIBILITY
    )
    assert classify_alert(SoAlert(id="a", classtype="Malware Command and Control Activity")) is (
        AlertClass.UNKNOWN
    )  # not a real description; no guessing
    assert (
        classify_alert(SoAlert(id="a", classtype="Malware Command and Control Activity Detected"))
        is AlertClass.POST_COMPROMISE
    )


# ── Every classification the table knows gets a routing decision ────────────
#
# The description table above enumerates all 43 of Suricata's classifications,
# but the routing map had an opinion about only 20 of them and the other 23 fell
# through to UNKNOWN in silence. That silence is what let a shellcode rule be
# acknowledged unattended: "GPL SHELLCODE x86 setgid 0" carries the category "A
# system call was detected", which the table normalizes correctly to
# system-call-detect and the routing map then had nothing to say about.
# 156 unattended acknowledgements across two shellcode rules on the production
# instance, three of them after the description fix went live.


def test_the_classtype_a_shellcode_rule_actually_carries_is_an_exploit() -> None:
    """The measured production alert, field for field.

    Severity is medium/2, below the severity arm of the high-stakes guard; the
    signature calls itself "Minor", which is not one of the three severities the
    fallback reads; and the rule name carries no malware token. The
    classification is the only signal there is, and it is a rule-author-declared
    one.
    """
    for rule_name in ("GPL SHELLCODE x86 setgid 0", "GPL SHELLCODE x86 setuid 0"):
        alert = SoAlert(
            id="a",
            rule_name=rule_name,
            classtype="A system call was detected",
            severity_label="medium",
            severity_score=2,
            rule_metadata=RuleMetadata(signature_severity="Minor"),
        )
        assert classify_alert(alert) is AlertClass.EXPLOIT_ATTEMPT, rule_name


def test_every_classification_the_table_knows_has_a_routing_decision() -> None:
    """No classification may fall through the routing map by accident.

    The fix for the shellcode hole is not one more entry, it is the rule that
    the classification table and the routing map cover the same ground: every
    shortname the table can produce is either mapped to a class or listed in
    ``_UNROUTED_CLASSTYPES`` on purpose. Adding a classification to the table
    without deciding what it means now fails here instead of quietly becoming
    UNKNOWN.
    """
    from soc_ai.agent.classifier import (
        _CLASSTYPE_DESCRIPTIONS,
        _CLASSTYPE_MAP,
        _UNROUTED_CLASSTYPES,
    )

    known = set(_CLASSTYPE_DESCRIPTIONS.values())
    decided = set(_CLASSTYPE_MAP) | _UNROUTED_CLASSTYPES
    assert not (known - decided), (
        f"classifications with no routing decision: {sorted(known - decided)}"
    )
    # No entry may be in both, and nothing may be parked in the unrouted set
    # that the table cannot actually produce (a dead entry hides a typo).
    assert not (set(_CLASSTYPE_MAP) & _UNROUTED_CLASSTYPES)
    assert not (_UNROUTED_CLASSTYPES - known)


def test_the_attack_classtypes_the_escalation_guard_uses_are_all_routed() -> None:
    """The auto-ack cap and the Oracle-escalation guard must not disagree.

    ``_ATTACK_CLASSTYPES`` is the escalation guard's own list of what counts as
    an attack. Every member of it has to land somewhere the routing map treats
    as more than UNKNOWN, or the two answer "is this an attack" differently.
    """
    from soc_ai.agent.classifier import _CLASSTYPE_MAP
    from soc_ai.agent.decision_templates import _ATTACK_CLASSTYPES

    unmapped = _ATTACK_CLASSTYPES - set(_CLASSTYPE_MAP)
    assert not unmapped, f"attack classtypes with no class: {sorted(unmapped)}"


def test_the_benign_classtypes_production_sends_stay_benign() -> None:
    """NEGATIVE CONTROL for the widening above.

    These are the classtype values actually measured on the production grid,
    in their EVE description form. Widening the routing map must not turn the
    ordinary FP population into high-stakes alerts. If it did, the auto-ack
    feature would be off rather than fixed.
    """
    benign = (
        "Misc activity",
        "Not Suspicious Traffic",
        "Potential Corporate Privacy Violation",
        "Device Retrieving External IP Address Detected",
        "Potentially Bad Traffic",
        "Generic Protocol Command Decode",
        "Unknown Traffic",
    )
    for description in benign:
        assert classify_alert(SoAlert(id="a", classtype=description)) not in (
            AlertClass.EXPLOIT_ATTEMPT,
            AlertClass.POST_COMPROMISE,
        ), description
