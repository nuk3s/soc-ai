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
