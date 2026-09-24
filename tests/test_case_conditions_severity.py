"""A critical detection invites the origin-chain pivot (2026-09-19).

The range's DCSync alert is a Sigma rule: no Suricata classtype, no malware
token in its name, severity critical. The two rule-class predicates read it as
routine, so the user message said "None of the conditional tools applies to
this alert. Do not call them", and the loop obeyed: "the conditional tools say
none applies, so I should not call origin chain" (01M2X1N6, seq 13). It then
stopped with "from which host" as an open question. The detector's own
severity is its claim of a hostile act, and that claim is what the origin-chain
condition asks for.
"""

from __future__ import annotations

from typing import Any

from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext


def _sigma(
    severity_label: str | None,
    rule_name: str = "Active Directory Replication from Non Machine Account",
) -> Any:
    return EnrichedAlertContext(
        alert=SoAlert(
            id="alert-dcsync",
            rule_name=rule_name,
            host_ip=["10.20.30.11"],
            event_module="sigma",
            severity_label=severity_label,
        )
    )


def _render(enriched: Any) -> str:
    from soc_ai.agent.prompts import _format_investigator_prompt, case_conditions

    conditions = case_conditions(enriched, playbooks_available=False, web_search_available=True)
    return _format_investigator_prompt("alert-dcsync", "{}", conditions=conditions)


def test_a_critical_sigma_detection_on_an_internal_host_names_the_origin_chain() -> None:
    """The DCSync alert: no classtype, no malware token, severity critical."""
    rendered = _render(_sigma("critical"))
    assert "t_origin_chain" in rendered
    assert "None of the conditional tools applies" not in rendered


def test_a_high_severity_detection_names_it_too() -> None:
    assert "t_origin_chain" in _render(_sigma("high"))


def test_a_low_severity_detection_on_an_internal_host_does_not() -> None:
    """NEGATIVE CONTROL: an informational or low detection is the ordinary
    case on a grid, and chasing who drove the host costs a turn for nothing."""
    for label in ("low", "informational", "medium", None):
        rendered = _render(
            _sigma(label, rule_name="Security Onion - Grid Node Login Failure (SSH)")
        )
        assert "t_origin_chain" not in rendered, label


def test_a_critical_detection_from_outside_does_not_chase_the_victim() -> None:
    """NEGATIVE CONTROL: the actor has to be internal. A critical rule on
    an inbound exploit from the internet names the attacker, and the victim
    host was not driven by anyone."""
    from soc_ai.tools.enrichment import IndicatorEnrichment

    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="alert-inbound",
            rule_name="ET EXPLOIT Successful Apache ActiveMQ Remote Code Execution",
            source_ip="203.0.113.10",
            destination_ip="10.20.30.41",
            severity_label="high",
        ),
        enrichments={
            "203.0.113.10": IndicatorEnrichment(
                indicator="203.0.113.10", indicator_type="ip", internal=False
            ),
            "10.20.30.41": IndicatorEnrichment(
                indicator="10.20.30.41", indicator_type="ip", internal=True
            ),
        },
    )
    assert "t_origin_chain" not in _render(enriched)
