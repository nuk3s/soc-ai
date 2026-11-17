"""The high-stakes guard and an Informational rule (review 2026-11-13, D4).

Production, 2026-10-31 to 2026-11-13: 274 confident false positives waited for
a manual acknowledge with the reason ``high_stakes``. 131 of them were one
rule, "ET USER_AGENTS Steam HTTP Client User-Agent". Security Onion gave the
alert the severity high. The author of the rule declared the signature
severity Informational.

Security Onion takes the severity of a Suricata alert from the priority of its
classification. "Potential Corporate Privacy Violation" has priority 1, so
every rule of that classification reads as high. The signature severity is the
statement of the rule author about that one rule.

The severity arm of the guard no longer holds an alert when all of these are
true: the severity is high, the signature severity is Informational, and no
other arm fires. The negative controls below plant each case the change must
not reach.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.agent.orchestrator import _is_high_stakes_alert, maybe_auto_ack_fp
from soc_ai.config import Settings
from soc_ai.so_client.models import RuleMetadata, SoAlert

from tests import test_autotriage as autotriage_tests
from tests.test_autotriage import (
    _FakeState,
    _seed_investigation,
    at_settings,  # noqa: F401 - the shared fixture
)

_STEAM = "ET USER_AGENTS Steam HTTP Client User-Agent"
_PRIVACY = "Potential Corporate Privacy Violation"


def _alert(**over: Any) -> SoAlert:
    """The Steam alert of the review, field for field, with overrides."""
    fields: dict[str, Any] = {
        "id": "ev-steam",
        "rule_name": _STEAM,
        "classtype": _PRIVACY,
        "severity_label": "high",
        "severity_score": 3,
        "event_module": "suricata",
        "event_dataset": "suricata.alert",
        "rule_metadata": RuleMetadata(signature_severity="Informational"),
    }
    fields.update(over)
    return SoAlert(**fields)


# ── The change ──────────────────────────────────────────────────────────────


def test_an_informational_rule_with_high_severity_is_not_high_stakes() -> None:
    assert _is_high_stakes_alert(_alert()) is False


@pytest.mark.parametrize(
    ("label", "score"),
    [("high", None), (None, 3), ("HIGH", 3), (" High ", None)],
)
def test_each_form_of_the_high_severity_reads_the_same(
    label: str | None, score: int | None
) -> None:
    alert = _alert(severity_label=label, severity_score=score)
    assert _is_high_stakes_alert(alert) is False


# ── Negative controls: each case the change must not reach ──────────────────


@pytest.mark.parametrize(
    "classtype",
    [
        "Attempted Administrator Privilege Gain",
        "Web Application Attack",
        "A Network Trojan was detected",
        "Malware Command and Control Activity Detected",
        # In the attack set of the Oracle guard, and in no class of the map
        # that the first arm reads as an exploit.
        "Attempted Information Leak",
    ],
)
def test_an_exploit_or_malware_classification_stays_high_stakes(classtype: str) -> None:
    """The classification arm fires first. The signature severity cannot lower it."""
    alert = _alert(rule_name="ET WEB_SERVER request", classtype=classtype)
    assert _is_high_stakes_alert(alert) is True


def test_a_malware_token_in_the_rule_name_stays_high_stakes() -> None:
    alert = _alert(rule_name="ET MALWARE BPFDoor ICMP beacon", classtype="Misc activity")
    assert _is_high_stakes_alert(alert) is True


def test_a_deception_sensor_stays_high_stakes() -> None:
    """A decoy hit that carries the two fields of the change is still held."""
    alert = _alert(
        rule_name=None,
        classtype=None,
        event_dataset="opencanary.events",
        event_module="opencanary",
    )
    assert _is_high_stakes_alert(alert) is True


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        RuleMetadata(signature_severity=None),
        RuleMetadata(signature_severity="Minor"),
        RuleMetadata(signature_severity="Major"),
        RuleMetadata(attack_target="Client_Endpoint"),
    ],
)
def test_an_alert_with_no_informational_signature_severity_keeps_the_severity_arm(
    metadata: RuleMetadata | None,
) -> None:
    """High severity alone still holds the alert when the rule author said
    nothing, or said more than Informational."""
    assert _is_high_stakes_alert(_alert(rule_metadata=metadata)) is True


@pytest.mark.parametrize(
    ("label", "score"),
    [("critical", 4), ("critical", None), (None, 4), (None, 99), ("high", 4), ("critical", 3)],
)
def test_a_critical_severity_stays_high_stakes(label: str | None, score: int | None) -> None:
    """The priority of a Suricata classification gives high at most. A
    critical severity comes from another source, and it still holds the alert."""
    alert = _alert(severity_label=label, severity_score=score)
    assert _is_high_stakes_alert(alert) is True


def test_a_medium_informational_alert_was_never_high_stakes() -> None:
    """Control on the test itself: the guard is not always True."""
    assert _is_high_stakes_alert(_alert(severity_label="medium", severity_score=2)) is False


# ── The two write paths obey the same function ──────────────────────────────


def _auto_ack(alert: SoAlert) -> tuple[Any, AsyncMock]:
    helper = autotriage_tests.TestMaybeAutoAckFp
    ctx = helper._make_ctx({"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7})
    report = helper._make_report(verdict="false_positive", confidence=0.9)
    emit, audit, _ = helper._make_emit_audit()
    write = AsyncMock(return_value=({"ok": True}, None))
    with patch("soc_ai.agent.orchestrator.execute_write_tool", write):
        result = asyncio.run(
            maybe_auto_ack_fp(
                report,
                alert.id,
                alert=alert,
                ctx=ctx,
                emit_ev=emit,
                audit_ev=audit,
                investigated=True,
            )
        )
    return result, write


def test_the_direct_auto_ack_writes_the_informational_alert() -> None:
    result, write = _auto_ack(_alert())
    write.assert_awaited_once()
    assert write.await_args is not None and write.await_args.args[1] == {"alert_id": "ev-steam"}
    assert result is not None and result.kind == "auto_ack"


def test_the_direct_auto_ack_holds_an_exploit_alert_of_the_same_severity() -> None:
    """NEGATIVE CONTROL on the write path. Same severity, same signature
    severity, an exploit classification: the ack waits for a person."""
    result, write = _auto_ack(_alert(classtype="Web Application Attack"))
    write.assert_not_awaited()
    assert result is not None and result.kind == "auto_ack_skipped"
    assert result.payload["reason"] == "high_stakes"


def _grid_hit(es_id: str, *, category: str, signature_severity: str | None) -> dict[str, Any]:
    """An alert document the way the grid stores it."""
    rule: dict[str, Any] = {"name": _STEAM}
    if signature_severity is not None:
        rule["metadata"] = {"signature_severity": [signature_severity]}
    return {
        "_id": es_id,
        "_source": {
            "@timestamp": "2026-11-10T06:41:00.000Z",
            "source": {"ip": "10.0.0.41"},
            "destination": {"ip": "203.0.113.9"},
            "rule": rule,
            "event": {
                "severity_label": "high",
                "severity": 3,
                "module": "suricata",
                "dataset": "suricata.alert",
            },
            "message": f'{{"alert": {{"category": "{category}"}}}}',
        },
    }


def test_the_inherited_ack_obeys_the_same_function(at_settings: Settings) -> None:  # noqa: F811
    """The inherited path acks an alert on the verdict of another alert. The
    guard is the only check on the alert that the write reaches.

    Three alerts of one cluster, all with the severity high. The Informational
    alert is acknowledged. The exploit alert and the alert with no signature
    severity wait for a person.
    """
    from soc_ai.webui import autotriage as at

    es = AsyncMock()
    es.search.return_value = {
        "took": 1,
        "hits": {
            "total": {"value": 3, "relation": "eq"},
            "hits": [
                _grid_hit("ev-info", category=_PRIVACY, signature_severity="Informational"),
                _grid_hit(
                    "ev-exploit",
                    category="Web Application Attack",
                    signature_severity="Informational",
                ),
                _grid_hit("ev-unsaid", category=_PRIVACY, signature_severity=None),
            ],
        },
    }
    state = _FakeState(at_settings, es)
    source = _seed_investigation(at_settings, rule_name=_STEAM, alert_es_id="src-ev")
    autotriage_tests.TestInheritedFpAutoAck._grounded_source(at_settings, source)
    status = at.AutoTriageStatus()
    acks = [
        at.InheritedAck(alert_es_id=i, rule_name=_STEAM, inherited_from=source, confidence=0.9)
        for i in ("ev-info", "ev-exploit", "ev-unsaid")
    ]
    ctx = SimpleNamespace(auth=AsyncMock(), settings=at_settings, audit=None)

    write = AsyncMock(return_value=({"ok": True}, None))
    with patch("soc_ai.tools.write_exec.execute_write_tool", write):
        asyncio.run(at._ack_inherited_fps(state, ctx, acks, status))

    write.assert_awaited_once()
    assert write.await_args is not None and write.await_args.args[1] == {"alert_id": "ev-info"}
    assert status.inherited_acked == 1
    assert status.inherited_refused == {"high_stakes": 2}


# ── The exception needs positive knowledge (review of the lane, defects 4, 6) ──
#
# The first version asked one question: is the signature Informational. An
# alert whose classification no arm could read then left the hold, because the
# arms above had nothing to read. The exception now holds unless the alert is
# Suricata, its classification is one that is high by its own priority and
# informational by its class, and every signature severity is Informational.


@pytest.mark.parametrize(
    ("case", "over"),
    [
        (
            "the message did not parse, so no classification was read",
            {"rule_name": "LOCAL SMB admin share write", "classtype": None},
        ),
        ("an empty classification", {"classtype": "  "}),
        (
            "a local classification",
            {"rule_name": "LOCAL lateral tool transfer", "classtype": "Local Lateral Movement"},
        ),
        (
            "an unrouted classification with an explicit priority 1",
            {
                "rule_name": "LOCAL suspicious filename",
                "classtype": "A suspicious filename was detected",
            },
        ),
        (
            "an informational classification of priority 3 with an explicit priority 1",
            {"rule_name": "LOCAL raised rule", "classtype": "Misc activity"},
        ),
        (
            "a document that is not Suricata",
            {
                "rule_name": "Sigma rule",
                "event_module": "sigma",
                "event_dataset": "sigma.alert",
                "classtype": None,
            },
        ),
        (
            "a document that is not Suricata and copies the classification",
            {"event_module": "sigma", "event_dataset": "sigma.alert"},
        ),
        ("a document that names no producer", {"event_module": None, "event_dataset": None}),
        (
            "two producers in one document",
            {"event_module": "suricata", "event_dataset": "zeek.notice"},
        ),
    ],
)
def test_an_alert_that_the_guard_cannot_read_stays_high_stakes(
    case: str, over: dict[str, Any]
) -> None:
    """NEGATIVE CONTROL: each input of the review. Absence is never a reason."""
    assert _is_high_stakes_alert(_alert(**over)) is True, case


@pytest.mark.parametrize(
    ("values", "held"),
    [
        (["Informational", "Major"], True),
        (["Major", "Informational"], True),
        (["Informational", "Minor"], True),
        (["Informational", "Unheard-of"], True),
        (["Informational", "Informational"], False),
        (["Informational"], False),
        ("Informational", False),
    ],
)
def test_every_signature_severity_must_be_informational(values: Any, held: bool) -> None:
    """The first of two values decided, so the order of a list changed the answer."""
    metadata = RuleMetadata.from_rule_metadata_block({"signature_severity": values})
    assert _is_high_stakes_alert(_alert(rule_metadata=metadata)) is held


def test_the_most_severe_signature_severity_stands_for_the_rule() -> None:
    read = RuleMetadata.from_rule_metadata_block
    assert read({"signature_severity": ["Informational", "Major"]}).signature_severity == "Major"
    assert read({"signature_severity": ["Critical", "Minor"]}).signature_severity == "Critical"
    assert read({"signature_severity": ["Minor"]}).signature_severity == "Minor"
    assert read({"signature_severity": [None, " "], "tag": ["x"]}).signature_severity is None


@pytest.mark.parametrize(
    ("rule_name", "classtype"),
    [
        (_STEAM, _PRIVACY),
        ("ET POLICY PE EXE or DLL Windows file download HTTP", _PRIVACY),
        ("LOCAL policy rule", "policy-violation"),
        ("LOCAL content rule", "Inappropriate Content was Detected"),
    ],
)
def test_the_reach_of_the_exception(rule_name: str, classtype: str) -> None:
    """What leaves the hold, stated so the owner sees it: a Suricata rule of
    a classification that is high by its own priority and informational by
    its class, which its author declared Informational. The second row is the
    rule the review names."""
    assert _is_high_stakes_alert(_alert(rule_name=rule_name, classtype=classtype)) is False
