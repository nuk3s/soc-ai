"""A gate that changes a verdict keeps the text of the model (B2, 2026-11-13).

Review 2026-11-12, console finding 1. On run 01M6WEC0CG156GP1YX38YEAKV5 the
largest text of the report page was "soc-ai changed the verdict from a true
positive to needs more info". The Open questions card repeated that sentence.
The facts sat in the body. The headline also feeds the list rows and the bell.

The rule for every gate that lowers or changes a verdict:

- No gate writes to the summary. The text of the model stays whole.
- The change is one record on the report, ``verdict_change``: the gate, the
  verdict before and after, the reason and the missing evidence.
- The page prints the reason as one labeled line, and Open questions lists
  the missing evidence.
- The headline never contradicts the final verdict. A gate that lowers a
  claim to needs more info leaves the sentence of the model as the headline.
  A gate that refutes a claim puts its reason there, and the text of the
  model stays in the report under its own key.
"""

from __future__ import annotations

import ast
import asyncio
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.models.test import TestModel
from soc_ai.agent import gates
from soc_ai.agent.gates import (
    _HOST_ANCHORED_TP_LEAD,
    VERDICT_CHANGE_GATES,
    RunText,
    _downgrade_unevidenced_verdict,
    _downgrade_ungrounded_host_anchored_tp,
    _enforce_decisive_value_support,
    _refuse_benign_decoy_verdict,
    _synth_first_post_validate,
    enforce_session_verdict_consistency,
    is_refutation,
    oracle_view,
    report_text,
    run_text,
    strip_stored_gate_lead,
    verdict_change_from_audit,
    verdict_change_line,
)
from soc_ai.agent.orchestrator import investigate
from soc_ai.agent.triage import TriageReport
from soc_ai.api.recorder import InvestigationRecorder, _first_rationale
from soc_ai.api.webui import _timeline
from soc_ai.config import Settings
from soc_ai.so_client.models import SoAlert
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Investigation
from soc_ai.tools.get_alert_context import EnrichedAlertContext

from tests import test_hunt_subject as hs
from tests.test_agent import (
    _bpfdoor_tp_report,
    _make_ctx,
    _make_vpn_icmp_enriched,
    _run_synth_first_icmp_investigation,
)
from tests.test_validator_model_variance import _icmp_bundle, _tool_evidence
from tests.test_webui_api import _client

MODEL_TEXT = (
    "Host ws-1 opened a TLS session to a developer domain. Two sandbox reports "
    "flag the URL. The host contacted the domain on 7 days."
)
MODEL_HEADLINE = "Host ws-1 opened a TLS session to a developer domain"
HOST_GATE = "ungrounded_host_anchored_tp_downgrade"


def _report(verdict: str = "true_positive", **over: Any) -> TriageReport:
    base: dict[str, Any] = {
        "verdict": verdict,
        "confidence": 0.85,
        "summary": MODEL_TEXT,
        "citations": ["alert.rule_name"],
        "recommended_actions": [],
    }
    base.update(over)
    return TriageReport(**base)


# ── each gate keeps the summary and leaves a record ───────────────────────────


def _fire_host_history() -> tuple[Any, dict[str, Any]]:
    audit: dict[str, Any] = {}
    out = _downgrade_ungrounded_host_anchored_tp(_report(), _make_vpn_icmp_enriched(), audit)
    return out, audit


def _fire_icmp() -> tuple[Any, dict[str, Any]]:
    report = _report(citations=["bpfdoor-icmp-001", "alert.classtype"])
    return _synth_first_post_validate(
        report,
        _icmp_bundle(),
        candidate=None,
        targeted_messages=_tool_evidence(),
        targeted_tool_called=None,
        synthesis_confidence_floor=0.6,
    )


def _fire_evidence_gate() -> tuple[Any, dict[str, Any]]:
    audit: dict[str, Any] = {}
    out = _downgrade_unevidenced_verdict(
        _report(),
        _make_vpn_icmp_enriched(),
        None,
        audit,
        targeted_messages=None,
        targeted_tool_called=None,
    )
    return out, audit


def _fire_decisive_value() -> tuple[Any, dict[str, Any]]:
    audit: dict[str, Any] = {}
    report = _report(summary=MODEL_TEXT + " The C2 address is 185.220.101.47.")
    out = _enforce_decisive_value_support(
        report,
        _make_vpn_icmp_enriched(),
        audit,
        targeted_messages=None,
        targeted_tool_results=None,
    )
    return out, audit


def _fire_decoy() -> tuple[Any, dict[str, Any]]:
    audit: dict[str, Any] = {}
    enriched = EnrichedAlertContext(
        alert=SoAlert(id="canary-0001", event_dataset="opencanary", event_module="opencanary")
    )
    out = _refuse_benign_decoy_verdict(_report("false_positive"), enriched, audit)
    return out, audit


def _fire_floor() -> tuple[Any, dict[str, Any]]:
    report = _report(confidence=0.3, citations=[])
    return _synth_first_post_validate(
        report,
        _make_vpn_icmp_enriched(),
        candidate=None,
        targeted_messages=_tool_evidence(),
        targeted_tool_called=None,
        synthesis_confidence_floor=0.6,
    )


def _fire_malware_name() -> tuple[Any, dict[str, Any]]:
    enriched = _make_vpn_icmp_enriched()
    enriched.alert = SoAlert(
        id="malware-0001",
        rule_name="ET MALWARE Example Trojan Checkin",
        classtype="trojan-activity",
        source_ip="192.0.2.1",
        destination_ip="10.0.0.100",
    )
    enriched.host_alert_profile = {}
    return _synth_first_post_validate(
        _report(citations=["alert.rule_name"]),
        enriched,
        candidate=None,
        targeted_messages=None,
        targeted_tool_called=None,
        synthesis_confidence_floor=0.6,
    )


def _fire_session() -> tuple[Any, dict[str, Any]]:
    out, audit = enforce_session_verdict_consistency(
        _report("false_positive"),
        [{"id": "01PRIOR0000000000000000000", "verdict": "true_positive", "confidence": 0.8}],
    )
    assert audit is not None
    return out, {"session_verdict_conflict": audit}


_FIRE = {
    "verdict_floor_rewrite": _fire_floor,
    "icmp_solicited_downgrade": _fire_icmp,
    "malware_rule_name_ungrounded_downgrade": _fire_malware_name,
    "decoy_benign_verdict_refused": _fire_decoy,
    HOST_GATE: _fire_host_history,
    "unsupported_decisive_value_downgrade": _fire_decisive_value,
    "evidence_gate_downgrade": _fire_evidence_gate,
    "session_verdict_conflict": _fire_session,
}


@pytest.mark.parametrize("gate", sorted(_FIRE))
def test_a_gate_keeps_the_model_text_and_records_its_change(gate: str) -> None:
    out, audit = _FIRE[gate]()
    assert gate in audit, f"the fixture did not fire {gate}: {sorted(audit)}"
    original = (
        MODEL_TEXT + " The C2 address is 185.220.101.47."
        if gate == "unsupported_decisive_value_downgrade"
        else MODEL_TEXT
    )
    # No gate writes to the summary: the text of the model is whole.
    assert out.summary == original
    change = verdict_change_from_audit(audit)
    assert change is not None
    assert change["gate"] == gate
    assert change["to_verdict"] == out.verdict
    assert change["from_verdict"] != change["to_verdict"]
    assert change["reason"]
    stored = {**out.model_dump(mode="json"), **report_text(out.summary, change)}
    if out.verdict == "needs_more_info":
        # The claim stands, unproven: the sentence of the model is the
        # headline, and Open questions has evidence to ask for.
        assert _first_rationale(stored) == MODEL_HEADLINE
        assert "model_summary" not in stored
        assert change["missing"], gate
    else:
        # The claim is refuted: the reason of the gate is the headline, and
        # the text of the model has its own key.
        assert stored["summary"] == change["reason"]
        assert stored["model_summary"] == original
        assert MODEL_HEADLINE not in (_first_rationale(stored) or "")
        assert change["missing"] == []


def test_each_gate_of_the_table_has_a_fixture_or_a_stated_reason() -> None:
    """The no-baseline gate needs a catalog spec to fire. Its text is checked
    on a hand-built audit entry below. Each other gate fires above."""
    keys = {key for key, _field in VERDICT_CHANGE_GATES}
    # The vote is a step of the pipeline, tested on its own entry below.
    assert keys - set(_FIRE) == {"no_baseline_verdict_refused", "self_consistency_vote"}
    assert keys == set(gates._VERDICT_CHANGE_TEXT)


# The functions of gates.py that write a summary by rule: the copy for the
# Oracle, the text keys of the stored report and the reader of a stored run.
_SUMMARY_WRITERS_BY_RULE = frozenset({"oracle_view", "report_text", "run_text"})


def _summary_writes(source: str, allowed: frozenset[str] = _SUMMARY_WRITERS_BY_RULE) -> list[str]:
    """Each place in *source* where a function writes ``summary``.

    The class guard of the rule "no gate writes to the summary". It reads the
    syntax tree, so a write through a variable, a dict update, ``setattr`` or
    an attribute is found as a dict literal is.
    """
    offenders: list[str] = []
    for func in ast.walk(ast.parse(source)):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef) or func.name in allowed:
            continue
        for node in ast.walk(func):
            where = f"{func.name}:{getattr(node, 'lineno', 0)}"
            if isinstance(node, ast.Dict):
                keys = [k.value for k in node.keys if isinstance(k, ast.Constant)]
                if "summary" in keys:
                    offenders.append(f"{where} dict key")
            elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
                if isinstance(node.slice, ast.Constant) and node.slice.value == "summary":
                    offenders.append(f"{where} item write")
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                if node.attr == "summary":
                    offenders.append(f"{where} attribute write")
            elif isinstance(node, ast.Call):
                if any(kw.arg == "summary" for kw in node.keywords):
                    offenders.append(f"{where} keyword")
                name = node.func.id if isinstance(node.func, ast.Name) else None
                if name == "setattr" and len(node.args) >= 2:
                    target = node.args[1]
                    if not isinstance(target, ast.Constant) or target.value == "summary":
                        offenders.append(f"{where} setattr")
                if isinstance(node.func, ast.Attribute) and node.func.attr == "model_copy":
                    for kw in node.keywords:
                        if kw.arg == "update" and not isinstance(kw.value, ast.Dict):
                            offenders.append(f"{where} update is no dict literal")
                        if kw.arg is None:
                            offenders.append(f"{where} update through **")
    return offenders


def test_no_gate_writes_the_summary() -> None:
    """The class guard. No function of gates.py writes ``summary``, by any
    syntax. A new gate that does fails here."""
    offenders = _summary_writes(Path(gates.__file__).read_text(encoding="utf-8"))
    assert not offenders, offenders


@pytest.mark.parametrize(
    "body",
    [
        'return report.model_copy(update={"verdict": "x", "summary": "gate text"})',
        'changes = {"verdict": "x"}\n    changes["summary"] = "gate text"\n'
        "    return report.model_copy(update=changes)",
        'changes = {"verdict": "x"}\n    return report.model_copy(update=changes)',
        'changes = dict(summary="gate text")\n    return report.model_copy(update=changes)',
        'changes = {}\n    changes.update({"summary": "gate text"})\n    return changes',
        'changes = {}\n    changes.update(summary="gate text")\n    return changes',
        'setattr(report, "summary", "gate text")\n    return report',
        'setattr(report, field, "gate text")\n    return report',
        'report.summary = "gate text"\n    return report',
        'return TriageReport(verdict="x", summary="gate text")',
        'return report.model_copy(**{"update": changes})',
    ],
)
def test_the_guard_finds_each_way_to_write_the_summary(body: str) -> None:
    """The guard of the guard. Each body writes the summary in another syntax:
    a dict literal, a variable, a dict update, ``setattr``, an attribute."""
    source = f"def _new_gate(report, field, changes=None):\n    {body}\n"
    assert _summary_writes(source), body


def test_the_guard_passes_a_gate_that_keeps_the_summary() -> None:
    """Negative control: a gate that changes the verdict and the note only."""
    source = (
        "def _new_gate(report):\n"
        '    return report.model_copy(update={"verdict": "x", "validator_note": "n"})\n'
    )
    assert _summary_writes(source) == []


# ── the record ────────────────────────────────────────────────────────────────


def test_the_host_history_record_lists_concrete_missing_evidence() -> None:
    _out, audit = _fire_host_history()
    change = verdict_change_from_audit(audit)
    assert change == {
        "gate": HOST_GATE,
        "from_verdict": "true_positive",
        "to_verdict": "needs_more_info",
        "reason": (
            "The run found no direct evidence of an attack beyond the alert history of the host."
        ),
        "missing": [
            "A blocklist or MISP entry that matches an indicator.",
            "A record of the host with content of the event that the report cites by its "
            "id. Examples are a payload, an HTTP record and a DNS record.",
            "Attack evidence in the report beyond the alert history of the host. "
            "Examples are a beacon, a payload, a web shell and a path traversal.",
        ],
        "steps": [
            {
                "gate": HOST_GATE,
                "from_verdict": "true_positive",
                "to_verdict": "needs_more_info",
                "reason": (
                    "The run found no direct evidence of an attack beyond the alert "
                    "history of the host."
                ),
            }
        ],
    }
    assert verdict_change_line(change) == (
        "soc-ai changed the verdict from a true positive to needs more info. The run "
        "found no direct evidence of an attack beyond the alert history of the host."
    )


def test_a_finding_run_asks_for_a_record_of_the_finding() -> None:
    change = verdict_change_from_audit(
        {
            HOST_GATE: {
                "original_verdict": "true_positive",
                "downgraded_verdict": "needs_more_info",
                "on_finding": True,
            }
        }
    )
    assert change is not None
    assert any("among the documents that the finding cites" in m for m in change["missing"])
    assert any(
        "content of the event that the report cites by its id" in m for m in change["missing"]
    )


def test_the_no_baseline_record_names_the_spec_and_its_exceptions() -> None:
    change = verdict_change_from_audit(
        {
            "no_baseline_verdict_refused": {
                "spec_id": "identity-4662-dcsync-nonmachine",
                "original_verdict": "false_positive",
                "capped_verdict": "needs_more_info",
                "exceptions": ["The account of the directory sync appliance."],
            }
        }
    )
    assert change is not None
    assert "identity-4662-dcsync-nonmachine" in change["reason"]
    assert change["missing"] == [
        "Whether the principal is this exception of the spec: The account of the "
        "directory sync appliance.",
        "What drove the principal at that moment.",
    ]


def test_two_gates_name_the_first_verdict_and_the_last_gate() -> None:
    """The ICMP gate sets a false positive, and the decoy gate then refuses it.
    The record names the verdict of the model and the gate that set the
    verdict that stands, and it lists each step in order."""
    change = verdict_change_from_audit(
        {
            "icmp_solicited_downgrade": {
                "original_verdict": "true_positive",
                "downgraded_verdict": "false_positive",
            },
            "decoy_benign_verdict_refused": {
                "original_verdict": "false_positive",
                "capped_verdict": "needs_more_info",
            },
        }
    )
    assert change is not None
    assert change["gate"] == "decoy_benign_verdict_refused"
    assert (change["from_verdict"], change["to_verdict"]) == ("true_positive", "needs_more_info")
    assert [(s["gate"], s["from_verdict"], s["to_verdict"]) for s in change["steps"]] == [
        ("icmp_solicited_downgrade", "true_positive", "false_positive"),
        ("decoy_benign_verdict_refused", "false_positive", "needs_more_info"),
    ]
    assert all(step["reason"] for step in change["steps"])


def test_the_session_gate_after_the_icmp_gate_keeps_the_verdict_of_the_model() -> None:
    """Review defect 9. The model said true positive, the ICMP gate set a
    false positive and the same-session gate then held needs more info. The
    record named the false positive as the origin."""
    _out, icmp_audit = _fire_icmp()
    _held, session_audit = _fire_session()
    change = verdict_change_from_audit({**icmp_audit, **session_audit})
    assert change is not None
    assert change["gate"] == "session_verdict_conflict"
    assert (change["from_verdict"], change["to_verdict"]) == ("true_positive", "needs_more_info")
    assert [s["gate"] for s in change["steps"]] == [
        "icmp_solicited_downgrade",
        "session_verdict_conflict",
    ]
    # The final verdict is unsettled, so the claim is lowered and not refuted.
    assert not is_refutation(change)
    assert report_text(MODEL_TEXT, change) == {"summary": MODEL_TEXT}


def test_one_gate_has_one_step() -> None:
    change = verdict_change_from_audit(_fire_host_history()[1])
    assert change is not None
    assert [(s["gate"], s["from_verdict"], s["to_verdict"]) for s in change["steps"]] == [
        (HOST_GATE, "true_positive", "needs_more_info")
    ]


def test_the_vote_records_its_change_as_the_first_step() -> None:
    """The self-consistency vote runs before the gates. A vote that changes
    the verdict of the first report is a step of the record."""
    split = verdict_change_from_audit(
        {
            "self_consistency_vote": {
                "original_verdict": "true_positive",
                "voted_verdict": "inconclusive",
                "tally": {"true_positive": 1, "false_positive": 1},
            }
        }
    )
    assert split is not None
    assert split["gate"] == "self_consistency_vote"
    assert (split["from_verdict"], split["to_verdict"]) == ("true_positive", "inconclusive")
    assert split["missing"]
    assert not is_refutation(split)

    majority = verdict_change_from_audit(
        {
            "self_consistency_vote": {
                "original_verdict": "true_positive",
                "voted_verdict": "false_positive",
            },
            "evidence_gate_downgrade": {
                "original_verdict": "false_positive",
                "capped_verdict": "needs_more_info",
            },
        }
    )
    assert majority is not None
    assert majority["from_verdict"] == "true_positive"
    assert [s["gate"] for s in majority["steps"]] == [
        "self_consistency_vote",
        "evidence_gate_downgrade",
    ]


def test_a_vote_for_a_settled_verdict_is_no_refutation() -> None:
    """Negative control. The report after a vote is a sample that reached the
    voted verdict, so its text agrees with the verdict and stays the summary."""
    change = verdict_change_from_audit(
        {
            "self_consistency_vote": {
                "original_verdict": "true_positive",
                "voted_verdict": "false_positive",
            }
        }
    )
    assert change is not None
    assert not is_refutation(change)
    assert report_text(MODEL_TEXT, change) == {"summary": MODEL_TEXT}


def test_a_vote_that_keeps_the_verdict_is_no_change() -> None:
    assert (
        verdict_change_from_audit(
            {
                "self_consistency_vote": {
                    "original_verdict": "false_positive",
                    "voted_verdict": "false_positive",
                }
            }
        )
        is None
    )


@pytest.mark.parametrize(
    "audit",
    [
        {},
        None,
        {"citation_cap": {"original_confidence": 0.9, "capped_confidence": 0.8}},
        {HOST_GATE: {"reason": "an entry with no verdict pair"}},
        {HOST_GATE: {"original_verdict": "true_positive", "downgraded_verdict": "true_positive"}},
    ],
)
def test_an_audit_with_no_verdict_change_gives_no_record(audit: Any) -> None:
    """Negative control: a gate that changed no verdict puts no line on the page."""
    assert verdict_change_from_audit(audit) is None


def test_the_text_of_each_record_reads_in_ste() -> None:
    samples = [verdict_change_from_audit(fire()[1]) for fire in _FIRE.values()]
    samples.append(
        verdict_change_from_audit(
            {
                "no_baseline_verdict_refused": {
                    "spec_id": "spec-1",
                    "original_verdict": "false_positive",
                    "capped_verdict": "needs_more_info",
                }
            }
        )
    )
    for change in samples:
        assert change is not None
        for text in [verdict_change_line(change), *change["missing"]]:
            # No en dash, no em dash, no arrow and no parenthetical aside.
            assert not re.search("[–—→(]", text), text
            assert "true_positive" not in text
            assert "needs_more_info" not in text
            for sentence in re.split(r"(?<=\.)\s+", text):
                assert len(sentence.split()) <= 25, sentence


# ── the Oracle and the stored rows ────────────────────────────────────────────


def test_the_oracle_copy_opens_with_the_change_and_the_report_does_not() -> None:
    out, audit = _fire_host_history()
    change = verdict_change_from_audit(audit)
    view = oracle_view(out, change)
    assert view.summary == f"{_HOST_ANCHORED_TP_LEAD} {MODEL_TEXT}"
    assert out.summary == MODEL_TEXT
    assert oracle_view(out, None) is out

    evidence_out, evidence_audit = _fire_evidence_gate()
    evidence_view = oracle_view(evidence_out, verdict_change_from_audit(evidence_audit))
    assert evidence_view.summary.startswith(
        "soc-ai changed the verdict from a true positive to needs more info. The verdict "
        "rests on the alert fields only."
    )
    assert evidence_view.summary.endswith(MODEL_TEXT)


def test_a_stored_lead_is_removed_at_read_time() -> None:
    assert strip_stored_gate_lead(f"{_HOST_ANCHORED_TP_LEAD} {MODEL_TEXT}") == MODEL_TEXT
    assert (
        strip_stored_gate_lead("soc-ai changed the verdict from a true positive to needs more info")
        == ""
    )
    # Negative control: any other text is unchanged.
    assert strip_stored_gate_lead(MODEL_TEXT) == MODEL_TEXT
    assert strip_stored_gate_lead(None) == ""


# ── the pipeline ──────────────────────────────────────────────────────────────


async def _run_finding(settings: Settings) -> list[Any]:
    """A finding run whose local true positive the host history gate lowers.
    The Oracle is off, so the local verdict stands."""
    settings.investigate_when_unsure = True
    settings.oracle_enabled = False
    ctx = hs._make_ctx(settings)
    subject = hs._subject()
    local = _report(citations=["host_alert_profile"])

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        enriched = hs._enriched(alert_id)
        enriched.host_alert_profile = {"ET EXPLOIT Example PHP Code Injection in Filename": 12}
        return enriched

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=hs._fake_investigator()),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer", return_value=hs._fake_loop_synth(local)
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            MagicMock(return_value=None),
        ),
        patch("soc_ai.store.investigations.session_verdicts", AsyncMock(return_value=[])),
        patch("soc_ai.agent.orchestrator.maybe_auto_ack_fp", AsyncMock(return_value=None)),
    ):
        return [ev async for ev in investigate(hs.ANCHOR_ID, ctx=ctx, subject=subject)]


async def test_the_stored_report_keeps_the_model_text_and_carries_the_change(
    settings_kratos: Settings,
) -> None:
    events = await _run_finding(settings_kratos)
    assert any(e.kind == HOST_GATE for e in events)
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "needs_more_info"
    assert final["summary"] == MODEL_TEXT
    assert _first_rationale(final) == MODEL_HEADLINE
    change = final["verdict_change"]
    assert change["gate"] == HOST_GATE
    assert (change["from_verdict"], change["to_verdict"]) == ("true_positive", "needs_more_info")
    assert change["missing"]


async def test_a_run_with_no_gate_change_has_no_record(settings_kratos: Settings) -> None:
    """Negative control: the key is absent, so every other report keeps its shape."""
    events, _spies = await hs._run(
        settings_kratos,
        subject=hs._subject(),
        report=_report("false_positive", citations=[hs.ANCHOR_ID]),
    )
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert "verdict_change" not in final


# ── the headline never contradicts the final verdict ──────────────────────────
#
# A gate that LOWERS a claim to needs more info leaves the claim unproven: the
# sentence of the model stays the headline, and the Verdict change line
# follows. A gate that REFUTES the claim sets a settled verdict that the
# sentence of the model contradicts. A false positive row with the headline
# "BPFDoor ICMP heartbeat confirms a C2 tunnel" tells the analyst two things.
# So the reason of the gate is the headline of a refuted run, in the stored
# summary and in the stored headline, which every list and the page read. The
# text of the model stays in the report under its own key, ``model_summary``.

ICMP_HEADLINE = "The traffic is an echo request and its reply between two internal hosts"


def test_a_change_to_a_settled_verdict_is_a_refutation() -> None:
    icmp = verdict_change_from_audit(_fire_icmp()[1])
    assert is_refutation(icmp)
    assert is_refutation({"from_verdict": "false_positive", "to_verdict": "true_positive"})


@pytest.mark.parametrize("gate", sorted(set(_FIRE) - {"icmp_solicited_downgrade"}))
def test_a_change_to_needs_more_info_is_no_refutation(gate: str) -> None:
    """Negative control: every other gate lowers a claim. None refutes one."""
    assert not is_refutation(verdict_change_from_audit(_FIRE[gate]()[1]))


def test_no_change_is_no_refutation() -> None:
    assert not is_refutation(None)
    assert not is_refutation({})
    assert not is_refutation({"from_verdict": "true_positive", "to_verdict": "true_positive"})


def test_a_refuted_report_leads_with_the_reason_and_keeps_the_model_text() -> None:
    out, audit = _fire_icmp()
    change = verdict_change_from_audit(audit)
    assert change is not None
    fields = report_text(out.summary, change)
    assert fields == {"summary": change["reason"], "model_summary": MODEL_TEXT}
    assert _first_rationale({**fields, "recommended_actions": []}) == ICMP_HEADLINE


def test_a_lowered_report_keeps_the_model_text_as_its_summary() -> None:
    """Negative control: a needs more info run shows the sentence of the model."""
    out, audit = _fire_host_history()
    fields = report_text(out.summary, verdict_change_from_audit(audit))
    assert fields == {"summary": MODEL_TEXT}
    assert report_text(MODEL_TEXT, None) == {"summary": MODEL_TEXT}


def test_the_headline_of_a_refuted_report_ignores_an_action_of_the_model() -> None:
    """The first action rationale is the headline of a normal report. On a
    refuted report it is a sentence of the model, so the reason wins."""
    report = {
        "summary": "The traffic is an echo request and its reply. No entry matches.",
        "model_summary": MODEL_TEXT,
        "recommended_actions": [{"rationale": "Confirmed C2. Escalate the host."}],
    }
    assert _first_rationale(report) == "The traffic is an echo request and its reply"
    # Negative control: a normal report keeps the rationale of its first action.
    normal = {"summary": MODEL_TEXT, "recommended_actions": [{"rationale": "Escalate the host."}]}
    assert _first_rationale(normal) == "Escalate the host."


async def _icmp_run(settings: Settings) -> list[Any]:
    return await _run_synth_first_icmp_investigation(_make_ctx(settings))


async def test_a_refuted_run_stores_the_reason_as_its_summary(settings_kratos: Settings) -> None:
    model_text = _bpfdoor_tp_report().summary
    events = await _icmp_run(settings_kratos)
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "false_positive"
    assert final["verdict_change"]["gate"] == "icmp_solicited_downgrade"
    assert final["summary"] == final["verdict_change"]["reason"]
    assert final["model_summary"] == model_text
    assert _first_rationale(final) == ICMP_HEADLINE
    assert model_text not in final["summary"]


async def test_a_refuted_row_shows_no_sentence_of_the_model_in_any_list(
    settings_kratos: Settings,
) -> None:
    """The stored row is what each list reads: the headline column, the
    summary column, and the digests that the store builds from them."""
    from soc_ai.hunting.hunt_words import first_sentence
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
    from soc_ai.store.investigations import _digest_rationale

    model_text = _bpfdoor_tp_report().summary
    model_sentences = [s.strip() for s in model_text.split(". ") if s.strip()]
    events = await _icmp_run(settings_kratos)

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    recorder = InvestigationRecorder(maker, alert_id="bpfdoor-icmp-001", started_by="tester")
    await recorder.start()
    for event in events:
        await recorder.record(event.kind, event.sequence, event.payload)
    await recorder.finish("complete")
    async with maker() as db:
        row = await db.get(Investigation, recorder.investigation_id)
    await engine.dispose()

    assert row is not None
    assert row.verdict == "false_positive"
    assert row.rationale == ICMP_HEADLINE
    list_texts = [
        row.rationale or "",
        row.summary or "",
        first_sentence(row.summary or ""),
        _digest_rationale(row.rationale) or "",
    ]
    for text in list_texts:
        for sentence in model_sentences:
            assert sentence not in text, (sentence, text)
    # The text of the model is in the report, under its own key.
    assert row.report["model_summary"] == model_text
    text = run_text(row.report, rationale=row.rationale, summary=row.summary)
    assert text == RunText(
        headline=ICMP_HEADLINE, summary=row.report["summary"], model_text=model_text
    )


async def test_a_lowered_row_still_shows_the_sentence_of_the_model(
    settings_kratos: Settings,
) -> None:
    """Negative control: needs more info keeps the claim of the model as the
    headline. The reader adds no label for the text of the model."""
    events = await _run_finding(settings_kratos)
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "needs_more_info"
    assert "model_summary" not in final
    text = run_text(final, rationale=_first_rationale(final), summary=final["summary"])
    assert text == RunText(headline=MODEL_HEADLINE, summary=MODEL_TEXT, model_text=None)


def test_the_reader_repairs_the_rows_of_older_releases() -> None:
    """One reader for every stored shape, where the stored data allows."""
    # 2026-10-30 to B2: the lead of the host history gate opens the summary.
    lowered = run_text(
        {"summary": f"{_HOST_ANCHORED_TP_LEAD} {MODEL_TEXT}"},
        rationale="soc-ai changed the verdict from a true positive to needs more info",
        summary=None,
    )
    assert lowered == RunText(headline=MODEL_TEXT, summary=MODEL_TEXT, model_text=None)
    # Before B2: the solicited ICMP gate wrote its own summary and kept the
    # text of the model at the end of the validator note.
    icmp = run_text(
        {
            "summary": "Solicited internal ICMP echo request/reply between two internal hosts.",
            "validator_note": (
                "Verdict auto-corrected by the solicited-ICMP-echo validator. The reason. "
                f"Original agent summary: {MODEL_TEXT}"
            ),
        },
        rationale="Solicited internal ICMP echo request/reply between two internal hosts",
        summary=None,
    )
    assert icmp.headline == "Solicited internal ICMP echo request/reply between two internal hosts"
    assert icmp.model_text == MODEL_TEXT
    # Negative control: a row with no gate text reads as it is stored.
    plain = run_text({"summary": MODEL_TEXT}, rationale=MODEL_HEADLINE, summary=MODEL_TEXT)
    assert plain == RunText(headline=MODEL_HEADLINE, summary=MODEL_TEXT, model_text=None)
    assert run_text(None, rationale=None, summary=None) == RunText("", "", None)


async def test_the_session_gate_adds_its_step_to_the_record_of_the_run(
    settings_kratos: Settings,
) -> None:
    """Review defect 9, through the pipeline. The ICMP gate sets a false
    positive and the same-session gate then holds needs more info. The record
    keeps the true positive of the model as its origin and lists both steps."""

    def _held(report: Any, _digests: Any) -> tuple[Any, dict[str, Any] | None]:
        if report.verdict != "false_positive":
            return report, None
        return (
            report.model_copy(update={"verdict": "needs_more_info", "recommended_actions": []}),
            {
                "original_verdict": "false_positive",
                "held_verdict": "needs_more_info",
                "prior_investigation_id": "01PRIOR0000000000000000000",
            },
        )

    with patch("soc_ai.agent.orchestrator.enforce_session_verdict_consistency", _held):
        events = await _icmp_run(settings_kratos)
    final = next(e.payload for e in events if e.kind == "triage_report")
    change = final["verdict_change"]
    assert final["verdict"] == "needs_more_info"
    assert (change["from_verdict"], change["to_verdict"]) == ("true_positive", "needs_more_info")
    assert [s["gate"] for s in change["steps"]] == [
        "icmp_solicited_downgrade",
        "session_verdict_conflict",
    ]
    # The claim is lowered, so the text of the model is the summary again.
    assert final["summary"] == _bpfdoor_tp_report().summary
    assert "model_summary" not in final


async def test_a_vote_that_changes_the_verdict_is_in_the_record(settings_kratos: Settings) -> None:
    """The vote changed a verdict and set no record. The samples split, so
    the verdict of the first report becomes inconclusive."""
    from tests.test_agent import _run_synth_first

    settings_kratos.verdict_consistency_samples = 2
    settings_kratos.investigate_when_unsure = False
    report = _report("false_positive", citations=["alert.rule_name"])
    with patch(
        "soc_ai.agent.orchestrator._self_consistency_vote",
        lambda _reports: ("inconclusive", 0.5, "self-consistency split 2 ways"),
    ):
        events = await _run_synth_first(_make_ctx(settings_kratos), report=report)
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "inconclusive"
    change = final["verdict_change"]
    assert change["gate"] == "self_consistency_vote"
    assert (change["from_verdict"], change["to_verdict"]) == ("false_positive", "inconclusive")
    assert change["missing"]


async def test_a_vote_that_keeps_the_verdict_sets_no_record(settings_kratos: Settings) -> None:
    """Negative control: the samples agree with the first report."""
    from tests.test_agent import _run_synth_first

    settings_kratos.verdict_consistency_samples = 2
    settings_kratos.investigate_when_unsure = False
    report = _report("false_positive", citations=["alert.rule_name"])
    events = await _run_synth_first(_make_ctx(settings_kratos), report=report)
    assert any(e.kind == "self_consistency_vote" for e in events)
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert (
        "verdict_change" not in final or final["verdict_change"]["gate"] != "self_consistency_vote"
    )


# ── the API ───────────────────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _seed(client: TestClient, *, report: dict[str, Any], rationale: str, events: list[Any]) -> str:
    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(db, alert_es_id="es-gate-change", started_by="tester")
            if events:
                await inv_svc.append_events(db, inv.id, events)
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict=str(report["verdict"]),
                confidence=0.5,
                rationale=rationale,
                report=report,
            )
            return str(inv.id)

    return asyncio.run(_go())


def test_the_api_serves_the_change_and_the_missing_evidence(client: TestClient) -> None:
    _out, audit = _fire_host_history()
    change = verdict_change_from_audit(audit)
    assert change is not None
    inv_id = _seed(
        client,
        report={"verdict": "needs_more_info", "summary": MODEL_TEXT, "verdict_change": change},
        rationale=MODEL_HEADLINE,
        events=[
            {
                "sequence": 1,
                "kind": "investigation_transcript",
                "payload": {"open_questions": ["Which process opened the session?"]},
            }
        ],
    )
    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["rationale"] == MODEL_HEADLINE
    assert body["verdictChange"] == {
        "gate": HOST_GATE,
        "fromVerdict": "true_positive",
        "toVerdict": "needs_more_info",
        "reason": change["reason"],
        "missing": change["missing"],
        "steps": [
            {"gate": HOST_GATE, "fromVerdict": "true_positive", "toVerdict": "needs_more_info"}
        ],
    }
    # The missing evidence comes first, then the question of the run.
    assert body["openQuestions"] == [*change["missing"], "Which process opened the session?"]


def test_the_api_repairs_a_row_of_an_older_release(client: TestClient) -> None:
    """The stored shape of run 01M6WEC0CG156GP1YX38YEAKV5: the lead in the
    summary, its first sentence as the headline, and a gate event."""
    inv_id = _seed(
        client,
        report={
            "verdict": "needs_more_info",
            "summary": f"{_HOST_ANCHORED_TP_LEAD} {MODEL_TEXT}",
        },
        rationale="soc-ai changed the verdict from a true positive to needs more info",
        events=[
            {
                "sequence": 1,
                "kind": HOST_GATE,
                "payload": {
                    "original_verdict": "true_positive",
                    "downgraded_verdict": "needs_more_info",
                    "reason": "No blocklist or MISP entry matches an indicator.",
                },
            }
        ],
    )
    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["rationale"] == MODEL_TEXT
    assert body["summary"] == [{"t": "text", "v": MODEL_TEXT}]
    assert body["verdictChange"]["gate"] == HOST_GATE
    assert body["verdictChange"]["toVerdict"] == "needs_more_info"
    assert body["openQuestions"] == body["verdictChange"]["missing"]
    assert body["openQuestions"]


def test_an_oracle_verdict_on_an_older_row_shows_no_gate_line(client: TestClient) -> None:
    """Negative control. The Oracle restored the true positive, so the verdict
    of the gate no longer stands and the page states no change."""
    inv_id = _seed(
        client,
        report={
            "verdict": "true_positive",
            "summary": "[Oracle adjudicated] The claim is confirmed on the wire.",
            "local_verdict": "needs_more_info",
        },
        rationale="[Oracle adjudicated] The claim is confirmed on the wire",
        events=[
            {
                "sequence": 1,
                "kind": HOST_GATE,
                "payload": {
                    "original_verdict": "true_positive",
                    "downgraded_verdict": "needs_more_info",
                },
            }
        ],
    )
    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["verdictChange"] is None
    assert body["openQuestions"] == []


def test_the_open_questions_of_a_run_with_no_change_are_unchanged() -> None:
    """Negative control on the helper the focused re-run reads."""
    report = {"verdict": "needs_more_info", "open_questions": ["Did a session complete?"]}
    assert _timeline._open_questions_out(report, []) == ["Did a session complete?"]
    assert _timeline._verdict_change_out(report, []) is None


def test_the_api_serves_a_refuted_run_with_the_reason_as_its_headline(client: TestClient) -> None:
    out, audit = _fire_icmp()
    change = verdict_change_from_audit(audit)
    assert change is not None
    fields = report_text(out.summary, change)
    inv_id = _seed(
        client,
        report={"verdict": "false_positive", "verdict_change": change, **fields},
        rationale=ICMP_HEADLINE,
        events=[],
    )
    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["rationale"] == ICMP_HEADLINE
    assert body["summary"] == [{"t": "text", "v": change["reason"]}]
    assert body["modelText"] == MODEL_TEXT
    assert body["verdictChange"]["toVerdict"] == "false_positive"
    # A refuted run settles the verdict, so it asks no open question.
    assert body["openQuestions"] == []
    assert MODEL_HEADLINE not in body["rationale"]


def test_the_api_serves_no_model_text_for_a_lowered_run(client: TestClient) -> None:
    """Negative control: the summary of a needs more info run is the text of
    the model, so the page needs no second copy."""
    _out, audit = _fire_host_history()
    change = verdict_change_from_audit(audit)
    inv_id = _seed(
        client,
        report={"verdict": "needs_more_info", "summary": MODEL_TEXT, "verdict_change": change},
        rationale=MODEL_HEADLINE,
        events=[],
    )
    body = client.get(f"/api/v1/investigations/{inv_id}").json()
    assert body["rationale"] == MODEL_HEADLINE
    assert body["modelText"] is None
