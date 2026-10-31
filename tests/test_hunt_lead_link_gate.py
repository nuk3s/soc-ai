"""A link between leads goes in the narrative, never in a finding (change E).

On 2026-10-24 a lead hunt wrote "Leads 47 and 48 are one campaign" as a high
threat finding. The hunt opened an investigation for it, and the run ended in
error at the 900 s limit. Another hunt wrote "Lead 47 and 49 are one campaign".
The gate below turns such a threat into an observation, so no investigation
opens for it, and the lead of such a hunt does not close as clean.

The data is synthetic: lead numbers, TEST-NET addresses, example titles.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.agent.hunt import HuntFinding, HuntReport
from soc_ai.agent.hunt_gates import (
    _HIGH_NO_CITE_NOTE,
    _LEAD_LINK_NOTE,
    _UNRESOLVED_NOTE,
    gate_lead_links,
    is_lead_link,
)
from soc_ai.api.hunt_runner import _gate_hunt_citations
from soc_ai.config import Settings
from soc_ai.hunting.findings import finding_is_subject
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import leads as leads_store

from tests.test_leads_store import _db, _hunt_row, _lead_row


def _finding(title: str, **over: Any) -> HuntFinding:
    fields: dict[str, Any] = {
        "title": title,
        "detail": "The two leads share one target and one window.",
        "severity": "high",
        "category": "threat",
        "hosts": ["192.0.2.10", "192.0.2.20"],
        "citations": [],
    }
    fields.update(over)
    return HuntFinding(**fields)


@pytest.mark.parametrize(
    "title",
    [
        "Leads 47 and 48 are one campaign",
        "Lead 47 and 49 are one campaign",
        "Lead 47 and lead 48 are one campaign",
        "Related leads share one target",
        "Both leads are one campaign",
    ],
)
def test_a_threat_that_links_leads_becomes_an_observation(title: str) -> None:
    finding = _finding(title)
    assert is_lead_link(finding) is True
    out, n = gate_lead_links([finding])
    assert n == 1
    assert out[0].category == "observation"
    assert out[0].severity == "info"
    assert out[0].validator_note == _LEAD_LINK_NOTE
    assert out[0].title == title
    assert finding_is_subject(out[0].model_dump()) is False


@pytest.mark.parametrize(
    "finding",
    [
        _finding("Two internal hosts drive the exploit campaign"),
        _finding("Successful SSH to victim by host-a"),
        _finding("Misleading banner on port 80"),
        _finding("Web shell upload", detail="The same host is on lead 47 too."),
        _finding("Lead-generating analytic not verifiable here", category="visibility_gap"),
    ],
)
def test_a_threat_on_activity_keeps_its_type(finding: HuntFinding) -> None:
    out, n = gate_lead_links([finding])
    assert n == 0
    assert out[0] == finding
    assert out[0].validator_note is None


@pytest.mark.parametrize("citations", [[], ["lead-obs-000047x"]])
def test_the_citation_gate_runs_the_lead_link_gate_last(citations: list[str]) -> None:
    """The citation gate caps an uncited high threat and strips a citation
    that resolves to nothing, and it writes its own note. The lead-link gate
    runs after it, so the note says why the type changed."""
    report = HuntReport(
        findings=[_finding("Leads 47 and 48 are one campaign", citations=citations)],
        narrative="Two leads on one web server.",
        affected_hosts=["192.0.2.10"],
        confidence=0.6,
    )
    events: list[tuple[str, dict[str, Any]]] = []

    def _ev(kind: str, payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        events.append((kind, payload))
        return kind, payload

    out, ev = _gate_hunt_citations(report, [], _ev)
    assert ev is not None
    finding = out.findings[0]
    assert (finding.category, finding.severity) == ("observation", "info")
    assert finding.validator_note == _LEAD_LINK_NOTE
    assert finding.validator_note not in (_UNRESOLVED_NOTE, _HIGH_NO_CITE_NOTE)
    assert events[0][0] == "citation_validation"
    assert events[0][1]["lead_links"] == 1


@pytest.mark.parametrize(("lead_links", "settled"), [(1, "waits"), (0, "closed")])
async def test_a_lead_hunt_whose_only_threat_links_leads_waits(
    settings_kratos: Settings, lead_links: int, settled: str
) -> None:
    """The lowered link leaves an observation and no threat, so the outcome
    reads clean. The structured count on the citation event keeps the lead
    from a clean close. The control: with no link, the lead closes."""
    lowered = gate_lead_links([_finding("Leads 47 and 48 are one campaign")])[0][0]
    hunt_id = f"01LEADLINK{lead_links}"
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        lead = await _lead_row(db, hunt_id=hunt_id)
        hunt = await _hunt_row(
            db, hunt_id=hunt_id, lead_id=lead.id, findings=[lowered.model_dump()]
        )
        await hunt_svc.append_events(
            db,
            hunt_id,
            [
                {
                    "kind": "citation_validation",
                    "sequence": 4,
                    "payload": {"round": 1, "findings": 1, "lead_links": lead_links},
                }
            ],
        )
        assert leads_store.hunt_outcome_of(hunt) == "clean"
        assert await leads_store.settle_after_hunt(db, hunt) == settled
        lead = await leads_store.get(db, lead.id)
    if settled == "waits":
        assert lead.status == "hunting"
        assert leads_store.hold_reason_of(lead) == leads_store.HOLD_LEAD_LINK == "lead_link"
        sentence = leads_store.HOLD_SENTENCES["lead_link"]
        assert sentence == "The hunt linked this lead to other leads."
    else:
        assert lead.status == "dismissed"
        assert lead.dismissed_reason == leads_store.HUNT_CLEAN_REASON
