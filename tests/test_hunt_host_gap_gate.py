"""The hunt gate checks a host gap against the host's coverage.

A production hunt wrote "No host telemetry on <host> for attribution" as a
visibility gap. Its only evidence was two Elastic Defend queries that returned
zero. The host shipped system.syslog, system.auth and osquery through Elastic
Agent. The gate now reads the host's coverage, states the planes the host has
and the plane it lacks, and names the plane in the title.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.agent.hunt import HuntFinding, HuntReport
from soc_ai.agent.hunt_gates import gate_host_gaps
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult

from tests.test_dossier_coverage import host_logs_only_aggs

_HOST = "192.0.2.41"

# The production finding, anonymised: RFC 5737 address, example host names.
_GAP = HuntFinding(
    title="No host telemetry on app-01 for attribution",
    detail=(
        "Queries against endpoint.events.process and endpoint.events.network for "
        f"host.ip:{_HOST} return zero documents. This grid carries endpoint "
        "process/network data on other hosts such as build-01 and registry-01, but "
        "not on app-01. The recurring dead-domain DNS on app-01 therefore cannot be "
        "attributed to any process, and a malicious origin can neither be confirmed "
        "nor ruled out."
    ),
    severity="medium",
    category="visibility_gap",
    hosts=[_HOST],
    citations=[f"t_query_events_oql endpoint.events.process {_HOST}"],
)

_THREAT = HuntFinding(
    title="Recurring dead-domain DNS polling on app-01",
    detail="app-01 resolves two rare domains every five minutes.",
    severity="low",
    category="threat",
    hosts=[_HOST],
    citations=["doc-1"],
)


class _Settings:
    events_index_pattern = "logs-*"


class _FakeES:
    def __init__(self, aggregations: dict[str, Any] | None, error: Exception | None = None) -> None:
        self.aggregations = aggregations
        self.error = error
        self.calls = 0

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return EsSearchResult(total=1, took_ms=1, aggregations=self.aggregations)


def _report(*findings: HuntFinding) -> HuntReport:
    return HuntReport(findings=list(findings), narrative="Bottom line.")


@pytest.mark.asyncio
async def test_a_host_gap_on_a_covered_host_names_the_plane_it_lacks() -> None:
    es = _FakeES(host_logs_only_aggs())
    report, counts = await gate_host_gaps(_report(_THREAT, _GAP), elastic=es, settings=_Settings())

    threat, gap = report.findings
    assert threat == _THREAT  # a threat finding is not a gap; untouched
    assert gap.category == "visibility_gap"
    assert gap.title == "No process or endpoint network telemetry on app-01"
    assert gap.detail.startswith(
        "app-01 ships host logs (system.syslog 62,713, system.auth 11,309) and osquery "
        "(osquery_manager.result 2,623). app-01 ships no process events and no endpoint "
        "network events."
    )
    # The true, plane-level sentences survive.
    assert "return zero documents" in gap.detail
    for false_claim in ("no host telemetry", "no host-level"):
        assert false_claim not in gap.title.lower()
        assert false_claim not in gap.detail.lower()
    assert gap.validator_note is not None
    assert counts == {"host_gaps": 1, "host_gaps_rewritten": 1, "host_gaps_unread": 0}
    assert es.calls == 1


@pytest.mark.asyncio
async def test_an_unread_coverage_leaves_the_finding_and_says_so() -> None:
    es = _FakeES(None, error=TimeoutError("read timed out"))
    report, counts = await gate_host_gaps(_report(_GAP), elastic=es, settings=_Settings())

    (gap,) = report.findings
    assert gap.title == _GAP.title
    assert gap.detail == _GAP.detail
    assert gap.validator_note is not None
    assert "soc-ai could not read the host's coverage" in gap.validator_note
    assert counts["host_gaps_unread"] == 1


@pytest.mark.asyncio
async def test_a_host_that_ships_nothing_keeps_its_gap() -> None:
    es = _FakeES({"host_datasets": {"buckets": []}})
    report, counts = await gate_host_gaps(_report(_GAP), elastic=es, settings=_Settings())
    assert report.findings[0] == _GAP
    assert counts["host_gaps_rewritten"] == 0


@pytest.mark.asyncio
async def test_a_grid_gap_names_no_host_and_costs_no_read() -> None:
    grid_gap = _GAP.model_copy(update={"title": "No Kerberos telemetry on this grid", "hosts": []})
    es = _FakeES(host_logs_only_aggs())
    report, counts = await gate_host_gaps(_report(grid_gap), elastic=es, settings=_Settings())
    assert report.findings[0] == grid_gap
    assert es.calls == 0
    assert counts["host_gaps"] == 0


@pytest.mark.asyncio
async def test_a_host_that_ships_every_core_plane_has_no_gap() -> None:
    aggs = host_logs_only_aggs()
    aggs["host_datasets"]["buckets"] += [
        {"key": "endpoint.events.process", "doc_count": 900, "newest": {}},
        {"key": "endpoint.events.network", "doc_count": 400, "newest": {}},
    ]
    report, _counts = await gate_host_gaps(
        _report(_GAP), elastic=_FakeES(aggs), settings=_Settings()
    )
    (finding,) = report.findings
    assert finding.category == "observation"
    assert finding.title == "Host telemetry present on app-01"


def test_run_hunt_applies_the_host_gap_gate(settings_kratos: Settings) -> None:
    """Wiring: the gate runs inside the hunt runner, on the report it persists."""
    from pydantic_ai.models.test import TestModel
    from soc_ai.agent.orchestrator import InvestigationContext
    from soc_ai.api.hunt_runner import run_hunt

    fake_report = _report(_GAP)
    elastic = AsyncMock()
    elastic.search = AsyncMock(
        return_value=EsSearchResult(total=76645, took_ms=1, aggregations=host_logs_only_aggs())
    )
    ctx = InvestigationContext(settings=settings_kratos, auth=AsyncMock(), elastic=elastic)

    async def _go() -> list[Any]:
        events = []
        with (
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=TestModel(
                    call_tools=["t_query_events_oql"],
                    custom_output_args=fake_report.model_dump(mode="json"),
                ),
            ),
            patch(
                "soc_ai.agent.toolset.query_events_oql",
                AsyncMock(return_value=EsSearchResult(total=0, took_ms=1)),
            ),
        ):
            async for ev in run_hunt(ctx, objective="hunt for beaconing"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    report_ev = next(e for e in events if e.kind == "hunt_report")
    titles = [f["title"] for f in report_ev.payload["findings"]]
    assert "No process or endpoint network telemetry on app-01" in titles
    gate_ev = next(e for e in events if e.kind == "host_gap_validation")
    assert gate_ev.payload["host_gaps_rewritten"] == 1


@pytest.mark.asyncio
async def test_a_narrative_claim_about_a_covered_host_is_rewritten() -> None:
    report = HuntReport(
        findings=[_THREAT],
        narrative=(
            "No malicious indication. No host-level telemetry exists for app-01, so the "
            "process behind the lookups is unknown."
        ),
        affected_hosts=[_HOST],
    )
    es = _FakeES(host_logs_only_aggs())
    out, counts = await gate_host_gaps(report, elastic=es, settings=_Settings())
    assert out.narrative.startswith("No malicious indication. app-01 ships host logs")
    assert "No host-level telemetry" not in out.narrative
    assert counts["narrative_sentences_rewritten"] == 1


@pytest.mark.asyncio
async def test_a_narrative_with_no_claim_costs_no_read() -> None:
    report = HuntReport(
        findings=[_THREAT],
        narrative="This grid carries no endpoint process telemetry for app-01.",
        affected_hosts=[_HOST],
    )
    es = _FakeES(host_logs_only_aggs())
    out, counts = await gate_host_gaps(report, elastic=es, settings=_Settings())
    assert out is report
    assert es.calls == 0
    assert "narrative_sentences_rewritten" not in counts
