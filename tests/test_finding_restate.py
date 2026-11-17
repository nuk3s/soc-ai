"""A finding that restates an investigated finding starts no new investigation.

Prod, 2026-11-08 to 2026-11-12: the PHP2Shell story became 12 threat findings
and 12 investigations in 5 scheduled hunts. The /proc/self/maps claim was
investigated 5 times, and two of those runs judged the same request. The reuse
rule matched on the exact entity set and the exact document set, and each day
the finding cited one document more or one less.

At promotion, a threat finding that names no new entity and cites nothing new
links to the investigation of the earlier finding. The entry names that
finding, and the hunt page reads "Restates <earlier finding>, verdict <x>". A
finding that cites one new document keeps its own investigation.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting import finding_match
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Hunt, Investigation
from soc_ai.webui import hunt_findings

from tests.test_hunt_findings_investigated import (
    _MGR,
    FakeManager,
    _ctx,
    _hunt,
    _investigating_hunt,
    _run_phase,
    _runs,
    _state,
    _store,
)

_SOURCE = "192.0.2.226"
_TARGET = "192.0.2.164"
_D1 = "docAAAAAAAAAAAAAAAA1"
_D2 = "docAAAAAAAAAAAAAAAA2"
_D3 = "docCCCCCCCCCCCCCCCC3"


def _f(
    title: str,
    *,
    hosts: list[str] | None = None,
    citations: list[str] | None = None,
    severity: str = "high",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "title": title,
        "detail": f"{title}. The detail.",
        "severity": severity,
        "category": "threat",
        "hosts": hosts if hosts is not None else [_SOURCE, _TARGET],
        "citations": citations if citations is not None else [_D1, _D2],
        **extra,
    }


_EARLIER = _f("LFI succeeds and leaks /proc/self/maps", citations=[_D1, _D2, "rule:2036224"])


async def _store_documents(maker: Any, hunt_id: str, findings: list[dict[str, Any]]) -> None:
    """Store the tool result that holds each 'doc...' id the findings cite.

    A citation is a document only when the hunt stored it.
    """
    ids = sorted({c for f in findings for c in f["citations"] if str(c).startswith("doc")})
    async with maker() as db:
        await hunt_svc.append_events(
            db,
            hunt_id,
            [
                {
                    "sequence": 2,
                    "kind": "tool_call",
                    "payload": {
                        "tool_name": "t_query_events_oql",
                        "args": {},
                        "tool_call_id": "c1",
                    },
                },
                {
                    "sequence": 3,
                    "kind": "tool_result",
                    "payload": {
                        "tool_name": "t_query_events_oql",
                        "tool_call_id": "c1",
                        "result": {
                            "hits": [
                                {"_id": i, "_source": {"event": {"dataset": "zeek.http"}}}
                                for i in ids
                            ]
                        },
                    },
                },
            ],
        )


async def _first_hunt(
    settings: Settings,
    maker: Any,
    mgr: FakeManager,
    findings: list[dict[str, Any]] | None = None,
    *,
    lead_id: int | None = None,
) -> tuple[str, list[str]]:
    """The earlier hunt, investigated. Returns its id and its investigations."""
    listed = findings or [_EARLIER]
    hunt_id, plan = await _investigating_hunt(maker, settings, listed, lead_id=lead_id)
    await _store_documents(maker, hunt_id, listed)
    await _run_phase(settings, maker, mgr, hunt_id, plan)
    links = hunt_svc.finding_links(await _hunt(maker, hunt_id))
    return hunt_id, [str(links[o].investigation_id) for o in sorted(links)]


async def _second_hunt(
    settings: Settings,
    maker: Any,
    mgr: FakeManager,
    findings: list[dict[str, Any]],
    *,
    lead_id: int | None = None,
) -> tuple[Hunt, dict[int, hunt_svc.FindingLink], Any]:
    hunt_id, plan = await _investigating_hunt(maker, settings, findings, lead_id=lead_id)
    await _store_documents(maker, hunt_id, findings)
    verdicts = await _run_phase(settings, maker, mgr, hunt_id, plan)
    hunt = await _hunt(maker, hunt_id)
    return hunt, hunt_svc.finding_links(hunt), verdicts


def _keys(finding: dict[str, Any], machines: dict[str, str] | None = None) -> Any:
    """The keys of a finding whose hunt stored every 'doc...' id it cites."""
    stored = {
        c: finding_match.StoredDocument(key=c)
        for c in finding["citations"]
        if str(c).startswith("doc")
    }
    return finding_match.finding_keys(finding, documents=stored, machines=machines)


# ── the rule ────────────────────────────────────────────────────────────────


def test_restates_needs_a_document_and_nothing_new() -> None:
    earlier = _keys(_EARLIER)

    def later(**over: Any) -> Any:
        return _keys(_f("another wording", **over))

    # The same machines, and documents that the earlier finding cited.
    assert finding_match.restates(later(citations=[_D2]), earlier)
    assert finding_match.restates(later(citations=[_D1, _D2, "rule:2036224"]), earlier)
    # Negative controls. One new document, one new rule, one new technique.
    assert not finding_match.restates(later(citations=[_D2, _D3]), earlier)
    assert not finding_match.restates(later(citations=[_D2, "rule:2001219"]), earlier)
    assert not finding_match.restates(later(citations=[_D2, "T1486"]), earlier)
    # Another set of machines: one more host, and one host less.
    assert not finding_match.restates(later(hosts=[*_EARLIER["hosts"], "192.0.2.9"]), earlier)
    assert not finding_match.restates(later(hosts=[_TARGET], citations=[_D2]), earlier)
    # No resolved document: a rule alone, a technique alone, nothing at all.
    assert not finding_match.restates(later(citations=["rule:2036224"]), earlier)
    assert not finding_match.restates(later(citations=[]), earlier)
    assert not finding_match.restates(later(hosts=[], citations=[_D2]), earlier)


@pytest.mark.parametrize(
    "citation", ["t_query_events_oql", "192.168.100.20", "192.168.100.77:445", "mitre:T1003.006"]
)
def test_a_citation_that_is_no_stored_document_restates_nothing(citation: str) -> None:
    """The citation gate keeps a tool name and an address. Neither is a document."""
    earlier = _keys(_f("Nmap sweep of the app", hosts=[_TARGET], citations=[citation, _D1]))
    later = _keys(_f("Web shell upload on the app", hosts=[_TARGET], citations=[citation]))

    assert citation not in later.documents and citation not in earlier.documents
    assert not finding_match.restates(later, earlier)


def test_a_technique_that_the_earlier_finding_lacks_is_a_new_claim() -> None:
    earlier = _keys(_f("DNS tunnel", hosts=[_TARGET], citations=[_D1, "T1071"]))
    beacon = _keys(_f("HTTPS beacon", hosts=[_TARGET], citations=[_D1, "T1071"]))
    ransom = _keys(_f("Beacon and ransomware", hosts=[_TARGET], citations=[_D1, "T1071", "T1486"]))
    no_document = _keys(_f("Beacon again", hosts=[_TARGET], citations=["T1071"]))

    assert finding_match.restates(beacon, earlier)
    assert not finding_match.restates(ransom, earlier)
    assert not finding_match.restates(no_document, earlier)


def test_a_host_name_and_its_address_are_the_same_machine() -> None:
    machines = {"web01": "machine:agent:web01", _TARGET: "machine:agent:web01"}
    earlier = _f("Exploit of the app", hosts=["web01"], citations=[_D1])
    later = _f("Exploit of the app continues", hosts=[_TARGET], citations=[_D1])

    assert not finding_match.restates(_keys(later), _keys(earlier))
    assert finding_match.restates(_keys(later, machines), _keys(earlier, machines))


# ── the promotion ───────────────────────────────────────────────────────────


async def test_a_finding_that_restates_a_true_positive_links_to_its_investigation(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    first, (earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)
    assert len(mgr.started) == 1

    # The next day: other words, the same hosts, one document less.
    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    hunt, links, verdicts = await _second_hunt(settings_kratos, maker, mgr, [again])

    # No new investigation started.
    assert len(mgr.started) == 1
    assert len(await _runs(maker)) == 1
    link = links[0]
    assert link.state == hunt_svc.LINK_ENDED
    assert link.investigation_id == earlier_run
    assert link.origin == hunt_svc.ORIGIN_REUSED
    assert link.restates == {
        "hunt_id": first,
        "ordinal": 0,
        "title": "LFI succeeds and leaks /proc/self/maps",
    }
    assert hunt.status == "complete"
    assert (hunt.findings_total, hunt.findings_investigated) == (1, 1)
    assert verdicts is not None
    assert (verdicts.total, verdicts.decided, verdicts.threats) == (1, 1, 1)
    await engine.dispose()


@pytest.mark.parametrize("verdict", ["needs_more_info", "inconclusive", "false_positive", "error"])
async def test_only_a_true_positive_answers(settings_kratos: Settings, verdict: str) -> None:
    """A link to any other run buried the next claim for seven days."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: verdict})
    _first, (earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)

    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    _hunt_row, links, _verdicts = await _second_hunt(settings_kratos, maker, mgr, [again])

    assert len(mgr.started) == 2
    assert links[0].investigation_id == mgr.started[1]["inv_id"] != earlier_run
    assert links[0].origin == hunt_svc.ORIGIN_OPENED
    assert links[0].restates is None
    await engine.dispose()


async def test_a_run_that_still_runs_never_answers(settings_kratos: Settings) -> None:
    """A running run that then failed kept the link. It now gets none."""
    engine, maker = await _store(settings_kratos)
    slow = FakeManager(maker, verdicts={0: "error"}, auto=False)
    first_id, plan = await _investigating_hunt(maker, settings_kratos, [_EARLIER])
    await _store_documents(maker, first_id, [_EARLIER])
    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    second_id, plan2 = await _investigating_hunt(maker, settings_kratos, [again])
    await _store_documents(maker, second_id, [again])

    def phase(hunt_id: str, its_plan: Any) -> asyncio.Task[Any]:
        return asyncio.create_task(
            hunt_findings.investigate_findings(
                _state(maker, settings_kratos),
                hunt_id=hunt_id,
                ctx=_ctx(settings_kratos, maker),
                plan=its_plan,
            )
        )

    with patch(_MGR, return_value=slow):
        first_phase = phase(first_id, plan)
        for _ in range(400):
            if slow.started:
                break
            await asyncio.sleep(0.005)
        second_phase = phase(second_id, plan2)
        for _ in range(400):
            if len(slow.started) == 2:
                break
            await asyncio.sleep(0.005)
        # The second hunt started its own run while the first one still ran.
        assert len(slow.started) == 2
        for gate in slow.gates.values():
            gate.set()
        await first_phase
        await second_phase

    link = hunt_svc.finding_links(await _hunt(maker, second_id))[0]
    assert link.investigation_id == slow.started[1]["inv_id"]
    assert link.restates is None
    await engine.dispose()


async def test_the_latest_run_decides_after_a_rerun(settings_kratos: Settings) -> None:
    """The first run is a true positive. Its Re-run is not. The finding answers no more."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    first, (_earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)
    async with maker() as db:
        rerun = await inv_svc.create(
            db,
            alert_es_id=_D1,
            started_by="alice",
            rule_name=_EARLIER["title"],
            kind="hunt",
            hunt_id=first,
            finding_ordinal=0,
        )
        await inv_svc.finalize(db, rerun.id, status="complete", verdict="false_positive")

    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    new_mgr = FakeManager(maker)
    _hunt_row, links, _verdicts = await _second_hunt(settings_kratos, maker, new_mgr, [again])

    assert len(new_mgr.started) == 1
    assert links[0].restates is None
    await engine.dispose()


async def test_an_override_to_a_true_positive_answers(settings_kratos: Settings) -> None:
    """The verdict is read live from the row, after an analyst override."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "needs_more_info"})
    first, (earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)
    async with maker() as db:
        row = await db.get(Investigation, earlier_run)
        assert row is not None
        row.verdict = "true_positive"
        await db.commit()

    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    _hunt_row, links, _verdicts = await _second_hunt(settings_kratos, maker, mgr, [again])

    assert len(mgr.started) == 1
    assert links[0].restates is not None and links[0].restates["hunt_id"] == first
    await engine.dispose()


async def test_one_earlier_run_answers_for_one_finding_of_a_hunt(settings_kratos: Settings) -> None:
    """Two findings cite two halves of the earlier evidence. They make two claims."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    _first, (earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)

    findings = [
        _f("LFI on the app leaks /proc/self/maps", citations=[_D1], severity="low"),
        _f("A web shell was uploaded through the same endpoint", citations=[_D1, _D2]),
        _f("The source reads a third file", citations=[_D2], severity="low"),
    ]
    _hunt_row, links, _verdicts = await _second_hunt(settings_kratos, maker, mgr, findings)

    # The finding with the largest document overlap takes the earlier run.
    assert links[1].investigation_id == earlier_run and links[1].restates is not None
    # Every other finding gets its own run.
    assert len(mgr.started) == 3
    assert {s["finding_ordinal"] for s in mgr.started[1:]} == {0, 2}
    assert links[0].restates is None and links[2].restates is None
    assert (
        len({links[0].investigation_id, links[1].investigation_id, links[2].investigation_id}) == 3
    )
    await engine.dispose()


async def test_a_finding_with_a_new_document_gets_its_own_investigation(
    settings_kratos: Settings,
) -> None:
    """Negative control: new evidence is a new claim to judge."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    _first, (earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)

    more = _f("LFI on the app leaks /proc/self/maps", citations=[_D2, _D3])
    _hunt_row, links, _verdicts = await _second_hunt(settings_kratos, maker, mgr, [more])

    assert len(mgr.started) == 2
    assert links[0].investigation_id == mgr.started[1]["inv_id"] != earlier_run
    assert links[0].restates is None
    await engine.dispose()


async def test_a_document_id_that_the_hunt_did_not_store_restates_nothing(
    settings_kratos: Settings,
) -> None:
    """Negative control: the id has the shape of a document, and no hunt holds it."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    await _first_hunt(settings_kratos, maker, mgr)

    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, [again])
    # No stored tool result for this hunt.
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)

    assert len(mgr.started) == 2
    assert hunt_svc.finding_links(await _hunt(maker, hunt_id))[0].restates is None
    await engine.dispose()


async def test_each_new_claim_gets_its_own_investigation(settings_kratos: Settings) -> None:
    """Negative controls: a new host, a rule alone, and a finding that cites nothing."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    await _first_hunt(settings_kratos, maker, mgr)

    findings = [
        _f(
            "A third host joins the exploit", hosts=[_SOURCE, _TARGET, "192.0.2.9"], citations=[_D2]
        ),
        _f("The loose rule fires on the app again", citations=["rule:2036224"]),
        _f("The source reads more files", citations=[]),
    ]
    _hunt_row, links, _verdicts = await _second_hunt(settings_kratos, maker, mgr, findings)

    assert len(mgr.started) == 4
    assert all(links[o].restates is None for o in links)
    await engine.dispose()


async def test_the_look_back_is_seven_days(settings_kratos: Settings) -> None:
    """Negative control: an old investigation does not answer for a finding of today."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    _first, (earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)
    async with maker() as db:
        row = await db.get(Investigation, earlier_run)
        assert row is not None
        row.created_at = row.created_at - timedelta(days=inv_svc.SUBJECT_REUSE_DAYS, hours=1)
        await db.commit()

    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    _hunt_row, links, _verdicts = await _second_hunt(settings_kratos, maker, mgr, [again])

    assert len(mgr.started) == 2
    assert links[0].restates is None
    await engine.dispose()


async def test_a_sibling_finding_of_the_same_hunt_is_never_restated(
    settings_kratos: Settings,
) -> None:
    """Negative control: two findings of one hunt make two claims (change E)."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive", 1: "true_positive"})
    findings = [_EARLIER, _f("The same evidence, a second claim", citations=[_D2], severity="low")]

    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, findings)
    await _store_documents(maker, hunt_id, findings)
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)

    links = hunt_svc.finding_links(await _hunt(maker, hunt_id))
    assert len(mgr.started) == 2
    assert links[0].investigation_id != links[1].investigation_id
    assert links[0].restates is None and links[1].restates is None
    await engine.dispose()


async def test_a_lead_hunt_gives_each_finding_its_own_run(settings_kratos: Settings) -> None:
    """A verdict of an earlier claim must not close a lead as promoted."""
    from tests.test_hunt_findings_investigated import _lead

    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    _first, (earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)
    lead_id = await _lead(maker)

    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    _hunt_row, links, _verdicts = await _second_hunt(
        settings_kratos, maker, mgr, [again], lead_id=lead_id
    )

    assert len(mgr.started) == 2
    assert links[0].investigation_id == mgr.started[1]["inv_id"] != earlier_run
    assert links[0].restates is None
    await engine.dispose()


async def test_a_synthetic_evaluation_run_never_answers_for_a_real_finding(
    settings_kratos: Settings,
) -> None:
    """Negative control: a planted scenario describes nothing real."""
    engine, maker = await _store(settings_kratos)
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    _first, (earlier_run,) = await _first_hunt(settings_kratos, maker, mgr)
    async with maker() as db:
        row = await db.get(Investigation, earlier_run)
        assert row is not None
        row.is_synth_eval = True
        await db.commit()

    again = _f("LFI on the app leaks /proc/self/maps", citations=[_D2])
    _hunt_row, links, _verdicts = await _second_hunt(settings_kratos, maker, mgr, [again])

    assert len(mgr.started) == 2
    assert links[0].restates is None
    await engine.dispose()


def test_a_stored_entry_of_another_shape_reads_as_no_restatement() -> None:
    links = hunt_svc.finding_links_from(
        {
            "0": {"state": "ended", "investigation_id": "I1", "restates": "the earlier one"},
            "1": {"state": "ended", "investigation_id": "I2", "restates": {"ordinal": 0}},
            "2": {
                "state": "ended",
                "investigation_id": "I3",
                "restates": {"hunt_id": "H1", "ordinal": 2, "title": "T"},
            },
        }
    )

    assert links[0].restates is None and links[1].restates is None
    assert links[2].restates == {"hunt_id": "H1", "ordinal": 2, "title": "T"}


# ── the page ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _seed_linked_hunts(client: TestClient) -> tuple[str, str, str]:
    """An earlier hunt with a true positive finding, and a hunt whose finding restates it."""

    async def _go() -> tuple[str, str, str]:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            first = await hunt_svc.create(db, objective="daily hunt", started_by="scheduler")
            await hunt_svc.finalize(
                db, first.id, status="complete", report={"findings": [_EARLIER], "narrative": "n"}
            )
            run = await inv_svc.create(
                db,
                alert_es_id=_D1,
                started_by="system:hunt",
                rule_name=_EARLIER["title"],
                kind="hunt",
                hunt_id=first.id,
                finding_ordinal=0,
            )
            await inv_svc.finalize(
                db, run.id, status="complete", verdict="true_positive", confidence=0.8
            )
            row = await db.get(Investigation, run.id)
            assert row is not None
            row.created_at = row.created_at - timedelta(hours=6)
            second = await hunt_svc.create(db, objective="daily hunt", started_by="scheduler")
            findings = [
                _f("LFI on the app leaks /proc/self/maps", citations=[_D2]),
                _f("A new source exploits the app", hosts=["192.0.2.9"], citations=[_D3]),
            ]
            await hunt_svc.finalize(
                db,
                second.id,
                status="complete",
                report={"findings": findings, "narrative": "n"},
                finding_plan={
                    "0": hunt_svc.plan_entry(
                        hunt_svc.LINK_ENDED,
                        investigation_id=run.id,
                        origin=hunt_svc.ORIGIN_REUSED,
                        restates={"hunt_id": first.id, "ordinal": 0, "title": _EARLIER["title"]},
                    ),
                    "1": hunt_svc.plan_entry(hunt_svc.LINK_FAILED, reason="could_not_start"),
                },
            )
            hunt_row = await db.get(Hunt, second.id)
            assert hunt_row is not None
            hunt_row.status = "complete"
            await db.commit()
            return first.id, second.id, run.id

    return asyncio.run(_go())


def _rerun(client: TestClient, hunt_id: str, verdict: str) -> str:
    """A Re-run of the earlier finding that lands ``verdict``."""

    async def _go() -> str:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            run = await inv_svc.create(
                db,
                alert_es_id=_D1,
                started_by="alice",
                rule_name=_EARLIER["title"],
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=0,
            )
            await inv_svc.finalize(db, run.id, status="complete", verdict=verdict, confidence=0.9)
            return str(run.id)

    return asyncio.run(_go())


def test_the_hunt_page_names_the_restated_finding_and_its_verdict(client: TestClient) -> None:
    first, second, run = _seed_linked_hunts(client)

    body = client.get(f"/api/v1/hunts/{second}").json()

    restated = body["findings"][0]
    assert restated["restates"] == {
        "huntId": first,
        "ordinal": 0,
        "title": "LFI succeeds and leaks /proc/self/maps",
        "verdict": "true_positive",
        "answers": True,
    }
    assert restated["investigationId"] == run
    assert restated["verdict"] == "true_positive"
    assert restated["investigationOrigin"] == "reused"
    assert restated["investigationStatus"] == "complete"
    assert body["outcome"] == "threats_confirmed"
    # The restated finding has no run of its own. It counts the verdict that
    # answers for it, so the parts of the count sentence add up.
    assert body["outcome_label"] == "1 confirmed · 1 not judged · of 2 threat findings"
    assert (body["findingsConfirmed"], body["threatFindingCount"]) == (1, 2)
    row = next(h for h in client.get("/api/v1/hunts").json() if h["id"] == second)
    assert row["outcome_label"] == body["outcome_label"]
    # Negative control: a finding with no earlier finding carries none.
    assert body["findings"][1]["restates"] is None
    assert client.get(f"/api/v1/hunts/{first}").json()["findings"][0]["restates"] is None


def test_the_link_follows_a_rerun_of_the_earlier_finding(client: TestClient) -> None:
    """The stored run id is the run of the day of the hunt. The page reads the latest run."""
    first, second, run = _seed_linked_hunts(client)

    # The Re-run lands needs more info. The earlier finding answers no more.
    stale_run = _rerun(client, first, "needs_more_info")
    body = client.get(f"/api/v1/hunts/{second}").json()
    stale = body["findings"][0]
    assert stale["restates"]["verdict"] == "needs_more_info"
    assert stale["restates"]["answers"] is False
    # No borrowed verdict: the finding has no investigation, and the card
    # offers its own run.
    assert stale["investigationId"] is None and stale["verdict"] is None
    assert stale["investigationStatus"] is None
    assert body["outcome"] != "threats_confirmed"
    # The stale restated finding is not judged: it counts as no confirmed threat.
    assert body["findingsConfirmed"] == 0
    assert stale_run != run

    # The press on the finding starts its own run: no earlier run answers it.
    async def _answer() -> Any:
        from soc_ai.api.webui.routes_hunts import _finding_answer

        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            hunt = await db.get(Hunt, second)
            assert hunt is not None
            finding = hunt.report["findings"][0]
            return await _finding_answer(
                db, hunt=hunt, ordinal=0, finding=finding, rerun=False, is_synth_eval=False
            )

    assert asyncio.run(_answer()).run is None

    # A second Re-run lands a true positive. The link reads that run.
    confirmed = _rerun(client, first, "true_positive")
    body = client.get(f"/api/v1/hunts/{second}").json()
    live = body["findings"][0]
    assert live["restates"]["verdict"] == "true_positive" and live["restates"]["answers"] is True
    assert live["investigationId"] == confirmed
    assert live["verdict"] == "true_positive"
    assert body["outcome"] == "threats_confirmed"
    answer = asyncio.run(_answer())
    assert answer.run is not None and answer.run.id == confirmed


def test_the_link_follows_an_analyst_override(client: TestClient) -> None:
    first, second, run = _seed_linked_hunts(client)

    async def _override() -> None:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            row = await db.get(Investigation, run)
            assert row is not None
            row.verdict = "false_positive"
            await db.commit()

    asyncio.run(_override())

    finding = client.get(f"/api/v1/hunts/{second}").json()["findings"][0]

    assert finding["restates"]["verdict"] == "false_positive"
    assert finding["restates"]["answers"] is False
    assert finding["verdict"] is None and finding["investigationId"] is None
    _ = first
